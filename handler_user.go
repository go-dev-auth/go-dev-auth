package godevauth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-dev-auth/go-dev-auth/storage"
)

func (a *Auth) handleUpdateUser(c *Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var raw map[string]any
	if err := c.BindJSON(&raw); err != nil {
		return err
	}
	update := map[string]any{}
	if v, ok := raw["name"].(string); ok {
		update["name"] = v
	}
	if v, ok := raw["image"].(string); ok {
		update["image"] = v
	}
	if extra := a.collectAdditionalUserFields(raw); extra != nil {
		for k, v := range extra {
			update[k] = v
		}
	}
	if len(update) == 0 {
		return c.JSON(http.StatusOK, map[string]any{"status": true})
	}
	user, err := a.store.UpdateUser(c.Context(), sd.User.ID, update)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"status": true, "user": user})
}

type changeEmailBody struct {
	NewEmail    string `json:"newEmail"`
	CallbackURL string `json:"callbackURL"`
}

func (a *Auth) handleChangeEmail(c *Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body changeEmailBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if err := validateEmail(body.NewEmail); err != nil {
		return err
	}
	ctx := c.Context()
	newEmail := normalizeEmail(body.NewEmail)
	if newEmail == sd.User.Email {
		return NewAPIError(http.StatusBadRequest, "EMAIL_IS_THE_SAME", "Email is the same")
	}
	if _, err := a.store.FindUserByEmail(ctx, newEmail); err == nil {
		return NewAPIError(http.StatusBadRequest, "COULDNT_UPDATE_YOUR_EMAIL", "Couldn't update your email")
	} else if !errors.Is(err, storage.ErrNotFound) {
		return err
	}

	send := a.config.User.ChangeEmail.SendChangeEmailVerification
	if sd.User.EmailVerified {
		// A verified address is the account's recovery channel, so
		// moving it must be approved from that address. Refusing here
		// is deliberate: silently falling through would let a stolen
		// session relocate the account and then take it over via
		// password reset.
		if send == nil {
			a.logger.Error("go-dev-auth: ChangeEmail.SendChangeEmailVerification is required to change a verified email")
			return NewAPIError(http.StatusBadRequest, "VERIFICATION_REQUIRED",
				"Changing a verified email address requires email confirmation, which is not configured")
		}
		token, err := a.StoreToken(ctx, tokenKindChangeEmail,
			sd.User.ID+"|"+newEmail, a.config.EmailVerification.ExpiresIn)
		if err != nil {
			return err
		}
		approveURL := withQuery(c.BaseURL()+"/verify-email", "token", token)
		if body.CallbackURL != "" {
			approveURL = withQuery(approveURL, "callbackURL", body.CallbackURL)
		}
		if err := send(ctx, sd.User, newEmail, approveURL, token); err != nil {
			return NewAPIError(http.StatusInternalServerError, "FAILED_TO_SEND_EMAIL", "Failed to send email")
		}
		// Moving a verified address relocates the account's recovery
		// channel, so the request is worth recording even before it is
		// confirmed. Email is the current address; the proposed one is
		// deliberately not recorded, because at this point it is
		// unconfirmed input.
		a.EmitEvent(c, Event{
			Type:      EventEmailChangeRequested,
			ActorID:   sd.User.ID,
			Email:     sd.User.Email,
			SessionID: sd.Session.ID,
		})
		return c.JSON(http.StatusOK, map[string]any{"status": true, "message": "verification email sent"})
	}

	user, err := a.store.UpdateUser(ctx, sd.User.ID, map[string]any{
		"email":         newEmail,
		"emailVerified": false,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return NewAPIError(http.StatusBadRequest, "COULDNT_UPDATE_YOUR_EMAIL",
				"Couldn't update your email")
		}
		return err
	}
	a.EmitEvent(c, Event{
		Type:      EventEmailChanged,
		ActorID:   sd.User.ID,
		Email:     newEmail,
		SessionID: sd.Session.ID,
	})
	if a.config.EmailVerification.SendVerificationEmail != nil {
		_ = a.sendVerificationEmail(ctx, user, body.CallbackURL)
	}
	return c.JSON(http.StatusOK, map[string]any{"status": true, "user": user})
}

type deleteUserBody struct {
	Password    string `json:"password"`
	Token       string `json:"token"`
	CallbackURL string `json:"callbackURL"`
}

func (a *Auth) handleDeleteUser(c *Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body deleteUserBody
	if err := c.BindJSONOptional(&body); err != nil {
		return err
	}
	ctx := c.Context()
	cfg := a.config.User.DeleteUser

	// token flow completion; the token must belong to the caller
	if body.Token != "" {
		return a.completeDeleteUser(c, body.Token, sd.User.ID)
	}

	// password verification when provided
	if body.Password != "" {
		account, err := a.store.FindCredentialAccount(ctx, sd.User.ID)
		if err != nil {
			return ErrCredentialAccountNotFound
		}
		ok, err := a.config.EmailAndPassword.PasswordHasher.Verify(account.Password, body.Password)
		if err != nil || !ok {
			return ErrInvalidPassword
		}
	} else if cfg.SendDeleteAccountVerification != nil {
		// email verification flow
		token, err := a.StoreToken(ctx, tokenKindDeleteAccount, sd.User.ID, cfg.DeleteTokenExpiresIn)
		if err != nil {
			return err
		}
		deleteURL := withQuery(c.BaseURL()+"/delete-user/callback", "token", token)
		if body.CallbackURL != "" {
			deleteURL = withQuery(deleteURL, "callbackURL", body.CallbackURL)
		}
		if err := cfg.SendDeleteAccountVerification(ctx, sd.User, deleteURL, token); err != nil {
			return NewAPIError(http.StatusInternalServerError, "FAILED_TO_SEND_EMAIL", "Failed to send email")
		}
		return c.JSON(http.StatusOK, map[string]any{"success": true, "message": "verification email sent"})
	} else if !a.IsFresh(sd.Session) {
		// no password and no email flow: require a fresh session
		return ErrSessionExpired
	}

	return a.performDeleteUser(c, sd.User)
}

// handleDeleteUserConfirm renders a confirmation page for the emailed
// deletion link. Deletion itself happens on POST: a GET that destroys
// the account would fire on link scanners, mail-security gateways and
// browser prefetch.
func (a *Auth) handleDeleteUserConfirm(c *Ctx) error {
	token := c.Query("token")
	if token == "" {
		return ErrInvalidToken
	}
	if _, err := a.LookupToken(c.Context(), tokenKindDeleteAccount, token); err != nil {
		return ErrInvalidToken
	}
	action := withQuery(c.BaseURL()+"/delete-user/callback", "token", token)
	if callbackURL := c.Query("callbackURL"); callbackURL != "" {
		action = withQuery(action, "callbackURL", callbackURL)
	}
	c.W.Header().Set("Content-Type", "text/html; charset=utf-8")
	c.markWritten(http.StatusOK)
	_, _ = c.W.Write([]byte(deleteConfirmHTML(action, a.config.AppName)))
	return nil
}

func (a *Auth) handleDeleteUserCallback(c *Ctx) error {
	token := c.Query("token")
	if token == "" {
		return ErrInvalidToken
	}
	// The link itself is the authorization, so no session is required;
	// the token is single use and bound to one user.
	if err := a.completeDeleteUser(c, token, ""); err != nil {
		return err
	}
	if callbackURL := c.Query("callbackURL"); callbackURL != "" {
		if to, ok := a.safeRedirect(callbackURL); ok {
			return c.Redirect(to)
		}
	}
	return nil
}

// completeDeleteUser consumes a deletion token. When expectUserID is
// non-empty the token must belong to that user, so a leaked token
// cannot be redeemed from someone else's session.
func (a *Auth) completeDeleteUser(c *Ctx, token, expectUserID string) error {
	ctx := c.Context()
	// Check ownership before consuming, so someone else's session
	// cannot burn a victim's deletion link just by presenting it.
	if expectUserID != "" {
		v, err := a.LookupToken(ctx, tokenKindDeleteAccount, token)
		if err != nil || v.Value != expectUserID {
			return ErrInvalidToken
		}
	}
	userID, err := a.ConsumeToken(ctx, tokenKindDeleteAccount, token)
	if err != nil {
		return ErrInvalidToken
	}
	if expectUserID != "" && userID != expectUserID {
		return ErrInvalidToken
	}
	user, err := a.store.FindUserByID(ctx, userID)
	if err != nil {
		return ErrInvalidToken
	}
	return a.performDeleteUser(c, user)
}

func deleteConfirmHTML(action, appName string) string {
	return `<!DOCTYPE html><html><head><meta charset="utf-8">` +
		`<title>Confirm account deletion</title></head>` +
		`<body style="font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">` +
		`<form method="POST" action="` + htmlEscape(action) + `" style="text-align:center;max-width:28rem">` +
		`<h1>Delete your account?</h1>` +
		`<p>This permanently deletes your ` + htmlEscape(appName) + ` account and cannot be undone.</p>` +
		`<button type="submit" style="padding:.75rem 1.5rem;font-size:1rem">Yes, delete my account</button>` +
		`</form></body></html>`
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

func (a *Auth) performDeleteUser(c *Ctx, user *storage.User) error {
	ctx := c.Context()
	cfg := a.config.User.DeleteUser
	if cfg.BeforeDelete != nil {
		if err := cfg.BeforeDelete(ctx, user); err != nil {
			return err
		}
	}
	if err := a.store.DeleteUser(ctx, user.ID); err != nil {
		return err
	}
	a.clearSessionCookie(c.W)
	// Emitted after the delete succeeds and before AfterDelete, so the
	// record exists even if the application's own hook fails.
	a.EmitEvent(c, Event{Type: EventAccountDeleted, ActorID: user.ID, Email: user.Email})
	if cfg.AfterDelete != nil {
		_ = cfg.AfterDelete(ctx, user)
	}
	return c.JSON(http.StatusOK, map[string]any{"success": true})
}
