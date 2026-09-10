package godevauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-dev-auth/go-dev-auth/storage"
)

// sendVerificationEmail creates a token and delivers the verification
// email. The token is bound to the user ID (not the email address) so
// that a later address change cannot orphan or redirect it.
func (a *Auth) sendVerificationEmail(ctx context.Context, user *storage.User, callbackURL string) error {
	send := a.config.EmailVerification.SendVerificationEmail
	if send == nil {
		return ErrEmailVerificationDisabled
	}
	token, err := a.StoreToken(ctx, tokenKindEmailVerify,
		user.ID+"|"+user.Email, a.config.EmailVerification.ExpiresIn)
	if err != nil {
		return err
	}
	verifyURL := withQuery(a.config.BaseURL+a.config.BasePath+"/verify-email", "token", token)
	if callbackURL != "" {
		verifyURL = withQuery(verifyURL, "callbackURL", callbackURL)
	}
	if err := send(ctx, user, verifyURL, token); err != nil {
		a.logger.Error("go-dev-auth: failed to send verification email", "err", err)
		return NewAPIError(http.StatusInternalServerError, "FAILED_TO_SEND_EMAIL", "Failed to send email")
	}
	return nil
}

type sendVerificationEmailBody struct {
	Email       string `json:"email"`
	CallbackURL string `json:"callbackURL"`
}

func (a *Auth) handleSendVerificationEmail(c *Ctx) error {
	var body sendVerificationEmailBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if err := validateEmail(body.Email); err != nil {
		return err
	}
	user, err := a.store.FindUserByEmail(c.Context(), body.Email)
	if err != nil {
		// Don't leak existence in the body or the timing: match the
		// token write the send path does.
		a.dummyTokenWrite(c.Context())
		return c.OK()
	}
	if user.EmailVerified {
		a.dummyTokenWrite(c.Context())
		return c.OK()
	}
	if err := a.sendVerificationEmail(c.Context(), user, body.CallbackURL); err != nil {
		return err
	}
	return c.OK()
}

// handleVerifyEmail handles the GET verification link. With
// ConfirmationPage set it renders an interstitial that POSTs the token,
// so a link scanner's GET does not consume it; otherwise it verifies
// immediately (the default, for compatibility with clients that link
// straight to the GET endpoint).
func (a *Auth) handleVerifyEmail(c *Ctx) error {
	if a.config.EmailVerification.ConfirmationPage {
		token := c.Query("token")
		if token == "" {
			return ErrInvalidToken
		}
		action := withQuery(c.BaseURL()+"/verify-email", "token", token)
		if cb := c.Query("callbackURL"); cb != "" {
			action = withQuery(action, "callbackURL", cb)
		}
		c.W.Header().Set("Content-Type", "text/html; charset=utf-8")
		c.markWritten(http.StatusOK)
		_, _ = c.W.Write([]byte(verifyConfirmHTML(action, a.config.AppName)))
		return nil
	}
	return a.performVerifyEmail(c)
}

// handleVerifyEmailPost performs the verification. It is the form target
// of the confirmation page, and can also be called directly by a client
// that prefers to POST.
func (a *Auth) handleVerifyEmailPost(c *Ctx) error {
	return a.performVerifyEmail(c)
}

func verifyConfirmHTML(action, appName string) string {
	return `<!DOCTYPE html><html><head><meta charset="utf-8">` +
		`<title>Confirm your email</title></head>` +
		`<body style="font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">` +
		`<form method="POST" action="` + htmlEscape(action) + `" style="text-align:center;max-width:28rem">` +
		`<h1>Confirm your email address</h1>` +
		`<p>Click below to verify your ` + htmlEscape(appName) + ` email address.</p>` +
		`<button type="submit" style="padding:.75rem 1.5rem;font-size:1rem">Verify my email</button>` +
		`</form></body></html>`
}

// performVerifyEmail completes both the "verify my address" flow and the
// "approve my new address" half of the change-email flow, which share a
// link format but carry different token kinds.
func (a *Auth) performVerifyEmail(c *Ctx) error {
	token := c.Query("token")
	callbackURL := c.Query("callbackURL")
	fail := func() error {
		if callbackURL != "" {
			if to, ok := a.safeRedirect(callbackURL); ok {
				return c.Redirect(withQuery(to, "error", "invalid_token"))
			}
		}
		return ErrInvalidToken
	}
	if token == "" {
		return fail()
	}
	ctx := c.Context()

	// change-email approval: value is "<userID>|<newEmail>"
	if value, err := a.ConsumeToken(ctx, tokenKindChangeEmail, token); err == nil {
		userID, newEmail, ok := strings.Cut(value, "|")
		if !ok {
			return fail()
		}
		user, err := a.store.FindUserByID(ctx, userID)
		if err != nil {
			return fail()
		}
		// the address may have been claimed while the link sat in an inbox
		if existing, err := a.store.FindUserByEmail(ctx, newEmail); err == nil && existing.ID != userID {
			return NewAPIError(http.StatusBadRequest, "COULDNT_UPDATE_YOUR_EMAIL",
				"That email address is no longer available")
		}
		// Approval from the current address confirms intent, but the new
		// address has not yet proven control, so it lands unverified and
		// gets its own verification email below. Marking it verified on
		// this click alone would hand full recovery rights (password
		// reset) to an address that was never demonstrated.
		updated, err := a.store.UpdateUser(ctx, user.ID, map[string]any{
			"email":         normalizeEmail(newEmail),
			"emailVerified": false,
		})
		if err != nil {
			if isUniqueViolation(err) {
				return NewAPIError(http.StatusBadRequest, "COULDNT_UPDATE_YOUR_EMAIL",
					"That email address is no longer available")
			}
			return err
		}
		a.EmitEvent(c, Event{Type: EventEmailChanged, ActorID: updated.ID, Email: updated.Email})
		if a.config.EmailVerification.SendVerificationEmail != nil {
			_ = a.sendVerificationEmail(ctx, updated, callbackURL)
		}
		if h := a.config.EmailVerification.OnEmailVerification; h != nil {
			_ = h(ctx, updated)
		}
		if callbackURL != "" {
			if to, ok := a.safeRedirect(callbackURL); ok {
				return c.Redirect(to)
			}
		}
		return c.JSON(http.StatusOK, map[string]any{"status": true, "user": updated})
	}

	// standard email verification: value is "<userID>|<email>"
	value, err := a.ConsumeToken(ctx, tokenKindEmailVerify, token)
	if err != nil {
		return fail()
	}
	userID, issuedFor, ok := strings.Cut(value, "|")
	if !ok {
		return fail()
	}
	user, err := a.store.FindUserByID(ctx, userID)
	if err != nil {
		return fail()
	}
	// The token proves control of the address it was sent to. If the
	// account has since moved to a different address, it proves nothing
	// about the current one.
	if !strings.EqualFold(user.Email, issuedFor) {
		return fail()
	}
	if !user.EmailVerified {
		updated, err := a.store.UpdateUser(ctx, user.ID, map[string]any{"emailVerified": true})
		if err != nil {
			return err
		}
		user = updated
		a.EmitEvent(c, Event{Type: EventEmailVerified, ActorID: user.ID, Email: user.Email})
		if h := a.config.EmailVerification.OnEmailVerification; h != nil {
			_ = h(ctx, user)
		}
	}

	if a.config.EmailVerification.AutoSignInAfterVerification {
		c.SetAuthMethod(methodEmailVerification)
		if _, handled, err := a.SignInUser(c, user, true); err != nil {
			return err
		} else if handled {
			return nil
		}
	}
	if callbackURL != "" {
		if to, ok := a.safeRedirect(callbackURL); ok {
			return c.Redirect(to)
		}
	}
	return c.JSON(http.StatusOK, map[string]any{"status": true, "user": user})
}

func withQuery(rawURL, key, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}
