package godevauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-dev-auth/go-dev-auth/storage"
)

// ---- sign up ----

type signUpEmailBody struct {
	Name        string         `json:"name"`
	Email       string         `json:"email"`
	Password    string         `json:"password"`
	Image       string         `json:"image"`
	CallbackURL string         `json:"callbackURL"`
	RememberMe  *bool          `json:"rememberMe"`
	Extra       map[string]any `json:"-"`
}

func (a *Auth) handleSignUpEmail(c *Ctx) error {
	c.SetAuthMethod(methodCredential)
	if a.config.EmailAndPassword.DisableSignUp {
		return ErrSignUpDisabled
	}
	var body signUpEmailBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	// collect additional fields
	var rawAll map[string]any
	_ = c.BindJSONOptional(&rawAll)
	extra := a.collectAdditionalUserFields(rawAll)

	if err := validateEmail(body.Email); err != nil {
		return err
	}
	if err := a.validatePassword(body.Password); err != nil {
		return err
	}

	ctx := c.Context()
	if _, err := a.store.FindUserByEmail(ctx, body.Email); err == nil {
		return ErrUserAlreadyExists
	} else if !errors.Is(err, storage.ErrNotFound) {
		return err
	}

	hash, err := a.config.EmailAndPassword.PasswordHasher.Hash(body.Password)
	if err != nil {
		return err
	}
	user, err := a.store.CreateUser(ctx, &storage.User{
		Name:  body.Name,
		Email: body.Email,
		Image: body.Image,
		Extra: extra,
	})
	if err != nil {
		// The existence check above is inherently racy; the unique
		// index is the real arbiter. Report the loser of the race as a
		// duplicate rather than a server error.
		if errors.Is(err, storage.ErrUniqueViolation) {
			return ErrUserAlreadyExists
		}
		return err
	}
	if _, err := a.store.CreateAccount(ctx, &storage.Account{
		UserID:     user.ID,
		AccountID:  user.ID,
		ProviderID: "credential",
		Password:   hash,
	}); err != nil {
		return err
	}
	a.EmitEvent(c, Event{
		Type:    EventSignUp,
		ActorID: user.ID,
		Email:   user.Email,
		Method:  methodCredential,
	})

	if a.config.EmailVerification.SendOnSignUp {
		_ = a.sendVerificationEmail(ctx, user, body.CallbackURL)
	}

	requireVerification := a.config.EmailAndPassword.RequireEmailVerification
	autoSignIn := !a.config.EmailAndPassword.DisableAutoSignIn
	var token string
	if autoSignIn && !requireVerification {
		rememberMe := body.RememberMe == nil || *body.RememberMe
		sess, handled, err := a.SignInUser(c, user, rememberMe)
		if err != nil {
			return err
		}
		if handled {
			return nil
		}
		token = sess.Token
	}
	return c.JSON(http.StatusOK, map[string]any{
		"token": nullable(token),
		"user":  user,
	})
}

// collectAdditionalUserFields extracts client-writable additional user
// fields from the raw request body.
//
// Only fields the application declared in Config.User.AdditionalFields
// with Input:true are accepted. Anything else in the body is ignored —
// in particular the columns plugins add to the user table (role,
// banned, twoFactorEnabled, ...), which decide authorization and must
// never be settable by the account holder.
func (a *Auth) collectAdditionalUserFields(raw map[string]any) map[string]any {
	if raw == nil || len(a.writableUserFields) == 0 {
		return nil
	}
	var extra map[string]any
	for name := range a.writableUserFields {
		v, ok := raw[name]
		if !ok {
			continue
		}
		if extra == nil {
			extra = map[string]any{}
		}
		extra[name] = v
	}
	return extra
}

// ---- sign in ----

type signInEmailBody struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	CallbackURL string `json:"callbackURL"`
	RememberMe  *bool  `json:"rememberMe"`
}

func (a *Auth) handleSignInEmail(c *Ctx) error {
	c.SetAuthMethod(methodCredential)
	var body signInEmailBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if body.Email == "" || body.Password == "" {
		return a.signInFailed(c, body.Email, "", ReasonInvalidPassword, ErrInvalidEmailOrPassword)
	}
	ctx := c.Context()
	user, err := a.store.FindUserByEmail(ctx, body.Email)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			a.dummyVerify(body.Password)
			// The client is told only "invalid email or password", but
			// the audit trail records which of the two it was: an
			// attacker spraying addresses that do not exist looks
			// nothing like one guessing passwords for an account that
			// does, and only this distinction shows the difference.
			return a.signInFailed(c, body.Email, "", ReasonUnknownUser, ErrInvalidEmailOrPassword)
		}
		return err
	}
	account, err := a.store.FindCredentialAccount(ctx, user.ID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			// Social-only user: burn the same time as a real password
			// check so the response does not distinguish "no account"
			// from "no password on this account".
			a.dummyVerify(body.Password)
			return a.signInFailed(c, body.Email, user.ID, ReasonNoCredential, ErrInvalidEmailOrPassword)
		}
		return err
	}
	ok, err := a.config.EmailAndPassword.PasswordHasher.Verify(account.Password, body.Password)
	if err != nil {
		// A saturated hasher is a capacity problem, not a wrong
		// password; reporting it as one would tell the user their
		// credentials are bad and invite a retry storm.
		return err
	}
	if !ok {
		return a.signInFailed(c, body.Email, user.ID, ReasonInvalidPassword, ErrInvalidEmailOrPassword)
	}
	if a.config.EmailAndPassword.RequireEmailVerification && !user.EmailVerified {
		if a.config.EmailVerification.SendOnSignIn ||
			a.config.EmailVerification.SendVerificationEmail != nil {
			_ = a.sendVerificationEmail(ctx, user, body.CallbackURL)
		}
		return a.signInFailed(c, body.Email, user.ID, ReasonEmailNotVerified, ErrEmailNotVerified)
	}

	rememberMe := body.RememberMe == nil || *body.RememberMe
	sess, handled, err := a.SignInUser(c, user, rememberMe)
	if err != nil {
		return err
	}
	if handled {
		return nil
	}
	return c.JSON(http.StatusOK, map[string]any{
		"redirect": false,
		"token":    sess.Token,
		"user":     user,
	})
}

// signInFailed records a refused sign-in and returns the (deliberately
// vaguer) error the client sees.
func (a *Auth) signInFailed(c *Ctx, email, userID string, reason Reason, err error) error {
	a.EmitEvent(c, Event{
		Type:    EventSignIn,
		Outcome: OutcomeFailure,
		Reason:  reason,
		ActorID: userID,
		Email:   email,
		Method:  c.AuthMethod(),
	})
	return err
}

// dummyVerify burns password-hashing time on paths where no stored hash
// exists, so response time does not reveal whether an account exists.
func (a *Auth) dummyVerify(password string) {
	if d, ok := a.config.EmailAndPassword.PasswordHasher.(interface{ DummyVerify(string) }); ok {
		d.DummyVerify(password)
		return
	}
	_, _ = a.config.EmailAndPassword.PasswordHasher.Hash(password)
}

// ---- password reset ----

type forgetPasswordBody struct {
	Email      string `json:"email"`
	RedirectTo string `json:"redirectTo"`
}

func (a *Auth) handleForgetPassword(c *Ctx) error {
	var body forgetPasswordBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if err := validateEmail(body.Email); err != nil {
		return err
	}
	send := a.config.EmailAndPassword.SendResetPassword
	if send == nil {
		a.logger.Warn("go-dev-auth: SendResetPassword is not configured")
		return c.OK()
	}
	ctx := c.Context()
	user, err := a.store.FindUserByEmail(ctx, body.Email)
	if err != nil {
		// do not leak account existence
		return c.OK()
	}
	token, err := a.StoreToken(ctx, tokenKindResetPassword, user.ID,
		a.config.EmailAndPassword.ResetPasswordTokenExpiresIn)
	if err != nil {
		return err
	}
	resetURL := c.BaseURL() + "/reset-password/" + url.PathEscape(token)
	// Per-request redirectTo wins; otherwise fall back to the
	// configured application page. Without one of the two the emailed
	// link dead-ends on the error page, which is why New rejects that
	// configuration up front.
	callback := body.RedirectTo
	if callback == "" {
		callback = a.config.EmailAndPassword.ResetPasswordURL
	}
	if callback != "" {
		resetURL = withQuery(resetURL, "callbackURL", callback)
	}
	if err := send(ctx, user, resetURL, token); err != nil {
		a.logger.Error("go-dev-auth: failed to send reset password email", "err", err)
		return NewAPIError(http.StatusInternalServerError, "FAILED_TO_SEND_EMAIL", "Failed to send email")
	}
	// The token itself is never recorded: it is a bearer credential
	// with the power to take over the account.
	a.EmitEvent(c, Event{
		Type:    EventPasswordResetRequested,
		ActorID: user.ID,
		Email:   user.Email,
	})
	return c.OK()
}

func (a *Auth) handleResetPasswordRedirect(c *Ctx) error {
	token := c.Param("token")
	callbackURL := c.Query("callbackURL")
	if callbackURL == "" {
		// Links emailed before ResetPasswordURL was configured, or by a
		// caller that passed no redirectTo, carry no callback. Fall back
		// to the configured page so an old link in someone's inbox still
		// works after the operator fixes their configuration.
		callbackURL = a.config.EmailAndPassword.ResetPasswordURL
	}
	if callbackURL == "" {
		a.logger.Error("go-dev-auth: a password reset link was followed but there is " +
			"nowhere to send the user; set EmailAndPassword.ResetPasswordURL")
		return c.Redirect(c.BaseURL() + "/error")
	}
	if _, err := a.LookupToken(c.Context(), tokenKindResetPassword, token); err != nil {
		return c.Redirect(c.BaseURL() + "/error")
	}
	if to, ok := a.safeRedirect(callbackURL); ok {
		return c.Redirect(withQuery(to, "token", token))
	}
	return c.Redirect(c.BaseURL() + "/error")
}

type resetPasswordBody struct {
	NewPassword string `json:"newPassword"`
	Token       string `json:"token"`
}

func (a *Auth) handleResetPassword(c *Ctx) error {
	var body resetPasswordBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if body.Token == "" {
		body.Token = c.Query("token")
	}
	if body.Token == "" {
		return ErrInvalidToken
	}
	if err := a.validatePassword(body.NewPassword); err != nil {
		return err
	}
	ctx := c.Context()
	userID, err := a.ConsumeToken(ctx, tokenKindResetPassword, body.Token)
	if err != nil {
		return ErrInvalidToken
	}
	user, err := a.store.FindUserByID(ctx, userID)
	if err != nil {
		return ErrInvalidToken
	}
	hash, err := a.config.EmailAndPassword.PasswordHasher.Hash(body.NewPassword)
	if err != nil {
		return err
	}
	account, err := a.store.FindCredentialAccount(ctx, userID)
	if errors.Is(err, storage.ErrNotFound) {
		_, err = a.store.CreateAccount(ctx, &storage.Account{
			UserID: userID, AccountID: userID, ProviderID: "credential", Password: hash,
		})
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		if _, err := a.store.UpdateAccount(ctx, account.ID, map[string]any{"password": hash}); err != nil {
			return err
		}
	}
	// Password reset is the standard recovery path after a compromise,
	// so every existing session is revoked unless explicitly kept.
	revoked := false
	if !a.config.EmailAndPassword.KeepSessionsOnPasswordReset {
		_ = a.store.DeleteUserSessions(ctx, userID)
		revoked = true
	}
	a.EmitEvent(c, Event{Type: EventPasswordReset, ActorID: user.ID, Email: user.Email})
	if revoked {
		a.EmitEvent(c, Event{
			Type:    EventSessionRevoked,
			ActorID: user.ID,
			Email:   user.Email,
			Action:  "all_sessions_after_password_reset",
		})
	}
	if h := a.config.EmailAndPassword.OnPasswordReset; h != nil {
		_ = h(ctx, user)
	}
	return c.OK()
}

// ---- change / set password ----

type changePasswordBody struct {
	NewPassword         string `json:"newPassword"`
	CurrentPassword     string `json:"currentPassword"`
	RevokeOtherSessions bool   `json:"revokeOtherSessions"`
}

func (a *Auth) handleChangePassword(c *Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body changePasswordBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if err := a.validatePassword(body.NewPassword); err != nil {
		return err
	}
	ctx := c.Context()
	account, err := a.store.FindCredentialAccount(ctx, sd.User.ID)
	if err != nil {
		return ErrCredentialAccountNotFound
	}
	ok, err := a.config.EmailAndPassword.PasswordHasher.Verify(account.Password, body.CurrentPassword)
	if err != nil || !ok {
		a.EmitEvent(c, Event{
			Type:      EventPasswordChanged,
			Outcome:   OutcomeFailure,
			Reason:    ReasonInvalidPassword,
			ActorID:   sd.User.ID,
			Email:     sd.User.Email,
			SessionID: sd.Session.ID,
		})
		return ErrInvalidPassword
	}
	hash, err := a.config.EmailAndPassword.PasswordHasher.Hash(body.NewPassword)
	if err != nil {
		return err
	}
	if _, err := a.store.UpdateAccount(ctx, account.ID, map[string]any{"password": hash}); err != nil {
		return err
	}
	a.EmitEvent(c, Event{
		Type:      EventPasswordChanged,
		ActorID:   sd.User.ID,
		Email:     sd.User.Email,
		SessionID: sd.Session.ID,
	})
	// Changing a password is the other half of account recovery: a user
	// who does it to evict someone should not have to know to ask for
	// the other sessions to be dropped too. Reset already behaves this
	// way; this makes the pair consistent.
	token := ""
	if body.RevokeOtherSessions || !a.config.EmailAndPassword.KeepSessionsOnPasswordChange {
		_ = a.revokeOtherSessions(ctx, sd.User.ID, sd.Session.Token)
		token = sd.Session.Token
		a.EmitEvent(c, Event{
			Type:      EventSessionRevoked,
			ActorID:   sd.User.ID,
			Email:     sd.User.Email,
			SessionID: sd.Session.ID,
			Action:    "other_sessions_after_password_change",
		})
	}
	return c.JSON(http.StatusOK, map[string]any{
		"token": nullable(token),
		"user":  sd.User,
	})
}

type setPasswordBody struct {
	NewPassword         string `json:"newPassword"`
	RevokeOtherSessions bool   `json:"revokeOtherSessions"`
}

// handleSetPassword lets a social-only user add a credential account.
//
// There is no current password to ask for — that is the whole point of
// the endpoint — so the session is the only thing standing between a
// caller and a permanent, offline-usable credential for the account.
// That makes it the most valuable endpoint in the library to reach with
// a stolen cookie: it converts a session that expires, and that the
// owner can revoke, into a password that survives both. A fresh session
// is therefore required (as delete-user does), and the other sessions
// are dropped afterwards (as change-password does), so the change is
// both recent enough to be attributable and visible to the owner
// everywhere else they are signed in.
func (a *Auth) handleSetPassword(c *Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	if !a.IsFresh(sd.Session) {
		a.EmitEvent(c, Event{
			Type:      EventPasswordSet,
			Outcome:   OutcomeFailure,
			Reason:    ReasonSessionNotFresh,
			ActorID:   sd.User.ID,
			Email:     sd.User.Email,
			SessionID: sd.Session.ID,
		})
		return ErrSessionNotFresh
	}
	var body setPasswordBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if err := a.validatePassword(body.NewPassword); err != nil {
		return err
	}
	ctx := c.Context()
	if _, err := a.store.FindCredentialAccount(ctx, sd.User.ID); err == nil {
		return NewAPIError(http.StatusBadRequest, "PASSWORD_ALREADY_SET",
			"A password is already set. Use change-password instead.")
	}
	hash, err := a.config.EmailAndPassword.PasswordHasher.Hash(body.NewPassword)
	if err != nil {
		return err
	}
	if _, err := a.store.CreateAccount(ctx, &storage.Account{
		UserID: sd.User.ID, AccountID: sd.User.ID, ProviderID: "credential", Password: hash,
	}); err != nil {
		return err
	}
	a.EmitEvent(c, Event{
		Type:      EventPasswordSet,
		ActorID:   sd.User.ID,
		Email:     sd.User.Email,
		SessionID: sd.Session.ID,
	})
	// Same rule as change-password, and for the same reason: the way
	// this account is accessed just changed, so every other session
	// re-authenticates under the new arrangement.
	token := ""
	if body.RevokeOtherSessions || !a.config.EmailAndPassword.KeepSessionsOnPasswordChange {
		_ = a.revokeOtherSessions(ctx, sd.User.ID, sd.Session.Token)
		token = sd.Session.Token
		a.EmitEvent(c, Event{
			Type:      EventSessionRevoked,
			ActorID:   sd.User.ID,
			Email:     sd.User.Email,
			SessionID: sd.Session.ID,
			Action:    "other_sessions_after_password_set",
		})
	}
	return c.JSON(http.StatusOK, map[string]any{
		"status": true,
		"token":  nullable(token),
	})
}

// ---- helpers ----

func (a *Auth) validatePassword(password string) error {
	if len(password) < a.config.EmailAndPassword.MinPasswordLength {
		return ErrPasswordTooShort
	}
	if len(password) > a.config.EmailAndPassword.MaxPasswordLength {
		return ErrPasswordTooLong
	}
	return nil
}

func validateEmail(email string) error {
	email = strings.TrimSpace(email)
	at := strings.LastIndex(email, "@")
	if len(email) < 3 || len(email) > 254 || at <= 0 || at == len(email)-1 {
		return ErrInvalidEmail
	}
	if strings.ContainsAny(email, " \t\r\n") {
		return ErrInvalidEmail
	}
	domain := email[at+1:]
	if !strings.Contains(domain, ".") && domain != "localhost" {
		return ErrInvalidEmail
	}
	return nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// CreateSessionFor is a helper for plugins: it creates a session +
// cookie for the given user on this request.
func (a *Auth) CreateSessionFor(c *Ctx, user *storage.User, rememberMe bool) (*storage.Session, error) {
	return a.createSession(c, user, rememberMe, nil)
}

// InternalDB helpers exposed to plugins.

// FindUserByID loads a user by ID.
func (a *Auth) FindUserByID(ctx context.Context, id string) (*storage.User, error) {
	return a.store.FindUserByID(ctx, id)
}

// FindUserByEmail loads a user by email.
func (a *Auth) FindUserByEmail(ctx context.Context, email string) (*storage.User, error) {
	return a.store.FindUserByEmail(ctx, email)
}

// CreateUser creates a user record.
func (a *Auth) CreateUser(ctx context.Context, u *storage.User) (*storage.User, error) {
	return a.store.CreateUser(ctx, u)
}

// UpdateUserRecord applies an update to a user.
func (a *Auth) UpdateUserRecord(ctx context.Context, id string, update map[string]any) (*storage.User, error) {
	return a.store.UpdateUser(ctx, id, update)
}

// CreateCredentialAccount creates a credential account with a
// pre-hashed password for a user.
func (a *Auth) CreateCredentialAccount(ctx context.Context, userID, passwordHash string) error {
	_, err := a.store.CreateAccount(ctx, &storage.Account{
		UserID: userID, AccountID: userID, ProviderID: "credential", Password: passwordHash,
	})
	return err
}

// SetCredentialPassword sets (creating if needed) the hashed password of
// a user's credential account.
func (a *Auth) SetCredentialPassword(ctx context.Context, userID, passwordHash string) error {
	account, err := a.store.FindCredentialAccount(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return a.CreateCredentialAccount(ctx, userID, passwordHash)
		}
		return err
	}
	_, err = a.store.UpdateAccount(ctx, account.ID, map[string]any{"password": passwordHash})
	return err
}

// ListSessions lists all sessions of a user.
func (a *Auth) ListSessions(ctx context.Context, userID string) ([]*storage.Session, error) {
	return a.store.ListUserSessions(ctx, userID)
}

// DeleteUserByID removes a user with all sessions and accounts.
func (a *Auth) DeleteUserByID(ctx context.Context, userID string) error {
	return a.store.DeleteUser(ctx, userID)
}

// FindCredentialAccountByUser loads the credential (password) account of
// a user.
func (a *Auth) FindCredentialAccountByUser(ctx context.Context, userID string) (*storage.Account, error) {
	return a.store.FindCredentialAccount(ctx, userID)
}

// CreateVerificationValue stores a short-lived verification value.
func (a *Auth) CreateVerificationValue(ctx context.Context, identifier, value string, expiresIn time.Duration) (*storage.Verification, error) {
	return a.store.CreateVerification(ctx, identifier, value, expiresIn)
}

// FindVerificationValue retrieves a live verification value.
func (a *Auth) FindVerificationValue(ctx context.Context, identifier string) (*storage.Verification, error) {
	return a.store.FindVerification(ctx, identifier)
}

// DeleteVerificationValue removes a verification record by id.
func (a *Auth) DeleteVerificationValue(ctx context.Context, id string) error {
	return a.store.DeleteVerification(ctx, id)
}
