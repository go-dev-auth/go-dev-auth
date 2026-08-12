package godevauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/oauth2"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

type signInSocialBody struct {
	Provider           string   `json:"provider"`
	CallbackURL        string   `json:"callbackURL"`
	NewUserCallbackURL string   `json:"newUserCallbackURL"`
	ErrorCallbackURL   string   `json:"errorCallbackURL"`
	DisableRedirect    bool     `json:"disableRedirect"`
	Scopes             []string `json:"scopes"`
	LoginHint          string   `json:"loginHint"`
	RequestSignUp      bool     `json:"requestSignUp"`
	IDToken            *struct {
		Token string `json:"token"`
		Nonce string `json:"nonce"`
	} `json:"idToken"`
}

type oauthState struct {
	// Provider pins the state to the provider that issued it, so a
	// state minted for one provider cannot be replayed at another's
	// callback.
	Provider           string   `json:"provider"`
	CallbackURL        string   `json:"callbackURL,omitempty"`
	NewUserCallbackURL string   `json:"newUserCallbackURL,omitempty"`
	ErrorCallbackURL   string   `json:"errorCallbackURL,omitempty"`
	CodeVerifier       string   `json:"codeVerifier,omitempty"`
	LinkUserID         string   `json:"linkUserId,omitempty"`
	RequestSignUp      bool     `json:"requestSignUp,omitempty"`
	Scopes             []string `json:"scopes,omitempty"`
}

func (a *Auth) handleSignInSocial(c *Ctx) error {
	var body signInSocialBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	provider := a.SocialProvider(body.Provider)
	if provider == nil {
		return ErrProviderNotFound
	}

	// native SDK flow: verify a provider-issued ID token directly
	if body.IDToken != nil && body.IDToken.Token != "" {
		verifier, ok := provider.(oauth2.IDTokenVerifier)
		if !ok {
			return NewAPIError(http.StatusBadRequest, "ID_TOKEN_NOT_SUPPORTED",
				"Provider does not support id_token verification")
		}
		profile, valid := verifier.VerifyIDToken(c.Context(), body.IDToken.Token, body.IDToken.Nonce)
		if !valid {
			return ErrInvalidToken
		}
		c.SetAuthMethod(body.Provider)
		user, isNew, err := a.resolveOAuthUser(c.Context(), body.Provider, profile, nil, body.RequestSignUp)
		if err != nil {
			return err
		}
		if isNew {
			a.EmitEvent(c, Event{Type: EventSignUp, ActorID: user.ID, Email: user.Email, Method: body.Provider})
		}
		sess, handled, err := a.SignInUser(c, user, true)
		if err != nil {
			return err
		}
		if handled {
			return nil
		}
		return c.JSON(http.StatusOK, map[string]any{
			"redirect":  false,
			"token":     sess.Token,
			"user":      user,
			"isNewUser": isNew,
		})
	}

	state, authURL, err := a.startOAuthFlow(c, provider, oauthState{
		Provider:           body.Provider,
		CallbackURL:        body.CallbackURL,
		NewUserCallbackURL: body.NewUserCallbackURL,
		ErrorCallbackURL:   body.ErrorCallbackURL,
		RequestSignUp:      body.RequestSignUp,
		Scopes:             body.Scopes,
	}, body.LoginHint)
	if err != nil {
		return err
	}
	_ = state
	if body.DisableRedirect {
		return c.JSON(http.StatusOK, map[string]any{"url": authURL, "redirect": false})
	}
	return c.JSON(http.StatusOK, map[string]any{"url": authURL, "redirect": true})
}

// startOAuthFlow mints the state, binds it to this browser with a
// cookie and builds the provider authorization URL.
func (a *Auth) startOAuthFlow(c *Ctx, provider oauth2.Provider, st oauthState, loginHint string) (string, string, error) {
	state := oauth2.GenerateState()
	st.CodeVerifier = oauth2.GenerateCodeVerifier()
	if err := a.storeOAuthState(c.Context(), state, &st); err != nil {
		return "", "", err
	}
	// Binding the state to a cookie is what makes the callback
	// unforgeable: without it an attacker can complete their own
	// authorization and hand the resulting callback URL to a victim,
	// silently signing the victim into the attacker's account.
	a.setOAuthStateCookie(c.W, state)

	authURL, err := provider.AuthorizationURL(oauth2.AuthorizeRequest{
		State:        state,
		RedirectURI:  a.callbackURL(provider.ID()),
		Scopes:       st.Scopes,
		CodeVerifier: st.CodeVerifier,
		LoginHint:    loginHint,
	})
	if err != nil {
		return "", "", err
	}
	return state, authURL, nil
}

// CallbackURL returns the redirect URI to register with a provider's
// developer console for the given provider id, e.g.
//
//	auth.CallbackURL("google") // https://app.example.com/api/auth/callback/google
//
// It is derived from BaseURL and BasePath, so it stays correct when
// either changes. Registering a URI that does not match this exactly is
// the most common cause of a provider rejecting the flow, and the error
// the provider returns rarely says so — print this at startup rather
// than assembling the string by hand.
func (a *Auth) CallbackURL(providerID string) string {
	return a.callbackURL(providerID)
}

func (a *Auth) callbackURL(providerID string) string {
	return a.config.BaseURL + a.config.BasePath + "/callback/" + providerID
}

func (a *Auth) storeOAuthState(ctx context.Context, state string, st *oauthState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return a.StoreTokenValue(ctx, tokenKindOAuthState, state, string(raw), 10*time.Minute)
}

func (a *Auth) loadOAuthState(ctx context.Context, state string) (*oauthState, error) {
	value, err := a.ConsumeToken(ctx, tokenKindOAuthState, state)
	if err != nil {
		return nil, err
	}
	var st oauthState
	if err := json.Unmarshal([]byte(value), &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (a *Auth) handleOAuthCallback(c *Ctx) error {
	providerID := c.Param("provider")
	provider := a.SocialProvider(providerID)
	if provider == nil {
		return ErrProviderNotFound
	}
	// support both GET (query) and POST form_post (Apple)
	query := c.R.URL.Query()
	if c.R.Method == http.MethodPost {
		_ = c.R.ParseForm()
		query = c.R.Form
	}
	state := query.Get("state")
	code := query.Get("code")
	oauthErr := query.Get("error")

	stateCookie := a.readOAuthStateCookie(c.R)
	a.clearOAuthStateCookie(c.W)

	errorRedirect := func(st *oauthState, code string) error {
		target := a.config.BaseURL + a.config.BasePath + "/error"
		if st != nil && st.ErrorCallbackURL != "" {
			if to, ok := a.safeRedirect(st.ErrorCallbackURL); ok {
				target = to
			}
		} else if st != nil && st.CallbackURL != "" {
			if to, ok := a.safeRedirect(st.CallbackURL); ok {
				target = to
			}
		}
		return c.Redirect(withQuery(target, "error", code))
	}

	if state == "" || stateCookie == "" || !crypto.ConstantTimeEqual(state, stateCookie) {
		// Either the flow did not start in this browser, or the state
		// was replayed from elsewhere.
		return errorRedirect(nil, "state_mismatch")
	}
	st, err := a.loadOAuthState(c.Context(), state)
	if err != nil {
		return errorRedirect(nil, "state_mismatch")
	}
	if st.Provider != "" && st.Provider != providerID {
		return errorRedirect(st, "state_mismatch")
	}
	if oauthErr != "" {
		return errorRedirect(st, oauthErr)
	}
	if code == "" {
		return errorRedirect(st, "missing_code")
	}

	tokens, err := provider.Exchange(c.Context(), code, st.CodeVerifier, a.callbackURL(providerID))
	if err != nil {
		a.logger.Error("go-dev-auth: oauth code exchange failed", "provider", providerID, "err", err)
		return errorRedirect(st, "code_exchange_failed")
	}
	profile, err := provider.UserInfo(c.Context(), tokens)
	if err != nil {
		a.logger.Error("go-dev-auth: oauth user info failed", "provider", providerID, "err", err)
		return errorRedirect(st, "user_info_failed")
	}

	// explicit account linking flow
	if st.LinkUserID != "" {
		// Re-check the live session: the link was authorized by the
		// session that started the flow and must still be that session.
		sd, err := c.Session()
		if err != nil || sd == nil || sd.User.ID != st.LinkUserID {
			return errorRedirect(st, "session_mismatch")
		}
		if err := a.linkOAuthAccount(c.Context(), sd.User, providerID, profile, tokens); err != nil {
			var apiErr *APIError
			if errors.As(err, &apiErr) {
				a.EmitEvent(c, Event{
					Type: EventAccountLinked, Outcome: OutcomeFailure, Reason: eventReasonFor(err),
					ActorID: sd.User.ID, Email: sd.User.Email, Method: providerID,
				})
				return errorRedirect(st, apiErr.Code)
			}
			return errorRedirect(st, "link_failed")
		}
		// A new provider identity on an account is a new way in, so it
		// belongs in the trail next to password changes.
		a.EmitEvent(c, Event{
			Type: EventAccountLinked, ActorID: sd.User.ID, Email: sd.User.Email,
			SessionID: sd.Session.ID, Method: providerID,
		})
		target := a.config.BaseURL
		if st.CallbackURL != "" {
			if to, ok := a.safeRedirect(st.CallbackURL); ok {
				target = to
			}
		}
		return c.Redirect(target)
	}

	c.SetAuthMethod(providerID)
	user, isNew, err := a.resolveOAuthUser(c.Context(), providerID, profile, tokens, st.RequestSignUp)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			a.EmitEvent(c, Event{
				Type: EventSignIn, Outcome: OutcomeFailure, Reason: eventReasonFor(err),
				Email: profile.Email, Method: providerID,
			})
			return errorRedirect(st, apiErr.Code)
		}
		return errorRedirect(st, "internal_error")
	}
	if isNew {
		a.EmitEvent(c, Event{Type: EventSignUp, ActorID: user.ID, Email: user.Email, Method: providerID})
	}
	if _, handled, err := a.SignInUser(c, user, true); err != nil {
		return errorRedirect(st, "internal_error")
	} else if handled {
		return nil
	}
	target := a.config.BaseURL
	if isNew && st.NewUserCallbackURL != "" {
		if to, ok := a.safeRedirect(st.NewUserCallbackURL); ok {
			target = to
		}
	} else if st.CallbackURL != "" {
		if to, ok := a.safeRedirect(st.CallbackURL); ok {
			target = to
		}
	}
	return c.Redirect(target)
}

// resolveOAuthUser finds or creates the user for an OAuth profile,
// applying account linking rules.
func (a *Auth) resolveOAuthUser(ctx context.Context, providerID string, profile *oauth2.UserProfile, tokens *oauth2.Tokens, requestSignUp bool) (*storage.User, bool, error) {
	// existing account?
	account, err := a.store.FindAccount(ctx, providerID, profile.ID)
	if err == nil {
		user, err := a.store.FindUserByID(ctx, account.UserID)
		if err != nil {
			return nil, false, err
		}
		if tokens != nil {
			update, err := a.tokenUpdate(account.ID, tokens)
			if err != nil {
				return nil, false, err
			}
			_, _ = a.store.UpdateAccount(ctx, account.ID, update)
		}
		return user, false, nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return nil, false, err
	}

	// account linking by e-mail
	if profile.Email != "" && !a.config.Account.AccountLinking.Disabled {
		existing, err := a.store.FindUserByEmail(ctx, profile.Email)
		if err == nil {
			// Both conditions are required. A provider-asserted
			// "verified" flag alone is not enough: several providers
			// let users set an arbitrary address, which is exactly the
			// nOAuth account-takeover pattern. The deployment must also
			// have named the provider as trusted.
			if !profile.EmailVerified || !a.isTrustedProvider(providerID) {
				return nil, false, NewAPIError(http.StatusUnauthorized, "ACCOUNT_NOT_LINKED",
					"Account not linked. Sign in with your original method, then link this provider from your account settings.")
			}
			if err := a.linkOAuthAccount(ctx, existing, providerID, profile, tokens); err != nil {
				return nil, false, err
			}
			return existing, false, nil
		}
		if !errors.Is(err, storage.ErrNotFound) {
			return nil, false, err
		}
	}

	if a.config.DisableSocialSignUp && !requestSignUp {
		return nil, false, NewAPIError(http.StatusForbidden, "SIGNUP_DISABLED",
			"Sign up is disabled")
	}

	// new user
	user, err := a.store.CreateUser(ctx, &storage.User{
		Name:          profile.Name,
		Email:         profile.Email,
		EmailVerified: profile.EmailVerified,
		Image:         profile.Image,
	})
	if err != nil {
		if isUniqueViolation(err) {
			// lost a race with a concurrent sign-up for this address
			return nil, false, NewAPIError(http.StatusUnauthorized, "ACCOUNT_NOT_LINKED",
				"Account not linked. Sign in with your original method.")
		}
		return nil, false, err
	}
	if err := a.linkOAuthAccount(ctx, user, providerID, profile, tokens); err != nil {
		return nil, false, err
	}
	return user, true, nil
}

func (a *Auth) isTrustedProvider(providerID string) bool {
	for _, p := range a.config.Account.AccountLinking.TrustedProviders {
		if p == providerID {
			return true
		}
	}
	return false
}

// tokenUpdate builds the account-table update for a fresh token set.
//
// accountID is the row the update will be applied to. It is required:
// the ciphertext is bound to (account, accountID, field), so writing it
// anywhere else makes it unreadable — which is exactly the property
// that stops it being relocated.
func (a *Auth) tokenUpdate(accountID string, tokens *oauth2.Tokens) (map[string]any, error) {
	update := map[string]any{}
	if tokens.AccessToken != "" {
		enc, err := a.maybeEncrypt(accountBinding(accountID, "accessToken"), tokens.AccessToken)
		if err != nil {
			return nil, err
		}
		update["accessToken"] = enc
		update["accessTokenExpiresAt"] = tokens.AccessTokenExpiresAt
	}
	if tokens.RefreshToken != "" {
		enc, err := a.maybeEncrypt(accountBinding(accountID, "refreshToken"), tokens.RefreshToken)
		if err != nil {
			return nil, err
		}
		update["refreshToken"] = enc
		update["refreshTokenExpiresAt"] = tokens.RefreshTokenExpiresAt
	}
	if tokens.IDToken != "" {
		update["idToken"] = tokens.IDToken
	}
	if tokens.Scope != "" {
		update["scope"] = tokens.Scope
	}
	return update, nil
}

// linkOAuthAccount attaches a provider identity to a user, enforcing
// the configured linking policy.
//
// It is create-then-handle-conflict, not check-then-create: the row is
// inserted and a unique-constraint failure on (providerId, accountId) is
// what tells us the identity is already linked. That closes the TOCTOU
// window in which two concurrent callbacks for the same external identity
// each pass a "does it exist yet?" check and then both insert — the
// database, which now carries the composite unique constraint, is the
// arbiter, so exactly one row can ever exist for an external identity.
func (a *Auth) linkOAuthAccount(ctx context.Context, user *storage.User, providerID string, profile *oauth2.UserProfile, tokens *oauth2.Tokens) error {
	linking := a.config.Account.AccountLinking

	if linking.Disabled {
		// Linking is off, so a provider identity may only be attached
		// to the user it just created.
		if accounts, err := a.store.ListUserAccounts(ctx, user.ID); err == nil && len(accounts) > 0 {
			return NewAPIError(http.StatusForbidden, "ACCOUNT_LINKING_DISABLED",
				"Account linking is disabled")
		}
	} else if !linking.AllowDifferentEmails && profile.Email != "" && user.Email != "" &&
		!strings.EqualFold(normalizeEmail(profile.Email), user.Email) {
		return NewAPIError(http.StatusBadRequest, "EMAIL_MISMATCH",
			"The provider account's email does not match this account")
	}

	// The token ciphertext is bound to the row id, so the id has to
	// exist before the tokens are sealed. Generate it here rather than
	// letting CreateAccount do it, and hand the same value to both.
	acc := &storage.Account{
		ID:         a.store.generateID(storage.ModelAccount),
		UserID:     user.ID,
		AccountID:  profile.ID,
		ProviderID: providerID,
	}
	if tokens != nil {
		access, err := a.maybeEncrypt(accountBinding(acc.ID, "accessToken"), tokens.AccessToken)
		if err != nil {
			return err
		}
		refresh, err := a.maybeEncrypt(accountBinding(acc.ID, "refreshToken"), tokens.RefreshToken)
		if err != nil {
			return err
		}
		acc.AccessToken = access
		acc.RefreshToken = refresh
		acc.IDToken = tokens.IDToken
		acc.AccessTokenExpiresAt = tokens.AccessTokenExpiresAt
		acc.RefreshTokenExpiresAt = tokens.RefreshTokenExpiresAt
		acc.Scope = tokens.Scope
	}
	if _, err := a.store.CreateAccount(ctx, acc); err != nil {
		if !isUniqueViolation(err) {
			return err
		}
		// The database refused a second row for this external identity.
		// Load the row that won and reconcile: linking to the same user is
		// idempotent, linking to a different one is a conflict.
		existing, ferr := a.store.FindAccount(ctx, providerID, profile.ID)
		if ferr != nil {
			// The conflict was not on (providerId, accountId) after all
			// (e.g. a generated-id collision); report the original error.
			return err
		}
		if existing.UserID == user.ID {
			return nil // already linked to this user
		}
		return NewAPIError(http.StatusBadRequest, "ACCOUNT_ALREADY_LINKED",
			"This provider account is already linked to another user")
	}
	return nil
}
