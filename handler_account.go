package godevauth

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/oauth2"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// encPrefix marks an account token as encrypted at rest. It is not part
// of the ciphertext: the value after it is a crypto.Keyring value, which
// carries its own version and key id.
const encPrefix = "enc:"

func hasEncPrefix(value string) bool {
	return len(value) > len(encPrefix) && value[:len(encPrefix)] == encPrefix
}

// accountBinding names where an account token lives, so the ciphertext
// only opens in that column of that row. accountID must be the id the
// row will be stored under: callers that encrypt before the row exists
// (see linkOAuthAccount) generate the id first.
func accountBinding(accountID, field string) crypto.Binding {
	return crypto.Binding{Model: storage.ModelAccount, Record: accountID, Field: field}
}

// maybeEncrypt encrypts an OAuth token at rest when configured. It
// returns an error rather than silently storing plaintext: an operator
// who asked for encryption must not end up with third-party credentials
// in the clear and no signal that it happened.
func (a *Auth) maybeEncrypt(b crypto.Binding, value string) (string, error) {
	if value == "" || !a.config.Account.EncryptOAuthTokens {
		return value, nil
	}
	enc, err := a.keyring.Encrypt(b, value)
	if err != nil {
		return "", fmt.Errorf("go-dev-auth: failed to encrypt oauth token: %w", err)
	}
	return encPrefix + enc, nil
}

// maybeDecrypt reverses maybeEncrypt.
//
// It returns an error when a value that announces itself as encrypted
// cannot be decrypted. The previous behaviour — returning the input
// unchanged — was the worst possible outcome of a rotated secret: the
// caller could not tell a plaintext token from a ciphertext one, and
// /refresh-token duly forwarded an "enc:..." blob to the OAuth
// provider, leaking a fragment of the encrypted store to a third party
// and reporting nothing.
func (a *Auth) maybeDecrypt(b crypto.Binding, value string) (string, error) {
	if !hasEncPrefix(value) {
		return value, nil
	}
	dec, err := a.keyring.Decrypt(b, value[len(encPrefix):])
	if err != nil {
		return "", fmt.Errorf("%w: %w", errTokenUndecryptable, err)
	}
	return dec, nil
}

// errTokenUndecryptable wraps a failure to read a stored token so
// handlers can report it as a server-side configuration problem rather
// than as bad input from the client.
var errTokenUndecryptable = errors.New("go-dev-auth: a stored token could not be decrypted with any configured secret")

// reportUndecryptableToken logs the failure with enough context for an
// operator to act on and converts it into an API error.
func (a *Auth) reportUndecryptableToken(c *Ctx, account *storage.Account, field string, err error) error {
	a.logger.Error("go-dev-auth: stored oauth token could not be decrypted; "+
		"if Config.Secret was rotated, add the previous secret to Config.PreviousSecrets and run Auth.ReencryptSecrets",
		"accountId", account.ID, "providerId", account.ProviderID, "field", field, "err", err)
	a.EmitEvent(c, Event{
		Type:     EventAdminAction,
		Action:   "oauth_token_decrypt",
		Outcome:  OutcomeFailure,
		Reason:   ReasonDecryptionFailed,
		TargetID: account.UserID,
		Method:   account.ProviderID,
	})
	return ErrTokenDecryptionFailed
}

func (a *Auth) handleListAccounts(c *Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	accounts, err := a.store.ListUserAccounts(c.Context(), sd.User.ID)
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(accounts))
	for _, acc := range accounts {
		out = append(out, map[string]any{
			"id":         acc.ID,
			"providerId": acc.ProviderID,
			"accountId":  acc.AccountID,
			"scopes":     acc.Scope,
			"createdAt":  acc.CreatedAt,
			"updatedAt":  acc.UpdatedAt,
		})
	}
	return c.JSON(http.StatusOK, out)
}

type linkSocialBody struct {
	Provider    string   `json:"provider"`
	CallbackURL string   `json:"callbackURL"`
	Scopes      []string `json:"scopes"`
}

func (a *Auth) handleLinkSocial(c *Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body linkSocialBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	provider := a.SocialProvider(body.Provider)
	if provider == nil {
		return ErrProviderNotFound
	}
	_, authURL, err := a.startOAuthFlow(c, provider, oauthState{
		Provider:    body.Provider,
		CallbackURL: body.CallbackURL,
		LinkUserID:  sd.User.ID,
		Scopes:      body.Scopes,
	}, "")
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"url": authURL, "redirect": true})
}

type unlinkAccountBody struct {
	ProviderID string `json:"providerId"`
	AccountID  string `json:"accountId"`
}

func (a *Auth) handleUnlinkAccount(c *Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body unlinkAccountBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if body.ProviderID == "" {
		return ErrInvalidBody
	}
	ctx := c.Context()
	accounts, err := a.store.ListUserAccounts(ctx, sd.User.ID)
	if err != nil {
		return err
	}
	if len(accounts) <= 1 && !a.config.Account.AccountLinking.AllowUnlinkingAll {
		return ErrFailedToUnlinkLastAccount
	}
	var target *storage.Account
	for _, acc := range accounts {
		if acc.ProviderID != body.ProviderID {
			continue
		}
		if body.AccountID != "" && acc.AccountID != body.AccountID {
			continue
		}
		target = acc
		break
	}
	if target == nil {
		return ErrAccountNotFound
	}
	if err := a.store.DeleteAccount(ctx, target.ID); err != nil {
		return err
	}
	a.EmitEvent(c, Event{
		Type:      EventAccountUnlinked,
		ActorID:   sd.User.ID,
		Email:     sd.User.Email,
		SessionID: sd.Session.ID,
		Method:    target.ProviderID,
	})
	return c.JSON(http.StatusOK, map[string]any{"status": true})
}

type refreshTokenBody struct {
	ProviderID string `json:"providerId"`
	AccountID  string `json:"accountId"`
}

func (a *Auth) handleRefreshToken(c *Ctx) error {
	// Refreshing mints a fresh third-party access token and returns it,
	// so it is only ever performed for the caller's own account.
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	var body refreshTokenBody
	if err := c.BindJSON(&body); err != nil {
		return err
	}
	if body.ProviderID == "" {
		return ErrInvalidBody
	}
	ctx := c.Context()
	userID := sd.User.ID

	var account *storage.Account
	accounts, err := a.store.ListUserAccounts(ctx, userID)
	if err != nil {
		return err
	}
	for _, acc := range accounts {
		if acc.ProviderID == body.ProviderID &&
			(body.AccountID == "" || acc.AccountID == body.AccountID) {
			account = acc
			break
		}
	}
	if account == nil {
		return ErrAccountNotFound
	}

	provider := a.SocialProvider(body.ProviderID)
	if provider == nil {
		return ErrProviderNotFound
	}
	refresher, ok := provider.(oauth2.RefreshableProvider)
	if !ok {
		return NewAPIError(http.StatusBadRequest, "REFRESH_NOT_SUPPORTED",
			"Provider does not support token refresh")
	}
	refreshToken, err := a.maybeDecrypt(accountBinding(account.ID, "refreshToken"), account.RefreshToken)
	if err != nil {
		return a.reportUndecryptableToken(c, account, "refreshToken", err)
	}
	if refreshToken == "" {
		return NewAPIError(http.StatusBadRequest, "NO_REFRESH_TOKEN",
			"No refresh token available for this account")
	}
	tokens, err := refresher.RefreshToken(ctx, refreshToken)
	if err != nil {
		return NewAPIError(http.StatusBadRequest, "FAILED_TO_REFRESH_TOKEN", "Failed to refresh token")
	}
	update, err := a.tokenUpdate(account.ID, tokens)
	if err != nil {
		return err
	}
	if _, err := a.store.UpdateAccount(ctx, account.ID, update); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{
		"accessToken":          tokens.AccessToken,
		"accessTokenExpiresAt": nullableTime(tokens.AccessTokenExpiresAt),
	})
}

func (a *Auth) handleAccountInfo(c *Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	accountID := c.Query("accountId")
	if accountID == "" {
		return ErrInvalidBody
	}
	accounts, err := a.store.ListUserAccounts(c.Context(), sd.User.ID)
	if err != nil {
		return err
	}
	for _, acc := range accounts {
		if acc.AccountID != accountID && acc.ID != accountID {
			continue
		}
		provider := a.SocialProvider(acc.ProviderID)
		if provider == nil {
			return ErrProviderNotFound
		}
		accessToken, err := a.maybeDecrypt(accountBinding(acc.ID, "accessToken"), acc.AccessToken)
		if err != nil {
			return a.reportUndecryptableToken(c, acc, "accessToken", err)
		}
		profile, err := provider.UserInfo(c.Context(), &oauth2.Tokens{
			AccessToken: accessToken,
		})
		if err != nil {
			return NewAPIError(http.StatusBadRequest, "FAILED_TO_GET_ACCOUNT_INFO",
				"Failed to get account info")
		}
		return c.JSON(http.StatusOK, map[string]any{
			"user": map[string]any{
				"id":            profile.ID,
				"name":          profile.Name,
				"email":         profile.Email,
				"emailVerified": profile.EmailVerified,
				"image":         profile.Image,
			},
			"data": profile.Raw,
		})
	}
	return ErrAccountNotFound
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

var _ = errors.Is
