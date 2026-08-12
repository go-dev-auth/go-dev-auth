package godevauth

import (
	"context"
	"time"

	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// Token kinds used by the core. Plugins pass their own kind strings.
const (
	tokenKindResetPassword = "reset-password"
	tokenKindEmailVerify   = "email-verification"
	tokenKindChangeEmail   = "change-email"
	tokenKindDeleteAccount = "delete-account"
	tokenKindOAuthState    = "oauth-state"
)

// tokenIdentifier is the value stored in the verification table's
// identifier column. The raw token is never stored: only a SHA-256
// digest, so read access to the database (a backup, a replica, a slow
// query log) does not hand out working password-reset or magic links.
func tokenIdentifier(kind, token string) string {
	return kind + ":" + crypto.HashToken(token)
}

// StoreToken persists value under a one-time token of the given kind
// and returns the token to embed in a link or email. Only the token's
// digest is written to the database.
func (a *Auth) StoreToken(ctx context.Context, kind, value string, ttl time.Duration) (string, error) {
	token := crypto.GenerateToken(24)
	if _, err := a.store.CreateVerification(ctx, tokenIdentifier(kind, token), value, ttl); err != nil {
		return "", err
	}
	return token, nil
}

// StoreTokenValue persists value under a caller-supplied token. Use it
// when the token itself is generated elsewhere, or to replace the value
// stored against an existing token.
//
// Any previous record for the same token is removed first. Without
// that, storing again would append a second row: lookups return only
// the newest, but consuming deletes only that one, leaving the older
// rows redeemable. That is how a two-factor challenge could survive its
// own attempt counter and be replayed for extra sessions.
func (a *Auth) StoreTokenValue(ctx context.Context, kind, token, value string, ttl time.Duration) error {
	identifier := tokenIdentifier(kind, token)
	if err := a.store.DeleteVerificationsByIdentifier(ctx, identifier); err != nil {
		return err
	}
	_, err := a.store.CreateVerification(ctx, identifier, value, ttl)
	return err
}

// LookupToken returns the stored verification for a token without
// consuming it.
func (a *Auth) LookupToken(ctx context.Context, kind, token string) (*storage.Verification, error) {
	if token == "" {
		return nil, storage.ErrNotFound
	}
	return a.store.FindVerification(ctx, tokenIdentifier(kind, token))
}

// ConsumeToken looks a token up and deletes it, returning its stored
// value. It is the single-use path every one-time link should take.
//
// The delete is the claim: only the caller whose delete actually
// removed a row is handed the value. A plain lookup-then-delete would
// let concurrent requests all read the row before any of them removed
// it and all proceed — turning every one-time link (password reset,
// magic link, account deletion, OAuth state) into a multi-use one under
// load.
func (a *Auth) ConsumeToken(ctx context.Context, kind, token string) (string, error) {
	v, err := a.LookupToken(ctx, kind, token)
	if err != nil {
		return "", err
	}
	claimed, err := a.config.Database.DeleteMany(ctx, storage.ModelVerification,
		[]storage.Where{storage.W("id", v.ID)})
	if err != nil {
		return "", err
	}
	if claimed != 1 {
		return "", storage.ErrNotFound
	}
	return v.Value, nil
}

// CleanupExpired deletes expired verification records and expired
// sessions, returning how many rows were removed. Run it periodically:
// one-time tokens that are never clicked are otherwise never collected,
// and both tables grow without bound.
//
//	stop := auth.StartCleanup(context.Background(), time.Hour)
//	defer stop()
func (a *Auth) CleanupExpired(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	expired := []storage.Where{{Field: "expiresAt", Operator: storage.OpLte, Value: now}}
	verifications, err := a.config.Database.DeleteMany(ctx, storage.ModelVerification, expired)
	if err != nil {
		return 0, err
	}
	sessions, err := a.config.Database.DeleteMany(ctx, storage.ModelSession, expired)
	if err != nil {
		return verifications, err
	}
	return verifications + sessions, nil
}

// StartCleanup runs CleanupExpired on an interval in the background and
// returns a function that stops it. A zero or negative interval
// defaults to one hour.
func (a *Auth) StartCleanup(ctx context.Context, interval time.Duration) (stop func()) {
	if interval <= 0 {
		interval = time.Hour
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := a.CleanupExpired(ctx)
				if err != nil {
					a.logger.Error("go-dev-auth: cleanup failed", "err", err)
					continue
				}
				if n > 0 {
					a.logger.Debug("go-dev-auth: cleaned up expired records", "count", n)
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}
