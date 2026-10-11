// Package jwt issues JSON Web Tokens for authenticated sessions and
// serves the corresponding JWKS endpoint, mirroring better-auth's jwt
// plugin. Tokens are signed with EdDSA (Ed25519) by default; the signing
// key is generated on first use and stored (private key encrypted) in
// the database.
package jwt

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// ModelJWKS is the table storing signing keys.
const ModelJWKS = "jwks"

// fieldPrivateKey is the column holding the encrypted private half.
const fieldPrivateKey = "privateKey"

// binding names where an encrypted signing key lives. The private half
// is sealed against it, so the ciphertext cannot be moved to another
// row or another table and read back through an endpoint that returns
// plaintext (the two-factor plugin's TOTP-URI endpoint being the
// obvious one).
//
// The record component is the kid, which is also the row's primary key
// and is generated before the key is encrypted.
func binding(kid string) crypto.Binding {
	return crypto.Binding{Model: ModelJWKS, Record: kid, Field: fieldPrivateKey}
}

// Options configures the jwt plugin.
type Options struct {
	// Issuer defaults to BaseURL.
	Issuer string
	// Audience defaults to BaseURL.
	Audience string
	// ExpiresIn defaults to 15 minutes.
	ExpiresIn time.Duration
	// DefinePayload customizes claims derived from the session.
	DefinePayload func(sd *godevauth.SessionData) map[string]any
	// DisableSettingJwtHeader disables the `set-auth-jwt` header on
	// /get-session responses.
	DisableSettingJwtHeader bool
}

// Plugin implements the jwt plugin.
type Plugin struct {
	opts Options
	auth *godevauth.Auth

	// The signing key is loaded once and cached: it was previously
	// fetched and AEAD-decrypted on every /token, /jwks and Verify
	// call, and two concurrent cold starts could each insert a key,
	// leaving tokens signed by a key the JWKS endpoint never published.
	keyMu   sync.Mutex
	signing *signingKey

	// pubKeys caches stored public keys by kid for verification. Public
	// keys are not secret and never change for a kid, so a plain cache
	// with a storage reload on miss lets Verify select the right key
	// across rotations and instances.
	pubMu   sync.RWMutex
	pubKeys map[string]ed25519.PublicKey
}

// New builds the plugin.
func New(opts ...Options) *Plugin {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.ExpiresIn == 0 {
		o.ExpiresIn = 15 * time.Minute
	}
	return &Plugin{opts: o}
}

// ID implements godevauth.Plugin.
func (p *Plugin) ID() string { return "jwt" }

// Init implements godevauth.Plugin.
func (p *Plugin) Init(a *godevauth.Auth) error {
	p.auth = a
	return nil
}

func (p *Plugin) issuer() string {
	if p.opts.Issuer != "" {
		return p.opts.Issuer
	}
	return p.auth.Config().BaseURL
}

func (p *Plugin) audience() string {
	if p.opts.Audience != "" {
		return p.opts.Audience
	}
	return p.auth.Config().BaseURL
}

// Schema implements godevauth.SchemaPlugin.
func (p *Plugin) Schema(s *storage.Schema) {
	s.AddTable(&storage.Table{Name: ModelJWKS, Fields: []storage.Field{
		{Name: "id", Type: storage.FieldString, Required: true, Unique: true},
		{Name: "publicKey", Type: storage.FieldText, Required: true},
		{Name: "privateKey", Type: storage.FieldText, Required: true},
		{Name: "createdAt", Type: storage.FieldTime, Required: true},
	}})
}

// Routes implements godevauth.Plugin.
func (p *Plugin) Routes() []godevauth.Route {
	return []godevauth.Route{
		{Method: http.MethodGet, Path: "/token", Handler: p.handleToken},
		{Method: http.MethodGet, Path: "/jwks", Handler: p.handleJWKS},
		{Method: http.MethodGet, Path: "/.well-known/jwks.json", Handler: p.handleJWKS},
	}
}

type signingKey struct {
	kid  string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// loadOrCreateKey returns the cached signing key, loading or creating
// it on first use.
func (p *Plugin) loadOrCreateKey(ctx context.Context) (*signingKey, error) {
	p.keyMu.Lock()
	defer p.keyMu.Unlock()
	if p.signing != nil {
		return p.signing, nil
	}
	key, err := p.newestStoredKey(ctx)
	if err != nil {
		return nil, err
	}
	if key == nil {
		if key, err = p.createKey(ctx); err != nil {
			return nil, err
		}
	}
	p.signing = key
	return key, nil
}

func (p *Plugin) newestStoredKey(ctx context.Context) (*signingKey, error) {
	recs, err := p.auth.Storage().FindMany(ctx, ModelJWKS, nil,
		&storage.FindOptions{SortBy: &storage.SortBy{Field: "createdAt", Direction: "desc"}, Limit: 1})
	if err != nil || len(recs) == 0 {
		return nil, err
	}
	return p.decodeKey(recs[0])
}

// decodePublicKey reads only the public half of a stored key.
//
// Publishing a public key needs no secret at all, which is what makes
// JWKS resilient to a rotation: a key whose private half is no longer
// decryptable can still be published, so every token it ever signed
// stays verifiable.
func (p *Plugin) decodePublicKey(rec map[string]any) (*signingKey, error) {
	kid, _ := rec["id"].(string)
	pubRaw, _ := rec["publicKey"].(string)
	pub, err := base64.RawURLEncoding.DecodeString(pubRaw)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("jwt: stored key %q has a malformed public key", kid)
	}
	return &signingKey{kid: kid, pub: ed25519.PublicKey(pub)}, nil
}

// decodeKey reads a stored key including its private half, which is
// encrypted with the instance secret.
func (p *Plugin) decodeKey(rec map[string]any) (*signingKey, error) {
	key, err := p.decodePublicKey(rec)
	if err != nil {
		return nil, err
	}
	privEnc, _ := rec["privateKey"].(string)
	if privEnc == "" {
		return key, nil
	}
	// Through the keyring, so a key stored under a previous
	// Config.Secret is still readable while PreviousSecrets lists it.
	privRaw, err := p.auth.Keyring().Decrypt(binding(key.kid), privEnc)
	if err != nil {
		return nil, fmt.Errorf("jwt: stored signing key %q cannot be decrypted with any configured secret "+
			"(add the previous value of Config.Secret to Config.PreviousSecrets and run Auth.ReencryptSecrets): %w",
			key.kid, err)
	}
	priv, err := base64.RawURLEncoding.DecodeString(privRaw)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("jwt: stored key %q has a malformed private key", key.kid)
	}
	key.priv = ed25519.PrivateKey(priv)
	return key, nil
}

func (p *Plugin) createKey(ctx context.Context) (*signingKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	kid := crypto.GenerateID(16)
	privEnc, err := p.auth.Keyring().Encrypt(binding(kid), base64.RawURLEncoding.EncodeToString(priv))
	if err != nil {
		return nil, err
	}
	_, err = p.auth.Storage().Create(ctx, ModelJWKS, map[string]any{
		"id":         kid,
		"publicKey":  base64.RawURLEncoding.EncodeToString(pub),
		"privateKey": privEnc,
		"createdAt":  time.Now().UTC(),
	})
	if err != nil {
		// Another instance created a key concurrently; adopt theirs so
		// both sign with a key the JWKS endpoint publishes.
		if errors.Is(err, storage.ErrUniqueViolation) {
			if existing, ferr := p.newestStoredKey(ctx); ferr == nil && existing != nil {
				return existing, nil
			}
		}
		return nil, err
	}
	return &signingKey{kid: kid, priv: priv, pub: pub}, nil
}

// RotateKey generates a new signing key and starts signing with it.
// Previously issued tokens stay verifiable because /jwks continues to
// publish every stored public key until it is deleted.
func (p *Plugin) RotateKey(ctx context.Context) error {
	key, err := p.createKey(ctx)
	if err != nil {
		return err
	}
	p.keyMu.Lock()
	p.signing = key
	p.keyMu.Unlock()
	return nil
}

// SignSession issues a JWT for the given session data.
func (p *Plugin) SignSession(ctx context.Context, sd *godevauth.SessionData) (string, error) {
	key, err := p.loadOrCreateKey(ctx)
	if err != nil {
		return "", err
	}
	now := time.Now()
	var payload map[string]any
	if p.opts.DefinePayload != nil {
		payload = p.opts.DefinePayload(sd)
	} else {
		payload = map[string]any{
			"name":          sd.User.Name,
			"email":         sd.User.Email,
			"emailVerified": sd.User.EmailVerified,
			"image":         sd.User.Image,
		}
	}
	claims := crypto.Claims{
		"sub": sd.User.ID,
		"iss": p.issuer(),
		"aud": p.audience(),
		"iat": now.Unix(),
		"exp": now.Add(p.opts.ExpiresIn).Unix(),
	}
	for k, v := range payload {
		if _, reserved := claims[k]; !reserved {
			claims[k] = v
		}
	}
	return crypto.SignJWT(key.priv, key.kid, claims)
}

// Verify verifies a token issued by this plugin and returns its claims.
//
// The verifying key is selected by the token's own kid, from every
// stored public key — not just the one this process currently signs
// with. Without that, a token signed before a key rotation, or signed
// by another instance whose newest key this process has not cached,
// failed to verify even though its key is still published at /jwks. The
// iss and aud claims are checked too, so a token minted for a different
// audience is rejected rather than merely accepted as well-formed.
func (p *Plugin) Verify(ctx context.Context, token string) (crypto.Claims, error) {
	header, err := crypto.DecodeJWTHeader(token)
	if err != nil {
		return nil, err
	}
	pub, err := p.publicKeyByKID(ctx, header.Kid)
	if err != nil {
		return nil, err
	}
	claims, err := crypto.VerifyJWT(pub, token)
	if err != nil {
		return nil, err
	}
	if iss, _ := claims["iss"].(string); iss != p.issuer() {
		return nil, fmt.Errorf("jwt: issuer %q does not match %q", iss, p.issuer())
	}
	if !audienceContains(claims["aud"], p.audience()) {
		return nil, errors.New("jwt: audience does not match this application")
	}
	return claims, nil
}

// publicKeyByKID resolves a stored public key by its id. Results are
// cached (public keys are not secret and never change for a given kid),
// with a reload from storage on a cache miss so a key created by another
// instance is picked up.
func (p *Plugin) publicKeyByKID(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	if kid == "" {
		return nil, errors.New("jwt: token has no kid")
	}
	p.pubMu.RLock()
	pub, ok := p.pubKeys[kid]
	p.pubMu.RUnlock()
	if ok {
		return pub, nil
	}
	rec, err := p.auth.Storage().FindOne(ctx, ModelJWKS, []storage.Where{storage.W("id", kid)})
	if err != nil {
		return nil, fmt.Errorf("jwt: no signing key with id %q", kid)
	}
	key, err := p.decodePublicKey(rec)
	if err != nil {
		return nil, err
	}
	p.pubMu.Lock()
	if p.pubKeys == nil {
		p.pubKeys = map[string]ed25519.PublicKey{}
	}
	p.pubKeys[kid] = key.pub
	p.pubMu.Unlock()
	return key.pub, nil
}

// audienceContains reports whether aud (a string or an array of strings,
// as JWT allows) includes want.
func audienceContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func (p *Plugin) handleToken(c *godevauth.Ctx) error {
	sd, err := c.RequireSession()
	if err != nil {
		return err
	}
	token, err := p.SignSession(c.Context(), sd)
	if err != nil {
		return err
	}
	if !p.opts.DisableSettingJwtHeader {
		c.W.Header().Set("set-auth-jwt", token)
	}
	return c.JSON(http.StatusOK, map[string]any{"token": token})
}

// handleJWKS publishes every stored public key, not just the newest, so
// tokens signed before a rotation remain verifiable by relying parties.
//
// It decodes only the public halves. That matters: the previous version
// decrypted each private key on the way through and dropped, with a log
// line, any key it could not read. After a Config.Secret rotation that
// is every key — so the endpoint would quietly publish an incomplete
// key set and every token already in circulation would start failing
// verification at the relying party, which has no way to tell that
// apart from a forged token.
//
// Now an unreadable private key does not affect JWKS at all, and a key
// whose *public* half is corrupt fails the request loudly instead of
// silently shrinking the published set.
func (p *Plugin) handleJWKS(c *godevauth.Ctx) error {
	ctx := c.Context()
	newest := &storage.FindOptions{SortBy: &storage.SortBy{Field: "createdAt", Direction: "desc"}}
	recs, err := p.auth.Storage().FindMany(ctx, ModelJWKS, nil, newest)
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		// Cold start: mint the first key so the endpoint is never
		// empty. Deliberately only when nothing is stored — loading the
		// signing key unconditionally would decrypt a private key this
		// endpoint has no use for, and make publishing the public half
		// depend on a secret it does not need.
		if _, err := p.loadOrCreateKey(ctx); err != nil {
			return err
		}
		if recs, err = p.auth.Storage().FindMany(ctx, ModelJWKS, nil, newest); err != nil {
			return err
		}
	}
	keys := make([]crypto.JWK, 0, len(recs))
	for _, rec := range recs {
		key, err := p.decodePublicKey(rec)
		if err != nil {
			p.auth.Logger().Error("jwt: refusing to publish an incomplete key set", "err", err)
			return fmt.Errorf("jwt: cannot publish the key set: %w", err)
		}
		jwk, err := crypto.PublicJWK(key.kid, key.pub)
		if err != nil {
			p.auth.Logger().Error("jwt: refusing to publish an incomplete key set", "kid", key.kid, "err", err)
			return fmt.Errorf("jwt: cannot publish the key set: %w", err)
		}
		keys = append(keys, jwk)
	}
	c.W.Header().Set("Cache-Control", "max-age=3600")
	return c.JSON(http.StatusOK, crypto.JWKS{Keys: keys})
}

// ReencryptSecrets implements godevauth.SecretRotator: it rewrites the
// stored private keys under the current Config.Secret.
func (p *Plugin) ReencryptSecrets(ctx context.Context) (godevauth.ReencryptResult, error) {
	res, err := p.auth.ReencryptRecords(ctx, ModelJWKS, fieldPrivateKey)
	if err != nil {
		return res, err
	}
	// The cached signing key was decoded from the pre-rotation
	// ciphertext. The key material is unchanged, but dropping the cache
	// keeps the in-memory copy and the stored row in step.
	p.keyMu.Lock()
	p.signing = nil
	p.keyMu.Unlock()
	return res, nil
}

var _ godevauth.SecretRotator = (*Plugin)(nil)
