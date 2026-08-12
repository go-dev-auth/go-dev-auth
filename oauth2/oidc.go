package oauth2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-dev-auth/go-dev-auth/crypto"
)

// JWKSCache fetches and caches a provider's JSON Web Key Set.
//
// An ID token is only meaningful if its signature is checked against
// the issuer's published keys. Providers rotate those keys, so the set
// is refetched when a token names an unknown key id — with a floor on
// how often that can happen, so an attacker cannot turn unknown-kid
// tokens into a request amplifier against the provider.
type JWKSCache struct {
	URL    string
	Client *http.Client
	// TTL is how long a fetched key set is reused. Defaults to 1 hour.
	TTL time.Duration
	// MinRefreshInterval bounds forced refreshes. Defaults to 1 minute.
	MinRefreshInterval time.Duration
	// StaleGrace is how long past the TTL a cached key may still be
	// served when refetching fails. Defaults to 15 minutes; after that
	// the cache fails closed so a revoked key cannot be trusted
	// indefinitely.
	StaleGrace time.Duration
	// FetchTimeout bounds a single JWKS request. Defaults to 5s.
	FetchTimeout time.Duration

	mu          sync.Mutex
	keys        map[string]any
	fetchedAt   time.Time
	lastAttempt time.Time
}

func (c *JWKSCache) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	// http.DefaultClient has no timeout; a hung JWKS endpoint would
	// otherwise stall verification indefinitely.
	return &http.Client{Timeout: c.fetchTimeout()}
}

func (c *JWKSCache) ttl() time.Duration {
	if c.TTL > 0 {
		return c.TTL
	}
	return time.Hour
}

func (c *JWKSCache) minRefresh() time.Duration {
	if c.MinRefreshInterval > 0 {
		return c.MinRefreshInterval
	}
	return time.Minute
}

// Key returns the public key with the given id, fetching the key set if
// it is missing or stale.
func (c *JWKSCache) Key(ctx context.Context, kid string) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fresh := time.Since(c.fetchedAt) < c.ttl()
	if key, ok := c.keys[kid]; ok && fresh {
		return key, nil
	}
	// Unknown kid or stale set: refetch, rate limited.
	if time.Since(c.lastAttempt) < c.minRefresh() {
		if key, ok := c.keys[kid]; ok && c.withinGrace() {
			return key, nil
		}
		return nil, fmt.Errorf("oauth2: unknown key id %q (refresh rate limited)", kid)
	}

	// The fetch runs on its own bounded context, not the caller's.
	// Deriving it from the request would let a client that disconnects
	// mid-verification fail the fetch, and the resulting cooldown would
	// then block every other caller: one request per minute would be
	// enough to stop the process from ever picking up a rotated signing
	// key.
	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.fetchTimeout())
	defer cancel()
	keys, err := c.fetch(fetchCtx)
	if err != nil {
		// Only a completed attempt starts the cooldown, so a failure
		// caused by the provider being briefly unreachable does not
		// hand an attacker a lever.
		if !errors.Is(err, context.Canceled) {
			c.lastAttempt = time.Now()
		}
		if key, ok := c.keys[kid]; ok && c.withinGrace() {
			// Serve a known key through a short outage rather than
			// failing every sign-in on one bad response.
			return key, nil
		}
		return nil, err
	}
	c.lastAttempt = time.Now()
	c.keys = keys
	c.fetchedAt = time.Now()
	key, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("oauth2: key id %q not present in %s", kid, c.URL)
	}
	return key, nil
}

// withinGrace reports whether cached keys are still young enough to be
// served when a refetch fails. Past this point the cache fails closed,
// so a key the provider has revoked cannot be trusted forever.
func (c *JWKSCache) withinGrace() bool {
	return time.Since(c.fetchedAt) < c.ttl()+c.staleGrace()
}

func (c *JWKSCache) staleGrace() time.Duration {
	if c.StaleGrace > 0 {
		return c.StaleGrace
	}
	return 15 * time.Minute
}

func (c *JWKSCache) fetchTimeout() time.Duration {
	if c.FetchTimeout > 0 {
		return c.FetchTimeout
	}
	return 5 * time.Second
}

func (c *JWKSCache) fetch(ctx context.Context) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("oauth2: jwks endpoint %s returned %d", c.URL, res.StatusCode)
	}
	var set crypto.JWKS
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("oauth2: parsing jwks: %w", err)
	}
	out := make(map[string]any, len(set.Keys))
	for _, jwk := range set.Keys {
		pub, err := jwk.PublicKey()
		if err != nil {
			continue // unsupported key type; ignore rather than fail the set
		}
		out[jwk.Kid] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("oauth2: jwks contained no usable keys")
	}
	return out, nil
}

// IDTokenConfig describes how to verify a provider's ID tokens.
type IDTokenConfig struct {
	// Issuer is the exact expected "iss" claim.
	Issuer string
	// JWKSURL publishes the issuer's signing keys.
	JWKSURL string
	// Audience is the expected "aud" claim; normally the client id.
	Audience string
	// MapClaims turns verified claims into a profile. When nil, the
	// standard OIDC claims are used.
	MapClaims func(claims crypto.Claims) *UserProfile
	// Leeway tolerates clock skew when checking exp/iat. Defaults to
	// 60 seconds.
	Leeway time.Duration
	// RequireNonce rejects verification attempts made without a nonce.
	// Set it for flows where the server issued the nonce and can bind
	// the token to this login; leave it off for a token obtained from
	// the provider's own token endpoint, where the TLS channel already
	// binds it.
	RequireNonce bool
	// HTTPClient overrides http.DefaultClient for JWKS fetches.
	HTTPClient *http.Client

	cache *JWKSCache
	once  sync.Once
}

// VerifyIDToken checks an ID token's signature against the issuer's
// published keys and validates its claims.
//
// Every check here matters: without the signature check any party can
// mint a token; without the audience check a token issued for a
// different application at the same provider is accepted (a well-known
// cross-tenant impersonation path); without the nonce check a token
// captured elsewhere can be replayed into this login.
func (cfg *IDTokenConfig) VerifyIDToken(ctx context.Context, idToken, nonce string) (*UserProfile, bool) {
	profile, err := cfg.verify(ctx, idToken, nonce)
	if err != nil {
		return nil, false
	}
	return profile, true
}

func (cfg *IDTokenConfig) verify(ctx context.Context, idToken, nonce string) (*UserProfile, error) {
	if cfg.JWKSURL == "" || cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("oauth2: id token verification is not configured")
	}
	cfg.once.Do(func() {
		cfg.cache = &JWKSCache{URL: cfg.JWKSURL, Client: cfg.HTTPClient}
	})

	kid, err := jwtKeyID(idToken)
	if err != nil {
		return nil, err
	}
	key, err := cfg.cache.Key(ctx, kid)
	if err != nil {
		return nil, err
	}
	// VerifyJWT pins the algorithm to the key type, so a token cannot
	// downgrade itself to "none" or to HMAC using the public key as the
	// shared secret.
	claims, err := crypto.VerifyJWT(key, idToken)
	if err != nil {
		return nil, err
	}
	if iss, _ := claims["iss"].(string); iss != cfg.Issuer {
		return nil, fmt.Errorf("oauth2: id token issuer %q does not match %q", iss, cfg.Issuer)
	}
	multiAud, ok := audienceMatches(claims["aud"], cfg.Audience)
	if !ok {
		return nil, errors.New("oauth2: id token audience does not match this client")
	}
	// OIDC Core 3.1.3.7: when the token is addressed to more than one
	// audience, the authorized party must be this client. Otherwise a
	// token issued to a different relying party that happens to list
	// this one is accepted.
	if multiAud {
		if azp, _ := claims["azp"].(string); azp != cfg.Audience {
			return nil, errors.New("oauth2: multi-audience id token is not authorized for this client")
		}
	}
	// An ID token without an expiry never expires, so its lifetime
	// stops bounding replay. OIDC requires the claim; treat its absence
	// as invalid rather than eternal.
	exp, hasExp := claimSeconds(claims, "exp")
	if !hasExp {
		return nil, errors.New("oauth2: id token has no exp claim")
	}
	now := time.Now()
	if now.After(exp.Add(cfg.leeway())) {
		return nil, errors.New("oauth2: id token expired")
	}
	if iat, ok := claimSeconds(claims, "iat"); ok && iat.After(now.Add(cfg.leeway())) {
		return nil, errors.New("oauth2: id token was issued in the future")
	}
	if nonce == "" && cfg.RequireNonce {
		return nil, errors.New("oauth2: a nonce is required to verify this id token")
	}
	if nonce != "" {
		got, _ := claims["nonce"].(string)
		if got == "" || !crypto.ConstantTimeEqual(got, nonce) {
			return nil, errors.New("oauth2: id token nonce mismatch")
		}
	}
	mapper := cfg.MapClaims
	if mapper == nil {
		mapper = standardOIDCClaims
	}
	profile := mapper(claims)
	if profile == nil || profile.ID == "" {
		return nil, errors.New("oauth2: id token carried no subject")
	}
	profile.Raw = map[string]any(claims)
	return profile, nil
}

// audienceMatches handles "aud" being either a string or an array, as
// the JWT spec allows. multi reports whether the token names more than
// one audience, which triggers the azp check.
func audienceMatches(aud any, want string) (multi bool, ok bool) {
	switch v := aud.(type) {
	case string:
		return false, v == want
	case []any:
		found := false
		for _, item := range v {
			if s, isStr := item.(string); isStr && s == want {
				found = true
			}
		}
		return len(v) > 1, found
	}
	return false, false
}

// claimSeconds reads a NumericDate claim.
func claimSeconds(claims crypto.Claims, name string) (time.Time, bool) {
	switch v := claims[name].(type) {
	case float64:
		return time.Unix(int64(v), 0), true
	case int64:
		return time.Unix(v, 0), true
	}
	return time.Time{}, false
}

func (cfg *IDTokenConfig) leeway() time.Duration {
	if cfg.Leeway > 0 {
		return cfg.Leeway
	}
	return time.Minute
}

func standardOIDCClaims(claims crypto.Claims) *UserProfile {
	sub, _ := claims["sub"].(string)
	name, _ := claims["name"].(string)
	email, _ := claims["email"].(string)
	picture, _ := claims["picture"].(string)
	verified := false
	switch v := claims["email_verified"].(type) {
	case bool:
		verified = v
	case string:
		verified = v == "true"
	}
	return &UserProfile{
		ID:            sub,
		Name:          name,
		Email:         email,
		EmailVerified: verified,
		Image:         picture,
	}
}

// jwtKeyID reads the "kid" from a JWT header without trusting anything
// else in the token.
func jwtKeyID(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("oauth2: malformed id token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("oauth2: malformed id token header")
	}
	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return "", errors.New("oauth2: malformed id token header")
	}
	if strings.EqualFold(header.Alg, "none") {
		return "", errors.New("oauth2: id token declares alg=none")
	}
	if header.Kid == "" {
		return "", errors.New("oauth2: id token has no key id")
	}
	return header.Kid, nil
}
