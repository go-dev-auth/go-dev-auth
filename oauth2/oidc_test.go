package oauth2_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/oauth2"
)

// idp is a stand-in identity provider that publishes a JWKS and mints
// ID tokens, so the verifier can be exercised end to end.
type idp struct {
	server  *httptest.Server
	priv    *rsa.PrivateKey
	kid     string
	fetches int64
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &idp{priv: priv, kid: "key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&p.fetches, 1)
		jwk, err := crypto.PublicJWK(p.kid, &priv.PublicKey)
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	})
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *idp) config(audience string) *oauth2.IDTokenConfig {
	return &oauth2.IDTokenConfig{
		Issuer:   p.server.URL,
		JWKSURL:  p.server.URL + "/jwks",
		Audience: audience,
	}
}

func (p *idp) mint(t *testing.T, claims crypto.Claims) string {
	t.Helper()
	token, err := crypto.SignJWT(p.priv, p.kid, claims)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (p *idp) validClaims(audience string) crypto.Claims {
	return crypto.Claims{
		"iss":            p.server.URL,
		"aud":            audience,
		"sub":            "user-123",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"email":          "user@example.com",
		"email_verified": true,
		"name":           "Test User",
	}
}

func TestVerifyIDTokenAcceptsValidToken(t *testing.T) {
	p := newIDP(t)
	cfg := p.config("my-client-id")
	token := p.mint(t, p.validClaims("my-client-id"))

	profile, ok := cfg.VerifyIDToken(context.Background(), token, "")
	if !ok {
		t.Fatal("valid token rejected")
	}
	if profile.ID != "user-123" || profile.Email != "user@example.com" || !profile.EmailVerified {
		t.Fatalf("profile = %+v", profile)
	}
}

// TestVerifyIDTokenRejects covers the attacks the verifier exists to
// stop. Each case must fail closed.
func TestVerifyIDTokenRejects(t *testing.T) {
	p := newIDP(t)
	const audience = "my-client-id"
	cfg := p.config(audience)

	// A second, unrelated issuer: signature valid, but not by the key
	// the configured issuer publishes.
	other := newIDP(t)

	cases := []struct {
		name  string
		token func() string
	}{
		{"wrong audience: a token minted for another app at the same provider", func() string {
			c := p.validClaims("someone-elses-client-id")
			return p.mint(t, c)
		}},
		{"wrong issuer", func() string {
			c := p.validClaims(audience)
			c["iss"] = "https://evil.example.com"
			return p.mint(t, c)
		}},
		{"signed by a different key", func() string {
			return other.mint(t, p.validClaims(audience))
		}},
		{"expired", func() string {
			c := p.validClaims(audience)
			c["exp"] = time.Now().Add(-time.Hour).Unix()
			return p.mint(t, c)
		}},
		{"tampered payload", func() string {
			return p.mint(t, p.validClaims(audience)) + "x"
		}},
		{"alg none", func() string {
			// header {"alg":"none","kid":"key-1"} with an unsigned body
			return "eyJhbGciOiJub25lIiwia2lkIjoia2V5LTEifQ." +
				"eyJzdWIiOiJhdHRhY2tlciJ9."
		}},
		{"no subject", func() string {
			c := p.validClaims(audience)
			delete(c, "sub")
			return p.mint(t, c)
		}},
		{"malformed", func() string { return "not-a-jwt" }},
		{"empty", func() string { return "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := cfg.VerifyIDToken(context.Background(), tc.token(), ""); ok {
				t.Fatal("token was accepted; it must be rejected")
			}
		})
	}
}

// TestVerifyIDTokenNonce asserts replay protection when the caller
// supplies a nonce.
func TestVerifyIDTokenNonce(t *testing.T) {
	p := newIDP(t)
	cfg := p.config("my-client-id")

	claims := p.validClaims("my-client-id")
	claims["nonce"] = "expected-nonce"
	token := p.mint(t, claims)

	if _, ok := cfg.VerifyIDToken(context.Background(), token, "expected-nonce"); !ok {
		t.Fatal("matching nonce rejected")
	}
	if _, ok := cfg.VerifyIDToken(context.Background(), token, "different-nonce"); ok {
		t.Fatal("mismatched nonce accepted")
	}
	// a token with no nonce cannot satisfy a nonce requirement
	plain := p.mint(t, p.validClaims("my-client-id"))
	if _, ok := cfg.VerifyIDToken(context.Background(), plain, "expected-nonce"); ok {
		t.Fatal("token without a nonce accepted where one was required")
	}
}

// TestJWKSCaching asserts keys are cached rather than refetched per
// token, and that an unknown key id cannot be used to hammer the
// provider's JWKS endpoint.
func TestJWKSCaching(t *testing.T) {
	p := newIDP(t)
	cfg := p.config("my-client-id")
	token := p.mint(t, p.validClaims("my-client-id"))

	for i := 0; i < 5; i++ {
		if _, ok := cfg.VerifyIDToken(context.Background(), token, ""); !ok {
			t.Fatal("valid token rejected")
		}
	}
	if n := atomic.LoadInt64(&p.fetches); n != 1 {
		t.Fatalf("jwks fetched %d times for 5 verifications, want 1", n)
	}

	// Tokens naming an unknown key must not each trigger a fetch.
	unknown, err := crypto.SignJWT(p.priv, "unknown-kid", p.validClaims("my-client-id"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, ok := cfg.VerifyIDToken(context.Background(), unknown, ""); ok {
			t.Fatal("token with an unknown key id accepted")
		}
	}
	if n := atomic.LoadInt64(&p.fetches); n > 2 {
		t.Fatalf("jwks fetched %d times; unknown key ids must be rate limited", n)
	}
}

// TestVerifyIDTokenUnconfigured asserts the verifier fails closed when
// it has not been given an issuer/audience.
func TestVerifyIDTokenUnconfigured(t *testing.T) {
	p := newIDP(t)
	cfg := &oauth2.IDTokenConfig{JWKSURL: p.server.URL + "/jwks"} // no issuer, no audience
	token := p.mint(t, p.validClaims("my-client-id"))
	if _, ok := cfg.VerifyIDToken(context.Background(), token, ""); ok {
		t.Fatal("unconfigured verifier accepted a token")
	}
}

// TestEd25519IDToken covers the non-RSA key path through the same
// verifier.
func TestEd25519IDToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwk, _ := crypto.PublicJWK("ed-1", pub)
		_ = json.NewEncoder(w).Encode(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := &oauth2.IDTokenConfig{
		Issuer: server.URL, JWKSURL: server.URL + "/jwks", Audience: "aud-1",
	}
	token, err := crypto.SignJWT(priv, "ed-1", crypto.Claims{
		"iss": server.URL, "aud": "aud-1", "sub": "u1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.VerifyIDToken(context.Background(), token, ""); !ok {
		t.Fatal("valid Ed25519 token rejected")
	}
}

// Regression test for L1: IDTokenConfig.Leeway must tolerate a
// slightly-expired token; the underlying JWT check used to reject with
// zero tolerance before the leeway-aware check ran.
func TestVerifyIDTokenAppliesLeewayToExp(t *testing.T) {
	p := newIDP(t)
	cfg := p.config("client-1")
	cfg.Leeway = time.Minute
	claims := p.validClaims("client-1")
	claims["exp"] = time.Now().Add(-3 * time.Second).Unix()
	token := p.mint(t, claims)
	if _, ok := cfg.VerifyIDToken(context.Background(), token, ""); !ok {
		t.Fatal("token 3s past exp rejected despite 60s leeway")
	}
	claims["exp"] = time.Now().Add(-2 * time.Minute).Unix()
	if _, ok := cfg.VerifyIDToken(context.Background(), p.mint(t, claims), ""); ok {
		t.Fatal("token beyond leeway accepted")
	}
}

// Regression test for M12's mechanism: ValidateIssuer replaces the
// exact issuer match and can bind the issuer to other claims.
func TestVerifyIDTokenValidateIssuerOverride(t *testing.T) {
	p := newIDP(t)
	cfg := p.config("client-1")
	cfg.ValidateIssuer = func(iss string, claims crypto.Claims) bool {
		tid, _ := claims["tid"].(string)
		return iss == p.server.URL+"/tenant/"+tid
	}
	claims := p.validClaims("client-1")
	claims["iss"] = p.server.URL + "/tenant/t-1"
	claims["tid"] = "t-1"
	if _, ok := cfg.VerifyIDToken(context.Background(), p.mint(t, claims), ""); !ok {
		t.Fatal("issuer accepted by ValidateIssuer was rejected")
	}
	claims["tid"] = "t-2"
	if _, ok := cfg.VerifyIDToken(context.Background(), p.mint(t, claims), ""); ok {
		t.Fatal("issuer/tid mismatch accepted")
	}
}
