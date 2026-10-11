package godevauth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/oauth2"
)

// nativeIDP is a provider whose ID tokens the server verifies directly
// (the native SDK flow), backed by a local JWKS endpoint.
type nativeIDP struct {
	priv   *rsa.PrivateKey
	server *httptest.Server
}

func newNativeIDP(t *testing.T) (*nativeIDP, oauth2.Provider) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwk, _ := crypto.PublicJWK("k1", &priv.PublicKey)
		_ = json.NewEncoder(w).Encode(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	})
	p := &nativeIDP{priv: priv, server: server}
	provider := oauth2.New(oauth2.Spec{
		ProviderID: "nativeco",
		ClientID:   "native-client",
		Endpoints:  oauth2.Endpoints{AuthorizationURL: server.URL + "/authorize", TokenURL: server.URL + "/token"},
		IDToken: &oauth2.IDTokenConfig{
			Issuer:   server.URL,
			JWKSURL:  server.URL + "/jwks",
			Audience: "native-client",
		},
	})
	return p, provider
}

func (p *nativeIDP) mint(t *testing.T, email, nonce string) string {
	t.Helper()
	claims := crypto.Claims{
		"iss": p.server.URL, "aud": "native-client", "sub": "native-user-1",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"email": email, "email_verified": true, "name": "Native User",
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	token, err := crypto.SignJWT(p.priv, "k1", claims)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// Regression test for M3: the nonce used to be client-supplied and
// merely compared against the token's own claim, so it proved nothing —
// a leaked ID token was a bearer credential until exp. The server now
// mints single-use nonces and consumes them at sign-in.
func TestNativeIDTokenRequiresServerMintedNonce(t *testing.T) {
	idp, provider := newNativeIDP(t)
	_, tc := newTestAuth(t, func(cfg *godevauth.Config) {
		cfg.SocialProviders = []oauth2.Provider{provider}
	})

	signIn := func(token, nonce string) (*http.Response, map[string]any) {
		return tc.post("/sign-in/social", map[string]any{
			"provider": "nativeco",
			"idToken":  map[string]any{"token": token, "nonce": nonce},
		})
	}

	// Without a nonce: refused with guidance.
	res, body := signIn(idp.mint(t, "native@example.com", ""), "")
	if res.StatusCode != http.StatusBadRequest || body["code"] != "NONCE_REQUIRED" {
		t.Fatalf("nonce-less native sign-in: %d %v, want NONCE_REQUIRED", res.StatusCode, body)
	}

	// With an attacker-chosen nonce the server never minted: refused,
	// even though token and echoed nonce agree (the old, useless check).
	res, body = signIn(idp.mint(t, "native@example.com", "attacker-nonce"), "attacker-nonce")
	if res.StatusCode == http.StatusOK {
		t.Fatalf("self-chosen nonce accepted: %v", body)
	}

	// The real flow: fetch a nonce, have the provider embed it.
	res, body = tc.post("/id-token/nonce", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("id-token/nonce: %d %v", res.StatusCode, body)
	}
	nonce, _ := body["nonce"].(string)
	token := idp.mint(t, "native@example.com", nonce)
	res, body = signIn(token, nonce)
	if res.StatusCode != http.StatusOK || body["user"] == nil {
		t.Fatalf("native sign-in with server nonce: %d %v", res.StatusCode, body)
	}

	// Replay: the nonce was consumed, so the same token cannot sign in
	// twice.
	res, body = signIn(token, nonce)
	if res.StatusCode == http.StatusOK {
		t.Fatalf("replayed ID token accepted: %v", body)
	}
}
