package jwt_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/plugins/jwt"
	"github.com/go-dev-auth/go-dev-auth/plugins/plugintest"
)

// newEnv returns an environment with the jwt plugin mounted, a signed-in
// user and the plugin itself, which relying parties use through Verify.
func newEnv(t *testing.T, opts ...jwt.Options) (*plugintest.Env, *jwt.Plugin) {
	t.Helper()
	plugin := jwt.New(opts...)
	env := plugintest.New(t, plugin)
	env.SignUp("holder@example.com", "password123")
	return env, plugin
}

func TestRouteAuthorization(t *testing.T) {
	env, _ := newEnv(t)

	cases := []struct {
		path     string
		anonWant int
		why      string
	}{
		// A token names the caller, so issuing one to an anonymous
		// request would hand out an identity nobody proved.
		{"/token", http.StatusUnauthorized, "issues a credential"},
		// The key sets are public by design: relying parties fetch them
		// without any credential of their own.
		{"/jwks", http.StatusOK, "publishes public keys"},
		{"/.well-known/jwks.json", http.StatusOK, "publishes public keys"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			anon := env.Client()
			res, body := anon.GET(tc.path)
			if res.StatusCode != tc.anonWant {
				t.Fatalf("anonymous %s (%s): status %d, want %d: %v",
					tc.path, tc.why, res.StatusCode, tc.anonWant, body)
			}
		})
	}

	// Signing out must revoke the ability to mint tokens immediately.
	env.SignOut()
	res, body := env.GET("/token")
	env.RequireErrorCode(res, body, http.StatusUnauthorized, "UNAUTHORIZED")
}

func TestIssuedTokenVerifiesAndNamesTheSessionUser(t *testing.T) {
	env, plugin := newEnv(t)
	user, err := env.Auth.FindUserByEmail(context.Background(), "holder@example.com")
	if err != nil {
		t.Fatal(err)
	}

	res, body := env.GET("/token")
	env.RequireStatus(res, body, http.StatusOK)
	token, _ := body["token"].(string)
	if strings.Count(token, ".") != 2 {
		t.Fatalf("token = %q, want three JWT segments", token)
	}
	// The header duplicates the token so a client can capture it from a
	// response it did not parse.
	if got := res.Header.Get("set-auth-jwt"); got != token {
		t.Fatalf("set-auth-jwt = %q, want the issued token", got)
	}

	claims, err := plugin.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("the plugin could not verify its own token: %v", err)
	}
	// `sub` is the only claim a relying party may use to identify the
	// caller; getting it wrong authorizes the wrong account.
	if claims["sub"] != user.ID {
		t.Fatalf("sub = %v, want the user id %q", claims["sub"], user.ID)
	}
	if claims["iss"] != env.Auth.Config().BaseURL || claims["aud"] != env.Auth.Config().BaseURL {
		t.Fatalf("iss/aud = %v/%v, want %q", claims["iss"], claims["aud"], env.Auth.Config().BaseURL)
	}
	if claims["email"] != "holder@example.com" {
		t.Fatalf("email claim = %v", claims["email"])
	}
	exp, ok := claims["exp"].(float64)
	if !ok || int64(exp) <= time.Now().Unix() {
		t.Fatalf("exp = %v, want a time in the future", claims["exp"])
	}
}

func TestTamperedTokensAreRejected(t *testing.T) {
	env, plugin := newEnv(t)
	res, body := env.GET("/token")
	env.RequireStatus(res, body, http.StatusOK)
	token, _ := body["token"].(string)
	parts := strings.Split(token, ".")

	// Re-encode the payload with a different subject, keeping the
	// original signature: the classic forgery a verifier must catch.
	forgedClaims, err := crypto.DecodeJWTClaims(token)
	if err != nil {
		t.Fatal(err)
	}
	forgedClaims["sub"] = "somebody-else"
	raw, err := json.Marshal(forgedClaims)
	if err != nil {
		t.Fatal(err)
	}
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw) + "." + parts[2]

	cases := map[string]string{
		"empty":               "",
		"not a jwt":           "not-a-token",
		"missing signature":   parts[0] + "." + parts[1],
		"truncated signature": token[:len(token)-2],
		"swapped subject":     forged,
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := plugin.Verify(context.Background(), bad); err == nil {
				t.Fatalf("Verify accepted %q", bad)
			}
		})
	}
}

func TestJWKSPublishesAUsableKeyAndNoSecrets(t *testing.T) {
	env, _ := newEnv(t)
	res, body := env.GET("/token")
	env.RequireStatus(res, body, http.StatusOK)
	token, _ := body["token"].(string)

	res, jwksBody := env.GET("/jwks")
	env.RequireStatus(res, jwksBody, http.StatusOK)
	// Relying parties cache the key set; without this they refetch on
	// every single token verification.
	if res.Header.Get("Cache-Control") == "" {
		t.Error("/jwks did not set Cache-Control")
	}

	raw, _ := jwksBody["keys"].([]any)
	if len(raw) != 1 {
		t.Fatalf("keys = %v, want exactly one", jwksBody)
	}
	// A JWKS that leaked "d" would publish the signing key itself and
	// let anyone mint tokens.
	for _, field := range []string{"d", "privateKey", "secret"} {
		if _, bad := raw[0].(map[string]any)[field]; bad {
			t.Fatalf("the published key exposes %q: %v", field, raw[0])
		}
	}

	// Verify the token the way an external service would: with nothing
	// but the published key set.
	pub := publishedKey(t, jwksBody, 0)
	claims, err := crypto.VerifyJWT(pub, token)
	if err != nil {
		t.Fatalf("the published key does not verify the issued token: %v", err)
	}
	if claims["email"] != "holder@example.com" {
		t.Fatalf("claims = %v", claims)
	}
}

func TestRotationKeepsOlderTokensVerifiable(t *testing.T) {
	env, plugin := newEnv(t)
	res, body := env.GET("/token")
	env.RequireStatus(res, body, http.StatusOK)
	oldToken, _ := body["token"].(string)

	if err := plugin.RotateKey(context.Background()); err != nil {
		t.Fatalf("rotating the signing key: %v", err)
	}
	res, body = env.GET("/token")
	env.RequireStatus(res, body, http.StatusOK)
	newToken, _ := body["token"].(string)
	if newToken == oldToken {
		t.Fatal("rotation reissued the same token")
	}
	if _, err := plugin.Verify(context.Background(), newToken); err != nil {
		t.Fatalf("a token from the new key does not verify: %v", err)
	}

	// Both keys must stay published, otherwise every token minted
	// before a rotation is instantly rejected by relying parties.
	res, jwksBody := env.GET("/jwks")
	env.RequireStatus(res, jwksBody, http.StatusOK)
	keys, _ := jwksBody["keys"].([]any)
	if len(keys) != 2 {
		t.Fatalf("keys = %d after rotation, want 2", len(keys))
	}
	var verified bool
	for i := range keys {
		if _, err := crypto.VerifyJWT(publishedKey(t, jwksBody, i), oldToken); err == nil {
			verified = true
		}
	}
	if !verified {
		t.Fatal("no published key verifies the token issued before rotation")
	}
}

func TestDefinePayloadCannotOverrideReservedClaims(t *testing.T) {
	var plugin *jwt.Plugin
	env := plugintest.NewWith(t, func(cfg *godevauth.Config) {
		plugin = jwt.New(jwt.Options{
			Issuer:   "https://issuer.example.com",
			Audience: "https://api.example.com",
			DefinePayload: func(sd *godevauth.SessionData) map[string]any {
				return map[string]any{
					"role": "editor",
					// An application payload that names a different
					// subject must not be able to impersonate anyone.
					"sub": "attacker",
					"iss": "https://evil.example.com",
				}
			},
		})
		cfg.Plugins = []godevauth.Plugin{plugin}
	})
	user := env.SignUp("payload@example.com", "password123")

	res, body := env.GET("/token")
	env.RequireStatus(res, body, http.StatusOK)
	claims, err := plugin.Verify(context.Background(), body["token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != user.ID {
		t.Fatalf("sub = %v, want %q: a custom payload overrode the subject", claims["sub"], user.ID)
	}
	if claims["iss"] != "https://issuer.example.com" {
		t.Fatalf("iss = %v, want the configured issuer", claims["iss"])
	}
	if claims["aud"] != "https://api.example.com" {
		t.Fatalf("aud = %v, want the configured audience", claims["aud"])
	}
	if claims["role"] != "editor" {
		t.Fatalf("role = %v, want the custom claim to survive", claims["role"])
	}
	// The default payload is replaced, not merged.
	if _, present := claims["email"]; present {
		t.Fatalf("claims still carry the default email: %v", claims)
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	// A negative lifetime issues a token that is already past its exp,
	// which is the only difference from a token that has simply aged.
	env, plugin := newEnv(t, jwt.Options{ExpiresIn: -time.Minute})
	res, body := env.GET("/token")
	env.RequireStatus(res, body, http.StatusOK)

	_, err := plugin.Verify(context.Background(), body["token"].(string))
	if !errors.Is(err, crypto.ErrTokenExpired) {
		t.Fatalf("Verify error = %v, want ErrTokenExpired", err)
	}
}

func TestJWTHeaderCanBeDisabled(t *testing.T) {
	env, _ := newEnv(t, jwt.Options{DisableSettingJwtHeader: true})
	res, body := env.GET("/token")
	env.RequireStatus(res, body, http.StatusOK)
	// Proxies and access logs record headers; an application that opts
	// out must not have the credential echoed there anyway.
	if got := res.Header.Get("set-auth-jwt"); got != "" {
		t.Fatalf("set-auth-jwt = %q, want it suppressed", got)
	}
	if body["token"] == nil {
		t.Fatal("the body should still carry the token")
	}
}

// publishedKey turns the nth entry of a /jwks response into a public key.
func publishedKey(t *testing.T, jwksBody map[string]any, n int) any {
	t.Helper()
	raw, err := json.Marshal(jwksBody)
	if err != nil {
		t.Fatal(err)
	}
	var set crypto.JWKS
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	if n >= len(set.Keys) {
		t.Fatalf("key %d not published: %v", n, set.Keys)
	}
	pub, err := set.Keys[n].PublicKey()
	if err != nil {
		t.Fatalf("decoding published key %d: %v", n, err)
	}
	return pub
}

// Regression test for M8: Verify used only the process's current signing
// key, so a token signed before a rotation — or by another instance
// whose key this process had not cached — failed even though its key is
// still published. It must select the verifying key by the token's kid.
func TestVerifySelectsKeyByKID(t *testing.T) {
	env, plugin := newEnv(t)
	res, body := env.GET("/token")
	env.RequireStatus(res, body, http.StatusOK)
	oldToken, _ := body["token"].(string)

	if err := plugin.RotateKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The plugin now signs with a new key. A token from the previous
	// key must still verify through this same instance.
	if _, err := plugin.Verify(context.Background(), oldToken); err != nil {
		t.Fatalf("token from the pre-rotation key does not verify: %v", err)
	}

	// A second instance sharing the same storage (a fresh cache) must
	// verify a token signed by the first, selecting the key by kid from
	// storage rather than its own current key.
	other := jwt.New()
	if err := other.Init(env.Auth); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Verify(context.Background(), oldToken); err != nil {
		t.Fatalf("a second instance cannot verify a token by kid lookup: %v", err)
	}
}

// Regression test for M8: Verify checks the issuer and audience, not
// just the signature.
func TestVerifyChecksIssuerAndAudience(t *testing.T) {
	env, plugin := newEnv(t, jwt.Options{Issuer: "https://issuer.example", Audience: "https://app.example"})
	res, body := env.GET("/token")
	env.RequireStatus(res, body, http.StatusOK)
	token, _ := body["token"].(string)

	if _, err := plugin.Verify(context.Background(), token); err != nil {
		t.Fatalf("a token from this plugin does not verify: %v", err)
	}

	// A plugin with a different audience over the same storage must
	// reject it, even though the signature is valid.
	wrongAud := jwt.New(jwt.Options{Issuer: "https://issuer.example", Audience: "https://other.example"})
	if err := wrongAud.Init(env.Auth); err != nil {
		t.Fatal(err)
	}
	if _, err := wrongAud.Verify(context.Background(), token); err == nil {
		t.Fatal("a token for a different audience verified")
	}
}
