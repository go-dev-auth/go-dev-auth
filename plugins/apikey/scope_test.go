package apikey_test

import (
	"net/http"
	"testing"

	"github.com/go-dev-auth/go-dev-auth/plugins/apikey"
	"github.com/go-dev-auth/go-dev-auth/plugins/plugintest"
	twofactor "github.com/go-dev-auth/go-dev-auth/plugins/twofactor"
)

// envWith2FA mounts the api-key plugin alongside two-factor so the
// denied /two-factor/* and /set-password style routes actually exist to
// probe.
func envWith2FA(t *testing.T, o apikey.Options) *plugintest.Env {
	t.Helper()
	env := plugintest.New(t, apikey.New(o), twofactor.New())
	env.SignUp("owner@example.com", "password123")
	return env
}

// Regression test for M6: an API key must not reach the account- and
// admin-critical endpoints by default, even though its owner can.
func TestAPIKeyDeniedSensitiveRoutes(t *testing.T) {
	env := envWith2FA(t, apikey.Options{KeyPrefix: "gda_"})
	_, plain := createKey(t, env, map[string]any{"name": "k"})
	client := env.Client() // no cookie: only the key authenticates

	for _, path := range []string{"/set-password", "/delete-user", "/two-factor/disable"} {
		res, body := client.POST(path, map[string]any{"password": "password123"}, "x-api-key", plain)
		// Denied means the key never authenticated the request, so these
		// session-required endpoints answer 401, never 200.
		if res.StatusCode == http.StatusOK {
			t.Fatalf("%s reached with an API key: %v", path, body)
		}
	}

	// A non-sensitive endpoint still works with the key.
	res, body := client.GET("/get-session", "x-api-key", plain)
	env.RequireStatus(res, body, http.StatusOK)
	if body["user"] == nil {
		t.Fatalf("key did not authenticate a normal request: %v", body)
	}
}

// Regression test for M6 scopes: a scoped key is confined to its
// allowed path prefixes.
func TestAPIKeyScopesConfinePaths(t *testing.T) {
	env := newEnv(t)
	_, plain := createKey(t, env, map[string]any{"name": "scoped", "scopes": []string{"/get-session"}})
	client := env.Client()

	res, body := client.GET("/get-session", "x-api-key", plain)
	env.RequireStatus(res, body, http.StatusOK)
	if body["user"] == nil {
		t.Fatal("scoped key rejected on an in-scope path")
	}

	// /list-accounts is out of scope, so the key does not authenticate
	// it (list-accounts requires a session).
	res, body = client.GET("/list-accounts", "x-api-key", plain)
	if res.StatusCode == http.StatusOK {
		t.Fatalf("scoped key reached an out-of-scope path: %v", body)
	}
}

// Regression test for M6: API-key sessions are never "fresh", so they
// cannot satisfy the freshness gate the sensitive endpoints use even if
// the denial were lifted.
func TestAPIKeySessionIsNotFresh(t *testing.T) {
	env := envWith2FA(t, apikey.Options{KeyPrefix: "gda_", AllowSensitiveRoutes: true})
	_, plain := createKey(t, env, map[string]any{"name": "k"})
	client := env.Client()

	// With sensitive routes allowed the request reaches the handler, but
	// set-password requires a fresh session and an API-key session is
	// stamped stale, so it is still refused (not with 401-unauth, but
	// with the freshness error).
	res, body := client.POST("/set-password", map[string]any{"newPassword": "another-password"}, "x-api-key", plain)
	if res.StatusCode == http.StatusOK {
		t.Fatalf("an API key set a password through the freshness gate: %v", body)
	}
}

// Regression test for L12: verify must not return the key's metadata.
func TestVerifyDoesNotLeakMetadata(t *testing.T) {
	env := newEnv(t)
	_, plain := createKey(t, env, map[string]any{
		"name": "k", "metadata": map[string]any{"tenant": "secret-tenant"},
	})
	res, body := env.POST("/api-key/verify", map[string]any{"key": plain})
	env.RequireStatus(res, body, http.StatusOK)
	if body["valid"] != true {
		t.Fatalf("verify failed: %v", body)
	}
	key, _ := body["key"].(map[string]any)
	if _, leaked := key["metadata"]; leaked {
		t.Fatalf("verify leaked metadata: %v", key)
	}
}
