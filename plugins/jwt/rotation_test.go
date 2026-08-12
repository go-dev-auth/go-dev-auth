package jwt_test

import (
	"context"
	"net/http"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/plugins/jwt"
	"github.com/go-dev-auth/go-dev-auth/plugins/plugintest"
	"github.com/go-dev-auth/go-dev-auth/storage"
	"github.com/go-dev-auth/go-dev-auth/storage/memory"
)

const (
	oldSecret = "jwt-rotation-old-secret-0123456"
	newSecret = "jwt-rotation-new-secret-0123456"
)

func newRotationEnv(t *testing.T, db storage.Adapter, secret string, previous ...string) (*plugintest.Env, *jwt.Plugin) {
	t.Helper()
	plugin := jwt.New()
	env := plugintest.NewWith(t, func(cfg *godevauth.Config) {
		cfg.Database = db
		cfg.Secret = secret
		cfg.PreviousSecrets = previous
		cfg.Plugins = []godevauth.Plugin{plugin}
	})
	return env, plugin
}

func keyIDs(t *testing.T, body map[string]any) []string {
	t.Helper()
	raw, _ := body["keys"].([]any)
	var out []string
	for _, k := range raw {
		m, _ := k.(map[string]any)
		if kid, _ := m["kid"].(string); kid != "" {
			out = append(out, kid)
		}
	}
	return out
}

// The JWKS endpoint publishes public keys, which need no secret at all.
// It used to decrypt each private key on the way through and silently
// drop any it could not read — so after a secret rotation it served an
// empty key set, and every token already in circulation started failing
// verification at the relying party with no server-side error anywhere.
func TestJWKSStaysCompleteAfterASecretRotation(t *testing.T) {
	db := memory.New()
	before, _ := newRotationEnv(t, db, oldSecret)
	before.SignUp("jwks@example.com", "password123")

	res, body := before.GET("/jwks")
	before.RequireStatus(res, body, http.StatusOK)
	original := keyIDs(t, body)
	if len(original) != 1 {
		t.Fatalf("expected one published key, got %v", original)
	}

	// Secret rotated with the old one dropped: the worst case.
	after, _ := newRotationEnv(t, db, newSecret)
	res, body = after.GET("/jwks")
	after.RequireStatus(res, body, http.StatusOK)
	published := keyIDs(t, body)

	found := false
	for _, kid := range published {
		if kid == original[0] {
			found = true
		}
	}
	if !found {
		t.Fatalf("the key that signed live tokens vanished from JWKS: had %v, now %v", original, published)
	}
}

// Signing, unlike publishing, does need the private key. When it cannot
// be read the request must fail with an error naming the cause, not fall
// back to minting a fresh key (which would silently invalidate every
// token already issued).
func TestSigningFailsLoudlyWhenTheKeyIsUnreadable(t *testing.T) {
	db := memory.New()
	before, _ := newRotationEnv(t, db, oldSecret)
	before.SignUp("signer@example.com", "password123")
	res, body := before.GET("/token")
	before.RequireStatus(res, body, http.StatusOK)

	after, _ := newRotationEnv(t, db, newSecret)
	after.SignIn("signer@example.com", "password123")
	res, body = after.GET("/token")
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %v", res.StatusCode, body)
	}
	// And no second key was quietly created behind the operator's back.
	if n := after.Count(jwt.ModelJWKS); n != 1 {
		t.Fatalf("%d stored keys, want 1: an unreadable key must not be replaced silently", n)
	}
}

func TestSigningKeySurvivesRotationWithThePreviousSecret(t *testing.T) {
	db := memory.New()
	before, _ := newRotationEnv(t, db, oldSecret)
	before.SignUp("keeper@example.com", "password123")
	res, body := before.GET("/token")
	before.RequireStatus(res, body, http.StatusOK)
	first, _ := body["token"].(string)

	during, plugin := newRotationEnv(t, db, newSecret, oldSecret)
	during.SignIn("keeper@example.com", "password123")
	res, body = during.GET("/token")
	during.RequireStatus(res, body, http.StatusOK)

	// A token signed before the rotation still verifies, because the
	// same key is still in use.
	if _, err := plugin.Verify(context.Background(), first); err != nil {
		t.Fatalf("a token issued before the rotation stopped verifying: %v", err)
	}

	// Migrate, then drop the old secret.
	result, err := during.Auth.ReencryptSecrets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Rewritten != 1 || result.Unreadable != 0 {
		t.Fatalf("re-encryption result = %+v, want one key rewritten", result)
	}

	after, afterPlugin := newRotationEnv(t, db, newSecret)
	after.SignIn("keeper@example.com", "password123")
	res, body = after.GET("/token")
	after.RequireStatus(res, body, http.StatusOK)
	if _, err := afterPlugin.Verify(context.Background(), first); err != nil {
		t.Fatalf("the pre-rotation token stopped verifying after the migration: %v", err)
	}
}
