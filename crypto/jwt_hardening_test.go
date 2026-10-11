package crypto_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/go-dev-auth/go-dev-auth/crypto"
)

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Regression test for L18: a present but non-numeric exp claim used to
// be treated as absent, producing a token that never expires.
func TestVerifyJWTRejectsMalformedExp(t *testing.T) {
	key := rsaKey(t)
	for name, exp := range map[string]any{
		"string exp": "9999999999",
		"object exp": map[string]any{"at": 1},
		"bool exp":   true,
	} {
		t.Run(name, func(t *testing.T) {
			token, err := crypto.SignJWT(key, "k1", crypto.Claims{"sub": "u", "exp": exp})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := crypto.VerifyJWT(&key.PublicKey, token); err == nil {
				t.Fatal("token with malformed exp verified (would never expire)")
			}
		})
	}
}

// Regression test for L1: leeway must actually tolerate clock skew on
// exp; the zero-tolerance check used to fire before any leeway applied.
func TestVerifyJWTWithLeeway(t *testing.T) {
	key := rsaKey(t)
	token, err := crypto.SignJWT(key, "k1", crypto.Claims{
		"sub": "u", "exp": time.Now().Add(-3 * time.Second).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.VerifyJWT(&key.PublicKey, token); !errors.Is(err, crypto.ErrTokenExpired) {
		t.Fatalf("expired token without leeway: err = %v, want ErrTokenExpired", err)
	}
	if _, err := crypto.VerifyJWTWithLeeway(&key.PublicKey, token, time.Minute); err != nil {
		t.Fatalf("3s-expired token rejected despite 60s leeway: %v", err)
	}

	future, err := crypto.SignJWT(key, "k1", crypto.Claims{
		"sub": "u", "exp": time.Now().Add(time.Hour).Unix(), "nbf": time.Now().Add(3 * time.Second).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.VerifyJWTWithLeeway(&key.PublicKey, future, time.Minute); err != nil {
		t.Fatalf("nbf 3s ahead rejected despite leeway: %v", err)
	}
}

// Regression test for L17: keys published for encryption use, or on a
// curve other than the one the parser assumes, must be refused.
func TestJWKPublicKeyValidatesUseAndCurve(t *testing.T) {
	key := rsaKey(t)
	jwk, err := crypto.PublicJWK("k1", &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	jwk.Use = "enc"
	if _, err := jwk.PublicKey(); err == nil {
		t.Fatal("encryption-use key accepted for signature verification")
	}

	ec := crypto.JWK{Kty: "EC", Crv: "P-384", X: randB64(32), Y: randB64(32)}
	if _, err := ec.PublicKey(); err == nil {
		t.Fatal("P-384 key accepted by a P-256-only parser")
	}
}

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
