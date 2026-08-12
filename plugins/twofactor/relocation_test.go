package twofactor_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	godevauth "github.com/go-dev-auth/go-dev-auth"
	"github.com/go-dev-auth/go-dev-auth/crypto"
	jwtplugin "github.com/go-dev-auth/go-dev-auth/plugins/jwt"
	"github.com/go-dev-auth/go-dev-auth/plugins/plugintest"
	"github.com/go-dev-auth/go-dev-auth/plugins/twofactor"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// BL-1, end to end.
//
// Every value this library encrypts at rest is encrypted under the same
// key. Before ciphertexts were bound to their storage location, that
// meant any encrypted column could be pasted into any other encrypted
// column and would decrypt there — and /two-factor/get-totp-uri is a
// read oracle for exactly one such column: give it your own session and
// your own password and it decrypts twoFactor.secret and hands the
// plaintext back inside an otpauth:// URI.
//
// So an attacker with database write access and an ordinary account
// could copy a victim's encrypted OAuth refresh token, or the jwt
// plugin's Ed25519 signing key, into their own twoFactor.secret row and
// read the plaintext out of the API.
//
// These tests stand the whole attack up and assert it fails.

const attackerEmail = "attacker@example.com"

// relocationEnv mounts two-factor alongside jwt (which stores an
// encrypted signing key) with OAuth token encryption on, so there is
// something worth stealing in two other tables.
func relocationEnv(t *testing.T) *plugintest.Env {
	t.Helper()
	env := plugintest.NewWith(t, func(cfg *godevauth.Config) {
		cfg.Plugins = []godevauth.Plugin{twofactor.New(), jwtplugin.New()}
		cfg.Account = godevauth.AccountConfig{EncryptOAuthTokens: true}
	})
	env.SignUp(attackerEmail, userPassword)
	return env
}

// attackerRow returns the id of the attacker's twoFactor row.
func attackerRow(t *testing.T, env *plugintest.Env) string {
	t.Helper()
	users, err := env.Auth.Storage().FindMany(context.Background(), storage.ModelUser,
		[]storage.Where{storage.W("email", attackerEmail)}, nil)
	if err != nil || len(users) != 1 {
		t.Fatalf("locating the attacker: %v (%d rows)", err, len(users))
	}
	userID, _ := users[0]["id"].(string)
	rec, err := env.Auth.Storage().FindOne(context.Background(), twofactor.ModelTwoFactor,
		[]storage.Where{storage.W("userId", userID)})
	if err != nil {
		t.Fatalf("locating the attacker's twoFactor row: %v", err)
	}
	id, _ := rec["id"].(string)
	return id
}

// overwriteSecret is the attacker's database write.
func overwriteSecret(t *testing.T, env *plugintest.Env, rowID, ciphertext string) {
	t.Helper()
	if _, err := env.Auth.Storage().Update(context.Background(), twofactor.ModelTwoFactor,
		[]storage.Where{storage.W("id", rowID)},
		map[string]any{"secret": ciphertext}); err != nil {
		t.Fatalf("planting the stolen ciphertext: %v", err)
	}
}

// readTOTPURI performs the attack's read step.
func readTOTPURI(t *testing.T, env *plugintest.Env) (*http.Response, map[string]any) {
	t.Helper()
	return env.POST("/two-factor/get-totp-uri", map[string]any{"password": userPassword})
}

func TestStolenOAuthTokenCannotBeReadThroughTheTOTPURIEndpoint(t *testing.T) {
	env := relocationEnv(t)
	enroll(t, env)
	rowID := attackerRow(t, env)

	// The victim's refresh token, sealed the way handler_social.go
	// seals it: bound to the victim's account row and column.
	const stolen = "victim-oauth-refresh-token"
	ciphertext, err := env.Auth.Keyring().Encrypt(
		crypto.Binding{Model: storage.ModelAccount, Record: "victim-account", Field: "refreshToken"},
		stolen)
	if err != nil {
		t.Fatal(err)
	}
	overwriteSecret(t, env, rowID, ciphertext)

	res, body := readTOTPURI(t, env)
	assertNoLeak(t, res, body, stolen)
}

func TestStolenJWTSigningKeyCannotBeReadThroughTheTOTPURIEndpoint(t *testing.T) {
	env := relocationEnv(t)
	enroll(t, env)
	rowID := attackerRow(t, env)

	// Force the jwt plugin to mint and store its signing key, then take
	// the ciphertext straight out of the jwks table — the position an
	// attacker with database read access is in.
	res, body := env.GET("/token")
	env.RequireStatus(res, body, http.StatusOK)
	keys, err := env.Auth.Storage().FindMany(context.Background(), jwtplugin.ModelJWKS, nil, nil)
	if err != nil || len(keys) != 1 {
		t.Fatalf("reading the stored signing key: %v (%d rows)", err, len(keys))
	}
	kid, _ := keys[0]["id"].(string)
	stolenCiphertext, _ := keys[0]["privateKey"].(string)
	if stolenCiphertext == "" {
		t.Fatal("the signing key is not stored encrypted; the test is not testing anything")
	}
	// What the plaintext would be, so the assertion can look for it.
	plaintext, err := env.Auth.Keyring().Decrypt(
		crypto.Binding{Model: jwtplugin.ModelJWKS, Record: kid, Field: "privateKey"},
		stolenCiphertext)
	if err != nil {
		t.Fatalf("the fixture could not read the key at its own location: %v", err)
	}

	overwriteSecret(t, env, rowID, stolenCiphertext)

	res, body = readTOTPURI(t, env)
	assertNoLeak(t, res, body, plaintext)
}

// A relocated value must also not be usable as a second factor: the
// verify path decrypts the same column.
func TestRelocatedSecretCannotBeUsedToVerify(t *testing.T) {
	env := relocationEnv(t)
	secret, _ := enroll(t, env)
	rowID := attackerRow(t, env)

	// Re-seal the attacker's own, perfectly valid TOTP secret against a
	// different row. Same key, same plaintext, wrong place.
	ciphertext, err := env.Auth.Keyring().Encrypt(
		crypto.Binding{Model: twofactor.ModelTwoFactor, Record: "some-other-row", Field: "secret"},
		secret)
	if err != nil {
		t.Fatal(err)
	}
	overwriteSecret(t, env, rowID, ciphertext)

	client := env.Client()
	res, body := client.SignIn(attackerEmail, userPassword)
	env.RequireStatus(res, body, http.StatusOK)
	res, body = client.POST("/two-factor/verify-totp", map[string]any{"code": totp(t, secret)})
	env.RequireErrorCode(res, body, http.StatusInternalServerError, "TWO_FACTOR_SECRET_UNREADABLE")
	if client.Signed() {
		t.Fatal("a session was issued from a relocated ciphertext")
	}
}

// Even if a value somehow decrypts, TOTPURI must not echo something
// that is not a TOTP secret. This plants a correctly bound ciphertext
// whose plaintext is a signing key, which is the case the binding alone
// does not cover (an operator-side mix-up, or a future caller writing
// the wrong value to the right column).
func TestTOTPURIWillNotEchoANonSecret(t *testing.T) {
	env := relocationEnv(t)
	enroll(t, env)
	rowID := attackerRow(t, env)

	const notASecret = "kQe7ZzT1x-9pAbCdEfGhIjKlMnOpQrStUvWxYz012345"
	ciphertext, err := env.Auth.Keyring().Encrypt(
		crypto.Binding{Model: twofactor.ModelTwoFactor, Record: rowID, Field: "secret"},
		notASecret)
	if err != nil {
		t.Fatal(err)
	}
	overwriteSecret(t, env, rowID, ciphertext)

	res, body := readTOTPURI(t, env)
	assertNoLeak(t, res, body, notASecret)
}

// assertNoLeak checks that the endpoint failed loudly and that the
// plaintext appears nowhere in the response.
func assertNoLeak(t *testing.T, res *http.Response, body map[string]any, plaintext string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), plaintext) {
		t.Fatalf("the endpoint leaked the plaintext: %s", raw)
	}
	if uri, _ := body["totpURI"].(string); uri != "" {
		t.Fatalf("a TOTP URI was returned for a value that is not this row's secret: %q", uri)
	}
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (the stored value must be rejected loudly): %v",
			res.StatusCode, body)
	}
	if code, _ := body["code"].(string); code != "TWO_FACTOR_SECRET_UNREADABLE" {
		t.Fatalf("code = %q, want TWO_FACTOR_SECRET_UNREADABLE", code)
	}
}
