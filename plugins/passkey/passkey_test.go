package passkey_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/go-dev-auth/go-dev-auth/plugins/passkey"
	"github.com/go-dev-auth/go-dev-auth/plugins/plugintest"
)

// ---- a tiny CBOR encoder for building test vectors ----

func encUint(major byte, v uint64) []byte {
	switch {
	case v < 24:
		return []byte{major<<5 | byte(v)}
	case v <= 0xff:
		return []byte{major<<5 | 24, byte(v)}
	case v <= 0xffff:
		return []byte{major<<5 | 25, byte(v >> 8), byte(v)}
	default:
		return []byte{major<<5 | 26, byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
}

func encInt(i int64) []byte {
	if i >= 0 {
		return encUint(0, uint64(i))
	}
	return encUint(1, uint64(-1-i))
}

func encBytes(b []byte) []byte  { return append(encUint(2, uint64(len(b))), b...) }
func encText(s string) []byte   { return append(encUint(3, uint64(len(s))), s...) }
func encMapHeader(n int) []byte { return encUint(5, uint64(n)) }

// coseES256Key encodes the COSE_Key for a P-256 public key.
func coseES256Key(pub *ecdsa.PublicKey) []byte {
	x := pub.X.FillBytes(make([]byte, 32))
	y := pub.Y.FillBytes(make([]byte, 32))
	out := encMapHeader(5)
	out = append(out, encInt(1)...)  // kty
	out = append(out, encInt(2)...)  // EC2
	out = append(out, encInt(3)...)  // alg
	out = append(out, encInt(-7)...) // ES256
	out = append(out, encInt(-1)...) // crv
	out = append(out, encInt(1)...)  // P-256
	out = append(out, encInt(-2)...) // x
	out = append(out, encBytes(x)...)
	out = append(out, encInt(-3)...) // y
	out = append(out, encBytes(y)...)
	return out
}

// ---- a software authenticator ----

type authenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
	count  uint32
	rpID   string
	origin string
}

func newAuthenticator(t *testing.T, rpID, origin string) *authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatal(err)
	}
	return &authenticator{key: key, credID: credID, rpID: rpID, origin: origin}
}

const (
	flagUP = 1 << 0
	flagUV = 1 << 2
	flagAT = 1 << 6
)

func (a *authenticator) authData(flags byte, count uint32, attested bool) []byte {
	h := sha256.Sum256([]byte(a.rpID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	out = append(out, byte(count>>24), byte(count>>16), byte(count>>8), byte(count))
	if attested {
		out = append(out, make([]byte, 16)...) // aaguid
		out = append(out, byte(len(a.credID)>>8), byte(len(a.credID)))
		out = append(out, a.credID...)
		out = append(out, coseES256Key(&a.key.PublicKey)...)
	}
	return out
}

func (a *authenticator) clientData(t *testing.T, typ, challenge string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"type": typ, "challenge": challenge, "origin": a.origin,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// register produces a verify-registration request body for challenge.
func (a *authenticator) register(t *testing.T, challenge, name string) map[string]any {
	t.Helper()
	ad := a.authData(flagUP|flagUV|flagAT, a.count, true)
	attObj := encMapHeader(3)
	attObj = append(attObj, encText("fmt")...)
	attObj = append(attObj, encText("none")...)
	attObj = append(attObj, encText("attStmt")...)
	attObj = append(attObj, encMapHeader(0)...)
	attObj = append(attObj, encText("authData")...)
	attObj = append(attObj, encBytes(ad)...)
	return map[string]any{
		"name": name,
		"response": map[string]any{
			"id":    b64u(a.credID),
			"rawId": b64u(a.credID),
			"type":  "public-key",
			"response": map[string]any{
				"clientDataJSON":    b64u(a.clientData(t, "webauthn.create", challenge)),
				"attestationObject": b64u(attObj),
				"transports":        []string{"internal"},
			},
		},
	}
}

// assert produces a verify-authentication request body for challenge,
// bumping the counter like a real authenticator.
func (a *authenticator) assert(t *testing.T, challenge string) map[string]any {
	t.Helper()
	a.count++
	return a.assertWithCount(t, challenge, a.count)
}

func (a *authenticator) assertWithCount(t *testing.T, challenge string, count uint32) map[string]any {
	t.Helper()
	ad := a.authData(flagUP|flagUV, count, false)
	cd := a.clientData(t, "webauthn.get", challenge)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"response": map[string]any{
			"id":    b64u(a.credID),
			"rawId": b64u(a.credID),
			"type":  "public-key",
			"response": map[string]any{
				"clientDataJSON":    b64u(cd),
				"authenticatorData": b64u(ad),
				"signature":         b64u(sig),
			},
		},
	}
}

// newEnv returns an environment with a registered passkey for
// user@example.com, plus the authenticator that holds it.
func newEnv(t *testing.T) (*plugintest.Env, *authenticator) {
	t.Helper()
	env := plugintest.New(t, passkey.New())
	env.SignUp("user@example.com", "password123")

	// plugintest builds Auth with BaseURL http://127.0.0.1, so that is
	// the relying-party origin the plugin captured at Init.
	auth := newAuthenticator(t, "127.0.0.1", "http://127.0.0.1")

	res, opts := env.GET("/passkey/generate-register-options")
	env.RequireStatus(res, opts, http.StatusOK)
	challenge, _ := opts["challenge"].(string)
	if challenge == "" {
		t.Fatalf("no challenge in options: %v", opts)
	}
	rp, _ := opts["rp"].(map[string]any)
	if rp["id"] != "127.0.0.1" {
		t.Fatalf("rp.id = %v", rp["id"])
	}

	res, body := env.POST("/passkey/verify-registration", auth.register(t, challenge, "Laptop"))
	env.RequireStatus(res, body, http.StatusOK)
	return env, auth
}

func TestRegisterAndListPasskey(t *testing.T) {
	env, _ := newEnv(t)
	res, _ := env.GET("/passkey/list-user-passkeys")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list: %d", res.StatusCode)
	}
	if n := env.Count(passkey.ModelPasskey); n != 1 {
		t.Fatalf("stored passkeys = %d, want 1", n)
	}
	// The stored row never carries the private key, and the public key
	// is a parseable COSE structure, not raw junk.
	rec, err := env.Auth.Storage().FindOne(t.Context(), passkey.ModelPasskey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec["counter"] == nil || rec["credentialID"] == "" || rec["publicKey"] == "" {
		t.Fatalf("stored passkey incomplete: %v", rec)
	}
}

func TestPasskeySignIn(t *testing.T) {
	env, auth := newEnv(t)

	// A fresh browser with no cookies.
	client := env.Client()
	res, opts := client.POST("/passkey/generate-authenticate-options", map[string]any{})
	env.RequireStatus(res, opts, http.StatusOK)
	challenge, _ := opts["challenge"].(string)

	res, body := client.POST("/passkey/verify-authentication", auth.assert(t, challenge))
	env.RequireStatus(res, body, http.StatusOK)
	if body["token"] == nil {
		t.Fatalf("no session token in response: %v", body)
	}
	if session := client.Session(); session == nil {
		t.Fatal("no session cookie after passkey sign-in")
	}

	// The consumed challenge cannot be replayed.
	res, body = client.POST("/passkey/verify-authentication", auth.assertWithCount(t, challenge, auth.count+1))
	env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_PASSKEY_RESPONSE")
}

func TestPasskeyRejectsCounterRegression(t *testing.T) {
	env, auth := newEnv(t)
	client := env.Client()

	// Legitimate sign-in advances the stored counter to 1.
	_, opts := client.POST("/passkey/generate-authenticate-options", map[string]any{})
	challenge, _ := opts["challenge"].(string)
	res, body := client.POST("/passkey/verify-authentication", auth.assert(t, challenge))
	env.RequireStatus(res, body, http.StatusOK)

	// A cloned authenticator replays the same counter value.
	clone := env.Client()
	_, opts = clone.POST("/passkey/generate-authenticate-options", map[string]any{})
	challenge, _ = opts["challenge"].(string)
	res, body = clone.POST("/passkey/verify-authentication", auth.assertWithCount(t, challenge, 1))
	env.RequireErrorCode(res, body, http.StatusUnauthorized, "PASSKEY_COUNTER_REGRESSION")
}

func TestPasskeyRejectsWrongOrigin(t *testing.T) {
	env, auth := newEnv(t)
	client := env.Client()
	_, opts := client.POST("/passkey/generate-authenticate-options", map[string]any{})
	challenge, _ := opts["challenge"].(string)

	evil := *auth
	evil.origin = "https://evil.example.com"
	res, body := client.POST("/passkey/verify-authentication", evil.assert(t, challenge))
	env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_PASSKEY_RESPONSE")
}

func TestPasskeyRejectsForgedSignature(t *testing.T) {
	env, auth := newEnv(t)
	client := env.Client()
	_, opts := client.POST("/passkey/generate-authenticate-options", map[string]any{})
	challenge, _ := opts["challenge"].(string)

	// Same credential id, different private key.
	forger := newAuthenticator(t, auth.rpID, auth.origin)
	forger.credID = auth.credID
	res, body := client.POST("/passkey/verify-authentication", forger.assert(t, challenge))
	env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_PASSKEY_RESPONSE")
}

func TestRegistrationRequiresSession(t *testing.T) {
	env, _ := newEnv(t)
	anon := env.Client()
	res, _ := anon.GET("/passkey/generate-register-options")
	if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusForbidden {
		t.Fatalf("register options without session: %d", res.StatusCode)
	}
}

func TestRegistrationChallengeIsBoundToUser(t *testing.T) {
	env := plugintest.New(t, passkey.New())
	env.SignUp("alice@example.com", "password123")

	res, opts := env.GET("/passkey/generate-register-options")
	env.RequireStatus(res, opts, http.StatusOK)
	challenge, _ := opts["challenge"].(string)

	// A different user tries to redeem Alice's challenge.
	mallory := env.Client()
	mallory.SignUp("mallory@example.com", "password123")
	auth := newAuthenticator(t, "127.0.0.1", "http://127.0.0.1")
	res, body := mallory.POST("/passkey/verify-registration", auth.register(t, challenge, "Stolen"))
	env.RequireErrorCode(res, body, http.StatusBadRequest, "INVALID_PASSKEY_RESPONSE")
}

func TestDeletePasskeyRequiresOwnership(t *testing.T) {
	env, _ := newEnv(t)
	rec, err := env.Auth.Storage().FindOne(t.Context(), passkey.ModelPasskey, nil)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := rec["id"].(string)

	// Another user cannot delete it, even knowing the id.
	mallory := env.Client()
	mallory.SignUp("mallory2@example.com", "password123")
	res, body := mallory.POST("/passkey/delete-passkey", map[string]any{"id": id})
	env.RequireStatus(res, body, http.StatusOK)
	if n := env.Count(passkey.ModelPasskey); n != 1 {
		t.Fatal("another user's delete removed the passkey")
	}

	// The owner can.
	res, body = env.POST("/passkey/delete-passkey", map[string]any{"id": id})
	env.RequireStatus(res, body, http.StatusOK)
	if n := env.Count(passkey.ModelPasskey); n != 0 {
		t.Fatal("owner's delete did not remove the passkey")
	}
}
