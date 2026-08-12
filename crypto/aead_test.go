package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// legacyEncrypt reproduces the pre-versioning on-disk format exactly as
// it was written before key ids existed: base64url(nonce||ciphertext),
// key = sha256("go-dev-auth-enc:"+secret), no additional data.
//
// It is duplicated here on purpose. This is the compatibility contract
// with data already in production databases, so the test must pin the
// bytes independently of whatever aead.go does today.
func legacyEncrypt(t *testing.T, secret, plaintext string) string {
	t.Helper()
	sum := sha256.Sum256([]byte("go-dev-auth-enc:" + secret))
	gcm, err := newGCM(sum[:])
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plaintext), nil))
}

// testBinding is the storage location most tests seal against.
var testBinding = Binding{Model: "twoFactor", Record: "rec-1", Field: "secret"}

func TestKeyringRoundTrip(t *testing.T) {
	kr := NewKeyring("current-secret-0123456789abcdef")
	enc, err := kr.Encrypt(testBinding, "totp-secret")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(enc, ".")
	if len(parts) != 3 || parts[0] != "v2" {
		t.Fatalf("ciphertext %q is not v2.<kid>.<body>", enc)
	}
	kid, err := kr.CurrentKeyID()
	if err != nil {
		t.Fatal(err)
	}
	if parts[1] != kid {
		t.Fatalf("ciphertext key id = %q, want %q", parts[1], kid)
	}
	got, err := kr.Decrypt(testBinding, enc)
	if err != nil || got != "totp-secret" {
		t.Fatalf("Decrypt = %q, %v", got, err)
	}
	if kr.NeedsReencryption(enc) {
		t.Fatal("a value just written under the current key should not need re-encryption")
	}
}

// The whole point of the exercise: a value written before the upgrade
// must still be readable after it, and re-encrypting it must produce a
// current-format value.
func TestKeyringReadsLegacyFormat(t *testing.T) {
	const secret = "legacy-secret-0123456789abcdef"
	old := legacyEncrypt(t, secret, "stored-before-the-upgrade")

	kr := NewKeyring(secret)
	got, err := kr.Decrypt(testBinding, old)
	if err != nil {
		t.Fatalf("legacy value did not decrypt: %v", err)
	}
	if got != "stored-before-the-upgrade" {
		t.Fatalf("Decrypt = %q", got)
	}
	if !kr.NeedsReencryption(old) {
		t.Fatal("a legacy value must be reported as needing re-encryption")
	}
	// DecryptString is the compatibility entry point plugins used
	// before Keyring existed; it must read the old format too.
	if got, err := DecryptString(secret, testBinding, old); err != nil || got != "stored-before-the-upgrade" {
		t.Fatalf("DecryptString on legacy value = %q, %v", got, err)
	}
}

// Rotation: a value encrypted with the old secret stays readable once
// the old secret moves to PreviousSecrets, in both the legacy and the
// versioned format.
func TestKeyringRotation(t *testing.T) {
	const oldSecret = "old-secret-0123456789abcdefghij"
	const newSecret = "new-secret-0123456789abcdefghij"

	oldRing := NewKeyring(oldSecret)
	v1UnderOld, err := oldRing.Encrypt(testBinding, "secret-value")
	if err != nil {
		t.Fatal(err)
	}
	v0UnderOld := legacyEncrypt(t, oldSecret, "older-value")

	rotated := NewKeyring(newSecret, oldSecret)

	for name, tc := range map[string]struct{ enc, want string }{
		"versioned": {v1UnderOld, "secret-value"},
		"legacy":    {v0UnderOld, "older-value"},
	} {
		got, err := rotated.Decrypt(testBinding, tc.enc)
		if err != nil {
			t.Fatalf("%s value unreadable after rotation: %v", name, err)
		}
		if got != tc.want {
			t.Fatalf("%s: Decrypt = %q, want %q", name, got, tc.want)
		}
		if !rotated.NeedsReencryption(tc.enc) {
			t.Fatalf("%s: value under the previous key should need re-encryption", name)
		}
	}

	// New writes use the new key, and are readable by a keyring that
	// has only the new secret — that is what lets the old one be
	// dropped after re-encryption.
	fresh, err := rotated.Encrypt(testBinding, "secret-value")
	if err != nil {
		t.Fatal(err)
	}
	if rotated.NeedsReencryption(fresh) {
		t.Fatal("a fresh write must already be under the current key")
	}
	if got, err := NewKeyring(newSecret).Decrypt(testBinding, fresh); err != nil || got != "secret-value" {
		t.Fatalf("new-secret-only keyring could not read a fresh value: %q %v", got, err)
	}
}

// A value whose key is no longer configured must fail loudly, with an
// error a caller can recognise — not silently, and never by handing
// back the ciphertext.
func TestKeyringUnknownKeyFailsLoudly(t *testing.T) {
	const oldSecret = "dropped-secret-0123456789abcdef"
	const newSecret = "kept-secret-0123456789abcdefghi"

	orphan, err := NewKeyring(oldSecret).Encrypt(testBinding, "unreachable")
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewKeyring(newSecret).Decrypt(testBinding, orphan)
	if err == nil {
		t.Fatal("decryption under an unconfigured key must fail")
	}
	if !errors.Is(err, ErrNoMatchingKey) {
		t.Fatalf("err = %v, want ErrNoMatchingKey", err)
	}
	if got != "" {
		t.Fatalf("Decrypt returned %q alongside an error", got)
	}
	if strings.Contains(err.Error(), "unreachable") {
		t.Fatal("the error must not contain the plaintext")
	}

	// Same for the legacy format, where there is no key id to match on.
	legacyOrphan := legacyEncrypt(t, oldSecret, "unreachable")
	if _, err := NewKeyring(newSecret).Decrypt(testBinding, legacyOrphan); !errors.Is(err, ErrNoMatchingKey) {
		t.Fatalf("legacy orphan: err = %v, want ErrNoMatchingKey", err)
	}
}

// The key id is authenticated: relabelling a ciphertext must not be
// mistaken for a rotation problem, and must not open.
func TestKeyringKeyIDIsAuthenticated(t *testing.T) {
	const a = "secret-a-0123456789abcdefghijk"
	const b = "secret-b-0123456789abcdefghijk"
	ringA, ringB := NewKeyring(a), NewKeyring(b)

	enc, err := ringA.Encrypt(testBinding, "payload")
	if err != nil {
		t.Fatal(err)
	}
	kidB, err := ringB.CurrentKeyID()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(enc, ".")
	relabelled := "v2." + kidB + "." + parts[2]

	both := NewKeyring(b, a)
	if _, err := both.Decrypt(testBinding, relabelled); err == nil {
		t.Fatal("a relabelled ciphertext must not authenticate")
	} else if !errors.Is(err, ErrMalformedCiphertext) {
		t.Fatalf("err = %v, want ErrMalformedCiphertext", err)
	}
}

func TestKeyringRejectsGarbage(t *testing.T) {
	kr := NewKeyring("garbage-test-secret-0123456789ab")
	for _, in := range []string{
		"", "!", "v1", "v1.", "v1.abc", "v2.abcdefgh.AAAA",
		"v1.abcdefgh.!!!!", "v1.abcdefgh.AAAA.BBBB", strings.Repeat("A", 64),
	} {
		pt, err := kr.Decrypt(testBinding, in)
		if err == nil {
			t.Fatalf("Decrypt(%q) unexpectedly succeeded with %q", in, pt)
		}
		if pt != "" {
			t.Fatalf("Decrypt(%q) returned %q alongside error %v", in, pt, err)
		}
	}
}

func TestKeyringIgnoresDuplicateAndEmptyPreviousSecrets(t *testing.T) {
	const s = "dedupe-secret-0123456789abcdefg"
	kr := NewKeyring(s, "", s, s)
	if len(kr.keys) != 1 {
		t.Fatalf("keyring has %d keys, want 1", len(kr.keys))
	}
}

func TestDistinctSecretsGetDistinctKeyIDs(t *testing.T) {
	a, err := NewKeyring("kid-secret-a-0123456789abcdef").CurrentKeyID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewKeyring("kid-secret-b-0123456789abcdef").CurrentKeyID()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("different secrets produced the same key id")
	}
	if len(a) != base64.RawURLEncoding.EncodedLen(keyIDLen) {
		t.Fatalf("key id %q has unexpected length", a)
	}
}

// v1Encrypt reproduces the v1 on-disk format exactly as it was written
// before ciphertexts were bound to a storage location: same scrypt key
// derivation as v2, but with the literal "v1.<kid>" as the only
// additional authenticated data.
//
// Duplicated here on purpose, like legacyEncrypt: this is the
// compatibility contract with data already in production databases, so
// the bytes must be pinned independently of whatever aead.go does now.
func v1Encrypt(t *testing.T, secret, plaintext string) string {
	t.Helper()
	kid, gcm, err := keyFor(secret).v1()
	if err != nil {
		t.Fatal(err)
	}
	header := "v1." + kid
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), []byte(header))
	return header + "." + base64.RawURLEncoding.EncodeToString(sealed)
}

// BL-1. Every value in a deployment is encrypted under the same key, so
// without binding, a ciphertext lifted out of one column opens
// perfectly well in another. That is the whole exploit: copy a victim's
// encrypted OAuth refresh token into your own twoFactor.secret row and
// read the plaintext back out of the TOTP-URI endpoint.
//
// A v2 value must only open at the exact (model, record, field) it was
// written to.
func TestKeyringCiphertextCannotBeRelocated(t *testing.T) {
	const secret = "relocation-secret-0123456789abc"
	kr := NewKeyring(secret)

	origin := Binding{Model: "account", Record: "acc-1", Field: "refreshToken"}
	enc, err := kr.Encrypt(origin, "victim-refresh-token")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := kr.Decrypt(origin, enc); err != nil || got != "victim-refresh-token" {
		t.Fatalf("value did not open where it was written: %q %v", got, err)
	}

	elsewhere := map[string]Binding{
		"another model":  {Model: "twoFactor", Record: "acc-1", Field: "refreshToken"},
		"another record": {Model: "account", Record: "acc-2", Field: "refreshToken"},
		"another field":  {Model: "account", Record: "acc-1", Field: "accessToken"},
		"the 2FA secret column of an attacker-controlled row": {
			Model: "twoFactor", Record: "attacker-row", Field: "secret"},
	}
	for name, b := range elsewhere {
		got, err := kr.Decrypt(b, enc)
		if err == nil {
			t.Fatalf("%s: a relocated ciphertext opened and yielded %q", name, got)
		}
		if !errors.Is(err, ErrMalformedCiphertext) {
			t.Fatalf("%s: err = %v, want ErrMalformedCiphertext", name, err)
		}
		if got != "" {
			t.Fatalf("%s: Decrypt returned %q alongside an error", name, got)
		}
		if strings.Contains(err.Error(), "victim-refresh-token") {
			t.Fatalf("%s: the error leaked the plaintext", name)
		}
	}
}

// The binding components are length-prefixed, so no two distinct
// bindings can serialise to the same additional data by shuffling
// characters across a separator.
func TestBindingComponentsCannotBeConfused(t *testing.T) {
	const secret = "confusion-secret-0123456789abcd"
	kr := NewKeyring(secret)

	a := Binding{Model: "ab", Record: "c", Field: "d"}
	b := Binding{Model: "a", Record: "bc", Field: "d"}

	enc, err := kr.Encrypt(a, "payload")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := kr.Decrypt(b, enc); err == nil {
		t.Fatalf("bindings %v and %v were confused, yielding %q", a, b, got)
	}
}

// An incomplete binding is a programming error, not something to paper
// over by writing an unbound value.
func TestKeyringRejectsIncompleteBinding(t *testing.T) {
	kr := NewKeyring("incomplete-binding-secret-01234")
	for name, b := range map[string]Binding{
		"no model":  {Record: "r", Field: "f"},
		"no record": {Model: "m", Field: "f"},
		"no field":  {Model: "m", Record: "r"},
		"empty":     {},
	} {
		if _, err := kr.Encrypt(b, "x"); !errors.Is(err, ErrInvalidBinding) {
			t.Fatalf("%s: Encrypt err = %v, want ErrInvalidBinding", name, err)
		}
	}
	// Reading a v2 value without a binding must fail the same way, not
	// fall through to an unauthenticated open.
	enc, err := kr.Encrypt(testBinding, "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Decrypt(Binding{}, enc); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("Decrypt err = %v, want ErrInvalidBinding", err)
	}
}

// Compatibility: v1 values sitting in a deployed database must still
// read after the upgrade, and must be reported as needing migration.
func TestKeyringReadsUnboundV1(t *testing.T) {
	const secret = "v1-compat-secret-0123456789abcd"
	old := v1Encrypt(t, secret, "written-before-binding")
	if !strings.HasPrefix(old, "v1.") {
		t.Fatalf("fixture %q is not a v1 value", old)
	}

	kr := NewKeyring(secret)
	got, err := kr.Decrypt(testBinding, old)
	if err != nil {
		t.Fatalf("a v1 value stopped being readable: %v", err)
	}
	if got != "written-before-binding" {
		t.Fatalf("Decrypt = %q", got)
	}
	if !kr.NeedsReencryption(old) {
		t.Fatal("an unbound v1 value must be reported as needing re-encryption")
	}
	// The binding is not authenticated for v1, which is exactly why the
	// format has to be migrated away from: the same value opens
	// anywhere.
	if _, err := kr.Decrypt(Binding{Model: "x", Record: "y", Field: "z"}, old); err != nil {
		t.Fatalf("v1 compatibility read is supposed to ignore the binding: %v", err)
	}
}

// ... and once a deployment has migrated, the operator can stop
// accepting them, which is what actually closes the relocation hole for
// ciphertexts captured from an old backup.
func TestKeyringRejectUnboundClosesTheDowngrade(t *testing.T) {
	const secret = "reject-unbound-secret-0123456789"
	v0 := legacyEncrypt(t, secret, "ancient")
	v1 := v1Encrypt(t, secret, "old")

	strict := NewKeyringFrom(KeyringOptions{Current: secret, RejectUnbound: true})
	if strict.AcceptsUnbound() {
		t.Fatal("RejectUnbound was not honoured")
	}
	for name, enc := range map[string]string{"v0": v0, "v1": v1} {
		got, err := strict.Decrypt(testBinding, enc)
		if !errors.Is(err, ErrUnboundCiphertext) {
			t.Fatalf("%s: err = %v, want ErrUnboundCiphertext", name, err)
		}
		if got != "" {
			t.Fatalf("%s: Decrypt returned %q alongside an error", name, got)
		}
	}
	// Bound values are unaffected.
	enc, err := strict.Encrypt(testBinding, "current")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := strict.Decrypt(testBinding, enc); err != nil || got != "current" {
		t.Fatalf("a bound value must still read: %q %v", got, err)
	}
	// And a lenient keyring over the same data still reads them, so the
	// switch is reversible.
	if _, err := NewKeyring(secret).Decrypt(testBinding, v1); err != nil {
		t.Fatalf("clearing RejectUnbound must make the value readable again: %v", err)
	}
}
