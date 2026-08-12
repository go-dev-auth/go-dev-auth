package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fuzz targets for the parsers that attacker-controlled bytes reach:
// JWT verification and decoding, JWK import, the "salt:key" password
// hash format, HOTP/TOTP codes, the domain-separated HMAC used by signed
// cookies, and AES-GCM decryption.
//
// Every target asserts a security property, not merely the absence of a
// panic. The recurring shape is "acceptance implies authenticity": if a
// verifier returns success for fuzzer-supplied bytes, the test
// recomputes what the only acceptable input could have been and fails if
// they differ. A signature-bypass bug therefore fails the test even
// though it does not crash.
//
// Run one with:
//
//	go test -run '^$' -fuzz=FuzzVerifyJWT -fuzztime=30s ./crypto/...

// ---------------------------------------------------------------------
// shared key material
// ---------------------------------------------------------------------

type jwtKeys struct {
	hmac string

	edPriv ed25519.PrivateKey
	edPub  ed25519.PublicKey

	rsaPriv *rsa.PrivateKey
	ecPriv  *ecdsa.PrivateKey

	// validFor maps a verification key to the one token that key must
	// accept. Anything else accepted is a forgery.
	valid map[string]string
}

var (
	keysOnce sync.Once
	keys     *jwtKeys
)

// testKeys builds one key of each supported type. Generating RSA keys is
// slow, so it happens once for the whole fuzzing run.
func testKeys(tb testing.TB) *jwtKeys {
	tb.Helper()
	keysOnce.Do(func() {
		k := &jwtKeys{hmac: "fuzz-hmac-secret-0123456789abcdef"}
		var err error
		k.edPub, k.edPriv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		// 2048 bits is the smallest size worth asserting on and keeps
		// key generation off the hot path of the fuzz loop.
		k.rsaPriv, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		k.ecPriv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		claims := Claims{
			"sub": "user-1",
			"iss": "fuzz",
			// A fixed far-future instant, not now+delta: the seeded
			// tokens must be byte-identical across runs so a recorded
			// corpus entry stays meaningful.
			"exp": float64(4102444800), // 2100-01-01T00:00:00Z
		}
		k.valid = map[string]string{}
		for name, signer := range map[string]any{
			"hmac": k.hmac,
			"ed":   k.edPriv,
			"rsa":  k.rsaPriv,
			"ec":   k.ecPriv,
		} {
			tok, err := SignJWT(signer, "kid1", claims)
			if err != nil {
				panic(err)
			}
			k.valid[name] = tok
		}
		keys = k
	})
	return keys
}

// sameSignedToken reports whether got is the same token as want: equal
// signing input and a signature that decodes to the same bytes.
//
// Comparing decoded signature bytes rather than the base64 text avoids
// flagging a non-canonical re-encoding of the identical signature, which
// is not a forgery.
func sameSignedToken(got, want string) bool {
	g := strings.Split(got, ".")
	w := strings.Split(want, ".")
	if len(g) != 3 || len(w) != 3 {
		return false
	}
	if g[0] != w[0] || g[1] != w[1] {
		return false
	}
	gs, err1 := base64.RawURLEncoding.DecodeString(g[2])
	ws, err2 := base64.RawURLEncoding.DecodeString(w[2])
	return err1 == nil && err2 == nil && bytes.Equal(gs, ws)
}

// ---------------------------------------------------------------------
// JWT
// ---------------------------------------------------------------------

// FuzzVerifyJWT asserts that no fuzzer-supplied token verifies under any
// of the four supported key types unless it is the genuinely signed one.
//
// For HMAC the check is exact: the signature is recomputed. For the
// asymmetric keys, producing a second valid signature requires the
// private key, so any accepted token that is not the seeded one is a
// forgery — which is what an alg-confusion or signature-stripping bug
// looks like from the outside.
func FuzzVerifyJWT(f *testing.F) {
	k := testKeys(f)

	for _, tok := range k.valid {
		f.Add(tok)
	}
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("a.b.c")
	// alg:none with a payload but an empty signature - the canonical
	// signature-stripping attack.
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.")
	// alg:none with the signature segment removed entirely.
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9")
	// HS256 header over an empty payload.
	f.Add("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.")
	// a header that is valid base64 but not JSON
	f.Add("Zm9v.Zm9v.Zm9v")
	f.Add(strings.Repeat("A", 4096) + "." + strings.Repeat("B", 4096) + ".QQ")

	f.Fuzz(func(t *testing.T, token string) {
		k := testKeys(t)

		type check struct {
			name string
			key  any
		}
		for _, c := range []check{
			{"hmac", k.hmac},
			{"hmac", []byte(k.hmac)},
			{"ed", k.edPub},
			{"rsa", &k.rsaPriv.PublicKey},
			{"ec", &k.ecPriv.PublicKey},
		} {
			claims, err := VerifyJWT(c.key, token)
			if err != nil {
				if claims != nil {
					t.Fatalf("VerifyJWT(%s) returned claims %v alongside error %v", c.name, claims, err)
				}
				continue
			}
			if c.name == "hmac" {
				// The HMAC secret is a fixed constant, so the exact
				// check is available: recompute the MAC. (Comparing
				// against one seeded token would be wrong here — a
				// corpus entry carrying different claims but a correct
				// MAC is genuinely valid, not a forgery.)
				parts := strings.Split(token, ".")
				sig, decErr := base64.RawURLEncoding.DecodeString(parts[2])
				if decErr != nil || !bytes.Equal(sig, hmacSHA256([]byte(k.hmac), parts[0]+"."+parts[1])) {
					t.Fatalf("VerifyJWT(hmac) accepted %q whose signature is not HMAC(signing input)", token)
				}
				continue
			}
			// The asymmetric keys are generated per process, so the only
			// token that can verify is the one this process signed.
			// Anything else would be a forgery.
			if !sameSignedToken(token, k.valid[c.name]) {
				t.Fatalf("VerifyJWT(%s) accepted a token it never signed:\n got: %q\nwant: %q",
					c.name, token, k.valid[c.name])
			}
		}
	})
}

// FuzzJWTAlgConfusion asserts the classic attack stays closed: a token
// whose HMAC key is the verifier's *public* key must never verify
// against that public key, whatever the payload.
func FuzzJWTAlgConfusion(f *testing.F) {
	f.Add([]byte(`{"sub":"admin"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`{"exp":99999999999}`))

	f.Fuzz(func(t *testing.T, payload []byte) {
		k := testKeys(t)

		pubs := map[string][]byte{
			"ed": k.edPub,
			"ec": append(k.ecPriv.X.Bytes(), k.ecPriv.Y.Bytes()...),
			"rs": k.rsaPriv.PublicKey.N.Bytes(),
		}
		verifiers := []any{k.edPub, &k.ecPriv.PublicKey, &k.rsaPriv.PublicKey}

		for _, pub := range pubs {
			// Forge "HS256 signed with the public key as the secret".
			header := b64([]byte(`{"alg":"HS256","typ":"JWT"}`))
			body := b64(payload)
			signingInput := header + "." + body
			forged := signingInput + "." + b64(hmacSHA256(pub, signingInput))

			for _, v := range verifiers {
				if _, err := VerifyJWT(v, forged); err == nil {
					t.Fatalf("alg confusion: HS256 token keyed on the public key verified against %T", v)
				}
			}
			// The same trick with alg:none.
			none := b64([]byte(`{"alg":"none"}`)) + "." + body + "."
			for _, v := range verifiers {
				if _, err := VerifyJWT(v, none); err == nil {
					t.Fatalf("alg:none token verified against %T", v)
				}
			}
		}
	})
}

// FuzzDecodeJWTClaims checks the unauthenticated decode path. It must
// never panic and must agree with a straightforward reimplementation:
// success implies the payload segment really was base64url-encoded JSON.
func FuzzDecodeJWTClaims(f *testing.F) {
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwiZXhwIjo5OTk5OTk5OTk5fQ.sig")
	f.Add("a.b")
	f.Add("")
	f.Add(".")
	f.Add("x")
	f.Add("eyJhbGciOiJIUzI1NiJ9.bnVsbA.")     // payload "null"
	f.Add("eyJhbGciOiJIUzI1NiJ9.WzEsMiwzXQ.") // payload "[1,2,3]"
	f.Add("eyJhbGciOiJIUzI1NiJ9.IjEyMyI.")    // payload "\"123\""
	f.Add(strings.Repeat("e", 1000) + ".ZQ.Zg")
	f.Add("eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.a.b.c.d") // too many segments

	f.Fuzz(func(t *testing.T, token string) {
		claims, err := DecodeJWTClaims(token)
		if err != nil {
			if claims != nil {
				t.Fatalf("DecodeJWTClaims returned claims %v with error %v", claims, err)
			}
			return
		}
		parts := strings.Split(token, ".")
		if len(parts) < 2 {
			t.Fatalf("decoded a token with %d segments: %q", len(parts), token)
		}
		raw, decErr := base64.RawURLEncoding.DecodeString(parts[1])
		if decErr != nil {
			t.Fatalf("decoded a payload that is not base64url: %q", parts[1])
		}
		// A successful decode must have produced a JSON object; the API
		// returns Claims (a map), so anything else would have to have
		// been coerced.
		trimmed := strings.TrimSpace(string(raw))
		if claims != nil && !strings.HasPrefix(trimmed, "{") {
			t.Fatalf("non-object payload %q produced non-nil claims %v", trimmed, claims)
		}
	})
}

// FuzzJWKPublicKey feeds hostile JWK fields to the importer. Beyond "no
// panic", the property is that whatever key comes back cannot be used to
// verify a token the fuzzer also controls: an imported key must never
// turn into a signature-bypass.
func FuzzJWKPublicKey(f *testing.F) {
	f.Add("OKP", "Ed25519", "", "", "", "")
	f.Add("EC", "P-256", "AAAA", "AAAA", "", "")
	f.Add("RSA", "", "", "", "AQAB", "AQAB")
	f.Add("RSA", "", "", "", strings.Repeat("_", 700), "AQAB")
	f.Add("RSA", "", "", "", "AA", "AA")   // zero modulus, zero exponent
	f.Add("RSA", "", "", "", "AQ", "____") // huge exponent
	f.Add("oct", "", "AAAA", "", "", "")
	f.Add("", "", "", "", "", "")
	f.Add("EC", "P-256", "!!!!", "????", "", "")

	f.Fuzz(func(t *testing.T, kty, crv, x, y, n, e string) {
		// A modulus longer than any real key turns rsa.VerifyPKCS1v15
		// into a very slow big.Int operation; that is a fuzzing-speed
		// problem, not a bug, so bound the inputs.
		if len(x)+len(y)+len(n)+len(e) > 1024 {
			return
		}
		jwk := JWK{Kty: kty, Crv: crv, X: x, Y: y, N: n, E: e}
		pub, err := jwk.PublicKey()
		if err != nil {
			if pub != nil {
				t.Fatalf("PublicKey returned %T alongside error %v", pub, err)
			}
			return
		}
		if pub == nil {
			t.Fatal("PublicKey returned (nil, nil)")
		}
		// An imported key must reject tokens nobody signed with it.
		for _, tok := range []string{
			"eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",
			"eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhZG1pbiJ9.AAAA",
			"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.AAAA",
			"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.AAAA",
			"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.AAAA",
		} {
			if _, err := VerifyJWT(pub, tok); err == nil {
				t.Fatalf("JWK %+v imported to %T which verified the unsigned token %q", jwk, pub, tok)
			}
		}
	})
}

// ---------------------------------------------------------------------
// password hashes
// ---------------------------------------------------------------------

// fuzzScryptHasher uses the smallest legal scrypt parameters. The format
// parsing and the constant-time comparison are what is under test; the
// work factor only slows the fuzzer down.
var fuzzScryptHasher = NewScryptHasher(ScryptParams{N: 2, R: 1, P: 1, KeyLen: 16})

// FuzzScryptVerify drives the "saltHex:keyHex" parsing path with
// arbitrary stored values. The property is that Verify only ever returns
// true for a stored value that really is the hash of that password under
// the salt it carries — a malformed hash must never authenticate.
func FuzzScryptVerify(f *testing.F) {
	genuine, err := fuzzScryptHasher.Hash("correct horse battery staple")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(genuine, "correct horse battery staple")
	f.Add(genuine, "wrong password")
	f.Add("", "")
	f.Add(":", "")
	f.Add(":", "x")
	f.Add("::", "x")
	f.Add("abcd:", "x")
	f.Add(":abcd", "x")
	f.Add("zz:zz", "x")
	f.Add("00:", "")
	f.Add(strings.Repeat("0", 32)+":"+strings.Repeat("0", 32), "x")

	f.Fuzz(func(t *testing.T, stored, password string) {
		// Long salts make scrypt slow without exercising anything new.
		if len(stored) > 4096 || len(password) > 4096 {
			return
		}
		h := fuzzScryptHasher
		ok, err := h.Verify(stored, password)
		if err != nil {
			if ok {
				t.Fatalf("Verify returned true alongside error %v", err)
			}
			return
		}
		if !ok {
			return
		}
		// Accepted. Recompute what the only acceptable stored value is.
		saltHex, _, found := strings.Cut(stored, ":")
		if !found {
			t.Fatalf("Verify accepted %q which has no salt separator", stored)
		}
		want, derr := h.derive([]byte(password), []byte(saltHex))
		if derr != nil {
			t.Fatalf("re-deriving: %v", derr)
		}
		expected := saltHex + ":" + hex.EncodeToString(want)
		if !strings.EqualFold(stored, expected) {
			t.Fatalf("Verify accepted a hash it should not have:\nstored:   %q\nexpected: %q", stored, expected)
		}
	})
}

// ---------------------------------------------------------------------
// one-time passwords
// ---------------------------------------------------------------------

// FuzzVerifyTOTP feeds arbitrary secrets and codes to the TOTP verifier.
// The properties: it never panics on a malformed base32 secret, it never
// accepts a code outside the skew window, and the codes HOTP produces
// are always exactly `digits` decimal characters (an oracle that
// sometimes emits a shorter string would leak counter state through
// length).
func FuzzVerifyTOTP(f *testing.F) {
	secret := GenerateTOTPSecret()
	now := time.Unix(1_700_000_000, 0)
	code, err := TOTP(secret, now, 30, 6)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(secret, code, 30, 6, 1)
	f.Add(secret, "000000", 30, 6, 1)
	f.Add("", "", 30, 6, 1)
	f.Add("!!!!!!!!", "123456", 30, 6, 1)
	f.Add("a", "1", 0, 1, 0)
	f.Add("JBSWY3DPEHPK3PXP", "", 30, 8, 2)
	f.Add(strings.Repeat("A", 200), "12345678", 1, 8, 10)

	f.Fuzz(func(t *testing.T, secret, code string, period, digits, skew int) {
		// digits and period come from configuration, not from the
		// network; keep them in the range a configuration can express so
		// the target measures the parsing surface.
		if digits < 1 || digits > 10 || period < 0 || period > 3600 {
			return
		}
		if skew < 0 || skew > 16 || len(secret) > 4096 {
			return
		}
		now := time.Unix(1_700_000_000, 0)

		got := VerifyTOTP(secret, code, now, period, digits, skew)
		if !got {
			return
		}
		// Accepted: the code must equal HOTP at some counter inside the
		// window, and nothing else.
		p := period
		if p <= 0 {
			p = 30
		}
		counter := int64(uint64(now.Unix()) / uint64(p))
		matched := false
		for i := -skew; i <= skew; i++ {
			c := counter + int64(i)
			if c < 0 {
				continue
			}
			want, err := HOTP(secret, uint64(c), digits)
			if err != nil {
				t.Fatalf("VerifyTOTP accepted %q but HOTP errors: %v", code, err)
			}
			if len(want) != digits {
				t.Fatalf("HOTP(%d digits) produced %q (%d chars)", digits, want, len(want))
			}
			for _, r := range want {
				if r < '0' || r > '9' {
					t.Fatalf("HOTP produced a non-digit code %q", want)
				}
			}
			if want == code {
				matched = true
			}
		}
		if !matched {
			t.Fatalf("VerifyTOTP accepted %q for secret %q, but no counter in the skew window produces it", code, secret)
		}
	})
}

// ---------------------------------------------------------------------
// signed values and AEAD
// ---------------------------------------------------------------------

// FuzzVerifyHMACPurpose asserts the domain separation that signed
// cookies rely on: a signature is only valid for the exact (purpose,
// value) pair it was minted for, and a fuzzer-supplied signature is
// never accepted unless it equals the real one.
func FuzzVerifyHMACPurpose(f *testing.F) {
	const key = "fuzz-cookie-secret-0123456789abc"
	f.Add("session-token", "tok", SignHMACPurpose(key, "session-token", "tok"))
	f.Add("session-token", "tok", "")
	f.Add("", "", "")
	f.Add("a", "b", "c")
	f.Add("session-token", "tok", SignHMACPurpose(key, "session-data", "tok"))
	f.Add("session-data", "tok", SignHMACPurpose(key, "session-token", "tok"))

	f.Fuzz(func(t *testing.T, purpose, value, sig string) {
		const key = "fuzz-cookie-secret-0123456789abc"
		if !VerifyHMACPurpose(key, purpose, value, sig) {
			return
		}
		if want := SignHMACPurpose(key, purpose, value); sig != want {
			t.Fatalf("accepted signature %q for (%q,%q); only %q is valid", sig, purpose, value, want)
		}
		// Domain separation: the same signature must not validate under
		// a different purpose.
		if purpose != "other-purpose" && VerifyHMACPurpose(key, "other-purpose", value, sig) {
			t.Fatalf("signature for purpose %q also validated under a different purpose", purpose)
		}
		// And not under a different key.
		if VerifyHMACPurpose(key+"x", purpose, value, sig) {
			t.Fatal("signature validated under a different key")
		}
	})
}

// FuzzDecryptString drives AES-GCM open with arbitrary base64url input.
// Nothing the fuzzer produces should ever authenticate.
func FuzzDecryptString(f *testing.F) {
	const secret = "fuzz-aead-secret"
	fuzzBinding := Binding{Model: "account", Record: "acc-1", Field: "refreshToken"}
	enc, err := EncryptString(secret, fuzzBinding, "plaintext")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(enc)
	f.Add("")
	f.Add("A")
	f.Add("AAAAAAAAAAAAAAAA")
	f.Add(strings.Repeat("A", 64))
	f.Add("!!!!")

	f.Fuzz(func(t *testing.T, blob string) {
		const secret = "fuzz-aead-secret"
		if len(blob) > 8192 {
			return
		}
		fuzzBinding := Binding{Model: "account", Record: "acc-1", Field: "refreshToken"}
		pt, err := DecryptString(secret, fuzzBinding, blob)
		if err != nil {
			if pt != "" {
				t.Fatalf("DecryptString returned %q alongside error %v", pt, err)
			}
			return
		}
		// A successful open must round-trip: re-encrypting the
		// plaintext and decrypting must yield the same value.
		again, err := EncryptString(secret, fuzzBinding, pt)
		if err != nil {
			t.Fatal(err)
		}
		back, err := DecryptString(secret, fuzzBinding, again)
		if err != nil || back != pt {
			t.Fatalf("round trip failed: %q -> %q (%v)", pt, back, err)
		}
		// The same ciphertext must not open under a different secret.
		if _, err := DecryptString(secret+"x", fuzzBinding, blob); err == nil {
			t.Fatalf("ciphertext %q opened under the wrong secret", blob)
		}
	})
}
