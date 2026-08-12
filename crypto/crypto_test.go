package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"
)

// RFC 7914 test vectors.
func TestScryptVectors(t *testing.T) {
	cases := []struct {
		password, salt string
		N, r, p        int
		want           string
	}{
		{"", "", 16, 1, 1,
			"77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"},
		{"password", "NaCl", 1024, 8, 16,
			"fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"},
		{"pleaseletmein", "SodiumChloride", 16384, 8, 1,
			"7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"},
	}
	for _, tc := range cases {
		got, err := Scrypt([]byte(tc.password), []byte(tc.salt), tc.N, tc.r, tc.p, 64)
		if err != nil {
			t.Fatalf("scrypt(%q): %v", tc.password, err)
		}
		if hex.EncodeToString(got) != tc.want {
			t.Errorf("scrypt(%q) = %x, want %s", tc.password, got, tc.want)
		}
	}
}

func TestPasswordHasher(t *testing.T) {
	h := ScryptHasher{}
	hash, err := h.Hash("s3cret-password")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := h.Verify(hash, "s3cret-password")
	if err != nil || !ok {
		t.Fatalf("expected password to verify, ok=%v err=%v", ok, err)
	}
	ok, err = h.Verify(hash, "wrong-password")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("wrong password verified")
	}
}

// RFC 6238 TOTP test vectors (SHA-1, 8 digits) use the ASCII secret
// "12345678901234567890" which is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ in
// base32.
func TestTOTPVectors(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cases := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
	}
	for _, tc := range cases {
		got, err := TOTP(secret, time.Unix(tc.unix, 0), 30, 8)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("TOTP(%d) = %s, want %s", tc.unix, got, tc.want)
		}
	}
}

func TestVerifyTOTPSkew(t *testing.T) {
	secret := GenerateTOTPSecret()
	now := time.Now()
	code, err := TOTP(secret, now.Add(-30*time.Second), 30, 6)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyTOTP(secret, code, now, 30, 6, 1) {
		t.Error("expected code from previous step to verify with skew=1")
	}
	if VerifyTOTP(secret, code, now.Add(90*time.Second), 30, 6, 1) {
		t.Error("expected stale code to fail")
	}
}

func TestJWTRoundTripEdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := SignJWT(priv, "kid1", Claims{"sub": "user1", "exp": time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyJWT(pub, token)
	if err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "user1" {
		t.Errorf("sub = %v", claims["sub"])
	}
	// tampered token
	if _, err := VerifyJWT(pub, token+"x"); err == nil {
		t.Error("expected tampered token to fail")
	}
	// expired token
	expired, _ := SignJWT(priv, "kid1", Claims{"sub": "user1", "exp": time.Now().Add(-time.Hour).Unix()})
	if _, err := VerifyJWT(pub, expired); err != ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestJWTHS256(t *testing.T) {
	token, err := SignJWT("secret-key", "", Claims{"sub": "u"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyJWT("secret-key", token); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyJWT("wrong-key", token); err == nil {
		t.Error("expected wrong key to fail")
	}
}

func TestJWKRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := PublicJWK("k1", pub)
	if err != nil {
		t.Fatal(err)
	}
	back, err := jwk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(back.(ed25519.PublicKey)) {
		t.Error("JWK round trip mismatch")
	}
}

func TestAEADRoundTrip(t *testing.T) {
	b := Binding{Model: "account", Record: "acc-1", Field: "accessToken"}
	enc, err := EncryptString("secret", b, "hello world")
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptString("secret", b, enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec != "hello world" {
		t.Errorf("got %q", dec)
	}
	if _, err := DecryptString("wrong", b, enc); err == nil {
		t.Error("expected wrong secret to fail")
	}
	// The same ciphertext presented at a different column must not open.
	elsewhere := Binding{Model: "account", Record: "acc-1", Field: "refreshToken"}
	if _, err := DecryptString("secret", elsewhere, enc); err == nil {
		t.Error("expected a relocated ciphertext to fail")
	}
}

func TestHMAC(t *testing.T) {
	sig := SignHMAC("key", "value")
	if !VerifyHMAC("key", "value", sig) {
		t.Error("expected signature to verify")
	}
	if VerifyHMAC("key", "other", sig) {
		t.Error("expected bad value to fail")
	}
	if VerifyHMAC("other", "value", sig) {
		t.Error("expected bad key to fail")
	}
}

func TestGenerators(t *testing.T) {
	if len(GenerateID(32)) != 32 {
		t.Error("GenerateID length")
	}
	if GenerateID(32) == GenerateID(32) {
		t.Error("GenerateID collision")
	}
	if len(GenerateOTP(6)) != 6 {
		t.Error("GenerateOTP length")
	}
	if GenerateToken(32) == GenerateToken(32) {
		t.Error("GenerateToken collision")
	}
}
