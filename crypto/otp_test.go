package crypto

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

// BL-1, part 2. TOTPURI used to echo whatever it was handed straight
// into the otpauth:// URI it returns, which made it the read end of the
// ciphertext-relocation attack: whatever ended up in the "secret"
// column came back out of /two-factor/get-totp-uri verbatim.
//
// It must refuse anything that is not a TOTP secret, and the refusal
// must be explicit.
func TestTOTPURIRejectsNonBase32Secrets(t *testing.T) {
	for name, secret := range map[string]string{
		"empty":                    "",
		"an ed25519 signing key":   "kQe7ZzT1x-9pAbCdEfGhIjKlMnOpQrStUvWxYz012345",
		"an oauth refresh token":   "1//0gLm3xY_pQrs-tuvWXYZ.abc",
		"a keyring ciphertext":     "v2.xPSBV9Ra.AAAAAAAAAAAAAAAAAAAAAAAA",
		"base32 with 0/1/8/9":      "01890189018901890",
		"too short to be a secret": "JBSWY3DP", // 40 bits
	} {
		uri, err := TOTPURI("Issuer", "user@example.com", secret, 30, 6)
		if !errors.Is(err, ErrInvalidTOTPSecret) {
			t.Fatalf("%s: err = %v, want ErrInvalidTOTPSecret", name, err)
		}
		if uri != "" {
			t.Fatalf("%s: TOTPURI returned %q alongside an error", name, uri)
		}
		if secret != "" && strings.Contains(err.Error(), secret) {
			t.Fatalf("%s: the error echoed the rejected value", name)
		}
	}
}

func TestTOTPURIAcceptsAGeneratedSecret(t *testing.T) {
	secret := GenerateTOTPSecret()
	uri, err := TOTPURI("Acme Inc", "ada@example.com", secret, 0, 0)
	if err != nil {
		t.Fatalf("a freshly generated secret was rejected: %v", err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("uri = %q", uri)
	}
	if got := u.Query().Get("secret"); got != secret {
		t.Fatalf("secret = %q, want %q", got, secret)
	}
	if got := u.Query().Get("period"); got != "30" {
		t.Fatalf("period = %q, want the default 30", got)
	}
	if got := u.Query().Get("digits"); got != "6" {
		t.Fatalf("digits = %q, want the default 6", got)
	}
}

func TestValidateTOTPSecretAcceptsLowercaseAndPadding(t *testing.T) {
	secret := GenerateTOTPSecret()
	for name, in := range map[string]string{
		"as generated": secret,
		"lowercased":   strings.ToLower(secret),
		"padded":       secret + "======",
	} {
		if err := ValidateTOTPSecret(in); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
