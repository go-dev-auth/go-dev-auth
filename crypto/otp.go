package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ErrInvalidTOTPSecret means a value handed to TOTPURI is not a usable
// TOTP secret: not base32, or too short to be one.
//
// TOTPURI used to echo whatever it was given straight into the
// otpauth:// URI it returns. That made it the read end of any confusion
// about what a "secret" column holds — a value that is not a TOTP
// secret at all (an OAuth refresh token, a signing key) would be
// reflected back to the caller verbatim. It now refuses.
var ErrInvalidTOTPSecret = errors.New("crypto: not a valid base32 TOTP secret")

// minTOTPSecretBytes is the smallest shared secret RFC 4226 §4 allows
// (80 bits). GenerateTOTPSecret produces 160.
const minTOTPSecretBytes = 10

// ValidateTOTPSecret reports whether secret is a base32 string of at
// least 80 bits, the RFC 4226 minimum. Call it on anything read out of
// storage before treating it as a TOTP secret.
func ValidateTOTPSecret(secret string) error {
	if secret == "" {
		return fmt.Errorf("%w: empty", ErrInvalidTOTPSecret)
	}
	key, err := decodeBase32(secret)
	if err != nil {
		// The input is a credential; it is never echoed into the error.
		return fmt.Errorf("%w: not base32", ErrInvalidTOTPSecret)
	}
	if len(key) < minTOTPSecretBytes {
		return fmt.Errorf("%w: %d bits, want at least %d",
			ErrInvalidTOTPSecret, len(key)*8, minTOTPSecretBytes*8)
	}
	return nil
}

// HOTP computes the HMAC-based one-time password (RFC 4226) for the given
// base32 encoded secret and counter.
func HOTP(secret string, counter uint64, digits int) (string, error) {
	key, err := decodeBase32(secret)
	if err != nil {
		return "", err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod), nil
}

// TOTP computes the time-based one-time password (RFC 6238) for the given
// base32 encoded secret at time t.
func TOTP(secret string, t time.Time, period int, digits int) (string, error) {
	if period <= 0 {
		period = 30
	}
	counter := uint64(t.Unix()) / uint64(period)
	return HOTP(secret, counter, digits)
}

// VerifyTOTP checks code against the secret allowing skew steps of clock
// drift in both directions.
func VerifyTOTP(secret, code string, t time.Time, period, digits, skew int) bool {
	_, ok := VerifyTOTPCounter(secret, code, t, period, digits, skew)
	return ok
}

// VerifyTOTPCounter is VerifyTOTP that also returns the time-step
// counter the code matched. The caller persists it and refuses any
// later code whose counter is not strictly greater, which is what turns
// a one-time password into an actually one-time one: without it a
// shoulder-surfed or phished code stays valid for the whole skew window
// (RFC 6238 §5.2).
func VerifyTOTPCounter(secret, code string, t time.Time, period, digits, skew int) (int64, bool) {
	if period <= 0 {
		period = 30
	}
	counter := int64(uint64(t.Unix()) / uint64(period))
	for i := -skew; i <= skew; i++ {
		c := counter + int64(i)
		if c < 0 {
			continue
		}
		want, err := HOTP(secret, uint64(c), digits)
		if err != nil {
			return 0, false
		}
		if ConstantTimeEqual(want, code) {
			return c, true
		}
	}
	return 0, false
}

// GenerateTOTPSecret returns a new random base32 encoded TOTP secret.
func GenerateTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic("crypto: rand failure: " + err.Error())
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// TOTPURI builds an otpauth:// URI suitable for authenticator apps.
//
// It validates the secret (see ValidateTOTPSecret) and returns
// ErrInvalidTOTPSecret rather than emitting a URI containing something
// that is not a TOTP secret. The failure is explicit: a caller that
// hands it the wrong bytes gets an error, not a URI its user will scan
// into an authenticator that can never produce a matching code.
func TOTPURI(issuer, accountName, secret string, period, digits int) (string, error) {
	if err := ValidateTOTPSecret(secret); err != nil {
		return "", err
	}
	if period <= 0 {
		period = 30
	}
	if digits <= 0 {
		digits = 6
	}
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("period", fmt.Sprintf("%d", period))
	q.Set("digits", fmt.Sprintf("%d", digits))
	q.Set("algorithm", "SHA1")
	label := url.PathEscape(issuer) + ":" + url.PathEscape(accountName)
	return "otpauth://totp/" + label + "?" + q.Encode(), nil
}

func decodeBase32(s string) ([]byte, error) {
	s = strings.ToUpper(strings.TrimRight(s, "="))
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}
