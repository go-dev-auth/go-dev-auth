package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"hash"
	"sync"
)

const idAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// idAlphabetMask is the smallest power-of-two mask covering the
// alphabet (62 -> 63), used for unbiased rejection sampling.
const idAlphabetMask = 63

// GenerateID returns a random alphanumeric identifier of the given
// length. It draws entropy in a single read and uses rejection sampling
// so the distribution stays uniform.
func GenerateID(length int) string {
	if length <= 0 {
		length = 32
	}
	out := make([]byte, length)
	// 1.35x oversampling: with a 62/64 acceptance rate a single extra
	// batch is enough in virtually all cases, and the loop covers the
	// rest.
	buf := make([]byte, length+length/4+8)
	i := 0
	for i < length {
		mustRand(buf)
		for _, b := range buf {
			if i >= length {
				break
			}
			b &= idAlphabetMask
			if int(b) >= len(idAlphabet) {
				continue // reject, keeps the distribution uniform
			}
			out[i] = idAlphabet[b]
			i++
		}
	}
	return string(out)
}

// GenerateToken returns a URL-safe random token with n bytes of entropy.
func GenerateToken(n int) string {
	if n <= 0 {
		n = 32
	}
	b := make([]byte, n)
	mustRand(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// GenerateOTP returns a random numeric one-time code of the given
// length, using rejection sampling to avoid modulo bias.
func GenerateOTP(digits int) string {
	if digits <= 0 {
		digits = 6
	}
	out := make([]byte, digits)
	buf := make([]byte, digits+digits/2+8)
	i := 0
	for i < digits {
		mustRand(buf)
		for _, b := range buf {
			if i >= digits {
				break
			}
			// accept 0..249 so each digit is equally likely
			if b >= 250 {
				continue
			}
			out[i] = byte('0' + b%10)
			i++
		}
	}
	return string(out)
}

// mustRand fills b with cryptographically secure random bytes. A
// failure of the system CSPRNG is not recoverable for an auth library:
// continuing would silently emit predictable tokens.
func mustRand(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic("go-dev-auth/crypto: system CSPRNG unavailable: " + err.Error())
	}
}

// SignHMAC returns the base64url encoded HMAC-SHA256 of value under key.
//
// Deprecated in favour of SignHMACPurpose: signatures produced here are
// not domain separated, so a signature minted for one kind of value is
// valid for another. Retained for compatibility.
func SignHMAC(key, value string) string {
	return SignHMACPurpose(key, "", value)
}

// VerifyHMAC reports whether sig is a valid signature of value under key.
func VerifyHMAC(key, value, sig string) bool {
	return VerifyHMACPurpose(key, "", value, sig)
}

// macPool reuses HMAC state across calls. Every authenticated request
// verifies at least one signed cookie, and constructing an HMAC
// allocates the hasher plus two padded key blocks each time; resetting
// a pooled one costs nothing.
type pooledMAC struct {
	key []byte
	mac hash.Hash
}

var macPool sync.Pool

// SignHMACPurpose returns a domain-separated HMAC-SHA256 signature. The
// purpose string is bound into the signature so a value signed for one
// purpose (e.g. a session token) cannot be replayed as another (e.g. a
// cached session payload).
func SignHMACPurpose(key, purpose, value string) string {
	var sum [sha256.Size]byte
	appendHMAC(sum[:0], key, purpose, value)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// appendHMAC computes the MAC into dst, reusing a pooled hasher when the
// key matches the one it was built with.
func appendHMAC(dst []byte, key, purpose, value string) []byte {
	p, _ := macPool.Get().(*pooledMAC)
	if p == nil || !bytes.Equal(p.key, []byte(key)) {
		p = &pooledMAC{key: []byte(key), mac: hmac.New(sha256.New, []byte(key))}
	} else {
		p.mac.Reset()
	}
	if purpose != "" {
		p.mac.Write([]byte(purpose))
		p.mac.Write([]byte{0})
	}
	p.mac.Write([]byte(value))
	out := p.mac.Sum(dst)
	macPool.Put(p)
	return out
}

// VerifyHMACPurpose verifies a signature produced by SignHMACPurpose.
func VerifyHMACPurpose(key, purpose, value, sig string) bool {
	want := SignHMACPurpose(key, purpose, value)
	return subtle.ConstantTimeCompare([]byte(want), []byte(sig)) == 1
}

// HashToken returns a deterministic base64url encoded SHA-256 digest,
// used to store verifiable copies of secrets (API keys, one-time
// tokens) so that read access to the database does not yield usable
// credentials.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ConstantTimeEqual compares two strings in constant time.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
