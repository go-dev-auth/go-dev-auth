package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

func hmacSHA256(key []byte, msg string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}

// randReader adapts crypto/rand for signature APIs.
type randReader struct{}

func (randReader) Read(p []byte) (int, error) { return io.ReadFull(rand.Reader, p) }
