package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Default scrypt parameters. These match better-auth so password hashes
// are interoperable between the two libraries.
//
// Note the cost: N=16384, r=16 means each hash allocates and touches
// 128*N*r bytes = 32 MiB and burns tens of milliseconds of CPU. That is
// intentional (it is what makes offline cracking expensive) but it also
// means an unauthenticated sign-in endpoint is an expensive endpoint.
// ScryptHasher therefore bounds how many hashes run concurrently and
// reuses scratch buffers; keep rate limiting enabled in front of it.
const (
	DefaultScryptN      = 16384
	DefaultScryptR      = 16
	DefaultScryptP      = 1
	DefaultScryptKeyLen = 64
	saltSize            = 16
)

// PasswordHasher hashes and verifies passwords. Implement it to plug in
// a different algorithm (bcrypt, argon2id, a KMS, ...).
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(hash, password string) (bool, error)
}

// ScryptParams are the tunable scrypt cost parameters.
type ScryptParams struct {
	N, R, P, KeyLen int
	// MaxConcurrent bounds how many hashes may run at once. Each
	// in-flight hash holds 128*N*R bytes, so this is the knob that
	// caps peak memory under a burst of sign-ins. Defaults to
	// GOMAXPROCS (hashing is CPU bound; more concurrency buys nothing
	// but memory).
	MaxConcurrent int
	// MaxWait bounds how long a request may queue for a hashing slot
	// before being rejected outright. Defaults to 3 seconds.
	//
	// Without it, a flood of sign-in attempts does not exhaust memory
	// (MaxConcurrent sees to that) but does serialise: every request
	// waits behind the queue and latency climbs into seconds, which
	// upstream clients experience as a hang and retry — the classic way
	// a slow dependency turns into an outage. Failing fast sheds the
	// load instead.
	MaxWait time.Duration
}

// ErrHasherBusy is returned when a hash could not start within MaxWait.
// Handlers translate it into 503 with a Retry-After header rather than
// letting the caller block.
var ErrHasherBusy = errors.New("crypto: password hashing is saturated")

// DefaultScryptParams returns the better-auth compatible parameters.
func DefaultScryptParams() ScryptParams {
	return ScryptParams{
		N: DefaultScryptN, R: DefaultScryptR, P: DefaultScryptP,
		KeyLen: DefaultScryptKeyLen,
	}
}

// ScryptHasher is the default PasswordHasher. The zero value is usable
// and applies DefaultScryptParams.
type ScryptHasher struct {
	Params ScryptParams

	once sync.Once
	sem  chan struct{}
	pool sync.Pool
}

// NewScryptHasher returns a hasher with custom cost parameters. Changing
// N, R or P makes existing hashes unverifiable, so only do this on a
// fresh deployment (or migrate hashes on next successful sign-in).
func NewScryptHasher(params ScryptParams) *ScryptHasher {
	return &ScryptHasher{Params: params}
}

func (h *ScryptHasher) init() {
	h.once.Do(func() {
		if h.Params.N == 0 {
			h.Params.N = DefaultScryptN
		}
		if h.Params.R == 0 {
			h.Params.R = DefaultScryptR
		}
		if h.Params.P == 0 {
			h.Params.P = DefaultScryptP
		}
		if h.Params.KeyLen == 0 {
			h.Params.KeyLen = DefaultScryptKeyLen
		}
		if h.Params.MaxConcurrent <= 0 {
			h.Params.MaxConcurrent = runtime.GOMAXPROCS(0)
		}
		if h.Params.MaxWait == 0 {
			h.Params.MaxWait = 3 * time.Second
		}
		h.sem = make(chan struct{}, h.Params.MaxConcurrent)
		h.pool.New = func() any { return new(scryptScratch) }
	})
}

// derive runs scrypt with bounded concurrency and pooled scratch space.
func (h *ScryptHasher) derive(password, salt []byte) ([]byte, error) {
	h.init()
	if err := h.acquire(); err != nil {
		return nil, err
	}
	defer func() { <-h.sem }()

	scratch := h.pool.Get().(*scryptScratch)
	defer h.pool.Put(scratch)

	return scryptWith(scratch, password, salt,
		h.Params.N, h.Params.R, h.Params.P, h.Params.KeyLen)
}

// acquire takes a hashing slot, waiting at most MaxWait.
func (h *ScryptHasher) acquire() error {
	select {
	case h.sem <- struct{}{}:
		return nil
	default:
	}
	if h.Params.MaxWait < 0 {
		return ErrHasherBusy
	}
	timer := time.NewTimer(h.Params.MaxWait)
	defer timer.Stop()
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-timer.C:
		return ErrHasherBusy
	}
}

// Hash hashes password with scrypt, producing "saltHex:keyHex".
//
// The password bytes are hashed as received. better-auth applies
// Unicode NFKC normalization first, so a password containing non-ASCII
// characters that are not already in NFKC form (some accented letters,
// full-width forms, certain emoji sequences) produces a different hash
// here than in better-auth. ASCII passwords — the overwhelming majority
// — are unaffected and remain byte-for-byte compatible. NFKC is not
// applied because the standard library has no NFKC implementation and
// adding golang.org/x/text would break the zero-dependency guarantee;
// applications that need exact cross-runtime parity for non-ASCII
// passwords can normalize before calling, in a custom PasswordHasher.
func (h *ScryptHasher) Hash(password string) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	saltHex := hex.EncodeToString(salt)
	key, err := h.derive([]byte(password), []byte(saltHex))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%s", saltHex, hex.EncodeToString(key)), nil
}

// Verify reports whether password matches the stored hash.
func (h *ScryptHasher) Verify(stored, password string) (bool, error) {
	saltHex, keyHex, ok := strings.Cut(stored, ":")
	if !ok {
		return false, errors.New("crypto: malformed password hash")
	}
	want, err := hex.DecodeString(keyHex)
	if err != nil {
		return false, errors.New("crypto: malformed password hash")
	}
	got, err := h.derive([]byte(password), []byte(saltHex))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// DummyVerify performs a hash of equivalent cost and discards the
// result. Sign-in handlers call it when no account exists so that the
// response time does not reveal whether an address is registered.
func (h *ScryptHasher) DummyVerify(password string) {
	_, _ = h.derive([]byte(password), []byte("00000000000000000000000000000000"))
}
