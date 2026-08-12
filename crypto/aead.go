package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Symmetric encryption of values held at rest (TOTP secrets, backup
// codes, JWT signing keys, OAuth tokens).
//
// # On-disk format
//
// Values written by this package carry a version tag and a key
// identifier, so any stored value can be attributed to the key that
// produced it without trial decryption:
//
//	v2.<kid>.<base64url(nonce || AES-256-GCM(plaintext))>
//
// "v2" is the format version. It selects the key derivation function,
// the framing and the additional authenticated data, so the three can
// change together.
//
// <kid> is a key identifier: 6 bytes of a one-way function of the key
// material, base64url encoded (8 characters). It names the key, it does
// not reveal it.
//
// # Location binding
//
// The additional authenticated data of a v2 value covers the version,
// the key id and a Binding — the model, record id and field name the
// value was written to:
//
//	"v2." || kid || len(model) || model || len(record) || record || len(field) || field
//
// The three binding components are length-prefixed so no two distinct
// bindings can produce the same byte string.
//
// That is what stops a ciphertext being relocated. Every value in a
// deployment is encrypted under the same key, so without binding, an
// attacker with database write access can copy any encrypted column
// into any other encrypted column and have it decrypt: a victim's OAuth
// refresh token pasted into the attacker's own twoFactor.secret row is
// read back verbatim by the "show me my TOTP URI" endpoint. With
// binding, a value only opens in the exact place it was written.
//
// # Legacy formats (v0 and v1)
//
// Two earlier formats exist in deployed databases and are still
// readable:
//
//   - v0: a bare base64url(nonce || ciphertext) with the key derived as
//     a single SHA-256 pass over "go-dev-auth-enc:"+secret and no
//     additional data. A value with no "." in it is a v0 value (the
//     base64url alphabet contains no ".").
//   - v1: "v1.<kid>.<body>", same key derivation as v2 but with the
//     literal "v1.<kid>" as the only additional data — i.e. unbound.
//
// Neither is written any more. Both are *unbound*, so accepting them on
// read is itself a downgrade: an attacker who can write to the database
// and holds an old v1 ciphertext (from a backup, say) can still relocate
// it. Auth.ReencryptSecrets rewrites them as v2; once it reports nothing
// left to do, set Config.RequireBoundCiphertexts (KeyringOptions.
// RejectUnbound at this layer) and unbound values stop being accepted
// at all.
//
// # Key derivation
//
// v1 and v2 derive from the secret with scrypt rather than a single
// SHA-256 pass. The secret is operator-supplied and Config only
// requires 16 characters of it, so it may well be a passphrase rather
// than 32 bytes of entropy; a memory-hard KDF is what makes a stolen
// database expensive to attack in that case. The cost is paid once per
// distinct secret per process (see keyFor), not per value.
//
// Riding the version tag is what makes all of this possible: existing
// deployments keep reading their old values while every new write uses
// the stronger format.
const (
	encVersionV1 = "v1"
	encVersionV2 = "v2"

	// legacyKDFPrefix is the v0 key derivation input prefix. Frozen:
	// changing it makes every existing stored value unreadable.
	legacyKDFPrefix = "go-dev-auth-enc:"

	v1KDFSalt    = "go-dev-auth-enc-v1"
	v1KeyLabel   = "go-dev-auth-enc-v1:key"
	v1KeyIDLabel = "go-dev-auth-enc-v1:kid"

	// keyIDLen is how many bytes of the key-id digest are published in
	// the ciphertext. 48 bits is far more than enough to tell a handful
	// of configured keys apart and far too little to be useful to an
	// attacker.
	keyIDLen = 6
)

// v1 scrypt cost. Deliberately below the password hasher's parameters
// (N=16384, r=16): this runs once per process, but it runs at startup
// on every instance, and unlike a password hash it is not the attacker's
// only obstacle — the secret is expected to be high entropy.
const (
	v1ScryptN = 1 << 14
	v1ScryptR = 8
	v1ScryptP = 1
)

var (
	// ErrNoMatchingKey means the value was encrypted under a key that
	// is not configured. This is the error a rotated-away secret
	// produces: the fix is to list the old secret in
	// Config.PreviousSecrets, or to re-encrypt the value.
	ErrNoMatchingKey = errors.New("crypto: no configured key can decrypt this value")

	// ErrMalformedCiphertext means the value is not a ciphertext this
	// package produced, or has been altered since it was written, or
	// was presented at a storage location other than the one it was
	// written to.
	ErrMalformedCiphertext = errors.New("crypto: malformed ciphertext")

	// ErrUnboundCiphertext means the value is in one of the pre-binding
	// formats (v0 or v1) and this keyring was built with
	// KeyringOptions.RejectUnbound. Run Auth.ReencryptSecrets to
	// migrate the value, or clear the option until the migration has
	// finished.
	ErrUnboundCiphertext = errors.New("crypto: value predates location binding and unbound values are rejected")

	// ErrInvalidBinding means a caller asked to encrypt or decrypt a
	// bound value without naming where it lives. It is a programming
	// error, not a data problem.
	ErrInvalidBinding = errors.New("crypto: a Binding must name a model, a record and a field")
)

// Binding names the place a stored value lives: which model (table),
// which record, and which field. It is authenticated as part of every
// value this package writes, so a ciphertext taken from one column and
// pasted into another fails to open.
//
// All three components are required. Record must be an identifier that
// is already fixed at encryption time and does not change afterwards —
// in practice the record's primary key. Where a value is encrypted
// before its row exists, generate the id first and pass it to both the
// encryption and the insert (see the two-factor and jwt plugins).
type Binding struct {
	// Model is the storage model the value is written to, e.g.
	// storage.ModelAccount or twofactor.ModelTwoFactor.
	Model string
	// Record is the id of the row holding the value.
	Record string
	// Field is the column name within that row.
	Field string
}

// String renders the binding for logs and error messages. None of its
// components are secret.
func (b Binding) String() string { return b.Model + "/" + b.Record + "/" + b.Field }

func (b Binding) validate() error {
	if b.Model == "" || b.Record == "" || b.Field == "" {
		return fmt.Errorf("%w (got model=%q record=%q field=%q)",
			ErrInvalidBinding, b.Model, b.Record, b.Field)
	}
	return nil
}

// aad builds the additional authenticated data for a v2 value. The
// binding components are length-prefixed so that distinct bindings
// cannot collide by moving a separator into a component.
func (b Binding) aad(kid string) []byte {
	out := make([]byte, 0, len(encVersionV2)+1+len(kid)+24+len(b.Model)+len(b.Record)+len(b.Field))
	out = append(out, encVersionV2...)
	out = append(out, '.')
	out = append(out, kid...)
	for _, s := range [3]string{b.Model, b.Record, b.Field} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		out = append(out, n[:]...)
		out = append(out, s...)
	}
	return out
}

// Key is the key material derived from one secret. It derives lazily
// and at most once, because the v1 derivation is deliberately
// expensive.
type Key struct {
	secret string

	legacyOnce sync.Once
	legacyAEAD cipher.AEAD
	legacyErr  error

	v1Once sync.Once
	v1ID   string
	v1AEAD cipher.AEAD
	v1Err  error
}

// keyCache memoises derivation per secret for the lifetime of the
// process. Deriving costs tens of milliseconds and tens of megabytes;
// EncryptString is called per stored value, so paying that per call is
// not an option.
//
// The cache holds the secrets it is keyed by. That is not a new
// exposure — Config holds the same strings for the process lifetime —
// but it is why the map is bounded: a caller that cycles through
// secrets must not be able to grow it without limit.
var (
	keyCacheMu sync.Mutex
	keyCache   = map[string]*Key{}
)

const keyCacheLimit = 64

// keyFor returns the (possibly cached) Key for a secret.
func keyFor(secret string) *Key {
	keyCacheMu.Lock()
	defer keyCacheMu.Unlock()
	if k, ok := keyCache[secret]; ok {
		return k
	}
	if len(keyCache) >= keyCacheLimit {
		// Dropping the cache costs a re-derivation, never correctness.
		keyCache = make(map[string]*Key, keyCacheLimit)
	}
	k := &Key{secret: secret}
	keyCache[secret] = k
	return k
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// legacy returns the v0 AEAD for this key.
func (k *Key) legacy() (cipher.AEAD, error) {
	k.legacyOnce.Do(func() {
		sum := sha256.Sum256([]byte(legacyKDFPrefix + k.secret))
		k.legacyAEAD, k.legacyErr = newGCM(sum[:])
	})
	return k.legacyAEAD, k.legacyErr
}

// v1 returns the key identifier and AEAD for the scrypt derivation,
// which v1 introduced and v2 reuses unchanged: v2 changed the framing
// and the additional data, not the key.
func (k *Key) v1() (string, cipher.AEAD, error) {
	k.v1Once.Do(func() {
		master, err := Scrypt([]byte(k.secret), []byte(v1KDFSalt), v1ScryptN, v1ScryptR, v1ScryptP, 32)
		if err != nil {
			k.v1Err = err
			return
		}
		// Two independent labels, so the published key id is not a
		// function of the encryption key itself.
		encSum := sha256.Sum256(append([]byte(v1KeyLabel), master...))
		idSum := sha256.Sum256(append([]byte(v1KeyIDLabel), master...))
		k.v1ID = base64.RawURLEncoding.EncodeToString(idSum[:keyIDLen])
		k.v1AEAD, k.v1Err = newGCM(encSum[:])
	})
	return k.v1ID, k.v1AEAD, k.v1Err
}

// Keyring is an ordered set of keys: the current one, which every new
// value is encrypted under, followed by previous keys that stored
// values may still be encrypted under.
//
// It is what makes Config.Secret rotatable. Deploy with the new secret
// as Secret and the old one in PreviousSecrets, re-encrypt (see
// Auth.ReencryptSecrets), then drop the old secret on the next deploy.
type Keyring struct {
	keys []*Key

	// acceptUnbound allows reads of the pre-binding v0 and v1 formats.
	// Set once at construction and never mutated, so a Keyring stays
	// safe to share across goroutines.
	acceptUnbound bool
}

// KeyringOptions configures a Keyring.
type KeyringOptions struct {
	// Current is the secret every new value is encrypted under.
	Current string
	// Previous are secrets stored values may still be encrypted under,
	// in order of preference. Empty and duplicate entries are ignored.
	Previous []string
	// RejectUnbound refuses to decrypt values written in the v0 or v1
	// formats, which are not bound to their storage location and can
	// therefore be relocated between columns by anyone with database
	// write access.
	//
	// Leave it clear until Auth.ReencryptSecrets reports a pass with
	// nothing left to rewrite; setting it before the migration has
	// finished makes the un-migrated values unreadable (not lost — they
	// become readable again the moment it is cleared).
	RejectUnbound bool
}

// NewKeyringFrom builds a keyring from explicit options.
func NewKeyringFrom(opts KeyringOptions) *Keyring {
	kr := &Keyring{keys: []*Key{keyFor(opts.Current)}, acceptUnbound: !opts.RejectUnbound}
	for _, p := range opts.Previous {
		if p == "" || p == opts.Current {
			continue
		}
		dup := false
		for _, k := range kr.keys {
			if k.secret == p {
				dup = true
				break
			}
		}
		if !dup {
			kr.keys = append(kr.keys, keyFor(p))
		}
	}
	return kr
}

// NewKeyring builds a keyring from the current secret and any previous
// secrets, in order of preference. Empty and duplicate secrets are
// ignored. The pre-binding formats are accepted on read; use
// NewKeyringFrom with RejectUnbound to close that off once a
// deployment has finished migrating.
func NewKeyring(current string, previous ...string) *Keyring {
	return NewKeyringFrom(KeyringOptions{Current: current, Previous: previous})
}

// AcceptsUnbound reports whether this keyring will read values written
// in the pre-binding v0 and v1 formats.
func (kr *Keyring) AcceptsUnbound() bool { return kr.acceptUnbound }

// CurrentKeyID returns the identifier of the key new values are
// encrypted under. It is safe to log: it names the key, it does not
// reveal it.
func (kr *Keyring) CurrentKeyID() (string, error) {
	id, _, err := kr.keys[0].v1()
	return id, err
}

// Encrypt seals plaintext under the current key, bound to the storage
// location b. The resulting value only opens again when presented with
// the same Binding, so it cannot be moved to another model, record or
// field.
//
// b must name all three; an incomplete Binding is a programming error
// and returns ErrInvalidBinding rather than silently writing an
// unbound value.
func (kr *Keyring) Encrypt(b Binding, plaintext string) (string, error) {
	if err := b.validate(); err != nil {
		return "", err
	}
	kid, gcm, err := kr.keys[0].v1()
	if err != nil {
		return "", err
	}
	header := encVersionV2 + "." + kid
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), b.aad(kid))
	return header + "." + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Decrypt opens a value produced by Encrypt, or by any earlier version
// of this package, under whichever configured key wrote it.
//
// b names where the value was read from. For a v2 value it must match
// the Binding it was written with, or the value does not open — that is
// the whole point. For the pre-binding v0 and v1 formats b is not
// authenticated and is only used in error messages; those formats are
// refused outright when the keyring was built with
// KeyringOptions.RejectUnbound.
//
// It never returns a plaintext alongside an error, and it never returns
// the input on failure: a caller that cannot decrypt a value must find
// that out, not receive the ciphertext and pass it on.
func (kr *Keyring) Decrypt(b Binding, encrypted string) (string, error) {
	if !strings.Contains(encrypted, ".") {
		return kr.decryptLegacy(b, encrypted)
	}
	parts := strings.Split(encrypted, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("%w: expected version.keyid.body", ErrMalformedCiphertext)
	}
	version, kid, body := parts[0], parts[1], parts[2]
	var aad []byte
	switch version {
	case encVersionV2:
		if err := b.validate(); err != nil {
			return "", err
		}
		aad = b.aad(kid)
	case encVersionV1:
		if !kr.acceptUnbound {
			return "", fmt.Errorf("%w (v1 value at %s)", ErrUnboundCiphertext, b)
		}
		aad = []byte(version + "." + kid)
	default:
		return "", fmt.Errorf("%w: unsupported format version %q", ErrMalformedCiphertext, version)
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return "", fmt.Errorf("%w: body is not base64url", ErrMalformedCiphertext)
	}
	for _, k := range kr.keys {
		id, gcm, err := k.v1()
		if err != nil {
			return "", err
		}
		if id != kid {
			continue
		}
		if len(raw) < gcm.NonceSize() {
			return "", fmt.Errorf("%w: too short", ErrMalformedCiphertext)
		}
		pt, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], aad)
		if err != nil {
			// The key id matched, so this is not a rotation problem:
			// the value has been altered, truncated, or lifted from a
			// different storage location than the one it is being read
			// from.
			return "", fmt.Errorf("%w: authentication failed under key %s at %s "+
				"(altered, truncated, or copied from another record or column)",
				ErrMalformedCiphertext, kid, b)
		}
		return string(pt), nil
	}
	return "", fmt.Errorf("%w (key id %s)", ErrNoMatchingKey, kid)
}

// decryptLegacy opens a pre-versioning (v0) value by trying each
// configured key in turn. There is no key id to select on, so trial
// decryption is the only option; GCM authentication makes a wrong key a
// certain miss.
func (kr *Keyring) decryptLegacy(b Binding, encrypted string) (string, error) {
	if !kr.acceptUnbound {
		return "", fmt.Errorf("%w (v0 value at %s)", ErrUnboundCiphertext, b)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("%w: not base64url", ErrMalformedCiphertext)
	}
	for _, k := range kr.keys {
		gcm, err := k.legacy()
		if err != nil {
			return "", err
		}
		if len(raw) < gcm.NonceSize() {
			return "", fmt.Errorf("%w: too short", ErrMalformedCiphertext)
		}
		pt, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
		if err == nil {
			return string(pt), nil
		}
	}
	return "", fmt.Errorf("%w (legacy format, no key id)", ErrNoMatchingKey)
}

// NeedsReencryption reports whether a stored value was written by
// anything other than the current key in the current format — i.e.
// whether re-encrypting it would let an operator drop a previous
// secret, or would move an unbound v0/v1 value to the bound v2 format.
func (kr *Keyring) NeedsReencryption(encrypted string) bool {
	parts := strings.Split(encrypted, ".")
	if len(parts) != 3 || parts[0] != encVersionV2 {
		return true
	}
	id, _, err := kr.keys[0].v1()
	if err != nil {
		return true
	}
	return parts[1] != id
}

// EncryptString encrypts plaintext with the current format under a
// single key, bound to the storage location b.
//
// Prefer Keyring: this helper cannot decrypt values written under a
// previous secret, which is what rotation needs.
func EncryptString(secret string, b Binding, plaintext string) (string, error) {
	return NewKeyring(secret).Encrypt(b, plaintext)
}

// DecryptString reverses EncryptString, also accepting the pre-binding
// v0 and v1 formats.
//
// Prefer Keyring: this helper only knows one key.
func DecryptString(secret string, b Binding, encrypted string) (string, error) {
	return NewKeyring(secret).Decrypt(b, encrypted)
}
