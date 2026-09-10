package passkey

// WebAuthn wire-format parsing and signature verification. Everything
// here operates on data supplied by the client, so every parse is
// bounds-checked and every verification fails closed.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// COSE algorithm identifiers (RFC 9053) accepted for credentials.
const (
	coseAlgES256 = -7   // ECDSA w/ SHA-256 on P-256
	coseAlgEdDSA = -8   // Ed25519
	coseAlgRS256 = -257 // RSASSA-PKCS1-v1_5 w/ SHA-256
)

var errWebAuthn = errors.New("passkey: invalid webauthn data")

// clientData is the parsed clientDataJSON.
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

func parseClientData(raw []byte) (*clientData, error) {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return nil, fmt.Errorf("%w: clientDataJSON: %v", errWebAuthn, err)
	}
	return &cd, nil
}

// authenticator data flag bits.
const (
	flagUserPresent    = 1 << 0
	flagUserVerified   = 1 << 2
	flagBackupEligible = 1 << 3
	flagBackedUp       = 1 << 4
	flagAttestedData   = 1 << 6
)

// authData is the parsed authenticator data structure.
type authData struct {
	rpIDHash  []byte
	flags     byte
	signCount uint32

	// attested credential data, present only when flagAttestedData set
	aaguid       []byte
	credentialID []byte
	publicKey    []byte // raw CBOR COSE key bytes
}

func (a *authData) userPresent() bool    { return a.flags&flagUserPresent != 0 }
func (a *authData) userVerified() bool   { return a.flags&flagUserVerified != 0 }
func (a *authData) backupEligible() bool { return a.flags&flagBackupEligible != 0 }
func (a *authData) backedUp() bool       { return a.flags&flagBackedUp != 0 }

func parseAuthData(raw []byte) (*authData, error) {
	if len(raw) < 37 {
		return nil, fmt.Errorf("%w: authenticator data too short", errWebAuthn)
	}
	ad := &authData{
		rpIDHash:  raw[:32],
		flags:     raw[32],
		signCount: uint32(raw[33])<<24 | uint32(raw[34])<<16 | uint32(raw[35])<<8 | uint32(raw[36]),
	}
	rest := raw[37:]
	if ad.flags&flagAttestedData != 0 {
		if len(rest) < 18 {
			return nil, fmt.Errorf("%w: truncated attested credential data", errWebAuthn)
		}
		ad.aaguid = rest[:16]
		credLen := int(rest[16])<<8 | int(rest[17])
		rest = rest[18:]
		if credLen == 0 || credLen > 1023 || len(rest) < credLen {
			// The spec caps credential ids at 1023 bytes.
			return nil, fmt.Errorf("%w: bad credential id length %d", errWebAuthn, credLen)
		}
		ad.credentialID = rest[:credLen]
		rest = rest[credLen:]
		// The COSE key is a CBOR item possibly followed by extensions;
		// decode by prefix and validate it parses as a key later.
		_, n, err := cborDecodePrefix(rest)
		if err != nil {
			return nil, fmt.Errorf("%w: credential public key: %v", errWebAuthn, err)
		}
		ad.publicKey = rest[:n]
	}
	return ad, nil
}

// checkRPIDHash compares the authenticator's rpIdHash to SHA-256(rpID).
func (a *authData) checkRPIDHash(rpID string) bool {
	want := sha256.Sum256([]byte(rpID))
	return subtle.ConstantTimeCompare(a.rpIDHash, want[:]) == 1
}

// cosePublicKey is a parsed, validated credential public key.
type cosePublicKey struct {
	alg int64
	ec  *ecdsa.PublicKey
	rsa *rsa.PublicKey
	ed  ed25519.PublicKey
}

// parseCOSEKey validates and parses a COSE_Key. Only the algorithms in
// the registration options are accepted; a credential minted under an
// unknown algorithm is refused at registration rather than stored and
// found unverifiable at sign-in.
func parseCOSEKey(raw []byte) (*cosePublicKey, error) {
	item, err := cborDecode(raw)
	if err != nil {
		return nil, err
	}
	m, ok := item.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("%w: COSE key is not a map", errWebAuthn)
	}
	intVal := func(k int64) (int64, bool) {
		v, ok := m[k].(int64)
		return v, ok
	}
	bytesVal := func(k int64) ([]byte, bool) {
		v, ok := m[k].([]byte)
		return v, ok
	}
	kty, _ := intVal(1)
	alg, _ := intVal(3)

	switch {
	case kty == 2 && alg == coseAlgES256: // EC2
		crv, _ := intVal(-1)
		if crv != 1 { // P-256
			return nil, fmt.Errorf("%w: unsupported EC curve %d", errWebAuthn, crv)
		}
		x, okX := bytesVal(-2)
		y, okY := bytesVal(-3)
		if !okX || !okY || len(x) != 32 || len(y) != 32 {
			return nil, fmt.Errorf("%w: bad EC coordinates", errWebAuthn)
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, fmt.Errorf("%w: point not on curve", errWebAuthn)
		}
		return &cosePublicKey{alg: alg, ec: pub}, nil

	case kty == 3 && alg == coseAlgRS256: // RSA
		n, okN := bytesVal(-1)
		e, okE := bytesVal(-2)
		if !okN || !okE || len(n) < 256 || len(n) > 1024 || len(e) == 0 || len(e) > 8 {
			// 2048-bit minimum; WebAuthn RSA keys are 2048 in practice.
			return nil, fmt.Errorf("%w: bad RSA key size", errWebAuthn)
		}
		eInt := new(big.Int).SetBytes(e)
		if !eInt.IsInt64() || eInt.Int64() < 3 || eInt.Int64()%2 == 0 {
			return nil, fmt.Errorf("%w: bad RSA exponent", errWebAuthn)
		}
		return &cosePublicKey{alg: alg, rsa: &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(eInt.Int64())}}, nil

	case kty == 1 && alg == coseAlgEdDSA: // OKP
		crv, _ := intVal(-1)
		if crv != 6 { // Ed25519
			return nil, fmt.Errorf("%w: unsupported OKP curve %d", errWebAuthn, crv)
		}
		x, okX := bytesVal(-2)
		if !okX || len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: bad Ed25519 key", errWebAuthn)
		}
		return &cosePublicKey{alg: alg, ed: ed25519.PublicKey(x)}, nil
	}
	return nil, fmt.Errorf("%w: unsupported key type/algorithm (kty=%d alg=%d)", errWebAuthn, kty, alg)
}

// verifySignature checks sig over signed data per the key's algorithm.
// The signed message for WebAuthn assertions is
// authenticatorData || SHA-256(clientDataJSON).
func (k *cosePublicKey) verifySignature(data, sig []byte) bool {
	switch {
	case k.ec != nil:
		digest := sha256.Sum256(data)
		return ecdsa.VerifyASN1(k.ec, digest[:], sig)
	case k.rsa != nil:
		digest := sha256.Sum256(data)
		return rsa.VerifyPKCS1v15(k.rsa, crypto.SHA256, digest[:], sig) == nil
	case k.ed != nil:
		return ed25519.Verify(k.ed, data, sig)
	}
	return false
}

// attestationObject is the decoded registration attestation.
type attestationObject struct {
	format   string
	authData *authData
}

func parseAttestationObject(raw []byte) (*attestationObject, error) {
	item, err := cborDecode(raw)
	if err != nil {
		return nil, err
	}
	m, ok := item.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("%w: attestation object is not a map", errWebAuthn)
	}
	format, _ := m["fmt"].(string)
	adBytes, ok := m["authData"].([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: attestation object missing authData", errWebAuthn)
	}
	ad, err := parseAuthData(adBytes)
	if err != nil {
		return nil, err
	}
	return &attestationObject{format: format, authData: ad}, nil
}

// b64 decodes base64url without padding (the WebAuthn JSON encoding),
// tolerating standard padding for lenient clients.
func b64(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("%w: bad base64url", errWebAuthn)
}

func b64Equal(a, b string) bool {
	ab, errA := b64(a)
	bb, errB := b64(b)
	if errA != nil || errB != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}
