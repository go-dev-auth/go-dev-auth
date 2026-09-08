package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// JWTHeader is the JOSE header of a JWT.
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
}

// Claims is a generic JWT claims set.
type Claims map[string]any

var (
	// ErrInvalidToken indicates a malformed or badly signed token.
	ErrInvalidToken = errors.New("crypto: invalid token")
	// ErrTokenExpired indicates the exp claim is in the past.
	ErrTokenExpired = errors.New("crypto: token expired")
)

func b64(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }
func b64json(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return b64(raw), nil
}

// SignJWT signs claims producing a compact JWT. Supported keys:
//
//   - ed25519.PrivateKey -> EdDSA
//   - *rsa.PrivateKey    -> RS256
//   - *ecdsa.PrivateKey  -> ES256
//   - []byte / string    -> HS256
func SignJWT(key any, kid string, claims Claims) (string, error) {
	var alg string
	switch key.(type) {
	case ed25519.PrivateKey:
		alg = "EdDSA"
	case *rsa.PrivateKey:
		alg = "RS256"
	case *ecdsa.PrivateKey:
		alg = "ES256"
	case []byte, string:
		alg = "HS256"
	default:
		return "", fmt.Errorf("crypto: unsupported signing key %T", key)
	}
	header, err := b64json(JWTHeader{Alg: alg, Typ: "JWT", Kid: kid})
	if err != nil {
		return "", err
	}
	payload, err := b64json(claims)
	if err != nil {
		return "", err
	}
	signingInput := header + "." + payload
	var sig []byte
	switch k := key.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(signingInput))
	case *rsa.PrivateKey:
		digest := sha256.Sum256([]byte(signingInput))
		sig, err = rsa.SignPKCS1v15(nil, k, crypto.SHA256, digest[:])
		if err != nil {
			return "", err
		}
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256([]byte(signingInput))
		r, s, err2 := ecdsa.Sign(randReader{}, k, digest[:])
		if err2 != nil {
			return "", err2
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		sig = make([]byte, 2*size)
		r.FillBytes(sig[:size])
		s.FillBytes(sig[size:])
	case []byte:
		sig = hmacSHA256(k, signingInput)
	case string:
		sig = hmacSHA256([]byte(k), signingInput)
	}
	return signingInput + "." + b64(sig), nil
}

// VerifyJWT verifies token with key and returns its claims. Supported
// keys: ed25519.PublicKey, *rsa.PublicKey, *ecdsa.PublicKey, []byte/string
// (HMAC). Expiry (exp) and not-before (nbf) are enforced.
func VerifyJWT(key any, token string) (Claims, error) {
	return VerifyJWTWithLeeway(key, token, 0)
}

// VerifyJWTWithLeeway is VerifyJWT tolerating clock skew of leeway on
// the exp and nbf checks. OIDC verification passes the configured
// IDTokenConfig.Leeway here; without it the config field was dead for
// exp, because this check rejected with zero tolerance before the
// caller's leeway-aware check ever ran.
func VerifyJWTWithLeeway(key any, token string, leeway time.Duration) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var header JWTHeader
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, ErrInvalidToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}
	signingInput := parts[0] + "." + parts[1]
	switch k := key.(type) {
	case ed25519.PublicKey:
		if header.Alg != "EdDSA" || !ed25519.Verify(k, []byte(signingInput), sig) {
			return nil, ErrInvalidToken
		}
	case *rsa.PublicKey:
		if header.Alg != "RS256" {
			return nil, ErrInvalidToken
		}
		digest := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig); err != nil {
			return nil, ErrInvalidToken
		}
	case *ecdsa.PublicKey:
		if header.Alg != "ES256" {
			return nil, ErrInvalidToken
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return nil, ErrInvalidToken
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		digest := sha256.Sum256([]byte(signingInput))
		if !ecdsa.Verify(k, digest[:], r, s) {
			return nil, ErrInvalidToken
		}
	case []byte:
		if header.Alg != "HS256" || !ConstantTimeEqual(string(hmacSHA256(k, signingInput)), string(sig)) {
			return nil, ErrInvalidToken
		}
	case string:
		if header.Alg != "HS256" || !ConstantTimeEqual(string(hmacSHA256([]byte(k), signingInput)), string(sig)) {
			return nil, ErrInvalidToken
		}
	default:
		return nil, fmt.Errorf("crypto: unsupported verification key %T", key)
	}
	claims, err := DecodeJWTClaims(token)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if v, present := claims["exp"]; present {
		exp, ok := numericClaimTime(v)
		if !ok {
			// A malformed exp (a string, an object) must not read as
			// "no expiry": that turns a provider quirk or an attacker's
			// type confusion into an eternal token.
			return nil, ErrInvalidToken
		}
		if !now.Before(exp.Add(leeway)) {
			return nil, ErrTokenExpired
		}
	}
	if v, present := claims["nbf"]; present {
		nbf, ok := numericClaimTime(v)
		if !ok {
			return nil, ErrInvalidToken
		}
		if now.Add(leeway).Before(nbf) {
			return nil, ErrInvalidToken
		}
	}
	return claims, nil
}

// numericClaimTime interprets a JWT NumericDate claim value. A present
// but non-numeric value returns ok=false and must be treated as
// malformed, never as absent.
func numericClaimTime(v any) (time.Time, bool) {
	switch t := v.(type) {
	case float64:
		return time.Unix(int64(t), 0), true
	case int64:
		return time.Unix(t, 0), true
	case json.Number:
		n, err := t.Int64()
		return time.Unix(n, 0), err == nil
	}
	return time.Time{}, false
}

// DecodeJWTHeader decodes the header of a JWT without verifying it, so a
// caller can select the verifying key by its kid before verification.
func DecodeJWTHeader(token string) (JWTHeader, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return JWTHeader{}, ErrInvalidToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return JWTHeader{}, ErrInvalidToken
	}
	var header JWTHeader
	if err := json.Unmarshal(raw, &header); err != nil {
		return JWTHeader{}, ErrInvalidToken
	}
	return header, nil
}

// DecodeJWTClaims decodes the payload of a JWT without verifying it.
func DecodeJWTClaims(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, ErrInvalidToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

func claimInt(c Claims, name string) (int64, bool) {
	v, ok := c[name]
	if !ok {
		return 0, false
	}
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case int64:
		return t, true
	case json.Number:
		n, err := t.Int64()
		return n, err == nil
	}
	return 0, false
}

// JWK is a JSON Web Key public representation.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// JWKS is a JSON Web Key set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicJWK builds a JWK from a public key.
func PublicJWK(kid string, pub any) (JWK, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return JWK{Kty: "OKP", Crv: "Ed25519", Kid: kid, Use: "sig", Alg: "EdDSA", X: b64(k)}, nil
	case *rsa.PublicKey:
		e := big.NewInt(int64(k.E))
		return JWK{Kty: "RSA", Kid: kid, Use: "sig", Alg: "RS256", N: b64(k.N.Bytes()), E: b64(e.Bytes())}, nil
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		x := make([]byte, size)
		y := make([]byte, size)
		k.X.FillBytes(x)
		k.Y.FillBytes(y)
		return JWK{Kty: "EC", Crv: "P-256", Kid: kid, Use: "sig", Alg: "ES256", X: b64(x), Y: b64(y)}, nil
	}
	return JWK{}, fmt.Errorf("crypto: unsupported public key %T", pub)
}

// PublicKey converts a JWK back into a crypto public key. Keys marked
// for a use other than signing are refused, and the curve is checked
// against what the parser assumes: interpreting P-384 coordinates on
// P-256 would otherwise produce a garbage key that still "verifies"
// whatever happens to match it.
func (j JWK) PublicKey() (any, error) {
	if j.Use != "" && j.Use != "sig" {
		return nil, ErrInvalidToken
	}
	switch j.Kty {
	case "OKP":
		if j.Crv != "" && j.Crv != "Ed25519" {
			return nil, ErrInvalidToken
		}
		x, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, ErrInvalidToken
		}
		return ed25519.PublicKey(x), nil
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(j.N)
		if err != nil {
			return nil, ErrInvalidToken
		}
		e, err := base64.RawURLEncoding.DecodeString(j.E)
		if err != nil {
			return nil, ErrInvalidToken
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case "EC":
		if j.Crv != "P-256" {
			return nil, ErrInvalidToken
		}
		x, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil {
			return nil, ErrInvalidToken
		}
		y, err := base64.RawURLEncoding.DecodeString(j.Y)
		if err != nil {
			return nil, ErrInvalidToken
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, ErrInvalidToken
		}
		return pub, nil
	}
	return nil, fmt.Errorf("crypto: unsupported jwk kty %q", j.Kty)
}
