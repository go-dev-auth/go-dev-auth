// Package crypto implements the cryptographic primitives used by
// go-dev-auth: scrypt password hashing (RFC 7914), PBKDF2, TOTP/HOTP,
// random tokens, HMAC signing and AES-GCM symmetric encryption.
//
// Everything is built on the Go standard library; the package has no
// external dependencies.
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"math/bits"
)

// scryptScratch holds the large working buffers scrypt needs. Reusing
// them across calls avoids allocating (and zeroing) tens of megabytes
// per password hash, which otherwise dominates GC time on sign-in
// heavy workloads.
type scryptScratch struct {
	v  []uint32
	xy []uint32
}

func (s *scryptScratch) buffers(N, r int) ([]uint32, []uint32) {
	if cap(s.v) < 32*N*r {
		s.v = make([]uint32, 32*N*r)
	}
	if cap(s.xy) < 64*r {
		s.xy = make([]uint32, 64*r)
	}
	return s.v[:32*N*r], s.xy[:64*r]
}

// Scrypt derives a key from password and salt using the scrypt key
// derivation function as specified in RFC 7914.
func Scrypt(password, salt []byte, N, r, p, keyLen int) ([]byte, error) {
	return scryptWith(new(scryptScratch), password, salt, N, r, p, keyLen)
}

func scryptWith(scratch *scryptScratch, password, salt []byte, N, r, p, keyLen int) ([]byte, error) {
	if N <= 1 || N&(N-1) != 0 {
		return nil, errors.New("crypto/scrypt: N must be > 1 and a power of 2")
	}
	if r <= 0 || p <= 0 {
		return nil, errors.New("crypto/scrypt: r and p must be positive")
	}
	if uint64(r)*uint64(p) >= 1<<30 || r > (1<<31-1)/128/p || r > (1<<31-1)/128/N || N > (1<<31-1)/128/r {
		return nil, errors.New("crypto/scrypt: parameters are too large")
	}

	v, xy := scratch.buffers(N, r)
	b := PBKDF2(sha256.New, password, salt, 1, p*128*r)

	for i := 0; i < p; i++ {
		smix(b[i*128*r:], r, N, v, xy)
	}

	return PBKDF2(sha256.New, password, b, 1, keyLen), nil
}

func blockCopy(dst, src []uint32, n int) {
	copy(dst, src[:n])
}

func blockXOR(dst, src []uint32, n int) {
	for i, v := range src[:n] {
		dst[i] ^= v
	}
}

// salsaXOR applies Salsa20/8 to the XOR of in and tmp, storing the result
// into both out and tmp.
func salsaXOR(tmp *[16]uint32, in, out []uint32) {
	w0 := tmp[0] ^ in[0]
	w1 := tmp[1] ^ in[1]
	w2 := tmp[2] ^ in[2]
	w3 := tmp[3] ^ in[3]
	w4 := tmp[4] ^ in[4]
	w5 := tmp[5] ^ in[5]
	w6 := tmp[6] ^ in[6]
	w7 := tmp[7] ^ in[7]
	w8 := tmp[8] ^ in[8]
	w9 := tmp[9] ^ in[9]
	w10 := tmp[10] ^ in[10]
	w11 := tmp[11] ^ in[11]
	w12 := tmp[12] ^ in[12]
	w13 := tmp[13] ^ in[13]
	w14 := tmp[14] ^ in[14]
	w15 := tmp[15] ^ in[15]

	x0, x1, x2, x3 := w0, w1, w2, w3
	x4, x5, x6, x7 := w4, w5, w6, w7
	x8, x9, x10, x11 := w8, w9, w10, w11
	x12, x13, x14, x15 := w12, w13, w14, w15

	for i := 0; i < 8; i += 2 {
		x4 ^= bits.RotateLeft32(x0+x12, 7)
		x8 ^= bits.RotateLeft32(x4+x0, 9)
		x12 ^= bits.RotateLeft32(x8+x4, 13)
		x0 ^= bits.RotateLeft32(x12+x8, 18)

		x9 ^= bits.RotateLeft32(x5+x1, 7)
		x13 ^= bits.RotateLeft32(x9+x5, 9)
		x1 ^= bits.RotateLeft32(x13+x9, 13)
		x5 ^= bits.RotateLeft32(x1+x13, 18)

		x14 ^= bits.RotateLeft32(x10+x6, 7)
		x2 ^= bits.RotateLeft32(x14+x10, 9)
		x6 ^= bits.RotateLeft32(x2+x14, 13)
		x10 ^= bits.RotateLeft32(x6+x2, 18)

		x3 ^= bits.RotateLeft32(x15+x11, 7)
		x7 ^= bits.RotateLeft32(x3+x15, 9)
		x11 ^= bits.RotateLeft32(x7+x3, 13)
		x15 ^= bits.RotateLeft32(x11+x7, 18)

		x1 ^= bits.RotateLeft32(x0+x3, 7)
		x2 ^= bits.RotateLeft32(x1+x0, 9)
		x3 ^= bits.RotateLeft32(x2+x1, 13)
		x0 ^= bits.RotateLeft32(x3+x2, 18)

		x6 ^= bits.RotateLeft32(x5+x4, 7)
		x7 ^= bits.RotateLeft32(x6+x5, 9)
		x4 ^= bits.RotateLeft32(x7+x6, 13)
		x5 ^= bits.RotateLeft32(x4+x7, 18)

		x11 ^= bits.RotateLeft32(x10+x9, 7)
		x8 ^= bits.RotateLeft32(x11+x10, 9)
		x9 ^= bits.RotateLeft32(x8+x11, 13)
		x10 ^= bits.RotateLeft32(x9+x8, 18)

		x12 ^= bits.RotateLeft32(x15+x14, 7)
		x13 ^= bits.RotateLeft32(x12+x15, 9)
		x14 ^= bits.RotateLeft32(x13+x12, 13)
		x15 ^= bits.RotateLeft32(x14+x13, 18)
	}
	x0 += w0
	x1 += w1
	x2 += w2
	x3 += w3
	x4 += w4
	x5 += w5
	x6 += w6
	x7 += w7
	x8 += w8
	x9 += w9
	x10 += w10
	x11 += w11
	x12 += w12
	x13 += w13
	x14 += w14
	x15 += w15

	out[0], tmp[0] = x0, x0
	out[1], tmp[1] = x1, x1
	out[2], tmp[2] = x2, x2
	out[3], tmp[3] = x3, x3
	out[4], tmp[4] = x4, x4
	out[5], tmp[5] = x5, x5
	out[6], tmp[6] = x6, x6
	out[7], tmp[7] = x7, x7
	out[8], tmp[8] = x8, x8
	out[9], tmp[9] = x9, x9
	out[10], tmp[10] = x10, x10
	out[11], tmp[11] = x11, x11
	out[12], tmp[12] = x12, x12
	out[13], tmp[13] = x13, x13
	out[14], tmp[14] = x14, x14
	out[15], tmp[15] = x15, x15
}

func blockMix(tmp *[16]uint32, in, out []uint32, r int) {
	blockCopy(tmp[:], in[(2*r-1)*16:], 16)
	for i := 0; i < 2*r; i += 2 {
		salsaXOR(tmp, in[i*16:], out[i*8:])
		salsaXOR(tmp, in[i*16+16:], out[i*8+r*16:])
	}
}

func integer(b []uint32, r int) uint64 {
	j := (2*r - 1) * 16
	return uint64(b[j]) | uint64(b[j+1])<<32
}

func smix(b []byte, r, N int, v, xy []uint32) {
	var tmp [16]uint32
	x := xy
	y := xy[32*r:]

	j := 0
	for i := 0; i < 32*r; i++ {
		x[i] = binary.LittleEndian.Uint32(b[j:])
		j += 4
	}
	for i := 0; i < N; i += 2 {
		blockCopy(v[i*(32*r):], x, 32*r)
		blockMix(&tmp, x, y, r)

		blockCopy(v[(i+1)*(32*r):], y, 32*r)
		blockMix(&tmp, y, x, r)
	}
	for i := 0; i < N; i += 2 {
		j := int(integer(x, r) & uint64(N-1))
		blockXOR(x, v[j*(32*r):], 32*r)
		blockMix(&tmp, x, y, r)

		j = int(integer(y, r) & uint64(N-1))
		blockXOR(y, v[j*(32*r):], 32*r)
		blockMix(&tmp, y, x, r)
	}
	j = 0
	for _, w := range x[:32*r] {
		binary.LittleEndian.PutUint32(b[j:], w)
		j += 4
	}
}

// PBKDF2 implements the password based key derivation function 2 as
// specified in RFC 2898 / PKCS #5 v2.0.
func PBKDF2(h func() hash.Hash, password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}
