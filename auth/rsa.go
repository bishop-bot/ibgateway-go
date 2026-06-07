package auth

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// RSAKey represents an RSA key for encryption operations.
type RSAKey struct {
	n *big.Int
	e int64
	eInt *big.Int
}

// NewRSAKey creates a new empty RSA key.
func NewRSAKey() *RSAKey {
	return&RSAKey{}
}

// SetPublic sets the public key from hex-encoded modulus N and exponent E.
func (r *RSAKey) SetPublic(N, E string) error {
	var ok bool
	r.n, ok = new(big.Int).SetString(N, 16)
	if !ok {
		return errors.New("invalid RSA modulus (N)")
	}
	r.eInt, ok = new(big.Int).SetString(E, 10)
	if !ok {
		return errors.New("invalid RSA exponent (E)")
	}
	r.e = int64(r.eInt.Int64())
	return nil
}

// Encrypt encrypts the plaintext using PKCS#1 v1.5 padding and returns the hex-encoded result.
func (r *RSAKey) Encrypt(plaintext string) string {
	// Pad the plaintext using PKCS#1 v1.5
	k := (r.n.BitLen() + 7) / 8
	padded := r.pkcs1Pad2(plaintext, k)
	if padded == nil {
		return ""
	}

	// Perform raw RSA encryption: m^e mod n
	m := new(big.Int).SetBytes(padded)
	c := new(big.Int).Exp(m, big.NewInt(r.e), r.n)

	// Return hex-encoded result
	return r.evenHex(c.Text(16))
}

// pkcs1Pad2 pads the input string s to n bytes using PKCS#1 v1.5 type 2 padding.
func (r *RSAKey) pkcs1Pad2(s string, n int) []byte {
	if n < len(s)+11 {
		return nil
	}

	ba := make([]byte, n)
	i := len(s) - 1

	// Copy the input string in reverse
	for i >= 0 && n > 0 {
		ba[n-1] = s[i]
		i--
		n--
	}

	ba[n-1] = 0
	n--

	// Fill with random non-zero bytes
	for n > 2 {
		randomByte := r.getRandomByte()
		for randomByte == 0 {
			randomByte = r.getRandomByte()
		}
		ba[n-1] = randomByte
		n--
	}

	ba[n-1] = 2
	n--
	ba[n-1] = 0

	return ba
}

// getRandomByte returns a single random byte.
func (r *RSAKey) getRandomByte() byte {
	b := make([]byte, 1)
	rand.Read(b)
	return b[0]
}

// evenHex ensures the hex string has an even length.
func (r *RSAKey) evenHex(hexStr string) string {
	if len(hexStr)%2 == 0 {
		return hexStr
	}
	return "0" + hexStr
}
