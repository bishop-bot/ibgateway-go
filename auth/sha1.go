package auth

import (
	"crypto/sha1"
	"encoding/hex"
)

// SHA1 provides SHA1 hashing utilities for the authentication protocol.
type SHA1 struct{}

// Hash computes the SHA1 hash of the input strings and returns the hex-encoded result.
func (s *SHA1) Hash(inputs ...string) string {
	h := sha1.New()
	for _, input := range inputs {
		h.Write([]byte(input))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// HashFromHex computes the SHA1 hash of a hex-encoded string.
// The input is first decoded from hex, then hashed.
func (s *SHA1) HashFromHex(hexInput string) string {
	// Decode hex input to bytes
	data, err := hex.DecodeString(hexInput)
	if err != nil {
		return ""
	}
	h := sha1.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// HashBytes computes the SHA1 hash of raw bytes and returns the hex-encoded result.
func (s *SHA1) HashBytes(data []byte) string {
	h := sha1.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
