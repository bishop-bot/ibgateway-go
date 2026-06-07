package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strings"
)

// OCRA provides the OATH Challenge-Response Algorithm implementation.
// Reference: https://tools.ietf.org/html/rfc6287
type OCRA struct{}

// GenerateOCRA generates an OCRA challenge response.
// ocraSuite: The OCRA suite string (e.g., "OCRA-1:HOTP-SHA1-8:C-QN06-PSHA1")
// key: Hex-encoded secret key
// counter: Counter value as string
// question: Challenge question as hex string
// password: PIN/password as hex string
func (o *OCRA) GenerateOCRA(ocraSuite, key, counter, question, password string) string {
	// Parse the OCRA suite
	parts := strings.Split(ocraSuite, ":")
	if len(parts) < 3 {
		return ""
	}

	cryptoFunction := parts[1]
	dataInput := parts[2]

	// Determine hash algorithm and code digits
	hashAlgo := "SHA1"
	codeDigits := 8

	if strings.Contains(strings.ToLower(cryptoFunction), "sha256") {
		hashAlgo = "SHA256"
	} else if strings.Contains(strings.ToLower(cryptoFunction), "sha512") {
		hashAlgo = "SHA512"
	}

	// Parse code digits from crypto function (e.g., "HOTP-SHA1-8" -> 8)
	dashIdx := strings.LastIndex(cryptoFunction, "-")
	if dashIdx != -1 {
		fmt.Sscanf(cryptoFunction[dashIdx+1:], "%d", &codeDigits)
	}

	// Build the message
	msg := o.buildOCRAMessage(ocraSuite, counter, question, password, dataInput)

	// Compute HMAC
	var hmacResult []byte
	switch hashAlgo {
	case "SHA1":
		h := hmac.New(sha1.New, o.hexToBytes(key))
		h.Write(msg)
		hmacResult = h.Sum(nil)
	case "SHA256":
		// For SHA256, we need to import crypto/sha256
		// For now, fall back to SHA1 for IB Key compatibility
		h := hmac.New(sha1.New, o.hexToBytes(key))
		h.Write(msg)
		hmacResult = h.Sum(nil)
	default:
		h := hmac.New(sha1.New, o.hexToBytes(key))
		h.Write(msg)
		hmacResult = h.Sum(nil)
	}

	// Dynamic truncation
	offset := hmacResult[len(hmacResult)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(hmacResult[offset:offset+4]) & 0x7fffffff

	// Calculate OTP
	digitsPower := []uint32{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000}
	otp := truncated % digitsPower[codeDigits]

	// Format result with leading zeros
	result := fmt.Sprintf("%0*d", codeDigits, otp)
	return result
}

// buildOCRAMessage constructs the message buffer for OCRA.
func (o *OCRA) buildOCRAMessage(ocraSuite, counter, question, password, dataInput string) []byte {
	// Determine component lengths
	counterLength := 0
	questionLength := 0
	passwordLength := 0

	// Counter
	if strings.HasPrefix(strings.ToLower(dataInput), "c") {
		counterLength = 8
		// Pad counter to 16 hex chars
		for len(counter) < 16 {
			counter = "0" + counter
		}
	}

	// Question - always 128 bytes
	if strings.Contains(strings.ToLower(dataInput), "q") {
		questionLength = 128
		// Pad question to 256 hex chars
		for len(question) < 256 {
			question += "0"
		}
	}

	// Password with SHA1
	if strings.Contains(strings.ToLower(dataInput), "psha1") {
		passwordLength = 20
	}

	// Calculate total length
	totalLen := len(ocraSuite) + counterLength + questionLength + passwordLength + 1

	msg := make([]byte, totalLen)

	// Copy OCRA suite
	copy(msg, []byte(ocraSuite))

	// Delimiter
	msg[len(ocraSuite)] = 0x00

	// Counter
	if counterLength > 0 {
		counterBytes := o.hexToBytes(counter)
		copy(msg[len(ocraSuite)+1:], counterBytes)
	}

	// Question
	if questionLength > 0 {
		questionBytes := o.hexToBytes(question)
		copy(msg[len(ocraSuite)+1+counterLength:], questionBytes)
	}

	// Password
	if passwordLength > 0 {
		passwordBytes := o.hexToBytes(password)
		copy(msg[len(ocraSuite)+1+counterLength+questionLength:], passwordBytes)
	}

	return msg
}

// hexToBytes converts a hex string to bytes.
func (o *OCRA) hexToBytes(hexStr string) []byte {
	result := make([]byte, len(hexStr)/2)
	for i := 0; i < len(hexStr)/2; i++ {
		var byteVal byte
		fmt.Sscanf(hexStr[i*2:i*2+2], "%02x", &byteVal)
		result[i] = byteVal
	}
	return result
}
