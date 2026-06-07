package auth

import (
	"testing"
)

func TestNewAuthenticator(t *testing.T) {
	tests := []struct {
		name    string
		config  AuthConfig
		wantErr bool
	}{
		{
			name: "valid config with TOTP",
			config: AuthConfig{
				Username:           "testuser",
				Password:           "testpass",
				BaseURL:            "https://localhost:5000",
				SecondFactorMethod: TOTP,
				TOTPSecret:         "JBSWY3DPEHPK3PXP",
			},
			wantErr: false,
		},
		{
			name: "missing username",
			config: AuthConfig{
				Password:           "testpass",
				BaseURL:            "https://localhost:5000",
				SecondFactorMethod: TOTP,
				TOTPSecret:         "JBSWY3DPEHPK3PXP",
			},
			wantErr: true,
		},
		{
			name: "missing password",
			config: AuthConfig{
				Username:           "testuser",
				BaseURL:            "https://localhost:5000",
				SecondFactorMethod: TOTP,
				TOTPSecret:         "JBSWY3DPEHPK3PXP",
			},
			wantErr: true,
		},
		{
			name: "missing baseURL",
			config: AuthConfig{
				Username:           "testuser",
				Password:           "testpass",
				SecondFactorMethod: TOTP,
				TOTPSecret:         "JBSWY3DPEHPK3PXP",
			},
			wantErr: true,
		},
		{
			name: "IBKey without OCRA details",
			config: AuthConfig{
				Username:           "testuser",
				Password:           "testpass",
				BaseURL:            "https://localhost:5000",
				SecondFactorMethod: IBKeyAndroid,
			},
			wantErr: true,
		},
		{
			name: "TOTP without secret",
			config: AuthConfig{
				Username:           "testuser",
				Password:           "testpass",
				BaseURL:            "https://localhost:5000",
				SecondFactorMethod: TOTP,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAuthenticator(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAuthenticator() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSHA1Hash(t *testing.T) {
	sha := &SHA1{}

	tests := []struct {
		name     string
		inputs   []string
		expected string
	}{
		{
			name:     "simple string",
			inputs:   []string{"hello"},
			expected: "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
		},
		{
			name:     "multiple strings",
			inputs:   []string{"hello", "world"},
			expected: "6adfb183a4a2c94a2f92dab5ade762a47889a5a1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sha.Hash(tt.inputs...)
			if result != tt.expected {
				t.Errorf("SHA1.Hash() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestSHA1HashFromHex(t *testing.T) {
	sha := &SHA1{}

	// Hash of "hello" in hex
	hexInput := "68656c6c6f" // "hello" in hex
	expected := "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"

	result := sha.HashFromHex(hexInput)
	if result != expected {
		t.Errorf("SHA1.HashFromHex() = %v, expected %v", result, expected)
	}
}

func TestRSAKeySetPublic(t *testing.T) {
	rsa := NewRSAKey()

	// Test with valid public key values
	err := rsa.SetPublic(
		"d4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43",
		"3",
	)
	if err != nil {
		t.Errorf("RSAKey.SetPublic() error = %v", err)
	}
}

func TestRSAKeyEncrypt(t *testing.T) {
	rsa := NewRSAKey()

	// Set up a public key
	rsa.SetPublic(
		"d4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43",
		"3",
	)

	// Encrypt a short string
	plaintext := "test"
	ciphertext := rsa.Encrypt(plaintext)

	if ciphertext == "" {
		t.Error("RSAKey.Encrypt() returned empty string")
	}

	// Should return hex-encoded result
	if len(ciphertext) == 0 || len(ciphertext)%2 != 0 {
		t.Errorf("RSAKey.Encrypt() should return hex string, got %v", ciphertext)
	}
}

func TestGenerateRandomBigInt(t *testing.T) {
	tests := []struct {
		name  string
		bytes int
	}{
		{"32 bytes", 32},
		{"16 bytes", 16},
		{"8 bytes", 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateRandomBigInt(tt.bytes)

			// Check it's a valid positive number
			if result.Sign() <= 0 {
				t.Errorf("generateRandomBigInt() = %v, expected positive", result)
			}

			// Check it has the right number of bits (approximately)
			bitLen := result.BitLen()
			if bitLen > tt.bytes*8 {
				t.Errorf("generateRandomBigInt() bit length = %v, expected <= %v", bitLen, tt.bytes*8)
			}
		})
	}
}

func TestGenerateTOTP(t *testing.T) {
	// Test with a known secret
	secret := "JBSWY3DPEHPK3PXP"

	// Generate TOTP twice
	totp1 := generateTOTP(secret)
	totp2 := generateTOTP(secret)

	// They should be different (or same if called within same 30-second window)
	if len(totp1) != 6 {
		t.Errorf("generateTOTP() length = %v, expected 6", len(totp1))
	}

	// Same secret should produce same result within same time window
	if totp1 != totp2 {
		t.Log("TOTP values differ between calls (expected if >30s apart)")
	}
}

func TestBase32Decode(t *testing.T) {
	tests := []struct {
		name     string
		encoded  string
		wantErr  bool
	}{
		{"empty string", "", false},
		{"simple", "JBSWY3DPEHPK3PXP", false},
		{"with padding", "JBSWY3DP", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := base32Decode(tt.encoded)
			if (err != nil) != tt.wantErr {
				t.Errorf("base32Decode() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEvenHex(t *testing.T) {
	auth := &Authenticator{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"even length", "aabbcc", "aabbcc"},
		{"odd length", "aabbccd", "0aabbccd"},
		{"empty string", "", ""},
		{"single char", "a", "0a"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := auth.evenHex(tt.input)
			if result != tt.expected {
				t.Errorf("evenHex() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestNzero(t *testing.T) {
	auth := &Authenticator{}

	tests := []struct {
		name     string
		n        int
		expected string
	}{
		{"zero", 0, ""},
		{"one", 1, "0"},
		{"three", 3, "000"},
		{"ten", 10, "0000000000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := auth.nzero(tt.n)
			if result != tt.expected {
				t.Errorf("nzero() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestParseResponse(t *testing.T) {
	// Sample XML response
	xmlData := []byte(`<?xml version="1.0"?>
	<ib_auth_res>
		<ini_params>
			<g>2</g>
			<N>d4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43</N>
			<proto>6</proto>
			<hash>SHA1</hash>
			<s>aabbccdd</s>
			<B>1234567890abcdef</B>
			<lp>false</lp>
			<paper>false</paper>
			<rsapub>abcdef1234567890</rsapub>
		</ini_params>
	</ib_auth_res>`)

	resp, err := parseResponse(xmlData)
	if err != nil {
		t.Fatalf("parseResponse() error = %v", err)
	}

	if resp.IniParams == nil {
		t.Fatal("parseResponse() IniParams is nil")
	}

	if resp.IniParams.G != "2" {
		t.Errorf("parseResponse() G = %v, expected 2", resp.IniParams.G)
	}

	if resp.IniParams.Proto != "6" {
		t.Errorf("parseResponse() Proto = %v, expected 6", resp.IniParams.Proto)
	}

	if resp.IniParams.LP {
		t.Error("parseResponse() LP should be false")
	}

	if resp.IniParams.Paper {
		t.Error("parseResponse() Paper should be false")
	}
}

func TestTwoFactorError(t *testing.T) {
	err := NewTwoFactorError("test error")
	expected := "two-factor authentication error: test error"

	if err.Error() != expected {
		t.Errorf("TwoFactorError.Error() = %v, expected %v", err.Error(), expected)
	}
}

func TestAuthenticationError(t *testing.T) {
	err := NewAuthenticationError("test error")
	expected := "authentication error: test error"

	if err.Error() != expected {
		t.Errorf("AuthenticationError.Error() = %v, expected %v", err.Error(), expected)
	}
}

func TestMaxLoginAttemptsError(t *testing.T) {
	err := NewMaxLoginAttemptsError("test error")
	expected := "max login attempts error: test error"

	if err.Error() != expected {
		t.Errorf("MaxLoginAttemptsError.Error() = %v, expected %v", err.Error(), expected)
	}
}
