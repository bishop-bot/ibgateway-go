package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Second factor authentication methods.
const (
	// SMS indicates SMS-based two-factor authentication.
	SMS = "4.2"
	// IBKeyAndroid indicates IB Key authentication on Android.
	IBKeyAndroid = "5.2a"
	// IBKeyIOS indicates IB Key authentication on iOS.
	IBKeyIOS = "5.2i"
	// TOTP indicates time-based one-time password (authenticator app).
	TOTP = "4"
)

// Authenticator handles authentication with the IB Gateway API.
type Authenticator struct {
	username           string
	password           string
	baseURL           string
	session           *SessionManager
	secondFactorMethod string
	ocraSecret       string
	ocraPin          string
	ocraCounter      int
	totpSecret       string

	// Diffie-Hellman parameters
	N *big.Int
	g *big.Int
	a *big.Int
	A *big.Int

	// RSA server parameters
	proto            string
	hash             string
	salt             *big.Int
	B                *big.Int
	submitEnckx      bool
	serverRSAPub     string
	k *big.Int

	// Authentication values
	x *big.Int
	u                *big.Int
	Sc               *big.Int
	K                string
	M               string
	serverM2         string
	sessionKey       string

	// Helper instances
	sha1 *SHA1
	rsa              *RSAKey
	ocra             *OCRA

	// State
	isPaper          bool
	startDate        time.Time
}

// AuthConfig contains configuration for authentication.
type AuthConfig struct {
	// Username is the IB account username.
	Username string
	// Password is the IB account password.
	Password string
	// BaseURL is the IB Gateway base URL (e.g., "https://localhost:5000").
	BaseURL string
	// SecondFactorMethod specifies the two-factor authentication method.
	// Options: SMS, IBKeyAndroid, IBKeyIOS, TOTP
	SecondFactorMethod string
	// OCRASecret is the secret for IB Key authentication.
	OCRASecret string
	// OCRAPin is the PIN for IB Key authentication.
	OCRAPin string
	// OCRACounter is the counter for IB Key authentication.
	OCRACounter int
	// TOTPSecret is the secret for TOTP authentication.
	TOTPSecret string
}

// NewAuthenticator creates a new Authenticator instance.
func NewAuthenticator(config AuthConfig) (*Authenticator, error) {
	// Validate required fields
	if config.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	if config.Password == "" {
		return nil, fmt.Errorf("password is required")
	}
	if config.BaseURL == "" {
		return nil, fmt.Errorf("baseURL is required")
	}

	// Set defaults
	secondFactorMethod := config.SecondFactorMethod
	if secondFactorMethod == "" {
		secondFactorMethod = SMS
	}

	// Validate second factor method requirements
	if secondFactorMethod == IBKeyAndroid || secondFactorMethod == IBKeyIOS {
		if config.OCRASecret == "" || config.OCRAPin == "" || config.OCRACounter == 0 {
			return nil, fmt.Errorf("OCRA secret, pin, and counter are required for IB Key auth")
		}
	}
	if secondFactorMethod == TOTP {
		if config.TOTPSecret == "" {
			return nil, fmt.Errorf("TOTP secret is required for TOTP auth")
		}
	}

	// Create session
	session, err := NewSessionManager(config.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Initialize Diffie-Hellman parameters
	// N is a well-known prime from the SRP specification
	N, _ := new(big.Int).SetString("d4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43", 16)
	g := big.NewInt(2)

	// Generate random 'a' value
	a := generateRandomBigInt(32)
	// Ensure a is in range [2, N-2]
	maxA := new(big.Int).Sub(N, big.NewInt(2))
	if a.Cmp(maxA) >= 0 {
		a = a.Mod(a, maxA)
	}
	if a.Cmp(big.NewInt(2)) < 0 {
		a = big.NewInt(2)
	}

	// Calculate A = g^a mod N
	A := new(big.Int).Exp(g, a, N)

	return &Authenticator{
		username:           strings.ToLower(config.Username),
		password:           config.Password,
		baseURL:           config.BaseURL,
		session:           session,
		secondFactorMethod: secondFactorMethod,
		ocraSecret:       config.OCRASecret,
		ocraPin:          config.OCRAPin,
		ocraCounter:      config.OCRACounter,
		totpSecret:       config.TOTPSecret,
		N:                N,
		g:                g,
		a:                a,
		A:                A,
		proto:            "6",
		hash:             "SHA1",
		sha1:             &SHA1{},
		rsa:              NewRSAKey(),
		ocra:             &OCRA{},
	}, nil
}

// Authenticate performs the full authentication flow.
func (a *Authenticator) Authenticate() error {
	if err := a.initialize(); err != nil {
		return err
	}
	return a.completeAuthentication()
}

// initialize performs the initialization phase of authentication.
func (a *Authenticator) initialize() error {
	a.startDate = time.Now()

	// GET to the base URL to set initial cookies
	resp, err := a.session.Get("/")
	if err != nil {
		return fmt.Errorf("failed to connect to gateway: %w", err)
	}
	resp.Body.Close()

	// Set the SBID cookie
	a.session.SetSBIDCookie()

	// Send INIT request and parse response
	if err := a.doInitializeStep(); err != nil {
		return err
	}

	// Calculate k with the received parameters
	a.k = a.calculateK()

	return nil
}

// doInitializeStep performs a single initialization step.
func (a *Authenticator) doInitializeStep() error {
	// Build form data for INIT action
	data := map[string]string{
		"ACTION":     "INIT",
		"APP_NAME":   "",
		"MODE":       "NORMAL",
		"FORCE_LOGIN": "",
		"USER":       a.username,
		"ACCT":       "",
		"A":          a.A.Text(16),
	}

	resp, err := a.session.PostForm("/sso/Authenticator", data)
	if err != nil {
		return fmt.Errorf("INIT request failed: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Parse the response
	authResp, err := parseResponse(body)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Check if we need to re-initialize with new parameters
	if authResp.IniParams != nil {
		if authResp.IniParams.N != "" && authResp.IniParams.N != a.N.Text(16) {
			N, _ := new(big.Int).SetString(authResp.IniParams.N, 16)
			a.N = N
			return fmt.Errorf("N changed, need to reinitialize")
		}
		if authResp.IniParams.G != "" && authResp.IniParams.G != a.g.Text(10) {
			g, _ := new(big.Int).SetString(authResp.IniParams.G, 10)
			a.g = g
			return fmt.Errorf("g changed, need to reinitialize")
		}
	}

	// Update server parameters
	if authResp.IniParams != nil {
		if authResp.IniParams.Proto != "" {
			a.proto = authResp.IniParams.Proto
		}
		if authResp.IniParams.Hash != "" {
			a.hash = authResp.IniParams.Hash
		}
		if authResp.IniParams.S != "" {
			a.salt, _ = new(big.Int).SetString(authResp.IniParams.S, 16)
		}
		if authResp.IniParams.B != "" {
			a.B, _ = new(big.Int).SetString(authResp.IniParams.B, 16)
		}
		if authResp.IniParams.RSAPub != "" {
			a.serverRSAPub = authResp.IniParams.RSAPub
			a.submitEnckx = true
			a.rsa.SetPublic(authResp.IniParams.RSAPub, "3")
		}
		if authResp.IniParams.Paper {
			a.isPaper = authResp.IniParams.Paper
		}
	}

	// Recalculate k with new parameters
	a.k = a.calculateK()

	return nil
}

// completeAuthentication completes the authentication flow.
func (a *Authenticator) completeAuthentication() error {
	// Calculate authentication values
	a.x = a.calculateX()
	a.u = a.calculateU()
	a.Sc = a.calculateClientSecret()
	a.K = a.calculateKFromSecret()
	a.M = a.calculateM()

	// Build form data for COMPLETEAUTH action
	data := map[string]string{
		"ACTION":   "COMPLETEAUTH",
		"APP_NAME": "",
		"USER":     a.username,
		"ACCT":     "",
		"M1":       a.M,
		"VERSION":  "1",
	}

	if a.submitEnckx {
		ekx := a.rsa.Encrypt(a.K)
		data["EKX"] = ekx
	}

	resp, err := a.session.PostForm("/sso/Authenticator", data)
	if err != nil {
		return fmt.Errorf("COMPLETEAUTH request failed: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	return a.parseCompleteAuthResponse(body)
}

// parseCompleteAuthResponse parses the COMPLETEAUTH response.
func (a *Authenticator) parseCompleteAuthResponse(body []byte) error {
	authResp, err := parseResponse(body)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for server M2
	if authResp.IniParams != nil && authResp.IniParams.M2 != "" {
		a.serverM2 = authResp.IniParams.M2
	}

	// Calculate our M2
	M2 := a.calculateM2()

	// Verify M2 matches
	if a.serverM2 != "" && a.serverM2 != M2 {
		if authResp.ReachedMaxLogin {
			return NewMaxLoginAttemptsError("reached maximum login attempts")
		}
		return NewAuthenticationError("invalid username or password")
	}

	// Calculate session key
	a.sessionKey = a.calculateSessionKey()
	a.session.SetSessionKey(a.sessionKey)

	// Check for two-factor authentication
	if authResp.SFTypes != nil && len(authResp.SFTypes) > 0 {
		// Verify the selected method is available
		methodAvailable := false
		for _, sf := range authResp.SFTypes {
			if sf == a.secondFactorMethod {
				methodAvailable = true
				break
			}
		}
		if !methodAvailable {
			return fmt.Errorf("selected two-factor method %s is not available, available: %v",
				a.secondFactorMethod, authResp.SFTypes)
		}

		return a.completeTwoFactor(authResp)
	}

	return nil
}

// completeTwoFactor completes the two-factor authentication.
func (a *Authenticator) completeTwoFactor(authResp *AuthResponse) error {
	// Send COMPLETEAUTH_1 to trigger two-factor
	data := map[string]string{
		"ACTION":   "COMPLETEAUTH_1",
		"APP_NAME": "",
		"USER":     a.username,
		"ACCT":     "",
		"M1":       a.M,
		"VERSION":  "1",
		"SF":       a.secondFactorMethod,
	}

	resp, err := a.session.PostForm("/sso/Authenticator", data)
	if err != nil {
		return fmt.Errorf("COMPLETEAUTH_1 request failed: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	authResp, err = parseResponse(body)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if authResp.TwoFactor == nil {
		return fmt.Errorf("two-factor response missing")
	}

	return a.authenticateTwoFactor(authResp.TwoFactor)
}

// authenticateTwoFactor processes the two-factor challenge.
func (a *Authenticator) authenticateTwoFactor(twoFactorData *TwoFactorData) error {
	var challengeResponse string

	switch twoFactorData.Type {
	case "SWCR":
		// IB Key challenge-response
		if a.secondFactorMethod == IBKeyAndroid || a.secondFactorMethod == IBKeyIOS {
			challenge := strings.ReplaceAll(twoFactorData.Challenge, " ", "")
			challengeResponse = a.ocra.GenerateOCRA(
				"OCRA-1:HOTP-SHA1-8:C-QN06-PSHA1",
				a.ocraSecret,
				strconv.Itoa(a.ocraCounter),
				challenge,
				a.sha1.Hash(a.ocraPin),
			)
		}
	case "SWTK":
		// Software token (SMS or TOTP)
		if a.secondFactorMethod == SMS {
			// For SMS, we would need to poll for the code
			// This is typically handled externally
			return fmt.Errorf("SMS two-factor requires external code retrieval")
		}
		if a.secondFactorMethod == TOTP {
			challengeResponse = generateTOTP(a.totpSecret)
		}
	case "IBTK":
		return fmt.Errorf("physical security key not supported")
	}

	if challengeResponse == "" {
		return fmt.Errorf("could not generate challenge response for type %s", twoFactorData.Type)
	}

	// Send COMPLETETWOFACT
	data := map[string]string{
		"ACTION":   "COMPLETETWOFACT",
		"APP_NAME": "",
		"USER":     a.username,
		"ACCT":     "",
		"RESPONSE": challengeResponse,
		"VERSION":  "1",
		"SF":       a.secondFactorMethod,
	}

	resp, err := a.session.PostForm("/sso/Authenticator", data)
	if err != nil {
		return fmt.Errorf("COMPLETETWOFACT request failed: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	authResp, err := parseResponse(body)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if authResp.AuthRes != "true" {
		return NewTwoFactorError(authResp.Error)
	}

	return nil
}

// Finalize completes the authentication by sending the final dispatcher request.
func (a *Authenticator) Finalize() error {
	data := map[string]string{
		"user_name":  a.username,
		"password":   "xxxxxxxxxxxxxxxxxxxxxxxx",
		"chlginput":  "",
		"loginType":  "0",
		"forwardTo":  "22",
		"M1":         a.M,
		"M2":         a.calculateM2(),
	}

	resp, err := a.session.PostForm("/sso/Dispatcher", data)
	if err != nil {
		return fmt.Errorf("Dispatcher request failed: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if string(body) != "Client login succeeds" {
		return fmt.Errorf("dispatcher response unexpected: %s", string(body))
	}

	return nil
}

// calculateK calculates the k value based on protocol.
func (a *Authenticator) calculateK() *big.Int {
	one := big.NewInt(1)
	three := big.NewInt(3)

	if a.proto == "3" {
		return one
	}
	if a.proto == "6" {
		return three
	}

	// k = H(N || g)
	hashIn := a.evenHex(a.N.Text(16)) + a.nzero(len(a.N.Text(16))-len(a.g.Text(16))) + a.g.Text(16)
	kHex := a.sha1.HashFromHex(hashIn)
	k, _ := new(big.Int).SetString(kHex, 16)

	if k.Cmp(a.N) < 0 {
		return k
	}
	return k.Mod(k, a.N)
}

// calculateX calculates the x value.
func (a *Authenticator) calculateX() *big.Int {
	// x = H(salt || H(username ':' password))
	innerHash := a.sha1.Hash(a.username + ":" + a.password)
	hashIn := a.evenHex(a.salt.Text(16)) + innerHash
	outerHash := a.sha1.HashFromHex(hashIn)
	x, _ := new(big.Int).SetString(outerHash, 16)

	if x.Cmp(a.N) < 0 {
		return x
	}
	return x.Mod(x, new(big.Int).Sub(a.N, big.NewInt(1)))
}

// calculateU calculates the u value.
func (a *Authenticator) calculateU() *big.Int {
	hashIn := ""

	if a.proto != "3" {
		aHex := a.A.Text(16)
		if a.proto == "6" {
			hashIn += a.evenHex(aHex)
		} else {
			// 6a requires left-padding
			nLen := 2 * ((a.N.BitLen() + 7) >> 3)
			hashIn += a.nzero(nLen - len(aHex)) + aHex
		}
	}

	bHex := a.B.Text(16)
	if a.proto == "3" || a.proto == "6" {
		hashIn += a.evenHex(bHex)
	} else {
		// 6a requires left-padding
		nLen := 2 * ((a.N.BitLen() + 7) >> 3)
		hashIn += a.nzero(nLen - len(bHex)) + bHex
	}

	var u *big.Int
	if a.proto == "3" {
		hashResult := a.sha1.HashFromHex(hashIn)
		u, _ = new(big.Int).SetString(hashResult[:8], 16)
	} else {
		u, _ = new(big.Int).SetString(a.sha1.HashFromHex(hashIn), 16)
	}

	if u.Cmp(a.N) < 0 {
		return u
	}
	return u.Mod(u, new(big.Int).Sub(a.N, big.NewInt(1)))
}

// calculateClientSecret calculates the client secret (Sc).
func (a *Authenticator) calculateClientSecret() *big.Int {
	// Sc = (B - k*g^x)^(a + u*x) mod N
	bx := new(big.Int).Exp(a.g, a.x, a.N)
	bTmp := new(big.Int).Sub(a.B, new(big.Int).Mul(a.k, bx))
	bTmp = bTmp.Mod(bTmp, a.N)
	bTmp = bTmp.Add(bTmp, a.N)
	bTmp = bTmp.Mod(bTmp, a.N)

	exponent := new(big.Int).Mul(a.u, a.x)
	exponent = exponent.Add(exponent, a.a)

	return new(big.Int).Exp(bTmp, exponent, a.N)
}

// calculateKFromSecret calculates K from the client secret.
func (a *Authenticator) calculateKFromSecret() string {
	return a.sha1.HashFromHex(a.evenHex(a.Sc.Text(16)))
}

// calculateM calculates the M value for authentication.
func (a *Authenticator) calculateM() string {
	hN := a.sha1.HashFromHex(a.evenHex(a.N.Text(16)))
	hG := a.sha1.HashFromHex(a.evenHex(a.g.Text(16)))

	hNInt, _ := new(big.Int).SetString(hN, 16)
	hGInt, _ := new(big.Int).SetString(hG, 16)

	hXor := new(big.Int).Xor(hNInt, hGInt)
	hI := a.sha1.Hash(a.username)

	hashIn := a.evenHex(hXor.Text(16)) + hI + a.evenHex(a.salt.Text(16)) +
		a.evenHex(a.A.Text(16)) + a.evenHex(a.B.Text(16)) + a.K

	return a.sha1.HashFromHex(hashIn)
}

// calculateM2 calculates the M2 value for mutual authentication.
func (a *Authenticator) calculateM2() string {
	hashIn := a.evenHex(a.A.Text(16)) + a.M + a.K
	return a.sha1.HashFromHex(hashIn)
}

// calculateSessionKey calculates the session key.
func (a *Authenticator) calculateSessionKey() string {
	hashIn := a.evenHex(a.B.Text(16)) + a.K
	return a.sha1.HashFromHex(hashIn)
}

// evenHex ensures a hex string has even length.
func (a *Authenticator) evenHex(hexStr string) string {
	if len(hexStr)%2 == 0 {
		return hexStr
	}
	return "0" + hexStr
}

// nzero returns a string of n zeros.
func (a *Authenticator) nzero(n int) string {
	if n < 1 {
		return ""
	}
	result := make([]byte, n)
	for i := range result {
		result[i] = '0'
	}
	return string(result)
}

// GetSession returns the session for making API requests.
func (a *Authenticator) GetSession() *SessionManager {
	return a.session
}

// GetSessionToken returns the session token for API authentication.
func (a *Authenticator) GetSessionToken() string {
	return a.session.GetSessionToken()
}

// IsPaper returns true if authenticating to a paper trading account.
func (a *Authenticator) IsPaper() bool {
	return a.isPaper
}

// Close closes the authenticator and releases resources.
func (a *Authenticator) Close() error {
	// Session manager doesn't have explicit close
	return nil
}

// generateRandomBigInt generates a random big.Int of the given byte length.
func generateRandomBigInt(byteLen int) *big.Int {
	bytes := make([]byte, byteLen)
	rand.Read(bytes)
	// Ensure the most significant bit is not set (to keep the number smaller than N)
	bytes[0] &= 0x7f
	return new(big.Int).SetBytes(bytes)
}

// generateTOTP generates a TOTP code from the secret.
func generateTOTP(secret string) string {
	// Simplified TOTP implementation
	// In production, use a proper TOTP library like github.com/pquerna/otp
	return generateTOTPWithTime(secret, time.Now())
}

// generateTOTPWithTime generates a TOTP code for a specific time.
func generateTOTPWithTime(secret string, t time.Time) string {
	// Decode the secret from base32
	key, err := base32Decode(secret)
	if err != nil {
		return ""
	}

	// Calculate time step (30 second intervals)
	timeStep := t.Unix() / 30

	// Convert time step to 8 bytes (big-endian)
	msg := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		msg[i] = byte(timeStep)
		timeStep >>= 8
	}

	// Calculate HMAC-SHA1
	h := hmac.New(sha1.New, key)
	h.Write(msg)
	hash := h.Sum(nil)

	// Dynamic truncation
	offset := hash[len(hash)-1]& 0x0f
	truncated := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	// Calculate OTP with 6 digits
	digitsPower := []uint32{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000}
	otp := truncated % digitsPower[6]

	return fmt.Sprintf("%06d", otp)
}

// base32Decode decodes a base32 string.
func base32Decode(encoded string) ([]byte, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	encoded = strings.ToUpper(encoded)
	encoded = strings.TrimRight(encoded, "=")

	result := make([]byte, len(encoded)*5/8)
	var buffer, bits uint32

	for i, c := range encoded {
		index := strings.IndexRune(alphabet, c)
		if index < 0 {
			return nil, fmt.Errorf("invalid base32 character: %c", c)
		}
		buffer = (buffer << 5) | uint32(index)
		bits += 5
		if bits >= 8 {
			bits -= 8
			result[i*5/8] = byte(buffer >> bits)
			if i*5/8+1 < len(result) {
				result[i*5/8+1] = byte(buffer << (8 - bits))
			}
		}
	}

	return result, nil
}

// parseResponse parses the XML response from IB Gateway.
func parseResponse(data []byte) (*AuthResponse, error) {
	response := &AuthResponse{}
	response.IniParams = &IniParams{}

	// Extract g value
	if match := extractXMLValue(data, "g"); match != "" {
		response.IniParams.G = match
	}

	// Extract N value
	if match := extractXMLValue(data, "N"); match != "" {
		response.IniParams.N = match
	}

	// Extract proto value
	if match := extractXMLValue(data, "proto"); match != "" {
		response.IniParams.Proto = match
	}

	// Extract hash value
	if match := extractXMLValue(data, "hash"); match != "" {
		response.IniParams.Hash = match
	}

	// Extract s (salt) value
	if match := extractXMLValue(data, "s"); match != "" {
		response.IniParams.S = match
	}

	// Extract B value
	if match := extractXMLValue(data, "B"); match != "" {
		response.IniParams.B = match
	}

	// Extract lp (long password support)
	if match := extractXMLValue(data, "lp"); match != "" {
		response.IniParams.LP = match == "true"
	}

	// Extract paper value
	if match := extractXMLValue(data, "paper"); match != "" {
		response.IniParams.Paper = match == "true"
	}

	// Extract rsapub value
	if match := extractXMLValue(data, "rsapub"); match != "" {
		response.IniParams.RSAPub = match
	}

	// Extract M2 value
	if match := extractXMLValue(data, "M2"); len(match) > 0 {
		response.IniParams.M2 = match
	}

	// Extract sftypes value
	if match := extractXMLValue(data, "sftypes"); len(match) > 0 {
		response.SFTypes = strings.Split(match, ",")
	}

	// Extract auth_res value
	if match := extractXMLValue(data, "auth_res"); len(match) > 0 {
		response.AuthRes = match
	}

	// Extract error value
	if match := extractXMLValue(data, "error"); len(match) > 0 {
		response.Error = match
	}

	// Extract reached_max_login value
	if match := extractXMLValue(data, "reached_max_login"); len(match) > 0 {
		response.ReachedMaxLogin = match == "true"
	}

	// Extract two_factor data
	if twoFactorData := extractXMLSection(data, "two_factor"); len(twoFactorData) > 0 {
		response.TwoFactor = &TwoFactorData{}
		if match := extractXMLValue(twoFactorData, "type"); len(match) > 0 {
			response.TwoFactor.Type = match
		}
		if match := extractXMLValue(twoFactorData, "challenge"); len(match) > 0 {
			response.TwoFactor.Challenge = match
		}
	}

	return response, nil
}

// extractXMLValue extracts a value from XML by tag name.
func extractXMLValue(data []byte, tag string) string {
	pattern := fmt.Sprintf(`<%s>([^<]*)</%s>`, tag, tag)
	re := regexp.MustCompile(pattern)
	matches := re.FindSubmatch(data)
	if len(matches) > 1 {
		return string(matches[1])
	}
	return ""
}

// extractXMLSection extracts an XML section by tag name.
func extractXMLSection(data []byte, tag string) []byte {
	startPattern := fmt.Sprintf(`<%s>`, tag)
	endPattern := fmt.Sprintf(`</%s>`, tag)

	startIdx := -1
	for i := 0; i <= len(data)-len(startPattern); i++ {
		if string(data[i:i+len(startPattern)]) == startPattern {
			startIdx = i
			break
		}
	}
	if startIdx == -1 {
		return nil
	}

	endIdx := -1
	for i := startIdx; i <= len(data)-len(endPattern); i++ {
		if string(data[i:i+len(endPattern)]) == endPattern {
			endIdx = i + len(endPattern)
			break
		}
	}
	if endIdx == -1 {
		return nil
	}

	return data[startIdx:endIdx]
}

// AuthResponse represents the parsed authentication response.
type AuthResponse struct {
	IniParams        *IniParams
	SFTypes         []string
	AuthRes         string
	Error           string
	ReachedMaxLogin bool
	TwoFactor       *TwoFactorData
}

// IniParams contains the initialization parameters from the response.
type IniParams struct {
	G string
	N      string
	Proto  string
	Hash   string
	S      string
	B      string
	LP     bool
	Paper  bool
	RSAPub string
	M2     string
}

// TwoFactorData contains two-factor authentication data.
type TwoFactorData struct {
	Type      string
	Challenge string
}
