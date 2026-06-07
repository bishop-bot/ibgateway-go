package auth

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// SessionManager provides a managed HTTP session with cookie support.
type SessionManager struct {
	client     *http.Client
	baseURL    string
	jar *cookiejar.Jar
	authCookie string
}

// NewSessionManager creates a new session manager.
func NewSessionManager(baseURL string) (*SessionManager, error) {
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: nil, // Use default public suffix list
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // IB Gateway uses self-signed certs
		},
	}

	client := &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   60 * time.Second,
	}

	return &SessionManager{
		client:  client,
		baseURL: baseURL,
		jar:     jar,
	}, nil
}

// Get performs an HTTP GET request.
func (sm *SessionManager) Get(path string) (*http.Response, error) {
	return sm.doRequest("GET", path, nil, nil)
}

// PostForm performs an HTTP POST request with form data.
func (sm *SessionManager) PostForm(path string, data map[string]string) (*http.Response, error) {
	formData := make(url.Values)
	for k, v := range data {
		formData.Set(k, v)
	}
	return sm.doRequest("POST", path, strings.NewReader(formData.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
}

// PostJSON performs an HTTP POST request with JSON data.
func (sm *SessionManager) PostJSON(path string, data interface{}) (*http.Response, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return sm.doRequest("POST", path, strings.NewReader(string(jsonData)), map[string]string{
		"Content-Type": "application/json",
	})
}

// doRequest performs an HTTP request.
func (sm *SessionManager) doRequest(method, path string, body io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, sm.baseURL+path, body)
	if err != nil {
		return nil, err
	}

	// Set default headers
	req.Header.Set("User-Agent", "ibgateway-go/1.0")
	req.Header.Set("Accept", "*/*")

	// Set custom headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return sm.client.Do(req)
}

// SetCookie sets a cookie.
func (sm *SessionManager) SetCookie(name, value string, expiry time.Time) {
	cookie := &http.Cookie{
		Name:    name,
		Value:   value,
		Path:    "/",
		Expires: expiry,
	}

	baseURL, _ := url.Parse(sm.baseURL)
	sm.jar.SetCookies(baseURL, []*http.Cookie{cookie})
}

// GetCookie gets a cookie by name.
func (sm *SessionManager) GetCookie(name string) string {
	baseURL, _ := url.Parse(sm.baseURL)
	cookies := sm.jar.Cookies(baseURL)
	for _, c := range cookies {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// SetSBIDCookie sets the SBID cookie with a 10-year expiry.
func (sm *SessionManager) SetSBIDCookie() {
	expiry := time.Now().Add(10 * 365 * 24 * time.Hour)
	ssoID := generateSSOID()
	sm.SetCookie("SBID", ssoID, expiry)
}

// GetSessionToken extracts the session token from cookies.
func (sm *SessionManager) GetSessionToken() string {
	return sm.GetCookie("api")
}

// SetSessionToken sets the session token cookie.
func (sm *SessionManager) SetSessionToken(token string) {
	expiry := time.Now().Add(24 * time.Hour)
	sm.SetCookie("api", token, expiry)
}

// GetSessionKey gets the session key cookie.
func (sm *SessionManager) GetSessionKey() string {
	return sm.GetCookie("XYZAB_AM.LOGIN")
}

// SetSessionKey sets the session key cookie.
func (sm *SessionManager) SetSessionKey(key string) {
	expiry := time.Now().Add(24 * time.Hour)
	sm.SetCookie("XYZAB_AM.LOGIN", key, expiry)
}

// GetClient returns the underlying HTTP client.
func (sm *SessionManager) GetClient() *http.Client {
	return sm.client
}

// GetBaseURL returns the base URL.
func (sm *SessionManager) GetBaseURL() string {
	return sm.baseURL
}

// generateSSOID generates a random SSO ID.
func generateSSOID() string {
	timestamp := time.Now().UnixMilli()
	return fmt.Sprintf("%s%x", randomString(16), timestamp)
}

// randomString generates a random string of given length.
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}
