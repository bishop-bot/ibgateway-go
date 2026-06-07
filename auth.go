// Package ibgateway provides authentication for the Interactive Brokers
// Client Portal Web API Gateway.
//
// The auth subpackage contains the core authentication functionality.
//
// Example usage:
//
//	import "github.com/bishop-bot/ibgateway-go"
//
//	authConfig := ibgateway.AuthConfig{
//	    Username:           "user",
//	    Password:           "pass",
//	    BaseURL:            "https://localhost:5000",
//	    SecondFactorMethod: ibgateway.TOTP,
//	    TOTPSecret:         "secret",
//	}
//	authenticator, _ := ibgateway.NewAuthenticator(authConfig)
//	defer authenticator.Close()
package ibgateway

import "github.com/bishop-bot/ibgateway-go/auth"

// Re-export all types and functions from the auth package
type AuthConfig = auth.AuthConfig
type Authenticator = auth.Authenticator
type SessionManager = auth.SessionManager
type AuthResponse = auth.AuthResponse
type IniParams = auth.IniParams
type TwoFactorData = auth.TwoFactorData

// Re-export error types
type TwoFactorError = auth.TwoFactorError
type AuthenticationError = auth.AuthenticationError
type MaxLoginAttemptsError = auth.MaxLoginAttemptsError

// Re-export constants
const (
	SMS         = auth.SMS
	IBKeyAndroid = auth.IBKeyAndroid
	IBKeyIOS     = auth.IBKeyIOS
	TOTP         = auth.TOTP
)

// Re-export functions
var NewAuthenticator = auth.NewAuthenticator
var NewSessionManager = auth.NewSessionManager
var NewTwoFactorError = auth.NewTwoFactorError
var NewAuthenticationError = auth.NewAuthenticationError
var NewMaxLoginAttemptsError = auth.NewMaxLoginAttemptsError