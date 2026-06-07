# IB Gateway Go Library

A Go library for authenticating with the Interactive Brokers (IB) Client Portal Web API Gateway.

## Overview

This library provides a pure Go implementation of the authentication flow used by the IB Gateway API. It handles:

- SRP (Secure Remote Password) authentication
- Two-factor authentication (SMS, IB Key, TOTP)
- Cookie management for session persistence
- RSA encryption for secure communication

## Installation

```bash
go get github.com/bishop-bot/ibgateway-go/auth
```

## Usage

### Basic Authentication with TOTP

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/bishop-bot/ibgateway-go/auth"
)

func main() {
    // Create authenticator with TOTP second factor
    authConfig := auth.AuthConfig{
        Username:           "your_username",
        Password:           "your_password",
        BaseURL:            "https://localhost:5000",
        SecondFactorMethod: auth.TOTP,
        TOTPSecret:         "YOUR_TOTP_SECRET", // e.g., from Google Authenticator
    }
    
    authenticator, err := auth.NewAuthenticator(authConfig)
    if err != nil {
        log.Fatal(err)
    }
    defer authenticator.Close()
    
    // Authenticate
    if err := authenticator.Authenticate(); err != nil {
        log.Fatal(err)
    }
    
    // Finalize the authentication
    if err := authenticator.Finalize(); err != nil {
        log.Fatal(err)
    }
    
    fmt.Println("Authentication successful!")
    fmt.Printf("Is Paper Trading: %v\n", authenticator.IsPaper())
}
```

### Using IB Key Authentication

```go
authConfig := auth.AuthConfig{
    Username:           "your_username",
    Password:           "your_password",
    BaseURL:            "https://localhost:5000",
    SecondFactorMethod: auth.IBKeyAndroid, // or auth.IBKeyIOS
    OCRASecret:         "YOUR_OCRA_SECRET",
    OCRAPin:            "YOUR_PIN",
    OCRACounter:        2,
}
```

### Using SMS Authentication

```go
authConfig := auth.AuthConfig{
    Username:           "your_username",
    Password:           "your_password",
    BaseURL:            "https://localhost:5000",
    SecondFactorMethod: auth.SMS,
}
```

### Making Authenticated Requests

After authentication, you can use the session to make API requests:

```go
session := authenticator.GetSession()

// Make a request to get account info
resp, err := session.Get("/v1/api/portfolio/accounts")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

// Read and parse the response
body, _ := io.ReadAll(resp.Body)
fmt.Println(string(body))
```

## Second Factor Methods

The library supports the following two-factor authentication methods:

| Constant | Description |
|----------|-------------|
| `auth.SMS` | SMS-based verification code |
| `auth.TOTP` | Time-based one-time password (Google Authenticator, etc.) |
| `auth.IBKeyAndroid` | IB Key on Android device |
| `auth.IBKeyIOS` | IB Key on iOS device |

## API Reference

### NewAuthenticator

Creates a new Authenticator instance.

```go
func NewAuthenticator(config AuthConfig) (*Authenticator, error)
```

### AuthConfig

Configuration for authentication:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `Username` | string | Yes | IB account username |
| `Password` | string | Yes | IB account password |
| `BaseURL` | string | Yes | Gateway URL (e.g., `https://localhost:5000`) |
| `SecondFactorMethod` | string | No | Default: `SMS` |
| `OCRASecret` | string | For IB Key | OCRA secret for IB Key auth |
| `OCRAPin` | string | For IB Key | PIN for IB Key auth |
| `OCRACounter` | int | For IB Key | Counter for IB Key auth |
| `TOTPSecret` | string | For TOTP | TOTP secret (base32 encoded) |

### Authenticator Methods

| Method | Description |
|--------|-------------|
| `Authenticate()` | Perform the full authentication flow |
| `Finalize()` | Complete authentication with dispatcher request |
| `GetSession()` | Get the HTTP session for API requests |
| `GetSessionToken()` | Get the session token |
| `IsPaper()` | Check if authenticating to paper trading |
| `Close()` | Close the authenticator and release resources |

## Error Handling

The library provides specific error types:

- `auth.AuthenticationError` - General authentication failures
- `auth.TwoFactorError` - Two-factor authentication errors
- `auth.MaxLoginAttemptsError` - Too many failed login attempts

```go
if _, ok := err.(*auth.MaxLoginAttemptsError); ok {
    // Handle max login attempts error
}
```

## Session Management

The library manages cookies automatically. The session token can be retrieved and stored for later use:

```go
// Get session token after authentication
token := authenticator.GetSessionToken()

// Store token for future use
// (In production, store securely)

// Reuse token in a new session
session, _ := auth.NewSessionManager("https://localhost:5000")
session.SetSessionToken(storedToken)
```

## Requirements

- Go 1.21 or higher
- IB Gateway running and accessible
- IB account with API access enabled

## IB Gateway Setup

1. Download and install IB Gateway from Interactive Brokers
2. Enable API access in the Gateway settings
3. Configure the API port (default: 5000)
4. Enable two-factor authentication in your IB account

## Security Considerations

- Never hardcode credentials in your code
- Use environment variables or a secrets manager
- The library uses TLS with certificate verification disabled by default (IB Gateway uses self-signed certs)
- Store session tokens securely

## References

- [Interactive Brokers Web API Documentation](https://www.interactivebrokers.com/campus/ibkr-api-page/webapi-doc/)
- [Reference Node.js Implementation](https://github.com/michaeljherrmann/ib-gateway-service)

## License

MIT License
