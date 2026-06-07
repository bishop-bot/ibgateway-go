// Package auth provides authentication functionality for the Interactive Brokers
// Client Portal Web API Gateway.
package auth

import "fmt"

// TwoFactorError represents an error during two-factor authentication.
type TwoFactorError struct {
	Message string
}

func (e *TwoFactorError) Error() string {
	return fmt.Sprintf("two-factor authentication error: %s", e.Message)
}

// NewTwoFactorError creates a new TwoFactorError.
func NewTwoFactorError(message string) *TwoFactorError {
	return &TwoFactorError{Message: message}
}

// AuthenticationError represents a general authentication failure.
type AuthenticationError struct {
	Message string
}

func (e *AuthenticationError) Error() string {
	return fmt.Sprintf("authentication error: %s", e.Message)
}

// NewAuthenticationError creates a new AuthenticationError.
func NewAuthenticationError(message string) *AuthenticationError {
	return &AuthenticationError{Message: message}
}

// MaxLoginAttemptsError indicates too many failed login attempts.
type MaxLoginAttemptsError struct {
	Message string
}

func (e *MaxLoginAttemptsError) Error() string {
	return fmt.Sprintf("max login attempts error: %s", e.Message)
}

// NewMaxLoginAttemptsError creates a new MaxLoginAttemptsError.
func NewMaxLoginAttemptsError(message string) *MaxLoginAttemptsError {
	return &MaxLoginAttemptsError{Message: message}
}
