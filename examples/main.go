package main

import (
	"fmt"
	"log"
	"os"

	"github.com/bishop-bot/ibgateway-go/auth"
)

func main() {
	// Get credentials from environment variables
	username := os.Getenv("IB_USERNAME")
	password := os.Getenv("IB_PASSWORD")
	baseURL := os.Getenv("IB_BASE_URL")
	totpSecret := os.Getenv("IB_TOTP_SECRET")

	if username == "" || password == "" {
		log.Fatal("IB_USERNAME and IB_PASSWORD environment variables are required")
	}

	if baseURL == "" {
		baseURL = "https://localhost:5000"
	}

	// Create authenticator configuration
	authConfig := auth.AuthConfig{
		Username:           username,
		Password:           password,
		BaseURL:            baseURL,
		SecondFactorMethod: auth.TOTP,
	}

	// Add TOTP secret if provided
	if totpSecret != "" {
		authConfig.TOTPSecret = totpSecret
	}

	// Create authenticator
	authenticator, err := auth.NewAuthenticator(authConfig)
	if err != nil {
		log.Fatalf("Failed to create authenticator: %v", err)
	}
	defer authenticator.Close()

	// Perform authentication
	log.Println("Starting authentication...")
	if err := authenticator.Authenticate(); err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	// Finalize authentication
	log.Println("Finalizing authentication...")
	if err := authenticator.Finalize(); err != nil {
		log.Fatalf("Failed to finalize: %v", err)
	}

	log.Println("Authentication successful!")

	// Check if paper trading
	if authenticator.IsPaper() {
		fmt.Println("Connected to paper trading account")
	} else {
		fmt.Println("Connected to live trading account")
	}

	// Get session and make API request
	session := authenticator.GetSession()

	// Example: Get accounts
	resp, err := session.Get("/v1/api/portfolio/accounts")
	if err != nil {
		log.Printf("Failed to get accounts: %v", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Response status: %s\n", resp.Status)
}
