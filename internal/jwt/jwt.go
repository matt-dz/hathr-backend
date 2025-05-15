// Package jwt provides functions for creating and verifying JSON Web Tokens (JWTs).

package jwt

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	jose "gopkg.in/square/go-jose.v2"
)

// Creates a JWT
func CreateJWT(userID string, admin bool, privateKeyBytes []byte) (string, error) {

	claims := jwt.MapClaims{
		"sub":   userID,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
		"admin": admin,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return "", err
	}

	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return signed, nil
}

// Validates a JWT
func ValidateJWT(rawToken string) (*jwt.Token, error) {

	// Load JWKS path
	var jwks jose.JSONWebKeySet
	jwksPath := os.Getenv("JWKS_PATH")
	if _, err := os.Stat(jwksPath); err != nil {
		return nil, fmt.Errorf("Invalid JWKS_PATH: %w", err)
	}

	// Read the JWKS
	data, err := os.ReadFile(jwksPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read JWKS file: %w", err)
	}
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal JWKS file: %w", err)
	}

	// Create JWT parse function
	parserFunc := func(token *jwt.Token) (interface{}, error) {
		kidVal, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("Missing/invalid kid value")
		}

		keyMatches := jwks.Key(kidVal)
		if len(keyMatches) == 0 {
			return nil, fmt.Errorf("No key for kid %q", kidVal)
		}

		pub, ok := keyMatches[0].Key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("Invalid key type for kid %q. Expected RSA.", kidVal)
		}
		return pub, nil
	}

	// Parse the token
	token, err := jwt.ParseWithClaims(rawToken, nil, parserFunc)
	return token, err
}
