package admin_auth

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AdminClientAuth manages authentication for admin clients
type AdminClientAuth struct {
	adminSharedSecret []byte
	authorizedKeys    map[string]ed25519.PublicKey
}

// AdminClaims represents JWT claims for admin authentication
type AdminClaims struct {
	ClientID string `json:"client_id"`
	jwt.RegisteredClaims
}

// NewAdminClientAuth creates a new admin client authentication manager
func NewAdminClientAuth() (*AdminClientAuth, error) {
	sharedSecret := os.Getenv("ADMIN_SHARED_SECRET")
	if sharedSecret == "" {
		return nil, errors.New("ADMIN_SHARED_SECRET not set in environment")
	}

	auth := &AdminClientAuth{
		adminSharedSecret: []byte(sharedSecret),
		authorizedKeys:    make(map[string]ed25519.PublicKey),
	}

	// Load authorized client keys from environment variable
	authorizedKeysStr := os.Getenv("AUTHORIZED_CLIENT_KEYS")
	if authorizedKeysStr != "" {
		for _, keyHex := range strings.Split(authorizedKeysStr, ",") {
			keyHex = strings.TrimSpace(keyHex)
			if keyHex != "" {
				keyBytes, err := hex.DecodeString(keyHex)
				if err != nil {
					return nil, fmt.Errorf("invalid authorized key format: %v", err)
				}

				if len(keyBytes) != ed25519.PublicKeySize {
					return nil, fmt.Errorf("invalid key size: expected %d bytes, got %d", ed25519.PublicKeySize, len(keyBytes))
				}

				publicKey := ed25519.PublicKey(keyBytes)
				auth.authorizedKeys[keyHex] = publicKey
			}
		}
	}

	if len(auth.authorizedKeys) == 0 {
		log.Printf("WARNING: No authorized client keys configured")
	}

	return auth, nil
}

// GenerateToken generates a JWT token for admin authentication
func (a *AdminClientAuth) GenerateToken(clientID string) (string, error) {
	claims := &AdminClaims{
		ClientID: clientID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "main-server",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.adminSharedSecret)
}

// ValidateToken validates a JWT token for admin authentication
func (a *AdminClientAuth) ValidateToken(tokenString string) (*AdminClaims, error) {
	claims := &AdminClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.adminSharedSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

// VerifyClientKey verifies if a client key is authorized
func (a *AdminClientAuth) VerifyClientKey(keyHex string) bool {
	_, exists := a.authorizedKeys[keyHex]
	return exists
}

// AuthorizeWSConnection authorizes a WebSocket connection request
func (a *AdminClientAuth) AuthorizeWSConnection(queryParams map[string]string, headers map[string][]string) error {
	// Try multiple authentication methods
	var token string
	
	// Method 1: Query parameter
	if queryToken := queryParams["admin_token"]; queryToken != "" {
		token = queryToken
	} else if queryToken := queryParams["token"]; queryToken != "" {
		token = queryToken
	} else {
		// Method 2: Authorization header
		if authHeaders := headers["Authorization"]; len(authHeaders) > 0 {
			authHeader := authHeaders[0]
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = authHeader[7:]
			} else if strings.HasPrefix(authHeader, "Admin ") {
				token = authHeader[6:]
			}
		}
	}

	if token == "" {
		return errors.New("no authentication token provided")
	}

	_, err := a.ValidateToken(token)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	return nil
}

// AuthorizeCommandRequest authorizes an admin command request
func (a *AdminClientAuth) AuthorizeCommandRequest(headers map[string][]string) error {
	var token string

	// Look for token in Authorization header
	if authHeaders := headers["Authorization"]; len(authHeaders) > 0 {
		authHeader := authHeaders[0]
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = authHeader[7:]
		} else if strings.HasPrefix(authHeader, "Admin ") {
			token = authHeader[6:]
		} else {
			// If no prefix, assume it's the token directly
			token = authHeader
		}
	}

	if token == "" {
		return errors.New("no authentication token provided")
	}

	_, err := a.ValidateToken(token)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	return nil
}

// GenerateClientKeyPair generates a new key pair for an admin client
func (a *AdminClientAuth) GenerateClientKeyPair() (publicKeyHex, privateKeyHex string, err error) {
	// Generate a new public/private key pair using Ed25519
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	publicKeyHex = hex.EncodeToString(publicKey)
	privateKeyHex = hex.EncodeToString(privateKey)

	return publicKeyHex, privateKeyHex, nil
}

// SignMessage signs a message with a private key
func (a *AdminClientAuth) SignMessage(message string, privateKeyHex string) (string, error) {
	privateKey, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key size: expected %d bytes", ed25519.PrivateKeySize)
	}

	signature := ed25519.Sign(ed25519.PrivateKey(privateKey), []byte(message))
	return hex.EncodeToString(signature), nil
}

// VerifySignature verifies a signature for a message using a public key
func (a *AdminClientAuth) VerifySignature(message, signatureHex, publicKeyHex string) (bool, error) {
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, fmt.Errorf("invalid signature: %w", err)
	}

	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return false, fmt.Errorf("invalid public key: %w", err)
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size: expected %d bytes", ed25519.PublicKeySize)
	}

	return ed25519.Verify(ed25519.PublicKey(publicKey), []byte(message), signature), nil
}

// GenerateHMAC generates an HMAC for a message
func (a *AdminClientAuth) GenerateHMAC(message string) string {
	h := hmac.New(sha256.New, a.adminSharedSecret)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyHMAC verifies an HMAC for a message
func (a *AdminClientAuth) VerifyHMAC(message, expectedHMAC string) bool {
	calculatedHMAC := a.GenerateHMAC(message)
	return hmac.Equal([]byte(calculatedHMAC), []byte(expectedHMAC))
}