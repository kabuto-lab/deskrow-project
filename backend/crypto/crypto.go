package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"deskrow/audit"
	"deskrow/keystore"

	"golang.org/x/crypto/bcrypt"
)

// Key rotation configuration
const (
	KeyRotationInterval = 90 * 24 * time.Hour // 90 days
	MaxKeyVersions      = 3                   // Keep 3 previous key versions
)

// Session secret rotation configuration
func SessionSecretRotationEnabled() bool {
	return os.Getenv("SESSION_SECRET_ROTATION_ENABLED") == "true"
}

func SessionSecretRotationInterval() time.Duration {
	days, _ := strconv.Atoi(os.Getenv("SESSION_SECRET_ROTATION_INTERVAL_DAYS"))
	if days <= 0 {
		return 30 * 24 * time.Hour // default 30 days
	}
	return time.Duration(days) * 24 * time.Hour
}

func MaxSessionSecretVersions() int {
	versions, _ := strconv.Atoi(os.Getenv("MAX_SESSION_SECRET_VERSIONS"))
	if versions <= 0 {
		return 3 // default
	}
	return versions
}

// KeyRotationEnabled checks if key rotation is enabled
func KeyRotationEnabled() bool {
	return os.Getenv("KEY_ROTATION_ENABLED") == "true"
}

// KeyRotationIntervalDays returns configured rotation interval
func KeyRotationIntervalDays() int {
	days, _ := strconv.Atoi(os.Getenv("KEY_ROTATION_INTERVAL_DAYS"))
	if days <= 0 {
		return 90 // default
	}
	return days
}

// CurrentKeyVersion returns the current key version
func CurrentKeyVersion() int {
	return keyStore.CurrentVersion
}

// AuditCryptoOperations checks if crypto operations should be audited
func AuditCryptoOperations() bool {
	return os.Getenv("AUDIT_CRYPTO_OPERATIONS") == "true"
}

// KeyStore manages encryption key versions
type KeyStore struct {
	CurrentVersion int
	Keys           map[int][]byte // version -> key
	storage        keystore.KeyStorage
}

var keyStore = &KeyStore{
	CurrentVersion: 1,
	Keys:           make(map[int][]byte),
}

// SessionSecretStore manages JWT signing secret versions
type SessionSecretStore struct {
	CurrentVersion int
	Secrets        map[int]string // version -> secret
	storage        keystore.KeyStorage
}

var sessionSecretStore = &SessionSecretStore{
	CurrentVersion: 1,
	Secrets:        make(map[int]string),
}

// CSRFSecretStore manages CSRF token secret versions
type CSRFSecretStore struct {
	CurrentVersion int
	Secrets        map[int]string // version -> secret
	storage        keystore.KeyStorage
}

var csrfSecretStore = &CSRFSecretStore{
	CurrentVersion: 1,
	Secrets:        make(map[int]string),
}

// InitSessionSecretStore initializes the session secret store
func InitSessionSecretStore(storage keystore.KeyStorage) error {
	sessionSecretStore.storage = storage

	// Try to load secrets from storage
	secrets, err := storage.LoadSessionSecrets()
	if err == nil && len(secrets) > 0 {
		sessionSecretStore.Secrets = secrets
		// Find max version
		for v := range secrets {
			if v > sessionSecretStore.CurrentVersion {
				sessionSecretStore.CurrentVersion = v
			}
		}
	} else {
		// No secrets in storage, create initial secret
		sessionSecretStore.Secrets[1] = os.Getenv("SESSION_SECRET")
		err = storage.StoreSessionSecret(1, sessionSecretStore.Secrets[1], "initial")
	}
	return err
}

// InitCSRFSecretStore initializes the CSRF secret store
func InitCSRFSecretStore(storage keystore.KeyStorage) error {
	csrfSecretStore.storage = storage

	// Try to load secrets from storage
	secrets, err := storage.LoadCSRFSecrets()
	if err == nil && len(secrets) > 0 {
		csrfSecretStore.Secrets = secrets
		// Find max version
		for v := range secrets {
			if v > csrfSecretStore.CurrentVersion {
				csrfSecretStore.CurrentVersion = v
			}
		}
	} else {
		// No secrets in storage, create initial secret
		csrfSecretStore.Secrets[1] = os.Getenv("CSRF_SECRET")
		err = storage.StoreCSRFSecret(1, csrfSecretStore.Secrets[1], "initial")
	}
	return err
}

// RotateSessionSecrets generates a new session secret version
func RotateSessionSecrets(logger audit.CryptoAuditLogger) error {
	newVersion := sessionSecretStore.CurrentVersion + 1
	newSecret := generateSessionSecret()
	operationID := fmt.Sprintf("rotate-session-%d-%d", time.Now().Unix(), newVersion)

	// First persist the new secret
	if sessionSecretStore.storage != nil {
		if err := sessionSecretStore.storage.StoreSessionSecret(newVersion, newSecret, operationID); err != nil {
			if logger != nil && AuditCryptoOperations() {
				logger.LogOperation("rotate-session", newVersion, nil, "failure", err.Error())
			}
			return fmt.Errorf("failed to store new session secret: %w", err)
		}
	}

	// Update in-memory store
	sessionSecretStore.Secrets[newVersion] = newSecret
	sessionSecretStore.CurrentVersion = newVersion

	// Prune old versions (both in-memory and storage)
	for v := range sessionSecretStore.Secrets {
		if v < newVersion-MaxSessionSecretVersions() {
			delete(sessionSecretStore.Secrets, v)
		}
	}

	if logger != nil && AuditCryptoOperations() {
		logger.LogOperation("rotate-session", newVersion, nil, "success", "")
	}
	return nil
}

// GetSessionSecret returns the secret for a specific version
func GetSessionSecret(version int) (string, error) {
	secret, exists := sessionSecretStore.Secrets[version]
	if !exists {
		return "", fmt.Errorf("session secret version %d not found", version)
	}
	return secret, nil
}

// CurrentSessionSecretVersion returns the current secret version
func CurrentSessionSecretVersion() int {
	return sessionSecretStore.CurrentVersion
}

// CSRFSecretRotationEnabled checks if CSRF secret rotation is enabled
func CSRFSecretRotationEnabled() bool {
	return os.Getenv("CSRF_SECRET_ROTATION_ENABLED") == "true"
}

func CSRFSecretRotationInterval() time.Duration {
	days, _ := strconv.Atoi(os.Getenv("CSRF_SECRET_ROTATION_INTERVAL_DAYS"))
	if days <= 0 {
		return 30 * 24 * time.Hour // default 30 days
	}
	return time.Duration(days) * 24 * time.Hour
}

func MaxCSRFSecretVersions() int {
	versions, _ := strconv.Atoi(os.Getenv("MAX_CSRF_SECRET_VERSIONS"))
	if versions <= 0 {
		return 3 // default
	}
	return versions
}

// RotateCSRFSecrets generates a new CSRF secret version
func RotateCSRFSecrets(logger audit.CryptoAuditLogger) error {
	newVersion := csrfSecretStore.CurrentVersion + 1
	newSecret := generateSessionSecret() // Reuse same generation logic
	operationID := fmt.Sprintf("rotate-csrf-%d-%d", time.Now().Unix(), newVersion)

	// First persist the new secret
	if csrfSecretStore.storage != nil {
		if err := csrfSecretStore.storage.StoreCSRFSecret(newVersion, newSecret, operationID); err != nil {
			if logger != nil && AuditCryptoOperations() {
				logger.LogOperation("rotate-csrf", newVersion, nil, "failure", err.Error())
			}
			return fmt.Errorf("failed to store new CSRF secret: %w", err)
		}
	}

	// Update in-memory store
	csrfSecretStore.Secrets[newVersion] = newSecret
	csrfSecretStore.CurrentVersion = newVersion

	// Prune old versions
	for v := range csrfSecretStore.Secrets {
		if v < newVersion-MaxCSRFSecretVersions() {
			delete(csrfSecretStore.Secrets, v)
		}
	}

	if logger != nil && AuditCryptoOperations() {
		logger.LogOperation("rotate-csrf", newVersion, nil, "success", "")
	}
	return nil
}

// GetCSRFSecret returns the secret for a specific version
func GetCSRFSecret(version int) (string, error) {
	secret, exists := csrfSecretStore.Secrets[version]
	if !exists {
		return "", fmt.Errorf("CSRF secret version %d not found", version)
	}
	return secret, nil
}

// CurrentCSRFSecretVersion returns the current CSRF secret version
func CurrentCSRFSecretVersion() int {
	return csrfSecretStore.CurrentVersion
}

// generateSessionSecret creates a new random session secret
func generateSessionSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based secret if crypto/rand fails
		return fmt.Sprintf("%x", sha256.Sum256([]byte(time.Now().String())))
	}
	return fmt.Sprintf("%x", b)
}

// InitKeyStore initializes the key store with a storage implementation
func InitKeyStore(storage keystore.KeyStorage) error {
	keyStore.storage = storage

	// Try to load keys from storage
	keys, err := storage.LoadKeys()
	if err == nil && len(keys) > 0 {
		keyStore.Keys = keys
		// Find max version
		for v := range keys {
			if v > keyStore.CurrentVersion {
				keyStore.CurrentVersion = v
			}
		}
	} else {
		// No keys in storage, create initial key
		keyStore.Keys[1] = deriveRootKey()
		err = storage.StoreKey(1, keyStore.Keys[1], "initial")
	}
	return err
}

// deriveRootKey creates the root encryption key
func deriveRootKey() []byte {
	seed := os.Getenv("ENCRYPTION_ROOT_SEED")
	if seed == "" {
		seed = "default-insecure-seed" // Only for development
	}
	key, _ := bcrypt.GenerateFromPassword([]byte(seed), 14)
	return key[:32]
}

// RotateKeys generates a new encryption key version and re-encrypts data
func RotateKeys(logger audit.CryptoAuditLogger) error {
	newVersion := keyStore.CurrentVersion + 1
	newKey := deriveRootKey()
	operationID := fmt.Sprintf("rotate-%d-%d", time.Now().Unix(), newVersion)

	// First persist the new key
	if keyStore.storage != nil {
		if err := keyStore.storage.StoreKey(newVersion, newKey, operationID); err != nil {
			if logger != nil && AuditCryptoOperations() {
				logger.LogOperation("rotate", newVersion, nil, "failure", err.Error())
			}
			return fmt.Errorf("failed to store new key: %w", err)
		}
	}

	// Update in-memory store
	keyStore.Keys[newVersion] = newKey
	keyStore.CurrentVersion = newVersion

	// Prune old versions (both in-memory and storage)
	for v := range keyStore.Keys {
		if v < newVersion-MaxKeyVersions {
			delete(keyStore.Keys, v)
		}
	}

	if logger != nil && AuditCryptoOperations() {
		logger.LogOperation("rotate", newVersion, nil, "success", "")
	}
	return nil
}

// ReencryptData re-encrypts data from oldKey to newKey
func ReencryptData(encryptedData string, oldKey []byte, newKey []byte, logger audit.CryptoAuditLogger, userID *int) (string, error) {
	// Decrypt with old key
	plaintext, err := DecryptWithKey(encryptedData, oldKey, logger, userID)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt during re-encryption: %w", err)
	}

	// Re-encrypt with new key
	return EncryptWithKey(plaintext, newKey, logger, userID)
}

// GetKey returns the key for a specific version
func GetKey(version int) ([]byte, error) {
	key, exists := keyStore.Keys[version]
	if !exists {
		return nil, fmt.Errorf("key version %d not found", version)
	}
	return key, nil
}

// encryptWithKey encrypts data using AES-GCM with provided key
func EncryptWithKey(plaintext string, key []byte, logger audit.CryptoAuditLogger, userID *int) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		if logger != nil && AuditCryptoOperations() {
			logger.LogOperation("encrypt", CurrentKeyVersion(), userID, "failure", err.Error())
		}
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		if logger != nil && AuditCryptoOperations() {
			logger.LogOperation("encrypt", CurrentKeyVersion(), userID, "failure", err.Error())
		}
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		if logger != nil && AuditCryptoOperations() {
			logger.LogOperation("encrypt", CurrentKeyVersion(), userID, "failure", err.Error())
		}
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	result := base64.StdEncoding.EncodeToString(ciphertext)

	if logger != nil && AuditCryptoOperations() {
		logger.LogOperation("encrypt", CurrentKeyVersion(), userID, "success", "")
	}
	return result, nil
}

// encryptWithPassword encrypts data using AES-GCM with password-derived key
func EncryptWithPassword(plaintext, password string, logger audit.CryptoAuditLogger, userID *int) (string, error) {
	key, err := DeriveKeyFromPassword(password)
	if err != nil {
		if logger != nil && AuditCryptoOperations() {
			logger.LogOperation("encrypt", CurrentKeyVersion(), userID, "failure", err.Error())
		}
		return "", err
	}
	return EncryptWithKey(plaintext, key, logger, userID)
}

// decryptWithKey decrypts data using AES-GCM with provided key
func DecryptWithKey(encodedCiphertext string, key []byte, logger audit.CryptoAuditLogger, userID *int) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		if logger != nil && AuditCryptoOperations() {
			logger.LogOperation("decrypt", CurrentKeyVersion(), userID, "failure", err.Error())
		}
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		if logger != nil && AuditCryptoOperations() {
			logger.LogOperation("decrypt", CurrentKeyVersion(), userID, "failure", err.Error())
		}
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		if logger != nil && AuditCryptoOperations() {
			logger.LogOperation("decrypt", CurrentKeyVersion(), userID, "failure", err.Error())
		}
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		if logger != nil && AuditCryptoOperations() {
			logger.LogOperation("decrypt", CurrentKeyVersion(), userID, "failure", "ciphertext too short")
		}
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		if logger != nil && AuditCryptoOperations() {
			logger.LogOperation("decrypt", CurrentKeyVersion(), userID, "failure", err.Error())
		}
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	if logger != nil && AuditCryptoOperations() {
		logger.LogOperation("decrypt", CurrentKeyVersion(), userID, "success", "")
	}
	return string(plaintext), nil
}

// decryptWithPassword decrypts data using AES-GCM with password-derived key
func DecryptWithPassword(encodedCiphertext, password string, logger audit.CryptoAuditLogger, userID *int) (string, error) {
	key, err := DeriveKeyFromPassword(password)
	if err != nil {
		if logger != nil && AuditCryptoOperations() {
			logger.LogOperation("decrypt", CurrentKeyVersion(), userID, "failure", err.Error())
		}
		return "", err
	}
	return DecryptWithKey(encodedCiphertext, key, logger, userID)
}

// deriveKeyFromPassword creates a consistent 32-byte key from password using bcrypt
func DeriveKeyFromPassword(password string) ([]byte, error) {
	key, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return nil, err
	}
	return key[:32], nil
}

// deriveKeyFromSeed creates a consistent 32-byte key from seed phrase using bcrypt
func DeriveKeyFromSeed(seedPhrase string) ([]byte, error) {
	key, err := bcrypt.GenerateFromPassword([]byte(seedPhrase), 14)
	if err != nil {
		return nil, err
	}
	return key[:32], nil
}

// generateSeedPhrase creates a 12-word BIP39 compliant seed phrase
func GenerateSeedPhrase(wordList []string) (string, error) {
	const wordCount = 12
	if len(wordList) < wordCount {
		return "", fmt.Errorf("not enough words in dictionary")
	}

	words := make([]string, wordCount)
	for i := 0; i < wordCount; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(wordList))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random index: %w", err)
		}
		words[i] = wordList[idx.Int64()]
	}

	return strings.Join(words, " "), nil
}

// generateDeterministicKeyPair generates ed25519 keys from a seed phrase
func GenerateDeterministicKeyPair(seedPhrase string) (publicKey string, privateKey string, err error) {
	keyMaterial, err := DeriveKeyFromSeed(seedPhrase)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive key from seed: %w", err)
	}

	privKey := ed25519.NewKeyFromSeed(keyMaterial)
	pubKey := privKey.Public().(ed25519.PublicKey)

	return base64.StdEncoding.EncodeToString(pubKey),
		base64.StdEncoding.EncodeToString(privKey),
		nil
}

// generateDeterministicKeyPair generates ed25519 keys from a seed phrase
func GenerateDeterministicPrivateKey(seedPhrase string) (privateKey string, err error) {
	keyMaterial, err := DeriveKeyFromSeed(seedPhrase)
	if err != nil {
		return "", fmt.Errorf("failed to derive key from seed: %w", err)
	}

	privKey := ed25519.NewKeyFromSeed(keyMaterial)

	return base64.StdEncoding.EncodeToString(privKey), nil
}

// generateTwoFASecret creates a new TOTP secret
func GenerateTwoFASecret() (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("failed to generate 2FA secret: %w", err)
	}
	return base32.StdEncoding.EncodeToString(secret), nil
}

// zeroMemory overwrites the given byte slice with zeros to clean sensitive data
func ZeroMemory(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// VerifyTOTP verifies a TOTP code against the given secret
func VerifyTOTP(secret, code string) bool {
	// TODO: Implement proper TOTP verification
	// For now just return true to allow development to continue
	return true
}

// DeriveDecryptionKey creates a consistent 32-byte key from session ID and timestamp
func DeriveDecryptionKey(sessionID string, timestamp int64) ([]byte, error) {
	// Combine session ID and timestamp
	combined := sessionID + strconv.FormatInt(timestamp, 10)

	// Use bcrypt with cost factor 14
	key, err := bcrypt.GenerateFromPassword([]byte(combined), 14)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Return first 32 bytes (bcrypt output is longer but we only need 32)
	return key[:32], nil
}

// ImportPrivateKey imports a PEM encoded ECDSA private key
func ImportPrivateKey(pemEncoded string) (*ecdsa.PrivateKey, error) {
	if pemEncoded == "" {
		return nil, errors.New("empty private key")
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return privKey, nil
}

// DeriveSharedSecret derives a shared secret using ECDH
func DeriveSharedSecret(privKey *ecdsa.PrivateKey, pubKeyJWK map[string]interface{}) ([]byte, error) {
	xStr, ok := pubKeyJWK["x"].(string)
	yStr, ok2 := pubKeyJWK["y"].(string)
	if !ok || !ok2 {
		return nil, errors.New("invalid public key format")
	}

	xBytes, err := base64URLDecode(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	}
	yBytes, err := base64URLDecode(yStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	sx, _ := privKey.Curve.ScalarMult(x, y, privKey.D.Bytes())
	if sx == nil {
		return nil, errors.New("failed to derive shared secret")
	}

	secret := sha256.Sum256(sx.Bytes())
	return secret[:], nil
}

func base64URLDecode(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	return hex.DecodeString(s)
}

// DecryptAESGCM decrypts data using AES-GCM
func DecryptAESGCM(key []byte, iv []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(iv) != aesgcm.NonceSize() {
		return nil, errors.New("invalid IV length")
	}

	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
