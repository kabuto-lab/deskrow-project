package db

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"sync"

	"deskrow/keystore" // Import keystore for the interface

	_ "modernc.org/sqlite"
)

const secretsDbPath = "data/secrets.db"

// SecretsDatabase handles operations specific to the secrets database.
type SecretsDatabase struct {
	db *sql.DB
	mu sync.Mutex
}

var secretsDBInstance *SecretsDatabase // Singleton instance for secrets DB

// InitSecretsDB initializes the secrets database connection and schema.
func InitSecretsDB() error {
	if secretsDBInstance != nil {
		log.Println("Secrets database already initialized.")
		return nil // Already initialized
	}

	// Ensure data directory exists
	if err := os.MkdirAll("data", 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	log.Printf("Initializing secrets database at %s...", secretsDbPath)
	db, err := sql.Open("sqlite", secretsDbPath+"?_journal_mode=WAL")
	if err != nil {
		log.Printf("Failed to open secrets database: %v", err)
		return fmt.Errorf("failed to open secrets database: %w", err)
	}

	// Ensure the file exists
	if _, err := os.Stat(secretsDbPath); os.IsNotExist(err) {
		log.Printf("Secrets database file not found at %s, creating...", secretsDbPath)
		db.Close() // Close initial handle
		file, createErr := os.Create(secretsDbPath)
		if createErr != nil {
			log.Printf("Failed to create secrets database file: %v", createErr)
			return fmt.Errorf("failed to create secrets database file: %w", createErr)
		}
		file.Close()
		// Reopen
		db, err = sql.Open("sqlite", secretsDbPath+"?_journal_mode=WAL")
		if err != nil {
			log.Printf("Failed to reopen secrets database after creation: %v", err)
			return fmt.Errorf("failed to reopen secrets database: %w", err)
		}
	}

	secretsDB := &SecretsDatabase{db: db}
	if err := secretsDB.initSecretsSchema(); err != nil {
		db.Close()
		log.Printf("Failed to initialize secrets database schema: %v", err)
		return fmt.Errorf("failed to initialize secrets database schema: %w", err)
	}

	secretsDBInstance = secretsDB // Set singleton
	log.Println("Secrets database initialized successfully.")
	return nil
}

// initSecretsSchema creates the necessary tables in the secrets database.
func (sdb *SecretsDatabase) initSecretsSchema() error {
	sdb.mu.Lock()
	defer sdb.mu.Unlock()

	schema := `
	CREATE TABLE IF NOT EXISTS security_keys (
		key_name TEXT PRIMARY KEY,                 -- e.g., encryption_key_1, session_secret_1
		version INTEGER NOT NULL,                  -- Key/secret version number
		key_value BLOB NOT NULL,                   -- The actual key/secret data (use TEXT for non-byte secrets)
		rotation_operation_id TEXT,                -- ID linking to the rotation operation
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_used_at TIMESTAMP,
		is_active BOOLEAN DEFAULT TRUE
	);
	CREATE INDEX IF NOT EXISTS idx_security_keys_version ON security_keys (version);
	CREATE INDEX IF NOT EXISTS idx_security_keys_active_name ON security_keys (is_active, key_name);
	`
	_, err := sdb.db.Exec(schema)
	if err != nil {
		log.Printf("Error creating security_keys table in secrets.db: %v", err)
	}
	return err
}

// CloseSecretsDB closes the secrets database connection.
func CloseSecretsDB() error {
	if secretsDBInstance != nil && secretsDBInstance.db != nil {
		log.Println("Closing secrets database connection.")
		err := secretsDBInstance.db.Close()
		secretsDBInstance = nil // Clear the instance
		return err
	}
	return nil
}

// GetSecretsDB returns the singleton instance of the SecretsDatabase.
// Panics if not initialized. Consider returning an error instead for robustness.
func GetSecretsDB() *SecretsDatabase {
	if secretsDBInstance == nil {
		log.Panic("Secrets database accessed before initialization")
	}
	return secretsDBInstance
}

// --- Key/Secret Storage Methods for SecretsDatabase ---

// StoreSecurityKey stores or updates an encryption key.
func (sdb *SecretsDatabase) StoreSecurityKey(version int, keyData string, operationID string) error {
	sdb.mu.Lock()
	defer sdb.mu.Unlock()
	keyName := fmt.Sprintf("encryption_key_%d", version)
	_, err := sdb.db.Exec(`
		INSERT INTO security_keys (key_name, version, key_value, rotation_operation_id, is_active)
		VALUES (?, ?, ?, ?, TRUE)
		ON CONFLICT(key_name) DO UPDATE SET
			key_value = excluded.key_value,
			rotation_operation_id = excluded.rotation_operation_id,
			last_used_at = CURRENT_TIMESTAMP,
			is_active = TRUE
	`, keyName, version, keyData, operationID)
	return err
}

// LoadSecurityKeys loads all active encryption keys. Returns map[version]keyData(string).
func (sdb *SecretsDatabase) LoadSecurityKeys() (map[int]string, error) {
	sdb.mu.Lock() // Read lock might be sufficient if using WAL
	defer sdb.mu.Unlock()
	rows, err := sdb.db.Query(`
		SELECT version, key_value
		FROM security_keys
		WHERE key_name LIKE 'encryption_key_%' AND is_active = TRUE
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make(map[int]string)
	for rows.Next() {
		var version int
		var keyData string
		if err := rows.Scan(&version, &keyData); err != nil {
			return nil, err
		}
		keys[version] = keyData
	}
	return keys, nil
}

// StoreSessionSecret stores or updates a session secret.
func (sdb *SecretsDatabase) StoreSessionSecret(version int, secret string, operationID string) error {
	sdb.mu.Lock()
	defer sdb.mu.Unlock()
	keyName := fmt.Sprintf("session_secret_%d", version)
	_, err := sdb.db.Exec(`
		INSERT INTO security_keys (key_name, version, key_value, rotation_operation_id, is_active)
		VALUES (?, ?, ?, ?, TRUE)
		ON CONFLICT(key_name) DO UPDATE SET
			key_value = excluded.key_value,
			rotation_operation_id = excluded.rotation_operation_id,
			last_used_at = CURRENT_TIMESTAMP,
			is_active = TRUE
	`, keyName, version, secret, operationID)
	return err
}

// LoadSessionSecrets loads all active session secrets.
func (sdb *SecretsDatabase) LoadSessionSecrets() (map[int]string, error) {
	sdb.mu.Lock()
	defer sdb.mu.Unlock()
	rows, err := sdb.db.Query(`
		SELECT version, key_value
		FROM security_keys
		WHERE key_name LIKE 'session_secret_%' AND is_active = TRUE
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	secrets := make(map[int]string)
	for rows.Next() {
		var version int
		var secret string
		if err := rows.Scan(&version, &secret); err != nil {
			return nil, err
		}
		secrets[version] = secret
	}
	return secrets, nil
}

// --- KeyStorage Implementation using SecretsDatabase ---

// secretsDBKeyStorage implements keystore.KeyStorage using the SecretsDatabase.
type secretsDBKeyStorage struct {
	sdb *SecretsDatabase // Reference to the secrets database instance
}

// NewSecretsDBKeyStorage creates a new KeyStorage implementation backed by SecretsDatabase.
// This function now resides in the db package.
func NewSecretsDBKeyStorage(sdb *SecretsDatabase) keystore.KeyStorage {
	if sdb == nil {
		log.Panic("SecretsDatabase instance provided to NewSecretsDBKeyStorage is nil")
	}
	return &secretsDBKeyStorage{sdb: sdb}
}

// StoreKey stores an encryption key in secrets.db.
func (ks *secretsDBKeyStorage) StoreKey(version int, key []byte, operationID string) error {
	keyData := base64.StdEncoding.EncodeToString(key)
	return ks.sdb.StoreSecurityKey(version, keyData, operationID)
}

// LoadKeys loads active encryption keys from secrets.db.
func (ks *secretsDBKeyStorage) LoadKeys() (map[int][]byte, error) {
	keyMapStr, err := ks.sdb.LoadSecurityKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to load security keys from secrets DB: %w", err)
	}

	keyMapBytes := make(map[int][]byte)
	for version, keyData := range keyMapStr {
		keyBytes, err := base64.StdEncoding.DecodeString(keyData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key version %d from secrets DB: %w", version, err)
		}
		keyMapBytes[version] = keyBytes
	}
	return keyMapBytes, nil
}

// StoreSessionSecret stores a session secret in secrets.db.
func (ks *secretsDBKeyStorage) StoreSessionSecret(version int, secret string, operationID string) error {
	return ks.sdb.StoreSessionSecret(version, secret, operationID)
}

// LoadSessionSecrets loads active session secrets from secrets.db.
func (ks *secretsDBKeyStorage) LoadSessionSecrets() (map[int]string, error) {
	return ks.sdb.LoadSessionSecrets()
}

// StoreCSRFSecret stores a CSRF secret in secrets.db.
func (ks *secretsDBKeyStorage) StoreCSRFSecret(version int, secret string, operationID string) error {
	return ks.sdb.StoreCSRFSecret(version, secret, operationID)
}

// LoadCSRFSecrets loads active CSRF secrets from secrets.db.
func (ks *secretsDBKeyStorage) LoadCSRFSecrets() (map[int]string, error) {
	return ks.sdb.LoadCSRFSecrets()
}

// StoreServerFingerprint stores a server's public key fingerprint
func (ks *secretsDBKeyStorage) StoreServerFingerprint(fingerprint string) error {
	ks.sdb.mu.Lock()
	defer ks.sdb.mu.Unlock()

	_, err := ks.sdb.db.Exec(`
		INSERT INTO security_keys (key_name, version, key_value, is_active)
		VALUES ('server_fingerprint', 1, ?, TRUE)
		ON CONFLICT(key_name) DO UPDATE SET
			key_value = excluded.key_value,
			last_used_at = CURRENT_TIMESTAMP
	`, fingerprint)
	return err
}

// LoadServerFingerprint retrieves the stored server fingerprint
func (ks *secretsDBKeyStorage) LoadServerFingerprint() (string, error) {
	ks.sdb.mu.Lock()
	defer ks.sdb.mu.Unlock()

	var fingerprint string
	err := ks.sdb.db.QueryRow(`
		SELECT key_value 
		FROM security_keys
		WHERE key_name = 'server_fingerprint' AND is_active = TRUE
	`).Scan(&fingerprint)

	if err == sql.ErrNoRows {
		return "", nil // No fingerprint stored yet
	}
	return fingerprint, err
}

// StoreCSRFSecret stores or updates a CSRF secret.
func (sdb *SecretsDatabase) StoreCSRFSecret(version int, secret string, operationID string) error {
	sdb.mu.Lock()
	defer sdb.mu.Unlock()
	keyName := fmt.Sprintf("csrf_secret_%d", version)
	_, err := sdb.db.Exec(`
		INSERT INTO security_keys (key_name, version, key_value, rotation_operation_id, is_active)
		VALUES (?, ?, ?, ?, TRUE)
		ON CONFLICT(key_name) DO UPDATE SET
			key_value = excluded.key_value,
			rotation_operation_id = excluded.rotation_operation_id,
			last_used_at = CURRENT_TIMESTAMP,
			is_active = TRUE
	`, keyName, version, secret, operationID)
	return err
}

// LoadCSRFSecrets loads all active CSRF secrets.
func (sdb *SecretsDatabase) LoadCSRFSecrets() (map[int]string, error) {
	sdb.mu.Lock()
	defer sdb.mu.Unlock()
	rows, err := sdb.db.Query(`
		SELECT version, key_value
		FROM security_keys
		WHERE key_name LIKE 'csrf_secret_%' AND is_active = TRUE
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	secrets := make(map[int]string)
	for rows.Next() {
		var version int
		var secret string
		if err := rows.Scan(&version, &secret); err != nil {
			return nil, err
		}
		secrets[version] = secret
	}
	return secrets, nil
}
