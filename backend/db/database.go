package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"deskrow/audit"
	"deskrow/logs"
	"deskrow/shared/logging"

	_ "modernc.org/sqlite"
)

// logService is a reference to the logging service
var logService *logs.LogService

// cryptoAuditLogger implements CryptoAuditLogger
type cryptoAuditLogger struct{}

// SetLogSender is a no-op since we use direct logging
func (l *cryptoAuditLogger) SetLogSender(sender audit.LogSender) {}

func (l *cryptoAuditLogger) LogOperation(operation string, keyVersion int, userID *int, status string, errorMsg string) error {
	// First log to database
	dbErr := l.logOperationToDB(operation, keyVersion, userID, status, errorMsg)

	// Then log via logService
	if logService != nil {
		fields := map[string]interface{}{
			"operation":   operation,
			"key_version": keyVersion,
			"status":      status,
		}
		if userID != nil {
			fields["user_id"] = *userID
		}
		if errorMsg != "" {
			fields["error"] = errorMsg
		}

		msg := logging.LogMessage{
			Timestamp: time.Now(),
			Type:      "audit",
			Level:     logging.LevelInfo,
			Message:   "Crypto operation",
			Fields:    fields,
		}
		logService.Log(msg)
	}

	return dbErr
}

// logOperationToDB handles the database insertion part of LogOperation.
func (l *cryptoAuditLogger) logOperationToDB(operation string, keyVersion int, userID *int, status string, errorMsg string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	var userIDVal sql.NullInt64
	if userID != nil {
		userIDVal = sql.NullInt64{Int64: int64(*userID), Valid: true}
	}

	_, err := DB.Exec(`
		INSERT INTO crypto_audit_log (
			operation, 
			key_version, 
			user_id, 
			status, 
			error_message,
			created_at
		) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		operation,
		keyVersion,
		userIDVal,
		status,
		errorMsg,
	)
	return err
}

// DefaultCryptoAuditLogger provides the default implementation
var DefaultCryptoAuditLogger audit.CryptoAuditLogger = &cryptoAuditLogger{}

// NOTE: databaseKeyStorage implementation (implementing keystore.KeyStorage)
// and DefaultKeyStorage variable have been removed from this file.
// This functionality needs to be reimplemented using AdminDatabase.

// DatabaseWrapper implements the websocket.Database interface
type DatabaseWrapper struct {
	db *sql.DB
}

// GetUserCount returns the total number of users in the database
func (w *DatabaseWrapper) GetUserCount() (int, error) {
	var count int
	err := w.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get user count: %w", err)
	}
	return count, nil
}

// GetActiveSessionCount returns the number of active user sessions
func (w *DatabaseWrapper) GetActiveSessionCount() (int, error) {
	var count int
	// Assuming active sessions are those with valid tokens created in last 24 hours
	err := w.db.QueryRow(`
		SELECT COUNT(DISTINCT user_id) 
		FROM sessions 
		WHERE created_at > datetime('now', '-24 hours')
	`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get active session count: %w", err)
	}
	return count, nil
}

var DB *sql.DB                 // Connection pool for the main deskrow.db
var DBWrapper *DatabaseWrapper // Wrapper that implements websocket.Database interface

func Init(logSvc *logs.LogService) error {
	logService = logSvc
	var err error
	dbPath := "data/deskrow.db"

	// Create database file if it doesn't exist
	// Ensure data directory exists
	if err := os.MkdirAll("data", 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		log.Printf("Database file not found at %s, creating new one", dbPath)
		file, err := os.Create(dbPath)
		if err != nil {
			log.Printf("Failed to create database file at %s: %v", dbPath, err)
			return fmt.Errorf("failed to create database file: %w", err)
		}
		file.Close()
		if err := os.Chmod(dbPath, 0644); err != nil {
			log.Printf("Failed to set permissions on %s: %v", dbPath, err)
			return fmt.Errorf("failed to set database permissions: %w", err)
		}
		log.Printf("Successfully created database file at %s", dbPath)
	} else {
		log.Printf("Using existing database file at %s", dbPath)
	}

	DB, err = sql.Open("sqlite", dbPath)
	if err != nil {
		log.Printf("Failed to open database: %v", err)
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Verify connection
	err = DB.Ping()
	if err != nil {
		log.Printf("Database connection failed: %v", err)
		return fmt.Errorf("database connection failed: %w", err)
	}

	// Initialize the database wrapper
	DBWrapper = &DatabaseWrapper{db: DB}

	// Create tables for main DB if they don't exist
	if err := createMainTables(); err != nil { // Renamed function call
		log.Printf("Main table creation error: %v", err)
		DB.Close() // Close main DB connection on error
		return fmt.Errorf("failed to create main tables: %w", err)
	}

	// Initialize the backup database
	if err := InitBackupDB(); err != nil {
		log.Printf("Backup database initialization error: %v", err)
		DB.Close() // Close main DB connection on error
		return fmt.Errorf("failed to initialize backup database: %w", err)
	}

	// NOTE: AdminDatabase initialization might happen here or in admin/main.go
	// adminDB := NewAdminDatabase() // Example if initialized here

	log.Println("Main database initialized successfully")
	return nil
}

// createMainTables creates tables specific to the main deskrow.db.
func createMainTables() error { // Renamed function
	// Users table - check if we need to migrate
	_, err := DB.Exec(`
		CREATE TABLE IF NOT EXISTS users_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username_hash TEXT UNIQUE NOT NULL,        -- Bcrypt hashed username for lookup
			username_encrypted_pwd TEXT NOT NULL,      -- Password-derived encrypted username
			username_encrypted_seed TEXT DEFAULT '',   -- Seed-phrase derived encrypted username
			password_hash TEXT NOT NULL,               -- Bcrypt hashed password
			password_encrypted_seed TEXT DEFAULT '',   -- Seed-phrase derived encrypted password
			seed_encrypted TEXT DEFAULT '',            -- Password-derived encrypted seed phrase
			public_key_encrypted TEXT DEFAULT '',      -- Password-derived encrypted public key
			private_key_encrypted TEXT DEFAULT '',     -- Password-derived encrypted private key
			two_fa_secret_encrypted TEXT DEFAULT '',   -- Password-derived encrypted 2FA secret
			wallet_address TEXT,                       -- Public key/address from connected wallet
			wallet_type TEXT,                          -- Type of wallet (phantom, metamask, etc)
			is_wallet_user BOOLEAN DEFAULT FALSE,      -- True if wallet-only user
			key_version INTEGER DEFAULT 1,             -- Current encryption key version
			last_rotated_at TIMESTAMP,                 -- When keys were last rotated
			last_reencrypted_at TIMESTAMP,             -- When data was last re-encrypted
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			CONSTRAINT wallet_unique UNIQUE (wallet_address)
		)
	`)
	if err != nil {
		return err
	}

	// Drop old users table if it exists
	_, err = DB.Exec(`DROP TABLE IF EXISTS users`)
	if err != nil {
		return err
	}

	// Rename new table to users
	_, err = DB.Exec(`ALTER TABLE users_new RENAME TO users`)
	if err != nil {
		return err
	}

	// Identities table
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS identities (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			public_key TEXT UNIQUE NOT NULL,
			private_key_encrypted TEXT NOT NULL,
			alias TEXT NOT NULL,
			is_default BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		return err
	}

	// Transactions table
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS transactions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			hash TEXT UNIQUE NOT NULL,
			amount REAL NOT NULL,
			description TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		return err
	}

	// Crypto audit log table
	_, err = DB.Exec(`
		CREATE TABLE IF NOT EXISTS crypto_audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			operation TEXT NOT NULL,                  -- encrypt/decrypt/rotate
			key_version INTEGER NOT NULL,             -- Key version used
			user_id INTEGER,                          -- User ID if applicable
			status TEXT NOT NULL,                     -- success/failure
			error_message TEXT,                       -- Error details if failed
			metadata TEXT,                            -- Additional operation metadata
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)
	`)
	if err != nil {
		return err
	}

	// NOTE: encryption_keys, session_secrets, csrf_secrets, and encrypted_data_backups
	// table creations have been removed from here. They are now handled in
	// admin-database.go and backup_database.go respectively.

	return nil
}
