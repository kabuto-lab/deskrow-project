package db

import (
	"database/sql"
	// "encoding/base64" // No longer needed here
	"fmt"
	"log"
	"os"
	"sync"
	"time" // Ensure time is imported

	// "deskrow/backend/keystore" // No longer needed here

	_ "modernc.org/sqlite"
)

const backupDbPath = "data/deskrow_bak.db"

// BackupDatabase handles operations specific to the backup database.
type BackupDatabase struct {
	db *sql.DB
	mu sync.Mutex
}

// BackupRecord represents a single row in the backup table.
type BackupRecord struct {
	ID              int
	UserID          int
	OperationID     string
	KeyVersion      int
	FieldName       string
	EncryptedData   string
	BackupTimestamp time.Time
	Restored        bool
}

var backupDBInstance *BackupDatabase // Singleton instance for backup DB

// InitBackupDB initializes the backup database connection and schema.
func InitBackupDB() error {
	if backupDBInstance != nil {
		log.Println("Backup database already initialized.")
		return nil // Already initialized
	}

	// Ensure data directory exists
	if err := os.MkdirAll("data", 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	log.Printf("Initializing backup database at %s...", backupDbPath)
	db, err := sql.Open("sqlite", backupDbPath+"?_journal_mode=WAL")
	if err != nil {
		log.Printf("Failed to open backup database: %v", err)
		return fmt.Errorf("failed to open backup database: %w", err)
	}

	// Ensure the file exists (Open doesn't create it automatically if it's missing)
	if _, err := os.Stat(backupDbPath); os.IsNotExist(err) {
		log.Printf("Backup database file not found at %s, creating...", backupDbPath)
		// Close the initial handle before creating
		db.Close()
		file, createErr := os.Create(backupDbPath)
		if createErr != nil {
			log.Printf("Failed to create backup database file: %v", createErr)
			return fmt.Errorf("failed to create backup database file: %w", createErr)
		}
		file.Close()
		// Reopen the database
		db, err = sql.Open("sqlite", backupDbPath+"?_journal_mode=WAL")
		if err != nil {
			log.Printf("Failed to reopen backup database after creation: %v", err)
			return fmt.Errorf("failed to reopen backup database: %w", err)
		}
	}

	backupDB := &BackupDatabase{db: db}
	if err := backupDB.initBackupSchema(); err != nil {
		db.Close() // Close connection on schema error
		log.Printf("Failed to initialize backup database schema: %v", err)
		return fmt.Errorf("failed to initialize backup database schema: %w", err)
	}

	backupDBInstance = backupDB // Set the singleton instance
	log.Println("Backup database initialized successfully.")
	return nil
}

// initBackupSchema creates the necessary tables in the backup database.
func (bdb *BackupDatabase) initBackupSchema() error {
	bdb.mu.Lock()
	defer bdb.mu.Unlock()

	schema := `
	CREATE TABLE IF NOT EXISTS encrypted_data_backups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,                 -- Reference to user ID in main DB (for context)
		operation_id TEXT NOT NULL,               -- Unique ID for the rotation operation
		key_version INTEGER NOT NULL,             -- Key version being rotated from
		field_name TEXT NOT NULL,                 -- Which field was backed up (e.g., 'username_encrypted_pwd')
		encrypted_data TEXT NOT NULL,             -- Original encrypted data (using the old key)
		backup_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		restored BOOLEAN DEFAULT FALSE           -- Whether this backup was used for restore
	);
	CREATE INDEX IF NOT EXISTS idx_backup_user_op ON encrypted_data_backups (user_id, operation_id);
	`
	_, err := bdb.db.Exec(schema)
	if err != nil {
		log.Printf("Error creating backup table: %v", err)
	}
	return err
}

// CloseBackupDB closes the backup database connection.
func CloseBackupDB() error {
	if backupDBInstance != nil && backupDBInstance.db != nil {
		log.Println("Closing backup database connection.")
		err := backupDBInstance.db.Close()
		backupDBInstance = nil // Clear the instance
		return err
	}
	return nil
}

// AddEncryptedBackup stores an encrypted data backup.
func AddEncryptedBackup(userID int, operationID string, keyVersion int, fieldName string, encryptedData string) error {
	if backupDBInstance == nil || backupDBInstance.db == nil {
		return fmt.Errorf("backup database not initialized")
	}
	backupDBInstance.mu.Lock()
	defer backupDBInstance.mu.Unlock()

	_, err := backupDBInstance.db.Exec(`
		INSERT INTO encrypted_data_backups
		(user_id, operation_id, key_version, field_name, encrypted_data)
		VALUES (?, ?, ?, ?, ?)`,
		userID, operationID, keyVersion, fieldName, encryptedData,
	)
	if err != nil {
		log.Printf("Failed to add encrypted backup: %v", err)
		return fmt.Errorf("failed to add encrypted backup: %w", err)
	}
	return nil
}

// GetBackupsForOperation retrieves all non-restored backups for a specific user and operation ID.
func GetBackupsForOperation(userID int, operationID string) ([]BackupRecord, error) {
	if backupDBInstance == nil || backupDBInstance.db == nil {
		return nil, fmt.Errorf("backup database not initialized")
	}
	backupDBInstance.mu.Lock() // Use read lock if safe
	defer backupDBInstance.mu.Unlock()

	rows, err := backupDBInstance.db.Query(`
		SELECT id, user_id, operation_id, key_version, field_name, encrypted_data, backup_timestamp, restored
		FROM encrypted_data_backups
		WHERE user_id = ? AND operation_id = ? AND restored = FALSE`,
		userID, operationID)
	if err != nil {
		return nil, fmt.Errorf("failed to query backups: %w", err)
	}
	defer rows.Close()

	var backups []BackupRecord
	for rows.Next() {
		var b BackupRecord
		if err := rows.Scan(&b.ID, &b.UserID, &b.OperationID, &b.KeyVersion, &b.FieldName, &b.EncryptedData, &b.BackupTimestamp, &b.Restored); err != nil {
			return nil, fmt.Errorf("failed to scan backup row: %w", err)
		}
		backups = append(backups, b)
	}
	return backups, nil
}

// MarkBackupRestored marks a specific backup record as restored.
func MarkBackupRestored(backupID int) error {
	if backupDBInstance == nil || backupDBInstance.db == nil {
		return fmt.Errorf("backup database not initialized")
	}
	backupDBInstance.mu.Lock()
	defer backupDBInstance.mu.Unlock()

	_, err := backupDBInstance.db.Exec(`
		UPDATE encrypted_data_backups
		SET restored = TRUE
		WHERE id = ?`,
		backupID)
	if err != nil {
		log.Printf("Failed to mark backup %d as restored: %v", backupID, err)
		return fmt.Errorf("failed to mark backup as restored: %w", err)
	}
	return nil
}

// NOTE: KeyStorage implementation moved to secrets_database.go
