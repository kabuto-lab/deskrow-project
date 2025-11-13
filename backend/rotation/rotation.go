package rotation

import (
	"database/sql"
	"deskrow/crypto"
	"deskrow/db"
	"fmt"
	"log"
	"time"
)

type RotationService struct {
	DB *sql.DB
}

func NewRotationService(db *sql.DB) *RotationService {
	return &RotationService{DB: db}
}

func (rs *RotationService) RunScheduledRotation() error {
	// Check if rotation is enabled
	if !crypto.KeyRotationEnabled() {
		return nil
	}

	// Get users needing rotation
	users, err := rs.getUsersNeedingRotation()
	if err != nil {
		return err
	}

	// Rotate keys for each user
	for _, user := range users {
		if err := rs.rotateUserKeys(user); err != nil {
			log.Printf("Failed to rotate keys for user %d: %v", user.ID, err)
			continue
		}
	}

	return nil
}

func (rs *RotationService) getUsersNeedingRotation() ([]db.User, error) {
	// Query users where last_rotated_at is older than rotation interval
	// or has never been rotated
	rows, err := rs.DB.Query(`
		SELECT id 
		FROM users 
		WHERE last_rotated_at IS NULL 
		OR last_rotated_at < datetime('now', ?)`,
		fmt.Sprintf("-%d days", crypto.KeyRotationIntervalDays()))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []db.User
	for rows.Next() {
		var user db.User
		if err := rows.Scan(&user.ID); err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// backupEncryptedData method removed, using db.AddEncryptedBackup directly.

func (rs *RotationService) rotateUserKeys(user db.User) error {
	// Generate unique operation ID for this rotation
	operationID := fmt.Sprintf("rotation-%d-%d", user.ID, time.Now().Unix())
	currentKeyVersion := crypto.CurrentKeyVersion() // Get version before potential rotation

	// Get full user data with encrypted fields FIRST
	fullUser, err := db.GetUserByID(user.ID)
	if err != nil {
		return fmt.Errorf("failed to get user data for rotation: %w", err)
	}
	if fullUser == nil {
		return fmt.Errorf("user %d not found for rotation", user.ID)
	}

	// Backup current encrypted data to backup DB *before* main DB transaction
	fieldsToBackup := map[string]string{
		"username_encrypted_pwd":  fullUser.UsernameEncryptedPwd,
		"seed_encrypted":          fullUser.SeedEncrypted,
		"public_key_encrypted":    fullUser.PublicKeyEncrypted,
		"private_key_encrypted":   fullUser.PrivateKeyEncrypted,
		"two_fa_secret_encrypted": fullUser.TwoFASecretEncrypted,
	}
	for fieldName, encryptedData := range fieldsToBackup {
		if encryptedData != "" { // Only backup non-empty fields
			if err := db.AddEncryptedBackup(user.ID, operationID, currentKeyVersion, fieldName, encryptedData); err != nil {
				// Log error but potentially continue? Or fail hard? For now, fail hard.
				return fmt.Errorf("failed to backup field %s to backup DB: %w", fieldName, err)
			}
		}
	}

	// --- Start Main DB Transaction ---
	tx, err := rs.DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	rollback := true // Assume rollback unless commit succeeds
	defer func() {
		if rollback {
			log.Printf("Rolling back transaction for user %d rotation (operation: %s)", user.ID, operationID)
			tx.Rollback()
		}
	}()

	// Get old key (using the version we captured earlier)
	oldKey, err := crypto.GetKey(currentKeyVersion)
	if err != nil {
		return fmt.Errorf("failed to get old key (version %d): %w", currentKeyVersion, err)
	}

	// Rotate keys (this updates the secrets DB)
	if err := crypto.RotateKeys(db.DefaultCryptoAuditLogger); err != nil {
		// Rotation failed, no changes made to main DB yet, backups exist.
		return fmt.Errorf("key rotation failed: %w", err)
	}
	newKeyVersion := crypto.CurrentKeyVersion() // Get the *new* current version

	// Get new key after rotation
	newKey, err := crypto.GetKey(newKeyVersion)
	if err != nil {
		// This is bad - rotation happened but we can't get the new key.
		// Main DB tx will rollback. Backups exist. Manual intervention likely needed.
		return fmt.Errorf("failed to get new key (version %d) after rotation: %w", newKeyVersion, err)
	}

	// Re-encrypt all sensitive data using old and new keys
	reencryptedFields := make(map[string]string)
	fieldsToReencrypt := []struct {
		name string
		val  string
	}{
		{"username_encrypted_pwd", fullUser.UsernameEncryptedPwd},
		{"seed_encrypted", fullUser.SeedEncrypted},
		{"public_key_encrypted", fullUser.PublicKeyEncrypted},
		{"private_key_encrypted", fullUser.PrivateKeyEncrypted},
		{"two_fa_secret_encrypted", fullUser.TwoFASecretEncrypted},
	}

	for _, field := range fieldsToReencrypt {
		if field.val != "" {
			// Pass the correct old key version to the audit logger if needed
			reencrypted, err := crypto.ReencryptData(field.val, oldKey, newKey, db.DefaultCryptoAuditLogger, &user.ID)
			if err != nil {
				// Re-encryption failed. Rollback transaction. Backups exist.
				// No need to call restoreFromBackup here as the transaction handles atomicity.
				return fmt.Errorf("failed to re-encrypt field %s: %w", field.name, err)
			}
			reencryptedFields[field.name] = reencrypted
		} else {
			reencryptedFields[field.name] = "" // Ensure map entry exists even if empty
		}
	}

	// Update user record with new key version and re-encrypted data
	_, err = tx.Exec(`
		UPDATE users 
		SET key_version = ?, 
			last_rotated_at = CURRENT_TIMESTAMP,
			last_reencrypted_at = CURRENT_TIMESTAMP,
			username_encrypted_pwd = ?,
			seed_encrypted = ?,
			public_key_encrypted = ?,
			private_key_encrypted = ?,
			two_fa_secret_encrypted = ?
		WHERE id = ?`,
		newKeyVersion, // Use the new key version
		reencryptedFields["username_encrypted_pwd"],
		reencryptedFields["seed_encrypted"],
		reencryptedFields["public_key_encrypted"],
		reencryptedFields["private_key_encrypted"],
		reencryptedFields["two_fa_secret_encrypted"],
		user.ID)
	if err != nil {
		return err
	}

	// Commit the main DB transaction
	if err = tx.Commit(); err != nil {
		// Commit failed. Backups still exist. Manual intervention might be needed.
		rollback = false // Prevent redundant rollback call
		return fmt.Errorf("failed to commit transaction after re-encryption: %w", err)
	}
	rollback = false // Commit succeeded

	// Log rotation success (using main DB connection, outside transaction)
	// Consider moving audit logging to use Admin DB if appropriate
	if crypto.AuditCryptoOperations() {
		if err := rs.logRotationSuccess(user.ID, newKeyVersion); err != nil { // Corrected: user.ID
			// Log the error but don't fail the whole rotation
			log.Printf("Warning: Failed to log successful rotation for user %d: %v", user.ID, err) // Corrected: user.ID
		}
	}

	log.Printf("Successfully rotated keys for user %d to version %d (operation: %s)", user.ID, newKeyVersion, operationID)
	return nil
}

// restoreFromBackup is likely no longer needed as transaction rollback handles atomicity.
// If explicit restore logic is ever required, it needs careful implementation
// to coordinate between main DB and backup DB.

// logRotationSuccess logs a successful rotation event.
// Note: This now uses the main DB connection directly, not the transaction.
func (rs *RotationService) logRotationSuccess(userID int, newKeyVersion int) error {
	_, err := rs.DB.Exec(`
		INSERT INTO crypto_audit_log (
			operation, 
			key_version, 
			user_id, 
			status, 
			created_at
		) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		"key_rotation",
		newKeyVersion, // Log the version rotated *to*
		userID,
		"success") // Log status
	return err
}
