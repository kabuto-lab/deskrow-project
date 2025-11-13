package db

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"
)

const adminDbPath = "data/admin.db" // Define the path for the admin database

// AdminDatabase handles operations specific to the admin database (e.g., keys, logs).
type AdminDatabase struct {
	db *sql.DB
	mu sync.Mutex
}

// NewAdminDatabase creates and initializes a new AdminDatabase instance.
func NewAdminDatabase() *AdminDatabase {
	// Ensure data directory exists
	if err := os.MkdirAll("data", 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	db, err := sql.Open("sqlite", adminDbPath+"?_journal_mode=WAL")
	if err != nil {
		log.Fatalf("Failed to open admin database: %v", err)
	}

	adminDB := &AdminDatabase{db: db}
	if err := adminDB.initSchema(); err != nil {
		log.Fatalf("Failed to initialize admin database schema: %v", err)
	}

	log.Println("Admin database initialized successfully at", adminDbPath)
	return adminDB
}

// initSchema creates the necessary tables if they don't exist.
func (adb *AdminDatabase) initSchema() error {
	adb.mu.Lock()
	defer adb.mu.Unlock()

	// Schema for admin users, sessions, and audit logs. Keys/Secrets are in secrets.db
	schema := `
	CREATE TABLE IF NOT EXISTS admin_users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		email TEXT UNIQUE NOT NULL,
		full_name TEXT,
		is_super_admin BOOLEAN DEFAULT FALSE,
		is_active BOOLEAN DEFAULT TRUE,
		last_login TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS admin_sessions (
		session_token TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		expires_at TIMESTAMP NOT NULL,
		last_accessed_at TIMESTAMP,
		ip_address TEXT,
		user_agent TEXT,
		FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_admin_sessions_user_id ON admin_sessions (user_id);
	CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at ON admin_sessions (expires_at);

	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		actor TEXT,
		action TEXT NOT NULL,
		details TEXT
	);

	CREATE TABLE IF NOT EXISTS admin_roles (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		description TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS admin_user_roles (
		user_id INTEGER NOT NULL,
		role_id INTEGER NOT NULL,
		assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (user_id, role_id),
		FOREIGN KEY (user_id) REFERENCES admin_users(id) ON DELETE CASCADE,
		FOREIGN KEY (role_id) REFERENCES admin_roles(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS admin_role_permissions (
		role_id INTEGER NOT NULL,
		permission TEXT NOT NULL,
		granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (role_id, permission),
		FOREIGN KEY (role_id) REFERENCES admin_roles(id) ON DELETE CASCADE
	);
	`
	_, err := adb.db.Exec(schema)
	return err
}

// Close closes the admin database connection.
func (adb *AdminDatabase) Close() error {
	adb.mu.Lock()
	defer adb.mu.Unlock()
	if adb.db != nil {
		log.Println("Closing admin database connection.")
		return adb.db.Close()
	}
	return nil
}

// StoreLog inserts a log entry into the audit_logs table.
// Currently stores the raw string; consider parsing structured logs (e.g., JSON).
func (adb *AdminDatabase) StoreLog(logEntry string) error {
	adb.mu.Lock()
	defer adb.mu.Unlock()

	// Simple insertion of the raw log message
	_, err := adb.db.Exec(`
		INSERT INTO audit_logs (action, details, actor) 
		VALUES (?, ?, ?)`,
		"LOG_RECEIVED", // Action type
		logEntry,       // Raw log message as details
		"System",       // Actor (assuming system logs for now)
	)
	if err != nil {
		log.Printf("AdminDB: Failed to store log: %v", err)
		return fmt.Errorf("failed to insert log into admin DB: %w", err)
	}
	return nil
}

// VerifyAdminSession checks if a session token is valid and returns the associated user ID.
// TODO: Ensure admin_sessions table exists in admin.db schema
func (adb *AdminDatabase) VerifyAdminSession(token string) (int, error) {
	adb.mu.Lock() // Lock if necessary, though QueryRow is generally safe for concurrent reads
	defer adb.mu.Unlock()

	var userID int
	err := adb.db.QueryRow(
		"SELECT user_id FROM admin_sessions WHERE session_token = ? AND expires_at > CURRENT_TIMESTAMP",
		token,
	).Scan(&userID)

	if err != nil {
		// Consider logging the specific error here
		// Return a more generic error or sql.ErrNoRows if appropriate
		return 0, err // Return the original error (could be sql.ErrNoRows)
	}

	return userID, nil
}

// --- Admin Session Management ---

// CreateAdminSession creates a new session token for an admin user.
func (adb *AdminDatabase) CreateAdminSession(userID int, duration time.Duration) (string, error) {
	adb.mu.Lock()
	defer adb.mu.Unlock()

	// Generate secure random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate session token bytes: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)
	expiresAt := time.Now().Add(duration)

	_, err := adb.db.Exec(`
		INSERT INTO admin_sessions (session_token, user_id, expires_at, last_accessed_at) 
		VALUES (?, ?, ?, ?)`,
		token, userID, expiresAt, time.Now(),
	)
	if err != nil {
		log.Printf("AdminDB: Failed to insert admin session: %v", err)
		return "", fmt.Errorf("failed to create admin session: %w", err)
	}
	return token, nil
}

// ValidateAdminSession checks if a session token is valid and returns the user ID.
// It also updates the last_accessed_at timestamp.
func (adb *AdminDatabase) ValidateAdminSession(token string) (int, error) {
	adb.mu.Lock() // Potentially needs finer-grained locking or WAL mode benefits
	defer adb.mu.Unlock()

	var userID int
	var expiresAt time.Time

	err := adb.db.QueryRow(`
		SELECT user_id, expires_at 
		FROM admin_sessions 
		WHERE session_token = ?`,
		token,
	).Scan(&userID, &expiresAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("session not found")
		}
		log.Printf("AdminDB: Error querying session token: %v", err)
		return 0, fmt.Errorf("error validating session: %w", err)
	}

	if time.Now().After(expiresAt) {
		// Optional: Clean up expired session here or in a separate job
		// adb.db.Exec("DELETE FROM admin_sessions WHERE session_token = ?", token)
		return 0, fmt.Errorf("session expired")
	}

	// Update last accessed time (best effort)
	_, updateErr := adb.db.Exec(`
		UPDATE admin_sessions 
		SET last_accessed_at = ? 
		WHERE session_token = ?`,
		time.Now(), token,
	)
	if updateErr != nil {
		log.Printf("AdminDB: Failed to update session last_accessed_at: %v", updateErr)
		// Don't fail validation just because timestamp update failed
	}

	return userID, nil
}

// DeleteAdminSession removes a session token from the database (logout).
func (adb *AdminDatabase) DeleteAdminSession(token string) error {
	adb.mu.Lock()
	defer adb.mu.Unlock()

	_, err := adb.db.Exec("DELETE FROM admin_sessions WHERE session_token = ?", token)
	if err != nil {
		log.Printf("AdminDB: Failed to delete session token: %v", err)
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// GetAdminUserRoles returns all role names for a given admin user.
func (adb *AdminDatabase) GetAdminUserRoles(userID int) ([]string, error) {
	adb.mu.Lock()
	defer adb.mu.Unlock()

	rows, err := adb.db.Query(`
		SELECT r.name 
		FROM admin_roles r
		JOIN admin_user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = ?`,
		userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user roles: %w", err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating roles: %w", err)
	}

	return roles, nil
}

// GetAdminRolePermissions returns all permissions for a given role.
func (adb *AdminDatabase) GetAdminRolePermissions(role string) ([]string, error) {
	adb.mu.Lock()
	defer adb.mu.Unlock()

	rows, err := adb.db.Query(`
		SELECT rp.permission
		FROM admin_role_permissions rp
		JOIN admin_roles r ON rp.role_id = r.id
		WHERE r.name = ?`,
		role)
	if err != nil {
		return nil, fmt.Errorf("failed to query role permissions: %w", err)
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, perm)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permissions: %w", err)
	}

	return permissions, nil
}

// GetAdminUserCount returns the total number of admin users.
func (adb *AdminDatabase) GetAdminUserCount() (int, error) {
	adb.mu.Lock()
	defer adb.mu.Unlock()

	var count int
	err := adb.db.QueryRow("SELECT COUNT(*) FROM admin_users").Scan(&count)
	if err != nil {
		log.Printf("AdminDB: Error counting admin users: %v", err)
		return 0, fmt.Errorf("failed to count admin users: %w", err)
	}
	return count, nil
}

// ensureDefaultAdminUser updates or creates the default admin user with current credentials
func ensureDefaultAdminUser(adb *AdminDatabase) error {
	if adb.db == nil {
		return fmt.Errorf("admin database connection is nil")
	}

	username := os.Getenv("DEFAULT_ADMIN_USERNAME")
	password := os.Getenv("DEFAULT_ADMIN_PASSWORD")
	if username == "" || password == "" {
		return fmt.Errorf("default admin credentials not set in .env")
	}

	// Check if user already exists
	existingUser, err := adb.GetAdminUserByUsername(username)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to check for existing admin user: %w", err)
	}

	if existingUser != nil {
		// Update existing user's password
		log.Printf("Updating password for existing admin user: %s", username)
		err := bcrypt.CompareHashAndPassword([]byte(existingUser.PasswordHash), []byte(password))
		if err != nil {
			// Only update if password changed
			err = adb.UpdateAdminUserPassword(existingUser.ID, password)
			if err != nil {
				return fmt.Errorf("failed to update admin user password: %w", err)
			}
			log.Printf("Successfully updated password for admin user: %s", username)
		} else {
			log.Printf("Admin user %s already has current password", username)
		}
	} else {
		// Create new admin user
		log.Printf("Creating new admin user: %s", username)
		_, err := adb.CreateAdminUser(
			username,
			password,
			username+"@example.com",
			"Default Admin",
			true,
		)
		if err != nil {
			return fmt.Errorf("failed to create admin user: %w", err)
		}
		log.Printf("Successfully created admin user: %s", username)
	}
	return nil
}

// NOTE: Admin user related methods are now in admin-user.go
