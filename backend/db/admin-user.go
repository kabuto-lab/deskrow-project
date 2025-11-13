package db

import (
	"database/sql"
	"errors" // Ensure errors is imported
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type AdminUser struct {
	ID           int
	Username     string
	PasswordHash string
	Email        string
	FullName     string
	IsSuperAdmin bool
	IsActive     bool
	LastLogin    *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// ErrAdminUserNotFound is returned when an admin user is not found.
var ErrAdminUserNotFound = errors.New("admin user not found")

type AdminRole struct {
	ID          int
	Name        string
	Description string
	CreatedAt   time.Time
}

type AdminPermission struct {
	ID          int
	Name        string
	Description string
	CreatedAt   time.Time
}

// CreateAdminUser adds a new admin user to the database.
// It now requires an AdminDatabase instance.
func (adb *AdminDatabase) CreateAdminUser(username, password, email, fullName string, isSuperAdmin bool) (*AdminUser, error) {
	if adb == nil || adb.db == nil {
		return nil, fmt.Errorf("admin database connection is nil")
	}

	if username == "" || password == "" || email == "" {
		return nil, fmt.Errorf("username, password and email are required")
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	result, err := adb.db.Exec(
		"INSERT INTO admin_users (username, password_hash, email, full_name, is_super_admin) VALUES (?, ?, ?, ?, ?)",
		username, string(passwordHash), email, fullName, isSuperAdmin,
	)
	if err != nil {
		log.Printf("Database error creating admin user: %v", err)
		if err.Error() == "UNIQUE constraint failed: admin_users.username" {
			return nil, fmt.Errorf("username already exists")
		}
		if err.Error() == "UNIQUE constraint failed: admin_users.email" {
			return nil, fmt.Errorf("email already exists")
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert ID: %w", err)
	}

	return &AdminUser{
		ID:           int(id),
		Username:     username,
		PasswordHash: string(passwordHash),
		Email:        email,
		FullName:     fullName,
		IsSuperAdmin: isSuperAdmin,
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}, nil
}

// GetAdminUserByID retrieves an admin user by their ID.
func (adb *AdminDatabase) GetAdminUserByID(id int) (*AdminUser, error) {
	if adb == nil || adb.db == nil {
		return nil, fmt.Errorf("admin database connection is nil")
	}
	var user AdminUser
	err := adb.db.QueryRow(
		"SELECT id, username, password_hash, email, full_name, is_super_admin, is_active, last_login, created_at, updated_at FROM admin_users WHERE id = ?",
		id,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Email, &user.FullName, &user.IsSuperAdmin, &user.IsActive, &user.LastLogin, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAdminUserNotFound // Return specific error
		}
		return nil, fmt.Errorf("database error querying admin user by ID: %w", err) // Wrap other errors
	}

	return &user, nil
}

// GetAdminUserByUsername retrieves an admin user by their username.
func (adb *AdminDatabase) GetAdminUserByUsername(username string) (*AdminUser, error) {
	if adb == nil || adb.db == nil {
		return nil, fmt.Errorf("admin database connection is nil")
	}
	var user AdminUser
	err := adb.db.QueryRow(
		"SELECT id, username, password_hash, email, full_name, is_super_admin, is_active, last_login, created_at, updated_at FROM admin_users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Email, &user.FullName, &user.IsSuperAdmin, &user.IsActive, &user.LastLogin, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAdminUserNotFound // Return specific error
		}
		return nil, fmt.Errorf("database error querying admin user by username: %w", err) // Wrap other errors
	}

	return &user, nil
}

// AuthenticateAdminUser verifies admin credentials.
func (adb *AdminDatabase) AuthenticateAdminUser(username, password string) (*AdminUser, error) {
	if adb == nil || adb.db == nil {
		log.Println("Authentication failed: admin database connection is nil")
		return nil, fmt.Errorf("admin database connection is nil")
	}
	if username == "" || password == "" {
		log.Println("Authentication failed: empty username or password")
		return nil, fmt.Errorf("username and password are required")
	}

	log.Printf("Looking up admin user '%s'", username)
	user, err := adb.GetAdminUserByUsername(username)
	if err != nil {
		log.Printf("User lookup failed for '%s': %v", username, err)
		return nil, fmt.Errorf("authentication error: %w", err)
	}
	if user == nil {
		log.Printf("User '%s' not found", username)
		return nil, fmt.Errorf("invalid credentials")
	}

	if !user.IsActive {
		log.Printf("User '%s' is inactive", username)
		return nil, fmt.Errorf("account is inactive")
	}

	log.Printf("Verifying password for user '%s'", username)
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		log.Printf("Password verification failed for user '%s': %v (stored hash: %s)", username, err, user.PasswordHash)
		return nil, fmt.Errorf("invalid credentials")
	}

	log.Printf("Successfully authenticated user '%s'", username)

	// Update last login time
	_, err = adb.db.Exec( // Use adb.db
		"UPDATE admin_users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
		user.ID,
	)
	if err != nil {
		log.Printf("Failed to update last login time: %v", err)
	}

	return user, nil
}

// UpdateAdminUserPassword updates the password for a given admin user ID.
func (adb *AdminDatabase) UpdateAdminUserPassword(id int, newPassword string) error {
	if adb == nil || adb.db == nil {
		return fmt.Errorf("admin database connection is nil")
	}

	if newPassword == "" {
		return fmt.Errorf("new password is required")
	}

	// Hash new password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), 14)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	_, err = adb.db.Exec( // Use adb.db
		"UPDATE admin_users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		string(passwordHash), id,
	)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// CreateAdminRole adds a new admin role.
func (adb *AdminDatabase) CreateAdminRole(name, description string) (*AdminRole, error) {
	if adb == nil || adb.db == nil {
		return nil, fmt.Errorf("admin database connection is nil")
	}

	if name == "" {
		return nil, fmt.Errorf("role name is required")
	}

	result, err := adb.db.Exec( // Use adb.db
		"INSERT INTO admin_roles (name, description) VALUES (?, ?)",
		name, description,
	)
	if err != nil {
		if err.Error() == "UNIQUE constraint failed: admin_roles.name" {
			return nil, fmt.Errorf("role name already exists")
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert ID: %w", err)
	}

	return &AdminRole{
		ID:          int(id),
		Name:        name,
		Description: description,
		CreatedAt:   time.Now(),
	}, nil
}

// GetAdminRoleByID retrieves an admin role by ID.
func (adb *AdminDatabase) GetAdminRoleByID(id int) (*AdminRole, error) {
	if adb == nil || adb.db == nil {
		return nil, fmt.Errorf("admin database connection is nil")
	}
	var role AdminRole
	err := adb.db.QueryRow( // Use adb.db
		"SELECT id, name, description, created_at FROM admin_roles WHERE id = ?",
		id,
	).Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &role, nil
}

// CreateAdminPermission adds a new admin permission.
func (adb *AdminDatabase) CreateAdminPermission(name, description string) (*AdminPermission, error) {
	if adb == nil || adb.db == nil {
		return nil, fmt.Errorf("admin database connection is nil")
	}

	if name == "" {
		return nil, fmt.Errorf("permission name is required")
	}

	result, err := adb.db.Exec( // Use adb.db
		"INSERT INTO admin_permissions (name, description) VALUES (?, ?)",
		name, description,
	)
	if err != nil {
		if err.Error() == "UNIQUE constraint failed: admin_permissions.name" {
			return nil, fmt.Errorf("permission name already exists")
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert ID: %w", err)
	}

	return &AdminPermission{
		ID:          int(id),
		Name:        name,
		Description: description,
		CreatedAt:   time.Now(),
	}, nil
}

// GetAdminPermissionByID retrieves an admin permission by ID.
func (adb *AdminDatabase) GetAdminPermissionByID(id int) (*AdminPermission, error) {
	if adb == nil || adb.db == nil {
		return nil, fmt.Errorf("admin database connection is nil")
	}
	var perm AdminPermission
	err := adb.db.QueryRow( // Use adb.db
		"SELECT id, name, description, created_at FROM admin_permissions WHERE id = ?",
		id,
	).Scan(&perm.ID, &perm.Name, &perm.Description, &perm.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &perm, nil
}

// AssignRoleToAdminUser assigns a role to a user.
func (adb *AdminDatabase) AssignRoleToAdminUser(userID, roleID int) error {
	if adb == nil || adb.db == nil {
		return fmt.Errorf("admin database connection is nil")
	}

	_, err := adb.db.Exec( // Use adb.db
		"INSERT INTO admin_user_roles (user_id, role_id) VALUES (?, ?)",
		userID, roleID,
	)
	if err != nil {
		if err.Error() == "FOREIGN KEY constraint failed" {
			return fmt.Errorf("invalid user or role ID")
		}
		if err.Error() == "UNIQUE constraint failed: admin_user_roles.user_id, admin_user_roles.role_id" {
			return fmt.Errorf("user already has this role")
		}
		return fmt.Errorf("database error: %w", err)
	}

	return nil
}

// AssignPermissionToAdminRole assigns a permission to a role.
func (adb *AdminDatabase) AssignPermissionToAdminRole(roleID, permissionID int) error {
	if adb == nil || adb.db == nil {
		return fmt.Errorf("admin database connection is nil")
	}

	_, err := adb.db.Exec( // Use adb.db
		"INSERT INTO admin_role_permissions (role_id, permission_id) VALUES (?, ?)",
		roleID, permissionID,
	)
	if err != nil {
		if err.Error() == "FOREIGN KEY constraint failed" {
			return fmt.Errorf("invalid role or permission ID")
		}
		if err.Error() == "UNIQUE constraint failed: admin_role_permissions.role_id, admin_role_permissions.permission_id" {
			return fmt.Errorf("role already has this permission")
		}
		return fmt.Errorf("database error: %w", err)
	}

	return nil
}

// LogAdminActivity logs an action performed by an admin user.
func (adb *AdminDatabase) LogAdminActivity(userID int, action, entityType string, entityID *int, ipAddress, userAgent, metadata string) error {
	if adb == nil || adb.db == nil {
		return fmt.Errorf("admin database connection is nil")
	}

	var entityIDVal sql.NullInt64
	if entityID != nil {
		entityIDVal = sql.NullInt64{Int64: int64(*entityID), Valid: true}
	}

	_, err := adb.db.Exec( // Use adb.db
		"INSERT INTO admin_activity_logs (user_id, action, entity_type, entity_id, ip_address, user_agent, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)",
		userID, action, entityType, entityIDVal, ipAddress, userAgent, metadata,
	)
	if err != nil {
		return fmt.Errorf("failed to log activity: %w", err)
	}

	return nil
}
