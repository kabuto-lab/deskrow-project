package middleware

import (
	"context"
	"deskrow/db"
	"fmt"
	"net/http"
	"strings"
)

// contextKey is a custom type to avoid context key collisions.
type contextKey string

const (
	adminUserKey        contextKey = "adminUser"
	adminPermissionsKey contextKey = "adminPermissions"
)

// contextWithAdminUser stores the admin user in the context.
func contextWithAdminUser(ctx context.Context, user *db.AdminUser) context.Context {
	return context.WithValue(ctx, adminUserKey, user)
}

// AdminUserFromContext retrieves the admin user from the context.
func AdminUserFromContext(ctx context.Context) *db.AdminUser {
	if user, ok := ctx.Value(adminUserKey).(*db.AdminUser); ok {
		return user
	}
	return nil
}

// contextWithAdminPermissions stores the admin permissions in the context.
func contextWithAdminPermissions(ctx context.Context, permissions map[string]bool) context.Context {
	return context.WithValue(ctx, adminPermissionsKey, permissions)
}

// AdminPermissionsFromContext retrieves the admin permissions from the context.
func AdminPermissionsFromContext(ctx context.Context) map[string]bool {
	if perms, ok := ctx.Value(adminPermissionsKey).(map[string]bool); ok {
		return perms
	}
	return nil
}

// RequirePermission creates middleware that checks for a specific permission
func RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			adminUser := AdminUserFromContext(r.Context())
			if adminUser == nil {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			if adminUser.IsSuperAdmin {
				next.ServeHTTP(w, r)
				return
			}

			permissions, ok := r.Context().Value(adminPermissionsKey).(map[string]bool)
			if !ok || !permissions[permission] {
				http.Error(w, "Insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Remove duplicate type and constant declarations
// type contextKey string
// const adminUserKey contextKey = "adminUser"
// const adminPermissionsKey contextKey = "adminPermissions"

// AdminAuthMiddleware creates an authentication middleware that uses the provided AdminDatabase.
func AdminAuthMiddleware(adb *db.AdminDatabase) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if adb == nil {
				http.Error(w, "Admin database not configured for middleware", http.StatusInternalServerError)
				return
			}

			// Get session token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			// Expecting "Bearer <token>"
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
				return
			}
			token := parts[1]

			// Verify session token in admin database
			userID, err := adb.VerifyAdminSession(token)
			if err != nil {
				http.Error(w, "Invalid or expired session token", http.StatusUnauthorized)
				return
			}

			// Get admin user details
			adminUser, err := adb.GetAdminUserByID(userID)
			if err != nil || adminUser == nil {
				http.Error(w, "Admin user not found", http.StatusUnauthorized)
				return
			}

			if !adminUser.IsActive {
				http.Error(w, "Admin account is inactive", http.StatusForbidden)
				return
			}

			// Get user roles and permissions
			roles, err := adb.GetAdminUserRoles(userID)
			if err != nil {
				http.Error(w, "Failed to load user roles", http.StatusInternalServerError)
				return
			}

			permissions := make(map[string]bool)
			for _, role := range roles {
				rolePerms, err := adb.GetAdminRolePermissions(role)
				if err != nil {
					http.Error(w, "Failed to load role permissions", http.StatusInternalServerError)
					return
				}
				for _, perm := range rolePerms {
					permissions[perm] = true
				}
			}

			// Add admin user and permissions to request context
			ctx := r.Context()
			ctx = contextWithAdminUser(ctx, adminUser)
			ctx = contextWithAdminPermissions(ctx, permissions)
			r = r.WithContext(ctx)

			// Log the request
			go func() {
				_ = adb.LogAdminActivity(
					adminUser.ID,
					"api_request",
					"admin",
					nil,
					r.RemoteAddr,
					r.UserAgent(),
					fmt.Sprintf("%s %s", r.Method, r.URL.Path),
				)
			}()

			next.ServeHTTP(w, r)
		})
	}
}
