package auth

import (
	"fmt"
	"testing"
)

func TestNewAuthManager(t *testing.T) {
	// Test creation with default configuration
	am, err := NewAuthManager(nil)
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	if am.config.HashMethod != "argon2" {
		t.Errorf("Expected hash method argon2, got %s", am.config.HashMethod)
	}

	if am.config.SessionTimeout != 3600 {
		t.Errorf("Expected session timeout 3600, got %d", am.config.SessionTimeout)
	}
}

func TestNewAuthManagerWithMFA(t *testing.T) {
	config := DefaultAuthConfig()
	config.EnableMFA = true
	config.MFA = &MFAConfig{
		Enabled:     true,
		TOTPEnabled: true,
		Issuer:      "Test GoVPN",
	}

	am, err := NewAuthManager(config)
	if err != nil {
		t.Fatalf("Failed to create AuthManager with MFA: %v", err)
	}

	if am.mfaProvider == nil {
		t.Error("MFA provider should not be nil")
	}
}

func TestCreateUser(t *testing.T) {
	am, err := NewAuthManager(DefaultAuthConfig())
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	username := "testuser"
	password := "testpassword123"

	user, err := am.CreateUser(username, password)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	if user.Username != username {
		t.Errorf("Expected username %s, got %s", username, user.Username)
	}

	if user.Source != "local" {
		t.Errorf("Expected source 'local', got %s", user.Source)
	}

	if !user.IsActive {
		t.Error("User should be active by default")
	}

	if len(user.Roles) != 1 || user.Roles[0] != "user" {
		t.Errorf("Expected roles [user], got %v", user.Roles)
	}
}

func TestCreateUserDuplicate(t *testing.T) {
	am, err := NewAuthManager(DefaultAuthConfig())
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	username := "testuser"
	password := "testpassword123"

	// Create first user
	_, err = am.CreateUser(username, password)
	if err != nil {
		t.Fatalf("Failed to create first user: %v", err)
	}

	// Attempt to create duplicate
	_, err = am.CreateUser(username, password)
	if err == nil {
		t.Error("Expected error when creating duplicate user")
	}
}

func TestAuthenticateUser(t *testing.T) {
	am, err := NewAuthManager(DefaultAuthConfig())
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	username := "testuser"
	password := "testpassword123"

	// Create user
	_, err = am.CreateUser(username, password)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Authenticate with correct password
	result, err := am.AuthenticateUser(username, password)
	if err != nil {
		t.Fatalf("Failed to authenticate user: %v", err)
	}

	if result.User.Username != username {
		t.Errorf("Expected username %s, got %s", username, result.User.Username)
	}

	if result.Source != "local" {
		t.Errorf("Expected source 'local', got %s", result.Source)
	}

	if result.RequiresMFA {
		t.Error("MFA should not be required for basic auth")
	}
}

func TestAuthenticateUserWrongPassword(t *testing.T) {
	am, err := NewAuthManager(DefaultAuthConfig())
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	username := "testuser"
	password := "testpassword123"
	wrongPassword := "wrongpassword"

	// Create user
	_, err = am.CreateUser(username, password)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Authenticate with wrong password
	_, err = am.AuthenticateUser(username, wrongPassword)
	if err == nil {
		t.Error("Expected error when authenticating with wrong password")
	}
}

func TestAuthenticateNonExistentUser(t *testing.T) {
	am, err := NewAuthManager(DefaultAuthConfig())
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	// Authenticate non-existent user
	_, err = am.AuthenticateUser("nonexistent", "password")
	if err == nil {
		t.Error("Expected error when authenticating non-existent user")
	}
}

func TestAuthenticateInactiveUser(t *testing.T) {
	am, err := NewAuthManager(DefaultAuthConfig())
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	username := "testuser"
	password := "testpassword123"

	// Create user
	_, err = am.CreateUser(username, password)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Deactivate user
	err = am.SetUserActive(username, false)
	if err != nil {
		t.Fatalf("Failed to deactivate user: %v", err)
	}

	// Authenticate inactive user
	_, err = am.AuthenticateUser(username, password)
	if err == nil {
		t.Error("Expected error when authenticating inactive user")
	}
}

func TestUpdatePassword(t *testing.T) {
	am, err := NewAuthManager(DefaultAuthConfig())
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	username := "testuser"
	oldPassword := "oldpassword123"
	newPassword := "newpassword456"

	// Create user
	_, err = am.CreateUser(username, oldPassword)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Update password
	err = am.UpdatePassword(username, newPassword)
	if err != nil {
		t.Fatalf("Failed to update password: %v", err)
	}

	// Verify old password doesn't work
	_, err = am.AuthenticateUser(username, oldPassword)
	if err == nil {
		t.Error("Old password should not work after update")
	}

	// Verify new password works
	_, err = am.AuthenticateUser(username, newPassword)
	if err != nil {
		t.Errorf("New password should work: %v", err)
	}
}

func TestUserRoles(t *testing.T) {
	am, err := NewAuthManager(DefaultAuthConfig())
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	username := "testuser"
	password := "testpassword123"

	// Create user
	_, err = am.CreateUser(username, password)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Add role
	err = am.AddUserRole(username, "admin")
	if err != nil {
		t.Fatalf("Failed to add role: %v", err)
	}

	user, exists := am.GetUser(username)
	if !exists {
		t.Fatal("User should exist")
	}

	hasRole := false
	for _, role := range user.Roles {
		if role == "admin" {
			hasRole = true
			break
		}
	}
	if !hasRole {
		t.Error("User should have admin role")
	}

	// Remove role
	err = am.RemoveUserRole(username, "admin")
	if err != nil {
		t.Fatalf("Failed to remove role: %v", err)
	}

	user, _ = am.GetUser(username)
	hasRole = false
	for _, role := range user.Roles {
		if role == "admin" {
			hasRole = true
			break
		}
	}
	if hasRole {
		t.Error("User should not have admin role after removal")
	}
}

func TestDeleteUser(t *testing.T) {
	am, err := NewAuthManager(DefaultAuthConfig())
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	username := "testuser"
	password := "testpassword123"

	// Create user
	_, err = am.CreateUser(username, password)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Verify user exists
	_, exists := am.GetUser(username)
	if !exists {
		t.Error("User should exist before deletion")
	}

	// Delete user
	err = am.DeleteUser(username)
	if err != nil {
		t.Fatalf("Failed to delete user: %v", err)
	}

	// Verify user doesn't exist
	_, exists = am.GetUser(username)
	if exists {
		t.Error("User should not exist after deletion")
	}
}

func TestListUsers(t *testing.T) {
	am, err := NewAuthManager(DefaultAuthConfig())
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	// Create several users
	users := []string{"user1", "user2", "user3"}
	for _, username := range users {
		_, err = am.CreateUser(username, "password123")
		if err != nil {
			t.Fatalf("Failed to create user %s: %v", username, err)
		}
	}

	// Get list of all users
	userList := am.ListUsers()

	if len(userList) != len(users) {
		t.Errorf("Expected %d users, got %d", len(users), len(userList))
	}

	for _, username := range users {
		if _, exists := userList[username]; !exists {
			t.Errorf("User %s should be in the list", username)
		}
	}
}

func TestMFAIntegration(t *testing.T) {
	config := DefaultAuthConfig()
	config.EnableMFA = true
	config.MFA = &MFAConfig{
		Enabled:     true,
		TOTPEnabled: true,
		Issuer:      "Test GoVPN",
	}

	am, err := NewAuthManager(config)
	if err != nil {
		t.Fatalf("Failed to create AuthManager with MFA: %v", err)
	}

	username := "testuser"

	// Check MFA status (should be disabled)
	status := am.GetMFAStatus(username)
	if status["enabled"].(bool) {
		t.Error("MFA should be disabled initially")
	}

	// Setup MFA
	totpData, err := am.SetupMFA(username, username+"@example.com")
	if err != nil {
		t.Fatalf("Failed to setup MFA: %v", err)
	}

	if totpData.Secret == "" {
		t.Error("TOTP secret should not be empty")
	}

	if len(totpData.BackupCodes) == 0 {
		t.Error("Backup codes should be generated")
	}
}

func TestPasswordHashing(t *testing.T) {
	// Test Argon2
	configArgon2 := DefaultAuthConfig()
	configArgon2.HashMethod = "argon2"

	am, err := NewAuthManager(configArgon2)
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	password := "testpassword123"
	salt, err := am.generateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	hash1, err := am.hashPassword(password, salt)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	hash2, err := am.hashPassword(password, salt)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	if hash1 != hash2 {
		t.Error("Same password and salt should produce same hash")
	}

	// Verify password validation
	if !am.verifyPassword(password, hash1, salt) {
		t.Error("Password verification should succeed")
	}

	if am.verifyPassword("wrongpassword", hash1, salt) {
		t.Error("Wrong password verification should fail")
	}

	// Test PBKDF2
	configPBKDF2 := DefaultAuthConfig()
	configPBKDF2.HashMethod = "pbkdf2"

	am2, err := NewAuthManager(configPBKDF2)
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	hash3, err := am2.hashPassword(password, salt)
	if err != nil {
		t.Fatalf("Failed to hash password with PBKDF2: %v", err)
	}

	if !am2.verifyPassword(password, hash3, salt) {
		t.Error("PBKDF2 password verification should succeed")
	}

	// Hashes of different algorithms should be different
	if hash1 == hash3 {
		t.Error("Argon2 and PBKDF2 should produce different hashes")
	}
}

func TestUnsupportedHashMethod(t *testing.T) {
	config := DefaultAuthConfig()
	config.HashMethod = "unsupported"

	am, err := NewAuthManager(config)
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	username := "testuser"
	password := "testpassword123"

	// Creating user with unsupported hash algorithm should fail
	_, err = am.CreateUser(username, password)
	if err == nil {
		t.Error("Expected error when using unsupported hash method")
	}
}

func TestConcurrentOperations(t *testing.T) {
	am, err := NewAuthManager(DefaultAuthConfig())
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	// Create users concurrently
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			username := fmt.Sprintf("user%d", id)
			password := "password123"

			_, err := am.CreateUser(username, password)
			if err != nil {
				t.Errorf("Failed to create user %s: %v", username, err)
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all users were created
	users := am.ListUsers()
	if len(users) != 10 {
		t.Errorf("Expected 10 users, got %d", len(users))
	}
}

func BenchmarkHashPassword(b *testing.B) {
	am, err := NewAuthManager(DefaultAuthConfig())
	if err != nil {
		b.Fatalf("Failed to create AuthManager: %v", err)
	}

	password := "testpassword123"
	salt, err := am.generateSalt()
	if err != nil {
		b.Fatalf("Failed to generate salt: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := am.hashPassword(password, salt)
		if err != nil {
			b.Fatalf("Failed to hash password: %v", err)
		}
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	am, err := NewAuthManager(DefaultAuthConfig())
	if err != nil {
		b.Fatalf("Failed to create AuthManager: %v", err)
	}

	password := "testpassword123"
	salt, err := am.generateSalt()
	if err != nil {
		b.Fatalf("Failed to generate salt: %v", err)
	}

	hash, err := am.hashPassword(password, salt)
	if err != nil {
		b.Fatalf("Failed to hash password: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		am.verifyPassword(password, hash, salt)
	}
}

func BenchmarkCreateUser(b *testing.B) {
	am, err := NewAuthManager(DefaultAuthConfig())
	if err != nil {
		b.Fatalf("Failed to create AuthManager: %v", err)
	}

	password := "testpassword123"

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		username := fmt.Sprintf("user%d", i)
		_, err := am.CreateUser(username, password)
		if err != nil {
			b.Fatalf("Failed to create user: %v", err)
		}
	}
}

func BenchmarkAuthenticateUser(b *testing.B) {
	am, err := NewAuthManager(DefaultAuthConfig())
	if err != nil {
		b.Fatalf("Failed to create AuthManager: %v", err)
	}

	username := "testuser"
	password := "testpassword123"

	_, err = am.CreateUser(username, password)
	if err != nil {
		b.Fatalf("Failed to create user: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := am.AuthenticateUser(username, password)
		if err != nil {
			b.Fatalf("Failed to authenticate user: %v", err)
		}
	}
}

// TestOIDCFallbackLogic tests OIDC fallback authentication logic
func TestOIDCFallbackLogic(t *testing.T) {
	config := DefaultAuthConfig()
	config.EnableOIDC = true
	config.OIDCPrimary = true
	config.AllowPasswordFallback = true
	config.AdminUsernames = []string{"admin"}

	am, err := NewAuthManager(config)
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	// Create admin user
	_, err = am.CreateUser("admin", "admin123")
	if err != nil {
		t.Fatalf("Failed to create admin user: %v", err)
	}
	err = am.AddUserRole("admin", "admin")
	if err != nil {
		t.Fatalf("Failed to add admin role: %v", err)
	}

	// Create regular user
	_, err = am.CreateUser("user", "user123")
	if err != nil {
		t.Fatalf("Failed to create regular user: %v", err)
	}

	// Test 1: Regular user should not be able to authenticate with password when OIDC is primary
	_, err = am.AuthenticateUser("user", "user123")
	if err == nil {
		t.Error("Regular user should not be able to authenticate with password when OIDC is primary")
	}

	// Test 2: Admin user should be able to authenticate with password when fallback is enabled
	result, err := am.AuthenticateUser("admin", "admin123")
	if err != nil {
		t.Errorf("Admin user should be able to authenticate with password: %v", err)
	}
	if result.User.Username != "admin" {
		t.Errorf("Expected admin user, got %s", result.User.Username)
	}

	// Test 3: Disable password fallback completely
	config.AllowPasswordFallback = false
	am.config = config

	_, err = am.AuthenticateUser("admin", "admin123")
	if err == nil {
		t.Error("Admin user should not be able to authenticate when password fallback is disabled")
	}
}

// TestOIDCUserCreation tests OIDC user creation and update
func TestOIDCUserCreation(t *testing.T) {
	config := DefaultAuthConfig()
	config.EnableOIDC = true

	am, err := NewAuthManager(config)
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	// Mock OIDC session
	session := &OIDCSession{
		UserID:   "oidc-user-123",
		Username: "john.doe",
		Email:    "john.doe@company.com",
		Claims: map[string]interface{}{
			"sub":   "oidc-user-123",
			"email": "john.doe@company.com",
		},
		Groups: []string{"users", "developers"},
		Roles:  []string{"user", "developer"},
	}

	// Test user creation from OIDC session
	result, err := am.AuthenticateOIDCUser(session)
	if err != nil {
		t.Fatalf("Failed to authenticate OIDC user: %v", err)
	}

	if result.User.Username != "john.doe" {
		t.Errorf("Expected username john.doe, got %s", result.User.Username)
	}

	if result.User.Source != "oidc" {
		t.Errorf("Expected source oidc, got %s", result.User.Source)
	}

	if result.Source != "oidc" {
		t.Errorf("Expected auth source oidc, got %s", result.Source)
	}

	// Test user update on subsequent authentication
	session.Email = "john.doe.updated@company.com"
	session.Groups = append(session.Groups, "admin")
	session.Roles = append(session.Roles, "admin")

	result, err = am.AuthenticateOIDCUser(session)
	if err != nil {
		t.Fatalf("Failed to update OIDC user: %v", err)
	}

	// Check if admin role was added
	hasAdminRole := false
	for _, role := range result.User.Roles {
		if role == "admin" {
			hasAdminRole = true
			break
		}
	}
	if !hasAdminRole {
		t.Error("User should have admin role after OIDC update")
	}
}

// TestAdminUserDetection tests admin user detection logic
func TestAdminUserDetection(t *testing.T) {
	config := DefaultAuthConfig()
	config.AdminUsernames = []string{"sysadmin", "root"}

	am, err := NewAuthManager(config)
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	// Test 1: User in admin usernames list
	if !am.isAdminUser("sysadmin") {
		t.Error("sysadmin should be detected as admin user")
	}

	// Test 2: Create user with admin role
	_, err = am.CreateUser("localadmin", "password123")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	err = am.AddUserRole("localadmin", "admin")
	if err != nil {
		t.Fatalf("Failed to add admin role: %v", err)
	}

	if !am.isAdminUser("localadmin") {
		t.Error("localadmin should be detected as admin user")
	}

	// Test 3: Regular user
	_, err = am.CreateUser("regularuser", "password123")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	if am.isAdminUser("regularuser") {
		t.Error("regularuser should not be detected as admin user")
	}

	// Test 4: Non-existent user
	if am.isAdminUser("nonexistent") {
		t.Error("non-existent user should not be detected as admin user")
	}
}

// TestMFARequirementForAdmins tests MFA requirement for admin users
func TestMFARequirementForAdmins(t *testing.T) {
	config := DefaultAuthConfig()
	config.RequireAdminMFA = true
	config.AdminUsernames = []string{"admin"}

	am, err := NewAuthManager(config)
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	// Create admin user
	_, err = am.CreateUser("admin", "admin123")
	if err != nil {
		t.Fatalf("Failed to create admin user: %v", err)
	}
	err = am.AddUserRole("admin", "admin")
	if err != nil {
		t.Fatalf("Failed to add admin role: %v", err)
	}

	// Create regular user
	_, err = am.CreateUser("user", "user123")
	if err != nil {
		t.Fatalf("Failed to create regular user: %v", err)
	}

	// Test admin user requires MFA
	result, err := am.AuthenticateUser("admin", "admin123")
	if err != nil {
		t.Fatalf("Failed to authenticate admin user: %v", err)
	}

	if !result.RequiresMFA {
		t.Error("Admin user should require MFA when RequireAdminMFA is enabled")
	}

	// Test regular user doesn't require MFA (unless configured separately)
	result, err = am.AuthenticateUser("user", "user123")
	if err != nil {
		t.Fatalf("Failed to authenticate regular user: %v", err)
	}

	// Should not require MFA for regular user unless MFA provider is configured
	if result.RequiresMFA && am.mfaProvider == nil {
		t.Error("Regular user should not require MFA when MFA provider is not configured")
	}
}
