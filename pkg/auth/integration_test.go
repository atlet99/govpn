package auth

import (
	"fmt"
	"testing"
	"time"
)

// TestComplexAuthenticationScenarios tests complex authentication scenarios
func TestComplexAuthenticationScenarios(t *testing.T) {
	// Scenario 1: OIDC primary with admin fallback
	t.Run("OIDC_Primary_Admin_Fallback", func(t *testing.T) {
		config := &AuthConfig{
			HashMethod:            "argon2",
			Argon2Memory:          64 * 1024,
			Argon2Time:            3,
			Argon2Threads:         4,
			Argon2KeyLength:       32,
			SaltLength:            16,
			EnableOIDC:            true,
			OIDCPrimary:           true,
			AllowPasswordFallback: true,
			AdminUsernames:        []string{"emergency-admin"},
			RequireAdminMFA:       true,
		}

		am, err := NewAuthManager(config)
		if err != nil {
			t.Fatalf("Failed to create AuthManager: %v", err)
		}

		// Create emergency admin
		_, err = am.CreateUser("emergency-admin", "super-secure-password")
		if err != nil {
			t.Fatalf("Failed to create emergency admin: %v", err)
		}

		// Create regular user
		_, err = am.CreateUser("regular-user", "password123")
		if err != nil {
			t.Fatalf("Failed to create regular user: %v", err)
		}

		// Test: Regular user cannot authenticate with password
		_, err = am.AuthenticateUser("regular-user", "password123")
		if err == nil {
			t.Error("Regular user should not be able to authenticate with password in OIDC primary mode")
		}

		// Test: Emergency admin can authenticate with password
		result, err := am.AuthenticateUser("emergency-admin", "super-secure-password")
		if err != nil {
			t.Errorf("Emergency admin should be able to authenticate: %v", err)
		}
		if !result.RequiresMFA {
			t.Error("Emergency admin should require MFA")
		}

		// Test: OIDC user creation and admin role assignment
		oidcSession := &OIDCSession{
			UserID:   "oidc-admin-123",
			Username: "oidc-admin",
			Email:    "admin@company.com",
			Claims:   map[string]interface{}{"sub": "oidc-admin-123"},
			Groups:   []string{"admin", "users"},
			Roles:    []string{"admin", "user"},
		}

		result, err = am.AuthenticateOIDCUser(oidcSession)
		if err != nil {
			t.Fatalf("Failed to authenticate OIDC admin: %v", err)
		}

		if !am.hasRole(result.User, "admin") {
			t.Error("OIDC user should have admin role")
		}
	})

	// Scenario 2: Mixed authentication sources with role synchronization
	t.Run("Mixed_Auth_Sources_Role_Sync", func(t *testing.T) {
		config := &AuthConfig{
			HashMethod:            "argon2",
			Argon2Memory:          64 * 1024,
			Argon2Time:            3,
			Argon2Threads:         4,
			Argon2KeyLength:       32,
			SaltLength:            16,
			EnableOIDC:            true,
			EnableLDAP:            true,
			OIDCPrimary:           false,
			AllowPasswordFallback: true,
		}

		am, err := NewAuthManager(config)
		if err != nil {
			t.Fatalf("Failed to create AuthManager: %v", err)
		}

		// Test local user
		_, err = am.CreateUser("local-user", "password123")
		if err != nil {
			t.Fatalf("Failed to create local user: %v", err)
		}

		result, err := am.AuthenticateUser("local-user", "password123")
		if err != nil {
			t.Errorf("Local user authentication failed: %v", err)
		}
		if result.Source != "local" {
			t.Errorf("Expected source 'local', got %s", result.Source)
		}

		// Test OIDC user with role changes
		oidcSession := &OIDCSession{
			UserID:   "oidc-user-456",
			Username: "dynamic-user",
			Email:    "user@company.com",
			Claims:   map[string]interface{}{"sub": "oidc-user-456"},
			Groups:   []string{"users"},
			Roles:    []string{"user"},
		}

		// First authentication - regular user
		result, err = am.AuthenticateOIDCUser(oidcSession)
		if err != nil {
			t.Fatalf("Failed to authenticate OIDC user: %v", err)
		}

		if am.hasRole(result.User, "admin") {
			t.Error("User should not have admin role initially")
		}

		// Role promotion - user becomes admin
		oidcSession.Groups = append(oidcSession.Groups, "admin")
		oidcSession.Roles = append(oidcSession.Roles, "admin")

		result, err = am.AuthenticateOIDCUser(oidcSession)
		if err != nil {
			t.Fatalf("Failed to authenticate OIDC user after promotion: %v", err)
		}

		if !am.hasRole(result.User, "admin") {
			t.Error("User should have admin role after promotion")
		}

		// Role demotion - admin role removed
		oidcSession.Groups = []string{"users"}
		oidcSession.Roles = []string{"user"}

		result, err = am.AuthenticateOIDCUser(oidcSession)
		if err != nil {
			t.Fatalf("Failed to authenticate OIDC user after demotion: %v", err)
		}

		if am.hasRole(result.User, "admin") {
			t.Error("User should not have admin role after demotion")
		}
	})

	// Scenario 3: Edge cases and error handling
	t.Run("Edge_Cases_Error_Handling", func(t *testing.T) {
		config := &AuthConfig{
			HashMethod:            "argon2",
			Argon2Memory:          64 * 1024,
			Argon2Time:            3,
			Argon2Threads:         4,
			Argon2KeyLength:       32,
			SaltLength:            16,
			EnableOIDC:            true,
			OIDCPrimary:           true,
			AllowPasswordFallback: false,
		}

		am, err := NewAuthManager(config)
		if err != nil {
			t.Fatalf("Failed to create AuthManager: %v", err)
		}

		// Test: Empty OIDC session
		emptySession := &OIDCSession{}
		_, err = am.AuthenticateOIDCUser(emptySession)
		if err == nil {
			t.Error("Should fail with empty OIDC session")
		}

		// Test: OIDC session without username
		invalidSession := &OIDCSession{
			UserID: "user-123",
			Email:  "user@company.com",
		}
		_, err = am.AuthenticateOIDCUser(invalidSession)
		if err == nil {
			t.Error("Should fail with OIDC session without username")
		}

		// Test: Non-existent user authentication
		_, err = am.AuthenticateUser("non-existent", "password")
		if err == nil {
			t.Error("Should fail for non-existent user")
		}

		// Test: Inactive user
		_, err = am.CreateUser("inactive-user", "password123")
		if err != nil {
			t.Fatalf("Failed to create inactive user: %v", err)
		}
		err = am.SetUserActive("inactive-user", false)
		if err != nil {
			t.Fatalf("Failed to set user inactive: %v", err)
		}

		_, err = am.AuthenticateUser("inactive-user", "password123")
		if err == nil {
			t.Error("Should fail for inactive user")
		}
	})
}

// TestAuthenticationPerformance tests authentication performance under load
func TestAuthenticationPerformance(t *testing.T) {
	config := &AuthConfig{
		HashMethod:      "argon2",
		Argon2Memory:    1024, // Reduced for testing
		Argon2Time:      1,    // Reduced for testing
		Argon2Threads:   1,    // Reduced for testing
		Argon2KeyLength: 32,
		SaltLength:      16,
	}
	am, err := NewAuthManager(config)
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	// Create test user
	_, err = am.CreateUser("perf-user", "password123")
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Benchmark sequential authentications (reduced count for faster testing)
	start := time.Now()
	iterations := 100 // Reduced from 1000
	for i := 0; i < iterations; i++ {
		_, err := am.AuthenticateUser("perf-user", "password123")
		if err != nil {
			t.Fatalf("Authentication failed on iteration %d: %v", i, err)
		}
	}
	duration := time.Since(start)

	avgDuration := duration / time.Duration(iterations)
	if avgDuration > 100*time.Millisecond { // Increased threshold for Argon2
		t.Errorf("Authentication too slow: %v per auth (expected < 100ms)", avgDuration)
	}

	t.Logf("Authentication performance: %v per auth", avgDuration)
}

// TestConcurrentAuthentication tests concurrent authentication scenarios
func TestConcurrentAuthentication(t *testing.T) {
	config := DefaultAuthConfig()
	am, err := NewAuthManager(config)
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	// Create multiple test users
	userCount := 10
	for i := 0; i < userCount; i++ {
		username := fmt.Sprintf("user-%d", i)
		_, err = am.CreateUser(username, "password123")
		if err != nil {
			t.Fatalf("Failed to create user %s: %v", username, err)
		}
	}

	// Test concurrent authentications
	done := make(chan bool, userCount)
	errors := make(chan error, userCount)

	for i := 0; i < userCount; i++ {
		go func(userIndex int) {
			username := fmt.Sprintf("user-%d", userIndex)
			_, err := am.AuthenticateUser(username, "password123")
			if err != nil {
				errors <- err
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < userCount; i++ {
		select {
		case <-done:
			// Success
		case err := <-errors:
			t.Errorf("Concurrent authentication failed: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("Concurrent authentication test timed out")
		}
	}
}

// TestSessionLifecycle tests session lifecycle management
func TestSessionLifecycle(t *testing.T) {
	config := &AuthConfig{
		EnableOIDC:     true,
		SessionTimeout: 1, // 1 second for testing
	}

	am, err := NewAuthManager(config)
	if err != nil {
		t.Fatalf("Failed to create AuthManager: %v", err)
	}

	// Create OIDC session
	session := &OIDCSession{
		UserID:    "session-user-123",
		Username:  "session-user",
		Email:     "session@company.com",
		Claims:    map[string]interface{}{"sub": "session-user-123"},
		ExpiresAt: time.Now().Add(2 * time.Second),
		CreatedAt: time.Now(),
	}

	result, err := am.AuthenticateOIDCUser(session)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	if result.SessionID == "" {
		t.Error("Session ID should not be empty")
	}

	// Test session is valid immediately
	user, exists := am.GetUser("session-user")
	if !exists {
		t.Error("User should exist after session creation")
	}

	if user.Source != "oidc" {
		t.Errorf("Expected source 'oidc', got %s", user.Source)
	}

	// Test session metadata
	if user.Metadata["email"] != "session@company.com" {
		t.Errorf("Expected email 'session@company.com', got %v", user.Metadata["email"])
	}
}
