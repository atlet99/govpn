package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/atlet99/govpn/pkg/auth"
	"github.com/atlet99/govpn/pkg/core"
)

func createTestServer(t *testing.T) (*Server, *auth.AuthManager) {
	// Create auth manager
	authConfig := &auth.AuthConfig{
		HashMethod:            "argon2",
		Argon2Memory:          1024, // Reduced for testing
		Argon2Time:            1,
		Argon2Threads:         1,
		Argon2KeyLength:       32,
		SaltLength:            16,
		EnableOIDC:            true,
		OIDCPrimary:           false,
		AllowPasswordFallback: true,
		AdminUsernames:        []string{"admin"},
	}

	authManager, err := auth.NewAuthManager(authConfig)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Create test users
	_, err = authManager.CreateUser("admin", "admin123")
	if err != nil {
		t.Fatalf("Failed to create admin user: %v", err)
	}
	err = authManager.AddUserRole("admin", "admin")
	if err != nil {
		t.Fatalf("Failed to add admin role: %v", err)
	}

	_, err = authManager.CreateUser("user", "user123")
	if err != nil {
		t.Fatalf("Failed to create regular user: %v", err)
	}

	// Create API server
	config := Config{
		BaseURL:   "/api/v1",
		JWTSecret: "test-secret-key",
	}

	// Mock VPN server
	vpnServer := &core.OpenVPNServer{}

	server := NewServer(config, vpnServer, authManager)

	return server, authManager
}

func TestLoginAPI(t *testing.T) {
	server, _ := createTestServer(t)

	tests := []struct {
		name           string
		request        LoginRequest
		expectedStatus int
		expectToken    bool
		expectError    bool
	}{
		{
			name: "Valid login",
			request: LoginRequest{
				Username: "admin",
				Password: "admin123",
			},
			expectedStatus: http.StatusOK,
			expectToken:    true,
			expectError:    false,
		},
		{
			name: "Invalid password",
			request: LoginRequest{
				Username: "admin",
				Password: "wrong",
			},
			expectedStatus: http.StatusUnauthorized,
			expectToken:    false,
			expectError:    true,
		},
		{
			name: "Missing username",
			request: LoginRequest{
				Password: "admin123",
			},
			expectedStatus: http.StatusBadRequest,
			expectToken:    false,
			expectError:    true,
		},
		{
			name: "Missing password",
			request: LoginRequest{
				Username: "admin",
			},
			expectedStatus: http.StatusBadRequest,
			expectToken:    false,
			expectError:    true,
		},
		{
			name: "Non-existent user",
			request: LoginRequest{
				Username: "nonexistent",
				Password: "password",
			},
			expectedStatus: http.StatusUnauthorized,
			expectToken:    false,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.request)
			req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			server.handleLogin(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			var response Response
			err := json.NewDecoder(w.Body).Decode(&response)
			if err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if tt.expectError && response.Success {
				t.Error("Expected error response, but got success")
			}

			if !tt.expectError && !response.Success {
				t.Errorf("Expected success response, but got error: %s", response.Error)
			}

			if tt.expectToken {
				loginResp, ok := response.Data.(map[string]interface{})
				if !ok {
					t.Error("Expected login response data")
				} else if loginResp["token"] == nil || loginResp["token"] == "" {
					t.Error("Expected token in response")
				}
			}
		})
	}
}

func TestOIDCFallbackAPI(t *testing.T) {
	// Create server with OIDC primary mode
	authConfig := &auth.AuthConfig{
		HashMethod:            "argon2",
		Argon2Memory:          1024,
		Argon2Time:            1,
		Argon2Threads:         1,
		Argon2KeyLength:       32,
		SaltLength:            16,
		EnableOIDC:            true,
		OIDCPrimary:           true,
		AllowPasswordFallback: true,
		AdminUsernames:        []string{"admin"},
	}

	authManager, err := auth.NewAuthManager(authConfig)
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	// Create test users
	_, err = authManager.CreateUser("admin", "admin123")
	if err != nil {
		t.Fatalf("Failed to create admin user: %v", err)
	}
	err = authManager.AddUserRole("admin", "admin")
	if err != nil {
		t.Fatalf("Failed to add admin role: %v", err)
	}

	_, err = authManager.CreateUser("user", "user123")
	if err != nil {
		t.Fatalf("Failed to create regular user: %v", err)
	}

	config := Config{
		BaseURL:   "/api/v1",
		JWTSecret: "test-secret-key",
	}

	vpnServer := &core.OpenVPNServer{}
	server := NewServer(config, vpnServer, authManager)

	// Test admin can login with password
	adminReq := LoginRequest{
		Username: "admin",
		Password: "admin123",
	}
	body, _ := json.Marshal(adminReq)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	server.handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Admin should be able to login, got status %d", w.Code)
	}

	// Test regular user cannot login with password
	userReq := LoginRequest{
		Username: "user",
		Password: "user123",
	}
	body, _ = json.Marshal(userReq)
	req = httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	server.handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Regular user should not be able to login in OIDC primary mode, got status %d", w.Code)
	}
}

func TestAuthStatusAPI(t *testing.T) {
	server, authManager := createTestServer(t)

	// Create user and get token
	user, _ := authManager.GetUser("admin")
	token, err := server.generateJWTToken(user)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Test valid token
	req := httptest.NewRequest("GET", "/api/v1/auth/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	server.handleAuthStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response Response
	err = json.NewDecoder(w.Body).Decode(&response)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !response.Success {
		t.Error("Expected success response")
	}

	// Test missing token
	req = httptest.NewRequest("GET", "/api/v1/auth/status", nil)
	w = httptest.NewRecorder()
	server.handleAuthStatus(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}

	// Test invalid token
	req = httptest.NewRequest("GET", "/api/v1/auth/status", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	w = httptest.NewRecorder()
	server.handleAuthStatus(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)

	// Test wrong method for login
	req := httptest.NewRequest("GET", "/api/v1/auth/login", nil)
	w := httptest.NewRecorder()
	server.handleLogin(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}

	// Test wrong method for auth status
	req = httptest.NewRequest("POST", "/api/v1/auth/status", nil)
	w = httptest.NewRecorder()
	server.handleAuthStatus(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}
