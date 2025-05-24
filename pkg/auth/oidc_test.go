package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// TestNewOIDCProvider tests OIDC provider creation with different configurations
func TestNewOIDCProvider(t *testing.T) {
	// Skip this test since it requires real OIDC provider
	t.Skip("Skipping OIDC provider creation test - requires real OIDC provider")

	tests := []struct {
		name      string
		config    *OIDCConfig
		expectErr bool
	}{
		{
			name: "valid configuration",
			config: &OIDCConfig{
				Enabled:        true,
				ProviderURL:    "https://example.com",
				ClientID:       "test-client",
				ClientSecret:   "test-secret",
				RedirectURL:    "https://app.com/callback",
				Scopes:         []string{"openid", "profile"},
				PkceEnabled:    true,
				SessionTimeout: 24 * time.Hour,
			},
			expectErr: false,
		},
		{
			name:      "nil configuration",
			config:    nil,
			expectErr: true,
		},
		{
			name: "disabled OIDC",
			config: &OIDCConfig{
				Enabled: false,
			},
			expectErr: true,
		},
		{
			name: "missing provider URL",
			config: &OIDCConfig{
				Enabled:  true,
				ClientID: "test-client",
			},
			expectErr: true,
		},
		{
			name: "missing client ID",
			config: &OIDCConfig{
				Enabled:     true,
				ProviderURL: "https://example.com",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewOIDCProvider(tt.config, NewTestLogger())
			if tt.expectErr && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if provider == nil && !tt.expectErr {
				t.Error("provider should not be nil")
			}
		})
	}
}

// TestOIDCConfig tests OIDC configuration validation and defaults
func TestOIDCConfig(t *testing.T) {
	config := &OIDCConfig{
		Enabled:      true,
		ProviderURL:  "https://auth.example.com",
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://app.example.com/callback",
		PkceEnabled:  true,
	}

	// Test default scope setting
	if len(config.Scopes) != 0 {
		t.Errorf("initial scopes should be empty, got: %v", config.Scopes)
	}

	// Test default session timeout
	if config.SessionTimeout != 0 {
		t.Errorf("initial session timeout should be 0, got: %v", config.SessionTimeout)
	}

	// Test PKCE enablement
	if !config.PkceEnabled {
		t.Error("PKCE should be enabled")
	}

	// Test claim mappings defaults
	if config.ClaimMappings.Username != "" {
		t.Error("username claim mapping should be empty initially")
	}
}

// TestClaimMappings tests claim mapping functionality
func TestClaimMappings(t *testing.T) {
	mappings := ClaimMappings{
		Username:    "preferred_username",
		Email:       "email",
		FirstName:   "given_name",
		LastName:    "family_name",
		DisplayName: "name",
		Groups:      "groups",
		Roles:       "realm_access.roles",
	}

	// Test that all mappings are set correctly
	if mappings.Username != "preferred_username" {
		t.Errorf("username mapping incorrect: %s", mappings.Username)
	}
	if mappings.Email != "email" {
		t.Errorf("email mapping incorrect: %s", mappings.Email)
	}
	if mappings.Groups != "groups" {
		t.Errorf("groups mapping incorrect: %s", mappings.Groups)
	}
	if mappings.Roles != "realm_access.roles" {
		t.Errorf("roles mapping incorrect: %s", mappings.Roles)
	}
}

// TestUserInfo tests UserInfo structure
func TestUserInfo(t *testing.T) {
	userInfo := &UserInfo{
		Sub:               "user123",
		Name:              "John Doe",
		GivenName:         "John",
		FamilyName:        "Doe",
		PreferredUsername: "john.doe",
		Email:             "john.doe@example.com",
		EmailVerified:     true,
		Groups:            []string{"admin", "users"},
		Roles:             []string{"administrator", "user"},
		CustomClaims: map[string]interface{}{
			"department": "engineering",
			"level":      "senior",
		},
	}

	// Test basic fields
	if userInfo.Sub != "user123" {
		t.Errorf("subject incorrect: %s", userInfo.Sub)
	}
	if userInfo.Email != "john.doe@example.com" {
		t.Errorf("email incorrect: %s", userInfo.Email)
	}
	if !userInfo.EmailVerified {
		t.Error("email should be verified")
	}

	// Test groups and roles
	if len(userInfo.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(userInfo.Groups))
	}
	if len(userInfo.Roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(userInfo.Roles))
	}

	// Test custom claims
	if userInfo.CustomClaims["department"] != "engineering" {
		t.Errorf("department claim incorrect: %v", userInfo.CustomClaims["department"])
	}
}

// TestDeviceAuthResponse tests device authorization response structure
func TestDeviceAuthResponse(t *testing.T) {
	response := &DeviceAuthResponse{
		DeviceCode:              "device123",
		UserCode:                "ABCD-EFGH",
		VerificationURI:         "https://auth.example.com/device",
		VerificationURIComplete: "https://auth.example.com/device?user_code=ABCD-EFGH",
		ExpiresIn:               600,
		Interval:                5,
	}

	// Test all fields are set correctly
	if response.DeviceCode != "device123" {
		t.Errorf("device code incorrect: %s", response.DeviceCode)
	}
	if response.UserCode != "ABCD-EFGH" {
		t.Errorf("user code incorrect: %s", response.UserCode)
	}
	if response.ExpiresIn != 600 {
		t.Errorf("expires in incorrect: %d", response.ExpiresIn)
	}
	if response.Interval != 5 {
		t.Errorf("interval incorrect: %d", response.Interval)
	}
}

// TestOIDCSession tests OIDC session structure and methods
func TestOIDCSession(t *testing.T) {
	now := time.Now()
	session := &OIDCSession{
		UserID:       "user123",
		Username:     "john.doe",
		Email:        "john.doe@example.com",
		AccessToken:  "access-token-123",
		RefreshToken: "refresh-token-123",
		IDToken:      "id-token-123",
		ExpiresAt:    now.Add(time.Hour),
		CreatedAt:    now,
		LastAccess:   now,
		Groups:       []string{"admin", "users"},
		Roles:        []string{"administrator"},
		Claims: map[string]interface{}{
			"sub":   "user123",
			"email": "john.doe@example.com",
			"name":  "John Doe",
		},
	}

	// Test basic session fields
	if session.UserID != "user123" {
		t.Errorf("user ID incorrect: %s", session.UserID)
	}
	if session.Email != "john.doe@example.com" {
		t.Errorf("email incorrect: %s", session.Email)
	}

	// Test token fields
	if session.AccessToken != "access-token-123" {
		t.Errorf("access token incorrect: %s", session.AccessToken)
	}
	if session.RefreshToken != "refresh-token-123" {
		t.Errorf("refresh token incorrect: %s", session.RefreshToken)
	}

	// Test time fields
	if session.ExpiresAt.Before(now) {
		t.Error("session should not be expired")
	}
	if session.CreatedAt.After(now.Add(time.Minute)) {
		t.Error("creation time should be close to now")
	}

	// Test groups and roles
	if len(session.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(session.Groups))
	}
	if len(session.Roles) != 1 {
		t.Errorf("expected 1 role, got %d", len(session.Roles))
	}

	// Test claims
	if session.Claims["sub"] != "user123" {
		t.Errorf("sub claim incorrect: %v", session.Claims["sub"])
	}
}

// TestAuthState tests authorization state structure
func TestAuthState(t *testing.T) {
	now := time.Now()
	state := &AuthState{
		State:         "random-state-123",
		CodeVerifier:  "code-verifier-123",
		CodeChallenge: "code-challenge-123",
		RedirectURI:   "https://app.example.com/callback",
		Scopes:        []string{"openid", "profile", "email"},
		CreatedAt:     now,
		ExpiresAt:     now.Add(10 * time.Minute),
		UserID:        "user123",
	}

	// Test basic fields
	if state.State != "random-state-123" {
		t.Errorf("state incorrect: %s", state.State)
	}
	if state.CodeVerifier != "code-verifier-123" {
		t.Errorf("code verifier incorrect: %s", state.CodeVerifier)
	}

	// Test PKCE fields
	if state.CodeChallenge != "code-challenge-123" {
		t.Errorf("code challenge incorrect: %s", state.CodeChallenge)
	}

	// Test scopes
	expectedScopes := []string{"openid", "profile", "email"}
	if len(state.Scopes) != len(expectedScopes) {
		t.Errorf("expected %d scopes, got %d", len(expectedScopes), len(state.Scopes))
	}

	// Test expiration
	if state.ExpiresAt.Before(state.CreatedAt) {
		t.Error("expiration should be after creation")
	}
}

// TestTokenResponse tests token response structure
func TestTokenResponse(t *testing.T) {
	response := &TokenResponse{
		AccessToken:  "access-token-123",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "refresh-token-123",
		IDToken:      "id-token-123",
		Scope:        "openid profile email",
	}

	// Test all fields
	if response.AccessToken != "access-token-123" {
		t.Errorf("access token incorrect: %s", response.AccessToken)
	}
	if response.TokenType != "Bearer" {
		t.Errorf("token type incorrect: %s", response.TokenType)
	}
	if response.ExpiresIn != 3600 {
		t.Errorf("expires in incorrect: %d", response.ExpiresIn)
	}
	if response.Scope != "openid profile email" {
		t.Errorf("scope incorrect: %s", response.Scope)
	}
}

// TestMockOIDCServer tests with a mock OIDC server
func TestMockOIDCServer(t *testing.T) {
	// Create mock OIDC server
	server := httptest.NewServer(nil)
	defer server.Close()

	// Set up the handler after server is created
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid_configuration":
			// Mock discovery endpoint
			discovery := map[string]interface{}{
				"issuer":                 server.URL,
				"authorization_endpoint": server.URL + "/auth",
				"token_endpoint":         server.URL + "/token",
				"userinfo_endpoint":      server.URL + "/userinfo",
				"jwks_uri":               server.URL + "/jwks",
				"scopes_supported":       []string{"openid", "profile", "email"},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(discovery); err != nil {
				http.Error(w, "encoding error", http.StatusInternalServerError)
				return
			}

		case "/jwks":
			// Mock JWKS endpoint
			jwks := map[string]interface{}{
				"keys": []interface{}{},
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				http.Error(w, "encoding error", http.StatusInternalServerError)
				return
			}

		case "/token":
			// Mock token endpoint
			token := map[string]interface{}{
				"access_token":  "mock-access-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "mock-refresh-token",
				"id_token":      "mock-id-token",
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(token); err != nil {
				http.Error(w, "encoding error", http.StatusInternalServerError)
				return
			}

		case "/userinfo":
			// Mock userinfo endpoint
			userinfo := map[string]interface{}{
				"sub":   "mock-user-123",
				"email": "mock@example.com",
				"name":  "Mock User",
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(userinfo); err != nil {
				http.Error(w, "encoding error", http.StatusInternalServerError)
				return
			}

		default:
			http.NotFound(w, r)
		}
	})

	t.Logf("Mock OIDC server running at: %s", server.URL)

	// Test discovery endpoint
	resp, err := http.Get(server.URL + "/.well-known/openid_configuration")
	if err != nil {
		t.Fatalf("failed to fetch discovery: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("discovery endpoint returned %d", resp.StatusCode)
	}

	var discovery map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		t.Fatalf("failed to decode discovery: %v", err)
	}

	if discovery["issuer"] != server.URL {
		t.Errorf("issuer mismatch: %v", discovery["issuer"])
	}
}

// TestOIDCAuthorizationURL tests authorization URL generation
func TestOIDCAuthorizationURL(t *testing.T) {
	// This test demonstrates the structure of authorization URLs
	config := &oauth2.Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "https://app.example.com/callback",
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://auth.example.com/authorize",
			TokenURL: "https://auth.example.com/token",
		},
	}

	state := "random-state-value"

	// Test basic authorization URL
	authURL := config.AuthCodeURL(state)
	if !strings.Contains(authURL, "https://auth.example.com/authorize") {
		t.Error("authorization URL should contain auth endpoint")
	}
	if !strings.Contains(authURL, "state="+state) {
		t.Error("authorization URL should contain state parameter")
	}
	if !strings.Contains(authURL, "client_id=test-client") {
		t.Error("authorization URL should contain client ID")
	}

	// Test PKCE authorization URL
	verifier := oauth2.GenerateVerifier()
	pkceAuthURL := config.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(verifier),
	)

	if !strings.Contains(pkceAuthURL, "code_challenge") {
		t.Error("PKCE URL should contain code challenge")
	}
	if !strings.Contains(pkceAuthURL, "code_challenge_method=S256") {
		t.Error("PKCE URL should use S256 challenge method")
	}

	// Parse and validate URL structure
	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("failed to parse authorization URL: %v", err)
	}

	query := parsedURL.Query()
	if query.Get("response_type") != "code" {
		t.Error("response type should be 'code'")
	}
	if query.Get("client_id") != "test-client" {
		t.Error("client ID mismatch in URL")
	}
	if query.Get("state") != state {
		t.Error("state mismatch in URL")
	}
}

// TestOIDCTokenExchange tests token exchange functionality
func TestOIDCTokenExchange(t *testing.T) {
	// Create mock server for token exchange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" && r.Method == "POST" {
			// Parse form data
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid form", http.StatusBadRequest)
				return
			}

			// Validate required parameters
			if r.Form.Get("grant_type") != "authorization_code" {
				http.Error(w, "invalid grant type", http.StatusBadRequest)
				return
			}

			if r.Form.Get("code") == "" {
				http.Error(w, "missing code", http.StatusBadRequest)
				return
			}

			// Return mock token response
			token := map[string]interface{}{
				"access_token":  "mock-access-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "mock-refresh-token",
				"id_token":      "mock-id-token",
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(token); err != nil {
				http.Error(w, "encoding error", http.StatusInternalServerError)
				return
			}
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Test token exchange
	config := &oauth2.Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "https://app.example.com/callback",
		Endpoint: oauth2.Endpoint{
			TokenURL: server.URL + "/token",
		},
	}

	ctx := context.Background()
	token, err := config.Exchange(ctx, "test-authorization-code")
	if err != nil {
		t.Fatalf("token exchange failed: %v", err)
	}

	if token.AccessToken != "mock-access-token" {
		t.Errorf("access token mismatch: %s", token.AccessToken)
	}
	if token.TokenType != "Bearer" {
		t.Errorf("token type mismatch: %s", token.TokenType)
	}
	if token.RefreshToken != "mock-refresh-token" {
		t.Errorf("refresh token mismatch: %s", token.RefreshToken)
	}

	// Test PKCE token exchange
	verifier := oauth2.GenerateVerifier()
	pkceToken, err := config.Exchange(
		ctx,
		"test-authorization-code",
		oauth2.VerifierOption(verifier),
	)
	if err != nil {
		t.Fatalf("PKCE token exchange failed: %v", err)
	}

	if pkceToken.AccessToken != "mock-access-token" {
		t.Errorf("PKCE access token mismatch: %s", pkceToken.AccessToken)
	}
}

// TestOIDCPKCE tests PKCE functionality
func TestOIDCPKCE(t *testing.T) {
	// Test verifier generation
	verifier := oauth2.GenerateVerifier()
	if len(verifier) < 43 || len(verifier) > 128 {
		t.Errorf("verifier length should be 43-128 chars, got %d", len(verifier))
	}

	// Test that multiple verifiers are different
	verifier2 := oauth2.GenerateVerifier()
	if verifier == verifier2 {
		t.Error("verifiers should be unique")
	}

	// Test S256 challenge option
	challengeOption := oauth2.S256ChallengeOption(verifier)
	if challengeOption == nil {
		t.Error("S256 challenge option should not be nil")
	}
}

// TestOIDCScopes tests scope handling
func TestOIDCScopes(t *testing.T) {
	testCases := []struct {
		name   string
		scopes []string
		valid  bool
	}{
		{
			name:   "basic openid scopes",
			scopes: []string{"openid", "profile", "email"},
			valid:  true,
		},
		{
			name:   "with groups scope",
			scopes: []string{"openid", "profile", "email", "groups"},
			valid:  true,
		},
		{
			name:   "missing openid",
			scopes: []string{"profile", "email"},
			valid:  false,
		},
		{
			name:   "empty scopes",
			scopes: []string{},
			valid:  false,
		},
		{
			name:   "custom scopes",
			scopes: []string{"openid", "custom:read", "custom:write"},
			valid:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Check if openid is present (required for OIDC)
			hasOpenID := false
			for _, scope := range tc.scopes {
				if scope == "openid" {
					hasOpenID = true
					break
				}
			}

			if tc.valid && !hasOpenID {
				t.Error("valid OIDC scopes should include 'openid'")
			}
			if !tc.valid && hasOpenID && len(tc.scopes) > 1 {
				// If it has openid and other scopes, it should be valid
				t.Errorf("scopes with openid should be valid: %v", tc.scopes)
			}
		})
	}
}

// TestOIDCClaimExtraction tests claim extraction functionality
func TestOIDCClaimExtraction(t *testing.T) {
	// Mock claims from ID token or userinfo
	claims := map[string]interface{}{
		"sub":                "user-123",
		"email":              "user@example.com",
		"email_verified":     true,
		"preferred_username": "testuser",
		"given_name":         "Test",
		"family_name":        "User",
		"name":               "Test User",
		"groups":             []interface{}{"admin", "users"},
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"user", "admin"},
		},
		"custom_claim": "custom_value",
	}

	// Test basic claim extraction
	if claims["sub"] != "user-123" {
		t.Errorf("sub claim incorrect: %v", claims["sub"])
	}

	if claims["email"] != "user@example.com" {
		t.Errorf("email claim incorrect: %v", claims["email"])
	}

	if claims["email_verified"] != true {
		t.Errorf("email_verified should be true: %v", claims["email_verified"])
	}

	// Test groups extraction
	groups, ok := claims["groups"].([]interface{})
	if !ok {
		t.Error("groups should be array")
	} else {
		if len(groups) != 2 {
			t.Errorf("expected 2 groups, got %d", len(groups))
		}
		if groups[0] != "admin" || groups[1] != "users" {
			t.Errorf("groups content incorrect: %v", groups)
		}
	}

	// Test nested roles extraction (Keycloak style)
	realmAccess, ok := claims["realm_access"].(map[string]interface{})
	if !ok {
		t.Error("realm_access should be object")
	} else {
		roles, ok := realmAccess["roles"].([]interface{})
		if !ok {
			t.Error("roles should be array")
		} else {
			if len(roles) != 2 {
				t.Errorf("expected 2 roles, got %d", len(roles))
			}
		}
	}
}

// TestOIDCSessionManagement tests session lifecycle
func TestOIDCSessionManagement(t *testing.T) {
	// Create mock sessions
	sessions := make(map[string]*OIDCSession)
	now := time.Now()

	// Add active session
	activeSession := &OIDCSession{
		UserID:      "user1",
		Username:    "testuser",
		AccessToken: "token1",
		ExpiresAt:   now.Add(time.Hour),
		CreatedAt:   now,
		LastAccess:  now,
	}
	sessions["session1"] = activeSession

	// Add expired session
	expiredSession := &OIDCSession{
		UserID:      "user2",
		Username:    "expireduser",
		AccessToken: "token2",
		ExpiresAt:   now.Add(-time.Hour), // Expired
		CreatedAt:   now.Add(-2 * time.Hour),
		LastAccess:  now.Add(-time.Hour),
	}
	sessions["session2"] = expiredSession

	// Test session validation
	if activeSession.ExpiresAt.Before(time.Now()) {
		t.Error("active session should not be expired")
	}

	if !expiredSession.ExpiresAt.Before(time.Now()) {
		t.Error("expired session should be expired")
	}

	// Test session cleanup (remove expired sessions)
	for sessionID, session := range sessions {
		if session.ExpiresAt.Before(time.Now()) {
			delete(sessions, sessionID)
		}
	}

	if len(sessions) != 1 {
		t.Errorf("expected 1 active session after cleanup, got %d", len(sessions))
	}

	if _, exists := sessions["session1"]; !exists {
		t.Error("active session should still exist")
	}

	if _, exists := sessions["session2"]; exists {
		t.Error("expired session should be removed")
	}
}
