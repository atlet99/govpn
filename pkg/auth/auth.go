package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"crypto/sha256"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// User represents a user in the system
type User struct {
	ID           string                 `json:"id"`
	Username     string                 `json:"username"`
	PasswordHash string                 `json:"password_hash"`
	Salt         string                 `json:"salt"`
	CreatedAt    time.Time              `json:"created_at"`
	LastLogin    time.Time              `json:"last_login"`
	IsActive     bool                   `json:"is_active"`
	Roles        []string               `json:"roles"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Source       string                 `json:"source"` // local, ldap, oidc
}

// AuthConfig configuration for authentication system
type AuthConfig struct {
	HashMethod       string      `json:"hash_method"`       // "argon2" or "pbkdf2"
	Argon2Memory     uint32      `json:"argon2_memory"`     // Memory for Argon2 (KB)
	Argon2Time       uint32      `json:"argon2_time"`       // Time for Argon2 (iterations)
	Argon2Threads    uint8       `json:"argon2_threads"`    // Threads for Argon2
	Argon2KeyLength  uint32      `json:"argon2_key_length"` // Key length for Argon2
	PBKDF2Iterations int         `json:"pbkdf2_iterations"` // Iterations for PBKDF2
	PBKDF2KeyLength  int         `json:"pbkdf2_key_length"` // Key length for PBKDF2
	SaltLength       int         `json:"salt_length"`       // Salt length
	SessionTimeout   int         `json:"session_timeout"`   // Session timeout in seconds
	EnableMFA        bool        `json:"enable_mfa"`        // Enable MFA
	EnableOIDC       bool        `json:"enable_oidc"`       // Enable OIDC
	EnableLDAP       bool        `json:"enable_ldap"`       // Enable LDAP
	MFA              *MFAConfig  `json:"mfa,omitempty"`
	OIDC             *OIDCConfig `json:"oidc,omitempty"`
	LDAP             *LDAPConfig `json:"ldap,omitempty"`
}

// DefaultAuthConfig returns default configuration
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		HashMethod:       "argon2",
		Argon2Memory:     64 * 1024, // 64MB
		Argon2Time:       3,
		Argon2Threads:    4,
		Argon2KeyLength:  32,
		PBKDF2Iterations: 100000,
		PBKDF2KeyLength:  32,
		SaltLength:       16,
		SessionTimeout:   3600, // 1 hour
		EnableMFA:        false,
		EnableOIDC:       false,
		EnableLDAP:       false,
	}
}

// AuthManager manages user authentication
type AuthManager struct {
	config       *AuthConfig
	users        map[string]*User
	mu           sync.RWMutex
	mfaProvider  *MFAProvider
	oidcProvider *OIDCProvider
	ldapProvider *LDAPProvider
	logger       Logger
}

// SimpleLogger simple Logger implementation for compatibility
type SimpleLogger struct{}

func (l *SimpleLogger) Printf(format string, v ...interface{}) {
	fmt.Printf("[AUTH] "+format+"\n", v...)
}

func (l *SimpleLogger) Errorf(format string, v ...interface{}) {
	fmt.Printf("[AUTH ERROR] "+format+"\n", v...)
}

func (l *SimpleLogger) Infof(format string, v ...interface{}) {
	fmt.Printf("[AUTH INFO] "+format+"\n", v...)
}

func (l *SimpleLogger) Debugf(format string, v ...interface{}) {
	fmt.Printf("[AUTH DEBUG] "+format+"\n", v...)
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(config *AuthConfig) (*AuthManager, error) {
	if config == nil {
		config = DefaultAuthConfig()
	}

	logger := &SimpleLogger{}

	am := &AuthManager{
		config: config,
		users:  make(map[string]*User),
		logger: logger,
	}

	// Initialize MFA provider
	if config.EnableMFA && config.MFA != nil {
		mfaProvider, err := NewMFAProvider(config.MFA, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize MFA provider: %w", err)
		}
		am.mfaProvider = mfaProvider
	}

	// Initialize OIDC provider
	if config.EnableOIDC && config.OIDC != nil {
		oidcProvider, err := NewOIDCProvider(config.OIDC, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize OIDC provider: %w", err)
		}
		am.oidcProvider = oidcProvider
	}

	// Initialize LDAP provider
	if config.EnableLDAP && config.LDAP != nil {
		ldapProvider, err := NewLDAPProvider(config.LDAP, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize LDAP provider: %w", err)
		}
		am.ldapProvider = ldapProvider
	}

	return am, nil
}

// AuthenticateResult authentication result
type AuthenticateResult struct {
	User         *User                  `json:"user"`
	RequiresMFA  bool                   `json:"requires_mfa"`
	MFAChallenge *TOTPData              `json:"mfa_challenge,omitempty"`
	Source       string                 `json:"source"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	SessionID    string                 `json:"session_id,omitempty"`
}

// AuthenticateUser authenticates user with multiple provider support
func (am *AuthManager) AuthenticateUser(username, password string) (*AuthenticateResult, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	// Try LDAP authentication
	if am.ldapProvider != nil {
		if result, err := am.ldapProvider.Authenticate(username, password); err == nil && result.Success {
			user := &User{
				ID:        result.User.Username,
				Username:  result.User.Username,
				CreatedAt: time.Now(),
				LastLogin: time.Now(),
				IsActive:  true,
				Roles:     result.User.Groups,
				Source:    "ldap",
				Metadata: map[string]interface{}{
					"email":        result.User.Email,
					"display_name": result.User.DisplayName,
					"is_admin":     result.User.IsAdmin,
				},
			}

			authResult := &AuthenticateResult{
				User:   user,
				Source: "ldap",
				Metadata: map[string]interface{}{
					"ldap_groups": result.User.Groups,
					"is_admin":    result.User.IsAdmin,
				},
			}

			// Check MFA requirement
			if am.mfaProvider != nil && am.mfaProvider.IsRequired(username) {
				authResult.RequiresMFA = true
			}

			return authResult, nil
		}
	}

	// Local authentication
	user, exists := am.users[username]
	if !exists {
		return nil, fmt.Errorf("user not found: %s", username)
	}

	if !user.IsActive {
		return nil, fmt.Errorf("user is inactive: %s", username)
	}

	if !am.verifyPassword(password, user.PasswordHash, user.Salt) {
		return nil, fmt.Errorf("invalid password for user: %s", username)
	}

	// Update last login time
	user.LastLogin = time.Now()

	authResult := &AuthenticateResult{
		User:   user,
		Source: "local",
	}

	// Check MFA requirement
	if am.mfaProvider != nil && am.mfaProvider.IsRequired(username) {
		authResult.RequiresMFA = true
	}

	return authResult, nil
}

// ValidateMFA validates MFA code
func (am *AuthManager) ValidateMFA(username, code string) (*MFAValidationResult, error) {
	if am.mfaProvider == nil {
		return nil, fmt.Errorf("MFA is not enabled")
	}
	return am.mfaProvider.ValidateMFA(username, code)
}

// SetupMFA sets up MFA for user
func (am *AuthManager) SetupMFA(username, accountName string) (*TOTPData, error) {
	if am.mfaProvider == nil {
		return nil, fmt.Errorf("MFA is not enabled")
	}
	return am.mfaProvider.SetupTOTP(username, accountName)
}

// VerifyMFASetup verifies and activates MFA
func (am *AuthManager) VerifyMFASetup(username, code string) error {
	if am.mfaProvider == nil {
		return fmt.Errorf("MFA is not enabled")
	}
	return am.mfaProvider.VerifyTOTPSetup(username, code)
}

// GetOIDCAuthURL gets URL for OIDC authentication
func (am *AuthManager) GetOIDCAuthURL(userID string) (string, error) {
	if am.oidcProvider == nil {
		return "", fmt.Errorf("OIDC is not enabled")
	}
	return am.oidcProvider.GetAuthorizationURL(userID)
}

// HandleOIDCCallback handles OIDC callback
func (am *AuthManager) HandleOIDCCallback(code, state string) (*OIDCSession, error) {
	if am.oidcProvider == nil {
		return nil, fmt.Errorf("OIDC is not enabled")
	}
	return am.oidcProvider.HandleCallback(code, state)
}

// GetLDAPUser gets user information from LDAP
func (am *AuthManager) GetLDAPUser(username string) (*LDAPUser, error) {
	if am.ldapProvider == nil {
		return nil, fmt.Errorf("LDAP is not enabled")
	}
	return am.ldapProvider.GetUser(username)
}

// GetMFAStatus returns MFA status for user
func (am *AuthManager) GetMFAStatus(username string) map[string]interface{} {
	if am.mfaProvider == nil {
		return map[string]interface{}{"enabled": false}
	}
	return am.mfaProvider.GetUserMFAStatus(username)
}

// generateSalt generates random salt
func (am *AuthManager) generateSalt() (string, error) {
	salt := make([]byte, am.config.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return hex.EncodeToString(salt), nil
}

// hashPassword hashes password using specified method
func (am *AuthManager) hashPassword(password, salt string) (string, error) {
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		return "", err
	}

	var hash []byte

	switch am.config.HashMethod {
	case "argon2":
		hash = argon2.IDKey(
			[]byte(password),
			saltBytes,
			am.config.Argon2Time,
			am.config.Argon2Memory,
			am.config.Argon2Threads,
			am.config.Argon2KeyLength,
		)
	case "pbkdf2":
		hash = pbkdf2.Key(
			[]byte(password),
			saltBytes,
			am.config.PBKDF2Iterations,
			am.config.PBKDF2KeyLength,
			sha256.New,
		)
	default:
		return "", fmt.Errorf("unsupported hash method: %s", am.config.HashMethod)
	}

	return hex.EncodeToString(hash), nil
}

// verifyPassword verifies password against hash
func (am *AuthManager) verifyPassword(password, hash, salt string) bool {
	expectedHash, err := am.hashPassword(password, salt)
	if err != nil {
		return false
	}

	// Use constant-time comparison to protect against timing attacks
	return subtle.ConstantTimeCompare([]byte(hash), []byte(expectedHash)) == 1
}

// CreateUser creates new user
func (am *AuthManager) CreateUser(username, password string) (*User, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	if _, exists := am.users[username]; exists {
		return nil, fmt.Errorf("user already exists: %s", username)
	}

	salt, err := am.generateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	hash, err := am.hashPassword(password, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %v", err)
	}

	user := &User{
		ID:           generateUserID(),
		Username:     username,
		PasswordHash: hash,
		Salt:         salt,
		CreatedAt:    time.Now(),
		IsActive:     true,
		Roles:        []string{"user"},
		Source:       "local",
		Metadata:     make(map[string]interface{}),
	}

	am.users[username] = user
	return user, nil
}

// GetUser returns user by username
func (am *AuthManager) GetUser(username string) (*User, bool) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	user, exists := am.users[username]
	return user, exists
}

// UpdatePassword updates user password
func (am *AuthManager) UpdatePassword(username, newPassword string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	user, exists := am.users[username]
	if !exists {
		return fmt.Errorf("user not found: %s", username)
	}

	salt, err := am.generateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %v", err)
	}

	hash, err := am.hashPassword(newPassword, salt)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	user.PasswordHash = hash
	user.Salt = salt

	return nil
}

// DeleteUser deletes user
func (am *AuthManager) DeleteUser(username string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if _, exists := am.users[username]; !exists {
		return fmt.Errorf("user not found: %s", username)
	}

	delete(am.users, username)
	return nil
}

// SetUserActive activates/deactivates user
func (am *AuthManager) SetUserActive(username string, active bool) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	user, exists := am.users[username]
	if !exists {
		return fmt.Errorf("user not found: %s", username)
	}

	user.IsActive = active
	return nil
}

// AddUserRole adds role to user
func (am *AuthManager) AddUserRole(username, role string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	user, exists := am.users[username]
	if !exists {
		return fmt.Errorf("user not found: %s", username)
	}

	// Check if role is not already added
	for _, existingRole := range user.Roles {
		if existingRole == role {
			return nil // Role already exists
		}
	}

	user.Roles = append(user.Roles, role)
	return nil
}

// RemoveUserRole removes role from user
func (am *AuthManager) RemoveUserRole(username, role string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	user, exists := am.users[username]
	if !exists {
		return fmt.Errorf("user not found: %s", username)
	}

	for i, existingRole := range user.Roles {
		if existingRole == role {
			user.Roles = append(user.Roles[:i], user.Roles[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("role not found: %s", role)
}

// ListUsers returns list of all users
func (am *AuthManager) ListUsers() map[string]*User {
	am.mu.RLock()
	defer am.mu.RUnlock()

	users := make(map[string]*User)
	for username, user := range am.users {
		users[username] = user
	}
	return users
}

// Close closes all providers
func (am *AuthManager) Close() error {
	if am.ldapProvider != nil {
		if err := am.ldapProvider.Close(); err != nil {
			return fmt.Errorf("failed to close LDAP provider: %w", err)
		}
	}
	return nil
}

// generateUserID generates unique user ID
func generateUserID() string {
	id := make([]byte, 16)
	_, _ = rand.Read(id) // Ignore error as crypto/rand doesn't return errors under normal conditions
	return hex.EncodeToString(id)
}
