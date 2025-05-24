package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"image"
	"image/png"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

// MFAConfig configuration for multi-factor authentication using standard libraries
type MFAConfig struct {
	Enabled          bool          `json:"enabled"`
	RequiredForAll   bool          `json:"required_for_all"`
	TOTPEnabled      bool          `json:"totp_enabled"`
	HOTPEnabled      bool          `json:"hotp_enabled"`
	BackupCodesCount int           `json:"backup_codes_count"`
	TOTPSettings     TOTPSettings  `json:"totp_settings"`
	HOTPSettings     HOTPSettings  `json:"hotp_settings"`
	Issuer           string        `json:"issuer"`
	AccountName      string        `json:"account_name"`
	GracePeriod      time.Duration `json:"grace_period"`
	MaxAttempts      int           `json:"max_attempts"`
	LockoutDuration  time.Duration `json:"lockout_duration"`
}

// TOTPSettings settings for Time-based OTP using standard library
type TOTPSettings struct {
	Period    uint          `json:"period"`    // Code validity period in seconds (standard library uses uint)
	Digits    otp.Digits    `json:"digits"`    // Number of digits in code (using standard library type)
	Algorithm otp.Algorithm `json:"algorithm"` // SHA1, SHA256, SHA512 (using standard library type)
	Skew      uint          `json:"skew"`      // Allowed time deviation
}

// HOTPSettings settings for HMAC-based OTP using standard library
type HOTPSettings struct {
	Digits    otp.Digits    `json:"digits"`    // Number of digits in code (using standard library type)
	Algorithm otp.Algorithm `json:"algorithm"` // SHA1, SHA256, SHA512 (using standard library type)
	Lookahead int           `json:"lookahead"` // Number of attempts ahead
}

// MFAProvider multi-factor authentication provider using standard libraries
type MFAProvider struct {
	config   *MFAConfig
	logger   Logger
	mu       sync.RWMutex
	userMFA  map[string]*UserMFAData
	attempts map[string]*AttemptCounter
}

// UserMFAData MFA data for user
type UserMFAData struct {
	UserID        string    `json:"user_id"`
	TOTPSecret    string    `json:"totp_secret,omitempty"` // Secret from standard library
	HOTPSecret    string    `json:"hotp_secret,omitempty"` // Secret from standard library
	HOTPCounter   uint64    `json:"hotp_counter"`
	BackupCodes   []string  `json:"backup_codes,omitempty"`
	IsEnabled     bool      `json:"is_enabled"`
	SetupComplete bool      `json:"setup_complete"`
	CreatedAt     time.Time `json:"created_at"`
	LastUsed      time.Time `json:"last_used"`
	DeviceName    string    `json:"device_name,omitempty"`
	TOTPKey       *otp.Key  `json:"-"` // The key object from standard library (not serialized)
	HOTPKey       *otp.Key  `json:"-"` // The HOTP key object (not serialized)
}

// AttemptCounter attempt counter for brute force protection
type AttemptCounter struct {
	UserID      string    `json:"user_id"`
	Attempts    int       `json:"attempts"`
	LastAttempt time.Time `json:"last_attempt"`
	LockedUntil time.Time `json:"locked_until"`
}

// TOTPData data for TOTP setup using standard library
type TOTPData struct {
	Secret      string   `json:"secret"`  // Base32 encoded secret
	QRCode      string   `json:"qr_code"` // Base64 encoded QR code image (PNG)
	URL         string   `json:"url"`     // Standard otpauth:// URL
	BackupCodes []string `json:"backup_codes"`
	Key         *otp.Key `json:"-"` // The actual key object (not serialized)
}

// MFAValidationResult MFA validation result
type MFAValidationResult struct {
	Valid          bool   `json:"valid"`
	Method         string `json:"method"` // totp, hotp, backup
	RemainingCodes int    `json:"remaining_codes,omitempty"`
	Error          string `json:"error,omitempty"`
}

// NewMFAProvider creates new MFA provider using standard libraries
func NewMFAProvider(config *MFAConfig, logger Logger) (*MFAProvider, error) {
	if config == nil {
		config = &MFAConfig{
			Enabled: false,
		}
	}

	// Set default values using standard library defaults
	if config.BackupCodesCount == 0 {
		config.BackupCodesCount = 10
	}

	if config.TOTPSettings.Period == 0 {
		config.TOTPSettings.Period = 30 // Standard TOTP period
	}
	if config.TOTPSettings.Digits == 0 {
		config.TOTPSettings.Digits = otp.DigitsSix // Standard library default
	}
	if config.TOTPSettings.Algorithm == 0 {
		config.TOTPSettings.Algorithm = otp.AlgorithmSHA1 // Standard library default
	}
	if config.TOTPSettings.Skew == 0 {
		config.TOTPSettings.Skew = 1
	}

	if config.HOTPSettings.Digits == 0 {
		config.HOTPSettings.Digits = otp.DigitsSix // Standard library default
	}
	if config.HOTPSettings.Algorithm == 0 {
		config.HOTPSettings.Algorithm = otp.AlgorithmSHA1 // Standard library default
	}
	if config.HOTPSettings.Lookahead == 0 {
		config.HOTPSettings.Lookahead = 10
	}

	if config.Issuer == "" {
		config.Issuer = "GoVPN"
	}

	if config.GracePeriod == 0 {
		config.GracePeriod = 5 * time.Minute
	}

	if config.MaxAttempts == 0 {
		config.MaxAttempts = 5
	}

	if config.LockoutDuration == 0 {
		config.LockoutDuration = 15 * time.Minute
	}

	provider := &MFAProvider{
		config:   config,
		logger:   logger,
		userMFA:  make(map[string]*UserMFAData),
		attempts: make(map[string]*AttemptCounter),
	}

	// Start goroutine for cleaning old attempts
	go provider.cleanupAttempts()

	logger.Printf("Initialized MFA provider using standard libraries (github.com/pquerna/otp)")
	return provider, nil
}

// SetupTOTP sets up TOTP for user using standard library
func (m *MFAProvider) SetupTOTP(userID, accountName string) (*TOTPData, error) {
	if !m.config.Enabled || !m.config.TOTPEnabled {
		return nil, fmt.Errorf("TOTP is disabled")
	}

	// Use standard library to generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      m.config.Issuer,
		AccountName: accountName,
		Period:      m.config.TOTPSettings.Period,
		Digits:      m.config.TOTPSettings.Digits,
		Algorithm:   m.config.TOTPSettings.Algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	// Generate backup codes
	backupCodes, err := m.generateBackupCodes(m.config.BackupCodesCount)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Generate QR code using standard library
	qrImage, err := key.Image(256, 256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR image: %w", err)
	}

	// Convert image to base64 PNG
	qrBase64, err := m.imageToBase64PNG(qrImage)
	if err != nil {
		return nil, fmt.Errorf("failed to encode QR image: %w", err)
	}

	// Save user data (but don't activate yet)
	m.mu.Lock()
	m.userMFA[userID] = &UserMFAData{
		UserID:        userID,
		TOTPSecret:    key.Secret(),
		BackupCodes:   backupCodes,
		IsEnabled:     false,
		SetupComplete: false,
		CreatedAt:     time.Now(),
		DeviceName:    "TOTP Device",
		TOTPKey:       key,
	}
	m.mu.Unlock()

	m.logger.Printf("TOTP setup initiated for user: %s using standard library", userID)

	return &TOTPData{
		Secret:      key.Secret(),
		QRCode:      qrBase64,
		URL:         key.URL(),
		BackupCodes: backupCodes,
		Key:         key,
	}, nil
}

// VerifyTOTPSetup verifies TOTP setup with user-provided code using standard library
func (m *MFAProvider) VerifyTOTPSetup(userID, code string) error {
	m.mu.Lock()
	userData, exists := m.userMFA[userID]
	m.mu.Unlock()

	if !exists {
		return fmt.Errorf("TOTP setup not found for user")
	}

	if userData.SetupComplete {
		return fmt.Errorf("TOTP setup already completed")
	}

	// Use standard library for validation
	valid := totp.Validate(code, userData.TOTPSecret)
	if !valid {
		return fmt.Errorf("invalid TOTP code")
	}

	// Activate TOTP
	m.mu.Lock()
	userData.IsEnabled = true
	userData.SetupComplete = true
	userData.LastUsed = time.Now()
	m.mu.Unlock()

	m.logger.Printf("TOTP setup completed for user: %s", userID)
	return nil
}

// SetupHOTP sets up HOTP for user using standard library
func (m *MFAProvider) SetupHOTP(userID, accountName string) (*TOTPData, error) {
	if !m.config.Enabled || !m.config.HOTPEnabled {
		return nil, fmt.Errorf("HOTP is disabled")
	}

	// Use standard library to generate HOTP key
	key, err := hotp.Generate(hotp.GenerateOpts{
		Issuer:      m.config.Issuer,
		AccountName: accountName,
		Digits:      m.config.HOTPSettings.Digits,
		Algorithm:   m.config.HOTPSettings.Algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate HOTP key: %w", err)
	}

	// Generate backup codes
	backupCodes, err := m.generateBackupCodes(m.config.BackupCodesCount)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Generate QR code
	qrImage, err := key.Image(256, 256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR image: %w", err)
	}

	// Convert image to base64 PNG
	qrBase64, err := m.imageToBase64PNG(qrImage)
	if err != nil {
		return nil, fmt.Errorf("failed to encode QR image: %w", err)
	}

	// Save user data
	m.mu.Lock()
	m.userMFA[userID] = &UserMFAData{
		UserID:        userID,
		HOTPSecret:    key.Secret(),
		HOTPCounter:   0,
		BackupCodes:   backupCodes,
		IsEnabled:     false,
		SetupComplete: false,
		CreatedAt:     time.Now(),
		DeviceName:    "HOTP Device",
		HOTPKey:       key,
	}
	m.mu.Unlock()

	m.logger.Printf("HOTP setup initiated for user: %s using standard library", userID)

	return &TOTPData{
		Secret:      key.Secret(),
		QRCode:      qrBase64,
		URL:         key.URL(),
		BackupCodes: backupCodes,
		Key:         key,
	}, nil
}

// ValidateMFA validates MFA code using standard libraries
func (m *MFAProvider) ValidateMFA(userID, code string) (*MFAValidationResult, error) {
	if !m.config.Enabled {
		return &MFAValidationResult{Valid: false, Error: "MFA is disabled"}, nil
	}

	// Check if user is locked out
	if m.isUserLocked(userID) {
		return &MFAValidationResult{Valid: false, Error: "user is temporarily locked out"}, nil
	}

	m.mu.RLock()
	userData, exists := m.userMFA[userID]
	m.mu.RUnlock()

	if !exists || !userData.IsEnabled {
		return &MFAValidationResult{Valid: false, Error: "MFA not set up for user"}, nil
	}

	// Try TOTP validation using standard library
	if userData.TOTPSecret != "" {
		if totp.Validate(code, userData.TOTPSecret) {
			m.clearFailedAttempts(userID)
			m.mu.Lock()
			userData.LastUsed = time.Now()
			m.mu.Unlock()
			return &MFAValidationResult{Valid: true, Method: "totp"}, nil
		}
	}

	// Try HOTP validation using standard library
	if userData.HOTPSecret != "" {
		for i := 0; i < m.config.HOTPSettings.Lookahead; i++ {
			testCounter := userData.HOTPCounter + uint64(i)
			valid, err := hotp.ValidateCustom(code, testCounter, userData.HOTPSecret, hotp.ValidateOpts{
				Digits:    m.config.HOTPSettings.Digits,
				Algorithm: m.config.HOTPSettings.Algorithm,
			})
			if err == nil && valid {
				m.clearFailedAttempts(userID)
				m.mu.Lock()
				userData.HOTPCounter = testCounter + 1
				userData.LastUsed = time.Now()
				m.mu.Unlock()
				return &MFAValidationResult{Valid: true, Method: "hotp"}, nil
			}
		}
	}

	// Try backup codes
	if valid, remaining := m.validateBackupCode(userData, code); valid {
		m.clearFailedAttempts(userID)
		return &MFAValidationResult{Valid: true, Method: "backup", RemainingCodes: remaining}, nil
	}

	// All validation failed
	m.recordFailedAttempt(userID)
	return &MFAValidationResult{Valid: false, Error: "invalid MFA code"}, nil
}

// IsRequired checks if MFA is required for user
func (m *MFAProvider) IsRequired(userID string) bool {
	if !m.config.Enabled {
		return false
	}

	if m.config.RequiredForAll {
		return true
	}

	m.mu.RLock()
	userData, exists := m.userMFA[userID]
	m.mu.RUnlock()

	return exists && userData.IsEnabled
}

// IsSetup checks if MFA is set up for user
func (m *MFAProvider) IsSetup(userID string) bool {
	m.mu.RLock()
	userData, exists := m.userMFA[userID]
	m.mu.RUnlock()

	return exists && userData.SetupComplete
}

// DisableMFA disables MFA for user
func (m *MFAProvider) DisableMFA(userID string) error {
	m.mu.Lock()
	userData, exists := m.userMFA[userID]
	if exists {
		userData.IsEnabled = false
		userData.SetupComplete = false
	}
	m.mu.Unlock()

	if !exists {
		return fmt.Errorf("MFA not found for user")
	}

	m.logger.Printf("MFA disabled for user: %s", userID)
	return nil
}

// GetUserMFAStatus returns MFA status for user
func (m *MFAProvider) GetUserMFAStatus(userID string) map[string]interface{} {
	m.mu.RLock()
	userData, exists := m.userMFA[userID]
	m.mu.RUnlock()

	status := map[string]interface{}{
		"enabled":        false,
		"setup_complete": false,
		"totp_enabled":   false,
		"hotp_enabled":   false,
		"backup_codes":   0,
		"last_used":      nil,
		"device_name":    "",
	}

	if exists {
		status["enabled"] = userData.IsEnabled
		status["setup_complete"] = userData.SetupComplete
		status["totp_enabled"] = userData.TOTPSecret != ""
		status["hotp_enabled"] = userData.HOTPSecret != ""
		status["backup_codes"] = len(userData.BackupCodes)
		status["device_name"] = userData.DeviceName
		if !userData.LastUsed.IsZero() {
			status["last_used"] = userData.LastUsed
		}
	}

	return status
}

// RegenerateBackupCodes regenerates backup codes for user
func (m *MFAProvider) RegenerateBackupCodes(userID string) ([]string, error) {
	m.mu.Lock()
	userData, exists := m.userMFA[userID]
	m.mu.Unlock()

	if !exists {
		return nil, fmt.Errorf("MFA not found for user")
	}

	newCodes, err := m.generateBackupCodes(m.config.BackupCodesCount)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	m.mu.Lock()
	userData.BackupCodes = newCodes
	m.mu.Unlock()

	m.logger.Printf("Backup codes regenerated for user: %s", userID)
	return newCodes, nil
}

// Private helper methods

// generateBackupCodes generates cryptographically secure backup codes
func (m *MFAProvider) generateBackupCodes(count int) ([]string, error) {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		// Generate 8 random bytes (64 bits)
		bytes := make([]byte, 8)
		if _, err := rand.Read(bytes); err != nil {
			return nil, err
		}
		// Encode as base32 and take first 8 characters
		code := base64.RawURLEncoding.EncodeToString(bytes)[:8]
		codes[i] = strings.ToUpper(code)
	}
	return codes, nil
}

// imageToBase64PNG converts image.Image to base64 encoded PNG
func (m *MFAProvider) imageToBase64PNG(img image.Image) (string, error) {
	// Create a buffer to store PNG bytes
	var buf bytes.Buffer

	// Encode image as PNG
	if err := png.Encode(&buf, img); err != nil {
		return "", fmt.Errorf("failed to encode image as PNG: %w", err)
	}

	// Encode to base64
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// validateBackupCode validates backup code
func (m *MFAProvider) validateBackupCode(userData *UserMFAData, code string) (bool, int) {
	code = strings.ToUpper(strings.TrimSpace(code))

	for i, backupCode := range userData.BackupCodes {
		if backupCode == code {
			// Remove used backup code
			userData.BackupCodes = append(userData.BackupCodes[:i], userData.BackupCodes[i+1:]...)
			return true, len(userData.BackupCodes)
		}
	}
	return false, len(userData.BackupCodes)
}

// isUserLocked checks if user is locked out
func (m *MFAProvider) isUserLocked(userID string) bool {
	m.mu.RLock()
	attempt, exists := m.attempts[userID]
	m.mu.RUnlock()

	if !exists {
		return false
	}

	return time.Now().Before(attempt.LockedUntil)
}

// recordFailedAttempt records failed MFA attempt
func (m *MFAProvider) recordFailedAttempt(userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	attempt, exists := m.attempts[userID]
	if !exists {
		attempt = &AttemptCounter{UserID: userID}
		m.attempts[userID] = attempt
	}

	attempt.Attempts++
	attempt.LastAttempt = time.Now()

	if attempt.Attempts >= m.config.MaxAttempts {
		attempt.LockedUntil = time.Now().Add(m.config.LockoutDuration)
		m.logger.Printf("User %s locked out for %v after %d failed attempts",
			userID, m.config.LockoutDuration, attempt.Attempts)
	}
}

// clearFailedAttempts clears failed attempts for user
func (m *MFAProvider) clearFailedAttempts(userID string) {
	m.mu.Lock()
	delete(m.attempts, userID)
	m.mu.Unlock()
}

// cleanupAttempts periodically cleans up old attempt records
func (m *MFAProvider) cleanupAttempts() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for userID, attempt := range m.attempts {
			// Clean up attempts older than lockout duration
			if now.After(attempt.LockedUntil) && now.Sub(attempt.LastAttempt) > m.config.LockoutDuration {
				delete(m.attempts, userID)
			}
		}
		m.mu.Unlock()
	}
}
