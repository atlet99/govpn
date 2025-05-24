package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TestNewMFAProvider tests MFA provider creation with different configurations
func TestNewMFAProvider(t *testing.T) {
	logger := NewTestLogger()

	tests := []struct {
		name      string
		config    *MFAConfig
		expectErr bool
	}{
		{
			name: "default configuration",
			config: &MFAConfig{
				Enabled:          true,
				TOTPEnabled:      true,
				BackupCodesCount: 10,
				TOTPSettings: TOTPSettings{
					Period:    30,
					Digits:    otp.DigitsSix,
					Algorithm: otp.AlgorithmSHA1,
					Skew:      1,
				},
				Issuer:          "GoVPN Test",
				MaxAttempts:     5,
				LockoutDuration: 15 * time.Minute,
			},
			expectErr: false,
		},
		{
			name:      "nil configuration",
			config:    nil,
			expectErr: false, // Should use defaults
		},
		{
			name: "disabled MFA",
			config: &MFAConfig{
				Enabled: false,
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewMFAProvider(tt.config, logger)
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

// TestMFATOTPSetup tests TOTP setup using standard library
func TestMFATOTPSetup(t *testing.T) {
	config := &MFAConfig{
		Enabled:          true,
		TOTPEnabled:      true,
		BackupCodesCount: 10,
		TOTPSettings: TOTPSettings{
			Period:    30,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
			Skew:      1,
		},
		Issuer: "GoVPN Test",
	}

	provider, err := NewMFAProvider(config, NewTestLogger())
	if err != nil {
		t.Fatalf("failed to create MFA provider: %v", err)
	}

	userID := "test-user"
	email := "test@example.com"

	// Test TOTP setup
	totpData, err := provider.SetupTOTP(userID, email)
	if err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}

	// Verify TOTP data structure
	if totpData.Secret == "" {
		t.Error("TOTP secret should not be empty")
	}
	if totpData.URL == "" {
		t.Error("TOTP URL should not be empty")
	}
	if totpData.QRCode == "" {
		t.Error("QR code should not be empty")
	}
	if len(totpData.BackupCodes) != config.BackupCodesCount {
		t.Errorf("expected %d backup codes, got %d", config.BackupCodesCount, len(totpData.BackupCodes))
	}
	if totpData.Key == nil {
		t.Error("TOTP key should not be nil")
	}

	// Verify URL format (should be otpauth://)
	if len(totpData.URL) < 10 || totpData.URL[:10] != "otpauth://" {
		t.Errorf("invalid TOTP URL format: %s", totpData.URL)
	}

	// Test setup verification with valid code
	validCode, err := totp.GenerateCode(totpData.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}

	err = provider.VerifyTOTPSetup(userID, validCode)
	if err != nil {
		t.Errorf("failed to verify TOTP setup with valid code: %v", err)
	}

	// Test setup verification with invalid code
	err = provider.VerifyTOTPSetup(userID, "000000")
	if err == nil {
		t.Error("should fail verification with invalid code")
	}
}

// TestMFATOTPValidation tests TOTP validation using standard library
func TestMFATOTPValidation(t *testing.T) {
	config := &MFAConfig{
		Enabled:     true,
		TOTPEnabled: true,
		TOTPSettings: TOTPSettings{
			Period:    30,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
			Skew:      1,
		},
		Issuer:      "GoVPN Test",
		MaxAttempts: 3,
	}

	provider, err := NewMFAProvider(config, NewTestLogger())
	if err != nil {
		t.Fatalf("failed to create MFA provider: %v", err)
	}

	userID := "test-user"
	email := "test@example.com"

	// Setup TOTP
	totpData, err := provider.SetupTOTP(userID, email)
	if err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}

	// Complete setup
	validCode, err := totp.GenerateCode(totpData.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}

	err = provider.VerifyTOTPSetup(userID, validCode)
	if err != nil {
		t.Fatalf("failed to verify TOTP setup: %v", err)
	}

	// Test validation with current valid code
	currentCode, err := totp.GenerateCode(totpData.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate current TOTP code: %v", err)
	}

	result, err := provider.ValidateMFA(userID, currentCode)
	if err != nil {
		t.Fatalf("failed to validate MFA: %v", err)
	}

	if !result.Valid {
		t.Error("MFA validation should succeed with valid code")
	}
	if result.Method != "totp" {
		t.Errorf("expected method 'totp', got '%s'", result.Method)
	}

	// Test validation with invalid code
	result, err = provider.ValidateMFA(userID, "000000")
	if err != nil {
		t.Fatalf("failed to validate MFA with invalid code: %v", err)
	}

	if result.Valid {
		t.Error("MFA validation should fail with invalid code")
	}
}

// TestMFABackupCodes tests backup code functionality
func TestMFABackupCodes(t *testing.T) {
	config := &MFAConfig{
		Enabled:          true,
		TOTPEnabled:      true,
		BackupCodesCount: 5,
		TOTPSettings: TOTPSettings{
			Period:    30,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
		Issuer: "GoVPN Test",
	}

	provider, err := NewMFAProvider(config, NewTestLogger())
	if err != nil {
		t.Fatalf("failed to create MFA provider: %v", err)
	}

	userID := "test-user"
	email := "test@example.com"

	// Setup TOTP
	totpData, err := provider.SetupTOTP(userID, email)
	if err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}

	// Complete setup
	validCode, err := totp.GenerateCode(totpData.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}

	err = provider.VerifyTOTPSetup(userID, validCode)
	if err != nil {
		t.Fatalf("failed to verify TOTP setup: %v", err)
	}

	// Test backup code validation
	if len(totpData.BackupCodes) == 0 {
		t.Fatal("should have backup codes")
	}

	backupCode := totpData.BackupCodes[0]
	result, err := provider.ValidateMFA(userID, backupCode)
	if err != nil {
		t.Fatalf("failed to validate backup code: %v", err)
	}

	if !result.Valid {
		t.Error("backup code validation should succeed")
	}
	if result.Method != "backup" {
		t.Errorf("expected method 'backup', got '%s'", result.Method)
	}
	if result.RemainingCodes != len(totpData.BackupCodes)-1 {
		t.Errorf("expected %d remaining codes, got %d", len(totpData.BackupCodes)-1, result.RemainingCodes)
	}

	// Test using same backup code again (should fail)
	result, err = provider.ValidateMFA(userID, backupCode)
	if err != nil {
		t.Fatalf("failed to validate used backup code: %v", err)
	}

	if result.Valid {
		t.Error("used backup code should not validate again")
	}

	// Test regenerating backup codes
	newCodes, err := provider.RegenerateBackupCodes(userID)
	if err != nil {
		t.Fatalf("failed to regenerate backup codes: %v", err)
	}

	if len(newCodes) != config.BackupCodesCount {
		t.Errorf("expected %d new backup codes, got %d", config.BackupCodesCount, len(newCodes))
	}

	// Verify new codes are different from original
	for _, newCode := range newCodes {
		for _, oldCode := range totpData.BackupCodes {
			if newCode == oldCode {
				t.Error("new backup codes should be different from old ones")
			}
		}
	}
}

// TestMFABruteForceProtection tests rate limiting and lockout functionality
func TestMFABruteForceProtection(t *testing.T) {
	config := &MFAConfig{
		Enabled:     true,
		TOTPEnabled: true,
		TOTPSettings: TOTPSettings{
			Period:    30,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
		Issuer:          "GoVPN Test",
		MaxAttempts:     3,
		LockoutDuration: 1 * time.Second, // Short lockout for testing
	}

	provider, err := NewMFAProvider(config, NewTestLogger())
	if err != nil {
		t.Fatalf("failed to create MFA provider: %v", err)
	}

	userID := "test-user"
	email := "test@example.com"

	// Setup and verify TOTP
	totpData, err := provider.SetupTOTP(userID, email)
	if err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}

	validCode, err := totp.GenerateCode(totpData.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}

	err = provider.VerifyTOTPSetup(userID, validCode)
	if err != nil {
		t.Fatalf("failed to verify TOTP setup: %v", err)
	}

	// Make multiple failed attempts
	for i := 0; i < config.MaxAttempts; i++ {
		result, err := provider.ValidateMFA(userID, "000000")
		if err != nil {
			t.Fatalf("failed to validate MFA attempt %d: %v", i+1, err)
		}
		if result.Valid {
			t.Errorf("attempt %d should fail with invalid code", i+1)
		}
	}

	// Next attempt should be locked out
	result, err := provider.ValidateMFA(userID, "000000")
	if err != nil {
		t.Fatalf("failed to validate MFA during lockout: %v", err)
	}
	if result.Valid {
		t.Error("should be locked out after max attempts")
	}
	if result.Error != "user is temporarily locked out" {
		t.Errorf("expected lockout error, got: %s", result.Error)
	}

	// Wait for lockout to expire
	time.Sleep(config.LockoutDuration + 100*time.Millisecond)

	// Should be able to attempt again
	currentCode, err := totp.GenerateCode(totpData.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate current TOTP code: %v", err)
	}

	result, err = provider.ValidateMFA(userID, currentCode)
	if err != nil {
		t.Fatalf("failed to validate MFA after lockout: %v", err)
	}
	if !result.Valid {
		t.Error("should be able to validate after lockout expires")
	}
}

// TestMFAStatus tests MFA status reporting
func TestMFAStatus(t *testing.T) {
	config := &MFAConfig{
		Enabled:     true,
		TOTPEnabled: true,
		TOTPSettings: TOTPSettings{
			Period:    30,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
		Issuer: "GoVPN Test",
	}

	provider, err := NewMFAProvider(config, NewTestLogger())
	if err != nil {
		t.Fatalf("failed to create MFA provider: %v", err)
	}

	userID := "test-user"

	// Check initial status
	status := provider.GetUserMFAStatus(userID)
	if status["enabled"].(bool) {
		t.Error("MFA should not be enabled initially")
	}
	if status["setup_complete"].(bool) {
		t.Error("setup should not be complete initially")
	}

	// Setup TOTP
	totpData, err := provider.SetupTOTP(userID, "test@example.com")
	if err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}

	// Check status after setup but before verification
	status = provider.GetUserMFAStatus(userID)
	if status["enabled"].(bool) {
		t.Error("MFA should not be enabled before verification")
	}
	if status["setup_complete"].(bool) {
		t.Error("setup should not be complete before verification")
	}

	// Complete setup
	validCode, err := totp.GenerateCode(totpData.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}

	err = provider.VerifyTOTPSetup(userID, validCode)
	if err != nil {
		t.Fatalf("failed to verify TOTP setup: %v", err)
	}

	// Check final status
	status = provider.GetUserMFAStatus(userID)
	if !status["enabled"].(bool) {
		t.Error("MFA should be enabled after verification")
	}
	if !status["setup_complete"].(bool) {
		t.Error("setup should be complete after verification")
	}
	if !status["totp_enabled"].(bool) {
		t.Error("TOTP should be enabled")
	}

	// Test IsRequired and IsSetup methods
	if !provider.IsRequired(userID) {
		t.Error("MFA should be required for user with MFA enabled")
	}
	if !provider.IsSetup(userID) {
		t.Error("MFA should be set up for user")
	}
}

// TestMFADisable tests disabling MFA for a user
func TestMFADisable(t *testing.T) {
	config := &MFAConfig{
		Enabled:     true,
		TOTPEnabled: true,
		TOTPSettings: TOTPSettings{
			Period:    30,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
		Issuer: "GoVPN Test",
	}

	provider, err := NewMFAProvider(config, NewTestLogger())
	if err != nil {
		t.Fatalf("failed to create MFA provider: %v", err)
	}

	userID := "test-user"

	// Setup and verify TOTP
	totpData, err := provider.SetupTOTP(userID, "test@example.com")
	if err != nil {
		t.Fatalf("failed to setup TOTP: %v", err)
	}

	validCode, err := totp.GenerateCode(totpData.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}

	err = provider.VerifyTOTPSetup(userID, validCode)
	if err != nil {
		t.Fatalf("failed to verify TOTP setup: %v", err)
	}

	// Verify MFA is enabled
	if !provider.IsSetup(userID) {
		t.Error("MFA should be set up")
	}

	// Disable MFA
	err = provider.DisableMFA(userID)
	if err != nil {
		t.Fatalf("failed to disable MFA: %v", err)
	}

	// Verify MFA is disabled
	if provider.IsSetup(userID) {
		t.Error("MFA should not be set up after disabling")
	}

	status := provider.GetUserMFAStatus(userID)
	if status["enabled"].(bool) {
		t.Error("MFA should not be enabled after disabling")
	}
	if status["setup_complete"].(bool) {
		t.Error("setup should not be complete after disabling")
	}
}

// TestMFAWithDisabledProvider tests behavior when MFA is disabled
func TestMFAWithDisabledProvider(t *testing.T) {
	config := &MFAConfig{
		Enabled: false,
	}

	provider, err := NewMFAProvider(config, NewTestLogger())
	if err != nil {
		t.Fatalf("failed to create MFA provider: %v", err)
	}

	userID := "test-user"

	// Attempt to setup TOTP when disabled
	_, err = provider.SetupTOTP(userID, "test@example.com")
	if err == nil {
		t.Error("should not be able to setup TOTP when MFA is disabled")
	}

	// Validation should return not enabled
	result, err := provider.ValidateMFA(userID, "123456")
	if err != nil {
		t.Fatalf("failed to validate MFA when disabled: %v", err)
	}
	if result.Valid {
		t.Error("validation should fail when MFA is disabled")
	}
	if result.Error != "MFA is disabled" {
		t.Errorf("expected 'MFA is disabled' error, got: %s", result.Error)
	}
}

// Helper function to create a test logger
func NewTestLogger() Logger {
	return &testLogger{}
}

type testLogger struct{}

func (l *testLogger) Printf(format string, v ...interface{}) {
	// Silent logger for tests
}

func (l *testLogger) Errorf(format string, v ...interface{}) {
	// Silent logger for tests
}

func (l *testLogger) Infof(format string, v ...interface{}) {
	// Silent logger for tests
}

func (l *testLogger) Debugf(format string, v ...interface{}) {
	// Silent logger for tests
}
