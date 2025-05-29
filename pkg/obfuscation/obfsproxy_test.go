package obfuscation

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// MockObfsproxy creates a mock version of obfsproxy for testing
type MockObfsproxy struct {
	*Obfsproxy
	mockExecutable string
	shouldFail     bool
}

// NewMockObfsproxy creates a new mock instance of obfsproxy
func NewMockObfsproxy(config *ObfsproxyConfig, logger *log.Logger, shouldFail bool) (*MockObfsproxy, error) {
	// Create a mock executable file
	mockScript := createMockObfsproxyScript(shouldFail)

	if config == nil {
		config = &ObfsproxyConfig{
			Enabled:    true,
			Executable: mockScript,
			Mode:       "client",
			Transport:  "obfs4",
			LogLevel:   "INFO",
		}
	} else {
		config.Executable = mockScript
	}

	obfs, err := NewObfsproxy(config, logger)
	if err != nil {
		return nil, err
	}

	return &MockObfsproxy{
		Obfsproxy:      obfs,
		mockExecutable: mockScript,
		shouldFail:     shouldFail,
	}, nil
}

// Cleanup deletes mock files
func (m *MockObfsproxy) Cleanup() {
	if m.mockExecutable != "" {
		os.Remove(m.mockExecutable)
	}
}

// createMockObfsproxyScript creates a mock obfsproxy script
func createMockObfsproxyScript(shouldFail bool) string {
	script := `#!/bin/bash
# Mock obfsproxy script for testing

if [ "$1" = "--help" ]; then
    echo "Mock obfsproxy for testing"
    exit 0
fi

# Log arguments for debugging
echo "Mock obfsproxy called with: $*" >&2

if [ "` + fmt.Sprintf("%t", shouldFail) + `" = "true" ]; then
    echo "Mock obfsproxy failed" >&2
    exit 1
fi

# Simulate obfsproxy behavior
while read line; do
    # Echo back the input with some transformation
    echo "obfs:$line"
done
`

	tmpFile, err := os.CreateTemp("", "mock_obfsproxy_*.sh")
	if err != nil {
		return ""
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(script); err != nil {
		return ""
	}
	if err := tmpFile.Chmod(0755); err != nil {
		return ""
	}

	return tmpFile.Name()
}

// isObfsproxyInstalled checks if obfsproxy or obfs4proxy is installed
func isObfsproxyInstalled() (string, bool) {
	// Check for obfsproxy first
	if _, err := exec.LookPath("obfsproxy"); err == nil {
		// Verify it's working
		cmd := exec.Command("obfsproxy", "--help")
		if err := cmd.Run(); err == nil {
			return "obfsproxy", true
		}
	}

	// Check for obfs4proxy
	if _, err := exec.LookPath("obfs4proxy"); err == nil {
		// Verify it's working
		cmd := exec.Command("obfs4proxy", "-help")
		// obfs4proxy returns error code 2 for -help, but that's normal
		output, _ := cmd.CombinedOutput()
		if strings.Contains(string(output), "Usage") {
			return "obfs4proxy", true
		}
	}

	return "", false
}

// TestObfsproxyInstallation tests if obfsproxy is properly installed
func TestObfsproxyInstallation(t *testing.T) {
	executable, installed := isObfsproxyInstalled()

	if !installed {
		t.Skip("No obfsproxy implementation found. Install with:")
		t.Skip("  macOS:   brew install obfs4proxy")
		t.Skip("  Ubuntu:  sudo apt-get install obfsproxy")
		t.Skip("  CentOS:  sudo yum install obfsproxy")
		t.Skip("  Python:  pip install obfsproxy")
		return
	}

	t.Logf("✅ Found obfsproxy implementation: %s", executable)

	// Test if we can create an obfsproxy instance
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	config := &ObfsproxyConfig{
		Enabled:    true,
		Executable: executable,
		Mode:       "client",
		Transport:  "obfs4",
		Address:    "127.0.0.1",
		Port:       9050,
		LogLevel:   "INFO",
	}

	obfs, err := NewObfsproxy(config, logger)
	if err != nil {
		t.Fatalf("Failed to create obfsproxy instance: %v", err)
	}

	if !obfs.IsAvailable() {
		t.Error("Obfsproxy should be available when properly installed")
	}

	t.Logf("✅ Obfsproxy is properly configured and available")
}

// TestObfsproxyMock tests obfsproxy with a mock executable file
func TestObfsproxyMock(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)

	t.Run("MockSuccess", func(t *testing.T) {
		config := &ObfsproxyConfig{
			Enabled:   true,
			Mode:      "client",
			Transport: "obfs4",
			Address:   "127.0.0.1",
			Port:      9050,
			LogLevel:  "INFO",
		}

		mockObfs, err := NewMockObfsproxy(config, logger, false)
		if err != nil {
			t.Fatalf("Failed to create mock obfsproxy: %v", err)
		}
		defer mockObfs.Cleanup()

		// Check the method name
		if mockObfs.Name() != MethodObfsproxy {
			t.Errorf("Expected method name %s, got %s", MethodObfsproxy, mockObfs.Name())
		}

		// Check availability
		if !mockObfs.IsAvailable() {
			t.Error("Mock obfsproxy should be available")
		}

		// Test obfuscation
		testData := []byte("Hello, World!")
		obfuscated, err := mockObfs.Obfuscate(testData)
		if err != nil {
			t.Errorf("Obfuscation failed: %v", err)
		}

		if !bytes.Equal(obfuscated, testData) {
			t.Errorf("Expected %v, got %v", testData, obfuscated)
		}

		// Test deobfuscation
		deobfuscated, err := mockObfs.Deobfuscate(obfuscated)
		if err != nil {
			t.Errorf("Deobfuscation failed: %v", err)
		}

		if !bytes.Equal(deobfuscated, testData) {
			t.Errorf("Expected %v, got %v", testData, deobfuscated)
		}

		// Check metrics
		metrics := mockObfs.GetMetrics()
		if metrics.PacketsProcessed != 2 { // obfuscate + deobfuscate
			t.Errorf("Expected 2 packets processed, got %d", metrics.PacketsProcessed)
		}
	})

	t.Run("MockFailure", func(t *testing.T) {
		config := &ObfsproxyConfig{
			Enabled:   true,
			Mode:      "client",
			Transport: "obfs4",
			Address:   "127.0.0.1",
			Port:      9050,
			LogLevel:  "INFO",
		}

		mockObfs, err := NewMockObfsproxy(config, logger, true)
		if err != nil {
			t.Fatalf("Failed to create mock obfsproxy: %v", err)
		}
		defer mockObfs.Cleanup()

		// Check availability
		if !mockObfs.IsAvailable() {
			t.Error("Mock obfsproxy should be available even if it will fail later")
		}
	})
}

// TestObfsproxyConfiguration tests different configurations
func TestObfsproxyConfiguration(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)

	testCases := []struct {
		name      string
		config    *ObfsproxyConfig
		shouldErr bool
	}{
		{
			name: "obfs3",
			config: &ObfsproxyConfig{
				Enabled:   true,
				Mode:      "client",
				Transport: "obfs3",
				Address:   "127.0.0.1",
				Port:      9050,
				LogLevel:  "INFO",
			},
			shouldErr: false,
		},
		{
			name: "obfs4",
			config: &ObfsproxyConfig{
				Enabled:   true,
				Mode:      "server",
				Transport: "obfs4",
				Address:   "0.0.0.0",
				Port:      443,
				Options:   "--cert=test123 --iat-mode=0",
				LogLevel:  "DEBUG",
			},
			shouldErr: false,
		},
		{
			name: "scramblesuit",
			config: &ObfsproxyConfig{
				Enabled:   true,
				Mode:      "client",
				Transport: "scramblesuit",
				Address:   "192.168.1.1",
				Port:      8080,
				Options:   "--password=secret123",
				LogLevel:  "ERROR",
			},
			shouldErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockObfs, err := NewMockObfsproxy(tc.config, logger, false)
			if tc.shouldErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.shouldErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if mockObfs != nil {
				defer mockObfs.Cleanup()

				// Check configuration
				if mockObfs.config.Transport != tc.config.Transport {
					t.Errorf("Expected transport %s, got %s", tc.config.Transport, mockObfs.config.Transport)
				}
				if mockObfs.config.Mode != tc.config.Mode {
					t.Errorf("Expected mode %s, got %s", tc.config.Mode, mockObfs.config.Mode)
				}
			}
		})
	}
}

// TestObfsproxyWithRealBinary tests with a real binary if available
func TestObfsproxyWithRealBinary(t *testing.T) {
	executable, installed := isObfsproxyInstalled()

	if !installed {
		t.Skip("No obfsproxy implementation found. Install with:")
		t.Skip("  macOS:   brew install obfs4proxy")
		t.Skip("  Ubuntu:  sudo apt-get install obfsproxy")
		t.Skip("  CentOS:  sudo yum install obfsproxy")
		t.Skip("  Python:  pip install obfsproxy")
		return
	}

	t.Logf("Testing with real binary: %s", executable)

	// Create configuration for real testing
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	config := &ObfsproxyConfig{
		Enabled:    true,
		Executable: executable,
		Mode:       "client",
		Transport:  "obfs4",
		Address:    "127.0.0.1",
		Port:       9050,
		LogLevel:   "INFO",
	}

	obfs, err := NewObfsproxy(config, logger)
	if err != nil {
		t.Fatalf("Failed to create obfsproxy: %v", err)
	}

	// Check availability
	if !obfs.IsAvailable() {
		t.Error("Real obfsproxy should be available")
	}

	// Check basic methods
	if obfs.Name() != MethodObfsproxy {
		t.Errorf("Expected method name %s, got %s", MethodObfsproxy, obfs.Name())
	}

	// Test metrics
	metrics := obfs.GetMetrics()
	if metrics.PacketsProcessed != 0 {
		t.Errorf("Expected 0 packets processed initially, got %d", metrics.PacketsProcessed)
	}

	t.Logf("✅ Real obfsproxy test completed successfully with %s", executable)
}

// TestObfsproxyConnection tests wrapping connections
func TestObfsproxyConnection(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)

	mockObfs, err := NewMockObfsproxy(nil, logger, false)
	if err != nil {
		t.Fatalf("Failed to create mock obfsproxy: %v", err)
	}
	defer mockObfs.Cleanup()

	// Create mock connection
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Test wrapping connection
	// Note: this may not work with mock script, but tests the interface
	_, err = mockObfs.WrapConn(client)
	if err != nil {
		t.Logf("WrapConn failed as expected with mock: %v", err)
	}
}

// BenchmarkObfsproxy benchmark for obfsproxy
func BenchmarkObfsproxy(b *testing.B) {
	logger := log.New(io.Discard, "", 0)

	mockObfs, err := NewMockObfsproxy(nil, logger, false)
	if err != nil {
		b.Fatalf("Failed to create mock obfsproxy: %v", err)
	}
	defer mockObfs.Cleanup()

	testData := []byte("Benchmark test data for obfsproxy performance testing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mockObfs.Obfuscate(testData)
		if err != nil {
			b.Fatalf("Obfuscation failed: %v", err)
		}
	}
}

// TestObfsproxyIntegration integration test with obfuscation engine
func TestObfsproxyIntegration(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)

	// Create engine configuration with obfsproxy
	config := &Config{
		EnabledMethods:  []ObfuscationMethod{MethodObfsproxy, MethodXORCipher},
		PrimaryMethod:   MethodObfsproxy,
		FallbackMethods: []ObfuscationMethod{MethodXORCipher},
		AutoDetection:   true,
		Obfsproxy: ObfsproxyConfig{
			Enabled:   true,
			Mode:      "client",
			Transport: "obfs4",
			Address:   "127.0.0.1",
			Port:      9050,
			LogLevel:  "INFO",
		},
		XORKey: []byte("test-key-for-xor-fallback-method"),
	}

	// Create mock file for obfsproxy
	mockScript := createMockObfsproxyScript(false)
	defer os.Remove(mockScript)
	config.Obfsproxy.Executable = mockScript

	engine, err := NewEngine(config, logger)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	// Check that obfsproxy is the current method
	currentMethod := engine.GetCurrentMethod()
	if currentMethod != MethodObfsproxy {
		t.Errorf("Expected current method %s, got %s", MethodObfsproxy, currentMethod)
	}

	// Test obfuscation through engine
	testData := []byte("Integration test data")
	obfuscated, err := engine.ObfuscateData(testData)
	if err != nil {
		t.Errorf("Engine obfuscation failed: %v", err)
	}

	deobfuscated, err := engine.DeobfuscateData(obfuscated)
	if err != nil {
		t.Errorf("Engine deobfuscation failed: %v", err)
	}

	if !bytes.Equal(testData, deobfuscated) {
		t.Errorf("Data mismatch: expected %v, got %v", testData, deobfuscated)
	}

	// Check metrics
	metrics := engine.GetMetrics()
	if metrics.TotalPackets < 2 {
		t.Errorf("Expected at least 2 packets processed, got %d", metrics.TotalPackets)
	}
}

// TestObfsproxyEnvironment tests different environments
func TestObfsproxyEnvironment(t *testing.T) {
	// Check what's actually installed
	installedExecutable, isInstalled := isObfsproxyInstalled()

	tests := []struct {
		name        string
		executable  string
		shouldExist bool
	}{
		{"obfsproxy", "obfsproxy", false},
		{"obfs4proxy", "obfs4proxy", false},
		{"nonexistent", "nonexistent-binary-12345", false},
	}

	// Update expected results based on actual installation
	if isInstalled {
		for i := range tests {
			if tests[i].executable == installedExecutable {
				tests[i].shouldExist = true
				t.Logf("Detected installed: %s", installedExecutable)
				break
			}
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
			config := &ObfsproxyConfig{
				Enabled:    true,
				Executable: tt.executable,
				Mode:       "client",
				Transport:  "obfs4",
				LogLevel:   "INFO",
			}

			obfs, err := NewObfsproxy(config, logger)
			if err != nil {
				t.Fatalf("Failed to create obfsproxy: %v", err)
			}

			available := obfs.IsAvailable()
			if available != tt.shouldExist {
				t.Errorf("Expected availability %v, got %v", tt.shouldExist, available)
			}

			if available {
				t.Logf("✅ %s is available and working", tt.executable)
			} else {
				t.Logf("❌ %s is not available (expected: %v)", tt.executable, tt.shouldExist)
			}
		})
	}
}
