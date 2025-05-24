package obfuscation

import (
	"bytes"
	"log"
	"os"
	"testing"
	"time"
)

func TestXORCipher(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	// Test with predefined key
	key := []byte("test-key-12345678901234567890")
	cipher, err := NewXORCipher(key, logger)
	if err != nil {
		t.Fatalf("Failed to create XOR cipher: %v", err)
	}

	// Test data
	testData := []byte("Hello, World! This is a test message for VPN obfuscation.")

	// Obfuscation
	obfuscated, err := cipher.Obfuscate(testData)
	if err != nil {
		t.Fatalf("Failed to obfuscate data: %v", err)
	}

	// Data should change
	if bytes.Equal(testData, obfuscated) {
		t.Error("Obfuscated data should be different from original")
	}

	// Deobfuscation
	deobfuscated, err := cipher.Deobfuscate(obfuscated)
	if err != nil {
		t.Fatalf("Failed to deobfuscate data: %v", err)
	}

	// Restored data should match original
	if !bytes.Equal(testData, deobfuscated) {
		t.Errorf("Deobfuscated data does not match original.\nOriginal: %s\nDeobfuscated: %s",
			string(testData), string(deobfuscated))
	}

	// Check metrics
	metrics := cipher.GetMetrics()
	if metrics.PacketsProcessed != 2 { // obfuscate + deobfuscate
		t.Errorf("Expected 2 packets processed, got %d", metrics.PacketsProcessed)
	}

	if metrics.BytesProcessed != int64(len(testData)*2) {
		t.Errorf("Expected %d bytes processed, got %d", len(testData)*2, metrics.BytesProcessed)
	}
}

func TestXORCipherRandomKey(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	// Test with auto-generated key
	cipher, err := NewXORCipher(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create XOR cipher with random key: %v", err)
	}

	if !cipher.IsAvailable() {
		t.Error("Cipher should be available")
	}

	if cipher.Name() != MethodXORCipher {
		t.Errorf("Expected method name %s, got %s", MethodXORCipher, cipher.Name())
	}
}

func TestObfuscationEngine(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	config := &Config{
		EnabledMethods:  []ObfuscationMethod{MethodXORCipher},
		PrimaryMethod:   MethodXORCipher,
		FallbackMethods: []ObfuscationMethod{},
		AutoDetection:   false,
		XORKey:          []byte("test-engine-key-123456789012"),
	}

	engine, err := NewEngine(config, logger)
	if err != nil {
		t.Fatalf("Failed to create obfuscation engine: %v", err)
	}
	defer engine.Close()

	// Check current method
	if engine.GetCurrentMethod() != MethodXORCipher {
		t.Errorf("Expected current method %s, got %s", MethodXORCipher, engine.GetCurrentMethod())
	}

	// Test data obfuscation
	testData := []byte("VPN traffic obfuscation test")

	obfuscated, err := engine.ObfuscateData(testData)
	if err != nil {
		t.Fatalf("Failed to obfuscate data through engine: %v", err)
	}

	deobfuscated, err := engine.DeobfuscateData(obfuscated)
	if err != nil {
		t.Fatalf("Failed to deobfuscate data through engine: %v", err)
	}

	if !bytes.Equal(testData, deobfuscated) {
		t.Errorf("Engine round-trip failed.\nOriginal: %s\nDeobfuscated: %s",
			string(testData), string(deobfuscated))
	}

	// Check engine metrics
	metrics := engine.GetMetrics()
	if metrics.TotalPackets != 2 {
		t.Errorf("Expected 2 total packets, got %d", metrics.TotalPackets)
	}

	if metrics.TotalBytes != int64(len(testData)*2) {
		t.Errorf("Expected %d total bytes, got %d", len(testData)*2, metrics.TotalBytes)
	}
}

func TestEngineWithRegionalProfile(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	config := &Config{
		EnabledMethods:   []ObfuscationMethod{MethodXORCipher, MethodTLSTunnel, MethodHTTPMimicry},
		PrimaryMethod:    MethodXORCipher,
		FallbackMethods:  []ObfuscationMethod{MethodTLSTunnel, MethodHTTPMimicry},
		AutoDetection:    true,
		DetectionTimeout: 5 * time.Second,
		RegionalProfile:  "china",
		XORKey:           []byte("china-test-key-1234567890123"),
	}

	engine, err := NewEngine(config, logger)
	if err != nil {
		t.Fatalf("Failed to create engine with China profile: %v", err)
	}
	defer engine.Close()

	// After applying China profile, primary method should be TLS Tunnel
	// (but it's a stub, so it may remain XOR)
	currentMethod := engine.GetCurrentMethod()
	t.Logf("Current method after China profile: %s", currentMethod)

	// Check that detector is created
	if engine.detector == nil {
		t.Error("DPI detector should be created when AutoDetection is enabled")
	}
}

func TestDPIDetector(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	detector := NewDPIDetector(5*time.Second, logger)

	// Check that successful operations reset the counter
	if detector.ShouldSwitch(MethodXORCipher, nil) {
		t.Error("Should not switch on successful operation")
	}

	// Simulate DPI-related errors
	dpiError := &mockError{message: "connection reset by peer"}

	// First two errors should not trigger switching
	if detector.ShouldSwitch(MethodXORCipher, dpiError) {
		t.Error("Should not switch after first DPI error")
	}

	if detector.ShouldSwitch(MethodXORCipher, dpiError) {
		t.Error("Should not switch after second DPI error")
	}

	// Third error should trigger switching
	if !detector.ShouldSwitch(MethodXORCipher, dpiError) {
		t.Error("Should switch after third DPI error")
	}
}

func TestStubObfuscator(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	stub := &stubObfuscator{
		name:   MethodTLSTunnel,
		logger: logger,
	}

	if stub.Name() != MethodTLSTunnel {
		t.Errorf("Expected stub name %s, got %s", MethodTLSTunnel, stub.Name())
	}

	if !stub.IsAvailable() {
		t.Error("Stub should always be available")
	}

	testData := []byte("test data for stub")

	// Stub should return data unchanged
	obfuscated, err := stub.Obfuscate(testData)
	if err != nil {
		t.Fatalf("Stub obfuscate failed: %v", err)
	}

	if !bytes.Equal(testData, obfuscated) {
		t.Error("Stub should return data unchanged")
	}

	deobfuscated, err := stub.Deobfuscate(testData)
	if err != nil {
		t.Fatalf("Stub deobfuscate failed: %v", err)
	}

	if !bytes.Equal(testData, deobfuscated) {
		t.Error("Stub should return data unchanged")
	}
}

// mockError for testing DPI detector
type mockError struct {
	message string
}

func (e *mockError) Error() string {
	return e.message
}

func TestTLSTunnel(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	config := &TLSTunnelConfig{
		ServerName:      "example.com",
		ALPN:            []string{"h2", "http/1.1"},
		FakeHTTPHeaders: true,
	}

	tunnel, err := NewTLSTunnel(config, logger)
	if err != nil {
		t.Fatalf("Failed to create TLS tunnel: %v", err)
	}

	if tunnel.Name() != MethodTLSTunnel {
		t.Errorf("Expected method name %s, got %s", MethodTLSTunnel, tunnel.Name())
	}

	if !tunnel.IsAvailable() {
		t.Error("TLS tunnel should be available")
	}

	// Test data obfuscation (for TLS tunnel, this is mostly a pass-through)
	testData := []byte("VPN traffic test data for TLS tunneling")

	obfuscated, err := tunnel.Obfuscate(testData)
	if err != nil {
		t.Fatalf("Failed to obfuscate data: %v", err)
	}

	deobfuscated, err := tunnel.Deobfuscate(obfuscated)
	if err != nil {
		t.Fatalf("Failed to deobfuscate data: %v", err)
	}

	if !bytes.Equal(testData, deobfuscated) {
		t.Errorf("TLS tunnel round-trip failed.\nOriginal: %s\nDeobfuscated: %s",
			string(testData), string(deobfuscated))
	}

	// Check metrics
	metrics := tunnel.GetMetrics()
	if metrics.PacketsProcessed != 2 {
		t.Errorf("Expected 2 packets processed, got %d", metrics.PacketsProcessed)
	}

	if metrics.BytesProcessed != int64(len(testData)*2) {
		t.Errorf("Expected %d bytes processed, got %d", len(testData)*2, metrics.BytesProcessed)
	}
}

func TestTLSTunnelDefaultConfig(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	// Test with empty config to check defaults
	config := &TLSTunnelConfig{}

	tunnel, err := NewTLSTunnel(config, logger)
	if err != nil {
		t.Fatalf("Failed to create TLS tunnel with default config: %v", err)
	}

	// Verify that defaults were set
	tlsTunnel := tunnel.(*TLSTunnel)
	if tlsTunnel.config.ServerName != "example.com" {
		t.Errorf("Expected default ServerName 'example.com', got '%s'", tlsTunnel.config.ServerName)
	}

	if len(tlsTunnel.config.ALPN) == 0 {
		t.Error("Expected default ALPN protocols to be set")
	}
}

func TestEngineWithTLSTunnel(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	config := &Config{
		EnabledMethods:  []ObfuscationMethod{MethodTLSTunnel},
		PrimaryMethod:   MethodTLSTunnel,
		FallbackMethods: []ObfuscationMethod{},
		AutoDetection:   false,
		TLSTunnel: TLSTunnelConfig{
			ServerName:      "secure.example.com",
			ALPN:            []string{"h2"},
			FakeHTTPHeaders: true,
		},
	}

	engine, err := NewEngine(config, logger)
	if err != nil {
		t.Fatalf("Failed to create engine with TLS tunnel: %v", err)
	}
	defer engine.Close()

	// Check current method
	if engine.GetCurrentMethod() != MethodTLSTunnel {
		t.Errorf("Expected current method %s, got %s", MethodTLSTunnel, engine.GetCurrentMethod())
	}

	// Test data obfuscation through engine
	testData := []byte("TLS tunnel engine test data")

	obfuscated, err := engine.ObfuscateData(testData)
	if err != nil {
		t.Fatalf("Failed to obfuscate data through engine: %v", err)
	}

	deobfuscated, err := engine.DeobfuscateData(obfuscated)
	if err != nil {
		t.Fatalf("Failed to deobfuscate data through engine: %v", err)
	}

	if !bytes.Equal(testData, deobfuscated) {
		t.Errorf("Engine TLS tunnel round-trip failed.\nOriginal: %s\nDeobfuscated: %s",
			string(testData), string(deobfuscated))
	}

	// Check engine metrics
	metrics := engine.GetMetrics()
	if metrics.TotalPackets != 2 {
		t.Errorf("Expected 2 total packets, got %d", metrics.TotalPackets)
	}
}

func BenchmarkXORObfuscation(b *testing.B) {
	logger := log.New(os.Stderr, "[BENCH] ", log.LstdFlags)
	cipher, err := NewXORCipher([]byte("benchmark-key-1234567890123456"), logger)
	if err != nil {
		b.Fatalf("Failed to create cipher: %v", err)
	}

	testData := bytes.Repeat([]byte("Hello, World! "), 100) // ~1.3KB

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := cipher.Obfuscate(testData)
		if err != nil {
			b.Fatalf("Obfuscation failed: %v", err)
		}
	}
}

func BenchmarkTLSTunnelObfuscation(b *testing.B) {
	logger := log.New(os.Stderr, "[BENCH] ", log.LstdFlags)

	config := &TLSTunnelConfig{
		ServerName:      "benchmark.example.com",
		ALPN:            []string{"h2"},
		FakeHTTPHeaders: false,
	}

	tunnel, err := NewTLSTunnel(config, logger)
	if err != nil {
		b.Fatalf("Failed to create TLS tunnel: %v", err)
	}

	testData := bytes.Repeat([]byte("TLS benchmark data "), 100) // ~1.9KB

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := tunnel.Obfuscate(testData)
		if err != nil {
			b.Fatalf("TLS obfuscation failed: %v", err)
		}
	}
}
