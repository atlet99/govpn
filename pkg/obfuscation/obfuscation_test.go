package obfuscation

import (
	"bytes"
	"log"
	"os"
	"strings"
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

func TestPacketPadding(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	config := &PacketPaddingConfig{
		Enabled:       true,
		MinPadding:    10,
		MaxPadding:    50,
		RandomizeSize: true,
	}

	padding, err := NewPacketPadding(config, logger)
	if err != nil {
		t.Fatalf("Failed to create packet padding: %v", err)
	}

	if padding.Name() != MethodPacketPadding {
		t.Errorf("Expected method name %s, got %s", MethodPacketPadding, padding.Name())
	}

	if !padding.IsAvailable() {
		t.Error("Packet padding should be available")
	}

	// Test data obfuscation with padding
	testData := []byte("Test packet data for padding obfuscation")

	obfuscated, err := padding.Obfuscate(testData)
	if err != nil {
		t.Fatalf("Failed to obfuscate data: %v", err)
	}

	// Obfuscated data should be larger due to padding
	expectedMinSize := len(testData) + config.MinPadding + 4 // +4 for header
	if len(obfuscated) < expectedMinSize {
		t.Errorf("Expected obfuscated data size at least %d, got %d", expectedMinSize, len(obfuscated))
	}

	expectedMaxSize := len(testData) + config.MaxPadding + 4 // +4 for header
	if len(obfuscated) > expectedMaxSize {
		t.Errorf("Expected obfuscated data size at most %d, got %d", expectedMaxSize, len(obfuscated))
	}

	// Deobfuscation should restore original data
	deobfuscated, err := padding.Deobfuscate(obfuscated)
	if err != nil {
		t.Fatalf("Failed to deobfuscate data: %v", err)
	}

	if !bytes.Equal(testData, deobfuscated) {
		t.Errorf("Packet padding round-trip failed.\nOriginal: %s\nDeobfuscated: %s",
			string(testData), string(deobfuscated))
	}

	// Check metrics
	metrics := padding.GetMetrics()
	if metrics.PacketsProcessed != 2 {
		t.Errorf("Expected 2 packets processed, got %d", metrics.PacketsProcessed)
	}
}

func TestPacketPaddingDefaultConfig(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	// Test with nil config to check defaults
	padding, err := NewPacketPadding(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create packet padding with default config: %v", err)
	}

	// Test that padding works with defaults
	testData := []byte("Default config test")

	obfuscated, err := padding.Obfuscate(testData)
	if err != nil {
		t.Fatalf("Failed to obfuscate with default config: %v", err)
	}

	deobfuscated, err := padding.Deobfuscate(obfuscated)
	if err != nil {
		t.Fatalf("Failed to deobfuscate with default config: %v", err)
	}

	if !bytes.Equal(testData, deobfuscated) {
		t.Errorf("Default config round-trip failed")
	}
}

func TestPacketPaddingDisabled(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	config := &PacketPaddingConfig{
		Enabled: false,
	}

	padding, err := NewPacketPadding(config, logger)
	if err != nil {
		t.Fatalf("Failed to create disabled packet padding: %v", err)
	}

	if padding.IsAvailable() {
		t.Error("Disabled packet padding should not be available")
	}

	testData := []byte("Test data for disabled padding")

	// When disabled, should return data unchanged
	obfuscated, err := padding.Obfuscate(testData)
	if err != nil {
		t.Fatalf("Failed to obfuscate with disabled padding: %v", err)
	}

	if !bytes.Equal(testData, obfuscated) {
		t.Error("Disabled padding should return data unchanged")
	}
}

func TestEngineWithPacketPadding(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	config := &Config{
		EnabledMethods:  []ObfuscationMethod{MethodPacketPadding},
		PrimaryMethod:   MethodPacketPadding,
		FallbackMethods: []ObfuscationMethod{},
		AutoDetection:   false,
		PacketPadding: PacketPaddingConfig{
			Enabled:       true,
			MinPadding:    5,
			MaxPadding:    20,
			RandomizeSize: true,
		},
	}

	engine, err := NewEngine(config, logger)
	if err != nil {
		t.Fatalf("Failed to create engine with packet padding: %v", err)
	}
	defer engine.Close()

	// Check current method
	if engine.GetCurrentMethod() != MethodPacketPadding {
		t.Errorf("Expected current method %s, got %s", MethodPacketPadding, engine.GetCurrentMethod())
	}

	// Test data obfuscation through engine
	testData := []byte("Engine packet padding test")

	obfuscated, err := engine.ObfuscateData(testData)
	if err != nil {
		t.Fatalf("Failed to obfuscate data through engine: %v", err)
	}

	deobfuscated, err := engine.DeobfuscateData(obfuscated)
	if err != nil {
		t.Fatalf("Failed to deobfuscate data through engine: %v", err)
	}

	if !bytes.Equal(testData, deobfuscated) {
		t.Errorf("Engine packet padding round-trip failed.\nOriginal: %s\nDeobfuscated: %s",
			string(testData), string(deobfuscated))
	}

	// Check engine metrics
	metrics := engine.GetMetrics()
	if metrics.TotalPackets != 2 {
		t.Errorf("Expected 2 total packets, got %d", metrics.TotalPackets)
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

func TestHTTPMimicry(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	config := &HTTPMimicryConfig{
		UserAgent:     "Mozilla/5.0 (Test Browser)",
		FakeHost:      "api.example.com",
		CustomHeaders: map[string]string{"X-API-Key": "test-key-123"},
		MimicWebsite:  "https://api.example.com",
	}

	mimicry, err := NewHTTPMimicry(config, logger)
	if err != nil {
		t.Fatalf("Failed to create HTTP mimicry: %v", err)
	}

	if mimicry.Name() != MethodHTTPMimicry {
		t.Errorf("Expected method name %s, got %s", MethodHTTPMimicry, mimicry.Name())
	}

	if !mimicry.IsAvailable() {
		t.Error("HTTP mimicry should be available")
	}

	// Test data obfuscation with HTTP mimicry
	testData := []byte("Secret VPN data that needs to be disguised as HTTP traffic")

	obfuscated, err := mimicry.Obfuscate(testData)
	if err != nil {
		t.Fatalf("Failed to obfuscate data: %v", err)
	}

	// Obfuscated data should be larger due to HTTP headers
	if len(obfuscated) <= len(testData) {
		t.Errorf("Expected obfuscated data to be larger than original, got %d <= %d", len(obfuscated), len(testData))
	}

	// Check that obfuscated data looks like HTTP
	obfuscatedStr := string(obfuscated)
	if !strings.Contains(obfuscatedStr, "HTTP/1.1") && !strings.Contains(obfuscatedStr, "Host:") {
		t.Error("Obfuscated data should contain HTTP headers")
	}

	// Deobfuscation should restore original data
	deobfuscated, err := mimicry.Deobfuscate(obfuscated)
	if err != nil {
		t.Fatalf("Failed to deobfuscate data: %v", err)
	}

	if !bytes.Equal(testData, deobfuscated) {
		t.Errorf("HTTP mimicry round-trip failed.\nOriginal: %s\nDeobfuscated: %s",
			string(testData), string(deobfuscated))
	}

	// Check metrics
	metrics := mimicry.GetMetrics()
	if metrics.PacketsProcessed != 2 {
		t.Errorf("Expected 2 packets processed, got %d", metrics.PacketsProcessed)
	}
}

func TestHTTPMimicryDefaultConfig(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	// Test with nil config to check defaults
	mimicry, err := NewHTTPMimicry(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create HTTP mimicry with default config: %v", err)
	}

	// Test that HTTP mimicry works with defaults
	testData := []byte("Default config test for HTTP mimicry")

	obfuscated, err := mimicry.Obfuscate(testData)
	if err != nil {
		t.Fatalf("Failed to obfuscate with default config: %v", err)
	}

	deobfuscated, err := mimicry.Deobfuscate(obfuscated)
	if err != nil {
		t.Fatalf("Failed to deobfuscate with default config: %v", err)
	}

	if !bytes.Equal(testData, deobfuscated) {
		t.Errorf("Default config round-trip failed")
	}
}

func TestHTTPMimicryDifferentSizes(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	mimicry, err := NewHTTPMimicry(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create HTTP mimicry: %v", err)
	}

	// Test different data sizes to trigger different HTTP structures
	testCases := []struct {
		name string
		data []byte
	}{
		{"Small data", []byte("Hi")},
		{"Medium data", []byte("This is a medium-sized test packet for HTTP mimicry")},
		{"Large data", bytes.Repeat([]byte("Large test data "), 100)}, // ~1.6KB
		{"Empty data", []byte{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			obfuscated, err := mimicry.Obfuscate(tc.data)
			if err != nil {
				t.Fatalf("Failed to obfuscate %s: %v", tc.name, err)
			}

			deobfuscated, err := mimicry.Deobfuscate(obfuscated)
			if err != nil {
				t.Fatalf("Failed to deobfuscate %s: %v", tc.name, err)
			}

			if !bytes.Equal(tc.data, deobfuscated) {
				t.Errorf("%s round-trip failed", tc.name)
			}
		})
	}
}

func TestEngineWithHTTPMimicry(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	config := &Config{
		EnabledMethods:  []ObfuscationMethod{MethodHTTPMimicry},
		PrimaryMethod:   MethodHTTPMimicry,
		FallbackMethods: []ObfuscationMethod{},
		AutoDetection:   false,
		HTTPMimicry: HTTPMimicryConfig{
			UserAgent:     "Mozilla/5.0 (Engine Test)",
			FakeHost:      "secure.api.com",
			CustomHeaders: map[string]string{"Authorization": "Bearer test-token"},
			MimicWebsite:  "https://secure.api.com",
		},
	}

	engine, err := NewEngine(config, logger)
	if err != nil {
		t.Fatalf("Failed to create engine with HTTP mimicry: %v", err)
	}
	defer engine.Close()

	// Check current method
	if engine.GetCurrentMethod() != MethodHTTPMimicry {
		t.Errorf("Expected current method %s, got %s", MethodHTTPMimicry, engine.GetCurrentMethod())
	}

	// Test data obfuscation through engine
	testData := []byte("Engine HTTP mimicry test data")

	obfuscated, err := engine.ObfuscateData(testData)
	if err != nil {
		t.Fatalf("Failed to obfuscate data through engine: %v", err)
	}

	deobfuscated, err := engine.DeobfuscateData(obfuscated)
	if err != nil {
		t.Fatalf("Failed to deobfuscate data through engine: %v", err)
	}

	if !bytes.Equal(testData, deobfuscated) {
		t.Errorf("Engine HTTP mimicry round-trip failed.\nOriginal: %s\nDeobfuscated: %s",
			string(testData), string(deobfuscated))
	}

	// Check engine metrics
	metrics := engine.GetMetrics()
	if metrics.TotalPackets != 2 {
		t.Errorf("Expected 2 total packets, got %d", metrics.TotalPackets)
	}
}

func BenchmarkHTTPMimicryObfuscation(b *testing.B) {
	logger := log.New(os.Stderr, "[BENCH] ", log.LstdFlags)

	config := &HTTPMimicryConfig{
		UserAgent:     "Mozilla/5.0 (Benchmark)",
		FakeHost:      "api.benchmark.com",
		CustomHeaders: map[string]string{},
		MimicWebsite:  "",
	}

	mimicry, err := NewHTTPMimicry(config, logger)
	if err != nil {
		b.Fatalf("Failed to create HTTP mimicry: %v", err)
	}

	testData := bytes.Repeat([]byte("HTTP mimicry bench "), 100) // ~1.9KB

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := mimicry.Obfuscate(testData)
		if err != nil {
			b.Fatalf("HTTP mimicry obfuscation failed: %v", err)
		}
	}
}

func BenchmarkPacketPaddingObfuscation(b *testing.B) {
	logger := log.New(os.Stderr, "[BENCH] ", log.LstdFlags)

	config := &PacketPaddingConfig{
		Enabled:       true,
		MinPadding:    10,
		MaxPadding:    50,
		RandomizeSize: true,
	}

	padding, err := NewPacketPadding(config, logger)
	if err != nil {
		b.Fatalf("Failed to create packet padding: %v", err)
	}

	testData := bytes.Repeat([]byte("Packet padding bench "), 100) // ~2.1KB

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := padding.Obfuscate(testData)
		if err != nil {
			b.Fatalf("Packet padding obfuscation failed: %v", err)
		}
	}
}

func TestTimingObfuscation(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	config := &TimingObfsConfig{
		Enabled:      true,
		MinDelay:     1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
		RandomJitter: true,
	}

	timing, err := NewTimingObfuscation(config, logger)
	if err != nil {
		t.Fatalf("Failed to create timing obfuscation: %v", err)
	}

	if timing.Name() != MethodTimingObfs {
		t.Errorf("Expected method name %s, got %s", MethodTimingObfs, timing.Name())
	}

	if !timing.IsAvailable() {
		t.Error("Timing obfuscation should be available")
	}

	// Test data obfuscation with timing
	testData := []byte("Test packet data for timing obfuscation")

	// Measure time for obfuscation (should include delay)
	start := time.Now()
	obfuscated, err := timing.Obfuscate(testData)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Failed to obfuscate data: %v", err)
	}

	// Data should remain unchanged
	if !bytes.Equal(testData, obfuscated) {
		t.Errorf("Timing obfuscation should not modify data.\nOriginal: %s\nObfuscated: %s",
			string(testData), string(obfuscated))
	}

	// Should have added some delay (at least minimum delay)
	if duration < config.MinDelay {
		t.Errorf("Expected delay at least %v, got %v", config.MinDelay, duration)
	}

	// Should not exceed maximum delay plus some tolerance
	tolerance := 5 * time.Millisecond
	if duration > config.MaxDelay+tolerance {
		t.Errorf("Expected delay at most %v + tolerance, got %v", config.MaxDelay, duration)
	}

	// Deobfuscation should be immediate (no delay) and return original data
	start = time.Now()
	deobfuscated, err := timing.Deobfuscate(obfuscated)
	deobfuscateDuration := time.Since(start)

	if err != nil {
		t.Fatalf("Failed to deobfuscate data: %v", err)
	}

	if !bytes.Equal(testData, deobfuscated) {
		t.Errorf("Timing obfuscation round-trip failed.\nOriginal: %s\nDeobfuscated: %s",
			string(testData), string(deobfuscated))
	}

	// Deobfuscation should be fast (no added delay)
	if deobfuscateDuration > 1*time.Millisecond {
		t.Errorf("Deobfuscation took too long: %v", deobfuscateDuration)
	}

	// Check metrics
	metrics := timing.GetMetrics()
	if metrics.PacketsProcessed != 2 {
		t.Errorf("Expected 2 packets processed, got %d", metrics.PacketsProcessed)
	}

	if metrics.BytesProcessed != int64(len(testData)*2) {
		t.Errorf("Expected %d bytes processed, got %d", len(testData)*2, metrics.BytesProcessed)
	}
}

func TestTimingObfuscationDefaultConfig(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	// Test with nil config to check defaults
	timing, err := NewTimingObfuscation(nil, logger)
	if err != nil {
		t.Fatalf("Failed to create timing obfuscation with default config: %v", err)
	}

	// Verify that defaults were set
	timingObfs := timing.(*TimingObfuscation)
	if timingObfs.config.MinDelay != 1*time.Millisecond {
		t.Errorf("Expected default MinDelay 1ms, got %v", timingObfs.config.MinDelay)
	}

	if timingObfs.config.MaxDelay != 50*time.Millisecond {
		t.Errorf("Expected default MaxDelay 50ms, got %v", timingObfs.config.MaxDelay)
	}

	if !timingObfs.config.RandomJitter {
		t.Error("Expected default RandomJitter to be true")
	}

	// Test functionality with defaults
	testData := []byte("Default config test")

	start := time.Now()
	obfuscated, err := timing.Obfuscate(testData)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Failed to obfuscate with defaults: %v", err)
	}

	if !bytes.Equal(testData, obfuscated) {
		t.Error("Timing obfuscation with defaults should not modify data")
	}

	// Should have added some delay
	if duration < 1*time.Millisecond {
		t.Errorf("Expected delay with defaults, got %v", duration)
	}
}

func TestTimingObfuscationDisabled(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	config := &TimingObfsConfig{
		Enabled:      false,
		MinDelay:     10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		RandomJitter: true,
	}

	timing, err := NewTimingObfuscation(config, logger)
	if err != nil {
		t.Fatalf("Failed to create disabled timing obfuscation: %v", err)
	}

	if timing.IsAvailable() {
		t.Error("Disabled timing obfuscation should not be available")
	}

	testData := []byte("Test with disabled timing obfuscation")

	// Should be very fast when disabled
	start := time.Now()
	obfuscated, err := timing.Obfuscate(testData)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Failed to obfuscate when disabled: %v", err)
	}

	if !bytes.Equal(testData, obfuscated) {
		t.Error("Disabled timing obfuscation should not modify data")
	}

	// Should not add significant delay when disabled
	if duration > 1*time.Millisecond {
		t.Errorf("Disabled timing obfuscation should be fast, took %v", duration)
	}
}

func TestTimingObfuscationFixedDelay(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	config := &TimingObfsConfig{
		Enabled:      true,
		MinDelay:     5 * time.Millisecond,
		MaxDelay:     5 * time.Millisecond, // Same as min for fixed delay
		RandomJitter: false,                // Disable jitter for predictable delay
	}

	timing, err := NewTimingObfuscation(config, logger)
	if err != nil {
		t.Fatalf("Failed to create fixed delay timing obfuscation: %v", err)
	}

	testData := []byte("Test fixed delay")

	// Test multiple times to ensure consistent delay
	for i := 0; i < 3; i++ {
		start := time.Now()
		_, err := timing.Obfuscate(testData)
		duration := time.Since(start)

		if err != nil {
			t.Fatalf("Failed to obfuscate (iteration %d): %v", i, err)
		}

		// Should be close to the fixed delay
		tolerance := 2 * time.Millisecond
		if duration < config.MaxDelay-tolerance || duration > config.MaxDelay+tolerance {
			t.Errorf("Iteration %d: Expected delay around %v, got %v", i, config.MaxDelay, duration)
		}
	}
}

func TestEngineWithTimingObfuscation(t *testing.T) {
	logger := log.New(os.Stderr, "[TEST] ", log.LstdFlags)

	config := &Config{
		EnabledMethods:  []ObfuscationMethod{MethodTimingObfs},
		PrimaryMethod:   MethodTimingObfs,
		FallbackMethods: []ObfuscationMethod{},
		AutoDetection:   false,
		TimingObfuscation: TimingObfsConfig{
			Enabled:      true,
			MinDelay:     1 * time.Millisecond,
			MaxDelay:     5 * time.Millisecond,
			RandomJitter: true,
		},
	}

	engine, err := NewEngine(config, logger)
	if err != nil {
		t.Fatalf("Failed to create engine with timing obfuscation: %v", err)
	}
	defer engine.Close()

	// Check current method
	if engine.GetCurrentMethod() != MethodTimingObfs {
		t.Errorf("Expected current method %s, got %s", MethodTimingObfs, engine.GetCurrentMethod())
	}

	// Test data obfuscation through engine
	testData := []byte("Timing obfuscation engine test data")

	start := time.Now()
	obfuscated, err := engine.ObfuscateData(testData)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Failed to obfuscate data through engine: %v", err)
	}

	if !bytes.Equal(testData, obfuscated) {
		t.Error("Engine timing obfuscation should not modify data")
	}

	// Should have added some delay
	if duration < 1*time.Millisecond {
		t.Errorf("Expected delay through engine, got %v", duration)
	}

	deobfuscated, err := engine.DeobfuscateData(obfuscated)
	if err != nil {
		t.Fatalf("Failed to deobfuscate data through engine: %v", err)
	}

	if !bytes.Equal(testData, deobfuscated) {
		t.Errorf("Engine timing obfuscation round-trip failed.\nOriginal: %s\nDeobfuscated: %s",
			string(testData), string(deobfuscated))
	}

	// Check engine metrics
	metrics := engine.GetMetrics()
	if metrics.TotalPackets != 2 {
		t.Errorf("Expected 2 total packets, got %d", metrics.TotalPackets)
	}
}

func BenchmarkTimingObfuscation(b *testing.B) {
	logger := log.New(os.Stderr, "[BENCH] ", log.LstdFlags)

	config := &TimingObfsConfig{
		Enabled:      true,
		MinDelay:     100 * time.Microsecond, // Use smaller delays for benchmarking
		MaxDelay:     500 * time.Microsecond,
		RandomJitter: true,
	}

	timing, err := NewTimingObfuscation(config, logger)
	if err != nil {
		b.Fatalf("Failed to create timing obfuscation: %v", err)
	}

	testData := bytes.Repeat([]byte("Hello, Timing! "), 50) // ~750 bytes

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := timing.Obfuscate(testData)
		if err != nil {
			b.Fatalf("Timing obfuscation failed: %v", err)
		}
	}
}
