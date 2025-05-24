package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/atlet99/govpn/pkg/obfuscation"
)

func main() {
	fmt.Println("=== GoVPN Traffic Obfuscation Demo ===")
	fmt.Println()

	// Create logger
	logger := log.New(os.Stdout, "[DEMO] ", log.LstdFlags)

	// XOR obfuscation demonstration
	fmt.Println("1. XOR Obfuscation Demo")
	fmt.Println("-----------------------")
	demoXORObfuscation(logger)
	fmt.Println()

	// Obfuscation engine demonstration
	fmt.Println("2. Obfuscation Engine Demo")
	fmt.Println("---------------------------")
	demoObfuscationEngine(logger)
	fmt.Println()

	// Regional profiles demonstration
	fmt.Println("3. Regional Profiles Demo")
	fmt.Println("-------------------------")
	demoRegionalProfiles(logger)
	fmt.Println()

	// TLS Tunneling demonstration
	fmt.Println("4. TLS Tunneling Demo")
	fmt.Println("---------------------")
	demoTLSTunneling(logger)
	fmt.Println()

	// Auto-switching demonstration
	fmt.Println("5. Auto-switching Demo")
	fmt.Println("----------------------")
	demoAutoSwitching(logger)
	fmt.Println()

	fmt.Println("Demo completed successfully!")
}

func demoXORObfuscation(logger *log.Logger) {
	// Create XOR obfuscator
	key := []byte("demo-key-12345678901234567890")
	cipher, err := obfuscation.NewXORCipher(key, logger)
	if err != nil {
		log.Fatalf("Failed to create XOR cipher: %v", err)
	}

	// Test data
	originalData := []byte("Hello, GoVPN! This is sensitive VPN traffic that needs obfuscation.")
	fmt.Printf("Original data: %s\n", string(originalData))

	// Obfuscation
	obfuscated, err := cipher.Obfuscate(originalData)
	if err != nil {
		log.Fatalf("Failed to obfuscate: %v", err)
	}
	fmt.Printf("Obfuscated:    %x\n", obfuscated)

	// Deobfuscation
	deobfuscated, err := cipher.Deobfuscate(obfuscated)
	if err != nil {
		log.Fatalf("Failed to deobfuscate: %v", err)
	}
	fmt.Printf("Deobfuscated:  %s\n", string(deobfuscated))

	// Check metrics
	metrics := cipher.GetMetrics()
	fmt.Printf("Metrics: %d packets, %d bytes processed\n",
		metrics.PacketsProcessed, metrics.BytesProcessed)
}

func demoObfuscationEngine(logger *log.Logger) {
	// Engine configuration
	config := &obfuscation.Config{
		EnabledMethods:   []obfuscation.ObfuscationMethod{obfuscation.MethodXORCipher},
		PrimaryMethod:    obfuscation.MethodXORCipher,
		FallbackMethods:  []obfuscation.ObfuscationMethod{},
		AutoDetection:    false,
		SwitchThreshold:  3,
		DetectionTimeout: 5 * time.Second,
		XORKey:           []byte("engine-demo-key-123456789012"),
	}

	// Create engine
	engine, err := obfuscation.NewEngine(config, logger)
	if err != nil {
		log.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	fmt.Printf("Current method: %s\n", engine.GetCurrentMethod())

	// Process several packets
	packets := [][]byte{
		[]byte("Packet 1: User authentication data"),
		[]byte("Packet 2: File transfer content"),
		[]byte("Packet 3: Video streaming data"),
	}

	for i, packet := range packets {
		obfuscated, err := engine.ObfuscateData(packet)
		if err != nil {
			log.Printf("Failed to obfuscate packet %d: %v", i+1, err)
			continue
		}

		deobfuscated, err := engine.DeobfuscateData(obfuscated)
		if err != nil {
			log.Printf("Failed to deobfuscate packet %d: %v", i+1, err)
			continue
		}

		fmt.Printf("Packet %d: %s -> [obfuscated] -> %s\n",
			i+1, string(packet), string(deobfuscated))
	}

	// Show engine metrics
	metrics := engine.GetMetrics()
	fmt.Printf("Engine metrics: %d packets, %d bytes, %d switches\n",
		metrics.TotalPackets, metrics.TotalBytes, metrics.MethodSwitches)
}

func demoRegionalProfiles(logger *log.Logger) {
	profiles := []string{"china", "iran", "russia"}

	for _, profile := range profiles {
		fmt.Printf("Testing %s profile:\n", profile)

		config := &obfuscation.Config{
			EnabledMethods:  []obfuscation.ObfuscationMethod{obfuscation.MethodXORCipher},
			PrimaryMethod:   obfuscation.MethodXORCipher,
			FallbackMethods: []obfuscation.ObfuscationMethod{},
			AutoDetection:   true,
			RegionalProfile: profile,
			XORKey:          []byte("regional-demo-key-1234567890"),
		}

		engine, err := obfuscation.NewEngine(config, logger)
		if err != nil {
			log.Printf("Failed to create engine for %s: %v", profile, err)
			continue
		}

		testData := []byte(fmt.Sprintf("Test data for %s region", profile))
		obfuscated, err := engine.ObfuscateData(testData)
		if err != nil {
			log.Printf("Failed to obfuscate for %s: %v", profile, err)
			engine.Close()
			continue
		}

		deobfuscated, err := engine.DeobfuscateData(obfuscated)
		if err != nil {
			log.Printf("Failed to deobfuscate for %s: %v", profile, err)
			engine.Close()
			continue
		}

		fmt.Printf("  Success: %s\n", string(deobfuscated))
		engine.Close()
	}
}

func demoTLSTunneling(logger *log.Logger) {
	// Create TLS tunnel configuration
	config := &obfuscation.Config{
		EnabledMethods:  []obfuscation.ObfuscationMethod{obfuscation.MethodTLSTunnel},
		PrimaryMethod:   obfuscation.MethodTLSTunnel,
		FallbackMethods: []obfuscation.ObfuscationMethod{},
		AutoDetection:   false,
		TLSTunnel: obfuscation.TLSTunnelConfig{
			ServerName:      "secure.example.com",
			ALPN:            []string{"h2", "http/1.1"},
			FakeHTTPHeaders: true,
		},
	}

	// Create engine with TLS tunnel
	engine, err := obfuscation.NewEngine(config, logger)
	if err != nil {
		log.Fatalf("Failed to create TLS tunnel engine: %v", err)
	}
	defer engine.Close()

	fmt.Printf("TLS Tunnel method: %s\n", engine.GetCurrentMethod())
	fmt.Printf("Server name: %s\n", config.TLSTunnel.ServerName)
	fmt.Printf("ALPN protocols: %v\n", config.TLSTunnel.ALPN)
	fmt.Printf("Fake HTTP headers: %v\n", config.TLSTunnel.FakeHTTPHeaders)

	// Test different types of data
	testCases := []struct {
		name string
		data []byte
	}{
		{"Web traffic", []byte("GET /api/data HTTP/1.1\r\nHost: example.com\r\n\r\n")},
		{"Video stream", []byte("Video stream chunk #1 with binary data...")},
		{"File upload", []byte("multipart/form-data; boundary=----WebKitFormBoundary")},
		{"JSON API", []byte(`{"user":"alice","action":"login","timestamp":1234567890}`)},
	}

	for _, tc := range testCases {
		fmt.Printf("\nTesting %s:\n", tc.name)
		fmt.Printf("Original:     %s\n", string(tc.data))

		// Obfuscate through TLS tunnel
		obfuscated, err := engine.ObfuscateData(tc.data)
		if err != nil {
			log.Printf("Failed to obfuscate %s: %v", tc.name, err)
			continue
		}

		// Deobfuscate
		deobfuscated, err := engine.DeobfuscateData(obfuscated)
		if err != nil {
			log.Printf("Failed to deobfuscate %s: %v", tc.name, err)
			continue
		}

		fmt.Printf("Deobfuscated: %s\n", string(deobfuscated))
		fmt.Printf("Round-trip:   %v\n", string(tc.data) == string(deobfuscated))
	}

	// Show TLS tunnel metrics
	metrics := engine.GetMetrics()
	fmt.Printf("\nTLS Tunnel metrics:\n")
	fmt.Printf("- Total packets: %d\n", metrics.TotalPackets)
	fmt.Printf("- Total bytes: %d\n", metrics.TotalBytes)
	fmt.Printf("- Method switches: %d\n", metrics.MethodSwitches)

	// Test the actual TLS tunnel obfuscator directly
	fmt.Printf("\nDirect TLS Tunnel test:\n")
	tlsConfig := &obfuscation.TLSTunnelConfig{
		ServerName:      "direct.example.com",
		ALPN:            []string{"h2"},
		FakeHTTPHeaders: false,
	}

	tunnel, err := obfuscation.NewTLSTunnel(tlsConfig, logger)
	if err != nil {
		log.Printf("Failed to create direct TLS tunnel: %v", err)
		return
	}

	directData := []byte("Direct TLS tunnel test data")
	obfuscated, err := tunnel.Obfuscate(directData)
	if err != nil {
		log.Printf("Direct obfuscation failed: %v", err)
		return
	}

	deobfuscated, err := tunnel.Deobfuscate(obfuscated)
	if err != nil {
		log.Printf("Direct deobfuscation failed: %v", err)
		return
	}

	fmt.Printf("Direct test successful: %v\n", string(directData) == string(deobfuscated))

	// Show TLS tunnel metrics
	tlsMetrics := tunnel.GetMetrics()
	fmt.Printf("Direct TLS metrics: %d packets, %d bytes processed\n",
		tlsMetrics.PacketsProcessed, tlsMetrics.BytesProcessed)
}

func demoAutoSwitching(logger *log.Logger) {
	// Configuration with auto-switching
	config := &obfuscation.Config{
		EnabledMethods: []obfuscation.ObfuscationMethod{
			obfuscation.MethodXORCipher,
			obfuscation.MethodTLSTunnel,
			obfuscation.MethodHTTPMimicry,
		},
		PrimaryMethod: obfuscation.MethodXORCipher,
		FallbackMethods: []obfuscation.ObfuscationMethod{
			obfuscation.MethodTLSTunnel,
			obfuscation.MethodHTTPMimicry,
		},
		AutoDetection:    true,
		SwitchThreshold:  2,
		DetectionTimeout: 3 * time.Second,
		XORKey:           []byte("auto-switch-demo-key-123456789"),
	}

	engine, err := obfuscation.NewEngine(config, logger)
	if err != nil {
		log.Fatalf("Failed to create engine: %v", err)
	}
	defer engine.Close()

	fmt.Printf("Initial method: %s\n", engine.GetCurrentMethod())

	// Simulate data processing
	testData := []byte("Auto-switching test data")

	for i := 0; i < 5; i++ {
		obfuscated, err := engine.ObfuscateData(testData)
		if err != nil {
			log.Printf("Iteration %d failed: %v", i+1, err)
			continue
		}

		deobfuscated, err := engine.DeobfuscateData(obfuscated)
		if err != nil {
			log.Printf("Deobfuscation %d failed: %v", i+1, err)
			continue
		}

		fmt.Printf("Iteration %d: method=%s, success=%v\n",
			i+1, engine.GetCurrentMethod(), string(testData) == string(deobfuscated))
	}

	// Show final metrics
	metrics := engine.GetMetrics()
	fmt.Printf("Final metrics: %d packets processed, %d method switches\n",
		metrics.TotalPackets, metrics.MethodSwitches)
}
