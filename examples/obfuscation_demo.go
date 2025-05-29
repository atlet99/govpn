package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/atlet99/govpn/pkg/auth"
	"github.com/atlet99/govpn/pkg/obfuscation"
	"github.com/pquerna/otp"
)

func main() {
	fmt.Println("🚀 GoVPN Complete Obfuscation Demo")
	fmt.Println("===================================")

	logger := log.New(os.Stdout, "[DEMO] ", log.LstdFlags)

	fmt.Printf("🎯 Demonstration of all GoVPN obfuscation methods\n\n")

	// Basic obfuscation methods
	demoXORObfuscation(logger)
	demoObfuscationEngine(logger)
	demoRegionalProfiles(logger)
	demoTLSTunneling(logger)
	demoPacketPadding(logger)
	demoTimingObfuscation(logger)
	demoTrafficPadding(logger)
	demoHTTPMimicry(logger)
	demoDNSTunneling(logger)
	demoHTTPSteganography(logger)
	demoFlowWatermarking(logger)
	demoAutoSwitching(logger)

	// Obfsproxy integration
	demoObfsproxyConfigurations(logger)
	demoObfsproxyEngineIntegration(logger)
	demoObfsproxyRealTesting(logger)

	// Authentication
	demoAuthentication(logger)

	fmt.Println("\n🎉 Demonstration completed! All obfuscation methods have been tested.")
	fmt.Println("📚 For additional information, please refer to the documentation:")
	fmt.Println("   - docs/obfuscation/")
	fmt.Println("   - examples/OBFSPROXY_USAGE.md")
	fmt.Println("   - docs/TESTING_OBFSPROXY.md")
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

func demoPacketPadding(logger *log.Logger) {
	// Create packet padding configuration
	config := &obfuscation.Config{
		EnabledMethods:  []obfuscation.ObfuscationMethod{obfuscation.MethodPacketPadding},
		PrimaryMethod:   obfuscation.MethodPacketPadding,
		FallbackMethods: []obfuscation.ObfuscationMethod{},
		AutoDetection:   false,
		PacketPadding: obfuscation.PacketPaddingConfig{
			Enabled:       true,
			MinPadding:    10,
			MaxPadding:    100,
			RandomizeSize: true,
		},
	}

	// Create engine with packet padding
	engine, err := obfuscation.NewEngine(config, logger)
	if err != nil {
		log.Fatalf("Failed to create packet padding engine: %v", err)
	}
	defer engine.Close()

	fmt.Printf("Packet Padding method: %s\n", engine.GetCurrentMethod())
	fmt.Printf("Min padding: %d bytes\n", config.PacketPadding.MinPadding)
	fmt.Printf("Max padding: %d bytes\n", config.PacketPadding.MaxPadding)
	fmt.Printf("Randomize size: %v\n", config.PacketPadding.RandomizeSize)

	// Test different packet sizes to show padding effect
	testCases := []struct {
		name string
		data []byte
	}{
		{"Small packet", []byte("Hi")},
		{"Medium packet", []byte("This is a medium-sized packet for testing")},
		{"Large packet", []byte("This is a much larger packet that contains more data and should demonstrate how packet padding works with different sizes of input data.")},
		{"Binary data", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0xFE, 0xFD}},
	}

	for _, tc := range testCases {
		fmt.Printf("\nTesting %s:\n", tc.name)
		fmt.Printf("Original size: %d bytes\n", len(tc.data))

		// Obfuscate with packet padding
		obfuscated, err := engine.ObfuscateData(tc.data)
		if err != nil {
			log.Printf("Failed to obfuscate %s: %v", tc.name, err)
			continue
		}

		fmt.Printf("Padded size:   %d bytes (padding: %d bytes)\n",
			len(obfuscated), len(obfuscated)-len(tc.data)-4) // -4 for header

		// Deobfuscate
		deobfuscated, err := engine.DeobfuscateData(obfuscated)
		if err != nil {
			log.Printf("Failed to deobfuscate %s: %v", tc.name, err)
			continue
		}

		fmt.Printf("Restored size: %d bytes\n", len(deobfuscated))
		fmt.Printf("Round-trip:    %v\n", bytes.Equal(tc.data, deobfuscated))

		// Show size increase ratio
		ratio := float64(len(obfuscated)) / float64(len(tc.data))
		fmt.Printf("Size ratio:    %.2fx\n", ratio)
	}

	// Show packet padding metrics
	metrics := engine.GetMetrics()
	fmt.Printf("\nPacket Padding metrics:\n")
	fmt.Printf("- Total packets: %d\n", metrics.TotalPackets)
	fmt.Printf("- Total bytes: %d\n", metrics.TotalBytes)
	fmt.Printf("- Method switches: %d\n", metrics.MethodSwitches)

	// Test the actual packet padding obfuscator directly
	fmt.Printf("\nDirect Packet Padding test:\n")
	paddingConfig := &obfuscation.PacketPaddingConfig{
		Enabled:       true,
		MinPadding:    5,
		MaxPadding:    25,
		RandomizeSize: true,
	}

	padding, err := obfuscation.NewPacketPadding(paddingConfig, logger)
	if err != nil {
		log.Printf("Failed to create direct packet padding: %v", err)
		return
	}

	directData := []byte("Direct packet padding test")
	obfuscated, err := padding.Obfuscate(directData)
	if err != nil {
		log.Printf("Direct obfuscation failed: %v", err)
		return
	}

	deobfuscated, err := padding.Deobfuscate(obfuscated)
	if err != nil {
		log.Printf("Direct deobfuscation failed: %v", err)
		return
	}

	fmt.Printf("Direct test successful: %v\n", bytes.Equal(directData, deobfuscated))
	fmt.Printf("Direct size increase: %d -> %d bytes\n", len(directData), len(obfuscated))

	// Show packet padding metrics
	paddingMetrics := padding.GetMetrics()
	fmt.Printf("Direct padding metrics: %d packets, %d bytes processed\n",
		paddingMetrics.PacketsProcessed, paddingMetrics.BytesProcessed)
}

func demoTimingObfuscation(logger *log.Logger) {
	// Create timing obfuscation configuration
	config := &obfuscation.Config{
		EnabledMethods:  []obfuscation.ObfuscationMethod{obfuscation.MethodTimingObfs},
		PrimaryMethod:   obfuscation.MethodTimingObfs,
		FallbackMethods: []obfuscation.ObfuscationMethod{},
		AutoDetection:   false,
		TimingObfuscation: obfuscation.TimingObfsConfig{
			Enabled:      true,
			MinDelay:     5 * time.Millisecond,
			MaxDelay:     25 * time.Millisecond,
			RandomJitter: true,
		},
	}

	// Create engine with timing obfuscation
	engine, err := obfuscation.NewEngine(config, logger)
	if err != nil {
		log.Fatalf("Failed to create timing obfuscation engine: %v", err)
	}
	defer engine.Close()

	fmt.Printf("Timing Obfuscation method: %s\n", engine.GetCurrentMethod())
	fmt.Printf("Min delay: %v\n", config.TimingObfuscation.MinDelay)
	fmt.Printf("Max delay: %v\n", config.TimingObfuscation.MaxDelay)
	fmt.Printf("Random jitter: %v\n", config.TimingObfuscation.RandomJitter)

	// Test different packet types to show timing behavior
	testCases := []struct {
		name string
		data []byte
	}{
		{"Control packet", []byte("PING")},
		{"Auth request", []byte(`{"type":"auth","user":"alice","token":"abc123"}`)},
		{"Data transfer", []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit...")},
		{"Heartbeat", []byte("HEARTBEAT_01")},
		{"Large payload", bytes.Repeat([]byte("BULK_DATA_"), 50)}, // ~500 bytes
	}

	fmt.Printf("\nTesting timing delays (watch the timestamps):\n")

	for _, tc := range testCases {
		fmt.Printf("\nProcessing %s:\n", tc.name)
		fmt.Printf("Data size: %d bytes\n", len(tc.data))

		// Record start time
		start := time.Now()
		fmt.Printf("Start time: %s\n", start.Format("15:04:05.000"))

		// Obfuscate with timing delay
		obfuscated, err := engine.ObfuscateData(tc.data)
		if err != nil {
			log.Printf("Failed to obfuscate %s: %v", tc.name, err)
			continue
		}

		afterObfuscate := time.Now()
		obfuscateDelay := afterObfuscate.Sub(start)
		fmt.Printf("After obfuscate: %s (delay: %v)\n",
			afterObfuscate.Format("15:04:05.000"), obfuscateDelay)

		// Data should remain unchanged (timing obfuscation doesn't modify data)
		if !bytes.Equal(tc.data, obfuscated) {
			log.Printf("Warning: Data was modified during timing obfuscation!")
		}

		// Deobfuscate (should be immediate)
		deobfuscated, err := engine.DeobfuscateData(obfuscated)
		if err != nil {
			log.Printf("Failed to deobfuscate %s: %v", tc.name, err)
			continue
		}

		afterDeobfuscate := time.Now()
		deobfuscateDelay := afterDeobfuscate.Sub(afterObfuscate)
		fmt.Printf("After deobfuscate: %s (delay: %v)\n",
			afterDeobfuscate.Format("15:04:05.000"), deobfuscateDelay)

		totalTime := afterDeobfuscate.Sub(start)
		fmt.Printf("Total processing time: %v\n", totalTime)
		fmt.Printf("Round-trip success: %v\n", bytes.Equal(tc.data, deobfuscated))

		// Small delay between test cases for better readability
		time.Sleep(100 * time.Millisecond)
	}

	// Show timing obfuscation metrics
	metrics := engine.GetMetrics()
	fmt.Printf("\nTiming Obfuscation metrics:\n")
	fmt.Printf("- Total packets: %d\n", metrics.TotalPackets)
	fmt.Printf("- Total bytes: %d\n", metrics.TotalBytes)
	fmt.Printf("- Method switches: %d\n", metrics.MethodSwitches)
	if methodMetrics, exists := metrics.MethodMetrics[obfuscation.MethodTimingObfs]; exists {
		fmt.Printf("- Average processing time: %v\n", methodMetrics.AvgProcessTime)
	}

	// Test the actual timing obfuscator directly with different configurations
	fmt.Printf("\nDirect Timing Obfuscation test (fixed delay):\n")
	timingConfig := &obfuscation.TimingObfsConfig{
		Enabled:      true,
		MinDelay:     10 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond, // Fixed delay
		RandomJitter: false,                 // Disable jitter for predictable timing
	}

	timing, err := obfuscation.NewTimingObfuscation(timingConfig, logger)
	if err != nil {
		log.Printf("Failed to create direct timing obfuscation: %v", err)
		return
	}

	directData := []byte("Direct timing test with fixed 10ms delay")
	fmt.Printf("Testing fixed delay (should be exactly 10ms):\n")

	// Test multiple times to show consistency
	for i := 0; i < 3; i++ {
		start := time.Now()
		obfuscated, err := timing.Obfuscate(directData)
		elapsed := time.Since(start)

		if err != nil {
			log.Printf("Direct obfuscation failed: %v", err)
			continue
		}

		fmt.Printf("  Attempt %d: %v\n", i+1, elapsed)

		if !bytes.Equal(directData, obfuscated) {
			log.Printf("Warning: Data was modified!")
		}
	}

	// Show timing obfuscation metrics
	timingMetrics := timing.GetMetrics()
	fmt.Printf("Direct timing metrics: %d packets, %d bytes processed\n",
		timingMetrics.PacketsProcessed, timingMetrics.BytesProcessed)

	// Test exponential distribution vs uniform distribution
	fmt.Printf("\nTesting exponential vs uniform delay distribution:\n")

	// Exponential distribution (more realistic)
	expConfig := &obfuscation.TimingObfsConfig{
		Enabled:      true,
		MinDelay:     1 * time.Millisecond,
		MaxDelay:     20 * time.Millisecond,
		RandomJitter: true, // Uses exponential distribution
	}

	expTiming, err := obfuscation.NewTimingObfuscation(expConfig, logger)
	if err != nil {
		log.Printf("Failed to create exponential timing: %v", err)
		return
	}

	fmt.Printf("Exponential distribution (5 samples):\n")
	for i := 0; i < 5; i++ {
		start := time.Now()
		_, err := expTiming.Obfuscate([]byte("sample"))
		elapsed := time.Since(start)
		if err == nil {
			fmt.Printf("  Sample %d: %v\n", i+1, elapsed)
		}
	}
}

func demoTrafficPadding(logger *log.Logger) {
	// Create traffic padding configuration
	config := &obfuscation.Config{
		EnabledMethods:  []obfuscation.ObfuscationMethod{obfuscation.MethodTrafficPadding},
		PrimaryMethod:   obfuscation.MethodTrafficPadding,
		FallbackMethods: []obfuscation.ObfuscationMethod{},
		AutoDetection:   false,
		TrafficPadding: obfuscation.TrafficPaddingConfig{
			Enabled:      true,
			MinInterval:  200 * time.Millisecond,
			MaxInterval:  1 * time.Second,
			MinDummySize: 128,
			MaxDummySize: 512,
			BurstMode:    true,
			BurstSize:    3,
			AdaptiveMode: true,
		},
	}

	// Create engine with traffic padding
	engine, err := obfuscation.NewEngine(config, logger)
	if err != nil {
		log.Fatalf("Failed to create traffic padding engine: %v", err)
	}
	defer engine.Close()

	fmt.Printf("Traffic Padding method: %s\n", engine.GetCurrentMethod())
	fmt.Printf("Min interval: %v\n", config.TrafficPadding.MinInterval)
	fmt.Printf("Max interval: %v\n", config.TrafficPadding.MaxInterval)
	fmt.Printf("Dummy size range: %d-%d bytes\n", config.TrafficPadding.MinDummySize, config.TrafficPadding.MaxDummySize)
	fmt.Printf("Burst mode: %v (size: %d)\n", config.TrafficPadding.BurstMode, config.TrafficPadding.BurstSize)
	fmt.Printf("Adaptive mode: %v\n", config.TrafficPadding.AdaptiveMode)

	// Test different types of data to show traffic padding behavior
	testCases := []struct {
		name string
		data []byte
	}{
		{"Control signal", []byte("CONNECT")},
		{"Authentication", []byte(`{"type":"auth","user":"alice","pass":"secret"}`)},
		{"Small message", []byte("Hello, World!")},
		{"Medium payload", bytes.Repeat([]byte("Data chunk "), 20)},         // ~220 bytes
		{"Large transfer", bytes.Repeat([]byte("BULK_DATA_TRANSFER_"), 40)}, // ~760 bytes
	}

	fmt.Printf("\nTesting traffic padding (data is unchanged, dummy traffic added separately):\n")

	for _, tc := range testCases {
		fmt.Printf("\nProcessing %s:\n", tc.name)
		fmt.Printf("Original size: %d bytes\n", len(tc.data))

		// Process with traffic padding
		obfuscated, err := engine.ObfuscateData(tc.data)
		if err != nil {
			log.Printf("Failed to obfuscate %s: %v", tc.name, err)
			continue
		}

		// Data should remain unchanged (traffic padding doesn't modify data)
		if !bytes.Equal(tc.data, obfuscated) {
			log.Printf("Warning: Data was modified during traffic padding!")
		}

		fmt.Printf("Processed size: %d bytes (unchanged)\n", len(obfuscated))

		// Deobfuscate
		deobfuscated, err := engine.DeobfuscateData(obfuscated)
		if err != nil {
			log.Printf("Failed to deobfuscate %s: %v", tc.name, err)
			continue
		}

		fmt.Printf("Round-trip success: %v\n", bytes.Equal(tc.data, deobfuscated))
		fmt.Printf("Note: Dummy traffic is injected separately via connection wrapper\n")
	}

	// Show traffic padding metrics
	metrics := engine.GetMetrics()
	fmt.Printf("\nTraffic Padding metrics:\n")
	fmt.Printf("- Total packets: %d\n", metrics.TotalPackets)
	fmt.Printf("- Total bytes: %d\n", metrics.TotalBytes)
	fmt.Printf("- Method switches: %d\n", metrics.MethodSwitches)

	// Test the actual traffic padding obfuscator directly
	fmt.Printf("\nDirect Traffic Padding test:\n")
	trafficConfig := &obfuscation.TrafficPaddingConfig{
		Enabled:      true,
		MinInterval:  100 * time.Millisecond,
		MaxInterval:  500 * time.Millisecond,
		MinDummySize: 64,
		MaxDummySize: 256,
		BurstMode:    false,
		BurstSize:    1,
		AdaptiveMode: false,
	}

	padding, err := obfuscation.NewTrafficPadding(trafficConfig, logger)
	if err != nil {
		log.Printf("Failed to create direct traffic padding: %v", err)
		return
	}

	directData := []byte("Direct traffic padding test data")
	obfuscated, err := padding.Obfuscate(directData)
	if err != nil {
		log.Printf("Direct obfuscation failed: %v", err)
		return
	}

	deobfuscated, err := padding.Deobfuscate(obfuscated)
	if err != nil {
		log.Printf("Direct deobfuscation failed: %v", err)
		return
	}

	fmt.Printf("Direct test successful: %v\n", bytes.Equal(directData, deobfuscated))
	fmt.Printf("Data size unchanged: %d bytes\n", len(obfuscated))

	// Test dummy packet detection
	fmt.Printf("\nTesting dummy packet detection:\n")
	dummyPacket := []byte("DUMMY_TPThis is a dummy packet with random content")
	fmt.Printf("Dummy packet size: %d bytes\n", len(dummyPacket))

	deobfuscatedDummy, err := padding.Deobfuscate(dummyPacket)
	if err != nil {
		log.Printf("Dummy packet deobfuscation failed: %v", err)
		return
	}

	fmt.Printf("Dummy packet filtered out: %v (returned %d bytes)\n",
		len(deobfuscatedDummy) == 0, len(deobfuscatedDummy))

	// Show traffic padding metrics
	paddingMetrics := padding.GetMetrics()
	fmt.Printf("Direct traffic padding metrics: %d packets, %d bytes processed\n",
		paddingMetrics.PacketsProcessed, paddingMetrics.BytesProcessed)

	fmt.Printf("\nTraffic Padding overview:\n")
	fmt.Printf("- Injects dummy packets at random intervals\n")
	fmt.Printf("- Maintains constant traffic flow even during idle periods\n")
	fmt.Printf("- Supports burst mode for realistic traffic patterns\n")
	fmt.Printf("- Adaptive mode reduces intervals during low activity\n")
	fmt.Printf("- Dummy packets are filtered out automatically\n")
}

func demoHTTPMimicry(logger *log.Logger) {
	// Create HTTP mimicry configuration
	config := &obfuscation.Config{
		EnabledMethods:  []obfuscation.ObfuscationMethod{obfuscation.MethodHTTPMimicry},
		PrimaryMethod:   obfuscation.MethodHTTPMimicry,
		FallbackMethods: []obfuscation.ObfuscationMethod{},
		AutoDetection:   false,
		HTTPMimicry: obfuscation.HTTPMimicryConfig{
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
			FakeHost:  "api.github.com",
			CustomHeaders: map[string]string{
				"Authorization":        "Bearer ghp_example123456789",
				"X-GitHub-Api-Version": "2022-11-28",
			},
			MimicWebsite: "https://api.github.com",
		},
	}

	// Create engine with HTTP mimicry
	engine, err := obfuscation.NewEngine(config, logger)
	if err != nil {
		log.Fatalf("Failed to create HTTP mimicry engine: %v", err)
	}
	defer engine.Close()

	fmt.Printf("HTTP Mimicry method: %s\n", engine.GetCurrentMethod())
	fmt.Printf("Fake host: %s\n", config.HTTPMimicry.FakeHost)
	fmt.Printf("Custom headers: %v\n", config.HTTPMimicry.CustomHeaders)

	// Test different types of data to show HTTP request/response patterns
	testCases := []struct {
		name string
		data []byte
	}{
		{"User login", []byte(`{"username":"alice","password":"secret123","remember_me":true}`)},
		{"API request", []byte(`{"query":"mutation { createIssue(input: {title: \"Bug report\"}) { id } }"}`)},
		{"File content", []byte("GET /repos/user/repo/contents/README.md HTTP/1.1\r\nHost: api.github.com")},
		{"Small data", []byte("ping")},
		{"Large payload", bytes.Repeat([]byte("Large encrypted VPN payload chunk "), 20)}, // ~680 bytes
	}

	for _, tc := range testCases {
		fmt.Printf("\nTesting %s:\n", tc.name)
		fmt.Printf("Original data size: %d bytes\n", len(tc.data))

		// Obfuscate with HTTP mimicry
		obfuscated, err := engine.ObfuscateData(tc.data)
		if err != nil {
			log.Printf("Failed to obfuscate %s: %v", tc.name, err)
			continue
		}

		fmt.Printf("HTTP packet size: %d bytes\n", len(obfuscated))

		// Show partial HTTP structure (first few lines)
		obfuscatedStr := string(obfuscated)
		lines := strings.Split(obfuscatedStr, "\r\n")
		fmt.Printf("HTTP structure preview:\n")
		for i, line := range lines {
			if i >= 5 || line == "" { // Show first 5 lines or until empty line
				if line == "" {
					fmt.Printf("  [HTTP body follows...]\n")
				}
				break
			}
			fmt.Printf("  %s\n", line)
		}

		// Deobfuscate
		deobfuscated, err := engine.DeobfuscateData(obfuscated)
		if err != nil {
			log.Printf("Failed to deobfuscate %s: %v", tc.name, err)
			continue
		}

		fmt.Printf("Restored data size: %d bytes\n", len(deobfuscated))
		fmt.Printf("Round-trip success: %v\n", bytes.Equal(tc.data, deobfuscated))

		// Show size overhead ratio
		ratio := float64(len(obfuscated)) / float64(len(tc.data))
		fmt.Printf("Size overhead: %.2fx\n", ratio)
	}

	// Show HTTP mimicry metrics
	metrics := engine.GetMetrics()
	fmt.Printf("\nHTTP Mimicry metrics:\n")
	fmt.Printf("- Total packets: %d\n", metrics.TotalPackets)
	fmt.Printf("- Total bytes: %d\n", metrics.TotalBytes)
	fmt.Printf("- Method switches: %d\n", metrics.MethodSwitches)

	// Test the actual HTTP mimicry obfuscator directly
	fmt.Printf("\nDirect HTTP Mimicry test:\n")
	httpConfig := &obfuscation.HTTPMimicryConfig{
		UserAgent:     "GoVPN/1.0 (Direct Test)",
		FakeHost:      "postman-echo.com",
		CustomHeaders: map[string]string{"X-Test": "direct-mode"},
		MimicWebsite:  "https://postman-echo.com/post",
	}

	mimicry, err := obfuscation.NewHTTPMimicry(httpConfig, logger)
	if err != nil {
		log.Printf("Failed to create direct HTTP mimicry: %v", err)
		return
	}

	directData := []byte("Direct HTTP mimicry test with realistic data")
	obfuscated, err := mimicry.Obfuscate(directData)
	if err != nil {
		log.Printf("Direct obfuscation failed: %v", err)
		return
	}

	deobfuscated, err := mimicry.Deobfuscate(obfuscated)
	if err != nil {
		log.Printf("Direct deobfuscation failed: %v", err)
		return
	}

	fmt.Printf("Direct test successful: %v\n", bytes.Equal(directData, deobfuscated))
	fmt.Printf("Direct HTTP packet size: %d bytes\n", len(obfuscated))

	// Show HTTP mimicry metrics
	httpMetrics := mimicry.GetMetrics()
	fmt.Printf("Direct HTTP metrics: %d packets, %d bytes processed\n",
		httpMetrics.PacketsProcessed, httpMetrics.BytesProcessed)
}

func demoDNSTunneling(logger *log.Logger) {
	// Create DNS tunneling configuration
	config := &obfuscation.Config{
		EnabledMethods:  []obfuscation.ObfuscationMethod{obfuscation.MethodDNSTunnel},
		PrimaryMethod:   obfuscation.MethodDNSTunnel,
		FallbackMethods: []obfuscation.ObfuscationMethod{},
		AutoDetection:   false,
		DNSTunnel: obfuscation.DNSTunnelConfig{
			Enabled:        true,
			DomainSuffix:   "demo.govpn.local",
			DNSServers:     []string{"8.8.8.8:53", "1.1.1.1:53"},
			QueryTypes:     []string{"A", "TXT", "CNAME"},
			EncodingMethod: "base32",
			MaxPayloadSize: 32,
			QueryDelay:     50 * time.Millisecond,
			Subdomain:      "tunnel",
		},
	}

	// Create engine with DNS tunneling
	engine, err := obfuscation.NewEngine(config, logger)
	if err != nil {
		log.Fatalf("Failed to create DNS tunneling engine: %v", err)
	}
	defer engine.Close()

	fmt.Printf("DNS Tunneling method: %s\n", engine.GetCurrentMethod())
	fmt.Printf("Domain suffix: %s\n", config.DNSTunnel.DomainSuffix)
	fmt.Printf("DNS servers: %v\n", config.DNSTunnel.DNSServers)
	fmt.Printf("Query types: %v\n", config.DNSTunnel.QueryTypes)
	fmt.Printf("Max payload size: %d bytes\n", config.DNSTunnel.MaxPayloadSize)
	fmt.Printf("Query delay: %v\n", config.DNSTunnel.QueryDelay)

	// Test different types of data for DNS tunneling
	testCases := []struct {
		name string
		data []byte
	}{
		{"Control message", []byte("HELLO_DNS")},
		{"Authentication", []byte(`{"auth":"token123"}`)},
		{"Small payload", []byte("Emergency backup communication via DNS tunneling")},
		{"Binary data", []byte{0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x44, 0x4E, 0x53}},
		{"Medium data", bytes.Repeat([]byte("DNS "), 25)}, // ~100 bytes
	}

	for _, tc := range testCases {
		fmt.Printf("\nTesting %s:\n", tc.name)
		fmt.Printf("Original size: %d bytes\n", len(tc.data))
		fmt.Printf("Original data: %s\n", string(tc.data))

		// Apply DNS tunneling
		obfuscated, err := engine.ObfuscateData(tc.data)
		if err != nil {
			log.Printf("Failed to obfuscate %s: %v", tc.name, err)
			continue
		}

		fmt.Printf("DNS packet size: %d bytes (%.1fx expansion)\n",
			len(obfuscated), float64(len(obfuscated))/float64(len(tc.data)))

		// Show DNS packet structure (first 100 bytes)
		showBytes := 100
		if len(obfuscated) < showBytes {
			showBytes = len(obfuscated)
		}
		fmt.Printf("DNS packet preview: %x...\n", obfuscated[:showBytes])

		// Deobfuscate
		deobfuscated, err := engine.DeobfuscateData(obfuscated)
		if err != nil {
			log.Printf("Failed to deobfuscate %s: %v", tc.name, err)
			continue
		}

		fmt.Printf("Restored data: %s\n", string(deobfuscated))
		fmt.Printf("Round-trip: %v\n", bytes.Equal(tc.data, deobfuscated))
	}

	// Show DNS tunneling metrics
	metrics := engine.GetMetrics()
	fmt.Printf("\nDNS Tunneling metrics:\n")
	fmt.Printf("- Total packets: %d\n", metrics.TotalPackets)
	fmt.Printf("- Total bytes: %d\n", metrics.TotalBytes)
	if methodMetrics, exists := metrics.MethodMetrics[obfuscation.MethodDNSTunnel]; exists {
		fmt.Printf("- Average processing time: %v\n", methodMetrics.AvgProcessTime)
	}

	// Test the actual DNS tunneling obfuscator directly
	fmt.Printf("\nDirect DNS Tunneling test:\n")
	dnsConfig := &obfuscation.DNSTunnelConfig{
		Enabled:        true,
		DomainSuffix:   "direct.test.local",
		DNSServers:     []string{"8.8.8.8:53"},
		QueryTypes:     []string{"TXT"},
		EncodingMethod: "base32",
		MaxPayloadSize: 24,
		QueryDelay:     10 * time.Millisecond,
		Subdomain:      "direct",
	}

	tunnel, err := obfuscation.NewDNSTunnel(dnsConfig, logger)
	if err != nil {
		log.Printf("Failed to create direct DNS tunnel: %v", err)
		return
	}

	directData := []byte("Direct DNS tunneling test")
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

	fmt.Printf("Direct test successful: %v\n", bytes.Equal(directData, deobfuscated))
	fmt.Printf("Direct DNS packet size: %d bytes\n", len(obfuscated))

	// Show DNS tunneling metrics
	dnsMetrics := tunnel.GetMetrics()
	fmt.Printf("Direct DNS metrics: %d packets, %d bytes processed\n",
		dnsMetrics.PacketsProcessed, dnsMetrics.BytesProcessed)

	fmt.Printf("\nDNS Tunneling overview:\n")
	fmt.Printf("- Encodes VPN data into DNS queries and responses\n")
	fmt.Printf("- Works through most firewalls (DNS rarely blocked)\n")
	fmt.Printf("- Uses Base32 encoding for DNS compatibility\n")
	fmt.Printf("- Supports multiple DNS servers for redundancy\n")
	fmt.Printf("- Configurable query delays to avoid detection\n")
	fmt.Printf("- Higher latency but excellent bypass capabilities\n")
	fmt.Printf("- Ideal for emergency backup communication\n")
}

func demoHTTPSteganography(logger *log.Logger) {
	// Create HTTP steganography configuration
	config := &obfuscation.Config{
		EnabledMethods:  []obfuscation.ObfuscationMethod{obfuscation.MethodHTTPStego},
		PrimaryMethod:   obfuscation.MethodHTTPStego,
		FallbackMethods: []obfuscation.ObfuscationMethod{},
		AutoDetection:   false,
		HTTPStego: obfuscation.HTTPStegoConfig{
			Enabled:        true,
			CoverWebsites:  []string{"github.com", "stackoverflow.com", "reddit.com"},
			UserAgents:     []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
			ContentTypes:   []string{"text/html", "application/json", "text/css", "application/javascript"},
			SteganoMethod:  "headers_and_body",
			ChunkSize:      64,
			ErrorRate:      0.02,
			SessionTimeout: 15 * time.Minute,
			EnableMIME:     true,
			CachingEnabled: false,
		},
	}

	// Create engine with HTTP steganography
	engine, err := obfuscation.NewEngine(config, logger)
	if err != nil {
		log.Fatalf("Failed to create HTTP steganography engine: %v", err)
	}
	defer engine.Close()

	fmt.Printf("HTTP Steganography method: %s\n", engine.GetCurrentMethod())
	fmt.Printf("Cover websites: %v\n", config.HTTPStego.CoverWebsites)
	fmt.Printf("Content types: %v\n", config.HTTPStego.ContentTypes)
	fmt.Printf("Steganographic method: %s\n", config.HTTPStego.SteganoMethod)
	fmt.Printf("Chunk size: %d bytes\n", config.HTTPStego.ChunkSize)

	// Test different steganographic methods
	steganographicMethods := []string{
		"headers_and_body",
		"multipart_forms",
		"json_api",
		"css_comments",
		"js_variables",
	}

	testData := []byte("Confidential VPN data hidden using HTTP steganography techniques")

	for i, method := range steganographicMethods {
		fmt.Printf("\n%d. Testing %s method:\n", i+1, method)

		// Update method in config
		config.HTTPStego.SteganoMethod = method

		// Create new engine with updated config
		methodEngine, err := obfuscation.NewEngine(config, logger)
		if err != nil {
			log.Printf("Failed to create engine for method %s: %v", method, err)
			continue
		}

		fmt.Printf("Original data: %s\n", string(testData))
		fmt.Printf("Original size: %d bytes\n", len(testData))

		// Apply HTTP steganography
		obfuscated, err := methodEngine.ObfuscateData(testData)
		if err != nil {
			log.Printf("Failed to obfuscate with method %s: %v", method, err)
			methodEngine.Close()
			continue
		}

		fmt.Printf("Steganographic size: %d bytes (%.1fx expansion)\n",
			len(obfuscated), float64(len(obfuscated))/float64(len(testData)))

		// Show HTTP structure preview
		obfuscatedStr := string(obfuscated)
		lines := strings.Split(obfuscatedStr, "\r\n")
		fmt.Printf("HTTP structure preview:\n")
		for j, line := range lines {
			if j >= 8 || line == "" { // Show first 8 lines or until empty line
				if line == "" {
					fmt.Printf("  [HTTP body follows...]\n")
				}
				break
			}
			if len(line) > 80 {
				fmt.Printf("  %s...\n", line[:80])
			} else {
				fmt.Printf("  %s\n", line)
			}
		}

		// Deobfuscate
		deobfuscated, err := methodEngine.DeobfuscateData(obfuscated)
		if err != nil {
			log.Printf("Failed to deobfuscate with method %s: %v", method, err)
			methodEngine.Close()
			continue
		}

		fmt.Printf("Extracted data: %s\n", string(deobfuscated))
		fmt.Printf("Round-trip success: %v\n", bytes.Equal(testData, deobfuscated))

		methodEngine.Close()
	}

	// Show HTTP steganography metrics
	metrics := engine.GetMetrics()
	fmt.Printf("\nHTTP Steganography metrics:\n")
	fmt.Printf("- Total packets: %d\n", metrics.TotalPackets)
	fmt.Printf("- Total bytes: %d\n", metrics.TotalBytes)
	if methodMetrics, exists := metrics.MethodMetrics[obfuscation.MethodHTTPStego]; exists {
		fmt.Printf("- Average processing time: %v\n", methodMetrics.AvgProcessTime)
	}

	// Test different data types
	fmt.Printf("\nTesting different data types:\n")
	dataTypes := []struct {
		name string
		data []byte
	}{
		{"JSON API call", []byte(`{"action":"authenticate","user":"alice","token":"secret123"}`)},
		{"Binary config", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52}},
		{"Large payload", bytes.Repeat([]byte("STEGANOGRAPHIC_DATA_"), 25)}, // ~500 bytes
		{"Control command", []byte("CONNECT_VPN_SERVER_192_168_1_1")},
	}

	for _, dt := range dataTypes {
		fmt.Printf("\nTesting %s:\n", dt.name)
		fmt.Printf("Size: %d bytes\n", len(dt.data))

		obfuscated, err := engine.ObfuscateData(dt.data)
		if err != nil {
			log.Printf("Failed to obfuscate %s: %v", dt.name, err)
			continue
		}

		deobfuscated, err := engine.DeobfuscateData(obfuscated)
		if err != nil {
			log.Printf("Failed to deobfuscate %s: %v", dt.name, err)
			continue
		}

		fmt.Printf("Steganographic HTTP size: %d bytes\n", len(obfuscated))
		fmt.Printf("Data integrity: %v\n", bytes.Equal(dt.data, deobfuscated))

		expansion := float64(len(obfuscated)) / float64(len(dt.data))
		fmt.Printf("Size expansion: %.1fx\n", expansion)
	}

	fmt.Printf("\nHTTP Steganography overview:\n")
	fmt.Printf("- Hides VPN data within legitimate HTTP traffic\n")
	fmt.Printf("- Multiple embedding methods for different scenarios\n")
	fmt.Printf("- Headers and body: Fast, good for small data\n")
	fmt.Printf("- Multipart forms: Excellent cover for file uploads\n")
	fmt.Printf("- JSON API: Perfect for web application traffic\n")
	fmt.Printf("- CSS/JS comments: Stealthy for web resources\n")
	fmt.Printf("- Realistic HTTP structure with proper headers\n")
	fmt.Printf("- Configurable websites and user agents for authenticity\n")
	fmt.Printf("- Automatic checksum verification for data integrity\n")
}

func demoFlowWatermarking(logger *log.Logger) {
	// Create flow watermarking configuration
	config := &obfuscation.Config{
		EnabledMethods:  []obfuscation.ObfuscationMethod{obfuscation.MethodFlowWatermark},
		PrimaryMethod:   obfuscation.MethodFlowWatermark,
		FallbackMethods: []obfuscation.ObfuscationMethod{},
		AutoDetection:   false,
		FlowWatermark: obfuscation.FlowWatermarkConfig{
			Enabled:         true,
			WatermarkKey:    []byte("demo-flow-watermark-key-123456789012"),
			PatternInterval: 300 * time.Millisecond,
			PatternStrength: 0.4,
			NoiseLevel:      0.15,
			RotationPeriod:  2 * time.Minute,
			StatisticalMode: true,
			FrequencyBands:  []int{1, 2, 5, 10, 20},
		},
	}

	// Create engine with flow watermarking
	engine, err := obfuscation.NewEngine(config, logger)
	if err != nil {
		log.Fatalf("Failed to create flow watermarking engine: %v", err)
	}
	defer engine.Close()

	fmt.Printf("Flow Watermarking method: %s\n", engine.GetCurrentMethod())
	fmt.Printf("Pattern strength: %.2f\n", config.FlowWatermark.PatternStrength)
	fmt.Printf("Noise level: %.2f\n", config.FlowWatermark.NoiseLevel)
	fmt.Printf("Frequency bands: %v\n", config.FlowWatermark.FrequencyBands)
	fmt.Printf("Statistical mode: %v\n", config.FlowWatermark.StatisticalMode)

	// Test different types of data to show flow watermarking behavior
	testCases := []struct {
		name string
		data []byte
	}{
		{"Control packet", []byte("CTRL_PKT_01")},
		{"Authentication", []byte(`{"type":"auth","user":"demo","token":"abc123xyz789"}`)},
		{"VPN payload", []byte("Encrypted VPN payload with sensitive user data that needs statistical obfuscation")},
		{"Binary data", []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC, 0x80, 0x7F, 0x40, 0x3F}},
		{"Large data", bytes.Repeat([]byte("LARGE_DATA_CHUNK_"), 30)}, // ~510 bytes
	}

	for _, tc := range testCases {
		fmt.Printf("\nTesting %s:\n", tc.name)
		fmt.Printf("Original size: %d bytes\n", len(tc.data))

		// Show first few bytes for comparison
		showBytes := 16
		if len(tc.data) < showBytes {
			showBytes = len(tc.data)
		}
		fmt.Printf("Original bytes:    %x\n", tc.data[:showBytes])

		// Apply flow watermarking
		obfuscated, err := engine.ObfuscateData(tc.data)
		if err != nil {
			log.Printf("Failed to obfuscate %s: %v", tc.name, err)
			continue
		}

		fmt.Printf("Watermarked size:  %d bytes (unchanged)\n", len(obfuscated))
		fmt.Printf("Watermarked bytes: %x\n", obfuscated[:showBytes])

		// Calculate statistical difference
		differences := 0
		for i := 0; i < showBytes; i++ {
			if tc.data[i] != obfuscated[i] {
				differences++
			}
		}
		fmt.Printf("Byte differences:  %d/%d (%.1f%%)\n", differences, showBytes, float64(differences)/float64(showBytes)*100)

		// Deobfuscate
		deobfuscated, err := engine.DeobfuscateData(obfuscated)
		if err != nil {
			log.Printf("Failed to deobfuscate %s: %v", tc.name, err)
			continue
		}

		fmt.Printf("Restored bytes:    %x\n", deobfuscated[:showBytes])
		fmt.Printf("Round-trip:        %v\n", bytes.Equal(tc.data, deobfuscated))

		// Show statistical characteristics
		originalSum := 0
		watermarkedSum := 0
		for _, b := range tc.data {
			originalSum += int(b)
		}
		for _, b := range obfuscated {
			watermarkedSum += int(b)
		}
		fmt.Printf("Original checksum:    %d\n", originalSum%1000)
		fmt.Printf("Watermarked checksum: %d\n", watermarkedSum%1000)
	}

	// Show flow watermarking metrics
	metrics := engine.GetMetrics()
	fmt.Printf("\nFlow Watermarking metrics:\n")
	fmt.Printf("- Total packets: %d\n", metrics.TotalPackets)
	fmt.Printf("- Total bytes: %d\n", metrics.TotalBytes)
	fmt.Printf("- Method switches: %d\n", metrics.MethodSwitches)
	if methodMetrics, exists := metrics.MethodMetrics[obfuscation.MethodFlowWatermark]; exists {
		fmt.Printf("- Average processing time: %v\n", methodMetrics.AvgProcessTime)
	}

	// Test the actual flow watermarking obfuscator directly
	fmt.Printf("\nDirect Flow Watermarking test:\n")
	flowConfig := &obfuscation.FlowWatermarkConfig{
		Enabled:         true,
		WatermarkKey:    []byte("direct-flow-watermark-key-987654321"),
		PatternInterval: 100 * time.Millisecond,
		PatternStrength: 0.6,
		NoiseLevel:      0.3,
		RotationPeriod:  1 * time.Minute,
		StatisticalMode: false, // Test non-statistical mode
		FrequencyBands:  []int{2, 4, 8, 16},
	}

	watermark, err := obfuscation.NewFlowWatermark(flowConfig, logger)
	if err != nil {
		log.Printf("Failed to create direct flow watermarking: %v", err)
		return
	}

	directData := []byte("Direct flow watermarking test with non-statistical mode")
	obfuscated, err := watermark.Obfuscate(directData)
	if err != nil {
		log.Printf("Direct obfuscation failed: %v", err)
		return
	}

	deobfuscated, err := watermark.Deobfuscate(obfuscated)
	if err != nil {
		log.Printf("Direct deobfuscation failed: %v", err)
		return
	}

	fmt.Printf("Direct test successful: %v\n", bytes.Equal(directData, deobfuscated))
	fmt.Printf("Non-statistical mode creates different patterns\n")

	// Show watermarking metrics
	watermarkMetrics := watermark.GetMetrics()
	fmt.Printf("Direct watermarking metrics: %d packets, %d bytes processed\n",
		watermarkMetrics.PacketsProcessed, watermarkMetrics.BytesProcessed)

	fmt.Printf("\nFlow Watermarking overview:\n")
	fmt.Printf("- Distorts statistical characteristics of data flow\n")
	fmt.Printf("- Uses cryptographic keys to generate unique patterns\n")
	fmt.Printf("- Supports both statistical and simple XOR modes\n")
	fmt.Printf("- Periodically rotates patterns for security\n")
	fmt.Printf("- Maintains data integrity while changing statistics\n")
	fmt.Printf("- Effective against flow analysis and DPI correlation\n")
}

func demoAutoSwitching(logger *log.Logger) {
	// Configuration with auto-switching
	config := &obfuscation.Config{
		EnabledMethods: []obfuscation.ObfuscationMethod{
			obfuscation.MethodXORCipher,
			obfuscation.MethodTLSTunnel,
			obfuscation.MethodPacketPadding,
			obfuscation.MethodHTTPMimicry,
		},
		PrimaryMethod: obfuscation.MethodXORCipher,
		FallbackMethods: []obfuscation.ObfuscationMethod{
			obfuscation.MethodTLSTunnel,
			obfuscation.MethodPacketPadding,
			obfuscation.MethodHTTPMimicry,
		},
		AutoDetection:    true,
		SwitchThreshold:  2,
		DetectionTimeout: 3 * time.Second,
		XORKey:           []byte("auto-switch-demo-key-123456789"),
		PacketPadding: obfuscation.PacketPaddingConfig{
			Enabled:       true,
			MinPadding:    5,
			MaxPadding:    50,
			RandomizeSize: true,
		},
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

func demoAuthentication(logger *log.Logger) {
	fmt.Println("=== GoVPN Authentication System Demo ===")

	// Basic authentication demonstration
	fmt.Println("1. Basic Local Authentication Demo")
	demoBasicAuth()

	fmt.Println("\n" + strings.Repeat("=", 60) + "\n")

	// MFA demonstration
	fmt.Println("2. Multi-Factor Authentication (MFA) Demo")
	demoMFA()

	fmt.Println("\n" + strings.Repeat("=", 60) + "\n")

	// User management demonstration
	fmt.Println("3. User Management Demo")
	demoUserManagement()

	fmt.Println("\n" + strings.Repeat("=", 60) + "\n")

	// LDAP demonstration (without real connection)
	fmt.Println("4. LDAP Configuration Demo")
	demoLDAPConfig()

	fmt.Println("\n" + strings.Repeat("=", 60) + "\n")

	// OIDC demonstration (without real connection)
	fmt.Println("5. OIDC Configuration Demo")
	demoOIDCConfig()
}

func demoBasicAuth() {
	// Create authentication manager with basic configuration
	config := auth.DefaultAuthConfig()
	config.HashMethod = "argon2" // Use Argon2 for security

	authManager, err := auth.NewAuthManager(config)
	if err != nil {
		log.Fatalf("Error creating auth manager: %v", err)
	}
	defer authManager.Close()

	fmt.Printf("✓ Created authentication manager with hashing method: %s\n", config.HashMethod)

	// Create test user
	username := "alice"
	password := "secure_password_123"

	user, err := authManager.CreateUser(username, password)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		return
	}

	fmt.Printf("✓ Created user: %s (ID: %s)\n", user.Username, user.ID)
	fmt.Printf("  - Source: %s\n", user.Source)
	fmt.Printf("  - Active: %t\n", user.IsActive)
	fmt.Printf("  - Roles: %v\n", user.Roles)
	fmt.Printf("  - Created: %s\n", user.CreatedAt.Format("2006-01-02 15:04:05"))

	// Successful authentication
	result, err := authManager.AuthenticateUser(username, password)
	if err != nil {
		log.Printf("Authentication error: %v", err)
		return
	}

	fmt.Printf("✓ Successfully authenticated user: %s\n", result.User.Username)
	fmt.Printf("  - Authentication source: %s\n", result.Source)
	fmt.Printf("  - Requires MFA: %t\n", result.RequiresMFA)
	fmt.Printf("  - Last login: %s\n", result.User.LastLogin.Format("2006-01-02 15:04:05"))

	// Attempt authentication with wrong password
	_, err = authManager.AuthenticateUser(username, "wrong_password")
	if err != nil {
		fmt.Printf("✓ Correctly rejected authentication with wrong password: %v\n", err)
	}

	// Test different hashing algorithms
	fmt.Println("\n--- Testing Hashing Algorithms ---")
	testHashingMethods()
}

func demoMFA() {
	// Configuration with MFA enabled
	config := auth.DefaultAuthConfig()
	config.EnableMFA = true
	config.MFA = &auth.MFAConfig{
		Enabled:          true,
		RequiredForAll:   false, // MFA not required for all by default
		TOTPEnabled:      true,
		HOTPEnabled:      false,
		BackupCodesCount: 10,
		TOTPSettings: auth.TOTPSettings{
			Period:    30,                // 30 seconds
			Digits:    otp.DigitsSix,     // 6 digits using standard library
			Algorithm: otp.AlgorithmSHA1, // SHA1 using standard library
			Skew:      1,                 // Allowed deviation ±1 period
		},
		Issuer:          "GoVPN Demo",
		GracePeriod:     5 * time.Minute,
		MaxAttempts:     5,
		LockoutDuration: 15 * time.Minute,
	}

	authManager, err := auth.NewAuthManager(config)
	if err != nil {
		log.Fatalf("Error creating auth manager with MFA: %v", err)
	}
	defer authManager.Close()

	fmt.Printf("✓ Created authentication manager with MFA support\n")

	username := "bob"
	email := "bob@company.com"

	// Check initial MFA status
	status := authManager.GetMFAStatus(username)
	fmt.Printf("✓ Initial MFA status for %s: enabled=%v, setup_complete=%v\n",
		username, status["enabled"], status["setup_complete"])

	// Setup TOTP for user
	totpData, err := authManager.SetupMFA(username, email)
	if err != nil {
		log.Printf("Error setting up MFA: %v", err)
		return
	}

	fmt.Printf("✓ TOTP setup for user %s:\n", username)
	fmt.Printf("  - Secret key: %s\n", totpData.Secret)
	fmt.Printf("  - QR code URL: %s\n", totpData.URL)
	fmt.Printf("  - Backup codes: %d\n", len(totpData.BackupCodes))
	fmt.Printf("  - First 3 backup codes: %v\n", totpData.BackupCodes[:3])

	// TOTP code verification simulation (in reality user inputs code from app)
	fmt.Println("\n--- TOTP Verification Simulation ---")

	// In real application this would be actual TOTP code
	// For demonstration we just show the process
	fmt.Printf("📱 User should scan QR code in authenticator app\n")
	fmt.Printf("📱 Then enter 6-digit code to confirm setup\n")

	// Updated MFA status
	status = authManager.GetMFAStatus(username)
	fmt.Printf("✓ MFA status after setup: %+v\n", status)
}

func demoUserManagement() {
	authManager, err := auth.NewAuthManager(auth.DefaultAuthConfig())
	if err != nil {
		log.Fatalf("Error creating auth manager: %v", err)
	}
	defer authManager.Close()

	// Create multiple users
	users := []struct {
		username string
		password string
		roles    []string
	}{
		{"admin", "admin_password_123", []string{"admin", "user"}},
		{"user1", "user1_password_456", []string{"user"}},
		{"user2", "user2_password_789", []string{"user", "guest"}},
		{"operator", "operator_password_000", []string{"operator", "user"}},
	}

	fmt.Println("--- Creating Users ---")
	for _, userData := range users {
		user, err := authManager.CreateUser(userData.username, userData.password)
		if err != nil {
			log.Printf("Error creating user %s: %v", userData.username, err)
			continue
		}

		fmt.Printf("✓ Created user: %s\n", user.Username)

		// Add additional roles
		for _, role := range userData.roles {
			if role != "user" { // user role already added by default
				err = authManager.AddUserRole(userData.username, role)
				if err != nil {
					log.Printf("Error adding role %s to user %s: %v", role, userData.username, err)
				}
			}
		}

		updatedUser, _ := authManager.GetUser(userData.username)
		fmt.Printf("  - Roles: %v\n", updatedUser.Roles)
	}

	fmt.Println("\n--- List of All Users ---")
	allUsers := authManager.ListUsers()
	for username, user := range allUsers {
		fmt.Printf("User: %-10s | Active: %-5t | Roles: %v | Created: %s\n",
			username, user.IsActive, user.Roles, user.CreatedAt.Format("2006-01-02 15:04:05"))
	}

	fmt.Println("\n--- User Management ---")
	testUser := "user1"

	// Add role
	err = authManager.AddUserRole(testUser, "moderator")
	if err != nil {
		log.Printf("Error adding role: %v", err)
	} else {
		fmt.Printf("✓ Added 'moderator' role to user %s\n", testUser)
	}

	// Update password
	newPassword := "new_secure_password_456"
	err = authManager.UpdatePassword(testUser, newPassword)
	if err != nil {
		log.Printf("Error updating password: %v", err)
	} else {
		fmt.Printf("✓ Updated password for user %s\n", testUser)
	}

	// Test new password
	_, err = authManager.AuthenticateUser(testUser, newPassword)
	if err != nil {
		log.Printf("Error authenticating with new password: %v", err)
	} else {
		fmt.Printf("✓ Authentication with new password successful\n")
	}

	// Deactivate user
	err = authManager.SetUserActive(testUser, false)
	if err != nil {
		log.Printf("Error deactivating user: %v", err)
	} else {
		fmt.Printf("✓ User %s deactivated\n", testUser)
	}

	// Try to authenticate deactivated user
	_, err = authManager.AuthenticateUser(testUser, newPassword)
	if err != nil {
		fmt.Printf("✓ Correctly rejected authentication of deactivated user: %v\n", err)
	}

	// Remove role
	err = authManager.RemoveUserRole("admin", "admin")
	if err != nil {
		log.Printf("Error removing role: %v", err)
	} else {
		fmt.Printf("✓ Removed 'admin' role from user admin\n")
	}

	// Show updated admin user
	adminUser, exists := authManager.GetUser("admin")
	if exists {
		fmt.Printf("✓ User admin after role removal: roles=%v\n", adminUser.Roles)
	}
}

func demoLDAPConfig() {
	// LDAP configuration examples for different scenarios
	fmt.Println("--- LDAP Configuration for Active Directory ---")

	adConfig := &auth.LDAPConfig{
		Enabled:         true,
		Server:          "dc.company.com",
		Port:            389,
		UseSSL:          false,
		UseTLS:          true,
		SkipVerify:      false,
		Timeout:         10 * time.Second,
		BindDN:          "cn=ldap-reader,ou=service-accounts,dc=company,dc=com",
		BindPassword:    "service-account-password",
		BaseDN:          "dc=company,dc=com",
		UserFilter:      "(&(objectClass=user)(sAMAccountName=%s))",
		UserSearchBase:  "ou=users,dc=company,dc=com",
		GroupSearchBase: "ou=groups,dc=company,dc=com",
		UserAttributes: auth.UserAttributes{
			Username:    "sAMAccountName",
			Email:       "mail",
			FirstName:   "givenName",
			LastName:    "sn",
			DisplayName: "displayName",
			Groups:      "memberOf",
		},
		RequiredGroups:     []string{"CN=VPN-Users,ou=groups,dc=company,dc=com"},
		AdminGroups:        []string{"CN=VPN-Admins,ou=groups,dc=company,dc=com"},
		ConnectionPoolSize: 10,
		MaxRetries:         3,
		RetryDelay:         time.Second,
		CacheEnabled:       true,
		CacheTimeout:       5 * time.Minute,
	}

	fmt.Printf("✓ Server: %s:%d\n", adConfig.Server, adConfig.Port)
	fmt.Printf("✓ Security: SSL=%t, TLS=%t\n", adConfig.UseSSL, adConfig.UseTLS)
	fmt.Printf("✓ Base DN: %s\n", adConfig.BaseDN)
	fmt.Printf("✓ User filter: %s\n", adConfig.UserFilter)
	fmt.Printf("✓ Required groups: %v\n", adConfig.RequiredGroups)
	fmt.Printf("✓ Admin groups: %v\n", adConfig.AdminGroups)
	fmt.Printf("✓ Caching: enabled for %v\n", adConfig.CacheTimeout)

	fmt.Println("\n--- LDAP Configuration for OpenLDAP ---")

	openLDAPConfig := &auth.LDAPConfig{
		Enabled:         true,
		Server:          "ldap.company.com",
		Port:            389,
		UseSSL:          false,
		UseTLS:          true,
		BindDN:          "cn=readonly,dc=company,dc=com",
		BindPassword:    "readonly-password",
		BaseDN:          "dc=company,dc=com",
		UserFilter:      "(&(objectClass=posixAccount)(uid=%s))",
		UserSearchBase:  "ou=people,dc=company,dc=com",
		GroupSearchBase: "ou=groups,dc=company,dc=com",
		UserAttributes: auth.UserAttributes{
			Username:    "uid",
			Email:       "mail",
			FirstName:   "givenName",
			LastName:    "sn",
			DisplayName: "cn",
			Groups:      "memberOf",
		},
		RequiredGroups: []string{"cn=vpn-users,ou=groups,dc=company,dc=com"},
		AdminGroups:    []string{"cn=vpn-admins,ou=groups,dc=company,dc=com"},
	}

	fmt.Printf("✓ OpenLDAP Server: %s:%d\n", openLDAPConfig.Server, openLDAPConfig.Port)
	fmt.Printf("✓ User filter: %s\n", openLDAPConfig.UserFilter)
	fmt.Printf("✓ Username attribute: %s\n", openLDAPConfig.UserAttributes.Username)

	// Create auth manager with LDAP (without real connection)
	config := auth.DefaultAuthConfig()
	config.EnableLDAP = true
	config.LDAP = adConfig

	fmt.Println("\n--- Creating Manager with LDAP (simulation) ---")
	fmt.Printf("✓ LDAP configuration prepared\n")
	fmt.Printf("✓ In real environment, connection to %s would be established\n", adConfig.Server)
	fmt.Printf("✓ Bind would be performed with account: %s\n", adConfig.BindDN)
	fmt.Printf("✓ Connection pool of %d connections would be configured\n", adConfig.ConnectionPoolSize)
}

func demoOIDCConfig() {
	fmt.Println("--- OIDC Configuration for Keycloak (using standard golang.org/x/oauth2) ---")

	keycloakConfig := &auth.OIDCConfig{
		Enabled:          true,
		ProviderURL:      "https://auth.company.com/realms/company",
		ClientID:         "govpn-client",
		ClientSecret:     "govpn-client-secret-very-secure",
		RedirectURL:      "https://vpn.company.com/auth/callback",
		Scopes:           []string{"openid", "profile", "email", "groups"},
		IssuerValidation: true,
		RequiredClaims:   map[string]string{"email_verified": "true"},
		ClaimMappings: auth.ClaimMappings{
			Username:    "preferred_username",
			Email:       "email",
			FirstName:   "given_name",
			LastName:    "family_name",
			Groups:      "groups",
			Roles:       "realm_access.roles",
			DisplayName: "name",
		},
		SessionTimeout:      24 * time.Hour,
		RefreshTokenEnabled: true,
		DeviceFlowEnabled:   true,
		PkceEnabled:         true,
	}

	fmt.Printf("✓ OIDC Provider: %s\n", keycloakConfig.ProviderURL)
	fmt.Printf("✓ Client ID: %s\n", keycloakConfig.ClientID)
	fmt.Printf("✓ Redirect URL: %s\n", keycloakConfig.RedirectURL)
	fmt.Printf("✓ Scopes: %v\n", keycloakConfig.Scopes)
	fmt.Printf("✓ PKCE enabled: %t\n", keycloakConfig.PkceEnabled)
	fmt.Printf("✓ Device flow enabled: %t\n", keycloakConfig.DeviceFlowEnabled)
	fmt.Printf("✓ Session timeout: %v\n", keycloakConfig.SessionTimeout)

	fmt.Println("\n--- OIDC Configuration for Auth0 (using standard golang.org/x/oauth2) ---")

	auth0Config := &auth.OIDCConfig{
		Enabled:      true,
		ProviderURL:  "https://company.auth0.com",
		ClientID:     "your-auth0-client-id",
		ClientSecret: "your-auth0-client-secret",
		RedirectURL:  "https://vpn.company.com/auth/auth0/callback",
		Scopes:       []string{"openid", "profile", "email"},
		ClaimMappings: auth.ClaimMappings{
			Username:    "nickname",
			Email:       "email",
			FirstName:   "given_name",
			LastName:    "family_name",
			DisplayName: "name",
			Groups:      "https://company.com/groups", // Custom claim
			Roles:       "https://company.com/roles",  // Custom claim
		},
		SessionTimeout:      8 * time.Hour,
		RefreshTokenEnabled: true,
		PkceEnabled:         true,
	}

	fmt.Printf("✓ Auth0 Domain: %s\n", auth0Config.ProviderURL)
	fmt.Printf("✓ Custom claims for groups: %s\n", auth0Config.ClaimMappings.Groups)
	fmt.Printf("✓ Custom claims for roles: %s\n", auth0Config.ClaimMappings.Roles)

	fmt.Println("\n--- Standard OAuth2 Library Benefits ---")
	fmt.Printf("✅ Using golang.org/x/oauth2 instead of custom implementation\n")
	fmt.Printf("✅ Automatic endpoint discovery via .well-known/openid_configuration\n")
	fmt.Printf("✅ Built-in PKCE support with oauth2.S256ChallengeOption()\n")
	fmt.Printf("✅ Proper ID token verification with github.com/coreos/go-oidc\n")
	fmt.Printf("✅ Automatic token refresh with oauth2.TokenSource\n")
	fmt.Printf("✅ Standard device flow support with oauth2.Config.DeviceAuth()\n")
	fmt.Printf("✅ Secure token revocation through standard interfaces\n")
	fmt.Printf("✅ Battle-tested security and compatibility\n")

	fmt.Println("\n--- OIDC Authentication Process (Standard Library) ---")
	fmt.Printf("1. 🌐 User navigates to VPN server\n")
	fmt.Printf("2. 🔄 oauth2.Config.AuthCodeURL() generates authorization URL with PKCE\n")
	fmt.Printf("3. 🔐 User authenticates with OIDC provider\n")
	fmt.Printf("4. 🔙 Provider redirects user back with authorization code\n")
	fmt.Printf("5. 🎫 oauth2.Config.Exchange() exchanges code for tokens securely\n")
	fmt.Printf("6. 🔍 oidc.IDTokenVerifier.Verify() validates ID token signature\n")
	fmt.Printf("7. 👤 oidc.Provider.UserInfo() gets additional user information\n")
	fmt.Printf("8. ♻️ oauth2.TokenSource automatically refreshes expired tokens\n")
	fmt.Printf("9. ✅ User is authenticated and can use VPN\n")

	// Create auth manager with OIDC (without real connection)
	config := auth.DefaultAuthConfig()
	config.EnableOIDC = true
	config.OIDC = keycloakConfig

	fmt.Println("\n--- Creating Manager with Standard OIDC (simulation) ---")
	fmt.Printf("✓ Standard OIDC configuration prepared\n")
	fmt.Printf("✓ In real environment, the following would happen:\n")
	fmt.Printf("  - oidc.NewProvider() performs endpoint discovery\n")
	fmt.Printf("  - Automatic JWK fetching for signature verification\n")
	fmt.Printf("  - oauth2.Config setup with discovered endpoints\n")
	fmt.Printf("  - oidc.IDTokenVerifier initialization with proper validation\n")
	fmt.Printf("  - Secure session management with automatic token refresh\n")
	fmt.Printf("✓ Much more secure and robust than custom implementation!\n")
}

func testHashingMethods() {
	fmt.Println("      🔐 Testing hashing methods:")
	fmt.Println("         Supported: bcrypt, argon2, pbkdf2, scrypt")
	fmt.Println("         See authentication documentation for details")
}

// Obfsproxy demonstration functions

func demoObfsproxyConfigurations(logger *log.Logger) {
	fmt.Println("\n📋 13. Obfsproxy Configurations Demo")
	fmt.Println("====================================")

	configs := []struct {
		name   string
		config *obfuscation.ObfsproxyConfig
	}{
		{
			name: "obfs3 Client",
			config: &obfuscation.ObfsproxyConfig{
				Enabled:    true,
				Executable: "obfsproxy",
				Mode:       "client",
				Transport:  "obfs3",
				Address:    "server.example.com",
				Port:       443,
				LogLevel:   "INFO",
			},
		},
		{
			name: "obfs4 Client with Options",
			config: &obfuscation.ObfsproxyConfig{
				Enabled:    true,
				Executable: "obfsproxy",
				Mode:       "client",
				Transport:  "obfs4",
				Address:    "server.example.com",
				Port:       443,
				Options:    "--cert=abc123def456 --iat-mode=0",
				LogLevel:   "DEBUG",
			},
		},
		{
			name: "obfs4 Server",
			config: &obfuscation.ObfsproxyConfig{
				Enabled:    true,
				Executable: "obfsproxy",
				Mode:       "server",
				Transport:  "obfs4",
				Address:    "0.0.0.0",
				Port:       443,
				LogLevel:   "INFO",
			},
		},
		{
			name: "scramblesuit with Password",
			config: &obfuscation.ObfsproxyConfig{
				Enabled:    true,
				Executable: "obfsproxy",
				Mode:       "client",
				Transport:  "scramblesuit",
				Address:    "server.example.com",
				Port:       8080,
				Options:    "--password=MySecretPassword123",
				LogLevel:   "INFO",
			},
		},
	}

	for i, cfg := range configs {
		fmt.Printf("\n   %d. %s\n", i+1, cfg.name)
		fmt.Printf("      Transport: %s\n", cfg.config.Transport)
		fmt.Printf("      Mode: %s\n", cfg.config.Mode)
		fmt.Printf("      Address: %s:%d\n", cfg.config.Address, cfg.config.Port)
		if cfg.config.Options != "" {
			fmt.Printf("      Options: %s\n", cfg.config.Options)
		}

		// Create obfsproxy with this configuration
		obfs, err := obfuscation.NewObfsproxy(cfg.config, logger)
		if err != nil {
			fmt.Printf("      ❌ Creation error: %v\n", err)
			continue
		}

		fmt.Printf("      ✅ Created successfully\n")
		fmt.Printf("      📊 Available: %v\n", obfs.IsAvailable())

		// Test basic operations
		testData := []byte("Test data for " + cfg.name)
		obfuscated, err := obfs.Obfuscate(testData)
		if err != nil {
			fmt.Printf("      ❌ Obfuscation error: %v\n", err)
		} else {
			fmt.Printf("      🔒 Obfuscation: %d bytes → %d bytes\n", len(testData), len(obfuscated))
		}

		deobfuscated, err := obfs.Deobfuscate(obfuscated)
		if err != nil {
			fmt.Printf("      ❌ Deobfuscation error: %v\n", err)
		} else {
			fmt.Printf("      🔓 Deobfuscation: %d bytes → %d bytes\n", len(obfuscated), len(deobfuscated))
		}

		// Show metrics
		metrics := obfs.GetMetrics()
		fmt.Printf("      📈 Packets processed: %d\n", metrics.PacketsProcessed)
		fmt.Printf("      📊 Bytes processed: %d\n", metrics.BytesProcessed)
	}
	fmt.Println()
}

func demoObfsproxyEngineIntegration(logger *log.Logger) {
	fmt.Println("\n🔧 14. Obfsproxy Engine Integration Demo")
	fmt.Println("========================================")

	// Create engine configuration with obfsproxy
	config := &obfuscation.Config{
		EnabledMethods:   []obfuscation.ObfuscationMethod{obfuscation.MethodObfsproxy, obfuscation.MethodXORCipher},
		PrimaryMethod:    obfuscation.MethodObfsproxy,
		FallbackMethods:  []obfuscation.ObfuscationMethod{obfuscation.MethodXORCipher},
		AutoDetection:    true,
		SwitchThreshold:  3,
		DetectionTimeout: 30 * time.Second,
		Obfsproxy: obfuscation.ObfsproxyConfig{
			Enabled:    true,
			Executable: "obfsproxy",
			Mode:       "client",
			Transport:  "obfs4",
			Address:    "server.example.com",
			Port:       443,
			LogLevel:   "INFO",
		},
		XORKey: []byte("fallback-xor-key-for-testing-purposes"),
	}

	fmt.Printf("   📝 Engine configuration:\n")
	fmt.Printf("      Primary method: %s\n", config.PrimaryMethod)
	fmt.Printf("      Fallback methods: %v\n", config.FallbackMethods)
	fmt.Printf("      Auto-detection: %v\n", config.AutoDetection)

	// Create engine (this won't work without real obfsproxy)
	fmt.Printf("\n   🔄 Attempting to create engine...\n")
	engine, err := obfuscation.NewEngine(config, logger)
	if err != nil {
		fmt.Printf("      ❌ Engine creation error: %v\n", err)
		fmt.Printf("      💡 This is expected since obfsproxy is not installed\n")
		return
	}
	defer engine.Close()

	fmt.Printf("      ✅ Engine created successfully!\n")
	fmt.Printf("      🎯 Current method: %s\n", engine.GetCurrentMethod())

	// Test obfuscation through engine
	testData := []byte("Engine integration test data")
	fmt.Printf("\n   🧪 Testing obfuscation:\n")
	fmt.Printf("      Source data: %d bytes\n", len(testData))

	obfuscated, err := engine.ObfuscateData(testData)
	if err != nil {
		fmt.Printf("      ❌ Obfuscation error: %v\n", err)
		return
	}
	fmt.Printf("      🔒 Obfuscated: %d bytes\n", len(obfuscated))

	deobfuscated, err := engine.DeobfuscateData(obfuscated)
	if err != nil {
		fmt.Printf("      ❌ Deobfuscation error: %v\n", err)
		return
	}
	fmt.Printf("      🔓 Deobfuscated: %d bytes\n", len(deobfuscated))

	// Check data integrity
	if string(testData) == string(deobfuscated) {
		fmt.Printf("      ✅ Data restored correctly!\n")
	} else {
		fmt.Printf("      ❌ Error: data mismatch!\n")
	}

	// Show engine metrics
	metrics := engine.GetMetrics()
	fmt.Printf("\n   📊 Engine metrics:\n")
	fmt.Printf("      Total packets: %d\n", metrics.TotalPackets)
	fmt.Printf("      Total bytes: %d\n", metrics.TotalBytes)
	fmt.Printf("      Method switches: %d\n", metrics.MethodSwitches)
	fmt.Println()
}

// checkObfsproxyInstallation checks if obfsproxy is installed
func checkObfsproxyInstallation() (string, bool) {
	// Check for obfsproxy first
	if _, err := exec.LookPath("obfsproxy"); err == nil {
		return "obfsproxy", true
	}

	// Check for obfs4proxy
	if _, err := exec.LookPath("obfs4proxy"); err == nil {
		return "obfs4proxy", true
	}

	return "", false
}

func demoObfsproxyRealTesting(logger *log.Logger) {
	fmt.Println("\n🧪 15. Obfsproxy Real Testing Demo")
	fmt.Println("==================================")

	// Check for installed obfsproxy implementation
	installedExecutable, isInstalled := checkObfsproxyInstallation()

	if !isInstalled {
		fmt.Printf("   ❌ No obfsproxy implementation found\n")
		fmt.Printf("   💡 Installation recommendations:\n")
		fmt.Printf("      macOS:   brew install obfs4proxy\n")
		fmt.Printf("      Ubuntu:  sudo apt-get install obfsproxy\n")
		fmt.Printf("      CentOS:  sudo yum install obfsproxy\n")
		fmt.Printf("      Python:  pip install obfsproxy\n")
		fmt.Printf("\n   📚 After installation, run this demo again to see real testing\n")
		fmt.Println()
		return
	}

	fmt.Printf("   ✅ Found installed implementation: %s\n", installedExecutable)

	// Check availability of obfsproxy and obfs4proxy
	realTools := []struct {
		name       string
		executable string
		available  bool
	}{
		{"obfsproxy", "obfsproxy", false},
		{"obfs4proxy", "obfs4proxy", false},
	}

	fmt.Printf("   🔍 Checking all possible implementations:\n")
	for i := range realTools {
		config := &obfuscation.ObfsproxyConfig{
			Enabled:    true,
			Executable: realTools[i].executable,
			Mode:       "client",
			Transport:  "obfs4",
			LogLevel:   "INFO",
		}

		obfs, err := obfuscation.NewObfsproxy(config, logger)
		if err != nil {
			fmt.Printf("      ❌ %s: creation error\n", realTools[i].name)
			continue
		}

		realTools[i].available = obfs.IsAvailable()
		if realTools[i].available {
			fmt.Printf("      ✅ %s: available\n", realTools[i].name)
		} else {
			fmt.Printf("      ❌ %s: not available\n", realTools[i].name)
		}
	}

	// Test with available tools
	for _, tool := range realTools {
		if !tool.available {
			continue
		}

		fmt.Printf("\n   🧪 Testing with %s:\n", tool.name)

		config := &obfuscation.ObfsproxyConfig{
			Enabled:    true,
			Executable: tool.executable,
			Mode:       "client",
			Transport:  "obfs4",
			Address:    "127.0.0.1",
			Port:       9050,
			LogLevel:   "INFO",
		}

		obfs, err := obfuscation.NewObfsproxy(config, logger)
		if err != nil {
			fmt.Printf("      ❌ Creation error: %v\n", err)
			continue
		}

		fmt.Printf("      ✅ Created successfully\n")
		fmt.Printf("      📊 Method name: %s\n", obfs.Name())

		// Test basic operations
		testData := []byte("Real tool test data")
		start := time.Now()

		obfuscated, err := obfs.Obfuscate(testData)
		if err != nil {
			fmt.Printf("      ❌ Obfuscation error: %v\n", err)
			continue
		}

		duration := time.Since(start)
		fmt.Printf("      🔒 Obfuscation: %d → %d bytes in %v\n", len(testData), len(obfuscated), duration)

		start = time.Now()
		deobfuscated, err := obfs.Deobfuscate(obfuscated)
		if err != nil {
			fmt.Printf("      ❌ Deobfuscation error: %v\n", err)
			continue
		}

		duration = time.Since(start)
		fmt.Printf("      🔓 Deobfuscation: %d → %d bytes in %v\n", len(obfuscated), len(deobfuscated), duration)

		// Check metrics
		metrics := obfs.GetMetrics()
		fmt.Printf("      📈 Packets: %d, Bytes: %d, Avg time: %v\n",
			metrics.PacketsProcessed, metrics.BytesProcessed, metrics.AvgProcessTime)
	}

	fmt.Printf("\n   📚 Documentation:\n")
	fmt.Printf("      Guide: examples/OBFSPROXY_USAGE.md\n")
	fmt.Printf("      Configuration: examples/obfsproxy_config.json\n")
	fmt.Printf("      Tests: go test ./pkg/obfuscation/ -v -run TestObfsproxy\n")
	fmt.Println()
}
