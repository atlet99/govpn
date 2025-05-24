package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
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

	// Packet Padding demonstration
	fmt.Println("5. Packet Padding Demo")
	fmt.Println("----------------------")
	demoPacketPadding(logger)
	fmt.Println()

	// Timing Obfuscation demonstration
	fmt.Println("6. Timing Obfuscation Demo")
	fmt.Println("--------------------------")
	demoTimingObfuscation(logger)
	fmt.Println()

	// Traffic Padding demonstration
	fmt.Println("7. Traffic Padding Demo")
	fmt.Println("-----------------------")
	demoTrafficPadding(logger)
	fmt.Println()

	// Flow Watermarking demonstration
	fmt.Println("8. Flow Watermarking Demo")
	fmt.Println("-------------------------")
	demoFlowWatermarking(logger)
	fmt.Println()

	// HTTP Mimicry demonstration
	fmt.Println("9. HTTP Mimicry Demo")
	fmt.Println("--------------------")
	demoHTTPMimicry(logger)
	fmt.Println()

	// Auto-switching demonstration
	fmt.Println("10. Auto-switching Demo")
	fmt.Println("-----------------------")
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
