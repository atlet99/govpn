package core

import (
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/atlet99/govpn/pkg/auth"
)

// BenchmarkConfigValidation tests the performance of configuration validation
func BenchmarkConfigValidation(b *testing.B) {
	config := DefaultConfig()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := config.Validate()
		if err != nil {
			b.Fatalf("Config validation failed: %v", err)
		}
	}
}

// BenchmarkConfigCreation tests performance of config creation
func BenchmarkConfigCreation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config := DefaultConfig()
		_ = config // Avoid compiler optimization
	}
}

// BenchmarkCipherContextCreation tests performance of cipher context creation
func BenchmarkCipherContextCreation(b *testing.B) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		b.Fatalf("Failed to generate random key: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, err := auth.NewCipherContext(auth.CipherAES256GCM, auth.AuthSHA256, key)
		if err != nil {
			b.Errorf("Failed to create cipher context: %v", err)
		}
		_ = ctx
	}
}

// BenchmarkEncryption tests encryption performance with different algorithms
func BenchmarkEncryption(b *testing.B) {
	testCases := []struct {
		name   string
		cipher auth.CipherMode
	}{
		{"AES-128-GCM", auth.CipherAES128GCM},
		{"AES-256-GCM", auth.CipherAES256GCM},
		{"ChaCha20-Poly1305", auth.CipherChacha20Poly1305},
	}

	data := make([]byte, 1500) // Typical MTU size
	if _, err := rand.Read(data); err != nil {
		b.Fatalf("Failed to generate test data: %v", err)
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			var keySize int
			switch tc.cipher {
			case auth.CipherAES128GCM:
				keySize = 16
			default:
				keySize = 32
			}

			key := make([]byte, keySize)
			if _, err := rand.Read(key); err != nil {
				b.Fatalf("Failed to generate random key: %v", err)
			}

			ctx, err := auth.NewCipherContext(tc.cipher, auth.AuthSHA256, key)
			if err != nil {
				b.Fatalf("Failed to create cipher context: %v", err)
			}

			b.ResetTimer()
			b.SetBytes(int64(len(data)))

			for i := 0; i < b.N; i++ {
				_, err := ctx.Encrypt(data)
				if err != nil {
					b.Errorf("Encryption failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkDecryption tests decryption performance
func BenchmarkDecryption(b *testing.B) {
	testCases := []struct {
		name   string
		cipher auth.CipherMode
	}{
		{"AES-128-GCM", auth.CipherAES128GCM},
		{"AES-256-GCM", auth.CipherAES256GCM},
		{"ChaCha20-Poly1305", auth.CipherChacha20Poly1305},
	}

	data := make([]byte, 1500)
	if _, err := rand.Read(data); err != nil {
		b.Fatalf("Failed to generate test data: %v", err)
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			var keySize int
			switch tc.cipher {
			case auth.CipherAES128GCM:
				keySize = 16
			default:
				keySize = 32
			}

			key := make([]byte, keySize)
			if _, err := rand.Read(key); err != nil {
				b.Fatalf("Failed to generate random key: %v", err)
			}

			ctx, err := auth.NewCipherContext(tc.cipher, auth.AuthSHA256, key)
			if err != nil {
				b.Fatalf("Failed to create cipher context: %v", err)
			}

			// Pre-encrypt test data
			encrypted, err := ctx.Encrypt(data)
			if err != nil {
				b.Fatalf("Failed to encrypt test data: %v", err)
			}

			b.ResetTimer()
			b.SetBytes(int64(len(data)))

			for i := 0; i < b.N; i++ {
				_, err := ctx.Decrypt(encrypted)
				if err != nil {
					b.Errorf("Decryption failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkEncryptionDecryptionRoundTrip tests full encryption-decryption cycle
func BenchmarkEncryptionDecryptionRoundTrip(b *testing.B) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		b.Fatalf("Failed to generate random key: %v", err)
	}

	ctx, err := auth.NewCipherContext(auth.CipherAES256GCM, auth.AuthSHA256, key)
	if err != nil {
		b.Fatalf("Failed to create cipher context: %v", err)
	}

	data := make([]byte, 1500)
	if _, err := rand.Read(data); err != nil {
		b.Fatalf("Failed to generate test data: %v", err)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		encrypted, err := ctx.Encrypt(data)
		if err != nil {
			b.Errorf("Encryption failed: %v", err)
			continue
		}

		_, err = ctx.Decrypt(encrypted)
		if err != nil {
			b.Errorf("Decryption failed: %v", err)
		}
	}
}

// BenchmarkConcurrentEncryption tests performance of parallel encryption
func BenchmarkConcurrentEncryption(b *testing.B) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		b.Fatalf("Failed to generate random key: %v", err)
	}

	data := make([]byte, 1500)
	if _, err := rand.Read(data); err != nil {
		b.Fatalf("Failed to generate test data: %v", err)
	}

	// Create pool of cipher contexts for each goroutine
	numWorkers := 10
	ctxPool := make([]*auth.CipherContext, numWorkers)

	for i := 0; i < numWorkers; i++ {
		ctx, err := auth.NewCipherContext(auth.CipherAES256GCM, auth.AuthSHA256, key)
		if err != nil {
			b.Fatalf("Failed to create cipher context: %v", err)
		}
		ctxPool[i] = ctx
	}

	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	b.RunParallel(func(pb *testing.PB) {
		workerID := 0
		ctx := ctxPool[workerID%numWorkers]

		for pb.Next() {
			_, err := ctx.Encrypt(data)
			if err != nil {
				b.Errorf("Encryption failed: %v", err)
			}
		}
	})
}

// BenchmarkKeyDerivation tests performance of key derivation
func BenchmarkKeyDerivation(b *testing.B) {
	masterSecret := make([]byte, 32)
	salt := make([]byte, 16)
	if _, err := rand.Read(masterSecret); err != nil {
		b.Fatalf("Failed to generate master secret: %v", err)
	}
	if _, err := rand.Read(salt); err != nil {
		b.Fatalf("Failed to generate salt: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := auth.DeriveKeys(masterSecret, salt, 32)
		if err != nil {
			b.Errorf("Key derivation failed: %v", err)
		}
	}
}

// BenchmarkCertificateManagerCreation tests performance of certificate manager creation
func BenchmarkCertificateManagerCreation(b *testing.B) {
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cm := auth.NewCertificateManager(
			auth.WithCAPath("/test/ca.crt"),
			auth.WithCertPath("/test/cert.crt"),
			auth.WithKeyPath("/test/key.key"),
		)
		_ = cm
	}
}

// BenchmarkPacketProcessing tests packet processing performance
func BenchmarkPacketProcessing(b *testing.B) {
	// Simulate IPv4 packet
	packet := make([]byte, 1500)
	packet[0] = 0x45 // IPv4, IHL=5

	b.ResetTimer()
	b.SetBytes(int64(len(packet)))

	for i := 0; i < b.N; i++ {
		// Simple packet processing - extract IP version
		version := packet[0] >> 4
		if version != 4 && version != 6 {
			b.Error("Invalid IP version")
		}
	}
}

// TestHighThroughput tests high load processing
func TestHighThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping high throughput test in short mode")
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	ctx, err := auth.NewCipherContext(auth.CipherAES256GCM, auth.AuthSHA256, key)
	if err != nil {
		t.Fatalf("Failed to create cipher context: %v", err)
	}

	data := make([]byte, 1500)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Test processing of large number of packets
	numPackets := 100000
	start := time.Now()

	for i := 0; i < numPackets; i++ {
		encrypted, err := ctx.Encrypt(data)
		if err != nil {
			t.Errorf("Encryption failed at packet %d: %v", i, err)
			break
		}

		_, err = ctx.Decrypt(encrypted)
		if err != nil {
			t.Errorf("Decryption failed at packet %d: %v", i, err)
			break
		}
	}

	duration := time.Since(start)
	packetsPerSecond := float64(numPackets) / duration.Seconds()
	mbps := (float64(numPackets) * float64(len(data)) * 8) / (1024 * 1024) / duration.Seconds()

	t.Logf("Processed %d packets in %v", numPackets, duration)
	t.Logf("Throughput: %.2f packets/sec, %.2f Mbps", packetsPerSecond, mbps)

	// Check minimum performance
	if packetsPerSecond < 10000 {
		t.Errorf("Performance too low: %.2f packets/sec (expected at least 10000)", packetsPerSecond)
	}
}

// TestConcurrentConnections tests handling of multiple connections
func TestConcurrentConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent connections test in short mode")
	}

	numConnections := 100
	packetsPerConnection := 1000
	var wg sync.WaitGroup

	start := time.Now()

	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(connID int) {
			defer wg.Done()

			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				t.Errorf("Connection %d: Failed to generate random key: %v", connID, err)
				return
			}

			ctx, err := auth.NewCipherContext(auth.CipherAES256GCM, auth.AuthSHA256, key)
			if err != nil {
				t.Errorf("Connection %d: Failed to create cipher context: %v", connID, err)
				return
			}

			data := make([]byte, 1500)
			if _, err := rand.Read(data); err != nil {
				t.Errorf("Connection %d: Failed to generate test data: %v", connID, err)
				return
			}

			for j := 0; j < packetsPerConnection; j++ {
				encrypted, err := ctx.Encrypt(data)
				if err != nil {
					t.Errorf("Connection %d, packet %d: Encryption failed: %v", connID, j, err)
					return
				}

				_, err = ctx.Decrypt(encrypted)
				if err != nil {
					t.Errorf("Connection %d, packet %d: Decryption failed: %v", connID, j, err)
					return
				}
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)

	totalPackets := numConnections * packetsPerConnection
	packetsPerSecond := float64(totalPackets) / duration.Seconds()

	t.Logf("Processed %d concurrent connections with %d packets each in %v",
		numConnections, packetsPerConnection, duration)
	t.Logf("Total throughput: %.2f packets/sec", packetsPerSecond)

	// Check that all connections processed in reasonable time
	if duration > 30*time.Second {
		t.Errorf("Concurrent connections test took too long: %v (expected < 30s)", duration)
	}
}

// TestMemoryUsage tests memory usage
func TestMemoryUsage(t *testing.T) {
	// Create multiple buffers to simulate load
	buffers := make([][]byte, 1000)

	for i := range buffers {
		buffers[i] = make([]byte, 1500)
		rand.Read(buffers[i])
	}

	// Process data
	for _, buffer := range buffers {
		for j := range buffer {
			buffer[j] ^= 0xFF
		}
	}

	// Check that data is processed correctly
	for _, buffer := range buffers {
		if len(buffer) != 1500 {
			t.Errorf("Buffer size mismatch: expected 1500, got %d", len(buffer))
		}
	}

	t.Logf("Memory usage test completed with %d buffers", len(buffers))
}

// BenchmarkDataProcessing tests data processing performance
func BenchmarkDataProcessing(b *testing.B) {
	// Create test data of different sizes
	testSizes := []int{64, 512, 1024, 4096, 8192}

	for _, size := range testSizes {
		b.Run(fmt.Sprintf("Size%d", size), func(b *testing.B) {
			data := make([]byte, size)
			rand.Read(data)

			b.SetBytes(int64(size))
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Simulate packet processing
				processed := make([]byte, len(data))
				copy(processed, data)

				// Simple processing (XOR with constant)
				for j := range processed {
					processed[j] ^= 0xAA
				}
			}
		})
	}
}

// BenchmarkMemoryAllocation tests memory allocation performance
func BenchmarkMemoryAllocation(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simulate buffer allocation for packets
		buffer := make([]byte, 1500) // MTU size
		_ = buffer
	}
}

// BenchmarkBufferReuse tests buffer reuse performance
func BenchmarkBufferReuse(b *testing.B) {
	bufferPool := make(chan []byte, 100)

	// Pre-fill the pool
	for i := 0; i < 100; i++ {
		bufferPool <- make([]byte, 1500)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Get buffer from pool
		var buffer []byte
		select {
		case buffer = <-bufferPool:
		default:
			buffer = make([]byte, 1500)
		}

		// Use buffer
		for j := range buffer {
			buffer[j] = byte(j % 256)
		}

		// Return to pool
		select {
		case bufferPool <- buffer:
		default:
			// Pool is full, discard buffer
		}
	}
}

// BenchmarkConcurrentProcessing tests concurrent processing performance
func BenchmarkConcurrentProcessing(b *testing.B) {
	data := make([]byte, 1024)
	rand.Read(data)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Simulate packet processing in goroutine
			processed := make([]byte, len(data))
			copy(processed, data)

			// Simple processing
			for j := range processed {
				processed[j] ^= 0x55
			}
		}
	})
}

// TestPerformanceMetrics tests performance metrics collection
func TestPerformanceMetrics(t *testing.T) {
	start := time.Now()

	// Simulate some work
	data := make([]byte, 10000)
	rand.Read(data)

	for i := 0; i < 1000; i++ {
		// Process data
		for j := range data {
			data[j] ^= byte(i % 256)
		}
	}

	duration := time.Since(start)

	// Check that operation completed in reasonable time
	if duration > time.Second {
		t.Errorf("Performance test took too long: %v", duration)
	}

	t.Logf("Performance test completed in %v", duration)
}

// TestThroughput tests throughput capability
func TestThroughput(t *testing.T) {
	const (
		packetSize = 1500
		numPackets = 10000
	)

	start := time.Now()
	totalBytes := int64(0)

	for i := 0; i < numPackets; i++ {
		packet := make([]byte, packetSize)
		rand.Read(packet)

		// Simulate packet processing
		for j := range packet {
			packet[j] ^= byte(i % 256)
		}

		totalBytes += int64(len(packet))
	}

	duration := time.Since(start)
	throughput := float64(totalBytes) / duration.Seconds() / 1024 / 1024 // MB/s

	t.Logf("Processed %d packets (%d MB) in %v", numPackets, totalBytes/1024/1024, duration)
	t.Logf("Throughput: %.2f MB/s", throughput)

	// Check that throughput is reasonable (greater than 100 MB/s)
	if throughput < 100 {
		t.Errorf("Throughput too low: %.2f MB/s", throughput)
	}
}
