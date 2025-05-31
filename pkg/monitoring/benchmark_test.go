package monitoring

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// BenchmarkMetricsCollector benchmark for metrics collector
func BenchmarkMetricsCollector(b *testing.B) {
	metrics := NewMetricsCollector()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		userID := "test-user"
		protocol := "udp"

		for pb.Next() {
			metrics.OnConnectionStart(userID, protocol)
			metrics.OnTrafficReceived(userID, protocol, 1024, 1)
			metrics.OnTrafficSent(userID, protocol, 512, 1)
			metrics.OnConnectionEnd(userID, "normal", time.Second)
		}
	})
}

// BenchmarkLogger benchmark for logger
func BenchmarkLogger(b *testing.B) {
	config := &LogConfig{
		Level:  LevelInfo,
		Format: FormatJSON,
		Output: "/dev/null", // Send to /dev/null for testing
	}

	logger, err := NewLogger(config)
	if err != nil {
		b.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			logger.LogConnectionStart("user123", "192.168.1.100", "10.8.0.100", "udp")
		}
	})
}

// BenchmarkLoggerOpenVPNFormat benchmark for OpenVPN-compatible format
func BenchmarkLoggerOpenVPNFormat(b *testing.B) {
	config := &LogConfig{
		Level:               LevelInfo,
		Format:              FormatOpenVPN,
		Output:              "/dev/null",
		EnableOpenVPNCompat: true,
	}

	logger, err := NewLogger(config)
	if err != nil {
		b.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			logger.LogConnectionStart("user123", "192.168.1.100", "10.8.0.100", "udp")
		}
	})
}

// BenchmarkPerformanceMonitor benchmark for performance monitor
func BenchmarkPerformanceMonitor(b *testing.B) {
	metrics := NewMetricsCollector()
	logger, _ := NewLogger(&LogConfig{
		Level:  LevelError, // Only errors for reducing overhead
		Format: FormatJSON,
		Output: "/dev/null",
	})
	defer logger.Close()

	monitor := NewPerformanceMonitor(metrics, logger, time.Hour) // Large interval for tests

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		userID := "bench-user"
		protocol := "udp"

		for pb.Next() {
			monitor.OnConnectionStart(userID, protocol)
			monitor.OnTrafficReceived(userID, protocol, 1024, 1)
			monitor.OnConnectionEnd(userID, "normal", time.Second)
		}
	})
}

// BenchmarkAlertManager benchmark for alert manager
func BenchmarkAlertManager(b *testing.B) {
	logger, _ := NewLogger(&LogConfig{
		Level:  LevelError,
		Format: FormatJSON,
		Output: "/dev/null",
	})
	defer logger.Close()

	metrics := NewMetricsCollector()
	monitor := NewPerformanceMonitor(metrics, logger, time.Hour)
	alertManager := NewAlertManager(logger, monitor, time.Hour) // Large interval

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alertManager.evaluateRules()
	}
}

// BenchmarkConcurrentOperations benchmark for concurrent operations
func BenchmarkConcurrentOperations(b *testing.B) {
	metrics := NewMetricsCollector()
	logger, _ := NewLogger(&LogConfig{
		Level:  LevelWarn,
		Format: FormatJSON,
		Output: "/dev/null",
	})
	defer logger.Close()

	monitor := NewPerformanceMonitor(metrics, logger, time.Hour)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		userID := fmt.Sprintf("user-%d", b.N)
		protocol := "udp"

		for pb.Next() {
			var wg sync.WaitGroup

			// Emulate multiple simultaneous operations
			wg.Add(3)

			go func() {
				defer wg.Done()
				monitor.OnConnectionStart(userID, protocol)
				monitor.OnConnectionEnd(userID, "normal", time.Second)
			}()

			go func() {
				defer wg.Done()
				monitor.OnAuthAttempt("password", "success")
			}()

			go func() {
				defer wg.Done()
				logger.LogConnectionStart(userID, "192.168.1.100", "10.8.0.100", protocol)
			}()

			wg.Wait()
		}
	})
}

// BenchmarkMemoryAllocation benchmark for memory allocation estimation
func BenchmarkMemoryAllocation(b *testing.B) {
	b.ReportAllocs()

	metrics := NewMetricsCollector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		userID := fmt.Sprintf("user-%d", i)
		protocol := "udp"

		metrics.OnConnectionStart(userID, protocol)
		metrics.OnTrafficReceived(userID, protocol, 1024, 1)
		metrics.OnConnectionEnd(userID, "normal", time.Second)
	}
}

// TestPerformanceUnderLoad test performance under load
func TestPerformanceUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	metrics := NewMetricsCollector()
	logger, err := NewLogger(&LogConfig{
		Level:  LevelInfo,
		Format: FormatJSON,
		Output: "stdout",
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	monitor := NewPerformanceMonitor(metrics, logger, 1*time.Second)
	monitor.Start()
	defer monitor.Stop()

	// Start HTTP server for metrics
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := metrics.StartMetricsServer(ctx, ":0"); err != nil {
			t.Logf("Metrics server error: %v", err)
		}
	}()

	// Create load
	const numGoroutines = 10
	const operationsPerGoroutine = 1000

	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < operationsPerGoroutine; j++ {
				userID := fmt.Sprintf("load-user-%d-%d", id, j)
				protocol := "udp"

				monitor.OnConnectionStart(userID, protocol)
				monitor.OnTrafficReceived(userID, protocol, 1024, 1)
				monitor.OnAuthAttempt("password", "success")
				monitor.OnObfuscationSwitch()

				logger.LogConnectionStart(userID, "192.168.1.100", "10.8.0.100", protocol)

				monitor.OnConnectionEnd(userID, "normal", time.Duration(j)*time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
	duration := time.Since(start)

	totalOps := numGoroutines * operationsPerGoroutine
	opsPerSecond := float64(totalOps) / duration.Seconds()

	t.Logf("Performance test completed:")
	t.Logf("- Total operations: %d", totalOps*5) // 5 operations per iteration
	t.Logf("- Duration: %v", duration)
	t.Logf("- Operations per second: %.2f", opsPerSecond*5)

	// Check that the system works correctly
	summary := monitor.GetMetricsSummary()
	if summary == nil {
		t.Error("Failed to get metrics summary")
	}

	// Wait a bit for metrics processing
	time.Sleep(2 * time.Second)
}

// Example example of using the monitoring system
func Example() {
	// Create monitoring components
	metrics := NewMetricsCollector()

	logConfig := &LogConfig{
		Level:  LevelError, // Only errors to not clutter output
		Format: FormatJSON,
		Output: "/dev/null", // Send to /dev/null
	}
	logger, _ := NewLogger(logConfig)
	defer logger.Close()

	monitor := NewPerformanceMonitor(metrics, logger, 30*time.Second)
	alertManager := NewAlertManager(logger, monitor, 30*time.Second)

	// Subscribe to alerts
	consoleSubscriber := NewConsoleAlertSubscriber(logger)
	alertManager.Subscribe(consoleSubscriber)

	// Start monitoring
	monitor.Start()
	alertManager.Start()

	// Start metrics server
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	go metrics.StartMetricsServer(ctx, ":0") // Random port

	// Emulate activity
	monitor.OnConnectionStart("user1", "udp")
	monitor.OnTrafficReceived("user1", "udp", 1024, 1)

	// Stop monitoring
	monitor.Stop()
	alertManager.Stop()

	fmt.Println("Monitoring example completed")
	// Output: Monitoring example completed
}

// BenchmarkDifferentLogFormats benchmark for comparing different logging formats
func BenchmarkDifferentLogFormats(b *testing.B) {
	formats := []struct {
		name   string
		format LogFormat
	}{
		{"JSON", FormatJSON},
		{"Text", FormatText},
		{"OpenVPN", FormatOpenVPN},
	}

	for _, format := range formats {
		b.Run(format.name, func(b *testing.B) {
			config := &LogConfig{
				Level:  LevelInfo,
				Format: format.format,
				Output: "/dev/null",
			}

			logger, err := NewLogger(config)
			if err != nil {
				b.Fatalf("Failed to create logger: %v", err)
			}
			defer logger.Close()

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					logger.LogConnectionStart("user123", "192.168.1.100", "10.8.0.100", "udp")
				}
			})
		})
	}
}
