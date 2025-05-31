package core

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestBufferPool tests the buffer pool functionality
func TestBufferPool(t *testing.T) {
	pool := NewBufferPool()

	t.Run("GetAndPutBuffer", func(t *testing.T) {
		// Test getting buffers of different sizes
		sizes := []int{100, 1000, 5000, 20000}

		for _, size := range sizes {
			buffer := pool.GetBuffer(size)
			if len(buffer) != size {
				t.Errorf("Expected buffer size %d, got %d", size, len(buffer))
			}

			// Put buffer back
			pool.PutBuffer(buffer)
		}
	})

	t.Run("BufferReuse", func(t *testing.T) {
		// Get a buffer
		buffer1 := pool.GetBuffer(SmallBufferSize)

		// Modify it
		buffer1[0] = 0xFF

		// Put it back
		pool.PutBuffer(buffer1)

		// Get another buffer of the same size
		buffer2 := pool.GetBuffer(SmallBufferSize)

		// Should be cleared
		if buffer2[0] != 0 {
			t.Error("Buffer was not cleared when returned to pool")
		}
	})

	t.Run("Stats", func(t *testing.T) {
		stats := pool.GetStats()
		if stats.Gets == 0 {
			t.Error("Expected non-zero gets in stats")
		}
	})
}

// TestTrackedBufferPool tests the tracked buffer pool
func TestTrackedBufferPool(t *testing.T) {
	pool := NewTrackedBufferPool()

	t.Run("Tracking", func(t *testing.T) {
		initialActive := pool.GetActiveBuffers()
		initialBytes := pool.GetTotalBytes()

		buffer := pool.GetBuffer(1000)

		if pool.GetActiveBuffers() != initialActive+1 {
			t.Error("Active buffer count not incremented")
		}

		if pool.GetTotalBytes() <= initialBytes {
			t.Error("Total bytes not incremented")
		}

		pool.PutBuffer(buffer)

		if pool.GetActiveBuffers() != initialActive {
			t.Error("Active buffer count not decremented")
		}
	})

	t.Run("ExtendedStats", func(t *testing.T) {
		stats := pool.GetExtendedStats()

		requiredKeys := []string{"gets", "puts", "hits", "misses", "active_buffers", "total_bytes", "hit_rate", "uptime_seconds"}
		for _, key := range requiredKeys {
			if _, exists := stats[key]; !exists {
				t.Errorf("Missing key in extended stats: %s", key)
			}
		}
	})
}

// TestRateLimiter tests the rate limiter functionality
func TestRateLimiter(t *testing.T) {
	capacity := int64(10)
	refillRate := int64(5) // 5 tokens per second
	limiter := NewRateLimiter(capacity, refillRate)

	t.Run("InitialCapacity", func(t *testing.T) {
		// Should start with full capacity
		for i := 0; i < int(capacity); i++ {
			if !limiter.Allow() {
				t.Errorf("Expected request %d to be allowed", i)
			}
		}

		// Next request should be denied
		if limiter.Allow() {
			t.Error("Expected request to be denied after capacity exhausted")
		}
	})

	t.Run("TokenRefill", func(t *testing.T) {
		// Create a new limiter for this test
		testLimiter := NewRateLimiter(1, 1) // 1 capacity, 1 token/sec

		// Exhaust capacity
		if !testLimiter.Allow() {
			t.Error("First request should be allowed")
		}

		// Should be denied immediately
		if testLimiter.Allow() {
			t.Error("Second request should be denied")
		}

		// Wait for refill (1 second + buffer should be enough for 1 token/sec)
		time.Sleep(1200 * time.Millisecond)

		// Should be allowed again
		if !testLimiter.Allow() {
			t.Error("Request should be allowed after refill")
		}
	})
}

// TestCircuitBreaker tests the circuit breaker functionality
func TestCircuitBreaker(t *testing.T) {
	maxFailures := int64(3)
	timeout := 100 * time.Millisecond
	halfOpenMax := int64(2)

	breaker := NewCircuitBreaker(maxFailures, timeout, halfOpenMax)

	t.Run("ClosedState", func(t *testing.T) {
		if breaker.GetState() != StateClosed {
			t.Error("Circuit breaker should start in closed state")
		}

		// Successful requests should work
		err := breaker.Execute(func() error { return nil })
		if err != nil {
			t.Errorf("Successful request failed: %v", err)
		}
	})

	t.Run("OpenState", func(t *testing.T) {
		// Cause failures to open the circuit
		for i := 0; i < int(maxFailures); i++ {
			_ = breaker.Execute(func() error { return &testError{} })
		}

		if breaker.GetState() != StateOpen {
			t.Error("Circuit breaker should be open after max failures")
		}

		// Requests should be rejected
		err := breaker.Execute(func() error { return nil })
		if err == nil || err.Error() != "circuit breaker is open" {
			t.Error("Requests should be rejected when circuit is open")
		}
	})

	t.Run("HalfOpenState", func(t *testing.T) {
		// Wait for timeout
		time.Sleep(timeout + 10*time.Millisecond)

		// First request should be allowed (transitions to half-open)
		err := breaker.Execute(func() error { return nil })
		if err != nil {
			t.Errorf("First request after timeout should be allowed: %v", err)
		}
	})

	t.Run("Stats", func(t *testing.T) {
		stats := breaker.GetStats()

		requiredKeys := []string{"state", "failures", "successes", "requests", "max_failures", "timeout_seconds", "half_open_max"}
		for _, key := range requiredKeys {
			if _, exists := stats[key]; !exists {
				t.Errorf("Missing key in circuit breaker stats: %s", key)
			}
		}
	})
}

// testError is a simple error type for testing
type testError struct{}

func (e *testError) Error() string {
	return "test error"
}

// TestReliabilityManager tests the reliability manager
func TestReliabilityManager(t *testing.T) {
	manager := NewReliabilityManager(100, 10) // 100 capacity, 10 refill/sec

	t.Run("SuccessfulRequest", func(t *testing.T) {
		err := manager.ProcessRequest("test-service", func() error {
			return nil
		})

		if err != nil {
			t.Errorf("Successful request failed: %v", err)
		}
	})

	t.Run("FailedRequest", func(t *testing.T) {
		err := manager.ProcessRequest("test-service", func() error {
			return &testError{}
		})

		if err == nil {
			t.Error("Failed request should return error")
		}
	})

	t.Run("RateLimiting", func(t *testing.T) {
		// Create a manager with very low capacity
		limitedManager := NewReliabilityManager(1, 1)

		// First request should succeed
		err := limitedManager.ProcessRequest("test", func() error { return nil })
		if err != nil {
			t.Errorf("First request should succeed: %v", err)
		}

		// Second request should be rate limited
		err = limitedManager.ProcessRequest("test", func() error { return nil })
		if err == nil || err.Error() != "rate limit exceeded" {
			t.Error("Second request should be rate limited")
		}
	})

	t.Run("Metrics", func(t *testing.T) {
		metrics := manager.GetMetrics()

		requiredKeys := []string{"total_requests", "successful_requests", "failed_requests", "rate_limited_requests", "success_rate", "uptime_seconds"}
		for _, key := range requiredKeys {
			if _, exists := metrics[key]; !exists {
				t.Errorf("Missing key in reliability metrics: %s", key)
			}
		}
	})

	t.Run("CircuitBreakerStats", func(t *testing.T) {
		stats := manager.GetCircuitBreakerStats()
		if len(stats) == 0 {
			t.Error("Expected circuit breaker stats")
		}
	})
}

// TestShutdownManager tests the shutdown manager
func TestShutdownManager(t *testing.T) {
	timeout := 5 * time.Second
	manager := NewShutdownManager(timeout)

	t.Run("ComponentRegistration", func(t *testing.T) {
		initialCount := manager.GetComponentCount()

		component := &testComponent{name: "test", priority: 1}
		manager.Register(component)

		if manager.GetComponentCount() != initialCount+1 {
			t.Error("Component count should increase after registration")
		}
	})

	t.Run("PriorityOrdering", func(t *testing.T) {
		manager := NewShutdownManager(timeout)

		// Register components in reverse priority order
		manager.Register(&testComponent{name: "high", priority: 10})
		manager.Register(&testComponent{name: "low", priority: 1})
		manager.Register(&testComponent{name: "medium", priority: 5})

		components := manager.GetComponents()

		// Should be ordered by priority (low to high)
		if components[0].Priority() != 1 || components[1].Priority() != 5 || components[2].Priority() != 10 {
			t.Error("Components not ordered by priority")
		}
	})

	t.Run("FunctionRegistration", func(t *testing.T) {
		manager := NewShutdownManager(timeout)

		called := false
		manager.RegisterFunc("test-func", 1, func(ctx context.Context) error {
			called = true
			return nil
		})

		_ = manager.Shutdown()

		if !called {
			t.Error("Registered function was not called during shutdown")
		}
	})

	t.Run("CleanupRegistration", func(t *testing.T) {
		manager := NewShutdownManager(timeout)

		called := false
		manager.RegisterCleanup("test-cleanup", 1, func() error {
			called = true
			return nil
		})

		_ = manager.Shutdown()

		if !called {
			t.Error("Registered cleanup was not called during shutdown")
		}
	})

	t.Run("IsShutdown", func(t *testing.T) {
		manager := NewShutdownManager(timeout)

		if manager.IsShutdown() {
			t.Error("Manager should not be shutdown initially")
		}

		_ = manager.Shutdown()

		if !manager.IsShutdown() {
			t.Error("Manager should be shutdown after calling Shutdown()")
		}
	})
}

// testComponent is a test implementation of ShutdownComponent
type testComponent struct {
	name           string
	priority       int
	shutdownCalled bool
	shutdownError  error
}

func (tc *testComponent) Name() string {
	return tc.name
}

func (tc *testComponent) Priority() int {
	return tc.priority
}

func (tc *testComponent) Shutdown(ctx context.Context) error {
	tc.shutdownCalled = true
	return tc.shutdownError
}

// TestContextManager tests the context manager
func TestContextManager(t *testing.T) {
	manager := NewContextManager()

	t.Run("RootContext", func(t *testing.T) {
		ctx := manager.GetRootContext()
		if ctx == nil {
			t.Error("Root context should not be nil")
		}

		select {
		case <-ctx.Done():
			t.Error("Root context should not be cancelled initially")
		default:
			// Expected
		}
	})

	t.Run("ChildContext", func(t *testing.T) {
		ctx, cancel := manager.CreateChildContext()

		select {
		case <-ctx.Done():
			t.Error("Child context should not be cancelled initially")
		default:
			// Expected
		}

		cancel()

		select {
		case <-ctx.Done():
			// Expected
		case <-time.After(100 * time.Millisecond):
			t.Error("Child context should be cancelled after calling cancel")
		}
	})

	t.Run("TimeoutContext", func(t *testing.T) {
		ctx, cancel := manager.CreateTimeoutContext(50 * time.Millisecond)
		defer cancel()

		select {
		case <-ctx.Done():
			t.Error("Timeout context should not be cancelled immediately")
		case <-time.After(10 * time.Millisecond):
			// Expected
		}

		select {
		case <-ctx.Done():
			// Expected
		case <-time.After(100 * time.Millisecond):
			t.Error("Timeout context should be cancelled after timeout")
		}
	})

	t.Run("Shutdown", func(t *testing.T) {
		manager := NewContextManager()
		ctx := manager.GetRootContext()

		manager.Shutdown()

		select {
		case <-ctx.Done():
			// Expected
		case <-time.After(100 * time.Millisecond):
			t.Error("Root context should be cancelled after shutdown")
		}
	})
}

// TestGlobalBufferPool tests the global buffer pool
func TestGlobalBufferPool(t *testing.T) {
	t.Run("GlobalAccess", func(t *testing.T) {
		buffer := GetBuffer(1000)
		if len(buffer) != 1000 {
			t.Errorf("Expected buffer size 1000, got %d", len(buffer))
		}

		PutBuffer(buffer)

		stats := GetPoolStats()
		if stats == nil {
			t.Error("Global pool stats should not be nil")
		}
	})
}

// BenchmarkBufferPool benchmarks buffer pool performance
func BenchmarkBufferPool(b *testing.B) {
	pool := NewBufferPool()

	b.Run("GetPutSmall", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buffer := pool.GetBuffer(SmallBufferSize)
			pool.PutBuffer(buffer)
		}
	})

	b.Run("GetPutMedium", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buffer := pool.GetBuffer(MediumBufferSize)
			pool.PutBuffer(buffer)
		}
	})

	b.Run("GetPutLarge", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			buffer := pool.GetBuffer(LargeBufferSize)
			pool.PutBuffer(buffer)
		}
	})
}

// BenchmarkRateLimiter benchmarks rate limiter performance
func BenchmarkRateLimiter(b *testing.B) {
	limiter := NewRateLimiter(1000000, 1000000) // High capacity for benchmarking

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.Allow()
	}
}

// BenchmarkCircuitBreaker benchmarks circuit breaker performance
func BenchmarkCircuitBreaker(b *testing.B) {
	breaker := NewCircuitBreaker(1000, time.Minute, 10)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = breaker.Execute(func() error { return nil })
	}
}

// BenchmarkReliabilityManager benchmarks reliability manager performance
func BenchmarkReliabilityManager(b *testing.B) {
	manager := NewReliabilityManager(1000000, 1000000) // High capacity for benchmarking

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = manager.ProcessRequest("test", func() error { return nil })
	}
}

// TestConcurrentBufferPool tests buffer pool under concurrent access
func TestConcurrentBufferPool(t *testing.T) {
	pool := NewTrackedBufferPool()

	const numGoroutines = 100
	const operationsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			for j := 0; j < operationsPerGoroutine; j++ {
				buffer := pool.GetBuffer(MediumBufferSize)
				// Simulate some work
				runtime.Gosched()
				pool.PutBuffer(buffer)
			}
		}()
	}

	wg.Wait()

	// Check that all buffers were returned
	if pool.GetActiveBuffers() != 0 {
		t.Errorf("Expected 0 active buffers, got %d", pool.GetActiveBuffers())
	}
}

// TestConcurrentRateLimiter tests rate limiter under concurrent access
func TestConcurrentRateLimiter(t *testing.T) {
	limiter := NewRateLimiter(1000, 100)

	const numGoroutines = 50
	const requestsPerGoroutine = 100

	var wg sync.WaitGroup
	var allowedCount int64
	var mu sync.Mutex

	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			for j := 0; j < requestsPerGoroutine; j++ {
				if limiter.Allow() {
					mu.Lock()
					allowedCount++
					mu.Unlock()
				}
				runtime.Gosched()
			}
		}()
	}

	wg.Wait()

	// Should have allowed some requests but not all due to rate limiting
	totalRequests := int64(numGoroutines * requestsPerGoroutine)
	if allowedCount == 0 {
		t.Error("Rate limiter should have allowed some requests")
	}
	if allowedCount >= totalRequests {
		t.Error("Rate limiter should have blocked some requests")
	}
}

// TestIntegration tests integration between components
func TestIntegration(t *testing.T) {
	// Create a shutdown manager
	shutdownManager := NewShutdownManager(5 * time.Second)

	// Create a reliability manager
	reliabilityManager := NewReliabilityManager(100, 10)

	// Create a buffer pool
	bufferPool := NewTrackedBufferPool()

	// Register cleanup for buffer pool
	shutdownManager.RegisterCleanup("buffer-pool", 1, func() error {
		// In a real scenario, we might want to drain the pool
		return nil
	})

	// Register cleanup for reliability manager
	shutdownManager.RegisterCleanup("reliability-manager", 2, func() error {
		// In a real scenario, we might want to stop accepting new requests
		return nil
	})

	// Simulate some work
	for i := 0; i < 100; i++ {
		err := reliabilityManager.ProcessRequest("test", func() error {
			buffer := bufferPool.GetBuffer(1024)
			defer bufferPool.PutBuffer(buffer)

			// Simulate work
			time.Sleep(time.Microsecond)
			return nil
		})

		if err != nil {
			t.Errorf("Request %d failed: %v", i, err)
		}
	}

	// Test graceful shutdown
	err := shutdownManager.Shutdown()
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}

	// Verify metrics
	reliabilityMetrics := reliabilityManager.GetMetrics()
	if reliabilityMetrics["total_requests"].(int64) != 100 {
		t.Error("Expected 100 total requests in metrics")
	}

	poolStats := bufferPool.GetExtendedStats()
	if poolStats["gets"].(int64) != 100 {
		t.Error("Expected 100 buffer gets in stats")
	}
}

// TestShutdownManager tests the shutdown manager with timeout
func TestShutdownManagerTimeout(t *testing.T) {
	timeout := 5 * time.Second
	manager := NewShutdownManager(timeout)

	// Test shutdown with timeout
	go func() {
		_ = manager.Shutdown()
	}()

	// Test shutdown with error
	go func() {
		_ = manager.Shutdown()
	}()
}
