package core

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimiter implements token bucket algorithm for rate limiting
type RateLimiter struct {
	tokens     int64
	capacity   int64
	refillRate int64
	lastRefill int64
	mu         sync.Mutex
}

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState int32

const (
	// StateClosed circuit is closed, requests pass through
	StateClosed CircuitBreakerState = iota
	// StateHalfOpen circuit is half-open, limited requests pass through
	StateHalfOpen
	// StateOpen circuit is open, requests are rejected
	StateOpen
)

// CircuitBreaker implements circuit breaker pattern
type CircuitBreaker struct {
	state           int32 // CircuitBreakerState
	failures        int64
	successes       int64
	requests        int64
	lastFailureTime int64
	lastSuccessTime int64

	// Configuration
	maxFailures     int64
	timeout         time.Duration
	halfOpenMaxReqs int64
}

// BreakerManager manages multiple circuit breakers
type BreakerManager struct {
	breakers map[string]*CircuitBreaker
	mu       sync.RWMutex
}

// ReliabilityManager combines rate limiting and circuit breaking
type ReliabilityManager struct {
	rateLimiter    *RateLimiter
	breakerManager *BreakerManager
	metrics        *ReliabilityMetrics
}

// ReliabilityMetrics tracks reliability statistics
type ReliabilityMetrics struct {
	totalRequests      int64
	rateLimitedReqs    int64
	circuitBreakerReqs int64
	successfulReqs     int64
	failedReqs         int64
	startTime          time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(capacity, refillRate int64) *RateLimiter {
	now := time.Now().UnixNano()
	return &RateLimiter{
		tokens:     capacity,
		capacity:   capacity,
		refillRate: refillRate,
		lastRefill: now,
	}
}

// Allow checks if a request is allowed under rate limiting
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now().UnixNano()
	elapsed := now - rl.lastRefill

	// Refill tokens based on elapsed time
	tokensToAdd := (elapsed / int64(time.Second)) * rl.refillRate
	rl.tokens = min(rl.capacity, rl.tokens+tokensToAdd)
	rl.lastRefill = now

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	return false
}

// GetTokens returns current token count
func (rl *RateLimiter) GetTokens() int64 {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.tokens
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(maxFailures int64, timeout time.Duration, halfOpenMaxReqs int64) *CircuitBreaker {
	return &CircuitBreaker{
		state:           int32(StateClosed),
		maxFailures:     maxFailures,
		timeout:         timeout,
		halfOpenMaxReqs: halfOpenMaxReqs,
	}
}

// Execute executes a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if !cb.allowRequest() {
		return fmt.Errorf("circuit breaker is open")
	}

	err := fn()
	if err != nil {
		cb.recordFailure()
		return err
	}

	cb.recordSuccess()
	return nil
}

// allowRequest checks if request should be allowed
func (cb *CircuitBreaker) allowRequest() bool {
	state := CircuitBreakerState(atomic.LoadInt32(&cb.state))

	switch state {
	case StateClosed:
		return true
	case StateOpen:
		return cb.shouldAttemptReset()
	case StateHalfOpen:
		return atomic.LoadInt64(&cb.requests) < cb.halfOpenMaxReqs
	default:
		return false
	}
}

// shouldAttemptReset checks if circuit breaker should attempt to reset
func (cb *CircuitBreaker) shouldAttemptReset() bool {
	lastFailure := atomic.LoadInt64(&cb.lastFailureTime)
	return time.Since(time.Unix(0, lastFailure)) >= cb.timeout
}

// recordSuccess records a successful request
func (cb *CircuitBreaker) recordSuccess() {
	atomic.AddInt64(&cb.successes, 1)
	atomic.StoreInt64(&cb.lastSuccessTime, time.Now().UnixNano())

	state := CircuitBreakerState(atomic.LoadInt32(&cb.state))
	if state == StateHalfOpen {
		// Reset to closed state after successful requests in half-open
		if atomic.LoadInt64(&cb.successes) >= cb.halfOpenMaxReqs {
			atomic.StoreInt32(&cb.state, int32(StateClosed))
			atomic.StoreInt64(&cb.failures, 0)
			atomic.StoreInt64(&cb.requests, 0)
		}
	}
}

// recordFailure records a failed request
func (cb *CircuitBreaker) recordFailure() {
	failures := atomic.AddInt64(&cb.failures, 1)
	atomic.StoreInt64(&cb.lastFailureTime, time.Now().UnixNano())

	if failures >= cb.maxFailures {
		atomic.StoreInt32(&cb.state, int32(StateOpen))
	}
}

// GetState returns current circuit breaker state
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	return CircuitBreakerState(atomic.LoadInt32(&cb.state))
}

// GetStats returns circuit breaker statistics
func (cb *CircuitBreaker) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"state":           cb.GetState(),
		"failures":        atomic.LoadInt64(&cb.failures),
		"successes":       atomic.LoadInt64(&cb.successes),
		"requests":        atomic.LoadInt64(&cb.requests),
		"max_failures":    cb.maxFailures,
		"timeout_seconds": cb.timeout.Seconds(),
		"half_open_max":   cb.halfOpenMaxReqs,
	}
}

// NewBreakerManager creates a new breaker manager
func NewBreakerManager() *BreakerManager {
	return &BreakerManager{
		breakers: make(map[string]*CircuitBreaker),
	}
}

// GetBreaker gets or creates a circuit breaker for a service
func (bm *BreakerManager) GetBreaker(service string, maxFailures int64, timeout time.Duration, halfOpenMaxReqs int64) *CircuitBreaker {
	bm.mu.RLock()
	breaker, exists := bm.breakers[service]
	bm.mu.RUnlock()

	if exists {
		return breaker
	}

	bm.mu.Lock()
	defer bm.mu.Unlock()

	// Double-check after acquiring write lock
	if breaker, exists := bm.breakers[service]; exists {
		return breaker
	}

	breaker = NewCircuitBreaker(maxFailures, timeout, halfOpenMaxReqs)
	bm.breakers[service] = breaker
	return breaker
}

// GetAllBreakers returns all circuit breakers
func (bm *BreakerManager) GetAllBreakers() map[string]*CircuitBreaker {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	result := make(map[string]*CircuitBreaker)
	for k, v := range bm.breakers {
		result[k] = v
	}
	return result
}

// NewReliabilityManager creates a new reliability manager
func NewReliabilityManager(rateLimitCapacity, rateLimitRefill int64) *ReliabilityManager {
	return &ReliabilityManager{
		rateLimiter:    NewRateLimiter(rateLimitCapacity, rateLimitRefill),
		breakerManager: NewBreakerManager(),
		metrics: &ReliabilityMetrics{
			startTime: time.Now(),
		},
	}
}

// ProcessRequest processes a request with reliability controls
func (rm *ReliabilityManager) ProcessRequest(service string, fn func() error) error {
	atomic.AddInt64(&rm.metrics.totalRequests, 1)

	// Check rate limiting first
	if !rm.rateLimiter.Allow() {
		atomic.AddInt64(&rm.metrics.rateLimitedReqs, 1)
		return fmt.Errorf("rate limit exceeded")
	}

	// Get circuit breaker for service
	breaker := rm.breakerManager.GetBreaker(service, 5, 30*time.Second, 3)

	// Execute with circuit breaker protection
	err := breaker.Execute(fn)
	if err != nil {
		if err.Error() == "circuit breaker is open" {
			atomic.AddInt64(&rm.metrics.circuitBreakerReqs, 1)
		} else {
			atomic.AddInt64(&rm.metrics.failedReqs, 1)
		}
		return err
	}

	atomic.AddInt64(&rm.metrics.successfulReqs, 1)
	return nil
}

// GetMetrics returns reliability metrics
func (rm *ReliabilityManager) GetMetrics() map[string]interface{} {
	uptime := time.Since(rm.metrics.startTime)
	totalReqs := atomic.LoadInt64(&rm.metrics.totalRequests)

	successRate := float64(0)
	if totalReqs > 0 {
		successRate = float64(atomic.LoadInt64(&rm.metrics.successfulReqs)) / float64(totalReqs) * 100
	}

	return map[string]interface{}{
		"total_requests":           totalReqs,
		"successful_requests":      atomic.LoadInt64(&rm.metrics.successfulReqs),
		"failed_requests":          atomic.LoadInt64(&rm.metrics.failedReqs),
		"rate_limited_requests":    atomic.LoadInt64(&rm.metrics.rateLimitedReqs),
		"circuit_breaker_requests": atomic.LoadInt64(&rm.metrics.circuitBreakerReqs),
		"success_rate":             successRate,
		"uptime_seconds":           uptime.Seconds(),
		"requests_per_second":      float64(totalReqs) / uptime.Seconds(),
		"rate_limiter_tokens":      rm.rateLimiter.GetTokens(),
	}
}

// GetCircuitBreakerStats returns stats for all circuit breakers
func (rm *ReliabilityManager) GetCircuitBreakerStats() map[string]interface{} {
	breakers := rm.breakerManager.GetAllBreakers()
	stats := make(map[string]interface{})

	for service, breaker := range breakers {
		stats[service] = breaker.GetStats()
	}

	return stats
}

// Helper function
func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
