package monitoring

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// EnhancedMetrics provides comprehensive monitoring capabilities
type EnhancedMetrics struct {
	// Memory pool metrics
	bufferPoolGets   prometheus.Counter
	bufferPoolPuts   prometheus.Counter
	bufferPoolHits   prometheus.Counter
	bufferPoolMisses prometheus.Counter
	activeBuffers    prometheus.Gauge
	totalBufferBytes prometheus.Gauge

	// Authentication metrics
	authAttempts *prometheus.CounterVec
	authDuration *prometheus.HistogramVec
	cacheHitRate *prometheus.GaugeVec
	sessionCount prometheus.Gauge
	mfaAttempts  *prometheus.CounterVec

	// Reliability metrics
	requestsTotal     *prometheus.CounterVec
	requestDuration   *prometheus.HistogramVec
	rateLimitHits     prometheus.Counter
	circuitBreakerOps *prometheus.CounterVec
	errorRate         *prometheus.GaugeVec

	// System metrics
	goroutineCount prometheus.Gauge
	memoryUsage    *prometheus.GaugeVec
	gcDuration     prometheus.Histogram
	cpuUsage       prometheus.Gauge

	// Business metrics
	activeConnections prometheus.Gauge
	dataTransferred   *prometheus.CounterVec
	tunnelLatency     *prometheus.HistogramVec
	connectionErrors  *prometheus.CounterVec

	// Security metrics
	securityEvents     *prometheus.CounterVec
	failedLogins       *prometheus.CounterVec
	suspiciousActivity prometheus.Counter

	// Compliance metrics
	auditEvents      *prometheus.CounterVec
	complianceChecks *prometheus.CounterVec
	dataRetention    *prometheus.GaugeVec

	mu sync.RWMutex
}

// MetricsConfig configures the enhanced metrics system
type MetricsConfig struct {
	Namespace    string
	Subsystem    string
	EnableAll    bool
	CustomLabels map[string]string
}

// DefaultMetricsConfig returns default metrics configuration
func DefaultMetricsConfig() *MetricsConfig {
	return &MetricsConfig{
		Namespace:    "govpn",
		Subsystem:    "server",
		EnableAll:    true,
		CustomLabels: make(map[string]string),
	}
}

// NewEnhancedMetrics creates a new enhanced metrics instance
func NewEnhancedMetrics(config *MetricsConfig) *EnhancedMetrics {
	if config == nil {
		config = DefaultMetricsConfig()
	}

	em := &EnhancedMetrics{}
	em.initializeMetrics(config)
	return em
}

// initializeMetrics initializes all Prometheus metrics
func (em *EnhancedMetrics) initializeMetrics(config *MetricsConfig) {
	// Memory pool metrics
	em.bufferPoolGets = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "buffer_pool_gets_total",
		Help:      "Total number of buffer pool get operations",
	})

	em.bufferPoolPuts = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "buffer_pool_puts_total",
		Help:      "Total number of buffer pool put operations",
	})

	em.bufferPoolHits = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "buffer_pool_hits_total",
		Help:      "Total number of buffer pool cache hits",
	})

	em.bufferPoolMisses = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "buffer_pool_misses_total",
		Help:      "Total number of buffer pool cache misses",
	})

	em.activeBuffers = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "active_buffers",
		Help:      "Number of currently active buffers",
	})

	em.totalBufferBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "total_buffer_bytes",
		Help:      "Total bytes in active buffers",
	})

	// Authentication metrics
	em.authAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "auth_attempts_total",
		Help:      "Total authentication attempts",
	}, []string{"method", "result"})

	em.authDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "auth_duration_seconds",
		Help:      "Authentication duration in seconds",
		Buckets:   prometheus.DefBuckets,
	}, []string{"method"})

	em.cacheHitRate = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "cache_hit_rate",
		Help:      "Cache hit rate percentage",
	}, []string{"cache_type"})

	em.sessionCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "active_sessions",
		Help:      "Number of active user sessions",
	})

	em.mfaAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "mfa_attempts_total",
		Help:      "Total MFA attempts",
	}, []string{"result"})

	// Reliability metrics
	em.requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "requests_total",
		Help:      "Total number of requests",
	}, []string{"service", "result"})

	em.requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "request_duration_seconds",
		Help:      "Request duration in seconds",
		Buckets:   prometheus.DefBuckets,
	}, []string{"service"})

	em.rateLimitHits = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "rate_limit_hits_total",
		Help:      "Total number of rate limit hits",
	})

	em.circuitBreakerOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "circuit_breaker_operations_total",
		Help:      "Total circuit breaker operations",
	}, []string{"service", "state", "result"})

	em.errorRate = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "error_rate",
		Help:      "Error rate percentage",
	}, []string{"service"})

	// System metrics
	em.goroutineCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "goroutines",
		Help:      "Number of goroutines",
	})

	em.memoryUsage = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "memory_usage_bytes",
		Help:      "Memory usage in bytes",
	}, []string{"type"})

	em.gcDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "gc_duration_seconds",
		Help:      "Garbage collection duration in seconds",
		Buckets:   prometheus.DefBuckets,
	})

	em.cpuUsage = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "cpu_usage_percent",
		Help:      "CPU usage percentage",
	})

	// Business metrics
	em.activeConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "active_connections",
		Help:      "Number of active VPN connections",
	})

	em.dataTransferred = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "data_transferred_bytes_total",
		Help:      "Total data transferred in bytes",
	}, []string{"direction"})

	em.tunnelLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "tunnel_latency_seconds",
		Help:      "VPN tunnel latency in seconds",
		Buckets:   prometheus.DefBuckets,
	}, []string{"tunnel_type"})

	em.connectionErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "connection_errors_total",
		Help:      "Total connection errors",
	}, []string{"error_type"})

	// Security metrics
	em.securityEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "security_events_total",
		Help:      "Total security events",
	}, []string{"event_type", "severity"})

	em.failedLogins = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "failed_logins_total",
		Help:      "Total failed login attempts",
	}, []string{"source", "reason"})

	em.suspiciousActivity = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "suspicious_activity_total",
		Help:      "Total suspicious activity events",
	})

	// Compliance metrics
	em.auditEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "audit_events_total",
		Help:      "Total audit events",
	}, []string{"event_type", "user"})

	em.complianceChecks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "compliance_checks_total",
		Help:      "Total compliance checks",
	}, []string{"check_type", "result"})

	em.dataRetention = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: config.Namespace,
		Subsystem: config.Subsystem,
		Name:      "data_retention_days",
		Help:      "Data retention period in days",
	}, []string{"data_type"})
}

// Buffer Pool Metrics Methods

// RecordBufferPoolGet records a buffer pool get operation
func (em *EnhancedMetrics) RecordBufferPoolGet() {
	em.bufferPoolGets.Inc()
}

// RecordBufferPoolPut records a buffer pool put operation
func (em *EnhancedMetrics) RecordBufferPoolPut() {
	em.bufferPoolPuts.Inc()
}

// RecordBufferPoolHit records a buffer pool cache hit
func (em *EnhancedMetrics) RecordBufferPoolHit() {
	em.bufferPoolHits.Inc()
}

// RecordBufferPoolMiss records a buffer pool cache miss
func (em *EnhancedMetrics) RecordBufferPoolMiss() {
	em.bufferPoolMisses.Inc()
}

// SetActiveBuffers sets the number of active buffers
func (em *EnhancedMetrics) SetActiveBuffers(count float64) {
	em.activeBuffers.Set(count)
}

// SetTotalBufferBytes sets the total bytes in active buffers
func (em *EnhancedMetrics) SetTotalBufferBytes(bytes float64) {
	em.totalBufferBytes.Set(bytes)
}

// Authentication Metrics Methods

// RecordAuthAttempt records an authentication attempt
func (em *EnhancedMetrics) RecordAuthAttempt(method, result string) {
	em.authAttempts.WithLabelValues(method, result).Inc()
}

// RecordAuthDuration records authentication duration
func (em *EnhancedMetrics) RecordAuthDuration(method string, duration time.Duration) {
	em.authDuration.WithLabelValues(method).Observe(duration.Seconds())
}

// SetCacheHitRate sets cache hit rate
func (em *EnhancedMetrics) SetCacheHitRate(cacheType string, rate float64) {
	em.cacheHitRate.WithLabelValues(cacheType).Set(rate)
}

// SetSessionCount sets the number of active sessions
func (em *EnhancedMetrics) SetSessionCount(count float64) {
	em.sessionCount.Set(count)
}

// RecordMFAAttempt records an MFA attempt
func (em *EnhancedMetrics) RecordMFAAttempt(result string) {
	em.mfaAttempts.WithLabelValues(result).Inc()
}

// Reliability Metrics Methods

// RecordRequest records a request
func (em *EnhancedMetrics) RecordRequest(service, result string) {
	em.requestsTotal.WithLabelValues(service, result).Inc()
}

// RecordRequestDuration records request duration
func (em *EnhancedMetrics) RecordRequestDuration(service string, duration time.Duration) {
	em.requestDuration.WithLabelValues(service).Observe(duration.Seconds())
}

// RecordRateLimitHit records a rate limit hit
func (em *EnhancedMetrics) RecordRateLimitHit() {
	em.rateLimitHits.Inc()
}

// RecordCircuitBreakerOp records a circuit breaker operation
func (em *EnhancedMetrics) RecordCircuitBreakerOp(service, state, result string) {
	em.circuitBreakerOps.WithLabelValues(service, state, result).Inc()
}

// SetErrorRate sets error rate for a service
func (em *EnhancedMetrics) SetErrorRate(service string, rate float64) {
	em.errorRate.WithLabelValues(service).Set(rate)
}

// System Metrics Methods

// SetGoroutineCount sets the number of goroutines
func (em *EnhancedMetrics) SetGoroutineCount(count float64) {
	em.goroutineCount.Set(count)
}

// SetMemoryUsage sets memory usage
func (em *EnhancedMetrics) SetMemoryUsage(memType string, bytes float64) {
	em.memoryUsage.WithLabelValues(memType).Set(bytes)
}

// RecordGCDuration records garbage collection duration
func (em *EnhancedMetrics) RecordGCDuration(duration time.Duration) {
	em.gcDuration.Observe(duration.Seconds())
}

// SetCPUUsage sets CPU usage percentage
func (em *EnhancedMetrics) SetCPUUsage(percent float64) {
	em.cpuUsage.Set(percent)
}

// Business Metrics Methods

// SetActiveConnections sets the number of active connections
func (em *EnhancedMetrics) SetActiveConnections(count float64) {
	em.activeConnections.Set(count)
}

// RecordDataTransferred records data transfer
func (em *EnhancedMetrics) RecordDataTransferred(direction string, bytes float64) {
	em.dataTransferred.WithLabelValues(direction).Add(bytes)
}

// RecordTunnelLatency records tunnel latency
func (em *EnhancedMetrics) RecordTunnelLatency(tunnelType string, latency time.Duration) {
	em.tunnelLatency.WithLabelValues(tunnelType).Observe(latency.Seconds())
}

// RecordConnectionError records a connection error
func (em *EnhancedMetrics) RecordConnectionError(errorType string) {
	em.connectionErrors.WithLabelValues(errorType).Inc()
}

// Security Metrics Methods

// RecordSecurityEvent records a security event
func (em *EnhancedMetrics) RecordSecurityEvent(eventType, severity string) {
	em.securityEvents.WithLabelValues(eventType, severity).Inc()
}

// RecordFailedLogin records a failed login attempt
func (em *EnhancedMetrics) RecordFailedLogin(source, reason string) {
	em.failedLogins.WithLabelValues(source, reason).Inc()
}

// RecordSuspiciousActivity records suspicious activity
func (em *EnhancedMetrics) RecordSuspiciousActivity() {
	em.suspiciousActivity.Inc()
}

// Compliance Metrics Methods

// RecordAuditEvent records an audit event
func (em *EnhancedMetrics) RecordAuditEvent(eventType, user string) {
	em.auditEvents.WithLabelValues(eventType, user).Inc()
}

// RecordComplianceCheck records a compliance check
func (em *EnhancedMetrics) RecordComplianceCheck(checkType, result string) {
	em.complianceChecks.WithLabelValues(checkType, result).Inc()
}

// SetDataRetention sets data retention period
func (em *EnhancedMetrics) SetDataRetention(dataType string, days float64) {
	em.dataRetention.WithLabelValues(dataType).Set(days)
}

// UpdateFromBufferPool updates metrics from buffer pool stats
func (em *EnhancedMetrics) UpdateFromBufferPool(stats map[string]interface{}) {
	em.mu.Lock()
	defer em.mu.Unlock()

	if gets, ok := stats["gets"].(int64); ok {
		em.bufferPoolGets.Add(float64(gets))
	}
	if puts, ok := stats["puts"].(int64); ok {
		em.bufferPoolPuts.Add(float64(puts))
	}
	if hits, ok := stats["hits"].(int64); ok {
		em.bufferPoolHits.Add(float64(hits))
	}
	if misses, ok := stats["misses"].(int64); ok {
		em.bufferPoolMisses.Add(float64(misses))
	}
	if activeBuffers, ok := stats["active_buffers"].(int64); ok {
		em.activeBuffers.Set(float64(activeBuffers))
	}
	if totalBytes, ok := stats["total_bytes"].(int64); ok {
		em.totalBufferBytes.Set(float64(totalBytes))
	}
}

// UpdateFromReliabilityManager updates metrics from reliability manager
func (em *EnhancedMetrics) UpdateFromReliabilityManager(stats map[string]interface{}) {
	em.mu.Lock()
	defer em.mu.Unlock()

	if totalReqs, ok := stats["total_requests"].(int64); ok {
		em.requestsTotal.WithLabelValues("total", "all").Add(float64(totalReqs))
	}
	if rateLimited, ok := stats["rate_limited_requests"].(int64); ok {
		em.rateLimitHits.Add(float64(rateLimited))
	}
	if successRate, ok := stats["success_rate"].(float64); ok {
		em.errorRate.WithLabelValues("total").Set(100 - successRate)
	}
}

// GetMetricsSummary returns a summary of all metrics
func (em *EnhancedMetrics) GetMetricsSummary() map[string]interface{} {
	em.mu.RLock()
	defer em.mu.RUnlock()

	return map[string]interface{}{
		"buffer_pool": map[string]interface{}{
			"enabled": true,
			"metrics": []string{"gets", "puts", "hits", "misses", "active_buffers", "total_bytes"},
		},
		"authentication": map[string]interface{}{
			"enabled": true,
			"metrics": []string{"attempts", "duration", "cache_hit_rate", "sessions", "mfa_attempts"},
		},
		"reliability": map[string]interface{}{
			"enabled": true,
			"metrics": []string{"requests", "duration", "rate_limits", "circuit_breaker", "error_rate"},
		},
		"system": map[string]interface{}{
			"enabled": true,
			"metrics": []string{"goroutines", "memory", "gc_duration", "cpu_usage"},
		},
		"business": map[string]interface{}{
			"enabled": true,
			"metrics": []string{"connections", "data_transfer", "latency", "errors"},
		},
		"security": map[string]interface{}{
			"enabled": true,
			"metrics": []string{"events", "failed_logins", "suspicious_activity"},
		},
		"compliance": map[string]interface{}{
			"enabled": true,
			"metrics": []string{"audit_events", "checks", "data_retention"},
		},
	}
}
