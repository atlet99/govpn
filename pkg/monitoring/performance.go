package monitoring

import (
	"context"
	"runtime"
	"sync"
	"time"
)

// PerformanceMonitor monitors system performance
type PerformanceMonitor struct {
	metrics  *MetricsCollector
	logger   *Logger
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	interval time.Duration

	// Counters for custom metrics
	connectionStarts    int64
	connectionEnds      int64
	authAttempts        int64
	obfuscationSwitches int64
	dpiDetections       int64

	mu sync.RWMutex
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor(metrics *MetricsCollector, logger *Logger, interval time.Duration) *PerformanceMonitor {
	ctx, cancel := context.WithCancel(context.Background())

	if interval == 0 {
		interval = 30 * time.Second // default interval
	}

	return &PerformanceMonitor{
		metrics:  metrics,
		logger:   logger,
		ctx:      ctx,
		cancel:   cancel,
		interval: interval,
	}
}

// Start starts the performance monitoring
func (pm *PerformanceMonitor) Start() {
	pm.wg.Add(1)
	go pm.collectSystemMetrics()

	pm.logger.LogSystemEvent("performance_monitor_started", "monitoring", "Performance monitoring started",
		"interval", pm.interval,
	)
}

// Stop stops the performance monitoring
func (pm *PerformanceMonitor) Stop() {
	pm.cancel()
	pm.wg.Wait()

	pm.logger.LogSystemEvent("performance_monitor_stopped", "monitoring", "Performance monitoring stopped")
}

// collectSystemMetrics collects system metrics
func (pm *PerformanceMonitor) collectSystemMetrics() {
	defer pm.wg.Done()

	ticker := time.NewTicker(pm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.updateSystemMetrics()
		}
	}
}

// updateSystemMetrics updates system metrics
func (pm *PerformanceMonitor) updateSystemMetrics() {
	// Runtime metrics
	var rtm runtime.MemStats
	runtime.ReadMemStats(&rtm)

	// Memory metrics
	pm.metrics.MemoryUsage.Set(float64(rtm.Alloc))
	pm.metrics.GoroutineCount.Set(float64(runtime.NumGoroutine()))

	// CPU usage (simplified - in real implementation would use system calls)
	// For now, we'll use GC overhead as a proxy for CPU usage
	gcCPU := float64(rtm.GCCPUFraction) * 100
	pm.metrics.CPUUsage.Set(gcCPU)

	// Log performance metrics
	pm.logger.LogPerformanceMetric("memory_usage", float64(rtm.Alloc), "bytes",
		"heap_objects", rtm.HeapObjects,
		"gc_runs", rtm.NumGC,
	)

	pm.logger.LogPerformanceMetric("goroutines", float64(runtime.NumGoroutine()), "count")
	pm.logger.LogPerformanceMetric("gc_cpu_fraction", float64(rtm.GCCPUFraction), "percent")

	// Custom application metrics
	pm.mu.RLock()
	pm.logger.LogPerformanceMetric("connection_starts", float64(pm.connectionStarts), "count")
	pm.logger.LogPerformanceMetric("connection_ends", float64(pm.connectionEnds), "count")
	pm.logger.LogPerformanceMetric("auth_attempts", float64(pm.authAttempts), "count")
	pm.logger.LogPerformanceMetric("obfuscation_switches", float64(pm.obfuscationSwitches), "count")
	pm.logger.LogPerformanceMetric("dpi_detections", float64(pm.dpiDetections), "count")
	pm.mu.RUnlock()
}

// Connection tracking
func (pm *PerformanceMonitor) OnConnectionStart(userID, protocol string) {
	pm.mu.Lock()
	pm.connectionStarts++
	pm.mu.Unlock()

	if pm.metrics != nil {
		pm.metrics.OnConnectionStart(userID, protocol)
	}
}

func (pm *PerformanceMonitor) OnConnectionEnd(userID, reason string, duration time.Duration) {
	pm.mu.Lock()
	pm.connectionEnds++
	pm.mu.Unlock()

	if pm.metrics != nil {
		pm.metrics.OnConnectionEnd(userID, reason, duration)
	}
}

// Traffic tracking
func (pm *PerformanceMonitor) OnTrafficReceived(userID, protocol string, bytes, packets int64) {
	if pm.metrics != nil {
		pm.metrics.OnTrafficReceived(userID, protocol, bytes, packets)
	}
}

func (pm *PerformanceMonitor) OnTrafficSent(userID, protocol string, bytes, packets int64) {
	if pm.metrics != nil {
		pm.metrics.OnTrafficSent(userID, protocol, bytes, packets)
	}
}

// Authentication tracking
func (pm *PerformanceMonitor) OnAuthAttempt(method, result string) {
	pm.mu.Lock()
	pm.authAttempts++
	pm.mu.Unlock()

	if pm.metrics != nil {
		pm.metrics.OnAuthAttempt(method, result)
	}
}

// Obfuscation tracking
func (pm *PerformanceMonitor) OnObfuscationSwitch() {
	pm.mu.Lock()
	pm.obfuscationSwitches++
	pm.mu.Unlock()

	if pm.metrics != nil {
		pm.metrics.OnObfuscationSwitch()
	}
}

func (pm *PerformanceMonitor) OnDPIDetection() {
	pm.mu.Lock()
	pm.dpiDetections++
	pm.mu.Unlock()

	if pm.metrics != nil {
		pm.metrics.OnDPIDetection()
	}
}

// GetMetricsSummary returns a summary of metrics
func (pm *PerformanceMonitor) GetMetricsSummary() map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var rtm runtime.MemStats
	runtime.ReadMemStats(&rtm)

	return map[string]interface{}{
		"runtime": map[string]interface{}{
			"memory_alloc":       rtm.Alloc,
			"memory_total_alloc": rtm.TotalAlloc,
			"memory_sys":         rtm.Sys,
			"memory_heap_alloc":  rtm.HeapAlloc,
			"memory_heap_sys":    rtm.HeapSys,
			"heap_objects":       rtm.HeapObjects,
			"goroutines":         runtime.NumGoroutine(),
			"gc_runs":            rtm.NumGC,
			"gc_cpu_fraction":    rtm.GCCPUFraction,
		},
		"application": map[string]interface{}{
			"connection_starts":    pm.connectionStarts,
			"connection_ends":      pm.connectionEnds,
			"auth_attempts":        pm.authAttempts,
			"obfuscation_switches": pm.obfuscationSwitches,
			"dpi_detections":       pm.dpiDetections,
		},
		"timestamp": time.Now(),
	}
}
