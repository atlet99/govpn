package monitoring

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsCollector collects metrics for GoVPN server
type MetricsCollector struct {
	// Connection metrics
	ActiveConnections    prometheus.Gauge
	TotalConnections     prometheus.Counter
	ConnectionDuration   prometheus.Histogram
	DisconnectionReasons prometheus.CounterVec

	// Traffic metrics
	BytesReceived   prometheus.CounterVec
	BytesSent       prometheus.CounterVec
	PacketsReceived prometheus.CounterVec
	PacketsSent     prometheus.CounterVec
	PacketsDropped  prometheus.CounterVec

	// Authentication metrics
	AuthAttempts    prometheus.CounterVec
	AuthSuccessful  prometheus.Counter
	AuthFailed      prometheus.CounterVec
	SessionDuration prometheus.Histogram
	ActiveSessions  prometheus.Gauge

	// Obfuscation metrics
	ObfuscationMethods prometheus.CounterVec
	ObfuscationSwitch  prometheus.Counter
	DPIDetections      prometheus.Counter
	ObfuscationLatency prometheus.Histogram

	// Server performance metrics
	CPUUsage            prometheus.Gauge
	MemoryUsage         prometheus.Gauge
	GoroutineCount      prometheus.Gauge
	OpenFileDescriptors prometheus.Gauge
	NetworkErrors       prometheus.CounterVec

	// Certificate metrics
	CertificatesTotal      prometheus.GaugeVec
	CertificatesExpiring   prometheus.Gauge
	CertificateRevocations prometheus.Counter

	// Protocol metrics
	ProtocolVersions prometheus.CounterVec
	ClientVersions   prometheus.CounterVec
	ProtocolErrors   prometheus.CounterVec

	registry *prometheus.Registry
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	collector := &MetricsCollector{
		registry: prometheus.NewRegistry(),

		// Connection metrics
		ActiveConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "govpn_active_connections",
			Help: "Number of currently active VPN connections",
		}),

		TotalConnections: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "govpn_total_connections",
			Help: "Total number of VPN connections since startup",
		}),

		ConnectionDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "govpn_connection_duration_seconds",
			Help:    "Duration of VPN connections in seconds",
			Buckets: prometheus.ExponentialBuckets(1, 2, 15), // 1s to ~9h
		}),

		DisconnectionReasons: *prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "govpn_disconnection_reasons_total",
				Help: "Total disconnections by reason",
			},
			[]string{"reason"},
		),

		// Traffic metrics
		BytesReceived: *prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "govpn_bytes_received_total",
				Help: "Total bytes received by protocol",
			},
			[]string{"protocol", "user"},
		),

		BytesSent: *prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "govpn_bytes_sent_total",
				Help: "Total bytes sent by protocol",
			},
			[]string{"protocol", "user"},
		),

		PacketsReceived: *prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "govpn_packets_received_total",
				Help: "Total packets received by protocol",
			},
			[]string{"protocol", "user"},
		),

		PacketsSent: *prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "govpn_packets_sent_total",
				Help: "Total packets sent by protocol",
			},
			[]string{"protocol", "user"},
		),

		PacketsDropped: *prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "govpn_packets_dropped_total",
				Help: "Total packets dropped by reason",
			},
			[]string{"reason"},
		),

		// Authentication metrics
		AuthAttempts: *prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "govpn_auth_attempts_total",
				Help: "Total authentication attempts by method",
			},
			[]string{"method", "result"},
		),

		AuthSuccessful: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "govpn_auth_successful_total",
			Help: "Total successful authentications",
		}),

		AuthFailed: *prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "govpn_auth_failed_total",
				Help: "Total failed authentications by reason",
			},
			[]string{"reason"},
		),

		SessionDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "govpn_session_duration_seconds",
			Help:    "Duration of authentication sessions in seconds",
			Buckets: prometheus.ExponentialBuckets(60, 2, 12), // 1min to ~68h
		}),

		ActiveSessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "govpn_active_sessions",
			Help: "Number of currently active authentication sessions",
		}),

		// Obfuscation metrics
		ObfuscationMethods: *prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "govpn_obfuscation_methods_total",
				Help: "Total usage of obfuscation methods",
			},
			[]string{"method", "region"},
		),

		ObfuscationSwitch: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "govpn_obfuscation_switch_total",
			Help: "Total number of automatic obfuscation method switches",
		}),

		DPIDetections: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "govpn_dpi_detections_total",
			Help: "Total number of DPI blocking detections",
		}),

		ObfuscationLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "govpn_obfuscation_latency_seconds",
			Help:    "Latency added by obfuscation processing",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10), // 1ms to ~1s
		}),

		// Server performance metrics
		CPUUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "govpn_cpu_usage_percent",
			Help: "Current CPU usage percentage",
		}),

		MemoryUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "govpn_memory_usage_bytes",
			Help: "Current memory usage in bytes",
		}),

		GoroutineCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "govpn_goroutines",
			Help: "Number of goroutines currently running",
		}),

		OpenFileDescriptors: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "govpn_open_file_descriptors",
			Help: "Number of open file descriptors",
		}),

		NetworkErrors: *prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "govpn_network_errors_total",
				Help: "Total network errors by type",
			},
			[]string{"type", "interface"},
		),

		// Certificate metrics
		CertificatesTotal: *prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "govpn_certificates_total",
				Help: "Total number of certificates by type and status",
			},
			[]string{"type", "status"},
		),

		CertificatesExpiring: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "govpn_certificates_expiring_30d",
			Help: "Number of certificates expiring within 30 days",
		}),

		CertificateRevocations: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "govpn_certificate_revocations_total",
			Help: "Total number of certificate revocations",
		}),

		// Protocol metrics
		ProtocolVersions: *prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "govpn_protocol_versions_total",
				Help: "Total connections by protocol version",
			},
			[]string{"version"},
		),

		ClientVersions: *prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "govpn_client_versions_total",
				Help: "Total connections by client version",
			},
			[]string{"version", "platform"},
		),

		ProtocolErrors: *prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "govpn_protocol_errors_total",
				Help: "Total protocol errors by type",
			},
			[]string{"error_type", "protocol"},
		),
	}

	// Register all metrics
	collector.registerMetrics()

	return collector
}

// registerMetrics registers all metrics in the registry
func (m *MetricsCollector) registerMetrics() {
	m.registry.MustRegister(
		// Connection metrics
		m.ActiveConnections,
		m.TotalConnections,
		m.ConnectionDuration,
		&m.DisconnectionReasons,

		// Traffic metrics
		&m.BytesReceived,
		&m.BytesSent,
		&m.PacketsReceived,
		&m.PacketsSent,
		&m.PacketsDropped,

		// Authentication metrics
		&m.AuthAttempts,
		m.AuthSuccessful,
		&m.AuthFailed,
		m.SessionDuration,
		m.ActiveSessions,

		// Obfuscation metrics
		&m.ObfuscationMethods,
		m.ObfuscationSwitch,
		m.DPIDetections,
		m.ObfuscationLatency,

		// Server performance metrics
		m.CPUUsage,
		m.MemoryUsage,
		m.GoroutineCount,
		m.OpenFileDescriptors,
		&m.NetworkErrors,

		// Certificate metrics
		&m.CertificatesTotal,
		m.CertificatesExpiring,
		m.CertificateRevocations,

		// Protocol metrics
		&m.ProtocolVersions,
		&m.ClientVersions,
		&m.ProtocolErrors,
	)
}

// Handler returns HTTP handler for metrics export
func (m *MetricsCollector) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// StartMetricsServer starts HTTP server for metrics export
func (m *MetricsCollector) StartMetricsServer(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK")) // Ignore write error in health check
	})

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx) // Ignore shutdown error
	}()

	return server.ListenAndServe()
}

// Connection tracking methods
func (m *MetricsCollector) OnConnectionStart(userID, protocol string) {
	m.ActiveConnections.Inc()
	m.TotalConnections.Inc()
	m.ProtocolVersions.WithLabelValues(protocol).Inc()
}

func (m *MetricsCollector) OnConnectionEnd(userID, reason string, duration time.Duration) {
	m.ActiveConnections.Dec()
	m.DisconnectionReasons.WithLabelValues(reason).Inc()
	m.ConnectionDuration.Observe(duration.Seconds())
}

// Traffic tracking methods
func (m *MetricsCollector) OnTrafficReceived(userID, protocol string, bytes, packets int64) {
	m.BytesReceived.WithLabelValues(protocol, userID).Add(float64(bytes))
	m.PacketsReceived.WithLabelValues(protocol, userID).Add(float64(packets))
}

func (m *MetricsCollector) OnTrafficSent(userID, protocol string, bytes, packets int64) {
	m.BytesSent.WithLabelValues(protocol, userID).Add(float64(bytes))
	m.PacketsSent.WithLabelValues(protocol, userID).Add(float64(packets))
}

func (m *MetricsCollector) OnPacketsDropped(reason string, count int64) {
	m.PacketsDropped.WithLabelValues(reason).Add(float64(count))
}

// Authentication tracking methods
func (m *MetricsCollector) OnAuthAttempt(method, result string) {
	m.AuthAttempts.WithLabelValues(method, result).Inc()
	if result == "success" {
		m.AuthSuccessful.Inc()
		m.ActiveSessions.Inc()
	} else {
		m.AuthFailed.WithLabelValues(result).Inc()
	}
}

func (m *MetricsCollector) OnSessionEnd(duration time.Duration) {
	m.ActiveSessions.Dec()
	m.SessionDuration.Observe(duration.Seconds())
}

// Obfuscation tracking methods
func (m *MetricsCollector) OnObfuscationMethodUsed(method, region string) {
	m.ObfuscationMethods.WithLabelValues(method, region).Inc()
}

func (m *MetricsCollector) OnObfuscationSwitch() {
	m.ObfuscationSwitch.Inc()
}

func (m *MetricsCollector) OnDPIDetection() {
	m.DPIDetections.Inc()
}

func (m *MetricsCollector) OnObfuscationProcessed(latency time.Duration) {
	m.ObfuscationLatency.Observe(latency.Seconds())
}

// Certificate tracking methods
func (m *MetricsCollector) UpdateCertificateCount(certType, status string, count float64) {
	m.CertificatesTotal.WithLabelValues(certType, status).Set(count)
}

func (m *MetricsCollector) UpdateExpiringCertificates(count float64) {
	m.CertificatesExpiring.Set(count)
}

func (m *MetricsCollector) OnCertificateRevocation() {
	m.CertificateRevocations.Inc()
}

// Network error tracking
func (m *MetricsCollector) OnNetworkError(errorType, interfaceName string) {
	m.NetworkErrors.WithLabelValues(errorType, interfaceName).Inc()
}

// Client information tracking
func (m *MetricsCollector) OnClientConnection(version, platform string) {
	m.ClientVersions.WithLabelValues(version, platform).Inc()
}

func (m *MetricsCollector) OnProtocolError(errorType, protocol string) {
	m.ProtocolErrors.WithLabelValues(errorType, protocol).Inc()
}
