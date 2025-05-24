package obfuscation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/big"
	mathrand "math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

// ObfuscationMethod represents the type of obfuscation method
type ObfuscationMethod string

const (
	MethodTLSTunnel      ObfuscationMethod = "tls_tunnel"
	MethodHTTPMimicry    ObfuscationMethod = "http_mimicry"
	MethodSSHMimicry     ObfuscationMethod = "ssh_mimicry"
	MethodDNSTunnel      ObfuscationMethod = "dns_tunnel"
	MethodXORCipher      ObfuscationMethod = "xor_cipher"
	MethodPacketPadding  ObfuscationMethod = "packet_padding"
	MethodTimingObfs     ObfuscationMethod = "timing_obfs"
	MethodTrafficPadding ObfuscationMethod = "traffic_padding"
	MethodFlowWatermark  ObfuscationMethod = "flow_watermark"
	MethodHTTPStego      ObfuscationMethod = "http_stego"
)

// Obfuscator interface for all obfuscation methods
type Obfuscator interface {
	Name() ObfuscationMethod
	Obfuscate(data []byte) ([]byte, error)
	Deobfuscate(data []byte) ([]byte, error)
	WrapConn(conn net.Conn) (net.Conn, error)
	IsAvailable() bool
	GetMetrics() ObfuscatorMetrics
}

// ObfuscatorMetrics metrics for each obfuscator
type ObfuscatorMetrics struct {
	PacketsProcessed int64         `json:"packets_processed"`
	BytesProcessed   int64         `json:"bytes_processed"`
	Errors           int64         `json:"errors"`
	AvgProcessTime   time.Duration `json:"avg_process_time"`
	LastUsed         time.Time     `json:"last_used"`
}

// Config contains configuration for the obfuscation engine
type Config struct {
	EnabledMethods    []ObfuscationMethod  `json:"enabled_methods"`
	PrimaryMethod     ObfuscationMethod    `json:"primary_method"`
	FallbackMethods   []ObfuscationMethod  `json:"fallback_methods"`
	AutoDetection     bool                 `json:"auto_detection"`
	SwitchThreshold   int                  `json:"switch_threshold"`
	DetectionTimeout  time.Duration        `json:"detection_timeout"`
	RegionalProfile   string               `json:"regional_profile"`
	PacketPadding     PacketPaddingConfig  `json:"packet_padding"`
	TimingObfuscation TimingObfsConfig     `json:"timing_obfuscation"`
	TrafficPadding    TrafficPaddingConfig `json:"traffic_padding"`
	FlowWatermark     FlowWatermarkConfig  `json:"flow_watermark"`
	TLSTunnel         TLSTunnelConfig      `json:"tls_tunnel"`
	HTTPMimicry       HTTPMimicryConfig    `json:"http_mimicry"`
	DNSTunnel         DNSTunnelConfig      `json:"dns_tunnel"`
	HTTPStego         HTTPStegoConfig      `json:"http_stego"`
	XORKey            []byte               `json:"xor_key,omitempty"`
}

type PacketPaddingConfig struct {
	Enabled       bool `json:"enabled"`
	MinPadding    int  `json:"min_padding"`
	MaxPadding    int  `json:"max_padding"`
	RandomizeSize bool `json:"randomize_size"`
}

type TimingObfsConfig struct {
	Enabled      bool          `json:"enabled"`
	MinDelay     time.Duration `json:"min_delay"`
	MaxDelay     time.Duration `json:"max_delay"`
	RandomJitter bool          `json:"random_jitter"`
}

type TrafficPaddingConfig struct {
	Enabled      bool          `json:"enabled"`
	MinInterval  time.Duration `json:"min_interval"`
	MaxInterval  time.Duration `json:"max_interval"`
	MinDummySize int           `json:"min_dummy_size"`
	MaxDummySize int           `json:"max_dummy_size"`
	BurstMode    bool          `json:"burst_mode"`
	BurstSize    int           `json:"burst_size"`
	AdaptiveMode bool          `json:"adaptive_mode"`
}

type FlowWatermarkConfig struct {
	Enabled         bool          `json:"enabled"`
	WatermarkKey    []byte        `json:"watermark_key,omitempty"`
	PatternInterval time.Duration `json:"pattern_interval"`
	PatternStrength float64       `json:"pattern_strength"`
	NoiseLevel      float64       `json:"noise_level"`
	RotationPeriod  time.Duration `json:"rotation_period"`
	StatisticalMode bool          `json:"statistical_mode"`
	FrequencyBands  []int         `json:"frequency_bands"`
}

type TLSTunnelConfig struct {
	ServerName      string   `json:"server_name"`
	ALPN            []string `json:"alpn"`
	FakeHTTPHeaders bool     `json:"fake_http_headers"`
}

type HTTPMimicryConfig struct {
	UserAgent     string            `json:"user_agent"`
	FakeHost      string            `json:"fake_host"`
	CustomHeaders map[string]string `json:"custom_headers"`
	MimicWebsite  string            `json:"mimic_website"`
}

type DNSTunnelConfig struct {
	Enabled        bool          `json:"enabled"`
	DomainSuffix   string        `json:"domain_suffix"`
	DNSServers     []string      `json:"dns_servers"`
	QueryTypes     []string      `json:"query_types"`
	EncodingMethod string        `json:"encoding_method"`
	MaxPayloadSize int           `json:"max_payload_size"`
	QueryDelay     time.Duration `json:"query_delay"`
	Subdomain      string        `json:"subdomain"`
}

// DPIDetector detects DPI blocking
type DPIDetector struct {
	detectionTimeout time.Duration
	switchThreshold  int
	failures         map[ObfuscationMethod]int
	lastFailure      map[ObfuscationMethod]time.Time
	mu               sync.RWMutex
	logger           *log.Logger
}

func NewDPIDetector(timeout time.Duration, logger *log.Logger) *DPIDetector {
	return &DPIDetector{
		detectionTimeout: timeout,
		switchThreshold:  3,
		failures:         make(map[ObfuscationMethod]int),
		lastFailure:      make(map[ObfuscationMethod]time.Time),
		logger:           logger,
	}
}

func (d *DPIDetector) ShouldSwitch(method ObfuscationMethod, err error) bool {
	if err == nil {
		d.resetFailures(method)
		return false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.isDPIRelatedError(err) {
		d.failures[method]++
		d.lastFailure[method] = time.Now()
		d.logger.Printf("DPI-related error detected for method %s: %v (failures: %d)",
			method, err, d.failures[method])
		return d.failures[method] >= d.switchThreshold
	}

	return false
}

func (d *DPIDetector) isDPIRelatedError(err error) bool {
	errorStr := strings.ToLower(err.Error())
	dpiPatterns := []string{
		"connection reset by peer",
		"connection refused",
		"timeout",
		"certificate verify failed",
		"handshake failure",
		"protocol error",
		"unexpected eof",
		"no route to host",
	}

	for _, pattern := range dpiPatterns {
		if strings.Contains(errorStr, pattern) {
			return true
		}
	}
	return false
}

func (d *DPIDetector) resetFailures(method ObfuscationMethod) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.failures[method] > 0 {
		d.logger.Printf("Resetting failure count for method %s", method)
		d.failures[method] = 0
		delete(d.lastFailure, method)
	}
}

// XORCipher simple XOR obfuscator
type XORCipher struct {
	key     []byte
	keyLen  int
	metrics ObfuscatorMetrics
	mu      sync.RWMutex
	logger  *log.Logger
}

func NewXORCipher(key []byte, logger *log.Logger) (*XORCipher, error) {
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("failed to generate random key: %w", err)
		}
	}

	return &XORCipher{
		key:    key,
		keyLen: len(key),
		logger: logger,
	}, nil
}

func (x *XORCipher) Name() ObfuscationMethod {
	return MethodXORCipher
}

func (x *XORCipher) Obfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		x.updateMetrics(len(data), time.Since(start), nil)
	}()

	if len(data) == 0 {
		return data, nil
	}

	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ x.key[i%x.keyLen]
	}

	return result, nil
}

func (x *XORCipher) Deobfuscate(data []byte) ([]byte, error) {
	return x.Obfuscate(data)
}

func (x *XORCipher) WrapConn(conn net.Conn) (net.Conn, error) {
	return &xorConn{Conn: conn, cipher: x}, nil
}

func (x *XORCipher) IsAvailable() bool {
	return len(x.key) > 0
}

func (x *XORCipher) GetMetrics() ObfuscatorMetrics {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.metrics
}

func (x *XORCipher) updateMetrics(dataSize int, processingTime time.Duration, err error) {
	x.mu.Lock()
	defer x.mu.Unlock()

	x.metrics.PacketsProcessed++
	x.metrics.BytesProcessed += int64(dataSize)
	x.metrics.LastUsed = time.Now()

	if err != nil {
		x.metrics.Errors++
	}

	if x.metrics.AvgProcessTime == 0 {
		x.metrics.AvgProcessTime = processingTime
	} else {
		x.metrics.AvgProcessTime = (x.metrics.AvgProcessTime + processingTime) / 2
	}
}

type xorConn struct {
	net.Conn
	cipher *XORCipher
}

func (c *xorConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err != nil || n == 0 {
		return n, err
	}

	deobfuscated, deobfErr := c.cipher.Deobfuscate(b[:n])
	if deobfErr != nil {
		return n, deobfErr
	}

	copy(b, deobfuscated)
	return n, nil
}

func (c *xorConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	obfuscated, obfErr := c.cipher.Obfuscate(b)
	if obfErr != nil {
		return 0, obfErr
	}

	return c.Conn.Write(obfuscated)
}

// stubObfuscator stub for unimplemented obfuscators
type stubObfuscator struct {
	name   ObfuscationMethod
	logger *log.Logger
}

func (s *stubObfuscator) Name() ObfuscationMethod {
	return s.name
}

func (s *stubObfuscator) Obfuscate(data []byte) ([]byte, error) {
	s.logger.Printf("Stub obfuscator %s: passthrough %d bytes", s.name, len(data))
	return data, nil
}

func (s *stubObfuscator) Deobfuscate(data []byte) ([]byte, error) {
	return data, nil
}

func (s *stubObfuscator) WrapConn(conn net.Conn) (net.Conn, error) {
	return conn, nil
}

func (s *stubObfuscator) IsAvailable() bool {
	return true
}

func (s *stubObfuscator) GetMetrics() ObfuscatorMetrics {
	return ObfuscatorMetrics{}
}

// TLSTunnel TLS tunneling obfuscator
type TLSTunnel struct {
	config  *TLSTunnelConfig
	metrics ObfuscatorMetrics
	mu      sync.RWMutex
	logger  *log.Logger
	cert    tls.Certificate
}

func NewTLSTunnel(config *TLSTunnelConfig, logger *log.Logger) (Obfuscator, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	tunnel := &TLSTunnel{
		config: config,
		logger: logger,
	}

	// Set defaults
	if tunnel.config.ServerName == "" {
		tunnel.config.ServerName = "example.com"
	}
	if len(tunnel.config.ALPN) == 0 {
		tunnel.config.ALPN = []string{"h2", "http/1.1"}
	}

	// Generate self-signed certificate for TLS tunneling
	if err := tunnel.generateCertificate(); err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	return tunnel, nil
}

func (t *TLSTunnel) generateCertificate() error {
	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"GoVPN"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{t.config.ServerName, "localhost"},
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Create TLS certificate
	t.cert = tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	return nil
}

func (t *TLSTunnel) Name() ObfuscationMethod {
	return MethodTLSTunnel
}

func (t *TLSTunnel) Obfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		t.updateMetrics(len(data), time.Since(start), nil)
	}()

	// For TLS tunneling, we encapsulate data in a TLS record
	// This is a simplified implementation - in real-world usage,
	// this would be handled by the TLS connection wrapper
	return data, nil
}

func (t *TLSTunnel) Deobfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		t.updateMetrics(len(data), time.Since(start), nil)
	}()

	// For TLS tunneling, deobfuscation is handled by TLS unwrapping
	return data, nil
}

func (t *TLSTunnel) WrapConn(conn net.Conn) (net.Conn, error) {
	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{t.cert},
		ServerName:   t.config.ServerName,
		NextProtos:   t.config.ALPN,
		MinVersion:   tls.VersionTLS12,
		// For obfuscation purposes, we accept any certificate
		InsecureSkipVerify: true,
	}

	// Wrap connection with TLS
	tlsConn := tls.Client(conn, tlsConfig)

	// Create wrapped connection with additional features
	wrappedConn := &tlsTunnelConn{
		Conn:   tlsConn,
		tunnel: t,
		config: t.config,
	}

	return wrappedConn, nil
}

func (t *TLSTunnel) IsAvailable() bool {
	return true
}

func (t *TLSTunnel) GetMetrics() ObfuscatorMetrics {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.metrics
}

func (t *TLSTunnel) updateMetrics(dataSize int, processingTime time.Duration, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.metrics.PacketsProcessed++
	t.metrics.BytesProcessed += int64(dataSize)
	t.metrics.LastUsed = time.Now()

	if err != nil {
		t.metrics.Errors++
	}

	// Update average processing time
	if t.metrics.AvgProcessTime == 0 {
		t.metrics.AvgProcessTime = processingTime
	} else {
		t.metrics.AvgProcessTime = (t.metrics.AvgProcessTime + processingTime) / 2
	}
}

// tlsTunnelConn wraps a TLS connection with additional obfuscation features
type tlsTunnelConn struct {
	net.Conn
	tunnel *TLSTunnel
	config *TLSTunnelConfig
}

func (c *tlsTunnelConn) Write(b []byte) (n int, err error) {
	if c.config.FakeHTTPHeaders && len(b) > 0 {
		// Add fake HTTP-like headers occasionally to confuse DPI
		// This is a simplified implementation
		if mathrand.Intn(10) == 0 { // 10% chance
			fakeHeader := "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
			headerBytes := []byte(fakeHeader)
			if len(headerBytes)+len(b) < 65536 { // Avoid too large packets
				combined := make([]byte, len(headerBytes)+len(b))
				copy(combined, headerBytes)
				copy(combined[len(headerBytes):], b)
				return c.Conn.Write(combined)
			}
		}
	}

	return c.Conn.Write(b)
}

// HTTPMimicry disguises VPN traffic as legitimate HTTP requests/responses
type HTTPMimicry struct {
	config       *HTTPMimicryConfig
	metrics      ObfuscatorMetrics
	mu           sync.RWMutex
	logger       *log.Logger
	userAgents   []string
	commonHosts  []string
	httpMethods  []string
	contentTypes []string
}

func NewHTTPMimicry(config *HTTPMimicryConfig, logger *log.Logger) (Obfuscator, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	if config == nil {
		config = &HTTPMimicryConfig{
			UserAgent:     "",
			FakeHost:      "",
			CustomHeaders: make(map[string]string),
			MimicWebsite:  "",
		}
	}

	mimicry := &HTTPMimicry{
		config: config,
		logger: logger,
		// Realistic User-Agent strings from popular browsers (2024 updated)
		userAgents: []string{
			// Windows Desktop - Chrome
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			// Windows Desktop - Edge
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/120.0.2210.144",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			// Windows Desktop - Firefox
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
			// macOS Desktop - Chrome
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
			// macOS Desktop - Safari
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			// macOS Desktop - Firefox
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:122.0) Gecko/20100101 Firefox/122.0",
			// Linux Desktop - Chrome
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
			// Linux Desktop - Firefox
			"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
			"Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
			// Mobile Android - Chrome
			"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
			"Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
			// Mobile Android - Samsung Browser
			"Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
			// Mobile iOS - Safari
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
			// Mobile iOS - Chrome
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/121.0.6167.66 Mobile/15E148 Safari/604.1",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/121.0.6167.66 Mobile/15E148 Safari/604.1",
		},
		// Common legitimate hostnames
		commonHosts: []string{
			"api.github.com",
			"www.googleapis.com",
			"cdn.jsdelivr.net",
			"fonts.googleapis.com",
			"ajax.googleapis.com",
			"api.openweathermap.org",
			"jsonplaceholder.typicode.com",
			"httpbin.org",
			"www.httpbin.org",
			"postman-echo.com",
		},
		// HTTP methods for different request types
		httpMethods: []string{
			"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
		},
		// Common content types
		contentTypes: []string{
			"application/json",
			"application/x-www-form-urlencoded",
			"text/html; charset=utf-8",
			"text/plain; charset=utf-8",
			"application/javascript",
			"text/css",
			"image/png",
			"image/jpeg",
		},
	}

	return mimicry, nil
}

func (h *HTTPMimicry) Name() ObfuscationMethod {
	return MethodHTTPMimicry
}

func (h *HTTPMimicry) Obfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		h.updateMetrics(len(data), time.Since(start), nil)
	}()

	if len(data) == 0 {
		return data, nil
	}

	// Create HTTP request/response structure to disguise VPN data
	httpPacket := h.createHTTPPacket(data)
	return httpPacket, nil
}

func (h *HTTPMimicry) Deobfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		h.updateMetrics(len(data), time.Since(start), nil)
	}()

	if len(data) == 0 {
		return data, nil
	}

	// Extract original VPN data from HTTP packet
	return h.extractVPNData(data)
}

func (h *HTTPMimicry) WrapConn(conn net.Conn) (net.Conn, error) {
	return &httpMimicryConn{
		Conn:    conn,
		mimicry: h,
	}, nil
}

func (h *HTTPMimicry) IsAvailable() bool {
	return true
}

func (h *HTTPMimicry) GetMetrics() ObfuscatorMetrics {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.metrics
}

func (h *HTTPMimicry) updateMetrics(dataSize int, processingTime time.Duration, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.metrics.PacketsProcessed++
	h.metrics.BytesProcessed += int64(dataSize)
	h.metrics.LastUsed = time.Now()

	if err != nil {
		h.metrics.Errors++
	}

	// Update average processing time
	if h.metrics.AvgProcessTime == 0 {
		h.metrics.AvgProcessTime = processingTime
	} else {
		h.metrics.AvgProcessTime = (h.metrics.AvgProcessTime + processingTime) / 2
	}
}

// createHTTPPacket wraps VPN data in a realistic HTTP request/response
func (h *HTTPMimicry) createHTTPPacket(vpnData []byte) []byte {
	// Determine if this should be a request or response (alternate based on data size)
	isRequest := len(vpnData)%2 == 0

	var httpPacket []byte
	if isRequest {
		httpPacket = h.createHTTPRequest(vpnData)
	} else {
		httpPacket = h.createHTTPResponse(vpnData)
	}

	return httpPacket
}

// createHTTPRequest creates a realistic HTTP request with VPN data as body
func (h *HTTPMimicry) createHTTPRequest(vpnData []byte) []byte {
	// Select random method and host
	method := h.httpMethods[mathrand.Intn(len(h.httpMethods))]

	var host string
	if h.config.FakeHost != "" {
		host = h.config.FakeHost
	} else {
		host = h.commonHosts[mathrand.Intn(len(h.commonHosts))]
	}

	// Generate realistic URL path
	paths := []string{"/api/v1/data", "/api/users", "/search", "/graphql", "/rest/api/2/issue", "/v1/chat/completions"}
	path := paths[mathrand.Intn(len(paths))]

	// Select User-Agent
	var userAgent string
	if h.config.UserAgent != "" {
		userAgent = h.config.UserAgent
	} else {
		userAgent = h.userAgents[mathrand.Intn(len(h.userAgents))]
	}

	// Build HTTP request
	var request strings.Builder
	request.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
	request.WriteString(fmt.Sprintf("Host: %s\r\n", host))
	request.WriteString(fmt.Sprintf("User-Agent: %s\r\n", userAgent))
	request.WriteString("Accept: application/json, text/plain, */*\r\n")
	request.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
	request.WriteString("Accept-Encoding: gzip, deflate, br\r\n")
	request.WriteString("Connection: keep-alive\r\n")

	// Add custom headers if configured
	for key, value := range h.config.CustomHeaders {
		request.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}

	// Add realistic headers for POST/PUT requests
	if method == "POST" || method == "PUT" || method == "PATCH" {
		contentType := h.contentTypes[mathrand.Intn(len(h.contentTypes))]
		request.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
		request.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(vpnData)))
	}

	request.WriteString("\r\n")

	// Add VPN data as HTTP body (for POST/PUT requests)
	result := []byte(request.String())
	if method == "POST" || method == "PUT" || method == "PATCH" {
		result = append(result, vpnData...)
	} else {
		// For GET requests, encode VPN data in headers or URL parameters
		result = h.encodeDataInHeaders(result, vpnData)
	}

	return result
}

// createHTTPResponse creates a realistic HTTP response with VPN data as body
func (h *HTTPMimicry) createHTTPResponse(vpnData []byte) []byte {
	// Generate realistic status codes
	statusCodes := []int{200, 201, 202, 204, 301, 302, 304, 400, 401, 404, 500, 502}
	statusCode := statusCodes[mathrand.Intn(len(statusCodes))]

	statusText := map[int]string{
		200: "OK", 201: "Created", 202: "Accepted", 204: "No Content",
		301: "Moved Permanently", 302: "Found", 304: "Not Modified",
		400: "Bad Request", 401: "Unauthorized", 404: "Not Found",
		500: "Internal Server Error", 502: "Bad Gateway",
	}

	var response strings.Builder
	response.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, statusText[statusCode]))
	response.WriteString("Server: nginx/1.20.2\r\n")
	response.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")))

	// Add realistic content type
	contentType := h.contentTypes[mathrand.Intn(len(h.contentTypes))]
	response.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
	response.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(vpnData)))

	// Add common response headers
	response.WriteString("Cache-Control: no-cache, private\r\n")
	response.WriteString("X-Content-Type-Options: nosniff\r\n")
	response.WriteString("X-Frame-Options: DENY\r\n")
	response.WriteString("X-XSS-Protection: 1; mode=block\r\n")
	response.WriteString("Connection: keep-alive\r\n")

	response.WriteString("\r\n")

	// Add VPN data as response body
	result := []byte(response.String())
	result = append(result, vpnData...)

	return result
}

// encodeDataInHeaders encodes small amounts of VPN data in HTTP headers for GET requests
func (h *HTTPMimicry) encodeDataInHeaders(httpData []byte, vpnData []byte) []byte {
	if len(vpnData) > 1024 { // Too large for headers, return as-is
		return append(httpData, vpnData...)
	}

	// Encode VPN data as base64 and split into multiple headers
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(vpnData)))
	base64.StdEncoding.Encode(encoded, vpnData)

	// Split encoded data into chunks and add as custom headers
	headerTemplate := "X-Request-ID: %s\r\nX-Trace-ID: %s\r\nX-Session-Token: %s\r\n\r\n"

	// Split into 3 parts for different headers
	chunkSize := len(encoded) / 3
	if chunkSize == 0 {
		chunkSize = len(encoded)
	}

	var chunk1, chunk2, chunk3 string
	if len(encoded) > 0 {
		end1 := chunkSize
		if end1 > len(encoded) {
			end1 = len(encoded)
		}
		chunk1 = string(encoded[:end1])

		if len(encoded) > chunkSize {
			end2 := chunkSize * 2
			if end2 > len(encoded) {
				end2 = len(encoded)
			}
			chunk2 = string(encoded[chunkSize:end2])

			if len(encoded) > chunkSize*2 {
				chunk3 = string(encoded[chunkSize*2:])
			}
		}
	}

	headerData := fmt.Sprintf(headerTemplate, chunk1, chunk2, chunk3)
	return []byte(strings.Replace(string(httpData), "\r\n\r\n", "\r\n"+headerData, 1))
}

// extractVPNData extracts original VPN data from HTTP packet
func (h *HTTPMimicry) extractVPNData(httpData []byte) ([]byte, error) {
	dataStr := string(httpData)

	// Find the HTTP headers/body separator
	separatorIndex := strings.Index(dataStr, "\r\n\r\n")
	if separatorIndex == -1 {
		return httpData, fmt.Errorf("invalid HTTP packet format")
	}

	headers := dataStr[:separatorIndex]
	body := dataStr[separatorIndex+4:]

	// Check if data is encoded in headers (for GET requests)
	if h.isEncodedInHeaders(headers) {
		return h.extractFromHeaders(headers)
	}

	// Otherwise, VPN data is in the body
	return []byte(body), nil
}

// isEncodedInHeaders checks if VPN data is encoded in custom headers
func (h *HTTPMimicry) isEncodedInHeaders(headers string) bool {
	return strings.Contains(headers, "X-Request-ID:") &&
		strings.Contains(headers, "X-Trace-ID:") &&
		strings.Contains(headers, "X-Session-Token:")
}

// extractFromHeaders extracts and decodes VPN data from custom headers
func (h *HTTPMimicry) extractFromHeaders(headers string) ([]byte, error) {
	lines := strings.Split(headers, "\r\n")
	var chunk1, chunk2, chunk3 string

	for _, line := range lines {
		if strings.HasPrefix(line, "X-Request-ID:") {
			chunk1 = strings.TrimSpace(strings.TrimPrefix(line, "X-Request-ID:"))
		} else if strings.HasPrefix(line, "X-Trace-ID:") {
			chunk2 = strings.TrimSpace(strings.TrimPrefix(line, "X-Trace-ID:"))
		} else if strings.HasPrefix(line, "X-Session-Token:") {
			chunk3 = strings.TrimSpace(strings.TrimPrefix(line, "X-Session-Token:"))
		}
	}

	// Reconstruct base64 encoded data
	encoded := chunk1 + chunk2 + chunk3
	if encoded == "" {
		return []byte{}, nil
	}

	// Decode from base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode VPN data from headers: %w", err)
	}

	return decoded, nil
}

// httpMimicryConn wraps a connection with HTTP mimicry
type httpMimicryConn struct {
	net.Conn
	mimicry *HTTPMimicry
}

func (c *httpMimicryConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err != nil || n == 0 {
		return n, err
	}

	deobfuscated, deobfErr := c.mimicry.Deobfuscate(b[:n])
	if deobfErr != nil {
		return n, deobfErr
	}

	copy(b, deobfuscated)
	return len(deobfuscated), nil
}

func (c *httpMimicryConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	obfuscated, obfErr := c.mimicry.Obfuscate(b)
	if obfErr != nil {
		return 0, obfErr
	}

	_, err = c.Conn.Write(obfuscated)
	if err != nil {
		return 0, err
	}

	// Return the number of original bytes written
	return len(b), nil
}

// DNSTunnel DNS tunneling obfuscator for emergency backup communication
type DNSTunnel struct {
	config       *DNSTunnelConfig
	metrics      ObfuscatorMetrics
	mu           sync.RWMutex
	logger       *log.Logger
	resolver     *net.Resolver
	queryCounter uint32
	encodingMap  map[byte]string
	decodingMap  map[string]byte
}

func NewDNSTunnel(config *DNSTunnelConfig, logger *log.Logger) (Obfuscator, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	if config == nil {
		config = &DNSTunnelConfig{
			Enabled: true,
		}
	}

	tunnel := &DNSTunnel{
		config: config,
		logger: logger,
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Second * 3,
				}
				return d.DialContext(ctx, network, address)
			},
		},
	}

	// Set defaults if not configured
	if tunnel.config.DomainSuffix == "" {
		tunnel.config.DomainSuffix = "example.com"
	}
	if len(tunnel.config.DNSServers) == 0 {
		tunnel.config.DNSServers = []string{"8.8.8.8:53", "1.1.1.1:53", "208.67.222.222:53"}
	}
	if len(tunnel.config.QueryTypes) == 0 {
		tunnel.config.QueryTypes = []string{"A", "AAAA", "TXT", "CNAME"}
	}
	if tunnel.config.EncodingMethod == "" {
		tunnel.config.EncodingMethod = "base32"
	}
	if tunnel.config.MaxPayloadSize == 0 {
		tunnel.config.MaxPayloadSize = 32 // Conservative size for DNS subdomain
	}
	if tunnel.config.QueryDelay == 0 {
		tunnel.config.QueryDelay = 100 * time.Millisecond
	}
	if tunnel.config.Subdomain == "" {
		tunnel.config.Subdomain = "api"
	}

	// Initialize encoding/decoding maps for custom DNS-safe encoding
	tunnel.initializeEncodingMaps()

	return tunnel, nil
}

func (d *DNSTunnel) initializeEncodingMaps() {
	// DNS-safe character set (lowercase letters and numbers only)
	dnsChars := "abcdefghijklmnopqrstuvwxyz0123456789"
	d.encodingMap = make(map[byte]string)
	d.decodingMap = make(map[string]byte)

	// Create 2-character encoding for each byte (base-36 like)
	for i := 0; i < 256; i++ {
		b := byte(i)
		first := dnsChars[i/36]
		second := dnsChars[i%36]
		encoded := string([]byte{first, second})
		d.encodingMap[b] = encoded
		d.decodingMap[encoded] = b
	}
}

func (d *DNSTunnel) Name() ObfuscationMethod {
	return MethodDNSTunnel
}

func (d *DNSTunnel) Obfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		d.updateMetrics(len(data), time.Since(start), nil)
	}()

	if !d.config.Enabled || len(data) == 0 {
		return data, nil
	}

	// Encode data using DNS tunneling protocol
	return d.encodeTosDNSQueries(data)
}

func (d *DNSTunnel) Deobfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		d.updateMetrics(len(data), time.Since(start), nil)
	}()

	if !d.config.Enabled || len(data) == 0 {
		return data, nil
	}

	// Decode DNS query responses back to original data
	return d.decodeFromDNSQueries(data)
}

func (d *DNSTunnel) WrapConn(conn net.Conn) (net.Conn, error) {
	return &dnsTunnelConn{
		Conn:   conn,
		tunnel: d,
	}, nil
}

func (d *DNSTunnel) IsAvailable() bool {
	return d.config.Enabled && len(d.config.DNSServers) > 0
}

func (d *DNSTunnel) GetMetrics() ObfuscatorMetrics {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.metrics
}

func (d *DNSTunnel) updateMetrics(dataSize int, processingTime time.Duration, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.metrics.PacketsProcessed++
	d.metrics.BytesProcessed += int64(dataSize)
	d.metrics.LastUsed = time.Now()

	if err != nil {
		d.metrics.Errors++
	}

	// Update average processing time
	if d.metrics.AvgProcessTime == 0 {
		d.metrics.AvgProcessTime = processingTime
	} else {
		d.metrics.AvgProcessTime = (d.metrics.AvgProcessTime + processingTime) / 2
	}
}

// encodeTosDNSQueries encodes VPN data into DNS query format
func (d *DNSTunnel) encodeTosDNSQueries(data []byte) ([]byte, error) {
	// Create DNS query packet structure with VPN data embedded
	encoded := d.encodeToDNSSafeString(data)

	// Split into chunks that fit in DNS subdomains (max 63 chars per label)
	chunks := d.splitIntoChunks(encoded, 60) // Leave some room for numbering

	var result []byte

	for i, chunk := range chunks {
		// Create a DNS query with VPN data in subdomain
		queryID := d.generateQueryID()
		subdomain := fmt.Sprintf("%s%02d%s", d.config.Subdomain, i, chunk)

		// Create a mock DNS query packet structure
		dnsQuery := d.createDNSQuery(queryID, subdomain)
		result = append(result, dnsQuery...)

		// Add sequence separator
		result = append(result, 0xFF, 0xFE) // DNS packet separator
	}

	return result, nil
}

// decodeFromDNSQueries decodes VPN data from DNS query format
func (d *DNSTunnel) decodeFromDNSQueries(data []byte) ([]byte, error) {
	// Parse DNS queries and extract VPN data from subdomains
	queries := d.parseDNSQueries(data)

	var encodedData string
	for _, query := range queries {
		// Extract data from subdomain
		if chunk := d.extractDataFromSubdomain(query); chunk != "" {
			encodedData += chunk
		}
	}

	// Decode from DNS-safe string back to original data
	return d.decodeFromDNSSafeString(encodedData)
}

// encodeToDNSSafeString converts bytes to DNS-safe string
func (d *DNSTunnel) encodeToDNSSafeString(data []byte) string {
	var result strings.Builder
	for _, b := range data {
		if encoded, exists := d.encodingMap[b]; exists {
			result.WriteString(encoded)
		}
	}
	return result.String()
}

// decodeFromDNSSafeString converts DNS-safe string back to bytes
func (d *DNSTunnel) decodeFromDNSSafeString(encoded string) ([]byte, error) {
	if len(encoded)%2 != 0 {
		return nil, fmt.Errorf("invalid encoded string length")
	}

	var result []byte
	for i := 0; i < len(encoded); i += 2 {
		chunk := encoded[i : i+2]
		if decoded, exists := d.decodingMap[chunk]; exists {
			result = append(result, decoded)
		} else {
			return nil, fmt.Errorf("invalid encoded chunk: %s", chunk)
		}
	}

	return result, nil
}

// splitIntoChunks splits string into chunks of specified size
func (d *DNSTunnel) splitIntoChunks(data string, chunkSize int) []string {
	var chunks []string
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks
}

// generateQueryID generates a unique query ID
func (d *DNSTunnel) generateQueryID() uint16 {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.queryCounter++
	return uint16(d.queryCounter)
}

// createDNSQuery creates a mock DNS query packet
func (d *DNSTunnel) createDNSQuery(queryID uint16, subdomain string) []byte {
	// Simplified DNS query packet structure
	// Header (12 bytes) + Question section
	query := make([]byte, 0, 512)

	// DNS Header
	query = append(query, byte(queryID>>8), byte(queryID)) // ID
	query = append(query, 0x01, 0x00)                      // Flags: standard query
	query = append(query, 0x00, 0x01)                      // Questions: 1
	query = append(query, 0x00, 0x00)                      // Answer RRs: 0
	query = append(query, 0x00, 0x00)                      // Authority RRs: 0
	query = append(query, 0x00, 0x00)                      // Additional RRs: 0

	// Question section: encode domain name
	fullDomain := subdomain + "." + d.config.DomainSuffix
	query = append(query, d.encodeDomainName(fullDomain)...)
	query = append(query, 0x00, 0x01) // Type: A
	query = append(query, 0x00, 0x01) // Class: IN

	return query
}

// encodeDomainName encodes domain name in DNS format
func (d *DNSTunnel) encodeDomainName(domain string) []byte {
	labels := strings.Split(domain, ".")
	var encoded []byte

	for _, label := range labels {
		if len(label) > 0 {
			encoded = append(encoded, byte(len(label)))
			encoded = append(encoded, []byte(label)...)
		}
	}
	encoded = append(encoded, 0x00) // Null terminator

	return encoded
}

// parseDNSQueries parses multiple DNS queries from data
func (d *DNSTunnel) parseDNSQueries(data []byte) []string {
	var queries []string

	// Split by DNS packet separator
	packets := d.splitBytesByPattern(data, []byte{0xFF, 0xFE})

	for _, packet := range packets {
		if len(packet) < 12 { // Minimum DNS header size
			continue
		}

		// Extract domain from question section
		if domain := d.extractDomainFromQuery(packet); domain != "" {
			queries = append(queries, domain)
		}
	}

	return queries
}

// splitBytesByPattern splits byte slice by pattern
func (d *DNSTunnel) splitBytesByPattern(data, pattern []byte) [][]byte {
	var result [][]byte
	start := 0

	for i := 0; i <= len(data)-len(pattern); i++ {
		if d.bytesEqual(data[i:i+len(pattern)], pattern) {
			if start < i {
				result = append(result, data[start:i])
			}
			start = i + len(pattern)
			i += len(pattern) - 1
		}
	}

	if start < len(data) {
		result = append(result, data[start:])
	}

	return result
}

// bytesEqual compares two byte slices
func (d *DNSTunnel) bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// extractDomainFromQuery extracts domain name from DNS query packet
func (d *DNSTunnel) extractDomainFromQuery(packet []byte) string {
	if len(packet) < 12 {
		return ""
	}

	// Skip DNS header (12 bytes)
	pos := 12
	domain := ""

	for pos < len(packet) {
		labelLen := int(packet[pos])
		if labelLen == 0 {
			break
		}

		pos++
		if pos+labelLen > len(packet) {
			break
		}

		if domain != "" {
			domain += "."
		}
		domain += string(packet[pos : pos+labelLen])
		pos += labelLen
	}

	return domain
}

// extractDataFromSubdomain extracts VPN data from DNS subdomain
func (d *DNSTunnel) extractDataFromSubdomain(domain string) string {
	// Remove domain suffix
	if !strings.HasSuffix(domain, "."+d.config.DomainSuffix) {
		return ""
	}

	subdomain := strings.TrimSuffix(domain, "."+d.config.DomainSuffix)

	// Remove API prefix and sequence number (first 5 characters)
	if len(subdomain) <= 5 || !strings.HasPrefix(subdomain, d.config.Subdomain) {
		return ""
	}

	// Extract data part (skip api + 2 digit sequence number)
	datapart := subdomain[len(d.config.Subdomain)+2:]
	return datapart
}

// dnsTunnelConn wraps a connection with DNS tunneling
type dnsTunnelConn struct {
	net.Conn
	tunnel *DNSTunnel
}

func (c *dnsTunnelConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err != nil || n == 0 {
		return n, err
	}

	// Add DNS tunneling delay to simulate real DNS queries
	time.Sleep(c.tunnel.config.QueryDelay)

	deobfuscated, deobfErr := c.tunnel.Deobfuscate(b[:n])
	if deobfErr != nil {
		return n, deobfErr
	}

	copy(b, deobfuscated)
	return len(deobfuscated), nil
}

func (c *dnsTunnelConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	// Add DNS tunneling delay to simulate real DNS queries
	time.Sleep(c.tunnel.config.QueryDelay)

	obfuscated, obfErr := c.tunnel.Obfuscate(b)
	if obfErr != nil {
		return 0, obfErr
	}

	_, err = c.Conn.Write(obfuscated)
	if err != nil {
		return 0, err
	}

	// Return the number of original bytes written
	return len(b), nil
}

// PacketPadding packet size randomization obfuscator
type PacketPadding struct {
	config  *PacketPaddingConfig
	metrics ObfuscatorMetrics
	mu      sync.RWMutex
	logger  *log.Logger
}

func NewPacketPadding(config *PacketPaddingConfig, logger *log.Logger) (Obfuscator, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	if config == nil {
		config = &PacketPaddingConfig{
			Enabled:       true,
			MinPadding:    1,
			MaxPadding:    256,
			RandomizeSize: true,
		}
	}

	// Set defaults if not configured
	if config.MinPadding <= 0 {
		config.MinPadding = 1
	}
	if config.MaxPadding <= 0 {
		config.MaxPadding = 256
	}
	if config.MinPadding > config.MaxPadding {
		config.MinPadding, config.MaxPadding = config.MaxPadding, config.MinPadding
	}

	return &PacketPadding{
		config: config,
		logger: logger,
	}, nil
}

func (p *PacketPadding) Name() ObfuscationMethod {
	return MethodPacketPadding
}

func (p *PacketPadding) Obfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		p.updateMetrics(len(data), time.Since(start), nil)
	}()

	if !p.config.Enabled || len(data) == 0 {
		return data, nil
	}

	// Calculate padding size
	paddingSize := p.config.MinPadding
	if p.config.RandomizeSize && p.config.MaxPadding > p.config.MinPadding {
		paddingRange := p.config.MaxPadding - p.config.MinPadding
		paddingSize = p.config.MinPadding + mathrand.Intn(paddingRange+1)
	}

	// Create padded data
	result := make([]byte, len(data)+paddingSize+4) // +4 for padding length header

	// Write original data length (first 4 bytes)
	result[0] = byte(len(data) >> 24)
	result[1] = byte(len(data) >> 16)
	result[2] = byte(len(data) >> 8)
	result[3] = byte(len(data))

	// Copy original data
	copy(result[4:4+len(data)], data)

	// Add random padding
	if paddingSize > 0 {
		_, err := rand.Read(result[4+len(data):])
		if err != nil {
			p.logger.Printf("Failed to generate random padding: %v", err)
			// Fallback to zero padding
			for i := 4 + len(data); i < len(result); i++ {
				result[i] = 0
			}
		}
	}

	return result, nil
}

func (p *PacketPadding) Deobfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		p.updateMetrics(len(data), time.Since(start), nil)
	}()

	if !p.config.Enabled || len(data) < 4 {
		return data, nil
	}

	// Read original data length from header
	originalLength := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])

	// Validate length
	if originalLength < 0 || originalLength > len(data)-4 {
		return data, fmt.Errorf("invalid data length in packet padding header: %d", originalLength)
	}

	// Extract original data
	result := make([]byte, originalLength)
	copy(result, data[4:4+originalLength])

	return result, nil
}

func (p *PacketPadding) WrapConn(conn net.Conn) (net.Conn, error) {
	return &packetPaddingConn{
		Conn:    conn,
		padding: p,
	}, nil
}

func (p *PacketPadding) IsAvailable() bool {
	return p.config.Enabled
}

func (p *PacketPadding) GetMetrics() ObfuscatorMetrics {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.metrics
}

func (p *PacketPadding) updateMetrics(dataSize int, processingTime time.Duration, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.metrics.PacketsProcessed++
	p.metrics.BytesProcessed += int64(dataSize)
	p.metrics.LastUsed = time.Now()

	if err != nil {
		p.metrics.Errors++
	}

	// Update average processing time
	if p.metrics.AvgProcessTime == 0 {
		p.metrics.AvgProcessTime = processingTime
	} else {
		p.metrics.AvgProcessTime = (p.metrics.AvgProcessTime + processingTime) / 2
	}
}

// packetPaddingConn wraps a connection with packet padding
type packetPaddingConn struct {
	net.Conn
	padding *PacketPadding
}

func (c *packetPaddingConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err != nil || n == 0 {
		return n, err
	}

	deobfuscated, deobfErr := c.padding.Deobfuscate(b[:n])
	if deobfErr != nil {
		return n, deobfErr
	}

	copy(b, deobfuscated)
	return len(deobfuscated), nil
}

func (c *packetPaddingConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	obfuscated, obfErr := c.padding.Obfuscate(b)
	if obfErr != nil {
		return 0, obfErr
	}

	_, err = c.Conn.Write(obfuscated)
	if err != nil {
		return 0, err
	}

	// Return the number of original bytes written
	return len(b), nil
}

// TimingObfuscation introduces random delays between packets to obfuscate timing patterns
type TimingObfuscation struct {
	config  *TimingObfsConfig
	metrics ObfuscatorMetrics
	mu      sync.RWMutex
	logger  *log.Logger
}

func NewTimingObfuscation(config *TimingObfsConfig, logger *log.Logger) (Obfuscator, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	if config == nil {
		config = &TimingObfsConfig{
			Enabled:      true,
			MinDelay:     1 * time.Millisecond,
			MaxDelay:     50 * time.Millisecond,
			RandomJitter: true,
		}
	}

	// Set defaults if not configured
	if config.MinDelay <= 0 {
		config.MinDelay = 1 * time.Millisecond
	}
	if config.MaxDelay <= 0 {
		config.MaxDelay = 50 * time.Millisecond
	}
	if config.MinDelay > config.MaxDelay {
		config.MinDelay, config.MaxDelay = config.MaxDelay, config.MinDelay
	}

	return &TimingObfuscation{
		config: config,
		logger: logger,
	}, nil
}

func (t *TimingObfuscation) Name() ObfuscationMethod {
	return MethodTimingObfs
}

func (t *TimingObfuscation) Obfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		t.updateMetrics(len(data), time.Since(start), nil)
	}()

	if !t.config.Enabled || len(data) == 0 {
		return data, nil
	}

	// Apply timing delay
	delay := t.calculateDelay()
	if delay > 0 {
		time.Sleep(delay)
	}

	// Return data unchanged - timing obfuscation doesn't modify data
	return data, nil
}

func (t *TimingObfuscation) Deobfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		t.updateMetrics(len(data), time.Since(start), nil)
	}()

	// Timing obfuscation doesn't modify data, so deobfuscation just returns the data
	return data, nil
}

func (t *TimingObfuscation) WrapConn(conn net.Conn) (net.Conn, error) {
	return &timingObfuscationConn{
		Conn:   conn,
		timing: t,
	}, nil
}

func (t *TimingObfuscation) IsAvailable() bool {
	return t.config.Enabled
}

func (t *TimingObfuscation) GetMetrics() ObfuscatorMetrics {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.metrics
}

func (t *TimingObfuscation) updateMetrics(dataSize int, processingTime time.Duration, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.metrics.PacketsProcessed++
	t.metrics.BytesProcessed += int64(dataSize)
	t.metrics.LastUsed = time.Now()

	if err != nil {
		t.metrics.Errors++
	}

	// Update average processing time
	if t.metrics.AvgProcessTime == 0 {
		t.metrics.AvgProcessTime = processingTime
	} else {
		t.metrics.AvgProcessTime = (t.metrics.AvgProcessTime + processingTime) / 2
	}
}

// calculateDelay calculates the delay to apply based on configuration
func (t *TimingObfuscation) calculateDelay() time.Duration {
	if !t.config.RandomJitter {
		// Use fixed maximum delay
		return t.config.MaxDelay
	}

	// Calculate random delay between min and max
	delayRange := t.config.MaxDelay - t.config.MinDelay
	if delayRange <= 0 {
		return t.config.MinDelay
	}

	// Use exponential distribution for more realistic timing patterns
	// This creates more natural-looking traffic timing
	randomFactor := mathrand.ExpFloat64()
	if randomFactor > 3.0 { // Cap the exponential distribution
		randomFactor = 3.0
	}

	// Scale to our delay range
	delay := t.config.MinDelay + time.Duration(float64(delayRange)*randomFactor/3.0)

	// Ensure we don't exceed maximum delay
	if delay > t.config.MaxDelay {
		delay = t.config.MaxDelay
	}

	return delay
}

// timingObfuscationConn wraps a connection with timing obfuscation
type timingObfuscationConn struct {
	net.Conn
	timing *TimingObfuscation
}

func (c *timingObfuscationConn) Read(b []byte) (n int, err error) {
	// Apply timing delay before reading
	if c.timing.config.Enabled {
		delay := c.timing.calculateDelay()
		if delay > 0 {
			time.Sleep(delay)
		}
	}

	return c.Conn.Read(b)
}

func (c *timingObfuscationConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	// Apply timing delay before writing
	if c.timing.config.Enabled {
		delay := c.timing.calculateDelay()
		if delay > 0 {
			time.Sleep(delay)
		}
	}

	return c.Conn.Write(b)
}

// TrafficPadding adds dummy traffic between real packets to mask traffic patterns
type TrafficPadding struct {
	config       *TrafficPaddingConfig
	metrics      ObfuscatorMetrics
	mu           sync.RWMutex
	logger       *log.Logger
	stopChannel  chan struct{}
	isActive     bool
	lastActivity time.Time
}

func NewTrafficPadding(config *TrafficPaddingConfig, logger *log.Logger) (Obfuscator, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	if config == nil {
		config = &TrafficPaddingConfig{
			Enabled:      true,
			MinInterval:  100 * time.Millisecond,
			MaxInterval:  2 * time.Second,
			MinDummySize: 64,
			MaxDummySize: 1024,
			BurstMode:    false,
			BurstSize:    3,
			AdaptiveMode: true,
		}
	}

	// Set defaults if not configured
	if config.MinInterval <= 0 {
		config.MinInterval = 100 * time.Millisecond
	}
	if config.MaxInterval <= 0 {
		config.MaxInterval = 2 * time.Second
	}
	if config.MinInterval > config.MaxInterval {
		config.MinInterval, config.MaxInterval = config.MaxInterval, config.MinInterval
	}
	if config.MinDummySize <= 0 {
		config.MinDummySize = 64
	}
	if config.MaxDummySize <= 0 {
		config.MaxDummySize = 1024
	}
	if config.MinDummySize > config.MaxDummySize {
		config.MinDummySize, config.MaxDummySize = config.MaxDummySize, config.MinDummySize
	}
	if config.BurstSize <= 0 {
		config.BurstSize = 3
	}

	return &TrafficPadding{
		config:       config,
		logger:       logger,
		stopChannel:  make(chan struct{}),
		isActive:     false,
		lastActivity: time.Now(),
	}, nil
}

func (tp *TrafficPadding) Name() ObfuscationMethod {
	return MethodTrafficPadding
}

func (tp *TrafficPadding) Obfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		tp.updateMetrics(len(data), time.Since(start), nil)
	}()

	if !tp.config.Enabled || len(data) == 0 {
		return data, nil
	}

	// Update last activity time
	tp.mu.Lock()
	tp.lastActivity = time.Now()
	tp.mu.Unlock()

	// Traffic padding doesn't modify the data, just injects dummy traffic
	// The dummy traffic injection happens in the connection wrapper
	return data, nil
}

func (tp *TrafficPadding) Deobfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		tp.updateMetrics(len(data), time.Since(start), nil)
	}()

	// Check if this is a dummy packet by examining a magic header
	if len(data) >= 8 && string(data[:8]) == "DUMMY_TP" {
		// This is a dummy packet, return empty data
		return []byte{}, nil
	}

	// Return original data (real traffic)
	return data, nil
}

func (tp *TrafficPadding) WrapConn(conn net.Conn) (net.Conn, error) {
	wrappedConn := &trafficPaddingConn{
		Conn:    conn,
		padding: tp,
		buffer:  make(chan []byte, 100), // Buffer for dummy packets
	}

	// Start dummy traffic generation if enabled
	if tp.config.Enabled {
		go wrappedConn.startDummyTrafficGenerator()
	}

	return wrappedConn, nil
}

func (tp *TrafficPadding) IsAvailable() bool {
	return tp.config.Enabled
}

func (tp *TrafficPadding) GetMetrics() ObfuscatorMetrics {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return tp.metrics
}

func (tp *TrafficPadding) updateMetrics(dataSize int, processingTime time.Duration, err error) {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	tp.metrics.PacketsProcessed++
	tp.metrics.BytesProcessed += int64(dataSize)
	tp.metrics.LastUsed = time.Now()

	if err != nil {
		tp.metrics.Errors++
	}

	// Update average processing time
	if tp.metrics.AvgProcessTime == 0 {
		tp.metrics.AvgProcessTime = processingTime
	} else {
		tp.metrics.AvgProcessTime = (tp.metrics.AvgProcessTime + processingTime) / 2
	}
}

// generateDummyPacket creates a dummy packet for traffic padding
func (tp *TrafficPadding) generateDummyPacket() []byte {
	// Calculate dummy packet size
	dummySize := tp.config.MinDummySize
	if tp.config.MaxDummySize > tp.config.MinDummySize {
		sizeRange := tp.config.MaxDummySize - tp.config.MinDummySize
		dummySize = tp.config.MinDummySize + mathrand.Intn(sizeRange+1)
	}

	// Create dummy packet with magic header
	dummy := make([]byte, dummySize)
	copy(dummy[:8], []byte("DUMMY_TP"))

	// Fill rest with random data
	if len(dummy) > 8 {
		_, err := rand.Read(dummy[8:])
		if err != nil {
			// Fallback to simple pattern if random generation fails
			for i := 8; i < len(dummy); i++ {
				dummy[i] = byte(i % 256)
			}
		}
	}

	return dummy
}

// calculateInterval calculates the next interval for dummy packet injection
func (tp *TrafficPadding) calculateInterval() time.Duration {
	if tp.config.MinInterval == tp.config.MaxInterval {
		return tp.config.MaxInterval
	}

	intervalRange := tp.config.MaxInterval - tp.config.MinInterval
	randomOffset := time.Duration(mathrand.Int63n(int64(intervalRange)))

	interval := tp.config.MinInterval + randomOffset

	// Apply adaptive mode - reduce interval during low activity
	if tp.config.AdaptiveMode {
		tp.mu.RLock()
		timeSinceActivity := time.Since(tp.lastActivity)
		tp.mu.RUnlock()

		// If no activity for a while, reduce interval to maintain cover traffic
		if timeSinceActivity > 5*time.Second {
			interval = interval / 2
		}
	}

	return interval
}

// trafficPaddingConn wraps a connection with traffic padding capabilities
type trafficPaddingConn struct {
	net.Conn
	padding *TrafficPadding
	buffer  chan []byte
	mu      sync.Mutex
}

func (c *trafficPaddingConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err != nil || n == 0 {
		return n, err
	}

	// Update activity time
	c.padding.mu.Lock()
	c.padding.lastActivity = time.Now()
	c.padding.mu.Unlock()

	// Check if this is a dummy packet
	deobfuscated, deobfErr := c.padding.Deobfuscate(b[:n])
	if deobfErr != nil {
		return n, deobfErr
	}

	// If it's a dummy packet (empty result), read the next packet
	if len(deobfuscated) == 0 {
		// This was a dummy packet, read the next one
		return c.Read(b)
	}

	// Copy real data back
	copy(b, deobfuscated)
	return len(deobfuscated), nil
}

func (c *trafficPaddingConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	// Update activity time
	c.padding.mu.Lock()
	c.padding.lastActivity = time.Now()
	c.padding.mu.Unlock()

	// Write real data
	return c.Conn.Write(b)
}

func (c *trafficPaddingConn) Close() error {
	// Signal dummy traffic generator to stop
	select {
	case c.padding.stopChannel <- struct{}{}:
	default:
	}
	return c.Conn.Close()
}

// startDummyTrafficGenerator starts generating dummy traffic in the background
func (c *trafficPaddingConn) startDummyTrafficGenerator() {
	if !c.padding.config.Enabled {
		return
	}

	c.padding.logger.Printf("Starting traffic padding generator")

	for {
		// Calculate next interval
		interval := c.padding.calculateInterval()

		select {
		case <-c.padding.stopChannel:
			c.padding.logger.Printf("Stopping traffic padding generator")
			return
		case <-time.After(interval):
			// Generate and send dummy traffic
			c.generateAndSendDummy()
		}
	}
}

// generateAndSendDummy generates and sends dummy packets
func (c *trafficPaddingConn) generateAndSendDummy() {
	if !c.padding.config.Enabled {
		return
	}

	packetsToSend := 1
	if c.padding.config.BurstMode {
		packetsToSend = 1 + mathrand.Intn(c.padding.config.BurstSize)
	}

	for i := 0; i < packetsToSend; i++ {
		dummyPacket := c.padding.generateDummyPacket()

		// Try to send dummy packet (non-blocking)
		go func(packet []byte) {
			c.mu.Lock()
			defer c.mu.Unlock()

			_, err := c.Conn.Write(packet)
			if err != nil {
				// Log error but don't fail - dummy traffic is best effort
				c.padding.logger.Printf("Failed to send dummy packet: %v", err)
			}
		}(dummyPacket)

		// Small delay between burst packets
		if i < packetsToSend-1 && c.padding.config.BurstMode {
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// FlowWatermark adds hidden watermarks to traffic flow to distort statistical characteristics
type FlowWatermark struct {
	config          *FlowWatermarkConfig
	metrics         ObfuscatorMetrics
	mu              sync.RWMutex
	logger          *log.Logger
	watermarkSeq    []byte
	currentPattern  []float64
	patternIndex    int
	lastRotation    time.Time
	rng             *mathrand.Rand
	frequencyFilter map[int]float64
}

func NewFlowWatermark(config *FlowWatermarkConfig, logger *log.Logger) (Obfuscator, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	if config == nil {
		config = &FlowWatermarkConfig{
			Enabled:         true,
			WatermarkKey:    nil,
			PatternInterval: 500 * time.Millisecond,
			PatternStrength: 0.3,
			NoiseLevel:      0.1,
			RotationPeriod:  5 * time.Minute,
			StatisticalMode: true,
			FrequencyBands:  []int{1, 2, 5, 10, 20, 50},
		}
	}

	// Set defaults if not configured
	if config.PatternInterval <= 0 {
		config.PatternInterval = 500 * time.Millisecond
	}
	if config.PatternStrength <= 0 || config.PatternStrength > 1.0 {
		config.PatternStrength = 0.3
	}
	if config.NoiseLevel < 0 || config.NoiseLevel > 1.0 {
		config.NoiseLevel = 0.1
	}
	if config.RotationPeriod <= 0 {
		config.RotationPeriod = 5 * time.Minute
	}
	if len(config.FrequencyBands) == 0 {
		config.FrequencyBands = []int{1, 2, 5, 10, 20, 50}
	}

	// Generate watermark key if not provided
	if len(config.WatermarkKey) == 0 {
		config.WatermarkKey = make([]byte, 32)
		if _, err := rand.Read(config.WatermarkKey); err != nil {
			return nil, fmt.Errorf("failed to generate watermark key: %w", err)
		}
	}

	fw := &FlowWatermark{
		config:          config,
		logger:          logger,
		lastRotation:    time.Now(),
		rng:             mathrand.New(mathrand.NewSource(time.Now().UnixNano())),
		frequencyFilter: make(map[int]float64),
	}

	// Initialize frequency filters
	for _, band := range config.FrequencyBands {
		fw.frequencyFilter[band] = fw.rng.Float64()
	}

	// Generate initial watermark sequence
	fw.generateWatermarkSequence()
	fw.generateWatermarkPattern()

	return fw, nil
}

func (fw *FlowWatermark) Name() ObfuscationMethod {
	return MethodFlowWatermark
}

func (fw *FlowWatermark) Obfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		fw.updateMetrics(len(data), time.Since(start), nil)
	}()

	if !fw.config.Enabled || len(data) == 0 {
		return data, nil
	}

	// Check if watermark pattern needs rotation
	fw.checkPatternRotation()

	// Apply flow watermarking - this modifies statistical characteristics
	// without changing the actual data content significantly
	watermarkedData := fw.applyWatermark(data)

	return watermarkedData, nil
}

func (fw *FlowWatermark) Deobfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		fw.updateMetrics(len(data), time.Since(start), nil)
	}()

	if !fw.config.Enabled || len(data) == 0 {
		return data, nil
	}

	// Remove watermark patterns to restore original data
	originalData := fw.removeWatermark(data)

	return originalData, nil
}

func (fw *FlowWatermark) WrapConn(conn net.Conn) (net.Conn, error) {
	return &flowWatermarkConn{
		Conn:      conn,
		watermark: fw,
		flowState: make(map[string]interface{}),
	}, nil
}

func (fw *FlowWatermark) IsAvailable() bool {
	return fw.config.Enabled
}

func (fw *FlowWatermark) GetMetrics() ObfuscatorMetrics {
	fw.mu.RLock()
	defer fw.mu.RUnlock()
	return fw.metrics
}

func (fw *FlowWatermark) updateMetrics(dataSize int, processingTime time.Duration, err error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	fw.metrics.PacketsProcessed++
	fw.metrics.BytesProcessed += int64(dataSize)
	fw.metrics.LastUsed = time.Now()

	if err != nil {
		fw.metrics.Errors++
	}

	// Update average processing time
	if fw.metrics.AvgProcessTime == 0 {
		fw.metrics.AvgProcessTime = processingTime
	} else {
		fw.metrics.AvgProcessTime = (fw.metrics.AvgProcessTime + processingTime) / 2
	}
}

// generateWatermarkSequence creates a unique watermark sequence based on the key
func (fw *FlowWatermark) generateWatermarkSequence() {
	// Use watermark key to seed deterministic sequence
	keySum := int64(0)
	for _, b := range fw.config.WatermarkKey {
		keySum += int64(b)
	}

	seqRng := mathrand.New(mathrand.NewSource(keySum))
	fw.watermarkSeq = make([]byte, 256)

	for i := range fw.watermarkSeq {
		fw.watermarkSeq[i] = byte(seqRng.Intn(256))
	}
}

// generateWatermarkPattern creates statistical patterns for flow distortion
func (fw *FlowWatermark) generateWatermarkPattern() {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	patternLength := len(fw.config.FrequencyBands) * 8
	fw.currentPattern = make([]float64, patternLength)

	for i := range fw.currentPattern {
		// Generate pattern based on frequency bands and watermark key
		keyIndex := i % len(fw.config.WatermarkKey)
		keyVal := float64(fw.config.WatermarkKey[keyIndex]) / 255.0

		// Create pattern with key-based scaling
		frequency := float64(fw.config.FrequencyBands[i%len(fw.config.FrequencyBands)])

		pattern := fw.config.PatternStrength * (0.5 + 0.5*mathrand.Float64()*keyVal)
		pattern *= (0.5 + 0.5*mathrand.Float64()*frequency/100.0)    // Frequency scaling
		pattern += fw.config.NoiseLevel * (mathrand.Float64() - 0.5) // Add noise

		fw.currentPattern[i] = pattern
	}

	fw.patternIndex = 0
}

// checkPatternRotation rotates watermark patterns periodically
func (fw *FlowWatermark) checkPatternRotation() {
	if time.Since(fw.lastRotation) > fw.config.RotationPeriod {
		fw.logger.Printf("Rotating flow watermark pattern")
		fw.generateWatermarkPattern()
		fw.lastRotation = time.Now()

		// Rotate frequency filters as well
		for band := range fw.frequencyFilter {
			fw.frequencyFilter[band] = fw.rng.Float64()
		}
	}
}

// applyWatermark applies statistical watermark to data
func (fw *FlowWatermark) applyWatermark(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	fw.mu.Lock()
	defer fw.mu.Unlock()

	// Apply watermark pattern to statistical characteristics
	for i, b := range result {
		if fw.config.StatisticalMode {
			// Use deterministic pattern index based on data position and watermark key
			// This ensures consistent obfuscation/deobfuscation
			patternIdx := (i + int(fw.watermarkSeq[i%len(fw.watermarkSeq)])) % len(fw.currentPattern)
			patternVal := fw.currentPattern[patternIdx]

			// Calculate watermark adjustment
			seqIdx := i % len(fw.watermarkSeq)
			watermarkByte := fw.watermarkSeq[seqIdx]

			// Apply subtle pattern-based modification
			adjustment := int(patternVal * float64(watermarkByte) / 255.0 * 16)
			adjustment -= 8 // Center around 0

			// Apply adjustment with wrapping
			newVal := int(b) + adjustment
			if newVal < 0 {
				newVal += 256
			}
			if newVal > 255 {
				newVal -= 256
			}

			result[i] = byte(newVal)
		} else {
			// Apply simple XOR-based watermark
			seqIdx := i % len(fw.watermarkSeq)
			result[i] = b ^ fw.watermarkSeq[seqIdx]
		}
	}

	return result
}

// removeWatermark removes statistical watermark from data
func (fw *FlowWatermark) removeWatermark(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	result := make([]byte, len(data))
	copy(result, data)

	fw.mu.Lock()
	defer fw.mu.Unlock()

	// Remove watermark pattern (reverse operation)
	for i, b := range result {
		if fw.config.StatisticalMode {
			// Use the same deterministic pattern index as in applyWatermark
			patternIdx := (i + int(fw.watermarkSeq[i%len(fw.watermarkSeq)])) % len(fw.currentPattern)
			patternVal := fw.currentPattern[patternIdx]

			seqIdx := i % len(fw.watermarkSeq)
			watermarkByte := fw.watermarkSeq[seqIdx]

			// Reverse pattern-based modification
			adjustment := int(patternVal * float64(watermarkByte) / 255.0 * 16)
			adjustment -= 8 // Center around 0

			// Reverse adjustment with wrapping
			newVal := int(b) - adjustment
			if newVal < 0 {
				newVal += 256
			}
			if newVal > 255 {
				newVal -= 256
			}

			result[i] = byte(newVal)
		} else {
			// Reverse simple XOR-based watermark
			seqIdx := i % len(fw.watermarkSeq)
			result[i] = b ^ fw.watermarkSeq[seqIdx]
		}
	}

	return result
}

// flowWatermarkConn wraps a connection with flow watermarking capabilities
type flowWatermarkConn struct {
	net.Conn
	watermark *FlowWatermark
	flowState map[string]interface{}
}

func (c *flowWatermarkConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err != nil || n == 0 {
		return n, err
	}

	// Apply watermark removal to incoming data
	deobfuscated, deobfErr := c.watermark.Deobfuscate(b[:n])
	if deobfErr != nil {
		return n, deobfErr
	}

	copy(b, deobfuscated)
	return len(deobfuscated), nil
}

func (c *flowWatermarkConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	// Apply watermark to outgoing data
	obfuscated, obfErr := c.watermark.Obfuscate(b)
	if obfErr != nil {
		return 0, obfErr
	}

	_, err = c.Conn.Write(obfuscated)
	if err != nil {
		return 0, err
	}

	// Return the number of original bytes written
	return len(b), nil
}

// HTTPSteganography hides VPN data within HTTP traffic using steganographic techniques
type HTTPSteganography struct {
	config     *HTTPStegoConfig
	metrics    ObfuscatorMetrics
	mu         sync.RWMutex
	logger     *log.Logger
	imagePool  [][]byte
	scriptPool [][]byte
	contentDB  map[string][]byte
	sessionID  string
	currentSeq uint32
}

type HTTPStegoConfig struct {
	Enabled        bool              `json:"enabled"`
	CoverWebsites  []string          `json:"cover_websites"`
	UserAgents     []string          `json:"user_agents"`
	ContentTypes   []string          `json:"content_types"`
	CustomHeaders  map[string]string `json:"custom_headers"`
	SteganoMethod  string            `json:"stegano_method"`
	ChunkSize      int               `json:"chunk_size"`
	ErrorRate      float64           `json:"error_rate"`
	SessionTimeout time.Duration     `json:"session_timeout"`
	EnableMIME     bool              `json:"enable_mime"`
	CachingEnabled bool              `json:"caching_enabled"`
}

func NewHTTPSteganography(config *HTTPStegoConfig, logger *log.Logger) (Obfuscator, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	if config == nil {
		config = &HTTPStegoConfig{
			Enabled: true,
		}
	}

	stego := &HTTPSteganography{
		config:    config,
		logger:    logger,
		contentDB: make(map[string][]byte),
		sessionID: fmt.Sprintf("sess_%d", time.Now().Unix()),
	}

	// Set defaults
	if len(stego.config.CoverWebsites) == 0 {
		stego.config.CoverWebsites = []string{
			"www.google.com",
			"www.github.com",
			"stackoverflow.com",
			"www.reddit.com",
			"news.ycombinator.com",
			"www.wikipedia.org",
		}
	}

	if len(stego.config.UserAgents) == 0 {
		stego.config.UserAgents = []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
		}
	}

	if len(stego.config.ContentTypes) == 0 {
		stego.config.ContentTypes = []string{
			"text/html",
			"application/javascript",
			"text/css",
			"application/json",
			"text/plain",
			"image/png",
			"image/jpeg",
		}
	}

	if stego.config.SteganoMethod == "" {
		stego.config.SteganoMethod = "headers_and_body"
	}

	if stego.config.ChunkSize <= 0 {
		stego.config.ChunkSize = 1024
	}

	if stego.config.ErrorRate <= 0 {
		stego.config.ErrorRate = 0.02 // 2% error rate for realism
	}

	if stego.config.SessionTimeout <= 0 {
		stego.config.SessionTimeout = 30 * time.Minute
	}

	// Initialize cover content pools
	stego.initializeCoverContent()

	return stego, nil
}

func (h *HTTPSteganography) Name() ObfuscationMethod {
	return MethodHTTPStego
}

func (h *HTTPSteganography) Obfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		h.updateMetrics(len(data), time.Since(start), nil)
	}()

	if !h.config.Enabled || len(data) == 0 {
		return data, nil
	}

	// Create steganographic HTTP traffic containing VPN data
	return h.createSteganographicHTTP(data)
}

func (h *HTTPSteganography) Deobfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		h.updateMetrics(len(data), time.Since(start), nil)
	}()

	if !h.config.Enabled || len(data) == 0 {
		return data, nil
	}

	// Extract VPN data from steganographic HTTP traffic
	return h.extractFromSteganographicHTTP(data)
}

func (h *HTTPSteganography) WrapConn(conn net.Conn) (net.Conn, error) {
	return &httpSteganographyConn{
		Conn:  conn,
		stego: h,
	}, nil
}

func (h *HTTPSteganography) IsAvailable() bool {
	return h.config.Enabled
}

func (h *HTTPSteganography) GetMetrics() ObfuscatorMetrics {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.metrics
}

func (h *HTTPSteganography) updateMetrics(dataSize int, processingTime time.Duration, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.metrics.PacketsProcessed++
	h.metrics.BytesProcessed += int64(dataSize)
	h.metrics.LastUsed = time.Now()

	if err != nil {
		h.metrics.Errors++
	}

	if h.metrics.AvgProcessTime == 0 {
		h.metrics.AvgProcessTime = processingTime
	} else {
		h.metrics.AvgProcessTime = (h.metrics.AvgProcessTime + processingTime) / 2
	}
}

// initializeCoverContent initializes pools of realistic cover content
func (h *HTTPSteganography) initializeCoverContent() {
	// Initialize image pool with realistic PNG/JPEG headers
	h.imagePool = [][]byte{
		// PNG header + some data
		{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52},
		// JPEG header + some data
		{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x48},
	}

	// Initialize script pool with realistic JavaScript/CSS fragments
	h.scriptPool = [][]byte{
		[]byte("function initApp(){document.addEventListener('DOMContentLoaded',function(){console.log('App initialized');});"),
		[]byte("var config={apiUrl:'https://api.example.com',timeout:5000,retries:3};window.appConfig=config;"),
		[]byte("body{margin:0;padding:20px;font-family:'Arial',sans-serif;background-color:#f5f5f5;}"),
		[]byte(".container{max-width:1200px;margin:0 auto;padding:0 15px;box-sizing:border-box;}"),
	}

	// Initialize content database with realistic web content
	h.contentDB["html_template"] = []byte(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Loading...</title>
    <style>body{font-family:Arial,sans-serif;margin:40px;}</style>
</head>
<body>
    <div id="content">
        <h1>Content Loading</h1>
        <p>Please wait while we load your content...</p>
        <div class="loader" data-id="{{SESSION_ID}}">Loading...</div>
    </div>
    <script>
        setTimeout(function(){
            document.getElementById('content').innerHTML = '<h2>Content Ready</h2>';
        }, {{DELAY}});
    </script>
</body>
</html>`)

	h.contentDB["json_template"] = []byte(`{
	"status": "success",
	"data": {
		"session": "{{SESSION_ID}}",
		"timestamp": {{TIMESTAMP}},
		"payload": "{{PAYLOAD}}",
		"metadata": {
			"size": {{SIZE}},
			"encoding": "base64",
			"checksum": "{{CHECKSUM}}"
		}
	}
}`)

	h.contentDB["css_template"] = []byte(`/* Stylesheet v1.0 */
.main-container {
	width: 100%;
	max-width: 1200px;
	margin: 0 auto;
	padding: 20px;
	/* data: {{PAYLOAD}} */
	box-sizing: border-box;
}

.header {
	background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
	/* session: {{SESSION_ID}} */
	color: white;
	padding: 30px 0;
	text-align: center;
	border-radius: 8px;
}`)

	h.contentDB["js_template"] = []byte(`// Application Module v2.1
(function(window) {
	'use strict';
	
	var app = {
		version: '2.1.0',
		session: '{{SESSION_ID}}',
		config: {
			// Embedded data: {{PAYLOAD}}
			apiEndpoint: 'https://api.example.com/v1',
			timeout: 5000,
			retries: 3,
			// checksum: {{CHECKSUM}}
		},
		
		init: function() {
			this.setupEventListeners();
			this.loadData();
		},
		
		loadData: function() {
			// Data loading logic here
			console.log('Data loaded for session:', this.session);
		}
	};
	
	window.App = app;
})(window);`)
}

// createSteganographicHTTP creates HTTP traffic with hidden VPN data
func (h *HTTPSteganography) createSteganographicHTTP(vpnData []byte) ([]byte, error) {
	switch h.config.SteganoMethod {
	case "headers_and_body":
		return h.createHeadersAndBodyStego(vpnData)
	case "multipart_forms":
		return h.createMultipartFormStego(vpnData)
	case "json_api":
		return h.createJSONAPIStego(vpnData)
	case "css_comments":
		return h.createCSSCommentsStego(vpnData)
	case "js_variables":
		return h.createJSVariablesStego(vpnData)
	default:
		return h.createHeadersAndBodyStego(vpnData)
	}
}

// extractFromSteganographicHTTP extracts VPN data from HTTP traffic
func (h *HTTPSteganography) extractFromSteganographicHTTP(httpData []byte) ([]byte, error) {
	switch h.config.SteganoMethod {
	case "headers_and_body":
		return h.extractFromHeadersAndBody(httpData)
	case "multipart_forms":
		return h.extractFromMultipartForm(httpData)
	case "json_api":
		return h.extractFromJSONAPI(httpData)
	case "css_comments":
		return h.extractFromCSSComments(httpData)
	case "js_variables":
		return h.extractFromJSVariables(httpData)
	default:
		return h.extractFromHeadersAndBody(httpData)
	}
}

// createHeadersAndBodyStego embeds VPN data in HTTP headers and body
func (h *HTTPSteganography) createHeadersAndBodyStego(vpnData []byte) ([]byte, error) {
	// Encode VPN data as base64 for header embedding
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(vpnData)))
	base64.StdEncoding.Encode(encoded, vpnData)

	// Split encoded data into chunks for different headers
	chunkSize := 64 // Max header value size
	var headerChunks []string
	for i := 0; i < len(encoded); i += chunkSize {
		end := i + chunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		headerChunks = append(headerChunks, string(encoded[i:end]))
	}

	// Select random website and user agent
	website := h.config.CoverWebsites[mathrand.Intn(len(h.config.CoverWebsites))]
	userAgent := h.config.UserAgents[mathrand.Intn(len(h.config.UserAgents))]

	// Create HTTP request with embedded data
	var httpPacket strings.Builder
	httpPacket.WriteString(fmt.Sprintf("GET /%s HTTP/1.1\r\n", h.generateRandomPath()))
	httpPacket.WriteString(fmt.Sprintf("Host: %s\r\n", website))
	httpPacket.WriteString(fmt.Sprintf("User-Agent: %s\r\n", userAgent))
	httpPacket.WriteString("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n")
	httpPacket.WriteString("Accept-Language: en-US,en;q=0.5\r\n")
	httpPacket.WriteString("Accept-Encoding: gzip, deflate, br\r\n")
	httpPacket.WriteString("Connection: keep-alive\r\n")
	httpPacket.WriteString("Upgrade-Insecure-Requests: 1\r\n")

	// Embed data chunks in custom headers
	headerNames := []string{"X-Request-ID", "X-Trace-ID", "X-Session-Token", "X-Client-ID", "X-API-Key"}
	for i, chunk := range headerChunks {
		if i < len(headerNames) {
			httpPacket.WriteString(fmt.Sprintf("%s: %s\r\n", headerNames[i], chunk))
		} else {
			// Use numbered headers for overflow
			httpPacket.WriteString(fmt.Sprintf("X-Custom-%02d: %s\r\n", i-len(headerNames)+1, chunk))
		}
	}

	// Add sequence number and checksum
	h.mu.Lock()
	h.currentSeq++
	seq := h.currentSeq
	h.mu.Unlock()

	checksum := h.calculateChecksum(vpnData)
	httpPacket.WriteString(fmt.Sprintf("X-Sequence: %d\r\n", seq))
	httpPacket.WriteString(fmt.Sprintf("X-Checksum: %08x\r\n", checksum))
	httpPacket.WriteString("\r\n")

	return []byte(httpPacket.String()), nil
}

// extractFromHeadersAndBody extracts VPN data from HTTP headers and body
func (h *HTTPSteganography) extractFromHeadersAndBody(httpData []byte) ([]byte, error) {
	dataStr := string(httpData)
	lines := strings.Split(dataStr, "\r\n")

	var encodedChunks []string
	var sequence uint32
	var expectedChecksum uint32

	// Parse headers to extract embedded data
	for _, line := range lines {
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			headerName := strings.TrimSpace(parts[0])
			headerValue := strings.TrimSpace(parts[1])

			switch {
			case headerName == "X-Request-ID" || headerName == "X-Trace-ID" ||
				headerName == "X-Session-Token" || headerName == "X-Client-ID" ||
				headerName == "X-API-Key" || strings.HasPrefix(headerName, "X-Custom-"):
				encodedChunks = append(encodedChunks, headerValue)
			case headerName == "X-Sequence":
				_, _ = fmt.Sscanf(headerValue, "%d", &sequence)
			case headerName == "X-Checksum":
				_, _ = fmt.Sscanf(headerValue, "%x", &expectedChecksum)
			}
		}
	}

	if len(encodedChunks) == 0 {
		return []byte{}, fmt.Errorf("no embedded data found in headers")
	}

	// Reconstruct encoded data
	encoded := strings.Join(encodedChunks, "")

	// Decode from base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode embedded data: %w", err)
	}

	// Verify checksum if available
	if expectedChecksum != 0 {
		actualChecksum := h.calculateChecksum(decoded)
		if actualChecksum != expectedChecksum {
			h.logger.Printf("Warning: checksum mismatch (expected: %08x, actual: %08x)", expectedChecksum, actualChecksum)
		}
	}

	return decoded, nil
}

// createMultipartFormStego embeds VPN data in multipart form data
func (h *HTTPSteganography) createMultipartFormStego(vpnData []byte) ([]byte, error) {
	boundary := fmt.Sprintf("----WebKitFormBoundary%016x", mathrand.Int63())

	var formData strings.Builder
	formData.WriteString("POST /api/upload HTTP/1.1\r\n")
	formData.WriteString("Host: " + h.config.CoverWebsites[mathrand.Intn(len(h.config.CoverWebsites))] + "\r\n")
	formData.WriteString("User-Agent: " + h.config.UserAgents[mathrand.Intn(len(h.config.UserAgents))] + "\r\n")
	formData.WriteString(fmt.Sprintf("Content-Type: multipart/form-data; boundary=%s\r\n", boundary))

	// Calculate content length later
	bodyBuilder := strings.Builder{}

	// Add normal form fields
	bodyBuilder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	bodyBuilder.WriteString("Content-Disposition: form-data; name=\"username\"\r\n\r\n")
	bodyBuilder.WriteString("user_" + fmt.Sprintf("%d", mathrand.Int63()) + "\r\n")

	bodyBuilder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	bodyBuilder.WriteString("Content-Disposition: form-data; name=\"description\"\r\n\r\n")
	bodyBuilder.WriteString("File upload description\r\n")

	// Add file with embedded VPN data
	bodyBuilder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	bodyBuilder.WriteString("Content-Disposition: form-data; name=\"file\"; filename=\"data.txt\"\r\n")
	bodyBuilder.WriteString("Content-Type: text/plain\r\n\r\n")

	// Encode VPN data and mix with dummy content
	encoded := base64.StdEncoding.EncodeToString(vpnData)
	bodyBuilder.WriteString("# Configuration file\r\n")
	bodyBuilder.WriteString("# Session: " + h.sessionID + "\r\n")
	bodyBuilder.WriteString("data=" + encoded + "\r\n")
	bodyBuilder.WriteString("# End of configuration\r\n")

	bodyBuilder.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	body := bodyBuilder.String()
	formData.WriteString(fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)))
	formData.WriteString(body)

	return []byte(formData.String()), nil
}

// extractFromMultipartForm extracts VPN data from multipart form data
func (h *HTTPSteganography) extractFromMultipartForm(httpData []byte) ([]byte, error) {
	dataStr := string(httpData)

	// Find the data field in the form
	start := strings.Index(dataStr, "data=")
	if start == -1 {
		return []byte{}, fmt.Errorf("no data field found in form")
	}

	start += 5 // Skip "data="
	end := strings.Index(dataStr[start:], "\r\n")
	if end == -1 {
		end = len(dataStr) - start
	}

	encoded := dataStr[start : start+end]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode form data: %w", err)
	}

	return decoded, nil
}

// createJSONAPIStego embeds VPN data in JSON API responses
func (h *HTTPSteganography) createJSONAPIStego(vpnData []byte) ([]byte, error) {
	template := string(h.contentDB["json_template"])

	// Encode VPN data
	encoded := base64.StdEncoding.EncodeToString(vpnData)
	checksum := fmt.Sprintf("%08x", h.calculateChecksum(vpnData))

	// Replace template variables
	template = strings.ReplaceAll(template, "{{SESSION_ID}}", h.sessionID)
	template = strings.ReplaceAll(template, "{{TIMESTAMP}}", fmt.Sprintf("%d", time.Now().Unix()))
	template = strings.ReplaceAll(template, "{{PAYLOAD}}", encoded)
	template = strings.ReplaceAll(template, "{{SIZE}}", fmt.Sprintf("%d", len(vpnData)))
	template = strings.ReplaceAll(template, "{{CHECKSUM}}", checksum)

	// Create HTTP response
	var response strings.Builder
	response.WriteString("HTTP/1.1 200 OK\r\n")
	response.WriteString("Server: nginx/1.20.2\r\n")
	response.WriteString("Content-Type: application/json\r\n")
	response.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(template)))
	response.WriteString("Cache-Control: no-cache\r\n")
	response.WriteString("Connection: keep-alive\r\n")
	response.WriteString("\r\n")
	response.WriteString(template)

	return []byte(response.String()), nil
}

// extractFromJSONAPI extracts VPN data from JSON API responses
func (h *HTTPSteganography) extractFromJSONAPI(httpData []byte) ([]byte, error) {
	dataStr := string(httpData)

	// Find JSON body
	bodyStart := strings.Index(dataStr, "\r\n\r\n")
	if bodyStart == -1 {
		return []byte{}, fmt.Errorf("no JSON body found")
	}

	jsonBody := dataStr[bodyStart+4:]

	// Extract payload from JSON (simple string search)
	payloadStart := strings.Index(jsonBody, `"payload": "`)
	if payloadStart == -1 {
		return []byte{}, fmt.Errorf("no payload found in JSON")
	}

	payloadStart += 12 // Skip `"payload": "`
	payloadEnd := strings.Index(jsonBody[payloadStart:], `"`)
	if payloadEnd == -1 {
		return []byte{}, fmt.Errorf("malformed payload in JSON")
	}

	encoded := jsonBody[payloadStart : payloadStart+payloadEnd]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JSON payload: %w", err)
	}

	return decoded, nil
}

// createCSSCommentsStego embeds VPN data in CSS comments
func (h *HTTPSteganography) createCSSCommentsStego(vpnData []byte) ([]byte, error) {
	template := string(h.contentDB["css_template"])

	// Encode VPN data
	encoded := base64.StdEncoding.EncodeToString(vpnData)

	// Replace template variables
	template = strings.ReplaceAll(template, "{{SESSION_ID}}", h.sessionID)
	template = strings.ReplaceAll(template, "{{PAYLOAD}}", encoded)

	// Create HTTP response
	var response strings.Builder
	response.WriteString("HTTP/1.1 200 OK\r\n")
	response.WriteString("Content-Type: text/css\r\n")
	response.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(template)))
	response.WriteString("Cache-Control: public, max-age=3600\r\n")
	response.WriteString("\r\n")
	response.WriteString(template)

	return []byte(response.String()), nil
}

// extractFromCSSComments extracts VPN data from CSS comments
func (h *HTTPSteganography) extractFromCSSComments(httpData []byte) ([]byte, error) {
	dataStr := string(httpData)

	// Find CSS body
	bodyStart := strings.Index(dataStr, "\r\n\r\n")
	if bodyStart == -1 {
		return []byte{}, fmt.Errorf("no CSS body found")
	}

	cssBody := dataStr[bodyStart+4:]

	// Extract data from comment
	dataStart := strings.Index(cssBody, "/* data: ")
	if dataStart == -1 {
		return []byte{}, fmt.Errorf("no data comment found in CSS")
	}

	dataStart += 9 // Skip "/* data: "
	dataEnd := strings.Index(cssBody[dataStart:], " */")
	if dataEnd == -1 {
		return []byte{}, fmt.Errorf("malformed data comment in CSS")
	}

	encoded := cssBody[dataStart : dataStart+dataEnd]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CSS data: %w", err)
	}

	return decoded, nil
}

// createJSVariablesStego embeds VPN data in JavaScript variables
func (h *HTTPSteganography) createJSVariablesStego(vpnData []byte) ([]byte, error) {
	template := string(h.contentDB["js_template"])

	// Encode VPN data
	encoded := base64.StdEncoding.EncodeToString(vpnData)
	checksum := fmt.Sprintf("%08x", h.calculateChecksum(vpnData))

	// Replace template variables
	template = strings.ReplaceAll(template, "{{SESSION_ID}}", h.sessionID)
	template = strings.ReplaceAll(template, "{{PAYLOAD}}", encoded)
	template = strings.ReplaceAll(template, "{{CHECKSUM}}", checksum)

	// Create HTTP response
	var response strings.Builder
	response.WriteString("HTTP/1.1 200 OK\r\n")
	response.WriteString("Content-Type: application/javascript\r\n")
	response.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(template)))
	response.WriteString("Cache-Control: public, max-age=3600\r\n")
	response.WriteString("\r\n")
	response.WriteString(template)

	return []byte(response.String()), nil
}

// extractFromJSVariables extracts VPN data from JavaScript variables
func (h *HTTPSteganography) extractFromJSVariables(httpData []byte) ([]byte, error) {
	dataStr := string(httpData)

	// Find JS body
	bodyStart := strings.Index(dataStr, "\r\n\r\n")
	if bodyStart == -1 {
		return []byte{}, fmt.Errorf("no JS body found")
	}

	jsBody := dataStr[bodyStart+4:]

	// Extract data from comment
	dataStart := strings.Index(jsBody, "// Embedded data: ")
	if dataStart == -1 {
		return []byte{}, fmt.Errorf("no embedded data found in JS")
	}

	dataStart += 18 // Skip "// Embedded data: "
	dataEnd := strings.Index(jsBody[dataStart:], "\n")
	if dataEnd == -1 {
		dataEnd = len(jsBody) - dataStart
	}

	encoded := strings.TrimSpace(jsBody[dataStart : dataStart+dataEnd])
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JS data: %w", err)
	}

	return decoded, nil
}

// generateRandomPath generates a realistic HTTP path
func (h *HTTPSteganography) generateRandomPath() string {
	paths := []string{
		"api/v1/data",
		"content/page.html",
		"assets/style.css",
		"scripts/app.js",
		"images/banner.jpg",
		"search?q=query",
		"user/profile",
		"dashboard",
		"settings/preferences",
		"help/documentation",
	}
	return paths[mathrand.Intn(len(paths))]
}

// calculateChecksum calculates a simple checksum for data integrity
func (h *HTTPSteganography) calculateChecksum(data []byte) uint32 {
	var checksum uint32
	for _, b := range data {
		checksum = checksum*31 + uint32(b)
	}
	return checksum
}

// httpSteganographyConn wraps a connection with HTTP steganography
type httpSteganographyConn struct {
	net.Conn
	stego *HTTPSteganography
}

func (c *httpSteganographyConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err != nil || n == 0 {
		return n, err
	}

	deobfuscated, deobfErr := c.stego.Deobfuscate(b[:n])
	if deobfErr != nil {
		return n, deobfErr
	}

	copy(b, deobfuscated)
	return len(deobfuscated), nil
}

func (c *httpSteganographyConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	obfuscated, obfErr := c.stego.Obfuscate(b)
	if obfErr != nil {
		return 0, obfErr
	}

	_, err = c.Conn.Write(obfuscated)
	if err != nil {
		return 0, err
	}

	// Return the number of original bytes written
	return len(b), nil
}

func NewHTTPSteganographyWithDefaults(logger *log.Logger) (Obfuscator, error) {
	return NewHTTPSteganography(nil, logger)
}

// Engine main obfuscation engine
type Engine struct {
	config      *Config
	obfuscators map[ObfuscationMethod]Obfuscator
	current     ObfuscationMethod
	metrics     *EngineMetrics
	detector    *DPIDetector
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	logger      *log.Logger
}

type EngineMetrics struct {
	TotalPackets    int64                                    `json:"total_packets"`
	TotalBytes      int64                                    `json:"total_bytes"`
	MethodSwitches  int64                                    `json:"method_switches"`
	DetectionEvents int64                                    `json:"detection_events"`
	MethodMetrics   map[ObfuscationMethod]*ObfuscatorMetrics `json:"method_metrics"`
	StartTime       time.Time                                `json:"start_time"`
	mu              sync.RWMutex
}

func NewEngine(config *Config, logger *log.Logger) (*Engine, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	ctx, cancel := context.WithCancel(context.Background())

	engine := &Engine{
		config:      config,
		obfuscators: make(map[ObfuscationMethod]Obfuscator),
		current:     config.PrimaryMethod,
		metrics: &EngineMetrics{
			MethodMetrics: make(map[ObfuscationMethod]*ObfuscatorMetrics),
			StartTime:     time.Now(),
		},
		ctx:    ctx,
		cancel: cancel,
		logger: logger,
	}

	if config.AutoDetection {
		engine.detector = NewDPIDetector(config.DetectionTimeout, logger)
	}

	if err := engine.initializeObfuscators(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize obfuscators: %w", err)
	}

	if config.RegionalProfile != "" {
		if err := engine.applyRegionalProfile(config.RegionalProfile); err != nil {
			logger.Printf("Warning: failed to apply regional profile %s: %v", config.RegionalProfile, err)
		}
	}

	go engine.monitoringLoop()

	return engine, nil
}

func (e *Engine) initializeObfuscators() error {
	for _, method := range e.config.EnabledMethods {
		var obfuscator Obfuscator
		var err error

		switch method {
		case MethodTLSTunnel:
			obfuscator, err = NewTLSTunnel(&e.config.TLSTunnel, e.logger)
		case MethodHTTPMimicry:
			obfuscator, err = NewHTTPMimicry(&e.config.HTTPMimicry, e.logger)
		case MethodDNSTunnel:
			obfuscator, err = NewDNSTunnel(&e.config.DNSTunnel, e.logger)
		case MethodXORCipher:
			obfuscator, err = NewXORCipher(e.config.XORKey, e.logger)
		case MethodPacketPadding:
			obfuscator, err = NewPacketPadding(&e.config.PacketPadding, e.logger)
		case MethodTimingObfs:
			obfuscator, err = NewTimingObfuscation(&e.config.TimingObfuscation, e.logger)
		case MethodTrafficPadding:
			obfuscator, err = NewTrafficPadding(&e.config.TrafficPadding, e.logger)
		case MethodFlowWatermark:
			obfuscator, err = NewFlowWatermark(&e.config.FlowWatermark, e.logger)
		case MethodHTTPStego:
			obfuscator, err = NewHTTPSteganography(&e.config.HTTPStego, e.logger)
		default:
			e.logger.Printf("Warning: unsupported obfuscation method: %s", method)
			continue
		}

		if err != nil {
			return fmt.Errorf("failed to initialize %s: %w", method, err)
		}

		if obfuscator.IsAvailable() {
			e.obfuscators[method] = obfuscator
			e.metrics.MethodMetrics[method] = &ObfuscatorMetrics{}
		} else {
			e.logger.Printf("Warning: obfuscator %s is not available", method)
		}
	}

	if len(e.obfuscators) == 0 {
		return fmt.Errorf("no obfuscators available")
	}

	if _, exists := e.obfuscators[e.current]; !exists {
		for method := range e.obfuscators {
			e.current = method
			break
		}
	}

	return nil
}

func (e *Engine) ObfuscateData(data []byte) ([]byte, error) {
	e.mu.RLock()
	obfuscator, exists := e.obfuscators[e.current]
	e.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("current obfuscation method %s not available", e.current)
	}

	start := time.Now()
	result, err := obfuscator.Obfuscate(data)
	processingTime := time.Since(start)

	e.updateMetrics(e.current, len(data), processingTime, err)

	if err != nil && e.config.AutoDetection && e.detector != nil {
		if e.detector.ShouldSwitch(e.current, err) {
			e.switchMethod()
		}
	}

	return result, err
}

func (e *Engine) DeobfuscateData(data []byte) ([]byte, error) {
	e.mu.RLock()
	obfuscator, exists := e.obfuscators[e.current]
	e.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("current obfuscation method %s not available", e.current)
	}

	start := time.Now()
	result, err := obfuscator.Deobfuscate(data)
	processingTime := time.Since(start)

	e.updateMetrics(e.current, len(data), processingTime, err)

	return result, err
}

func (e *Engine) WrapConnection(conn net.Conn) (net.Conn, error) {
	e.mu.RLock()
	obfuscator, exists := e.obfuscators[e.current]
	e.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("current obfuscation method %s not available", e.current)
	}

	wrappedConn, err := obfuscator.WrapConn(conn)
	if err != nil && e.config.AutoDetection && e.detector != nil {
		if e.detector.ShouldSwitch(e.current, err) {
			e.switchMethod()
			e.mu.RLock()
			newObfuscator := e.obfuscators[e.current]
			e.mu.RUnlock()
			return newObfuscator.WrapConn(conn)
		}
	}

	return wrappedConn, err
}

func (e *Engine) switchMethod() {
	e.mu.Lock()
	defer e.mu.Unlock()

	var nextMethod ObfuscationMethod
	var found bool

	for _, method := range e.config.FallbackMethods {
		if obf, exists := e.obfuscators[method]; exists && obf.IsAvailable() && method != e.current {
			nextMethod = method
			found = true
			break
		}
	}

	if !found {
		for method, obf := range e.obfuscators {
			if obf.IsAvailable() && method != e.current {
				nextMethod = method
				found = true
				break
			}
		}
	}

	if found {
		e.logger.Printf("Switching obfuscation method from %s to %s", e.current, nextMethod)
		e.current = nextMethod
		e.metrics.mu.Lock()
		e.metrics.MethodSwitches++
		e.metrics.mu.Unlock()
	}
}

func (e *Engine) updateMetrics(method ObfuscationMethod, dataSize int, processingTime time.Duration, err error) {
	e.metrics.mu.Lock()
	defer e.metrics.mu.Unlock()

	e.metrics.TotalPackets++
	e.metrics.TotalBytes += int64(dataSize)

	methodMetrics, exists := e.metrics.MethodMetrics[method]
	if !exists {
		methodMetrics = &ObfuscatorMetrics{}
		e.metrics.MethodMetrics[method] = methodMetrics
	}

	methodMetrics.PacketsProcessed++
	methodMetrics.BytesProcessed += int64(dataSize)
	methodMetrics.LastUsed = time.Now()

	if err != nil {
		methodMetrics.Errors++
	}

	if methodMetrics.AvgProcessTime == 0 {
		methodMetrics.AvgProcessTime = processingTime
	} else {
		methodMetrics.AvgProcessTime = (methodMetrics.AvgProcessTime + processingTime) / 2
	}
}

func (e *Engine) GetCurrentMethod() ObfuscationMethod {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.current
}

func (e *Engine) GetMetrics() *EngineMetrics {
	e.metrics.mu.RLock()
	defer e.metrics.mu.RUnlock()

	result := &EngineMetrics{
		TotalPackets:    e.metrics.TotalPackets,
		TotalBytes:      e.metrics.TotalBytes,
		MethodSwitches:  e.metrics.MethodSwitches,
		DetectionEvents: e.metrics.DetectionEvents,
		MethodMetrics:   make(map[ObfuscationMethod]*ObfuscatorMetrics),
		StartTime:       e.metrics.StartTime,
	}

	for method, metrics := range e.metrics.MethodMetrics {
		result.MethodMetrics[method] = &ObfuscatorMetrics{
			PacketsProcessed: metrics.PacketsProcessed,
			BytesProcessed:   metrics.BytesProcessed,
			Errors:           metrics.Errors,
			AvgProcessTime:   metrics.AvgProcessTime,
			LastUsed:         metrics.LastUsed,
		}
	}

	return result
}

func (e *Engine) monitoringLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.performHealthCheck()
		}
	}
}

func (e *Engine) performHealthCheck() {
	e.mu.RLock()
	currentObf := e.obfuscators[e.current]
	e.mu.RUnlock()

	if !currentObf.IsAvailable() {
		e.logger.Printf("Current obfuscation method %s is no longer available", e.current)
		e.switchMethod()
	}
}

func (e *Engine) applyRegionalProfile(profile string) error {
	switch profile {
	case "china":
		return e.applyChinaProfile()
	case "iran":
		return e.applyIranProfile()
	case "russia":
		return e.applyRussiaProfile()
	default:
		return fmt.Errorf("unknown regional profile: %s", profile)
	}
}

func (e *Engine) applyChinaProfile() error {
	e.logger.Printf("Applying China obfuscation profile")
	e.config.PrimaryMethod = MethodTLSTunnel
	e.config.FallbackMethods = []ObfuscationMethod{MethodHTTPMimicry, MethodXORCipher}
	e.config.SwitchThreshold = 2
	e.config.DetectionTimeout = 5 * time.Second
	return nil
}

func (e *Engine) applyIranProfile() error {
	e.logger.Printf("Applying Iran obfuscation profile")
	e.config.PrimaryMethod = MethodHTTPMimicry
	e.config.FallbackMethods = []ObfuscationMethod{MethodTLSTunnel, MethodXORCipher}
	e.config.SwitchThreshold = 3
	e.config.DetectionTimeout = 10 * time.Second
	return nil
}

func (e *Engine) applyRussiaProfile() error {
	e.logger.Printf("Applying Russia obfuscation profile")
	e.config.PrimaryMethod = MethodTLSTunnel
	e.config.FallbackMethods = []ObfuscationMethod{MethodHTTPMimicry, MethodXORCipher}
	e.config.SwitchThreshold = 4
	e.config.DetectionTimeout = 15 * time.Second
	return nil
}

func (e *Engine) Close() error {
	e.cancel()
	return nil
}
