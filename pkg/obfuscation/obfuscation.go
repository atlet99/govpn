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
	TLSTunnel         TLSTunnelConfig      `json:"tls_tunnel"`
	HTTPMimicry       HTTPMimicryConfig    `json:"http_mimicry"`
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

func NewHTTPSteganography(logger *log.Logger) (Obfuscator, error) {
	return &stubObfuscator{name: MethodHTTPStego, logger: logger}, nil
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
		case MethodXORCipher:
			obfuscator, err = NewXORCipher(e.config.XORKey, e.logger)
		case MethodPacketPadding:
			obfuscator, err = NewPacketPadding(&e.config.PacketPadding, e.logger)
		case MethodTimingObfs:
			obfuscator, err = NewTimingObfuscation(&e.config.TimingObfuscation, e.logger)
		case MethodTrafficPadding:
			obfuscator, err = NewTrafficPadding(&e.config.TrafficPadding, e.logger)
		case MethodHTTPStego:
			obfuscator, err = NewHTTPSteganography(e.logger)
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
