package obfuscation

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// ObfuscationMethod represents the type of obfuscation method
type ObfuscationMethod string

const (
	MethodTLSTunnel     ObfuscationMethod = "tls_tunnel"
	MethodHTTPMimicry   ObfuscationMethod = "http_mimicry"
	MethodSSHMimicry    ObfuscationMethod = "ssh_mimicry"
	MethodDNSTunnel     ObfuscationMethod = "dns_tunnel"
	MethodXORCipher     ObfuscationMethod = "xor_cipher"
	MethodPacketPadding ObfuscationMethod = "packet_padding"
	MethodTimingObfs    ObfuscationMethod = "timing_obfs"
	MethodHTTPStego     ObfuscationMethod = "http_stego"
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
	EnabledMethods    []ObfuscationMethod `json:"enabled_methods"`
	PrimaryMethod     ObfuscationMethod   `json:"primary_method"`
	FallbackMethods   []ObfuscationMethod `json:"fallback_methods"`
	AutoDetection     bool                `json:"auto_detection"`
	SwitchThreshold   int                 `json:"switch_threshold"`
	DetectionTimeout  time.Duration       `json:"detection_timeout"`
	RegionalProfile   string              `json:"regional_profile"`
	PacketPadding     PacketPaddingConfig `json:"packet_padding"`
	TimingObfuscation TimingObfsConfig    `json:"timing_obfuscation"`
	TLSTunnel         TLSTunnelConfig     `json:"tls_tunnel"`
	HTTPMimicry       HTTPMimicryConfig   `json:"http_mimicry"`
	XORKey            []byte              `json:"xor_key,omitempty"`
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

// Stub constructors
func NewTLSTunnel(config *TLSTunnelConfig, logger *log.Logger) (Obfuscator, error) {
	return &stubObfuscator{name: MethodTLSTunnel, logger: logger}, nil
}

func NewHTTPMimicry(config *HTTPMimicryConfig, logger *log.Logger) (Obfuscator, error) {
	return &stubObfuscator{name: MethodHTTPMimicry, logger: logger}, nil
}

func NewPacketPadding(config *PacketPaddingConfig, logger *log.Logger) (Obfuscator, error) {
	return &stubObfuscator{name: MethodPacketPadding, logger: logger}, nil
}

func NewTimingObfuscation(config *TimingObfsConfig, logger *log.Logger) (Obfuscator, error) {
	return &stubObfuscator{name: MethodTimingObfs, logger: logger}, nil
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
