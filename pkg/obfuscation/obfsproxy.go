package obfuscation

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ObfsproxyConfig contains configuration for obfsproxy
type ObfsproxyConfig struct {
	Enabled    bool   `json:"enabled"`
	Executable string `json:"executable"`
	Mode       string `json:"mode"`      // "client" or "server"
	Transport  string `json:"transport"` // "obfs3", "obfs4", "scramblesuit"
	Address    string `json:"address"`
	Port       int    `json:"port"`
	Options    string `json:"options"`
	LogLevel   string `json:"log_level"`
}

// Obfsproxy implements obfuscation through obfsproxy
type Obfsproxy struct {
	config  *ObfsproxyConfig
	metrics ObfuscatorMetrics
	mu      sync.RWMutex
	logger  *log.Logger
	cmd     *exec.Cmd
}

// NewObfsproxy creates a new instance of Obfsproxy
func NewObfsproxy(config *ObfsproxyConfig, logger *log.Logger) (*Obfsproxy, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	if config == nil {
		config = &ObfsproxyConfig{
			Enabled:    true,
			Executable: "obfsproxy",
			Mode:       "client",
			Transport:  "obfs4",
			LogLevel:   "INFO",
		}
	}

	return &Obfsproxy{
		config: config,
		logger: logger,
	}, nil
}

// Name returns the name of the obfuscation method
func (o *Obfsproxy) Name() ObfuscationMethod {
	return "obfsproxy"
}

// Obfuscate obfuscates data through obfsproxy
func (o *Obfsproxy) Obfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		o.updateMetrics(len(data), time.Since(start), nil)
	}()

	if !o.config.Enabled || len(data) == 0 {
		return data, nil
	}

	// For obfsproxy, obfuscation happens at the connection level
	// Here we just return the data as is
	return data, nil
}

// Deobfuscate deobfuscates data through obfsproxy
func (o *Obfsproxy) Deobfuscate(data []byte) ([]byte, error) {
	start := time.Now()
	defer func() {
		o.updateMetrics(len(data), time.Since(start), nil)
	}()

	// For obfsproxy, deobfuscation happens at the connection level
	// Here we just return the data as is
	return data, nil
}

// WrapConn wraps a connection in obfsproxy
func (o *Obfsproxy) WrapConn(conn net.Conn) (net.Conn, error) {
	if !o.config.Enabled {
		return conn, nil
	}

	// Start obfsproxy as a separate process
	args := []string{
		"--log-file=STDOUT",
		fmt.Sprintf("--log-level=%s", o.config.LogLevel),
		o.config.Mode,
		o.config.Transport,
		fmt.Sprintf("%s:%d", o.config.Address, o.config.Port),
	}

	if o.config.Options != "" {
		args = append(args, strings.Split(o.config.Options, " ")...)
	}

	o.cmd = exec.Command(o.config.Executable, args...)

	// Get stdin/stdout of obfsproxy
	stdin, err := o.cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	stdout, err := o.cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	// Start the process
	if err := o.cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start obfsproxy: %w", err)
	}

	// Create wrapped connection
	wrappedConn := &obfsproxyConn{
		Conn:    conn,
		obfs:    o,
		stdin:   stdin,
		stdout:  stdout,
		scanner: bufio.NewScanner(stdout),
	}

	// Start goroutine to handle obfsproxy output
	go wrappedConn.handleOutput()

	return wrappedConn, nil
}

// IsAvailable checks if obfsproxy is available
func (o *Obfsproxy) IsAvailable() bool {
	if !o.config.Enabled {
		return false
	}

	// Check if obfsproxy executable exists
	cmd := exec.Command("which", o.config.Executable)
	return cmd.Run() == nil
}

// GetMetrics returns obfuscation metrics
func (o *Obfsproxy) GetMetrics() ObfuscatorMetrics {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.metrics
}

// updateMetrics updates obfuscation metrics
func (o *Obfsproxy) updateMetrics(dataSize int, processingTime time.Duration, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.metrics.PacketsProcessed++
	o.metrics.BytesProcessed += int64(dataSize)
	o.metrics.LastUsed = time.Now()

	if err != nil {
		o.metrics.Errors++
	}

	if o.metrics.AvgProcessTime == 0 {
		o.metrics.AvgProcessTime = processingTime
	} else {
		o.metrics.AvgProcessTime = (o.metrics.AvgProcessTime + processingTime) / 2
	}
}

// obfsproxyConn is a wrapper for connection through obfsproxy
type obfsproxyConn struct {
	net.Conn
	obfs    *Obfsproxy
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	scanner *bufio.Scanner
	mu      sync.Mutex
}

// Read reads data from obfsproxy
func (c *obfsproxyConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.scanner.Scan() {
		if err := c.scanner.Err(); err != nil {
			return 0, fmt.Errorf("failed to read from obfsproxy: %w", err)
		}
		return 0, io.EOF
	}

	data := c.scanner.Bytes()
	if len(data) > len(b) {
		return 0, fmt.Errorf("buffer too small for obfsproxy data")
	}

	copy(b, data)
	return len(data), nil
}

// Write writes data to obfsproxy
func (c *obfsproxyConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err := c.stdin.Write(b); err != nil {
		return 0, fmt.Errorf("failed to write to obfsproxy: %w", err)
	}

	return len(b), nil
}

// Close closes the connection and stops obfsproxy
func (c *obfsproxyConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.obfs.cmd != nil && c.obfs.cmd.Process != nil {
		if err := c.obfs.cmd.Process.Kill(); err != nil {
			c.obfs.logger.Printf("Failed to kill obfsproxy process: %v", err)
		}
	}

	if err := c.stdin.Close(); err != nil {
		c.obfs.logger.Printf("Failed to close obfsproxy stdin: %v", err)
	}

	if err := c.stdout.Close(); err != nil {
		c.obfs.logger.Printf("Failed to close obfsproxy stdout: %v", err)
	}

	return c.Conn.Close()
}

// handleOutput processes obfsproxy output
func (c *obfsproxyConn) handleOutput() {
	for c.scanner.Scan() {
		line := c.scanner.Text()
		if strings.Contains(line, "ERROR") {
			c.obfs.logger.Printf("Obfsproxy error: %s", line)
		} else if strings.Contains(line, "WARNING") {
			c.obfs.logger.Printf("Obfsproxy warning: %s", line)
		}
	}

	if err := c.scanner.Err(); err != nil {
		c.obfs.logger.Printf("Error reading obfsproxy output: %v", err)
	}
}
