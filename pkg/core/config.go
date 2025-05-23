//go:build !windows
// +build !windows

package core

import (
	"errors"
	"time"
)

var (
	// ErrInvalidConfig indicates that the configuration is invalid
	ErrInvalidConfig = errors.New("invalid configuration")
)

// Config represents VPN server configuration
type Config struct {
	// Network settings
	ListenAddress string // Address to listen on
	Port          int    // Port to listen on
	Protocol      string // Protocol (tcp or udp)
	EnableTCP     bool   // Enable TCP server
	EnableUDP     bool   // Enable UDP server

	// Server network settings
	ServerNetwork string   // Server network CIDR (e.g., "10.8.0.0/24")
	Routes        []string // Routes to push to clients (CIDR notation)
	DNSServers    []string // DNS servers to push to clients

	// Device settings
	DeviceName  string // TUN/TAP device name
	DeviceType  string // Device type (tun or tap)
	MTU         int    // MTU size
	InternalDNS bool   // Whether to use internal DNS resolver

	// Security
	CipherMode string // Cipher mode
	AuthDigest string // Authentication digest
	TLSVersion string // TLS version (default: 1.3)
	AuthMode   string // Authentication mode

	// Certificate settings
	CAPath         string // CA certificate path
	CertPath       string // Server certificate path
	KeyPath        string // Server key path
	CRLPath        string // CRL path
	DHParamsPath   string // Diffie-Hellman parameters path
	TLSAuthKeyPath string // TLS authentication key path

	// Connection settings
	KeepaliveInterval int // Keepalive interval in seconds
	KeepaliveTimeout  int // Keepalive timeout in seconds

	// API settings
	EnableAPI        bool   // Enable REST API
	APIListenAddress string // API listen address
	APIPort          int    // API port
	APIAuth          bool   // Enable API authentication
	APIAuthSecret    string // API authentication secret

	// Timing settings (mostly for testing)
	HandshakeTimeout time.Duration // Handshake timeout
	ReadTimeout      time.Duration // Read timeout
	WriteTimeout     time.Duration // Write timeout

	// CLI settings
	ProfileName string // Current profile name
	ConfigPath  string // Path to current configuration file
	RunAsDaemon bool   // Whether to run as a daemon
	LogLevel    string // Log verbosity (error, warning, info, debug, trace)
	LogOutput   string // Log output (stdout, file, syslog)
	LogFilePath string // Log file path when LogOutput is "file"

	// Service settings
	ServiceName    string // Name for system service
	ServiceEnabled bool   // Whether to enable service
}

// DefaultConfig returns default configuration
func DefaultConfig() Config {
	return Config{
		// Network settings
		ListenAddress: "0.0.0.0",
		Port:          1194,
		Protocol:      "udp",
		EnableTCP:     true,
		EnableUDP:     true,
		ServerNetwork: "10.8.0.0/24",

		// Device settings
		DeviceName:  "tun0",
		DeviceType:  "tun",
		MTU:         1500,
		InternalDNS: false,

		// Security
		CipherMode: "AES-256-GCM",
		AuthDigest: "SHA512",
		TLSVersion: "1.3",
		AuthMode:   "certificate",

		// Certificate settings
		CAPath:         "certs/ca.crt",
		CertPath:       "certs/server.crt",
		KeyPath:        "certs/server.key",
		CRLPath:        "certs/crl.pem",
		DHParamsPath:   "certs/dh4096.pem",
		TLSAuthKeyPath: "certs/ta.key",

		// Connection settings
		KeepaliveInterval: 10,
		KeepaliveTimeout:  60,

		// API settings
		EnableAPI:        false,
		APIListenAddress: "127.0.0.1",
		APIPort:          8080,
		APIAuth:          true,
		APIAuthSecret:    "",

		// Timing settings
		HandshakeTimeout: time.Duration(30) * time.Second,
		ReadTimeout:      time.Duration(5) * time.Second,
		WriteTimeout:     time.Duration(5) * time.Second,

		// Push settings
		Routes:     []string{},
		DNSServers: []string{"8.8.8.8", "8.8.4.4"},

		// CLI settings
		ProfileName: "default",
		RunAsDaemon: false,
		LogLevel:    "info",
		LogOutput:   "stdout",

		// Service settings
		ServiceName:    "govpn",
		ServiceEnabled: false,
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Port <= 0 || c.Port > 65535 {
		return errors.New("invalid port number")
	}

	if c.Protocol != "tcp" && c.Protocol != "udp" && c.Protocol != "both" {
		return errors.New("protocol must be tcp, udp, or both")
	}

	if c.DeviceType != "tun" && c.DeviceType != "tap" {
		return errors.New("device type must be tun or tap")
	}

	if c.MTU < 576 || c.MTU > 9000 {
		return errors.New("invalid MTU value")
	}

	// We always use TLS in this implementation
	if c.CAPath == "" {
		return errors.New("CA path is required")
	}

	if c.CertPath == "" {
		return errors.New("certificate path is required")
	}

	if c.KeyPath == "" {
		return errors.New("key path is required")
	}

	// API validation
	if c.EnableAPI {
		if c.APIPort <= 0 || c.APIPort > 65535 {
			return errors.New("invalid API port number")
		}

		if c.APIAuth && c.APIAuthSecret == "" {
			return errors.New("API authentication enabled but no auth secret provided")
		}
	}

	// Log validation
	if c.LogOutput != "stdout" && c.LogOutput != "file" && c.LogOutput != "syslog" {
		return errors.New("log output must be stdout, file, or syslog")
	}

	if c.LogOutput == "file" && c.LogFilePath == "" {
		return errors.New("log file path is required when log output is file")
	}

	return nil
}
