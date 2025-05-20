//go:build windows
// +build windows

package core

import (
	"errors"
	"time"
)

const (
	// DefaultListenAddress default address to listen on
	DefaultListenAddress = "0.0.0.0"

	// DefaultPort default OpenVPN port
	DefaultPort = 1194

	// DefaultServerNetwork default VPN subnet
	DefaultServerNetwork = "10.8.0.0/24"

	// DefaultMTU default MTU value
	DefaultMTU = 1500

	// DefaultCipherMode default encryption mode
	DefaultCipherMode = "AES-256-GCM"

	// DefaultAuthDigest default authentication algorithm
	DefaultAuthDigest = "SHA512"

	// DefaultTLSVersion default TLS version
	DefaultTLSVersion = "1.3"

	// DefaultKeepaliveInterval default keepalive interval in seconds
	DefaultKeepaliveInterval = 10

	// DefaultKeepaliveTimeout default keepalive timeout in seconds
	DefaultKeepaliveTimeout = 60

	// DefaultMaxClients default maximum number of clients
	DefaultMaxClients = 100

	// DefaultAPIListenAddress default API listen address
	DefaultAPIListenAddress = "127.0.0.1"

	// DefaultAPIPort default API port
	DefaultAPIPort = 8080

	// DefaultHandshakeTimeout default handshake timeout
	DefaultHandshakeTimeout = 30 * time.Second

	// DefaultReadTimeout default read timeout
	DefaultReadTimeout = 5 * time.Second

	// DefaultWriteTimeout default write timeout
	DefaultWriteTimeout = 5 * time.Second
)

var (
	// ErrInvalidConfig indicates that the configuration is invalid
	ErrInvalidConfig = errors.New("invalid configuration")

	// DefaultDNSServers default DNS servers
	DefaultDNSServers = []string{"8.8.8.8", "8.8.4.4"}
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
	TLSEnabled bool   // Legacy option
	Cipher     string // Legacy option
	Auth       string // Legacy option

	// Certificate settings
	CAPath         string // CA certificate path
	CertPath       string // Server certificate path
	KeyPath        string // Server key path
	CRLPath        string // CRL path
	DHParamsPath   string // Diffie-Hellman parameters path
	TLSAuthKeyPath string // TLS authentication key path

	// Connection settings
	KeepaliveInterval int           // Keepalive interval in seconds
	KeepaliveTimeout  int           // Keepalive timeout in seconds
	MaxClients        int           // Legacy option
	KeepAlive         time.Duration // Legacy option

	// API settings
	EnableAPI        bool   // Enable REST API
	APIListenAddress string // API listen address
	APIPort          int    // API port
	APIAuth          bool   // Enable API authentication
	APIAuthSecret    string // API authentication secret

	// Timing settings
	HandshakeTimeout time.Duration // Handshake timeout
	ReadTimeout      time.Duration // Read timeout
	WriteTimeout     time.Duration // Write timeout

	// Legacy settings
	CompLZO          bool   // Use LZO compression
	KeepAliveTimeout int    // Keepalive timeout in seconds (legacy)
	LogLevel         string // Logging level
}

// DefaultConfig returns a default configuration
func DefaultConfig() Config {
	return Config{
		// Network settings
		ListenAddress: DefaultListenAddress,
		Port:          DefaultPort,
		Protocol:      "udp",
		EnableTCP:     true,
		EnableUDP:     true,
		ServerNetwork: DefaultServerNetwork,

		// Device settings
		DeviceName:  "govpn0",
		DeviceType:  "tun",
		MTU:         DefaultMTU,
		InternalDNS: false,

		// Security
		CipherMode: DefaultCipherMode,
		AuthDigest: DefaultAuthDigest,
		TLSVersion: DefaultTLSVersion,
		AuthMode:   "certificate",
		TLSEnabled: true,              // Legacy
		Cipher:     DefaultCipherMode, // Legacy
		Auth:       DefaultAuthDigest, // Legacy

		// Certificate settings
		CAPath:         "certs/ca.crt",
		CertPath:       "certs/server.crt",
		KeyPath:        "certs/server.key",
		CRLPath:        "certs/crl.pem",
		DHParamsPath:   "certs/dh4096.pem",
		TLSAuthKeyPath: "certs/ta.key",

		// Connection settings
		KeepaliveInterval: DefaultKeepaliveInterval,
		KeepaliveTimeout:  DefaultKeepaliveTimeout,
		MaxClients:        DefaultMaxClients,
		KeepAlive:         time.Duration(DefaultKeepaliveInterval) * time.Second, // Legacy

		// API settings
		EnableAPI:        false,
		APIListenAddress: DefaultAPIListenAddress,
		APIPort:          DefaultAPIPort,
		APIAuth:          true,
		APIAuthSecret:    "",

		// Timing settings
		HandshakeTimeout: DefaultHandshakeTimeout,
		ReadTimeout:      DefaultReadTimeout,
		WriteTimeout:     DefaultWriteTimeout,

		// Push settings
		Routes:     []string{},
		DNSServers: DefaultDNSServers,

		// Legacy settings
		CompLZO:          false,
		KeepAliveTimeout: DefaultKeepaliveTimeout,
		LogLevel:         "info",
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

	return nil
}
