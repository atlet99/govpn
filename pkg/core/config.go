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

// Config represents server configuration
type Config struct {
	// Network settings
	ListenAddress string
	Port          int
	Protocol      string // "tcp", "udp", or "both"
	EnableTCP     bool
	EnableUDP     bool
	ServerNetwork string

	// TUN/TAP device settings
	DeviceName string
	DeviceType string // "tun" or "tap"
	MTU        int

	// Security settings
	TLSEnabled     bool
	CAPath         string
	CertPath       string
	KeyPath        string
	CRLPath        string
	TLSAuthKeyPath string
	DHParamsPath   string
	Cipher         string
	Auth           string

	// Connection settings
	MaxClients       int
	KeepAlive        time.Duration
	HandshakeTimeout time.Duration

	// Routing settings
	Routes     []string // Routes for VPN clients
	DNSServers []string // DNS servers to push to clients

	// Advanced settings
	CompLZO          bool   // Use LZO compression
	KeepAliveTimeout int    // Keepalive timeout in seconds
	LogLevel         string // Logging level
}

// DefaultConfig returns a default configuration
func DefaultConfig() Config {
	return Config{
		ListenAddress:    "0.0.0.0",
		Port:             1194,
		Protocol:         "both",
		EnableTCP:        true,
		EnableUDP:        true,
		ServerNetwork:    "10.8.0.0/24",
		DeviceName:       "govpn0",
		DeviceType:       "tun",
		MTU:              1500,
		TLSEnabled:       true,
		CAPath:           "certs/ca.crt",
		CertPath:         "certs/server.crt",
		KeyPath:          "certs/server.key",
		CRLPath:          "certs/crl.pem",
		TLSAuthKeyPath:   "certs/ta.key",
		DHParamsPath:     "certs/dh2048.pem",
		Cipher:           "AES-256-GCM",
		Auth:             "SHA256",
		MaxClients:       100,
		KeepAlive:        time.Duration(10) * time.Second,
		HandshakeTimeout: time.Duration(30) * time.Second,
		Routes:           []string{},
		DNSServers:       []string{},
		CompLZO:          false,
		KeepAliveTimeout: 60,
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

	if c.TLSEnabled {
		if c.CAPath == "" {
			return errors.New("CA path required when TLS is enabled")
		}

		if c.CertPath == "" {
			return errors.New("certificate path required when TLS is enabled")
		}

		if c.KeyPath == "" {
			return errors.New("key path required when TLS is enabled")
		}
	}

	return nil
}
