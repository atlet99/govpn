// Package core contains VPN server core components
package core

import (
	"context"
	"errors"
	"net"
	"time"
)

var (
	// ErrNetworkNotAvailable indicates that the network is not available
	ErrNetworkNotAvailable = errors.New("network not available")

	// ErrTunDeviceNotAvailable indicates that the TUN device is not available
	ErrTunDeviceNotAvailable = errors.New("TUN device not available")

	// ErrInvalidCertificate indicates an invalid certificate
	ErrInvalidCertificate = errors.New("invalid certificate")

	// ErrAuthenticationFailed indicates authentication failure
	ErrAuthenticationFailed = errors.New("authentication failed")
)

// VPNServer represents the interface for a VPN server
type VPNServer interface {
	// Start launches the VPN server
	Start(ctx context.Context) error

	// Stop terminates the VPN server
	Stop() error

	// Status returns the current server status
	Status() ServerStatus
}

// ServerStatus represents the server status
type ServerStatus struct {
	Running      bool     `json:"running"`      // Whether the server is running
	ClientCount  int      `json:"clientCount"`  // Number of connected clients
	BytesIn      uint64   `json:"bytesIn"`      // Bytes received
	BytesOut     uint64   `json:"bytesOut"`     // Bytes sent
	ActiveRoutes []string `json:"activeRoutes"` // Active routes
	StartTime    int64    `json:"startTime"`    // Server start time (Unix timestamp)
}

// Connection represents a client connection to the VPN server
type Connection interface {
	// ID returns the unique connection identifier
	ID() string

	// Client returns information about the client
	Client() *ClientInfo

	// Stats returns connection statistics
	Stats() ConnectionStats

	// Close terminates the connection
	Close() error
}

// ClientInfo contains client information
type ClientInfo struct {
	CommonName   string   // Common Name from client certificate
	RemoteAddr   net.Addr // Client address
	AssignedIP   net.IP   // Assigned IP address
	ConnectedAt  int64    // Connection time (Unix timestamp)
	AuthMode     string   // Authentication mode
	VirtualRoute []string // Virtual routes
	UserID       string   // User ID (if applicable)
}

// ConnectionStats contains connection statistics
type ConnectionStats struct {
	BytesIn     uint64 // Bytes received
	BytesOut    uint64 // Bytes sent
	PacketsIn   uint64 // Packets received
	PacketsOut  uint64 // Packets sent
	ConnectedAt int64  // Connection time (Unix timestamp)
}

// TunnelDevice represents the interface for a tunnel device
type TunnelDevice interface {
	// Name returns the device name (e.g., tun0)
	Name() string

	// Type returns the device type (e.g., "tun" or "tap")
	Type() string

	// Read reads data from the device
	Read(p []byte) (n int, err error)

	// Write writes data to the device
	Write(p []byte) (n int, err error)

	// Close closes the device
	Close() error

	// MTU returns the device MTU
	MTU() int

	// SetMTU sets the device MTU
	SetMTU(mtu int) error

	// Interface returns the network interface associated with this device
	Interface() net.Interface
}

// VPNOption represents an option function for configuring the VPN server
type VPNOption func(*Config)

// ServerFactory creates a new instance of a VPN server
type ServerFactory func(Config) (VPNServer, error)

// VPNConnection represents a VPN connection
type VPNConnection struct {
	ID            string    // Connection ID
	ClientID      string    // Client ID
	StartTime     time.Time // Start time
	BytesReceived uint64    // Bytes received
	BytesSent     uint64    // Bytes sent
	RemoteAddr    net.Addr  // Remote address
	LocalAddr     net.Addr  // Local address
	Protocol      string    // Protocol (UDP or TCP)
}

// VPNClient represents a VPN client
type VPNClient struct {
	ID               string            // Client ID
	CommonName       string            // Certificate common name
	ConnectionTime   time.Time         // Connection time
	LastSeen         time.Time         // Last seen
	RealAddress      string            // Real IP address
	VirtualAddress   string            // Virtual IP address
	BytesReceived    uint64            // Bytes received
	BytesSent        uint64            // Bytes sent
	Connected        bool              // Whether the client is connected
	ActiveConnection *VPNConnection    // Active connection
	Properties       map[string]string // Properties (static and dynamic)
}

// ClientConfig represents VPN client configuration
type ClientConfig struct {
	// Connection settings
	ServerAddress string // VPN server address
	ServerPort    int    // VPN server port
	Protocol      string // Protocol (udp or tcp)

	// Certificate settings
	CertPath string // Client certificate path
	KeyPath  string // Client key path
	CAPath   string // CA certificate path

	// Device settings
	DeviceType string // Device type (tun or tap)
	DeviceName string // Device name
	MTU        int    // MTU size

	// Authentication settings
	Username string // Username for authentication
	Password string // Password for authentication
	OTP      string // One-time password

	// Security settings
	CipherMode string // Cipher mode (AES-256-GCM, etc.)
	AuthDigest string // Authentication digest (SHA256, etc.)

	// Network settings
	DNS    []string // DNS servers
	Routes []string // Routes to add

	// Compression settings
	CompressAlgorithm string // Compression algorithm

	// CLI settings
	LogLevel    string // Log verbosity (error, warning, info, debug, trace)
	LogOutput   string // Log output (stdout, file, syslog)
	LogFilePath string // Log file path when log-output is file
	RunAsDaemon bool   // Whether to run as a daemon
	ProfileName string // Profile name
	ConfigPath  string // Path to the configuration file

	// Service settings
	ServiceName    string // Name for system service
	ServiceEnabled bool   // Whether to enable service
}

// VPN represents a VPN interface
type VPN interface {
	// Start starts the VPN
	Start() error

	// Stop stops the VPN
	Stop() error

	// IsRunning returns whether the VPN is running
	IsRunning() bool

	// GetStatus returns the VPN status
	GetStatus() VPNStatus
}

// VPNStatus represents VPN status
type VPNStatus struct {
	State       string // Current state (starting, running, stopping, stopped)
	StartTime   int64  // Start time
	ClientCount int    // Number of connected clients
	BytesIn     uint64 // Bytes received
	BytesOut    uint64 // Bytes sent
	Uptime      int64  // Uptime in seconds
}
