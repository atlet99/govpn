// Package core contains VPN server core components
package core

import (
	"context"
	"net"
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
	Running      bool     // Whether the server is running
	ClientCount  int      // Number of connected clients
	BytesIn      uint64   // Bytes received
	BytesOut     uint64   // Bytes sent
	ActiveRoutes []string // Active routes
	StartTime    int64    // Server start time (Unix timestamp)
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
