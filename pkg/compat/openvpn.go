// Package compat implements OpenVPN compatibility layer
package compat

import (
	"errors"
	"io"
	"time"
)

// OpenVPN protocol constants
const (
	// OpenVPN packet types
	P_CONTROL_HARD_RESET_CLIENT_V1 = 1  // Initial key from client, forget previous state
	P_CONTROL_HARD_RESET_SERVER_V1 = 2  // Initial key from server, forget previous state
	P_CONTROL_SOFT_RESET_V1        = 3  // New key, graceful transition from old to new key
	P_CONTROL_V1                   = 4  // Control channel packet (usually TLS ciphertext)
	P_ACK_V1                       = 5  // Acknowledgement for P_CONTROL packets
	P_DATA_V1                      = 6  // Data channel packet
	P_DATA_V2                      = 9  // Data channel packet with peer-id
	P_CONTROL_HARD_RESET_CLIENT_V2 = 7  // Initial key from client, forget previous state
	P_CONTROL_HARD_RESET_SERVER_V2 = 8  // Initial key from server, forget previous state
	P_CONTROL_HARD_RESET_CLIENT_V3 = 10 // Initial key from client, forget previous state
	P_CONTROL_WKC_V1               = 11 // Initial key from server, forget previous state

	// Maximum size of an OpenVPN packet
	MAX_PACKET_SIZE = 1500
)

// OpenVPNPacketHeader represents an OpenVPN packet header
type OpenVPNPacketHeader struct {
	OpCode    byte     // Operation code
	KeyID     byte     // Key ID
	PeerID    uint32   // Peer ID (optional)
	MessageID uint32   // Message ID (for reliable delivery)
	ACKs      []uint32 // ACK message IDs
}

// OpenVPNPacket represents an OpenVPN packet
type OpenVPNPacket struct {
	Header  OpenVPNPacketHeader // Packet header
	Payload []byte              // Payload
}

// OpenVPNProtocol represents the interface for working with the OpenVPN protocol
type OpenVPNProtocol interface {
	// ParsePacket parses an OpenVPN packet from a byte array
	ParsePacket(data []byte) (*OpenVPNPacket, error)

	// SerializePacket serializes an OpenVPN packet to a byte array
	SerializePacket(packet *OpenVPNPacket) ([]byte, error)

	// NewControlPacket creates a new control packet
	NewControlPacket(opCode byte, messageID uint32, payload []byte) *OpenVPNPacket

	// NewDataPacket creates a new data packet
	NewDataPacket(keyID byte, payload []byte) *OpenVPNPacket
}

// OpenVPNConfigParser represents the interface for an OpenVPN configuration parser
type OpenVPNConfigParser interface {
	// ParseConfig parses OpenVPN configuration from an io.Reader
	ParseConfig(reader io.Reader) (map[string]interface{}, error)

	// ParseConfigFile parses OpenVPN configuration from a file
	ParseConfigFile(path string) (map[string]interface{}, error)
}

// OpenVPNTLSCrypto represents the interface for OpenVPN TLS cryptographic operations
type OpenVPNTLSCrypto interface {
	// Initialize initializes the cryptographic context
	Initialize() error

	// ProcessControlPacket processes a control packet
	ProcessControlPacket(packet *OpenVPNPacket) (*OpenVPNPacket, error)

	// EncryptDataPacket encrypts a data packet
	EncryptDataPacket(packet []byte, keyID byte) ([]byte, error)

	// DecryptDataPacket decrypts a data packet
	DecryptDataPacket(packet []byte, keyID byte) ([]byte, error)
}

// OpenVPNSessionManager represents the interface for managing OpenVPN sessions
type OpenVPNSessionManager interface {
	// NewSession creates a new session
	NewSession(clientID string) (string, error)

	// GetSession gets a session by ID
	GetSession(sessionID string) (OpenVPNSession, error)

	// RemoveSession removes a session
	RemoveSession(sessionID string) error

	// CleanupSessions cleans up expired sessions
	CleanupSessions(maxAge time.Duration) int
}

// OpenVPNSession represents an OpenVPN session
type OpenVPNSession interface {
	// ID returns the session ID
	ID() string

	// ClientID returns the client ID
	ClientID() string

	// LastActivity returns the time of last activity
	LastActivity() time.Time

	// UpdateActivity updates the time of last activity
	UpdateActivity()

	// SetKeys sets encryption keys
	SetKeys(keyID byte, encryptKey, decryptKey []byte) error

	// GetKeys gets encryption keys
	GetKeys(keyID byte) (encryptKey, decryptKey []byte, err error)
}

// ErrInvalidPacket indicates an invalid OpenVPN packet
var ErrInvalidPacket = errors.New("invalid OpenVPN packet")

// ErrSessionNotFound indicates a missing session
var ErrSessionNotFound = errors.New("session not found")

// ErrInvalidKey indicates an invalid key
var ErrInvalidKey = errors.New("invalid key")

// ErrInvalidConfig indicates an invalid configuration
var ErrInvalidConfig = errors.New("invalid OpenVPN configuration")
