package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	// OpenVPN protocol constants
	OpvnP_CONTROL_HARD_RESET_CLIENT_V1 byte = 1
	OpvnP_CONTROL_HARD_RESET_SERVER_V1 byte = 2
	OpvnP_CONTROL_SOFT_RESET_V1        byte = 3
	OpvnP_CONTROL_V1                   byte = 4
	OpvnP_ACK_V1                       byte = 5
	OpvnP_DATA_V1                      byte = 6
	OpvnP_CONTROL_HARD_RESET_CLIENT_V2 byte = 7
	OpvnP_CONTROL_HARD_RESET_SERVER_V2 byte = 8

	// Key constants
	KEY_METHOD_2 byte = 2

	// Session ID length
	SESSION_ID_LENGTH = 8

	// TLS authentication key length (2048 bits)
	TLS_AUTH_KEY_LENGTH = 256
)

var (
	// ErrPacketTooSmall is returned when a packet is too small to be valid
	ErrPacketTooSmall = errors.New("packet too small to be a valid OpenVPN packet")

	// ErrInvalidPacketOpcode is returned when a packet has an invalid opcode
	ErrInvalidPacketOpcode = errors.New("invalid OpenVPN packet opcode")

	// ErrHMACVerificationFailed is returned when HMAC verification fails
	ErrHMACVerificationFailed = errors.New("HMAC verification failed")
)

// OpenVPNPacket represents an OpenVPN protocol packet
type OpenVPNPacket struct {
	Opcode        byte
	KeyID         byte
	SessionID     []byte
	AckPacketID   uint32 // Used in ACK packets
	PacketID      uint32
	PayloadLength uint16
	Payload       []byte
	HMAC          []byte
}

// OpenVPNSession represents a client session
type OpenVPNSession struct {
	SessionID       []byte
	RemoteSessionID []byte
	TLSConfig       *tls.Config
	TLSAuthKey      []byte
	PacketID        uint32
	CipherContext   *CipherContext
	LastPacketTime  time.Time
	IsHandshaking   bool
	HandshakeState  *tls.ConnectionState
}

// NewOpenVPNSession creates a new OpenVPN session
func NewOpenVPNSession(tlsConfig *tls.Config, tlsAuthKey []byte) *OpenVPNSession {
	sessionID := make([]byte, SESSION_ID_LENGTH)
	if _, err := io.ReadFull(bytes.NewReader(tlsAuthKey[:SESSION_ID_LENGTH]), sessionID); err != nil {
		// In case of error, use random data
		_, _ = io.ReadFull(rand.Reader, sessionID)
	}

	return &OpenVPNSession{
		SessionID:      sessionID,
		TLSConfig:      tlsConfig,
		TLSAuthKey:     tlsAuthKey,
		PacketID:       1,
		LastPacketTime: time.Now(),
		IsHandshaking:  true,
	}
}

// NewPacket creates a new OpenVPN packet
func NewPacket(opcode byte, payload []byte) *OpenVPNPacket {
	return &OpenVPNPacket{
		Opcode:        opcode,
		KeyID:         0,
		SessionID:     make([]byte, SESSION_ID_LENGTH),
		PacketID:      0,
		PayloadLength: uint16(len(payload)),
		Payload:       payload,
		HMAC:          nil,
	}
}

// Marshal serializes an OpenVPN packet to bytes
func (p *OpenVPNPacket) Marshal() ([]byte, error) {
	// Calculate the length of the packet without HMAC
	packetLength := 1 + 1 + len(p.SessionID) + 4 + 2 + len(p.Payload)

	// Buffer to hold the packet
	buf := bytes.NewBuffer(make([]byte, 0, packetLength))

	// Opcode and key ID
	buf.WriteByte(p.Opcode)
	buf.WriteByte(p.KeyID)

	// Session ID
	buf.Write(p.SessionID)

	// Packet ID
	if err := binary.Write(buf, binary.BigEndian, p.PacketID); err != nil {
		return nil, fmt.Errorf("failed to write packet ID: %w", err)
	}

	// Payload length
	if err := binary.Write(buf, binary.BigEndian, p.PayloadLength); err != nil {
		return nil, fmt.Errorf("failed to write payload length: %w", err)
	}

	// Payload
	buf.Write(p.Payload)

	return buf.Bytes(), nil
}

// Unmarshal deserializes an OpenVPN packet from bytes
func (p *OpenVPNPacket) Unmarshal(data []byte) error {
	if len(data) < 8 {
		return ErrPacketTooSmall
	}

	// Read opcode and key ID
	p.Opcode = data[0]
	p.KeyID = data[1]

	// Validate opcode
	if p.Opcode < OpvnP_CONTROL_HARD_RESET_CLIENT_V1 || p.Opcode > OpvnP_CONTROL_HARD_RESET_SERVER_V2 {
		return ErrInvalidPacketOpcode
	}

	// Read session ID
	p.SessionID = make([]byte, SESSION_ID_LENGTH)
	copy(p.SessionID, data[2:2+SESSION_ID_LENGTH])

	// Read packet ID
	p.PacketID = binary.BigEndian.Uint32(data[2+SESSION_ID_LENGTH : 6+SESSION_ID_LENGTH])

	// Read payload length
	p.PayloadLength = binary.BigEndian.Uint16(data[6+SESSION_ID_LENGTH : 8+SESSION_ID_LENGTH])

	// Read payload
	if len(data) < 8+SESSION_ID_LENGTH+int(p.PayloadLength) {
		return ErrPacketTooSmall
	}

	p.Payload = make([]byte, p.PayloadLength)
	copy(p.Payload, data[8+SESSION_ID_LENGTH:8+SESSION_ID_LENGTH+int(p.PayloadLength)])

	return nil
}

// VerifyHMAC verifies the HMAC of a packet
func (p *OpenVPNPacket) VerifyHMAC(key []byte) bool {
	if len(p.HMAC) == 0 {
		return false
	}

	packetData, _ := p.Marshal()
	h := hmac.New(sha256.New, key)
	h.Write(packetData)
	calculatedHMAC := h.Sum(nil)

	return hmacEqual(calculatedHMAC, p.HMAC)
}

// AddHMAC adds an HMAC to a packet
func (p *OpenVPNPacket) AddHMAC(key []byte) {
	packetData, _ := p.Marshal()
	h := hmac.New(sha256.New, key)
	h.Write(packetData)
	p.HMAC = h.Sum(nil)
}

// ProcessClientHandshake processes a client handshake packet
func (s *OpenVPNSession) ProcessClientHandshake(packet *OpenVPNPacket) (*OpenVPNPacket, error) {
	if packet.Opcode != OpvnP_CONTROL_HARD_RESET_CLIENT_V1 &&
		packet.Opcode != OpvnP_CONTROL_HARD_RESET_CLIENT_V2 {
		return nil, fmt.Errorf("unexpected opcode for client handshake: %d", packet.Opcode)
	}

	// Save the client's session ID
	s.RemoteSessionID = packet.SessionID

	// Create server response
	responseOpcode := OpvnP_CONTROL_HARD_RESET_SERVER_V1
	if packet.Opcode == OpvnP_CONTROL_HARD_RESET_CLIENT_V2 {
		responseOpcode = OpvnP_CONTROL_HARD_RESET_SERVER_V2
	}

	responsePacket := NewPacket(responseOpcode, nil)
	responsePacket.SessionID = s.SessionID
	responsePacket.PacketID = s.PacketID
	s.PacketID++

	// Add HMAC if TLS authentication is enabled
	if s.TLSAuthKey != nil {
		responsePacket.AddHMAC(s.TLSAuthKey)
	}

	return responsePacket, nil
}

// ProcessControlPacket processes a control packet
func (s *OpenVPNSession) ProcessControlPacket(packet *OpenVPNPacket) (*OpenVPNPacket, error) {
	// Verify HMAC if TLS authentication is enabled
	if s.TLSAuthKey != nil && !packet.VerifyHMAC(s.TLSAuthKey) {
		return nil, ErrHMACVerificationFailed
	}

	// Update last packet time
	s.LastPacketTime = time.Now()

	// Process different packet types
	switch packet.Opcode {
	case OpvnP_CONTROL_HARD_RESET_CLIENT_V1, OpvnP_CONTROL_HARD_RESET_CLIENT_V2:
		// Handle client handshake
		return s.ProcessClientHandshake(packet)

	case OpvnP_CONTROL_V1:
		// Handle control message
		// TODO: Process control message (e.g., push routes, DNS, etc.)

		// Send an ACK
		ackPacket := NewPacket(OpvnP_ACK_V1, nil)
		ackPacket.SessionID = s.SessionID
		ackPacket.PacketID = s.PacketID
		s.PacketID++
		ackPacket.AckPacketID = packet.PacketID

		// Add HMAC if TLS authentication is enabled
		if s.TLSAuthKey != nil {
			ackPacket.AddHMAC(s.TLSAuthKey)
		}

		return ackPacket, nil

	case OpvnP_ACK_V1:
		// Process acknowledgment
		// Nothing to do for now
		return nil, nil

	case OpvnP_DATA_V1:
		// Process data packet
		// TODO: Decrypt and process data
		return nil, nil

	default:
		return nil, fmt.Errorf("unknown opcode: %d", packet.Opcode)
	}
}

// CreateDataPacket creates a data packet for transmission
func (s *OpenVPNSession) CreateDataPacket(data []byte) (*OpenVPNPacket, error) {
	if !s.IsHandshaking {
		// Encrypt data if handshake is complete
		if s.CipherContext != nil {
			var err error
			data, err = s.CipherContext.Encrypt(data)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt data: %w", err)
			}
		}
	}

	// Create data packet
	packet := NewPacket(OpvnP_DATA_V1, data)
	packet.SessionID = s.SessionID
	packet.PacketID = s.PacketID
	s.PacketID++

	// Add HMAC if TLS authentication is enabled
	if s.TLSAuthKey != nil {
		packet.AddHMAC(s.TLSAuthKey)
	}

	return packet, nil
}
