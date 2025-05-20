package core

import (
	"encoding/binary"
	"net"
)

// Constants for working with IP packets
const (
	IPv4Version      = 4
	IPv4VersionShift = 4
	IPv4MinHeaderLen = 20
	IPv4MaxHeaderLen = 60
	IPv4HdrLenUnit   = 4 // Header length is specified in 32-bit words (4 bytes)
)

// Constants for protocols
const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

// Packet represents a packet transmitted through TUN/TAP device
type Packet struct {
	data []byte
}

// NewPacket creates a new packet from a byte slice
func NewPacket(data []byte) *Packet {
	return &Packet{
		data: data,
	}
}

// IsIPv4 checks if the packet is IPv4
func (p *Packet) IsIPv4() bool {
	if len(p.data) < IPv4MinHeaderLen {
		return false
	}

	return (p.data[0] >> IPv4VersionShift) == IPv4Version
}

// GetIPv4Version returns the IP version
func (p *Packet) GetIPv4Version() byte {
	if len(p.data) < IPv4MinHeaderLen {
		return 0
	}
	return p.data[0] >> IPv4VersionShift
}

// GetIPv4HeaderLength returns the IPv4 header length in bytes
func (p *Packet) GetIPv4HeaderLength() int {
	if len(p.data) < IPv4MinHeaderLen {
		return 0
	}
	return int(p.data[0]&0x0F) * IPv4HdrLenUnit
}

// GetIPv4Protocol returns the protocol of the IPv4 packet
func (p *Packet) GetIPv4Protocol() byte {
	if len(p.data) < 10 {
		return 0
	}
	return p.data[9]
}

// GetIPv4SourceIP returns the source IP address of the IPv4 packet
func (p *Packet) GetIPv4SourceIP() net.IP {
	if len(p.data) < 16 {
		return nil
	}
	return net.IPv4(p.data[12], p.data[13], p.data[14], p.data[15])
}

// GetIPv4DestinationIP returns the destination IP address of the IPv4 packet
func (p *Packet) GetIPv4DestinationIP() net.IP {
	if len(p.data) < 20 {
		return nil
	}
	return net.IPv4(p.data[16], p.data[17], p.data[18], p.data[19])
}

// GetIPv4PayloadLength returns the length of the IPv4 payload
func (p *Packet) GetIPv4PayloadLength() int {
	if len(p.data) < IPv4MinHeaderLen {
		return 0
	}

	// Total packet length is stored in bytes 2-3
	totalLen := int(binary.BigEndian.Uint16(p.data[2:4]))
	headerLen := p.GetIPv4HeaderLength()

	if headerLen > totalLen {
		return 0
	}

	return totalLen - headerLen
}

// GetIPv4Payload returns the payload of the IPv4 packet
func (p *Packet) GetIPv4Payload() []byte {
	if len(p.data) < IPv4MinHeaderLen {
		return nil
	}

	headerLen := p.GetIPv4HeaderLength()
	totalLen := int(binary.BigEndian.Uint16(p.data[2:4]))

	if headerLen > totalLen || len(p.data) < totalLen {
		return nil
	}

	return p.data[headerLen:totalLen]
}

// SetIPv4SourceIP sets the source IP address of IPv4
func (p *Packet) SetIPv4SourceIP(srcIP net.IP) error {
	if len(p.data) < 16 {
		return nil
	}

	if len(srcIP) == 16 {
		// Convert IPv6 to IPv4 if possible
		srcIP = srcIP.To4()
	}

	if len(srcIP) != 4 {
		return nil
	}

	copy(p.data[12:16], srcIP)

	// Recalculate checksum
	p.recalculateIPv4Checksum()

	return nil
}

// SetIPv4DestinationIP sets the destination IP address of IPv4
func (p *Packet) SetIPv4DestinationIP(dstIP net.IP) error {
	if len(p.data) < 20 {
		return nil
	}

	if len(dstIP) == 16 {
		// Convert IPv6 to IPv4 if possible
		dstIP = dstIP.To4()
	}

	if len(dstIP) != 4 {
		return nil
	}

	copy(p.data[16:20], dstIP)

	// Recalculate checksum
	p.recalculateIPv4Checksum()

	return nil
}

// recalculateIPv4Checksum recalculates the IPv4 header checksum
func (p *Packet) recalculateIPv4Checksum() {
	if len(p.data) < IPv4MinHeaderLen {
		return
	}

	headerLen := p.GetIPv4HeaderLength()
	if headerLen < IPv4MinHeaderLen || len(p.data) < headerLen {
		return
	}

	// Zero out current checksum
	p.data[10] = 0
	p.data[11] = 0

	// Calculate new checksum
	var sum uint32
	// Process the header as a sequence of 16-bit words
	for i := 0; i < headerLen; i += 2 {
		if i+1 < headerLen {
			sum += uint32(p.data[i])<<8 | uint32(p.data[i+1])
		} else {
			sum += uint32(p.data[i]) << 8
		}
	}

	// Add carry
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// Invert bits
	sum = ^sum

	// Write checksum back to header
	p.data[10] = byte(sum >> 8)
	p.data[11] = byte(sum & 0xFF)
}

// ProcessPacket processes a data packet from a TUN/TAP device
func ProcessPacket(data []byte) (*Packet, error) {
	if len(data) < IPv4MinHeaderLen {
		return nil, nil
	}

	packet := NewPacket(data)

	// Check packet type
	if packet.IsIPv4() {
		// Process IPv4 packet
		return packet, nil
	}

	// Only support IPv4 for now
	return nil, nil
}

// CreateIPv4Packet creates a new IPv4 packet with the given parameters
func CreateIPv4Packet(srcIP, dstIP net.IP, protocol byte, payload []byte) *Packet {
	headerLen := IPv4MinHeaderLen
	totalLen := headerLen + len(payload)

	// Create minimal IPv4 header
	data := make([]byte, totalLen)
	if len(payload) > 0 {
		copy(data[headerLen:], payload)
	}

	srcIP = srcIP.To4()
	dstIP = dstIP.To4()

	// Fill header fields
	data[0] = byte((IPv4Version << IPv4VersionShift) | (headerLen / IPv4HdrLenUnit)) // Version and header length
	data[1] = 0                                                                      // Type of Service
	binary.BigEndian.PutUint16(data[2:4], uint16(totalLen))                          // Total length
	binary.BigEndian.PutUint16(data[4:6], 0)                                         // Identification
	binary.BigEndian.PutUint16(data[6:8], 0)                                         // Flags and fragment offset
	data[8] = 64                                                                     // TTL
	data[9] = protocol                                                               // Protocol

	// Checksum will be calculated later

	// Source and destination addresses
	copy(data[12:16], srcIP)
	copy(data[16:20], dstIP)

	// Copy payload
	if len(payload) > 0 {
		copy(data[headerLen:], payload)
	}

	packet := NewPacket(data)
	packet.recalculateIPv4Checksum()
	return packet
}
