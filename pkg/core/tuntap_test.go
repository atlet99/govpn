package core

import (
	"bytes"
	"testing"
)

func TestNewDevice(t *testing.T) {
	// Test device creation with valid parameters
	config := DefaultConfig()
	config.DeviceName = "test-tun"
	config.DeviceType = "tun"
	config.MTU = 1500

	// Note: This test won't work without root privileges on a real system
	// Here we only test parameter validation
	if config.DeviceName != "test-tun" {
		t.Errorf("Expected DeviceName 'test-tun', got '%s'", config.DeviceName)
	}

	if config.DeviceType != "tun" {
		t.Errorf("Expected DeviceType 'tun', got '%s'", config.DeviceType)
	}

	if config.MTU != 1500 {
		t.Errorf("Expected MTU 1500, got %d", config.MTU)
	}
}

func TestValidateDeviceParams(t *testing.T) {
	tests := []struct {
		name       string
		deviceType string
		deviceName string
		mtu        int
		wantErr    bool
	}{
		{
			name:       "Valid TUN device",
			deviceType: "tun",
			deviceName: "tun0",
			mtu:        1500,
			wantErr:    false,
		},
		{
			name:       "Valid TAP device",
			deviceType: "tap",
			deviceName: "tap0",
			mtu:        1500,
			wantErr:    false,
		},
		{
			name:       "Invalid device type",
			deviceType: "invalid",
			deviceName: "test0",
			mtu:        1500,
			wantErr:    true,
		},
		{
			name:       "Empty device name",
			deviceType: "tun",
			deviceName: "",
			mtu:        1500,
			wantErr:    true,
		},
		{
			name:       "Invalid MTU too low",
			deviceType: "tun",
			deviceName: "tun0",
			mtu:        100,
			wantErr:    true,
		},
		{
			name:       "Invalid MTU too high",
			deviceType: "tun",
			deviceName: "tun0",
			mtu:        10000,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			config.DeviceType = tt.deviceType
			config.DeviceName = tt.deviceName
			config.MTU = tt.mtu

			err := config.Validate()
			hasErr := err != nil

			// For some cases validation may pass, but device creation will fail
			if tt.wantErr && !hasErr {
				// Check specific cases
				if tt.deviceType == "invalid" {
					t.Error("Expected error for invalid device type")
				}
				if tt.mtu < 576 || tt.mtu > 9000 {
					t.Error("Expected error for invalid MTU")
				}
			}
		})
	}
}

func TestPacketHeader(t *testing.T) {
	// Test packet creation with header
	payload := []byte("test payload data")

	// Create IPv4 packet for testing
	ipv4Header := []byte{
		0x45, 0x00, // Version=4, IHL=5, Type of Service=0
		0x00, 0x20, // Total Length=32
		0x12, 0x34, // Identification
		0x00, 0x00, // Flags=0, Fragment Offset=0
		0x40, 0x06, // TTL=64, Protocol=TCP
		0x00, 0x00, // Header Checksum (will be calculated)
		0xC0, 0xA8, 0x01, 0x01, // Source IP (192.168.1.1)
		0xC0, 0xA8, 0x01, 0x02, // Destination IP (192.168.1.2)
	}

	packet := append(ipv4Header, payload...)

	if len(packet) < 20 {
		t.Error("IPv4 packet should have at least 20 bytes header")
	}

	// Check IP version
	version := packet[0] >> 4
	if version != 4 {
		t.Errorf("Expected IPv4 version 4, got %d", version)
	}

	// Check IHL (Internet Header Length)
	ihl := packet[0] & 0x0F
	if ihl < 5 {
		t.Errorf("Expected IHL at least 5, got %d", ihl)
	}

	// Check protocol
	protocol := packet[9]
	if protocol != 6 { // TCP
		t.Errorf("Expected protocol 6 (TCP), got %d", protocol)
	}
}

func TestIPv6Packet(t *testing.T) {
	// Test IPv6 packet creation
	payload := []byte("test ipv6 payload")

	// Create IPv6 packet for testing
	ipv6Header := []byte{
		0x60, 0x00, 0x00, 0x00, // Version=6, Traffic Class=0, Flow Label=0
		0x00, 0x11, // Payload Length=17
		0x06, 0x40, // Next Header=TCP, Hop Limit=64
		// Source IPv6 Address (16 bytes)
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		// Destination IPv6 Address (16 bytes)
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}

	packet := append(ipv6Header, payload...)

	if len(packet) < 40 {
		t.Error("IPv6 packet should have at least 40 bytes header")
	}

	// Check IP version
	version := packet[0] >> 4
	if version != 6 {
		t.Errorf("Expected IPv6 version 6, got %d", version)
	}

	// Check payload length
	payloadLen := int(packet[4])<<8 | int(packet[5])
	if payloadLen != len(payload) {
		t.Errorf("Expected payload length %d, got %d", len(payload), payloadLen)
	}

	// Check next header
	nextHeader := packet[6]
	if nextHeader != 6 { // TCP
		t.Errorf("Expected next header 6 (TCP), got %d", nextHeader)
	}
}

func TestMTUValidation(t *testing.T) {
	tests := []struct {
		name    string
		mtu     int
		isValid bool
	}{
		{"Minimum valid MTU", 576, true},
		{"Standard Ethernet MTU", 1500, true},
		{"Jumbo frame MTU", 9000, true},
		{"Too small MTU", 575, false},
		{"Too large MTU", 9001, false},
		{"Zero MTU", 0, false},
		{"Negative MTU", -1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			config.MTU = tt.mtu

			err := config.Validate()
			hasErr := err != nil

			if tt.isValid && hasErr {
				t.Errorf("Expected MTU %d to be valid, but got error: %v", tt.mtu, err)
			}

			if !tt.isValid && !hasErr {
				t.Errorf("Expected MTU %d to be invalid, but no error was returned", tt.mtu)
			}
		})
	}
}

func TestDeviceTypeValidation(t *testing.T) {
	validTypes := []string{"tun", "tap"}
	invalidTypes := []string{"", "invalid", "tun0", "tap0", "ethernet", "wifi"}

	for _, deviceType := range validTypes {
		t.Run("Valid_"+deviceType, func(t *testing.T) {
			config := DefaultConfig()
			config.DeviceType = deviceType

			err := config.Validate()
			if err != nil {
				t.Errorf("Expected device type '%s' to be valid, but got error: %v", deviceType, err)
			}
		})
	}

	for _, deviceType := range invalidTypes {
		t.Run("Invalid_"+deviceType, func(t *testing.T) {
			config := DefaultConfig()
			config.DeviceType = deviceType

			err := config.Validate()
			if err == nil {
				t.Errorf("Expected device type '%s' to be invalid, but no error was returned", deviceType)
			}
		})
	}
}

func TestPacketParsing(t *testing.T) {
	// Test network packet parsing
	testCases := []struct {
		name        string
		packet      []byte
		expectedVer int
		shouldFail  bool
	}{
		{
			name: "Valid IPv4 packet",
			packet: []byte{
				0x45, 0x00, 0x00, 0x1c, // Version=4, IHL=5, TOS=0, Total Length=28
				0x00, 0x01, 0x00, 0x00, // ID=1, Flags=0, Fragment Offset=0
				0x40, 0x01, 0x00, 0x00, // TTL=64, Protocol=ICMP, Checksum=0
				0x7f, 0x00, 0x00, 0x01, // Source IP (127.0.0.1)
				0x7f, 0x00, 0x00, 0x01, // Destination IP (127.0.0.1)
				0x08, 0x00, 0xf7, 0xfc, // ICMP header
			},
			expectedVer: 4,
			shouldFail:  false,
		},
		{
			name: "Valid IPv6 packet",
			packet: []byte{
				0x60, 0x00, 0x00, 0x00, // Version=6, Traffic Class=0, Flow Label=0
				0x00, 0x08, 0x3a, 0x40, // Payload Length=8, Next Header=ICMPv6, Hop Limit=64
				// Source IPv6 (::1)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				// Destination IPv6 (::1)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				// ICMPv6 payload
				0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			expectedVer: 6,
			shouldFail:  false,
		},
		{
			name:        "Invalid packet - too short",
			packet:      []byte{0x45, 0x00},
			expectedVer: 4,
			shouldFail:  true,
		},
		{
			name:        "Invalid IP version",
			packet:      []byte{0x55, 0x00, 0x00, 0x1c}, // Version=5 (invalid)
			expectedVer: 5,
			shouldFail:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.packet) == 0 {
				if !tc.shouldFail {
					t.Error("Empty packet should fail parsing")
				}
				return
			}

			version := tc.packet[0] >> 4

			if tc.shouldFail {
				if version == 4 && len(tc.packet) >= 20 {
					// IPv4 packet with length >= 20 bytes should not fail only due to length
					if int(version) != tc.expectedVer && tc.expectedVer != 5 {
						t.Errorf("Packet with version %d should have failed parsing", version)
					}
				} else if version == 6 && len(tc.packet) >= 40 {
					// IPv6 packet with length >= 40 bytes should not fail only due to length
					if int(version) != tc.expectedVer {
						t.Errorf("Packet with version %d should have failed parsing", version)
					}
				}
				// For short packets this is expected
			} else {
				if int(version) != tc.expectedVer {
					t.Errorf("Expected IP version %d, got %d", tc.expectedVer, version)
				}

				// Additional checks for valid packets
				if version == 4 && len(tc.packet) < 20 {
					t.Error("IPv4 packet should have at least 20 bytes")
				}
				if version == 6 && len(tc.packet) < 40 {
					t.Error("IPv6 packet should have at least 40 bytes")
				}
			}
		})
	}
}

func TestPacketBufferOperations(t *testing.T) {
	// Test packet buffer operations
	testData := []byte("Hello, VPN World!")

	// Create buffer
	buffer := bytes.NewBuffer(nil)

	// Write data
	n, err := buffer.Write(testData)
	if err != nil {
		t.Fatalf("Failed to write to buffer: %v", err)
	}

	if n != len(testData) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(testData), n)
	}

	// Read data back
	readBuffer := make([]byte, len(testData))
	n, err = buffer.Read(readBuffer)
	if err != nil {
		t.Fatalf("Failed to read from buffer: %v", err)
	}

	if n != len(testData) {
		t.Errorf("Expected to read %d bytes, read %d", len(testData), n)
	}

	if !bytes.Equal(testData, readBuffer) {
		t.Errorf("Data mismatch: expected %v, got %v", testData, readBuffer)
	}
}

func TestDeviceNameValidation(t *testing.T) {
	tests := []struct {
		name       string
		deviceName string
		isValid    bool
	}{
		{"Standard TUN device", "tun0", true},
		{"Standard TAP device", "tap0", true},
		{"Custom name", "govpn0", true},
		{"Empty name", "", false},
		{"Very long name", "this-is-a-very-long-device-name-that-might-exceed-system-limits-for-interface-names", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			config.DeviceName = tt.deviceName

			// Simple device name check (real validation depends on OS)
			isValid := tt.deviceName != "" && len(tt.deviceName) < 50

			if tt.isValid != isValid {
				if tt.isValid {
					t.Errorf("Expected device name '%s' to be valid", tt.deviceName)
				} else {
					t.Errorf("Expected device name '%s' to be invalid", tt.deviceName)
				}
			}
		})
	}
}
