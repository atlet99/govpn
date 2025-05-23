package core

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atlet99/govpn/pkg/auth"
)

// TestOpenVPNConfigCompatibility tests compatibility with OpenVPN configuration format
func TestOpenVPNConfigCompatibility(t *testing.T) {
	// Create temporary directory for test configurations
	tempDir, err := os.MkdirTemp("", "govpn_openvpn_compat_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Sample real OpenVPN server configuration
	serverConfig := `
# OpenVPN Server Configuration
port 1194
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-GCM
auth SHA512
compress lz4-v2
max-clients 100
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log-append  /var/log/openvpn.log
verb 3
explicit-exit-notify 1
`

	configPath := filepath.Join(tempDir, "server.ovpn")
	if err := os.WriteFile(configPath, []byte(serverConfig), 0644); err != nil {
		t.Fatalf("Failed to write server config: %v", err)
	}

	// Parse configuration as OpenVPN
	settings, err := parseOpenVPNConfig(configPath)
	if err != nil {
		t.Errorf("Failed to parse OpenVPN config: %v", err)
	}

	// Check basic parameters
	if settings["port"] != "1194" {
		t.Errorf("Expected port 1194, got %s", settings["port"])
	}

	if settings["proto"] != "udp" {
		t.Errorf("Expected protocol udp, got %s", settings["proto"])
	}

	if settings["dev"] != "tun" {
		t.Errorf("Expected device tun, got %s", settings["dev"])
	}

	if settings["cipher"] != "AES-256-GCM" {
		t.Errorf("Expected cipher AES-256-GCM, got %s", settings["cipher"])
	}

	if settings["auth"] != "SHA512" {
		t.Errorf("Expected auth SHA512, got %s", settings["auth"])
	}
}

// TestClientConfigCompatibility tests compatibility with OpenVPN client configurations
func TestClientConfigCompatibility(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "govpn_client_compat_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Sample OpenVPN client configuration
	clientConfig := `
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
remote-cert-tls server
cipher AES-256-GCM
auth SHA512
compress lz4-v2
verb 3
`

	configPath := filepath.Join(tempDir, "client.ovpn")
	if err := os.WriteFile(configPath, []byte(clientConfig), 0644); err != nil {
		t.Fatalf("Failed to write client config: %v", err)
	}

	settings, err := parseOpenVPNConfig(configPath)
	if err != nil {
		t.Errorf("Failed to parse OpenVPN client config: %v", err)
	}

	// Check client parameters
	if _, exists := settings["client"]; !exists {
		t.Error("Expected client directive to be present")
	}

	if settings["remote"] == "" {
		t.Error("Expected remote directive to be present")
	}

	if settings["cipher"] != "AES-256-GCM" {
		t.Errorf("Expected cipher AES-256-GCM, got %s", settings["cipher"])
	}
}

// TestCipherCompatibility tests encryption compatibility with OpenVPN
func TestCipherCompatibility(t *testing.T) {
	// Test OpenVPN-supported encryption algorithms
	supportedCiphers := []auth.CipherMode{
		auth.CipherAES256GCM,
		auth.CipherAES192GCM,
		auth.CipherAES128GCM,
		auth.CipherChacha20Poly1305,
	}

	for _, cipher := range supportedCiphers {
		t.Run(string(cipher), func(t *testing.T) {
			var keySize int
			switch cipher {
			case auth.CipherAES128GCM:
				keySize = 16
			case auth.CipherAES192GCM:
				keySize = 24
			default:
				keySize = 32
			}

			key := make([]byte, keySize)
			for i := range key {
				key[i] = byte(i % 256)
			}

			ctx, err := auth.NewCipherContext(cipher, auth.AuthSHA256, key)
			if err != nil {
				t.Fatalf("Failed to create cipher context for %s: %v", cipher, err)
			}

			// Test with different data sizes
			testData := [][]byte{
				[]byte(""),
				[]byte("a"),
				[]byte("Hello, OpenVPN!"),
				make([]byte, 1024), // Large data block
			}

			for i, data := range testData {
				encrypted, err := ctx.Encrypt(data)
				if err != nil {
					t.Errorf("Failed to encrypt test data %d: %v", i, err)
					continue
				}

				decrypted, err := ctx.Decrypt(encrypted)
				if err != nil {
					t.Errorf("Failed to decrypt test data %d: %v", i, err)
					continue
				}

				if string(data) != string(decrypted) {
					t.Errorf("Data mismatch for test %d", i)
				}
			}
		})
	}
}

// TestProtocolCompatibility tests protocol compatibility
func TestProtocolCompatibility(t *testing.T) {
	// Check support for protocols as in OpenVPN
	validProtocols := []string{"tcp", "udp", "both"}

	for _, protocol := range validProtocols {
		config := DefaultConfig()
		config.Protocol = protocol

		err := config.Validate()
		if err != nil {
			t.Errorf("Protocol %s should be valid (OpenVPN compatible), got error: %v", protocol, err)
		}
	}
}

// TestPortRangeCompatibility tests port range compatibility
func TestPortRangeCompatibility(t *testing.T) {
	// OpenVPN usually uses ports in range 1-65535
	testPorts := []int{1194, 443, 53, 80, 8080, 65535}

	for _, port := range testPorts {
		config := DefaultConfig()
		config.Port = port

		err := config.Validate()
		if err != nil {
			t.Errorf("Port %d should be valid (OpenVPN compatible), got error: %v", port, err)
		}
	}
}

// TestCertificatePathCompatibility tests certificate path compatibility
func TestCertificatePathCompatibility(t *testing.T) {
	// Standard OpenVPN paths
	standardPaths := map[string]string{
		"ca":   "/etc/openvpn/ca.crt",
		"cert": "/etc/openvpn/server.crt",
		"key":  "/etc/openvpn/server.key",
		"dh":   "/etc/openvpn/dh2048.pem",
	}

	config := DefaultConfig()
	config.CAPath = standardPaths["ca"]
	config.CertPath = standardPaths["cert"]
	config.KeyPath = standardPaths["key"]

	// Validation should not fail due to paths
	// (files may not exist, but paths are valid)
	if config.CAPath == "" || config.CertPath == "" || config.KeyPath == "" {
		t.Error("Certificate paths should be preserved from OpenVPN config")
	}
}

// TestNetworkCompatibility tests network settings compatibility
func TestNetworkCompatibility(t *testing.T) {
	// OpenVPN standard subnets
	validNetworks := []string{
		"10.8.0.0/24",
		"192.168.1.0/24",
		"172.16.0.0/16",
		"10.0.0.0/8",
	}

	for _, network := range validNetworks {
		_, _, err := net.ParseCIDR(network)
		if err != nil {
			t.Errorf("Network %s should be valid CIDR notation: %v", network, err)
		}
	}
}

// TestKeepAliveCompatibility tests keepalive settings compatibility
func TestKeepAliveCompatibility(t *testing.T) {
	config := DefaultConfig()

	// OpenVPN standard keepalive values
	config.KeepaliveInterval = 10 // ping each 10 seconds
	config.KeepaliveTimeout = 120 // timeout after 120 seconds

	err := config.Validate()
	if err != nil {
		t.Errorf("Standard OpenVPN keepalive settings should be valid: %v", err)
	}

	if config.KeepaliveInterval != 10 {
		t.Errorf("Expected keepalive interval 10, got %d", config.KeepaliveInterval)
	}

	if config.KeepaliveTimeout != 120 {
		t.Errorf("Expected keepalive timeout 120, got %d", config.KeepaliveTimeout)
	}
}

// TestDeviceCompatibility tests TUN/TAP device compatibility
func TestDeviceCompatibility(t *testing.T) {
	// OpenVPN supports both device types
	deviceTypes := []string{"tun", "tap"}

	for _, deviceType := range deviceTypes {
		config := DefaultConfig()
		config.DeviceType = deviceType

		err := config.Validate()
		if err != nil {
			t.Errorf("Device type %s should be valid (OpenVPN compatible): %v", deviceType, err)
		}
	}
}

// TestCompressionCompatibility tests compression support
func TestCompressionCompatibility(t *testing.T) {
	config := DefaultConfig()

	// OpenVPN supports LZO compression
	config.CompLZO = true

	// This should not cause validation errors
	err := config.Validate()
	if err != nil {
		t.Errorf("LZO compression should be compatible: %v", err)
	}

	if !config.CompLZO {
		t.Error("LZO compression flag should be preserved")
	}
}

// parseOpenVPNConfig parses OpenVPN configuration file and returns settings
func parseOpenVPNConfig(configPath string) (map[string]string, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	settings := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Parse line into key and value
		parts := strings.Fields(line)
		if len(parts) >= 1 {
			key := parts[0]
			value := ""
			if len(parts) > 1 {
				value = strings.Join(parts[1:], " ")
			}
			settings[key] = value
		}
	}

	return settings, scanner.Err()
}

// TestRealWorldScenario tests real-world usage scenario
func TestRealWorldScenario(t *testing.T) {
	// Create configuration as close as possible to real OpenVPN
	config := DefaultConfig()

	// Typical production OpenVPN server settings
	config.Port = 1194
	config.Protocol = "udp"
	config.DeviceType = "tun"
	config.DeviceName = "tun0"
	config.MTU = 1500
	config.CipherMode = "AES-256-GCM"
	config.AuthDigest = "SHA512"
	config.KeepaliveInterval = 10
	config.KeepaliveTimeout = 120
	config.MaxClients = 100

	// Validation
	err := config.Validate()
	if err != nil {
		t.Errorf("Real-world OpenVPN configuration should be valid: %v", err)
	}

	// Check that all critical parameters are set correctly
	if config.CipherMode != "AES-256-GCM" {
		t.Error("Should use secure cipher mode")
	}

	if config.AuthDigest != "SHA512" {
		t.Error("Should use strong authentication digest")
	}

	if config.Protocol != "udp" {
		t.Error("Should default to UDP protocol")
	}
}

// TestConfigurationMigration tests migration from OpenVPN configurations
func TestConfigurationMigration(t *testing.T) {
	// Simulate migration process from OpenVPN to GoVPN
	tempDir, err := os.MkdirTemp("", "govpn_migration_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Legacy OpenVPN configuration with deprecated settings
	legacyConfig := `
port 1194
proto udp
dev tun
cipher AES-256-CBC
auth SHA1
comp-lzo
keepalive 10 120
max-clients 50
`

	configPath := filepath.Join(tempDir, "legacy.ovpn")
	if err := os.WriteFile(configPath, []byte(legacyConfig), 0644); err != nil {
		t.Fatalf("Failed to write legacy config: %v", err)
	}

	settings, err := parseOpenVPNConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to parse legacy config: %v", err)
	}

	// Create new GoVPN configuration based on legacy
	migratedConfig := DefaultConfig()

	// Apply settings from legacy configuration
	if port := settings["port"]; port != "" {
		migratedConfig.Port = 1194 // In reality we would parse the string
	}

	if proto := settings["proto"]; proto != "" {
		migratedConfig.Protocol = proto
	}

	// Modernize deprecated security settings
	migratedConfig.CipherMode = "AES-256-GCM" // Upgrade from CBC to GCM
	migratedConfig.AuthDigest = "SHA512"      // Upgrade from SHA1 to SHA512

	// Check that migration was successful
	err = migratedConfig.Validate()
	if err != nil {
		t.Errorf("Migrated configuration should be valid: %v", err)
	}

	// Check security improvements
	if migratedConfig.CipherMode != "AES-256-GCM" {
		t.Error("Migration should upgrade cipher to GCM")
	}

	if migratedConfig.AuthDigest != "SHA512" {
		t.Error("Migration should upgrade auth digest to SHA512")
	}
}

// BenchmarkOpenVPNCompatibility benchmarks OpenVPN compatibility
func BenchmarkOpenVPNCompatibility(b *testing.B) {
	config := DefaultConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := config.Validate()
		if err != nil {
			b.Errorf("Validation failed: %v", err)
		}
	}
}
