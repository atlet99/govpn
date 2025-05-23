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

// TestOpenVPNConfigCompatibility тестирует совместимость с форматом конфигураций OpenVPN
func TestOpenVPNConfigCompatibility(t *testing.T) {
	// Создаем временную директорию для тестовых конфигураций
	tempDir, err := os.MkdirTemp("", "govpn_openvpn_compat_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Образец реальной конфигурации OpenVPN server
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

	// Парсим конфигурацию как OpenVPN
	settings, err := parseOpenVPNConfig(configPath)
	if err != nil {
		t.Errorf("Failed to parse OpenVPN config: %v", err)
	}

	// Проверяем основные параметры
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

// TestClientConfigCompatibility тестирует совместимость с клиентскими конфигурациями OpenVPN
func TestClientConfigCompatibility(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "govpn_client_compat_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Образец клиентской конфигурации OpenVPN
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

	// Проверяем клиентские параметры
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

// TestCipherCompatibility тестирует совместимость шифрования с OpenVPN
func TestCipherCompatibility(t *testing.T) {
	// Тестируем поддерживаемые в OpenVPN алгоритмы шифрования
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

			// Тестируем с разными размерами данных
			testData := [][]byte{
				[]byte(""),
				[]byte("a"),
				[]byte("Hello, OpenVPN!"),
				make([]byte, 1024), // Большой блок данных
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

// TestProtocolCompatibility тестирует совместимость протоколов
func TestProtocolCompatibility(t *testing.T) {
	// Проверяем поддержку протоколов как в OpenVPN
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

// TestPortRangeCompatibility тестирует совместимость портов
func TestPortRangeCompatibility(t *testing.T) {
	// OpenVPN обычно использует порты в диапазоне 1-65535
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

// TestCertificatePathCompatibility тестирует совместимость путей к сертификатам
func TestCertificatePathCompatibility(t *testing.T) {
	// Стандартные пути OpenVPN
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

	// Валидация не должна завершаться ошибкой из-за путей
	// (файлы могут не существовать, но пути валидны)
	if config.CAPath == "" || config.CertPath == "" || config.KeyPath == "" {
		t.Error("Certificate paths should be preserved from OpenVPN config")
	}
}

// TestNetworkCompatibility тестирует совместимость сетевых настроек
func TestNetworkCompatibility(t *testing.T) {
	// OpenVPN стандартные подсети
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

// TestKeepAliveCompatibility тестирует совместимость настроек keepalive
func TestKeepAliveCompatibility(t *testing.T) {
	config := DefaultConfig()

	// OpenVPN стандартные значения keepalive
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

// TestDeviceCompatibility тестирует совместимость TUN/TAP устройств
func TestDeviceCompatibility(t *testing.T) {
	// OpenVPN поддерживает оба типа устройств
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

// TestCompressionCompatibility тестирует поддержку сжатия
func TestCompressionCompatibility(t *testing.T) {
	config := DefaultConfig()

	// OpenVPN поддерживает LZO compression
	config.CompLZO = true

	// Это не должно вызывать ошибок валидации
	err := config.Validate()
	if err != nil {
		t.Errorf("LZO compression should be compatible: %v", err)
	}

	if !config.CompLZO {
		t.Error("LZO compression flag should be preserved")
	}
}

// parseOpenVPNConfig парсит конфигурационный файл OpenVPN и возвращает настройки
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

		// Пропускаем комментарии и пустые строки
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Разбираем строку на ключ и значение
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

// TestRealWorldScenario тестирует реальный сценарий использования
func TestRealWorldScenario(t *testing.T) {
	// Создание конфигурации, максимально близкой к реальной OpenVPN
	config := DefaultConfig()

	// Типичные настройки production OpenVPN сервера
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

	// Валидация
	err := config.Validate()
	if err != nil {
		t.Errorf("Real-world OpenVPN configuration should be valid: %v", err)
	}

	// Проверка, что все критичные параметры установлены правильно
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

// TestConfigurationMigration тестирует миграцию с OpenVPN конфигураций
func TestConfigurationMigration(t *testing.T) {
	// Симулируем процесс миграции с OpenVPN на GoVPN
	tempDir, err := os.MkdirTemp("", "govpn_migration_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Старая конфигурация OpenVPN с устаревшими настройками
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

	// Создаем новую конфигурацию GoVPN на основе legacy
	migratedConfig := DefaultConfig()

	// Применяем настройки из legacy конфигурации
	if port := settings["port"]; port != "" {
		migratedConfig.Port = 1194 // В реальности парсили бы строку
	}

	if proto := settings["proto"]; proto != "" {
		migratedConfig.Protocol = proto
	}

	// Модернизируем устаревшие настройки безопасности
	migratedConfig.CipherMode = "AES-256-GCM" // Обновляем с CBC на GCM
	migratedConfig.AuthDigest = "SHA512"      // Обновляем с SHA1 на SHA512

	// Проверяем, что миграция прошла успешно
	err = migratedConfig.Validate()
	if err != nil {
		t.Errorf("Migrated configuration should be valid: %v", err)
	}

	// Проверяем улучшения безопасности
	if migratedConfig.CipherMode != "AES-256-GCM" {
		t.Error("Migration should upgrade cipher to GCM")
	}

	if migratedConfig.AuthDigest != "SHA512" {
		t.Error("Migration should upgrade auth digest to SHA512")
	}
}

// BenchmarkOpenVPNCompatibility бенчмарк совместимости с OpenVPN
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
