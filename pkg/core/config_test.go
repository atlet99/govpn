package core

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	// Проверяем сетевые настройки
	if config.ListenAddress != "0.0.0.0" {
		t.Errorf("Expected ListenAddress '0.0.0.0', got '%s'", config.ListenAddress)
	}

	if config.Port != 1194 {
		t.Errorf("Expected Port 1194, got %d", config.Port)
	}

	if config.Protocol != "udp" {
		t.Errorf("Expected Protocol 'udp', got '%s'", config.Protocol)
	}

	// Проверяем настройки устройства
	if config.DeviceName != "tun0" {
		t.Errorf("Expected DeviceName 'tun0', got '%s'", config.DeviceName)
	}

	if config.DeviceType != "tun" {
		t.Errorf("Expected DeviceType 'tun', got '%s'", config.DeviceType)
	}

	if config.MTU != 1500 {
		t.Errorf("Expected MTU 1500, got %d", config.MTU)
	}

	// Проверяем настройки безопасности
	if config.CipherMode != "AES-256-GCM" {
		t.Errorf("Expected CipherMode 'AES-256-GCM', got '%s'", config.CipherMode)
	}

	if config.AuthDigest != "SHA512" {
		t.Errorf("Expected AuthDigest 'SHA512', got '%s'", config.AuthDigest)
	}

	if config.TLSVersion != "1.3" {
		t.Errorf("Expected TLSVersion '1.3', got '%s'", config.TLSVersion)
	}

	// Проверяем тайминги
	if config.HandshakeTimeout != 30*time.Second {
		t.Errorf("Expected HandshakeTimeout 30s, got %v", config.HandshakeTimeout)
	}

	// Проверяем CLI настройки
	if config.LogLevel != "info" {
		t.Errorf("Expected LogLevel 'info', got '%s'", config.LogLevel)
	}

	if config.LogOutput != "stdout" {
		t.Errorf("Expected LogOutput 'stdout', got '%s'", config.LogOutput)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Valid default config",
			config:  DefaultConfig(),
			wantErr: false,
		},
		{
			name: "Invalid port - too low",
			config: func() Config {
				c := DefaultConfig()
				c.Port = 0
				return c
			}(),
			wantErr: true,
			errMsg:  "invalid port number",
		},
		{
			name: "Invalid port - too high",
			config: func() Config {
				c := DefaultConfig()
				c.Port = 70000
				return c
			}(),
			wantErr: true,
			errMsg:  "invalid port number",
		},
		{
			name: "Invalid protocol",
			config: func() Config {
				c := DefaultConfig()
				c.Protocol = "invalid"
				return c
			}(),
			wantErr: true,
			errMsg:  "protocol must be tcp, udp, or both",
		},
		{
			name: "Invalid device type",
			config: func() Config {
				c := DefaultConfig()
				c.DeviceType = "invalid"
				return c
			}(),
			wantErr: true,
			errMsg:  "device type must be tun or tap",
		},
		{
			name: "Invalid MTU - too low",
			config: func() Config {
				c := DefaultConfig()
				c.MTU = 400
				return c
			}(),
			wantErr: true,
			errMsg:  "invalid MTU value",
		},
		{
			name: "Invalid MTU - too high",
			config: func() Config {
				c := DefaultConfig()
				c.MTU = 10000
				return c
			}(),
			wantErr: true,
			errMsg:  "invalid MTU value",
		},
		{
			name: "Missing CA path",
			config: func() Config {
				c := DefaultConfig()
				c.CAPath = ""
				return c
			}(),
			wantErr: true,
			errMsg:  "CA path is required",
		},
		{
			name: "Missing certificate path",
			config: func() Config {
				c := DefaultConfig()
				c.CertPath = ""
				return c
			}(),
			wantErr: true,
			errMsg:  "certificate path is required",
		},
		{
			name: "Missing key path",
			config: func() Config {
				c := DefaultConfig()
				c.KeyPath = ""
				return c
			}(),
			wantErr: true,
			errMsg:  "key path is required",
		},
		{
			name: "Invalid API port",
			config: func() Config {
				c := DefaultConfig()
				c.EnableAPI = true
				c.APIPort = 0
				return c
			}(),
			wantErr: true,
			errMsg:  "invalid API port number",
		},
		{
			name: "API auth enabled but no secret",
			config: func() Config {
				c := DefaultConfig()
				c.EnableAPI = true
				c.APIAuth = true
				c.APIAuthSecret = ""
				return c
			}(),
			wantErr: true,
			errMsg:  "API authentication enabled but no auth secret provided",
		},
		{
			name: "Invalid log output",
			config: func() Config {
				c := DefaultConfig()
				c.LogOutput = "invalid"
				return c
			}(),
			wantErr: true,
			errMsg:  "log output must be stdout, file, or syslog",
		},
		{
			name: "Log output file but no path",
			config: func() Config {
				c := DefaultConfig()
				c.LogOutput = "file"
				c.LogFilePath = ""
				return c
			}(),
			wantErr: true,
			errMsg:  "log file path is required when log output is file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("Config.Validate() error = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestConfigValidationWithValidSettings(t *testing.T) {
	config := DefaultConfig()

	// Тест с валидными API настройками
	config.EnableAPI = true
	config.APIPort = 8080
	config.APIAuth = true
	config.APIAuthSecret = "test-secret"

	if err := config.Validate(); err != nil {
		t.Errorf("Valid config should not return error: %v", err)
	}

	// Тест с файловым логированием
	config.LogOutput = "file"
	config.LogFilePath = "/tmp/govpn.log"

	if err := config.Validate(); err != nil {
		t.Errorf("Valid config with file logging should not return error: %v", err)
	}

	// Тест с syslog
	config.LogOutput = "syslog"
	config.LogFilePath = "" // Не требуется для syslog

	if err := config.Validate(); err != nil {
		t.Errorf("Valid config with syslog should not return error: %v", err)
	}
}

func TestConfigProtocolVariants(t *testing.T) {
	validProtocols := []string{"tcp", "udp", "both"}

	for _, protocol := range validProtocols {
		config := DefaultConfig()
		config.Protocol = protocol

		if err := config.Validate(); err != nil {
			t.Errorf("Protocol '%s' should be valid, got error: %v", protocol, err)
		}
	}
}

func TestConfigDeviceTypeVariants(t *testing.T) {
	validDeviceTypes := []string{"tun", "tap"}

	for _, deviceType := range validDeviceTypes {
		config := DefaultConfig()
		config.DeviceType = deviceType

		if err := config.Validate(); err != nil {
			t.Errorf("DeviceType '%s' should be valid, got error: %v", deviceType, err)
		}
	}
}
