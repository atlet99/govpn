package compat

import (
	"strings"
	"testing"
)

func TestParseConfigBasic(t *testing.T) {
	configData := `
# Basic OpenVPN configuration
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
`

	parser := NewConfigParser()
	config, err := parser.ParseConfig(strings.NewReader(configData))
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	// Test basic parameters
	if port, ok := config["port"].(int); !ok || port != 1194 {
		t.Errorf("Expected port 1194, got %v", config["port"])
	}

	if protocol, ok := config["protocol"].(string); !ok || protocol != "udp" {
		t.Errorf("Expected protocol 'udp', got %v", config["protocol"])
	}
}

func TestParseConfigAuthentication(t *testing.T) {
	configData := `
# Authentication configuration
auth-hash-method argon2
auth-argon2-memory 65536
auth-argon2-time 3
auth-argon2-threads 4
auth-session-timeout 3600
`

	parser := NewConfigParser()
	config, err := parser.ParseConfig(strings.NewReader(configData))
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	// Test authentication parameters
	if method, ok := config["auth_hash_method"].(string); !ok || method != "argon2" {
		t.Errorf("Expected auth_hash_method 'argon2', got %v", config["auth_hash_method"])
	}

	if memory, ok := config["auth_argon2_memory"].(int); !ok || memory != 65536 {
		t.Errorf("Expected auth_argon2_memory 65536, got %v", config["auth_argon2_memory"])
	}

	if timeout, ok := config["auth_session_timeout"].(int); !ok || timeout != 3600 {
		t.Errorf("Expected auth_session_timeout 3600, got %v", config["auth_session_timeout"])
	}
}

func TestParseConfigMFA(t *testing.T) {
	configData := `
# MFA configuration
mfa-enabled true
mfa-required-for-all false
mfa-issuer "GoVPN Test"
mfa-totp-period 30
mfa-totp-digits 6
mfa-backup-codes-count 10
`

	parser := NewConfigParser()
	config, err := parser.ParseConfig(strings.NewReader(configData))
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	// Test MFA parameters
	if enabled, ok := config["mfa_enabled"].(bool); !ok || !enabled {
		t.Errorf("Expected mfa_enabled true, got %v", config["mfa_enabled"])
	}

	if required, ok := config["mfa_required_for_all"].(bool); !ok || required {
		t.Errorf("Expected mfa_required_for_all false, got %v", config["mfa_required_for_all"])
	}

	if issuer, ok := config["mfa_issuer"].(string); !ok || issuer != "GoVPN Test" {
		t.Errorf("Expected mfa_issuer 'GoVPN Test', got %v", config["mfa_issuer"])
	}

	if digits, ok := config["mfa_totp_digits"].(int); !ok || digits != 6 {
		t.Errorf("Expected mfa_totp_digits 6, got %v", config["mfa_totp_digits"])
	}
}

func TestParseConfigOIDC(t *testing.T) {
	configData := `
# OIDC configuration
oidc-enabled true
oidc-provider-url https://auth.example.com
oidc-client-id test-client
oidc-scopes openid,profile,email
oidc-pkce-enabled true
`

	parser := NewConfigParser()
	config, err := parser.ParseConfig(strings.NewReader(configData))
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	// Test OIDC parameters
	if enabled, ok := config["oidc_enabled"].(bool); !ok || !enabled {
		t.Errorf("Expected oidc_enabled true, got %v", config["oidc_enabled"])
	}

	if url, ok := config["oidc_provider_url"].(string); !ok || url != "https://auth.example.com" {
		t.Errorf("Expected oidc_provider_url 'https://auth.example.com', got %v", config["oidc_provider_url"])
	}

	if scopes, ok := config["oidc_scopes"].([]string); !ok || len(scopes) != 3 {
		t.Errorf("Expected oidc_scopes with 3 elements, got %v", config["oidc_scopes"])
	} else {
		expected := []string{"openid", "profile", "email"}
		for i, scope := range expected {
			if scopes[i] != scope {
				t.Errorf("Expected scope %s, got %s", scope, scopes[i])
			}
		}
	}
}

func TestParseConfigLDAP(t *testing.T) {
	configData := `
# LDAP configuration
ldap-enabled true
ldap-server dc.example.com
ldap-port 389
ldap-use-tls true
ldap-bind-dn cn=reader,dc=example,dc=com
ldap-base-dn dc=example,dc=com
ldap-required-groups CN=VPN-Users,CN=Employees
`

	parser := NewConfigParser()
	config, err := parser.ParseConfig(strings.NewReader(configData))
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	// Test LDAP parameters
	if enabled, ok := config["ldap_enabled"].(bool); !ok || !enabled {
		t.Errorf("Expected ldap_enabled true, got %v", config["ldap_enabled"])
	}

	if server, ok := config["ldap_server"].(string); !ok || server != "dc.example.com" {
		t.Errorf("Expected ldap_server 'dc.example.com', got %v", config["ldap_server"])
	}

	if port, ok := config["ldap_port"].(int); !ok || port != 389 {
		t.Errorf("Expected ldap_port 389, got %v", config["ldap_port"])
	}

	if groups, ok := config["ldap_required_groups"].([]string); !ok || len(groups) != 2 {
		t.Errorf("Expected ldap_required_groups with 2 elements, got %v", config["ldap_required_groups"])
	}
}

func TestParseConfigObfuscation(t *testing.T) {
	configData := `
# Obfuscation configuration
obfuscation-enabled true
obfuscation-primary-method xor_cipher
xor-cipher-enabled true
xor-cipher-key MySecretKey123
packet-padding-enabled true
packet-padding-min-size 64
packet-padding-max-size 256
`

	parser := NewConfigParser()
	config, err := parser.ParseConfig(strings.NewReader(configData))
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	// Test obfuscation parameters
	if enabled, ok := config["obfuscation_enabled"].(bool); !ok || !enabled {
		t.Errorf("Expected obfuscation_enabled true, got %v", config["obfuscation_enabled"])
	}

	if method, ok := config["obfuscation_primary_method"].(string); !ok || method != "xor_cipher" {
		t.Errorf("Expected obfuscation_primary_method 'xor_cipher', got %v", config["obfuscation_primary_method"])
	}

	if key, ok := config["xor_cipher_key"].(string); !ok || key != "MySecretKey123" {
		t.Errorf("Expected xor_cipher_key 'MySecretKey123', got %v", config["xor_cipher_key"])
	}

	if minSize, ok := config["packet_padding_min_size"].(int); !ok || minSize != 64 {
		t.Errorf("Expected packet_padding_min_size 64, got %v", config["packet_padding_min_size"])
	}
}

func TestParseConfigComments(t *testing.T) {
	configData := `
# This is a comment
port 1194   # Comment after directive
# Another comment
proto udp
; Semicolon comment
dev tun
`

	parser := NewConfigParser()
	config, err := parser.ParseConfig(strings.NewReader(configData))
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	// Should have 3 parameters (comments ignored)
	expectedKeys := []string{"port", "protocol", "dev"}
	for _, key := range expectedKeys {
		if _, exists := config[key]; !exists {
			t.Errorf("Expected key %s to exist in config", key)
		}
	}
}

func TestParseConfigBooleanValues(t *testing.T) {
	testCases := []struct {
		input    string
		expected bool
	}{
		{"true", true},
		{"TRUE", true},
		{"yes", true},
		{"YES", true},
		{"1", true},
		{"on", true},
		{"ON", true},
		{"false", false},
		{"FALSE", false},
		{"no", false},
		{"NO", false},
		{"0", false},
		{"off", false},
		{"OFF", false},
	}

	for _, tc := range testCases {
		configData := "test-bool " + tc.input
		parser := NewConfigParser()
		config, err := parser.ParseConfig(strings.NewReader(configData))
		if err != nil {
			t.Fatalf("Failed to parse config with value %s: %v", tc.input, err)
		}

		if value := parseBoolValue(config["test-bool"]); value != tc.expected {
			t.Errorf("For input %s, expected %v, got %v", tc.input, tc.expected, value)
		}
	}
}

func TestParseConfigStringSlice(t *testing.T) {
	testCases := []struct {
		input    string
		expected []string
	}{
		{"single", []string{"single"}},
		{"one,two,three", []string{"one", "two", "three"}},
		{"spaced, values, here", []string{"spaced", "values", "here"}},
	}

	for _, tc := range testCases {
		result := parseStringSlice(tc.input)
		if len(result) != len(tc.expected) {
			t.Errorf("For input %s, expected length %d, got %d", tc.input, len(tc.expected), len(result))
			continue
		}

		for i, expected := range tc.expected {
			if result[i] != expected {
				t.Errorf("For input %s, at index %d expected %s, got %s", tc.input, i, expected, result[i])
			}
		}
	}
}
