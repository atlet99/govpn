package compat

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// OpenVPNConfigParserImpl implements the OpenVPNConfigParser interface
type OpenVPNConfigParserImpl struct{}

// NewConfigParser creates a new OpenVPN configuration parser
func NewConfigParser() OpenVPNConfigParser {
	return &OpenVPNConfigParserImpl{}
}

// ParseConfig parses OpenVPN configuration from an io.Reader
func (p *OpenVPNConfigParserImpl) ParseConfig(reader io.Reader) (map[string]interface{}, error) {
	config := make(map[string]interface{})
	scanner := bufio.NewScanner(reader)

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		// Remove comments and handle empty lines
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Parse directive
		directive, value, err := parseDirective(line)
		if err != nil {
			return nil, fmt.Errorf("error in line %d: %w", lineNumber, err)
		}

		// Add directive to configuration
		addDirectiveToConfig(config, directive, value)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading configuration: %w", err)
	}

	return config, nil
}

// ParseConfigFile parses OpenVPN configuration from a file
func (p *OpenVPNConfigParserImpl) ParseConfigFile(path string) (map[string]interface{}, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open configuration file: %w", err)
	}
	defer file.Close()

	return p.ParseConfig(file)
}

// parseDirective parses a line into directive and value
func parseDirective(line string) (string, interface{}, error) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", nil, fmt.Errorf("empty line")
	}

	directive := parts[0]

	// Directives without values
	if len(parts) == 1 {
		return directive, true, nil
	}

	// Handle quoted strings - rejoin if the value starts with a quote
	if len(parts) > 1 {
		remaining := strings.Join(parts[1:], " ")

		// Check if the value is quoted
		if strings.HasPrefix(remaining, "\"") && strings.HasSuffix(remaining, "\"") && len(remaining) > 1 {
			// Remove quotes and return as single string
			return directive, remaining[1 : len(remaining)-1], nil
		}

		// Directives with one value
		if len(parts) == 2 {
			return directive, parts[1], nil
		}

		// Directives with multiple values
		return directive, parts[1:], nil
	}

	return directive, parts[1], nil
}

// addDirectiveToConfig adds a directive to the configuration
func addDirectiveToConfig(config map[string]interface{}, directive string, value interface{}) {
	// Handle special cases
	switch directive {
	case "port":
		if strValue, ok := value.(string); ok {
			if port, err := strconv.Atoi(strValue); err == nil {
				config[directive] = port
			} else {
				config[directive] = strValue
			}
		} else {
			config[directive] = value
		}
	case "proto":
		config["protocol"] = value
	case "server":
		if strValues, ok := value.([]string); ok && len(strValues) >= 2 {
			config[directive] = strValues
			config["server_network"] = strings.Join([]string{strValues[0], strValues[1]}, " ")
		} else {
			config[directive] = value
		}
	case "push":
		if strValues, ok := value.([]string); ok {
			if pushes, exists := config["push"]; exists {
				if pushSlice, ok := pushes.([]string); ok {
					config["push"] = append(pushSlice, strings.Join(strValues, " "))
				} else {
					config["push"] = []string{strings.Join(strValues, " ")}
				}
			} else {
				config["push"] = []string{strings.Join(strValues, " ")}
			}
		}
	case "route":
		if strValues, ok := value.([]string); ok {
			if routes, exists := config["routes"]; exists {
				if routeSlice, ok := routes.([]string); ok {
					config["routes"] = append(routeSlice, strings.Join(strValues, " "))
				} else {
					config["routes"] = []string{strings.Join(strValues, " ")}
				}
			} else {
				config["routes"] = []string{strings.Join(strValues, " ")}
			}
		}
	case "verb":
		if strValue, ok := value.(string); ok {
			if verbLevel, err := strconv.Atoi(strValue); err == nil {
				config[directive] = verbLevel
				// Convert OpenVPN verbosity levels to logging levels
				switch {
				case verbLevel <= 2:
					config["log_level"] = "error"
				case verbLevel == 3:
					config["log_level"] = "warning"
				case verbLevel == 4:
					config["log_level"] = "info"
				default:
					config["log_level"] = "debug"
				}
			} else {
				config[directive] = strValue
			}
		}

	// === AUTHENTICATION PARAMETERS ===
	case "auth-user-pass-verify":
		config["auth_user_pass_verify"] = value
		config["enable_password_auth"] = true
	case "auth-user-pass-optional":
		if strValue, ok := value.(string); ok {
			config["auth_user_pass_optional"] = parseBoolValue(strValue)
		} else {
			config["auth_user_pass_optional"] = value
		}
	case "auth-hash-method":
		config["auth_hash_method"] = value
	case "auth-argon2-memory":
		config["auth_argon2_memory"] = parseIntValue(value)
	case "auth-argon2-time":
		config["auth_argon2_time"] = parseIntValue(value)
	case "auth-argon2-threads":
		config["auth_argon2_threads"] = parseIntValue(value)
	case "auth-argon2-key-length":
		config["auth_argon2_key_length"] = parseIntValue(value)
	case "auth-pbkdf2-iterations":
		config["auth_pbkdf2_iterations"] = parseIntValue(value)
	case "auth-pbkdf2-key-length":
		config["auth_pbkdf2_key_length"] = parseIntValue(value)
	case "auth-salt-length":
		config["auth_salt_length"] = parseIntValue(value)
	case "auth-session-timeout":
		config["auth_session_timeout"] = parseIntValue(value)

	// === MFA PARAMETERS ===
	case "mfa-enabled":
		config["mfa_enabled"] = parseBoolValue(value)
	case "mfa-required-for-all":
		config["mfa_required_for_all"] = parseBoolValue(value)
	case "mfa-issuer":
		config["mfa_issuer"] = value
	case "mfa-grace-period":
		config["mfa_grace_period"] = parseIntValue(value)
	case "mfa-max-attempts":
		config["mfa_max_attempts"] = parseIntValue(value)
	case "mfa-lockout-duration":
		config["mfa_lockout_duration"] = parseIntValue(value)
	case "mfa-totp-enabled":
		config["mfa_totp_enabled"] = parseBoolValue(value)
	case "mfa-totp-period":
		config["mfa_totp_period"] = parseIntValue(value)
	case "mfa-totp-digits":
		config["mfa_totp_digits"] = parseIntValue(value)
	case "mfa-totp-algorithm":
		config["mfa_totp_algorithm"] = value
	case "mfa-backup-codes-count":
		config["mfa_backup_codes_count"] = parseIntValue(value)

	// === OIDC PARAMETERS ===
	case "oidc-enabled":
		config["oidc_enabled"] = parseBoolValue(value)
	case "oidc-provider-url":
		config["oidc_provider_url"] = value
	case "oidc-client-id":
		config["oidc_client_id"] = value
	case "oidc-client-secret":
		config["oidc_client_secret"] = value
	case "oidc-redirect-url":
		config["oidc_redirect_url"] = value
	case "oidc-scopes":
		config["oidc_scopes"] = parseStringSlice(value)
	case "oidc-session-timeout":
		config["oidc_session_timeout"] = parseIntValue(value)
	case "oidc-refresh-token-enabled":
		config["oidc_refresh_token_enabled"] = parseBoolValue(value)
	case "oidc-pkce-enabled":
		config["oidc_pkce_enabled"] = parseBoolValue(value)
	case "oidc-claim-username":
		config["oidc_claim_username"] = value
	case "oidc-claim-email":
		config["oidc_claim_email"] = value
	case "oidc-claim-groups":
		config["oidc_claim_groups"] = value

	// === LDAP PARAMETERS ===
	case "ldap-enabled":
		config["ldap_enabled"] = parseBoolValue(value)
	case "ldap-server":
		config["ldap_server"] = value
	case "ldap-port":
		config["ldap_port"] = parseIntValue(value)
	case "ldap-use-ssl":
		config["ldap_use_ssl"] = parseBoolValue(value)
	case "ldap-use-tls":
		config["ldap_use_tls"] = parseBoolValue(value)
	case "ldap-skip-verify":
		config["ldap_skip_verify"] = parseBoolValue(value)
	case "ldap-timeout":
		config["ldap_timeout"] = parseIntValue(value)
	case "ldap-bind-dn":
		config["ldap_bind_dn"] = value
	case "ldap-bind-password":
		config["ldap_bind_password"] = value
	case "ldap-base-dn":
		config["ldap_base_dn"] = value
	case "ldap-user-filter":
		config["ldap_user_filter"] = value
	case "ldap-group-filter":
		config["ldap_group_filter"] = value
	case "ldap-user-search-base":
		config["ldap_user_search_base"] = value
	case "ldap-group-search-base":
		config["ldap_group_search_base"] = value
	case "ldap-required-groups":
		config["ldap_required_groups"] = parseStringSlice(value)
	case "ldap-admin-groups":
		config["ldap_admin_groups"] = parseStringSlice(value)
	case "ldap-user-attr-username":
		config["ldap_user_attr_username"] = value
	case "ldap-user-attr-email":
		config["ldap_user_attr_email"] = value
	case "ldap-user-attr-groups":
		config["ldap_user_attr_groups"] = value

	// === OBFUSCATION PARAMETERS ===
	case "obfuscation-enabled":
		config["obfuscation_enabled"] = parseBoolValue(value)
	case "obfuscation-auto-detect":
		config["obfuscation_auto_detect"] = parseBoolValue(value)
	case "obfuscation-primary-method":
		config["obfuscation_primary_method"] = value
	case "obfuscation-fallback-methods":
		config["obfuscation_fallback_methods"] = parseStringSlice(value)
	case "xor-cipher-enabled":
		config["xor_cipher_enabled"] = parseBoolValue(value)
	case "xor-cipher-key":
		config["xor_cipher_key"] = value
	case "packet-padding-enabled":
		config["packet_padding_enabled"] = parseBoolValue(value)
	case "packet-padding-min-size":
		config["packet_padding_min_size"] = parseIntValue(value)
	case "packet-padding-max-size":
		config["packet_padding_max_size"] = parseIntValue(value)
	case "timing-obfuscation-enabled":
		config["timing_obfuscation_enabled"] = parseBoolValue(value)
	case "tls-tunnel-enabled":
		config["tls_tunnel_enabled"] = parseBoolValue(value)
	case "tls-tunnel-port":
		config["tls_tunnel_port"] = parseIntValue(value)
	case "http-mimicry-enabled":
		config["http_mimicry_enabled"] = parseBoolValue(value)

	// === INCLUDE DIRECTIVES ===
	case "include", "config":
		// Handle included configuration files
		if includeFile, ok := value.(string); ok {
			config["included_files"] = append(getStringSliceValue(config, "included_files"), includeFile)
		}

	default:
		config[directive] = value
	}
}

// Helper functions for parsing values
func parseIntValue(value interface{}) int {
	switch v := value.(type) {
	case string:
		if intValue, err := strconv.Atoi(v); err == nil {
			return intValue
		}
	case int:
		return v
	}
	return 0
}

func parseBoolValue(value interface{}) bool {
	switch v := value.(type) {
	case string:
		lower := strings.ToLower(v)
		return lower == "true" || lower == "yes" || lower == "1" || lower == "on"
	case bool:
		return v
	}
	return false
}

func parseStringSlice(value interface{}) []string {
	switch v := value.(type) {
	case string:
		// Handle comma-separated values
		if strings.Contains(v, ",") {
			parts := strings.Split(v, ",")
			var result []string
			for _, part := range parts {
				result = append(result, strings.TrimSpace(part))
			}
			return result
		}
		return []string{v}
	case []string:
		return v
	}
	return nil
}

func getStringSliceValue(config map[string]interface{}, key string) []string {
	if value, exists := config[key]; exists {
		if slice, ok := value.([]string); ok {
			return slice
		}
	}
	return []string{}
}
