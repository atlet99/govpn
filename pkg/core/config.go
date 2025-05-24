//go:build !windows
// +build !windows

package core

import (
	"errors"
	"time"
)

var (
	// ErrInvalidConfig indicates that the configuration is invalid
	ErrInvalidConfig = errors.New("invalid configuration")
)

// Config represents VPN server configuration
type Config struct {
	// Network settings
	ListenAddress string // Address to listen on
	Port          int    // Port to listen on
	Protocol      string // Protocol (tcp or udp)
	EnableTCP     bool   // Enable TCP server
	EnableUDP     bool   // Enable UDP server

	// Server network settings
	ServerNetwork string   // Server network CIDR (e.g., "10.8.0.0/24")
	Routes        []string // Routes to push to clients (CIDR notation)
	DNSServers    []string // DNS servers to push to clients

	// Device settings
	DeviceName  string // TUN/TAP device name
	DeviceType  string // Device type (tun or tap)
	MTU         int    // MTU size
	InternalDNS bool   // Whether to use internal DNS resolver

	// Security
	CipherMode string // Cipher mode
	AuthDigest string // Authentication digest
	TLSVersion string // TLS version (default: 1.3)
	AuthMode   string // Authentication mode

	// Certificate settings
	CAPath         string // CA certificate path
	CertPath       string // Server certificate path
	KeyPath        string // Server key path
	CRLPath        string // CRL path
	DHParamsPath   string // Diffie-Hellman parameters path
	TLSAuthKeyPath string // TLS authentication key path

	// Connection settings
	KeepaliveInterval int // Keepalive interval in seconds
	KeepaliveTimeout  int // Keepalive timeout in seconds
	MaxClients        int // Maximum number of clients

	// API settings
	EnableAPI        bool   // Enable REST API
	APIListenAddress string // API listen address
	APIPort          int    // API port
	APIAuth          bool   // Enable API authentication
	APIAuthSecret    string // API authentication secret

	// Timing settings (mostly for testing)
	HandshakeTimeout time.Duration // Handshake timeout
	ReadTimeout      time.Duration // Read timeout
	WriteTimeout     time.Duration // Write timeout

	// CLI settings
	ProfileName string // Current profile name
	ConfigPath  string // Path to current configuration file
	RunAsDaemon bool   // Whether to run as a daemon
	LogLevel    string // Log verbosity (error, warning, info, debug, trace)
	LogOutput   string // Log output (stdout, file, syslog)
	LogFilePath string // Log file path when LogOutput is "file"

	// Service settings
	ServiceName    string // Name for system service
	ServiceEnabled bool   // Whether to enable service

	// === AUTHENTICATION SETTINGS ===
	// Basic authentication
	EnablePasswordAuth   bool   // Enable password authentication
	AuthHashMethod       string // Hash method (argon2/pbkdf2)
	AuthArgon2Memory     int    // Argon2 memory in KB
	AuthArgon2Time       int    // Argon2 time iterations
	AuthArgon2Threads    int    // Argon2 threads
	AuthArgon2KeyLength  int    // Argon2 key length
	AuthPBKDF2Iterations int    // PBKDF2 iterations
	AuthPBKDF2KeyLength  int    // PBKDF2 key length
	AuthSaltLength       int    // Salt length
	AuthSessionTimeout   int    // Session timeout in seconds

	// MFA settings
	EnableMFA           bool   // Enable multi-factor authentication
	MFARequiredForAll   bool   // Require MFA for all users
	MFAIssuer           string // MFA issuer name
	MFAGracePeriod      int    // Grace period for MFA setup in seconds
	MFAMaxAttempts      int    // Maximum MFA attempts
	MFALockoutDuration  int    // MFA lockout duration in seconds
	MFATOTPEnabled      bool   // Enable TOTP
	MFATOTPPeriod       int    // TOTP period in seconds
	MFATOTPDigits       int    // TOTP digits
	MFATOTPAlgorithm    string // TOTP algorithm
	MFABackupCodesCount int    // Number of backup codes

	// OIDC settings
	EnableOIDC              bool     // Enable OIDC authentication
	OIDCProviderURL         string   // OIDC provider URL
	OIDCClientID            string   // OIDC client ID
	OIDCClientSecret        string   // OIDC client secret
	OIDCRedirectURL         string   // OIDC redirect URL
	OIDCScopes              []string // OIDC scopes
	OIDCSessionTimeout      int      // OIDC session timeout in seconds
	OIDCRefreshTokenEnabled bool     // Enable refresh tokens
	OIDCPKCEEnabled         bool     // Enable PKCE
	OIDCClaimUsername       string   // Username claim mapping
	OIDCClaimEmail          string   // Email claim mapping
	OIDCClaimGroups         string   // Groups claim mapping

	// LDAP settings
	EnableLDAP           bool     // Enable LDAP authentication
	LDAPServer           string   // LDAP server address
	LDAPPort             int      // LDAP server port
	LDAPUseSSL           bool     // Use SSL/LDAPS
	LDAPUseTLS           bool     // Use StartTLS
	LDAPSkipVerify       bool     // Skip certificate verification
	LDAPTimeout          int      // Connection timeout in seconds
	LDAPBindDN           string   // Bind DN for LDAP
	LDAPBindPassword     string   // Bind password for LDAP
	LDAPBaseDN           string   // Base DN for searches
	LDAPUserFilter       string   // User search filter
	LDAPGroupFilter      string   // Group search filter
	LDAPUserSearchBase   string   // User search base
	LDAPGroupSearchBase  string   // Group search base
	LDAPRequiredGroups   []string // Required groups for access
	LDAPAdminGroups      []string // Admin groups
	LDAPUserAttrUsername string   // Username attribute
	LDAPUserAttrEmail    string   // Email attribute
	LDAPUserAttrGroups   string   // Groups attribute

	// Obfuscation settings
	EnableObfuscation        bool     `json:"enable_obfuscation"`
	ObfuscationMethods       []string `json:"obfuscation_methods"`
	PrimaryObfuscation       string   `json:"primary_obfuscation"`
	FallbackObfuscations     []string `json:"fallback_obfuscations"`
	ObfuscationAutoDetect    bool     `json:"obfuscation_auto_detect"`
	RegionalProfile          string   `json:"regional_profile"`
	XORKey                   string   `json:"xor_key,omitempty"`
	XORCipherEnabled         bool     // Enable XOR cipher
	PacketPaddingEnabled     bool     // Enable packet padding
	PacketPaddingMinSize     int      // Minimum padding size
	PacketPaddingMaxSize     int      // Maximum padding size
	TimingObfuscationEnabled bool     // Enable timing obfuscation
	TLSTunnelEnabled         bool     // Enable TLS tunnel
	TLSTunnelPort            int      // TLS tunnel port
	HTTPMimicryEnabled       bool     // Enable HTTP mimicry

	// Legacy settings
	CompLZO bool // Use LZO compression
}

// DefaultConfig returns default configuration
func DefaultConfig() Config {
	return Config{
		// Network settings
		ListenAddress: "0.0.0.0",
		Port:          1194,
		Protocol:      "udp",
		EnableTCP:     true,
		EnableUDP:     true,
		ServerNetwork: "10.8.0.0/24",

		// Device settings
		DeviceName:  "tun0",
		DeviceType:  "tun",
		MTU:         1500,
		InternalDNS: false,

		// Security
		CipherMode: "AES-256-GCM",
		AuthDigest: "SHA512",
		TLSVersion: "1.3",
		AuthMode:   "certificate",

		// Certificate settings
		CAPath:         "certs/ca.crt",
		CertPath:       "certs/server.crt",
		KeyPath:        "certs/server.key",
		CRLPath:        "certs/crl.pem",
		DHParamsPath:   "certs/dh4096.pem",
		TLSAuthKeyPath: "certs/ta.key",

		// Connection settings
		KeepaliveInterval: 10,
		KeepaliveTimeout:  60,
		MaxClients:        100,

		// API settings
		EnableAPI:        false,
		APIListenAddress: "127.0.0.1",
		APIPort:          8080,
		APIAuth:          true,
		APIAuthSecret:    "",

		// Timing settings
		HandshakeTimeout: time.Duration(30) * time.Second,
		ReadTimeout:      time.Duration(5) * time.Second,
		WriteTimeout:     time.Duration(5) * time.Second,

		// Push settings
		Routes:     []string{},
		DNSServers: []string{"8.8.8.8", "8.8.4.4"},

		// CLI settings
		ProfileName: "default",
		RunAsDaemon: false,
		LogLevel:    "info",
		LogOutput:   "stdout",

		// Service settings
		ServiceName:    "govpn",
		ServiceEnabled: false,

		// === AUTHENTICATION DEFAULTS ===
		// Basic authentication
		EnablePasswordAuth:   false,
		AuthHashMethod:       "argon2",
		AuthArgon2Memory:     65536, // 64MB
		AuthArgon2Time:       3,
		AuthArgon2Threads:    4,
		AuthArgon2KeyLength:  32,
		AuthPBKDF2Iterations: 100000,
		AuthPBKDF2KeyLength:  32,
		AuthSaltLength:       16,
		AuthSessionTimeout:   3600, // 1 hour

		// MFA defaults
		EnableMFA:           false,
		MFARequiredForAll:   false,
		MFAIssuer:           "GoVPN",
		MFAGracePeriod:      300, // 5 minutes
		MFAMaxAttempts:      5,
		MFALockoutDuration:  900, // 15 minutes
		MFATOTPEnabled:      true,
		MFATOTPPeriod:       30,
		MFATOTPDigits:       6,
		MFATOTPAlgorithm:    "SHA1",
		MFABackupCodesCount: 10,

		// OIDC defaults
		EnableOIDC:              false,
		OIDCSessionTimeout:      86400, // 24 hours
		OIDCRefreshTokenEnabled: true,
		OIDCPKCEEnabled:         true,
		OIDCClaimUsername:       "preferred_username",
		OIDCClaimEmail:          "email",
		OIDCClaimGroups:         "groups",

		// LDAP defaults
		EnableLDAP:           false,
		LDAPPort:             389,
		LDAPUseSSL:           false,
		LDAPUseTLS:           true,
		LDAPSkipVerify:       false,
		LDAPTimeout:          10,
		LDAPUserAttrUsername: "sAMAccountName",
		LDAPUserAttrEmail:    "mail",
		LDAPUserAttrGroups:   "memberOf",

		// Obfuscation settings
		EnableObfuscation:        false,
		ObfuscationMethods:       []string{"xor_cipher"},
		PrimaryObfuscation:       "xor_cipher",
		FallbackObfuscations:     []string{},
		ObfuscationAutoDetect:    false,
		RegionalProfile:          "",
		XORKey:                   "",
		XORCipherEnabled:         false,
		PacketPaddingEnabled:     false,
		PacketPaddingMinSize:     32,
		PacketPaddingMaxSize:     128,
		TimingObfuscationEnabled: false,
		TLSTunnelEnabled:         false,
		TLSTunnelPort:            443,
		HTTPMimicryEnabled:       false,

		// Legacy settings
		CompLZO: false,
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Port <= 0 || c.Port > 65535 {
		return errors.New("invalid port number")
	}

	if c.Protocol != "tcp" && c.Protocol != "udp" && c.Protocol != "both" {
		return errors.New("protocol must be tcp, udp, or both")
	}

	if c.DeviceType != "tun" && c.DeviceType != "tap" {
		return errors.New("device type must be tun or tap")
	}

	if c.MTU < 576 || c.MTU > 9000 {
		return errors.New("invalid MTU value")
	}

	// We always use TLS in this implementation
	if c.CAPath == "" {
		return errors.New("CA path is required")
	}

	if c.CertPath == "" {
		return errors.New("certificate path is required")
	}

	if c.KeyPath == "" {
		return errors.New("key path is required")
	}

	// API validation
	if c.EnableAPI {
		if c.APIPort <= 0 || c.APIPort > 65535 {
			return errors.New("invalid API port number")
		}

		if c.APIAuth && c.APIAuthSecret == "" {
			return errors.New("API authentication enabled but no auth secret provided")
		}
	}

	// Log validation
	if c.LogOutput != "stdout" && c.LogOutput != "file" && c.LogOutput != "syslog" {
		return errors.New("log output must be stdout, file, or syslog")
	}

	if c.LogOutput == "file" && c.LogFilePath == "" {
		return errors.New("log file path is required when log output is file")
	}

	return nil
}
