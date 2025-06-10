package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/atlet99/govpn/pkg/compat"
	"github.com/atlet99/govpn/pkg/core"
	"github.com/atlet99/govpn/pkg/server"
)

const (
	// DefaultPort default OpenVPN port
	DefaultPort = 1194

	// DefaultProtocol default protocol
	DefaultProtocol = "udp"

	// DefaultListenAddress default address to listen on
	DefaultListenAddress = "0.0.0.0"

	// DefaultDevice default device type
	DefaultDevice = "tun"

	// DefaultServerAddr default VPN server address
	DefaultServerAddr = "10.8.0.0"

	// DefaultServerMask default VPN server subnet mask
	DefaultServerMask = "255.255.255.0"

	// DefaultCipher default encryption algorithm
	DefaultCipher = "AES-256-GCM"

	// DefaultAuth default authentication algorithm
	DefaultAuth = "SHA256"

	// DefaultKeepalive default keepalive interval
	DefaultKeepalive = 10

	// DefaultKeepaliveTimeout default keepalive timeout
	DefaultKeepaliveTimeout = 120

	// DefaultAPIPort default API port
	DefaultAPIPort = 8080

	// DefaultAPIListenAddress default API listen address
	DefaultAPIListenAddress = "127.0.0.1"
)

// Command line flags
var (
	// Basic configuration options
	configFile  = flag.String("config", "", "Path to OpenVPN configuration file")
	configDir   = flag.String("config-dir", "", "Path to directory with configuration files")
	port        = flag.Int("port", DefaultPort, "Port to listen on")
	proto       = flag.String("proto", DefaultProtocol, "Protocol (udp or tcp)")
	listenAddr  = flag.String("listen", DefaultListenAddress, "Address to listen on")
	device      = flag.String("dev", DefaultDevice, "Device type (tun or tap)")
	serverAddr  = flag.String("server", DefaultServerAddr, "VPN server subnet")
	serverMask  = flag.String("mask", DefaultServerMask, "VPN server subnet mask")
	certFile    = flag.String("cert", "", "Path to server certificate file")
	keyFile     = flag.String("key", "", "Path to server key file")
	caFile      = flag.String("ca", "", "Path to CA file")
	cipher      = flag.String("cipher", DefaultCipher, "Encryption cipher")
	auth        = flag.String("auth", DefaultAuth, "Authentication algorithm")
	keepalive   = flag.Int("keepalive", DefaultKeepalive, "Keepalive interval in seconds")
	keepTimeout = flag.Int("keepalive-timeout", DefaultKeepaliveTimeout, "Keepalive timeout in seconds")

	// API options
	enableAPI     = flag.Bool("api", false, "Enable REST API")
	apiPort       = flag.Int("api-port", DefaultAPIPort, "REST API port")
	apiListenAddr = flag.String("api-listen", DefaultAPIListenAddress, "REST API listen address")
	apiAuth       = flag.Bool("api-auth", false, "Enable API authentication")
	apiAuthSecret = flag.String("api-auth-secret", "", "API authentication secret key")

	// CLI improvements
	daemon      = flag.Bool("daemon", false, "Run as a daemon")
	logLevel    = flag.String("log-level", "info", "Log level (error, warning, info, debug, trace)")
	logOutput   = flag.String("log-output", "stdout", "Log output (stdout, file, syslog)")
	logFile     = flag.String("log-file", "", "Log file path when log output is file")
	profileName = flag.String("profile", "", "Use specific profile from profiles directory")
	status      = flag.String("status", "", "Output status to file with specified interval (example: /var/log/govpn-status.log 10)")
	statsDump   = flag.Bool("stats", false, "Display server statistics and exit")
	version     = flag.Bool("version", false, "Display version information and exit")

	// Service management
	service = flag.String("service", "", "Service management (install, remove, start, stop)")

	// Track which flags were explicitly set on the command line
	explicitFlags = make(map[string]bool)

	// Obfuscation flags
	enableObfuscation = flag.Bool("obfuscation", false, "Enable traffic obfuscation")
	obfuscationMethod = flag.String("obfuscation-method", "xor_cipher", "Primary obfuscation method")
	regionalProfile   = flag.String("regional-profile", "", "Regional obfuscation profile (china, iran, russia)")
	xorKey            = flag.String("xor-key", "", "XOR key for obfuscation (hex string)")
)

func main() {
	// Parse flags and record which ones were explicitly set
	flag.Parse()
	flag.Visit(func(f *flag.Flag) {
		explicitFlags[f.Name] = true
	})

	// Check for version flag
	if *version {
		fmt.Printf("GoVPN Server v%s (OpenVPN compatible)\n", getVersion())
		os.Exit(0)
	}

	// Check for stats dump flag
	if *statsDump {
		dumpStats()
		os.Exit(0)
	}

	// Check for service management
	if *service != "" {
		handleServiceCommand(*service)
		os.Exit(0)
	}

	// Setup logging
	setupLogging(*logOutput, *logFile, *logLevel)

	// Get configuration
	vpnConfig := loadConfiguration()

	// Validate configuration
	if err := validateServerConfig(vpnConfig); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Configure obfuscation if enabled
	if *enableObfuscation {
		vpnConfig.EnableObfuscation = true
		vpnConfig.PrimaryObfuscation = *obfuscationMethod
		vpnConfig.ObfuscationMethods = []string{*obfuscationMethod}
		vpnConfig.RegionalProfile = *regionalProfile
		vpnConfig.XORKey = *xorKey
		vpnConfig.ObfuscationAutoDetect = true

		log.Printf("Obfuscation enabled with method: %s", *obfuscationMethod)
		if *regionalProfile != "" {
			log.Printf("Using regional profile: %s", *regionalProfile)
		}
	}

	// Create server configuration
	serverConfig := &server.Config{
		VPNConfig: vpnConfig,
		EnableAPI: *enableAPI || vpnConfig.EnableAPI,
	}

	// Create server
	mainServer, err := server.NewServer(serverConfig)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Run as daemon if requested
	if *daemon || vpnConfig.RunAsDaemon {
		if err := runAsDaemon(); err != nil {
			log.Fatalf("Failed to run as daemon: %v", err)
		}
	}

	// Setup signal handling for graceful termination
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	setupSignalHandling(cancel)

	// Start server
	if err := mainServer.Start(ctx); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	log.Printf("GoVPN server started on %s:%d", vpnConfig.ListenAddress, vpnConfig.Port)
	if vpnConfig.EnableAPI {
		log.Printf("REST API available at http://%s:%d/api/v1", vpnConfig.APIListenAddress, vpnConfig.APIPort)
	}

	// Set up status file if requested
	if *status != "" {
		parts := strings.SplitN(*status, " ", 2)
		statusPath := parts[0]
		interval := 10 // Default interval of 10 seconds

		if len(parts) > 1 {
			if i, err := strconv.Atoi(parts[1]); err == nil && i > 0 {
				interval = i
			}
		}

		setupStatusFile(mainServer, statusPath, interval)
	}

	// Wait for context cancellation
	<-ctx.Done()

	// Stop server
	if err := mainServer.Stop(); err != nil {
		log.Printf("Error stopping server: %v", err)
	}
}

// getDefaultDeviceName returns a default device name for the current OS
func getDefaultDeviceName() string {
	switch runtime.GOOS {
	case "windows":
		return "govpn"
	case "darwin":
		return "utun8"
	default:
		return "tun1"
	}
}

// setupSignalHandling sets up signal handling for graceful termination
func setupSignalHandling(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigChan {
			log.Printf("Received signal %v", sig)

			switch sig {
			case syscall.SIGHUP:
				log.Println("Reloading configuration...")
				// TODO: Implement hot reload logic
			default:
				log.Println("Shutting down...")
				cancel()
				return
			}
		}
	}()
}

// loadConfiguration loads the VPN configuration from file or command line arguments
func loadConfiguration() core.Config {
	// First priority: explicit config file path
	if *configFile != "" {
		config, err := loadConfigFile(*configFile)
		if err != nil {
			log.Fatalf("Error loading configuration file: %v", err)
		}
		return config
	}

	// Second priority: named profile
	if *profileName != "" {
		config, err := loadProfile(*profileName)
		if err != nil {
			log.Fatalf("Error loading profile '%s': %v", *profileName, err)
		}
		return config
	}

	// Third priority: config directory
	if *configDir != "" {
		config, err := loadConfigDir(*configDir)
		if err != nil {
			log.Fatalf("Error loading configuration directory: %v", err)
		}
		return config
	}

	// Fourth priority: standard locations
	configPath, err := core.FindConfigFile()
	if err == nil {
		config, err := loadConfigFile(configPath)
		if err == nil {
			return config
		}
	}

	// Last priority: command line parameters and defaults
	return createConfigFromFlags()
}

// loadConfigFile loads a configuration from a file
func loadConfigFile(path string) (core.Config, error) {
	// Parse configuration file
	parser := compat.NewConfigParser()
	openvpnConfig, err := parser.ParseConfigFile(path)
	if err != nil {
		return core.Config{}, fmt.Errorf("error parsing configuration file: %w", err)
	}

	// Convert OpenVPN configuration to GoVPN configuration
	config := convertConfig(openvpnConfig)
	config.ConfigPath = path

	// Override with command line flags
	applyConfigOverrides(&config)

	return config, nil
}

// loadProfile loads a configuration from a named profile
func loadProfile(name string) (core.Config, error) {
	// Search for profile in standard locations
	for _, dir := range core.DefaultConfigDirs {
		profilePath := filepath.Join(dir, core.DefaultProfilesDir, name+".ovpn")
		if fileExists(profilePath) {
			config, err := loadConfigFile(profilePath)
			if err != nil {
				return core.Config{}, err
			}

			config.ProfileName = name
			return config, nil
		}
	}

	return core.Config{}, fmt.Errorf("profile '%s' not found", name)
}

// loadConfigDir loads a configuration from a directory containing configuration files
func loadConfigDir(dir string) (core.Config, error) {
	// Check if directory exists
	if !dirExists(dir) {
		return core.Config{}, fmt.Errorf("directory '%s' does not exist", dir)
	}

	// Load first .ovpn file found
	files, err := filepath.Glob(filepath.Join(dir, "*.ovpn"))
	if err != nil {
		return core.Config{}, fmt.Errorf("error searching directory: %w", err)
	}

	if len(files) == 0 {
		return core.Config{}, fmt.Errorf("no configuration files found in '%s'", dir)
	}

	// Use the first file found
	return loadConfigFile(files[0])
}

// createConfigFromFlags creates a configuration from command line flags
func createConfigFromFlags() core.Config {
	// Convert IP + mask to CIDR format
	serverNetwork := convertToCIDR(*serverAddr, *serverMask)

	return core.Config{
		DeviceType:        *device,
		ListenAddress:     *listenAddr,
		Protocol:          *proto,
		Port:              *port,
		ServerNetwork:     serverNetwork,
		DeviceName:        getDefaultDeviceName(),
		CertPath:          *certFile,
		KeyPath:           *keyFile,
		CAPath:            *caFile,
		CipherMode:        *cipher,
		AuthDigest:        *auth,
		KeepaliveInterval: *keepalive,
		KeepaliveTimeout:  *keepTimeout,

		// API settings
		EnableAPI:        *enableAPI,
		APIPort:          *apiPort,
		APIListenAddress: *apiListenAddr,
		APIAuth:          *apiAuth,
		APIAuthSecret:    *apiAuthSecret,

		// CLI settings
		RunAsDaemon: *daemon,
		LogLevel:    *logLevel,
		LogOutput:   *logOutput,
		LogFilePath: *logFile,
	}
}

// applyConfigOverrides applies command line flag overrides to a loaded configuration
func applyConfigOverrides(config *core.Config) {
	// Only override if explicitly specified on command line
	if explicitFlags["port"] {
		config.Port = *port
	}
	if explicitFlags["proto"] {
		config.Protocol = *proto
	}
	if explicitFlags["listen"] {
		config.ListenAddress = *listenAddr
	}
	if explicitFlags["dev"] {
		config.DeviceType = *device
	}
	if explicitFlags["api"] {
		config.EnableAPI = *enableAPI
	}
	if explicitFlags["api-port"] {
		config.APIPort = *apiPort
	}
	if explicitFlags["api-listen"] {
		config.APIListenAddress = *apiListenAddr
	}
	if explicitFlags["api-auth"] {
		config.APIAuth = *apiAuth
	}
	if explicitFlags["api-auth-secret"] {
		config.APIAuthSecret = *apiAuthSecret
	}
	if explicitFlags["daemon"] {
		config.RunAsDaemon = *daemon
	}
	if explicitFlags["log-level"] {
		config.LogLevel = *logLevel
	}
	if explicitFlags["log-output"] {
		config.LogOutput = *logOutput
	}
	if explicitFlags["log-file"] {
		config.LogFilePath = *logFile
	}
}

// convertConfig converts OpenVPN configuration to GoVPN configuration
func convertConfig(openvpnConfig map[string]interface{}) core.Config {
	// Convert server network from OpenVPN format to CIDR format
	serverNetworkStr := getStringValue(openvpnConfig, "server_network", "10.8.0.0 255.255.255.0")
	serverNetwork := convertServerNetworkToCIDR(serverNetworkStr)

	config := core.Config{
		DeviceType:        getStringValue(openvpnConfig, "dev", "tun"),
		DeviceName:        getDefaultDeviceName(),
		ListenAddress:     getStringValue(openvpnConfig, "local", "0.0.0.0"),
		Protocol:          getStringValue(openvpnConfig, "protocol", "udp"),
		Port:              getIntValue(openvpnConfig, "port", 1194),
		EnableTCP:         getBoolValue(openvpnConfig, "tcp_enabled", true),
		EnableUDP:         getBoolValue(openvpnConfig, "udp_enabled", true),
		ServerNetwork:     serverNetwork,
		DNSServers:        getStringSlice(openvpnConfig, "dns"),
		CipherMode:        getStringValue(openvpnConfig, "cipher", "AES-256-GCM"),
		AuthDigest:        getStringValue(openvpnConfig, "auth", "SHA256"),
		CAPath:            getStringValue(openvpnConfig, "ca", ""),
		CertPath:          getStringValue(openvpnConfig, "cert", ""),
		KeyPath:           getStringValue(openvpnConfig, "key", ""),
		KeepaliveInterval: getIntValue(openvpnConfig, "keepalive_interval", 10),
		KeepaliveTimeout:  getIntValue(openvpnConfig, "keepalive_timeout", 120),
		LogLevel:          getStringValue(openvpnConfig, "log_level", "info"),
		RunAsDaemon:       getBoolValue(openvpnConfig, "daemon", false),

		// API settings
		EnableAPI:        getBoolValue(openvpnConfig, "api-enabled", false),
		APIListenAddress: getStringValue(openvpnConfig, "api-address", "127.0.0.1"),
		APIPort:          getIntValue(openvpnConfig, "api-port", 8080),
		APIAuth:          getBoolValue(openvpnConfig, "api_auth", true),
		APIAuthSecret:    getStringValue(openvpnConfig, "api_auth_secret", ""),

		// === AUTHENTICATION PARAMETERS ===
		// Basic authentication
		EnablePasswordAuth:   getBoolValue(openvpnConfig, "enable_password_auth", false),
		AuthHashMethod:       getStringValue(openvpnConfig, "auth_hash_method", "argon2"),
		AuthArgon2Memory:     getIntValue(openvpnConfig, "auth_argon2_memory", 65536),
		AuthArgon2Time:       getIntValue(openvpnConfig, "auth_argon2_time", 3),
		AuthArgon2Threads:    getIntValue(openvpnConfig, "auth_argon2_threads", 4),
		AuthArgon2KeyLength:  getIntValue(openvpnConfig, "auth_argon2_key_length", 32),
		AuthPBKDF2Iterations: getIntValue(openvpnConfig, "auth_pbkdf2_iterations", 100000),
		AuthPBKDF2KeyLength:  getIntValue(openvpnConfig, "auth_pbkdf2_key_length", 32),
		AuthSaltLength:       getIntValue(openvpnConfig, "auth_salt_length", 16),
		AuthSessionTimeout:   getIntValue(openvpnConfig, "auth_session_timeout", 3600),

		// MFA parameters
		EnableMFA:           getBoolValue(openvpnConfig, "mfa_enabled", false),
		MFARequiredForAll:   getBoolValue(openvpnConfig, "mfa_required_for_all", false),
		MFAIssuer:           getStringValue(openvpnConfig, "mfa_issuer", "GoVPN"),
		MFAGracePeriod:      getIntValue(openvpnConfig, "mfa_grace_period", 300),
		MFAMaxAttempts:      getIntValue(openvpnConfig, "mfa_max_attempts", 5),
		MFALockoutDuration:  getIntValue(openvpnConfig, "mfa_lockout_duration", 900),
		MFATOTPEnabled:      getBoolValue(openvpnConfig, "mfa_totp_enabled", true),
		MFATOTPPeriod:       getIntValue(openvpnConfig, "mfa_totp_period", 30),
		MFATOTPDigits:       getIntValue(openvpnConfig, "mfa_totp_digits", 6),
		MFATOTPAlgorithm:    getStringValue(openvpnConfig, "mfa_totp_algorithm", "SHA1"),
		MFABackupCodesCount: getIntValue(openvpnConfig, "mfa_backup_codes_count", 10),

		// OIDC parameters
		EnableOIDC:              getBoolValue(openvpnConfig, "oidc_enabled", false),
		OIDCProviderURL:         getStringValue(openvpnConfig, "oidc_provider_url", ""),
		OIDCClientID:            getStringValue(openvpnConfig, "oidc_client_id", ""),
		OIDCClientSecret:        getStringValue(openvpnConfig, "oidc_client_secret", ""),
		OIDCRedirectURL:         getStringValue(openvpnConfig, "oidc_redirect_url", ""),
		OIDCScopes:              getStringSlice(openvpnConfig, "oidc_scopes"),
		OIDCSessionTimeout:      getIntValue(openvpnConfig, "oidc_session_timeout", 86400),
		OIDCRefreshTokenEnabled: getBoolValue(openvpnConfig, "oidc_refresh_token_enabled", true),
		OIDCPKCEEnabled:         getBoolValue(openvpnConfig, "oidc_pkce_enabled", true),
		OIDCClaimUsername:       getStringValue(openvpnConfig, "oidc_claim_username", "preferred_username"),
		OIDCClaimEmail:          getStringValue(openvpnConfig, "oidc_claim_email", "email"),
		OIDCClaimGroups:         getStringValue(openvpnConfig, "oidc_claim_groups", "groups"),

		// LDAP parameters
		EnableLDAP:           getBoolValue(openvpnConfig, "ldap_enabled", false),
		LDAPServer:           getStringValue(openvpnConfig, "ldap_server", ""),
		LDAPPort:             getIntValue(openvpnConfig, "ldap_port", 389),
		LDAPUseSSL:           getBoolValue(openvpnConfig, "ldap_use_ssl", false),
		LDAPUseTLS:           getBoolValue(openvpnConfig, "ldap_use_tls", true),
		LDAPSkipVerify:       getBoolValue(openvpnConfig, "ldap_skip_verify", false),
		LDAPTimeout:          getIntValue(openvpnConfig, "ldap_timeout", 10),
		LDAPBindDN:           getStringValue(openvpnConfig, "ldap_bind_dn", ""),
		LDAPBindPassword:     getStringValue(openvpnConfig, "ldap_bind_password", ""),
		LDAPBaseDN:           getStringValue(openvpnConfig, "ldap_base_dn", ""),
		LDAPUserFilter:       getStringValue(openvpnConfig, "ldap_user_filter", ""),
		LDAPGroupFilter:      getStringValue(openvpnConfig, "ldap_group_filter", ""),
		LDAPUserSearchBase:   getStringValue(openvpnConfig, "ldap_user_search_base", ""),
		LDAPGroupSearchBase:  getStringValue(openvpnConfig, "ldap_group_search_base", ""),
		LDAPRequiredGroups:   getStringSlice(openvpnConfig, "ldap_required_groups"),
		LDAPAdminGroups:      getStringSlice(openvpnConfig, "ldap_admin_groups"),
		LDAPUserAttrUsername: getStringValue(openvpnConfig, "ldap_user_attr_username", "sAMAccountName"),
		LDAPUserAttrEmail:    getStringValue(openvpnConfig, "ldap_user_attr_email", "mail"),
		LDAPUserAttrGroups:   getStringValue(openvpnConfig, "ldap_user_attr_groups", "memberOf"),

		// Obfuscation parameters
		EnableObfuscation:        getBoolValue(openvpnConfig, "obfuscation_enabled", false),
		ObfuscationAutoDetect:    getBoolValue(openvpnConfig, "obfuscation_auto_detect", false),
		PrimaryObfuscation:       getStringValue(openvpnConfig, "obfuscation_primary_method", "xor_cipher"),
		FallbackObfuscations:     getStringSlice(openvpnConfig, "obfuscation_fallback_methods"),
		XORCipherEnabled:         getBoolValue(openvpnConfig, "xor_cipher_enabled", false),
		XORKey:                   getStringValue(openvpnConfig, "xor_cipher_key", ""),
		PacketPaddingEnabled:     getBoolValue(openvpnConfig, "packet_padding_enabled", false),
		PacketPaddingMinSize:     getIntValue(openvpnConfig, "packet_padding_min_size", 32),
		PacketPaddingMaxSize:     getIntValue(openvpnConfig, "packet_padding_max_size", 128),
		TimingObfuscationEnabled: getBoolValue(openvpnConfig, "timing_obfuscation_enabled", false),
		TLSTunnelEnabled:         getBoolValue(openvpnConfig, "tls_tunnel_enabled", false),
		TLSTunnelPort:            getIntValue(openvpnConfig, "tls_tunnel_port", 443),
		HTTPMimicryEnabled:       getBoolValue(openvpnConfig, "http_mimicry_enabled", false),
	}

	// Set default obfuscation methods if enabled but no methods specified
	if config.EnableObfuscation && len(config.ObfuscationMethods) == 0 {
		config.ObfuscationMethods = []string{config.PrimaryObfuscation}
	}

	// Set default OIDC scopes if enabled but no scopes specified
	if config.EnableOIDC && len(config.OIDCScopes) == 0 {
		config.OIDCScopes = []string{"openid", "profile", "email"}
	}

	return config
}

// validateServerConfig validates server configuration
func validateServerConfig(config core.Config) error {
	if config.Port <= 0 || config.Port > 65535 {
		return fmt.Errorf("invalid port: %d", config.Port)
	}

	if config.Protocol != "tcp" && config.Protocol != "udp" && config.Protocol != "both" {
		return fmt.Errorf("invalid protocol: %s", config.Protocol)
	}

	if config.DeviceType != "tun" && config.DeviceType != "tap" {
		return fmt.Errorf("invalid device type: %s", config.DeviceType)
	}

	if config.CAPath != "" && !fileExists(config.CAPath) {
		return fmt.Errorf("CA file not found: %s", config.CAPath)
	}

	if config.CertPath != "" && !fileExists(config.CertPath) {
		return fmt.Errorf("certificate file not found: %s", config.CertPath)
	}

	if config.KeyPath != "" && !fileExists(config.KeyPath) {
		return fmt.Errorf("key file not found: %s", config.KeyPath)
	}

	return nil
}

// fileExists checks if a file exists
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// dirExists checks if a directory exists
func dirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// getStringValue gets a string value from a configuration map with a default value
func getStringValue(config map[string]interface{}, key, defaultValue string) string {
	if value, ok := config[key]; ok {
		if strValue, ok := value.(string); ok {
			return strValue
		}
	}
	return defaultValue
}

// getIntValue gets an integer value from a configuration map with a default value
func getIntValue(config map[string]interface{}, key string, defaultValue int) int {
	if value, ok := config[key]; ok {
		switch v := value.(type) {
		case int:
			return v
		case string:
			if intValue, err := strconv.Atoi(v); err == nil {
				return intValue
			}
		}
	}
	return defaultValue
}

// getBoolValue gets a boolean value from a configuration map with a default value
func getBoolValue(config map[string]interface{}, key string, defaultValue bool) bool {
	if value, ok := config[key]; ok {
		switch v := value.(type) {
		case bool:
			return v
		case string:
			lower := strings.ToLower(v)
			if lower == "true" || lower == "yes" || lower == "1" {
				return true
			}
			if lower == "false" || lower == "no" || lower == "0" {
				return false
			}
		}
	}
	return defaultValue
}

// getStringSlice gets a string slice from a configuration map
func getStringSlice(config map[string]interface{}, key string) []string {
	if value, ok := config[key]; ok {
		switch v := value.(type) {
		case []string:
			return v
		case string:
			return []string{v}
		}
	}
	return nil
}

// setupLogging sets up logging based on configuration
func setupLogging(outputType, filePath, logLevel string) {
	var output io.Writer

	switch outputType {
	case "file":
		if filePath == "" {
			log.Fatal("Log file path not specified for file logging")
		}

		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}

		output = file

	case "syslog":
		// Syslog implementation depends on platform
		// For simplicity, just use stdout for now
		output = os.Stdout
		log.Println("Warning: syslog output not implemented on this platform, using stdout")

	default: // stdout or unknown
		output = os.Stdout
	}

	// Set log output
	log.SetOutput(output)

	// Set log flags based on level
	switch strings.ToLower(logLevel) {
	case "error":
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	case "warning", "warn":
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	case "info":
		log.SetFlags(log.Ldate | log.Ltime)
	case "debug":
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	case "trace":
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Llongfile)
	default:
		log.SetFlags(log.Ldate | log.Ltime)
	}
}

// runAsDaemon detaches the process to run as a daemon
func runAsDaemon() error {
	// On Unix systems, fork a new process and exit the parent
	// Note: This is a simplified implementation
	if runtime.GOOS == "windows" {
		log.Println("Daemon mode not fully supported on Windows")
		return nil
	}

	// The actual implementation would involve forking a process
	// and managing PID files, but for simplicity we just log a message
	log.Println("Running as daemon (simplified implementation)")

	return nil
}

// setupStatusFile sets up periodic writing of status to a file
func setupStatusFile(s *server.Server, path string, intervalSeconds int) {
	go func() {
		ticker := time.NewTicker(time.Duration(intervalSeconds) * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			status := s.Status()

			// Open the file for writing
			file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				log.Printf("Failed to open status file: %v", err)
				continue
			}

			// Write status information
			fmt.Fprintf(file, "GoVPN STATUS\n")
			fmt.Fprintf(file, "Updated: %s\n", time.Now().Format(time.RFC3339))
			fmt.Fprintf(file, "Uptime: %s\n", time.Since(time.Unix(status.StartTime, 0)).Round(time.Second))
			fmt.Fprintf(file, "Connected clients: %d\n", status.VPNStatus.ClientCount)
			// Add more status information as needed

			file.Close()
		}
	}()
}

// handleServiceCommand handles service management commands
func handleServiceCommand(command string) {
	switch command {
	case "install":
		log.Println("Installing service...")
		// Implementation depends on platform
		log.Println("Service installation not implemented yet")

	case "remove":
		log.Println("Removing service...")
		// Implementation depends on platform
		log.Println("Service removal not implemented yet")

	case "start":
		log.Println("Starting service...")
		// Implementation depends on platform
		log.Println("Service start not implemented yet")

	case "stop":
		log.Println("Stopping service...")
		// Implementation depends on platform
		log.Println("Service stop not implemented yet")

	default:
		log.Fatalf("Unknown service command: %s", command)
	}
}

// dumpStats dumps the current server statistics
func dumpStats() {
	fmt.Println("Server statistics not implemented yet")
}

// getVersion returns the current version of the application
func getVersion() string {
	return "0.1.0"
}

// convertToCIDR converts IP address and subnet mask to CIDR notation
func convertToCIDR(ip, mask string) string {
	// Parse IP address
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		log.Printf("Warning: invalid IP address %s, using default", ip)
		return "10.8.0.0/24"
	}

	// Parse subnet mask
	maskAddr := net.ParseIP(mask)
	if maskAddr == nil {
		log.Printf("Warning: invalid subnet mask %s, using default", mask)
		return fmt.Sprintf("%s/24", ip)
	}

	// Convert mask to prefix length
	mask4 := maskAddr.To4()
	if mask4 == nil {
		log.Printf("Warning: invalid IPv4 subnet mask %s, using default", mask)
		return fmt.Sprintf("%s/24", ip)
	}

	// Calculate prefix length
	prefixLen := 0
	for _, b := range mask4 {
		for i := 7; i >= 0; i-- {
			if (b>>i)&1 == 1 {
				prefixLen++
			} else {
				break
			}
		}
		if (b>>7)&1 == 0 {
			break
		}
	}

	return fmt.Sprintf("%s/%d", ip, prefixLen)
}

// convertServerNetworkToCIDR converts server network string from OpenVPN format to CIDR format
func convertServerNetworkToCIDR(serverNetwork string) string {
	// If already in CIDR format (contains /), return as is
	if strings.Contains(serverNetwork, "/") {
		return serverNetwork
	}

	// Split by space to get IP and mask
	parts := strings.Fields(serverNetwork)
	if len(parts) >= 2 {
		return convertToCIDR(parts[0], parts[1])
	}

	// If only IP provided, assume /24
	if len(parts) == 1 {
		return fmt.Sprintf("%s/24", parts[0])
	}

	// Default fallback
	log.Printf("Warning: invalid server network format '%s', using default", serverNetwork)
	return "10.8.0.0/24"
}
