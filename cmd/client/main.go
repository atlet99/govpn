package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/atlet99/govpn/pkg/compat"
	"github.com/atlet99/govpn/pkg/core"
)

var (
	// Basic connection options
	configFile = flag.String("config", "", "Path to OpenVPN configuration file")
	configDir  = flag.String("config-dir", "", "Path to directory with configuration files")
	serverAddr = flag.String("server", "127.0.0.1", "VPN server address")
	serverPort = flag.Int("port", 1194, "VPN server port")
	proto      = flag.String("proto", "udp", "Protocol (udp or tcp)")
	certFile   = flag.String("cert", "", "Path to client certificate file")
	keyFile    = flag.String("key", "", "Path to client key file")
	caFile     = flag.String("ca", "", "Path to CA file")

	// CLI improvements
	verbosity   = flag.Int("verb", 4, "Log verbosity level (1-9)")
	daemon      = flag.Bool("daemon", false, "Run as a daemon")
	profileName = flag.String("profile", "", "Use specific profile from profiles directory")
	logOutput   = flag.String("log-output", "stdout", "Log output (stdout, file, syslog)")
	logFile     = flag.String("log-file", "", "Log file path when log-output is file")
	version     = flag.Bool("version", false, "Display version information and exit")

	// Service management
	service = flag.String("service", "", "Service management (install, remove, start, stop)")

	// List profiles
	listProfiles = flag.Bool("list-profiles", false, "List available connection profiles")

	// Track which flags were explicitly set on the command line
	explicitFlags = make(map[string]bool)
)

func main() {
	// Parse flags and record which ones were explicitly set
	flag.Parse()
	flag.Visit(func(f *flag.Flag) {
		explicitFlags[f.Name] = true
	})

	// Check for version flag
	if *version {
		fmt.Printf("GoVPN Client v%s (OpenVPN compatible)\n", getVersion())
		os.Exit(0)
	}

	// Check for list-profiles flag
	if *listProfiles {
		displayAvailableProfiles()
		os.Exit(0)
	}

	// Check for service management
	if *service != "" {
		handleServiceCommand(*service)
		os.Exit(0)
	}

	// Setup logging
	setupLogging(*logOutput, *logFile, verbosityToLogLevel(*verbosity))

	// Get configuration
	clientConfig := loadConfiguration()

	log.Println("GoVPN client (in development)")
	log.Printf("Connection settings: %s:%d (%s)", clientConfig.ServerAddress, clientConfig.ServerPort, clientConfig.Protocol)

	// Setup signal handling for graceful termination
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Client ready to connect. Press Ctrl+C to exit.")

	// TODO: Implement client connection here

	// Wait for termination signal
	sig := <-sigChan
	log.Printf("Received signal %v, shutting down...", sig)
}

// loadConfiguration loads the VPN client configuration from file or command line arguments
func loadConfiguration() *core.ClientConfig {
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
func loadConfigFile(path string) (*core.ClientConfig, error) {
	// Parse configuration file
	parser := compat.NewConfigParser()
	openvpnConfig, err := parser.ParseConfigFile(path)
	if err != nil {
		return nil, fmt.Errorf("error parsing configuration file: %w", err)
	}

	// Convert OpenVPN configuration to GoVPN configuration
	config := convertClientConfig(openvpnConfig)
	config.ConfigPath = path

	// Override with command line flags
	applyConfigOverrides(config)

	return config, nil
}

// loadProfile loads a configuration from a named profile
func loadProfile(name string) (*core.ClientConfig, error) {
	// Search for profile in standard locations
	for _, dir := range core.DefaultConfigDirs {
		profilePath := filepath.Join(dir, core.DefaultProfilesDir, name+".ovpn")
		if fileExists(profilePath) {
			config, err := loadConfigFile(profilePath)
			if err != nil {
				return nil, err
			}

			config.ProfileName = name
			return config, nil
		}
	}

	return nil, fmt.Errorf("profile '%s' not found", name)
}

// loadConfigDir loads a configuration from a directory containing configuration files
func loadConfigDir(dir string) (*core.ClientConfig, error) {
	// Check if directory exists
	if !dirExists(dir) {
		return nil, fmt.Errorf("directory '%s' does not exist", dir)
	}

	// Load first .ovpn file found
	files, err := filepath.Glob(filepath.Join(dir, "*.ovpn"))
	if err != nil {
		return nil, fmt.Errorf("error searching directory: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no configuration files found in '%s'", dir)
	}

	// Use the first file found
	return loadConfigFile(files[0])
}

// createConfigFromFlags creates a configuration from command line flags
func createConfigFromFlags() *core.ClientConfig {
	return &core.ClientConfig{
		ServerAddress: *serverAddr,
		ServerPort:    *serverPort,
		Protocol:      *proto,
		CertPath:      *certFile,
		KeyPath:       *keyFile,
		CAPath:        *caFile,

		// CLI settings
		RunAsDaemon: *daemon,
		LogLevel:    verbosityToLogLevel(*verbosity),
		LogOutput:   *logOutput,
		LogFilePath: *logFile,
		ProfileName: "default",
	}
}

// applyConfigOverrides applies command line flag overrides to a loaded configuration
func applyConfigOverrides(config *core.ClientConfig) {
	// Only override if explicitly specified on command line
	if explicitFlags["server"] {
		config.ServerAddress = *serverAddr
	}
	if explicitFlags["port"] {
		config.ServerPort = *serverPort
	}
	if explicitFlags["proto"] {
		config.Protocol = *proto
	}
	if explicitFlags["cert"] {
		config.CertPath = *certFile
	}
	if explicitFlags["key"] {
		config.KeyPath = *keyFile
	}
	if explicitFlags["ca"] {
		config.CAPath = *caFile
	}
	if explicitFlags["daemon"] {
		config.RunAsDaemon = *daemon
	}
	if explicitFlags["verb"] {
		config.LogLevel = verbosityToLogLevel(*verbosity)
	}
	if explicitFlags["log-output"] {
		config.LogOutput = *logOutput
	}
	if explicitFlags["log-file"] {
		config.LogFilePath = *logFile
	}
}

// convertClientConfig converts OpenVPN configuration to GoVPN client configuration
func convertClientConfig(openvpnConfig map[string]interface{}) *core.ClientConfig {
	// Extract server and port from "remote" directive
	var serverAddress string
	var serverPort int

	if remote, ok := openvpnConfig["remote"]; ok {
		if remoteArray, ok := remote.([]string); ok && len(remoteArray) >= 2 {
			serverAddress = remoteArray[0]
			if port, err := strconv.Atoi(remoteArray[1]); err == nil {
				serverPort = port
			} else {
				serverPort = 1194
			}
		} else if remoteStr, ok := remote.(string); ok {
			parts := strings.Split(remoteStr, " ")
			if len(parts) >= 1 {
				serverAddress = parts[0]
			}
			if len(parts) >= 2 {
				if port, err := strconv.Atoi(parts[1]); err == nil {
					serverPort = port
				} else {
					serverPort = 1194
				}
			}
		}
	}

	if serverAddress == "" {
		serverAddress = "127.0.0.1"
	}

	if serverPort == 0 {
		serverPort = 1194
	}

	return &core.ClientConfig{
		ServerAddress:     serverAddress,
		ServerPort:        serverPort,
		Protocol:          getStringValue(openvpnConfig, "protocol", "udp"),
		CertPath:          getStringValue(openvpnConfig, "cert", ""),
		KeyPath:           getStringValue(openvpnConfig, "key", ""),
		CAPath:            getStringValue(openvpnConfig, "ca", ""),
		LogLevel:          verbosityToLogLevel(getIntValue(openvpnConfig, "verb", 4)),
		DeviceType:        getStringValue(openvpnConfig, "dev", "tun"),
		RunAsDaemon:       getBoolValue(openvpnConfig, "daemon", false),
		CipherMode:        getStringValue(openvpnConfig, "cipher", "AES-256-GCM"),
		AuthDigest:        getStringValue(openvpnConfig, "auth", "SHA256"),
		CompressAlgorithm: getStringValue(openvpnConfig, "compress", ""),
	}
}

// verbosityToLogLevel converts OpenVPN verbosity level to log level
func verbosityToLogLevel(verbosity int) string {
	switch {
	case verbosity <= 2:
		return "error"
	case verbosity == 3:
		return "warning"
	case verbosity == 4:
		return "info"
	case verbosity >= 5 && verbosity <= 7:
		return "debug"
	default:
		return "trace"
	}
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

// handleServiceCommand handles service management commands
func handleServiceCommand(command string) {
	switch command {
	case "install":
		log.Println("Installing client service...")
		// Implementation depends on platform
		log.Println("Service installation not implemented yet")

	case "remove":
		log.Println("Removing client service...")
		// Implementation depends on platform
		log.Println("Service removal not implemented yet")

	case "start":
		log.Println("Starting client service...")
		// Implementation depends on platform
		log.Println("Service start not implemented yet")

	case "stop":
		log.Println("Stopping client service...")
		// Implementation depends on platform
		log.Println("Service stop not implemented yet")

	default:
		log.Fatalf("Unknown service command: %s", command)
	}
}

// displayAvailableProfiles lists all available profiles
func displayAvailableProfiles() {
	profiles, err := core.ListProfiles()
	if err != nil {
		fmt.Printf("Error listing profiles: %v\n", err)
		return
	}

	if len(profiles) == 0 {
		fmt.Println("No profiles found in standard locations.")
		fmt.Printf("Standard locations:\n")
		for _, dir := range core.DefaultConfigDirs {
			fmt.Printf("  %s/%s\n", dir, core.DefaultProfilesDir)
		}
		return
	}

	fmt.Println("Available connection profiles:")
	for _, profile := range profiles {
		fmt.Printf("  %s\n", profile)
	}
}

// getVersion returns the current version of the application
func getVersion() string {
	return "0.1.0"
}
