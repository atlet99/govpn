package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/atlet99/govpn/pkg/compat"
	"github.com/atlet99/govpn/pkg/core"
)

var (
	configFile  = flag.String("config", "", "Path to OpenVPN configuration file")
	port        = flag.Int("port", 1194, "Port to listen on")
	proto       = flag.String("proto", "udp", "Protocol (udp or tcp)")
	listenAddr  = flag.String("listen", "0.0.0.0", "Address to listen on")
	device      = flag.String("dev", "tun", "Device type (tun or tap)")
	serverAddr  = flag.String("server", "10.8.0.0", "VPN server subnet")
	serverMask  = flag.String("mask", "255.255.255.0", "VPN server subnet mask")
	certFile    = flag.String("cert", "", "Path to server certificate file")
	keyFile     = flag.String("key", "", "Path to server key file")
	caFile      = flag.String("ca", "", "Path to CA file")
	verbosity   = flag.Int("verb", 4, "Log verbosity level (1-9)")
	cipher      = flag.String("cipher", "AES-256-GCM", "Encryption cipher")
	auth        = flag.String("auth", "SHA256", "Authentication algorithm")
	keepalive   = flag.Int("keepalive", 10, "Keepalive interval in seconds")
	keepTimeout = flag.Int("keepalive-timeout", 120, "Keepalive timeout in seconds")
)

func main() {
	flag.Parse()

	// Setup logging
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	// Check for configuration file
	var config core.Config
	if *configFile != "" {
		// Parse configuration file
		parser := compat.NewConfigParser()
		openvpnConfig, err := parser.ParseConfigFile(*configFile)
		if err != nil {
			log.Fatalf("Error parsing configuration file: %v", err)
		}

		// Convert OpenVPN configuration to GoVPN configuration
		config = convertConfig(openvpnConfig)
	} else {
		// Use command line parameters
		config = core.Config{
			DeviceType:       *device,
			ListenAddress:    *listenAddr,
			Protocol:         *proto,
			Port:             *port,
			ServerNetwork:    fmt.Sprintf("%s %s", *serverAddr, *serverMask),
			LogLevel:         getLogLevel(*verbosity),
			CertPath:         *certFile,
			KeyPath:          *keyFile,
			CAPath:           *caFile,
			Cipher:           *cipher,
			Auth:             *auth,
			KeepAlive:        time.Duration(*keepalive) * time.Second,
			KeepAliveTimeout: *keepTimeout,
		}
	}

	// Validate configuration
	if err := validateServerConfig(config); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Create server
	server, err := core.NewServer(config)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Setup signal handling for graceful termination
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	setupSignalHandling(cancel)

	// Start server
	if err := server.Start(ctx); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	// Wait for context cancellation
	<-ctx.Done()

	// Stop server
	if err := server.Stop(); err != nil {
		log.Printf("Error stopping server: %v", err)
	}
}

// setupSignalHandling sets up signal handling for graceful termination
func setupSignalHandling(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()
	}()
}

// convertConfig converts OpenVPN configuration to GoVPN configuration
func convertConfig(openvpnConfig map[string]interface{}) core.Config {
	config := core.Config{
		DeviceType:       getStringValue(openvpnConfig, "dev", "tun"),
		ListenAddress:    getStringValue(openvpnConfig, "local", "0.0.0.0"),
		Protocol:         getStringValue(openvpnConfig, "protocol", "udp"),
		Port:             getIntValue(openvpnConfig, "port", 1194),
		ServerNetwork:    getStringValue(openvpnConfig, "server_network", "10.8.0.0 255.255.255.0"),
		DNSServers:       getStringSlice(openvpnConfig, "dns"),
		LogLevel:         getStringValue(openvpnConfig, "log_level", "info"),
		CertPath:         getStringValue(openvpnConfig, "cert", ""),
		KeyPath:          getStringValue(openvpnConfig, "key", ""),
		CAPath:           getStringValue(openvpnConfig, "ca", ""),
		CRLPath:          getStringValue(openvpnConfig, "crl-verify", ""),
		CompLZO:          getBoolValue(openvpnConfig, "comp-lzo", false),
		Cipher:           getStringValue(openvpnConfig, "cipher", "AES-256-GCM"),
		Auth:             getStringValue(openvpnConfig, "auth", "SHA256"),
		KeepAlive:        time.Duration(getIntValue(openvpnConfig, "keepalive", 10)) * time.Second,
		KeepAliveTimeout: getIntValue(openvpnConfig, "keepalive-timeout", 120),
	}

	// Convert push routes
	if pushes, ok := openvpnConfig["push"].([]string); ok {
		routes := make([]string, 0)
		for _, push := range pushes {
			if strings.HasPrefix(push, "route ") {
				routes = append(routes, strings.TrimPrefix(push, "route "))
			}
		}
		if len(routes) > 0 {
			config.Routes = routes
		}
	}

	return config
}

// validateServerConfig performs additional validation of server configuration
func validateServerConfig(config core.Config) error {
	// Check for required certificate files
	if config.CertPath != "" && !fileExists(config.CertPath) {
		return fmt.Errorf("certificate file not found: %s", config.CertPath)
	}

	if config.KeyPath != "" && !fileExists(config.KeyPath) {
		return fmt.Errorf("key file not found: %s", config.KeyPath)
	}

	if config.CAPath != "" && !fileExists(config.CAPath) {
		return fmt.Errorf("CA file not found: %s", config.CAPath)
	}

	if config.CRLPath != "" && !fileExists(config.CRLPath) {
		return fmt.Errorf("CRL file not found: %s", config.CRLPath)
	}

	return nil
}

// fileExists checks if a file exists
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// getStringValue extracts a string value from the configuration map
func getStringValue(config map[string]interface{}, key, defaultValue string) string {
	if value, ok := config[key]; ok {
		if strValue, ok := value.(string); ok {
			return strValue
		}
	}
	return defaultValue
}

// getIntValue extracts an integer value from the configuration map
func getIntValue(config map[string]interface{}, key string, defaultValue int) int {
	if value, ok := config[key]; ok {
		if intValue, ok := value.(int); ok {
			return intValue
		}
		if strValue, ok := value.(string); ok {
			if intValue, err := strconv.Atoi(strValue); err == nil {
				return intValue
			}
		}
	}
	return defaultValue
}

// getBoolValue extracts a boolean value from the configuration map
func getBoolValue(config map[string]interface{}, key string, defaultValue bool) bool {
	if value, ok := config[key]; ok {
		if boolValue, ok := value.(bool); ok {
			return boolValue
		}
		if strValue, ok := value.(string); ok {
			return strValue == "true" || strValue == "yes" || strValue == "1"
		}
	}
	return defaultValue
}

// getStringSlice extracts a string slice from the configuration map
func getStringSlice(config map[string]interface{}, key string) []string {
	if value, ok := config[key]; ok {
		if strSlice, ok := value.([]string); ok {
			return strSlice
		}
		if strValue, ok := value.(string); ok {
			return []string{strValue}
		}
	}
	return nil
}

// getLogLevel returns a logging level based on OpenVPN verbosity level
func getLogLevel(verbosity int) string {
	switch {
	case verbosity <= 2:
		return "error"
	case verbosity == 3:
		return "warning"
	case verbosity == 4:
		return "info"
	default:
		return "debug"
	}
}
