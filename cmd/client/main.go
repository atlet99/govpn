package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var (
	configFile = flag.String("config", "", "Path to OpenVPN configuration file")
	serverAddr = flag.String("server", "127.0.0.1", "VPN server address")
	serverPort = flag.Int("port", 1194, "VPN server port")
	proto      = flag.String("proto", "udp", "Protocol (udp or tcp)")
	certFile   = flag.String("cert", "", "Path to client certificate file")
	keyFile    = flag.String("key", "", "Path to client key file")
	caFile     = flag.String("ca", "", "Path to CA file")
	verbosity  = flag.Int("verb", 4, "Log verbosity level (1-9)")
)

func main() {
	flag.Parse()

	// Setup logging
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	log.Println("GoVPN client (in development)")
	log.Printf("Connection settings: %s:%d (%s)", *serverAddr, *serverPort, *proto)

	if *configFile != "" {
		log.Printf("Using configuration file: %s", *configFile)
		// TODO: Implement OpenVPN configuration parsing and connection
	} else {
		log.Println("Note: Specifying --config is recommended for OpenVPN compatibility")
	}

	// Setup signal handling for graceful termination
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Client ready to connect. Press Ctrl+C to exit.")

	// Wait for termination signal
	sig := <-sigChan
	log.Printf("Received signal %v, shutting down...", sig)
}
