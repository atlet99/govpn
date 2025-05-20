package core

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// OpenVPNServer represents an OpenVPN-compatible server implementation
type OpenVPNServer struct {
	config     Config
	listener   net.Listener
	udpConn    *net.UDPConn
	device     TunnelDevice
	running    atomic.Bool
	conns      sync.Map // map[string]Connection
	stats      ServerStats
	wg         sync.WaitGroup
	shutdown   chan struct{}
	ctx        context.Context
	cancelFunc context.CancelFunc
}

// ServerStats contains server statistics
type ServerStats struct {
	bytesIn   atomic.Uint64
	bytesOut  atomic.Uint64
	startTime int64
	connCount atomic.Int32
}

// NewServer creates a new instance of an OpenVPN-compatible server
func NewServer(config Config) (*OpenVPNServer, error) {
	// Configuration validation
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	server := &OpenVPNServer{
		config:   config,
		shutdown: make(chan struct{}),
	}

	// Initialize statistics
	server.stats.startTime = time.Now().Unix()

	return server, nil
}

// Validate configuration correctness
func validateConfig(config Config) error {
	if config.Port <= 0 || config.Port > 65535 {
		return fmt.Errorf("invalid port: %d", config.Port)
	}

	if config.Protocol != "tcp" && config.Protocol != "udp" {
		return fmt.Errorf("invalid protocol: %s", config.Protocol)
	}

	return nil
}

// Start launches the VPN server
func (s *OpenVPNServer) Start(ctx context.Context) error {
	if s.running.Load() {
		return fmt.Errorf("server is already running")
	}

	// Create cancellable context
	s.ctx, s.cancelFunc = context.WithCancel(ctx)

	// Open TUN/TAP device
	device, err := openTunDevice(s.config)
	if err != nil {
		return fmt.Errorf("failed to open TUN device: %w", err)
	}
	s.device = device

	// Start network listener
	if err := s.startNetworkListener(); err != nil {
		s.device.Close()
		return fmt.Errorf("failed to start network listener: %w", err)
	}

	s.running.Store(true)

	// Start incoming connections handler
	s.wg.Add(1)
	go s.handleConnections()

	// Start TUN/TAP device handler
	s.wg.Add(1)
	go s.processTunDevice()

	log.Printf("VPN server started on %s:%d (%s)", s.config.ListenAddress, s.config.Port, s.config.Protocol)
	return nil
}

// startNetworkListener starts a network listener based on the protocol
func (s *OpenVPNServer) startNetworkListener() error {
	addr := fmt.Sprintf("%s:%d", s.config.ListenAddress, s.config.Port)

	if s.config.Protocol == "tcp" {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		s.listener = listener
	} else {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return err
		}

		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return err
		}
		s.udpConn = conn
	}

	return nil
}

// handleConnections handles incoming connections
func (s *OpenVPNServer) handleConnections() {
	defer s.wg.Done()

	if s.config.Protocol == "tcp" {
		s.handleTCPConnections()
	} else {
		s.handleUDPConnections()
	}
}

// handleTCPConnections handles incoming TCP connections
func (s *OpenVPNServer) handleTCPConnections() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			// Set deadline to check context
			s.listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))

			conn, err := s.listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout - continue
					continue
				}
				log.Printf("Error accepting connection: %v", err)
				continue
			}

			s.stats.connCount.Add(1)
			s.wg.Add(1)

			go func(conn net.Conn) {
				defer s.wg.Done()
				defer conn.Close()
				defer s.stats.connCount.Add(-1)

				s.handleTCPClient(conn)
			}(conn)
		}
	}
}

// handleUDPConnections handles incoming UDP packets
func (s *OpenVPNServer) handleUDPConnections() {
	buffer := make([]byte, 2048)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			// Set deadline to check context
			s.udpConn.SetReadDeadline(time.Now().Add(time.Second))

			n, addr, err := s.udpConn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout - continue
					continue
				}
				log.Printf("Error reading UDP packet: %v", err)
				continue
			}

			s.stats.bytesIn.Add(uint64(n))

			// Process packet
			s.handleUDPPacket(buffer[:n], addr)
		}
	}
}

// handleTCPClient handles TCP client connection
func (s *OpenVPNServer) handleTCPClient(conn net.Conn) {
	log.Printf("New TCP connection from %s", conn.RemoteAddr())

	// TODO: Implement complete OpenVPN handshake logic
	buffer := make([]byte, 2048)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			// Set deadline to check context
			conn.SetReadDeadline(time.Now().Add(time.Second * 60))

			n, err := conn.Read(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout - continue
					continue
				}
				log.Printf("Error reading data from client: %v", err)
				return
			}

			s.stats.bytesIn.Add(uint64(n))

			// Placeholder for packet processing
			log.Printf("Received %d bytes from TCP client", n)
		}
	}
}

// handleUDPPacket handles incoming UDP packet
func (s *OpenVPNServer) handleUDPPacket(packet []byte, addr *net.UDPAddr) {
	// TODO: Implement complete OpenVPN packet processing logic
	log.Printf("Received UDP packet from %s (%d bytes)", addr, len(packet))
}

// processTunDevice processes data from TUN/TAP device
func (s *OpenVPNServer) processTunDevice() {
	defer s.wg.Done()

	buffer := make([]byte, 2048)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			// Read data from TUN/TAP device
			n, err := s.device.Read(buffer)
			if err != nil {
				log.Printf("Error reading from TUN device: %v", err)
				continue
			}

			// Placeholder for packet processing
			log.Printf("Received %d bytes from TUN device", n)

			// TODO: Route packets to clients
		}
	}
}

// Stop stops the VPN server
func (s *OpenVPNServer) Stop() error {
	if !s.running.Load() {
		return fmt.Errorf("server is not running")
	}

	log.Println("Stopping VPN server...")

	// Cancel context to terminate all goroutines
	s.cancelFunc()

	// Close network resources
	if s.listener != nil {
		s.listener.Close()
	}

	if s.udpConn != nil {
		s.udpConn.Close()
	}

	// Close TUN/TAP device
	if s.device != nil {
		s.device.Close()
	}

	// Wait for all goroutines to finish
	s.wg.Wait()

	s.running.Store(false)
	log.Println("VPN server stopped")

	return nil
}

// Status returns the current server status
func (s *OpenVPNServer) Status() ServerStatus {
	activeRoutes := make([]string, 0)
	// TODO: Get active routes

	return ServerStatus{
		Running:      s.running.Load(),
		ClientCount:  int(s.stats.connCount.Load()),
		BytesIn:      s.stats.bytesIn.Load(),
		BytesOut:     s.stats.bytesOut.Load(),
		ActiveRoutes: activeRoutes,
		StartTime:    s.stats.startTime,
	}
}

// openTunDevice opens and configures a TUN/TAP device
func openTunDevice(config Config) (TunnelDevice, error) {
	// TODO: Implement TUN/TAP device opening on various platforms
	// This is a placeholder
	return nil, fmt.Errorf("TUN device opening not implemented")
}
