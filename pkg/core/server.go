package core

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/atlet99/govpn/pkg/auth"
)

// OpenVPNServer represents an OpenVPN-compatible server implementation
type OpenVPNServer struct {
	config   Config
	listener net.Listener
	udpConn  *net.UDPConn
	device   TunnelDevice
	running  atomic.Bool
	// conns field temporarily removed for linter compatibility
	// conns      sync.Map // map[string]Connection
	stats       ServerStats
	wg          sync.WaitGroup
	shutdown    chan struct{}
	ctx         context.Context
	cancelFunc  context.CancelFunc
	routeTable  *RouteTable // Routing table
	serverNet   *net.IPNet  // Server network (from config.ServerNetwork)
	serverIP    net.IP      // Server IP in the VPN network
	certManager *auth.CertificateManager
	sessions    sync.Map // map[string]*auth.OpenVPNSession
}

// ServerStats contains server statistics
type ServerStats struct {
	bytesIn   atomic.Uint64
	bytesOut  atomic.Uint64
	startTime int64
	connCount atomic.Int32
}

// NewServer creates a new server instance
func NewServer(config Config) (*OpenVPNServer, error) {
	server := &OpenVPNServer{
		config:   config,
		shutdown: make(chan struct{}),
		stats:    ServerStats{},
		certManager: auth.NewCertificateManager(
			auth.WithCAPath(config.CAPath),
			auth.WithCertPath(config.CertPath),
			auth.WithKeyPath(config.KeyPath),
			auth.WithCRLPath(config.CRLPath),
			auth.WithTLSAuthPath(config.TLSAuthKeyPath),
			auth.WithDhPath(config.DHParamsPath),
		),
	}

	_, serverNet, err := net.ParseCIDR(config.ServerNetwork)
	if err != nil {
		return nil, fmt.Errorf("invalid server network format: %w", err)
	}
	server.serverNet = serverNet

	serverIP := make(net.IP, len(serverNet.IP))
	copy(serverIP, serverNet.IP)
	server.serverIP = serverIP

	server.routeTable = NewRouteTable()

	if err := server.certManager.LoadCertificates(); err != nil {
		return nil, fmt.Errorf("failed to load certificates: %w", err)
	}

	return server, nil
}

// Start launches the VPN server
func (s *OpenVPNServer) Start(ctx context.Context) error {
	log.Printf("Starting OpenVPN server...")
	if s.running.Load() {
		return fmt.Errorf("server is already running")
	}

	s.ctx, s.cancelFunc = context.WithCancel(ctx)
	log.Printf("Context created")

	// Ensure MTU has a valid value
	mtu := s.config.MTU
	if mtu <= 0 {
		mtu = 1500 // Default MTU
	}

	conf := TunTapConfig{
		Name:       s.config.DeviceName,
		DeviceType: s.config.DeviceType,
		MTU:        mtu,
	}

	var err error
	log.Printf("Creating TUN/TAP device with config: %+v", conf)
	s.device, err = createTunTapDevice(conf)
	if err != nil {
		return fmt.Errorf("failed to create TUN/TAP device: %w", err)
	}
	log.Printf("TUN/TAP device created successfully")

	log.Printf("Configuring TUN/TAP device...")
	if err := s.configureDevice(); err != nil {
		s.device.Close()
		return fmt.Errorf("failed to configure TUN/TAP device: %w", err)
	}
	log.Printf("TUN/TAP device configured successfully")

	log.Printf("EnableTCP: %v, EnableUDP: %v", s.config.EnableTCP, s.config.EnableUDP)

	if s.config.EnableTCP {
		log.Printf("Starting TCP server...")
		if err := s.startTCPServer(); err != nil {
			s.device.Close()
			return fmt.Errorf("failed to start TCP server: %w", err)
		}
	}

	if s.config.EnableUDP {
		log.Printf("Starting UDP server...")
		if err := s.startUDPServer(); err != nil {
			if s.listener != nil {
				s.listener.Close()
			}
			s.device.Close()
			return fmt.Errorf("failed to start UDP server: %w", err)
		}
	}

	s.wg.Add(1)
	go s.processTunDevice()

	s.running.Store(true)
	return nil
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

			// Process the packet from TUN device
			packet := NewPacket(buffer[:n])
			if packet == nil {
				continue
			}

			// Check if the packet is IPv4
			if packet.IsIPv4() {
				dstIP := packet.GetIPv4DestinationIP()
				if dstIP == nil {
					continue
				}

				// Try to find the destination client session
				var clientFound bool
				s.sessions.Range(func(key, value interface{}) bool {
					session := value.(*auth.OpenVPNSession)
					if !session.IsHandshaking {
						// Create data packet
						dataPacket, err := session.CreateDataPacket(buffer[:n])
						if err != nil {
							log.Printf("Error creating data packet: %v", err)
							return true
						}

						// Marshal packet into bytes
						packetData, err := dataPacket.Marshal()
						if err != nil {
							log.Printf("Error marshaling packet: %v", err)
							return true
						}

						// TODO: Send the packet to the client
						// This would depend on whether the client is UDP or TCP
						// For now, we just log it
						log.Printf("Would send %d bytes to client %s", len(packetData), key)
						clientFound = true
						return false
					}
					return true
				})

				if !clientFound {
					log.Printf("No client session found for destination IP %s", dstIP)
				}
			}
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
	if s.routeTable != nil {
		routes := s.routeTable.GetAllRoutes()
		for _, route := range routes {
			activeRoutes = append(activeRoutes, route.Destination)
		}
	}

	return ServerStatus{
		Running:      s.running.Load(),
		ClientCount:  int(s.stats.connCount.Load()),
		BytesIn:      s.stats.bytesIn.Load(),
		BytesOut:     s.stats.bytesOut.Load(),
		ActiveRoutes: activeRoutes,
		StartTime:    s.stats.startTime,
	}
}

// Connection handling methods are commented out
// as they will be used in the future
/*
// getConnection returns a connection by its ID
func (s *OpenVPNServer) getConnection(id string) (Connection, bool) {
	conn, ok := s.conns.Load(id)
	if !ok {
		return nil, false
	}
	return conn.(Connection), true
}

// storeConnection stores a connection
func (s *OpenVPNServer) storeConnection(id string, conn Connection) {
	s.conns.Store(id, conn)
}

// deleteConnection deletes a connection
func (s *OpenVPNServer) deleteConnection(id string) {
	s.conns.Delete(id)
}
*/

// startUDPServer starts a UDP server
func (s *OpenVPNServer) startUDPServer() error {
	addr := fmt.Sprintf("%s:%d", s.config.ListenAddress, s.config.Port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	s.udpConn = conn

	s.wg.Add(1)
	go s.handleUDPServer()

	log.Printf("UDP server started on %s", addr)
	return nil
}

// startTCPServer starts a TCP server
func (s *OpenVPNServer) startTCPServer() error {
	addr := fmt.Sprintf("%s:%d", s.config.ListenAddress, s.config.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on TCP: %w", err)
	}
	s.listener = listener

	s.wg.Add(1)
	go s.handleTCPServer()

	log.Printf("TCP server started on %s", addr)
	return nil
}

// handleTCPServer handles incoming TCP connections
func (s *OpenVPNServer) handleTCPServer() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			// Set accept deadline to check context periodically
			if err := s.listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
				log.Printf("Error setting TCP listener deadline: %v", err)
			}

			conn, err := s.listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout - continue
					continue
				}
				log.Printf("Error accepting connection: %v", err)
				continue
			}

			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.handleTCPClient(conn)
			}()
		}
	}
}

// handleUDPServer handles incoming UDP packets
func (s *OpenVPNServer) handleUDPServer() {
	defer s.wg.Done()

	buffer := make([]byte, 2048)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			// Set read deadline to check context periodically
			if err := s.udpConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				log.Printf("Error setting UDP read deadline: %v", err)
			}

			n, addr, err := s.udpConn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout - continue
					continue
				}
				log.Printf("Error reading UDP: %v", err)
				continue
			}

			// Handle packet in a separate goroutine to avoid blocking
			data := make([]byte, n)
			copy(data, buffer[:n])

			go s.handleUDPPacket(data, addr)
		}
	}
}

// configureDevice configures the TUN/TAP device with IP address and routing
func (s *OpenVPNServer) configureDevice() error {
	// Set device MTU - use device's MTU (which has been validated and set to default if needed)
	deviceMTU := s.device.MTU()
	if deviceMTU <= 0 {
		deviceMTU = 1500 // Fallback
	}
	if err := setDeviceMTU(s.device.Name(), deviceMTU); err != nil {
		return fmt.Errorf("failed to set device MTU: %w", err)
	}

	// Set device up
	if err := setDeviceUp(s.device.Name()); err != nil {
		return fmt.Errorf("failed to set device up: %w", err)
	}

	// Set device address
	// Convert net mask to string format
	mask := s.serverNet.Mask
	netmask := net.IPv4(mask[0], mask[1], mask[2], mask[3]).String()

	if err := setDeviceAddress(s.device.Name(), s.serverIP.String(), netmask); err != nil {
		return fmt.Errorf("failed to set device address: %w", err)
	}

	log.Printf("TUN/TAP device %s configured with IP %s/%s", s.device.Name(), s.serverIP, netmask)
	return nil
}

// handleTCPClient handles a TCP client connection
func (s *OpenVPNServer) handleTCPClient(conn net.Conn) {
	defer s.wg.Done()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("New TCP client connected: %s", remoteAddr)

	sessionKey := remoteAddr
	buffer := make([]byte, 4096)

	tlsConfig, err := s.certManager.GetTLSConfig()
	if err != nil {
		log.Printf("Error creating TLS config: %v", err)
		conn.Close()
		return
	}

	session := auth.NewOpenVPNSession(tlsConfig, s.certManager.GetTLSAuthKey())
	s.sessions.Store(sessionKey, session)

	// Apply server push options
	pushOptions := auth.PushOptions{
		Routes:          s.config.Routes,
		DNSServers:      s.config.DNSServers,
		RedirectGateway: true,
		OtherOptions:    make(map[string]string),
	}
	session.UpdatePushOptions(pushOptions)

	for {
		select {
		case <-s.ctx.Done():
			conn.Close()
			return
		default:
			// Set deadline to check context
			if err := conn.SetReadDeadline(time.Now().Add(time.Second * 60)); err != nil {
				log.Printf("Error setting TCP client read deadline: %v", err)
			}

			n, err := conn.Read(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout - continue
					continue
				}
				log.Printf("Error reading data from client: %v", err)
				s.sessions.Delete(sessionKey)
				conn.Close()
				return
			}

			opvnPacket := &auth.OpenVPNPacket{}
			if err := opvnPacket.Unmarshal(buffer[:n]); err != nil {
				log.Printf("Error parsing OpenVPN packet: %v", err)
				continue
			}

			responsePacket, err := session.ProcessControlPacket(opvnPacket)
			if err != nil {
				log.Printf("Error processing packet: %v", err)
				continue
			}

			if responsePacket != nil {
				responseData, err := responsePacket.Marshal()
				if err != nil {
					log.Printf("Error marshaling response: %v", err)
					continue
				}

				if _, err := conn.Write(responseData); err != nil {
					log.Printf("Error sending response: %v", err)
					continue
				}
			}

			if opvnPacket.Opcode == auth.OpvnP_DATA_V1 {
				// Process data packet using the DecryptDataPacket method
				decryptedData, err := session.DecryptDataPacket(opvnPacket)
				if err != nil {
					log.Printf("Error processing data packet: %v", err)
					continue
				}

				// Process the IP packet
				packet := NewPacket(decryptedData)
				if packet != nil && packet.IsIPv4() {
					// Write the decrypted packet to the TUN device
					if _, err := s.device.Write(decryptedData); err != nil {
						log.Printf("Error writing to TUN device: %v", err)
					}
				}
			}
		}
	}
}

// handleUDPPacket handles incoming UDP packet
func (s *OpenVPNServer) handleUDPPacket(packet []byte, addr *net.UDPAddr) {
	sessionKey := addr.String()

	sessionInterface, exists := s.sessions.Load(sessionKey)

	opvnPacket := &auth.OpenVPNPacket{}
	if err := opvnPacket.Unmarshal(packet); err != nil {
		log.Printf("Error parsing OpenVPN packet: %v", err)
		return
	}

	var session *auth.OpenVPNSession

	if exists {
		session = sessionInterface.(*auth.OpenVPNSession)
	} else {
		tlsConfig, err := s.certManager.GetTLSConfig()
		if err != nil {
			log.Printf("Error creating TLS config: %v", err)
			return
		}

		session = auth.NewOpenVPNSession(tlsConfig, s.certManager.GetTLSAuthKey())

		// Apply server push options
		pushOptions := auth.PushOptions{
			Routes:          s.config.Routes,
			DNSServers:      s.config.DNSServers,
			RedirectGateway: true,
			OtherOptions:    make(map[string]string),
		}
		session.UpdatePushOptions(pushOptions)

		s.sessions.Store(sessionKey, session)
	}

	responsePacket, err := session.ProcessControlPacket(opvnPacket)
	if err != nil {
		log.Printf("Error processing packet: %v", err)
		return
	}

	if responsePacket != nil {
		responseData, err := responsePacket.Marshal()
		if err != nil {
			log.Printf("Error marshaling response: %v", err)
			return
		}

		if _, err := s.udpConn.WriteTo(responseData, addr); err != nil {
			log.Printf("Error sending response: %v", err)
			return
		}
	}

	if opvnPacket.Opcode == auth.OpvnP_DATA_V1 {
		// Process data packet using the DecryptDataPacket method
		decryptedData, err := session.DecryptDataPacket(opvnPacket)
		if err != nil {
			log.Printf("Error processing data packet: %v", err)
			return
		}

		// Process the IP packet
		packet := NewPacket(decryptedData)
		if packet != nil && packet.IsIPv4() {
			// Write the decrypted packet to the TUN device
			if _, err := s.device.Write(decryptedData); err != nil {
				log.Printf("Error writing to TUN device: %v", err)
			}
		}
	}
}
