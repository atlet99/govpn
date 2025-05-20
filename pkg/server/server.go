// Package server provides the main server implementation integrating VPN and API
package server

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/atlet99/govpn/pkg/api"
	"github.com/atlet99/govpn/pkg/core"
)

const (
	// DefaultAPIReadTimeout default timeout for API request reading
	DefaultAPIReadTimeout = 10 * time.Second

	// DefaultAPIWriteTimeout default timeout for API response writing
	DefaultAPIWriteTimeout = 10 * time.Second

	// DefaultAPIBasePath default base path for API endpoints
	DefaultAPIBasePath = "/api/v1"
)

// Server represents the main application server
type Server struct {
	config  *Config
	vpn     *core.OpenVPNServer
	api     *api.Server
	started bool
}

// Config represents the main server configuration
type Config struct {
	VPNConfig core.Config
	EnableAPI bool
}

// DefaultConfig returns a default server configuration
func DefaultConfig() *Config {
	vpnConfig := core.DefaultConfig()

	return &Config{
		VPNConfig: vpnConfig,
		EnableAPI: true,
	}
}

// NewServer creates a new server instance
func NewServer(config *Config) (*Server, error) {
	vpnServer, err := core.NewServer(config.VPNConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create VPN server: %w", err)
	}

	server := &Server{
		config: config,
		vpn:    vpnServer,
	}

	return server, nil
}

// Start starts the server
func (s *Server) Start(ctx context.Context) error {
	if s.started {
		return fmt.Errorf("server already started")
	}

	// Start VPN server
	if err := s.vpn.Start(ctx); err != nil {
		return fmt.Errorf("failed to start VPN server: %w", err)
	}

	// Start API server if enabled
	if s.config.EnableAPI && s.config.VPNConfig.EnableAPI {
		apiConfig := api.Config{
			ListenAddress: s.config.VPNConfig.APIListenAddress,
			Port:          s.config.VPNConfig.APIPort,
			BaseURL:       DefaultAPIBasePath,
			EnableAuth:    s.config.VPNConfig.APIAuth,
			JWTSecret:     s.config.VPNConfig.APIAuthSecret,
			ReadTimeout:   DefaultAPIReadTimeout,
			WriteTimeout:  DefaultAPIWriteTimeout,
		}

		s.api = api.NewServer(apiConfig, s.vpn)
		if err := s.api.Start(); err != nil {
			if stopErr := s.vpn.Stop(); stopErr != nil {
				log.Printf("Error stopping VPN server after API server start failed: %v", stopErr)
			}
			return fmt.Errorf("failed to start API server: %w", err)
		}

		log.Printf("API server started on %s:%d", apiConfig.ListenAddress, apiConfig.Port)
	}

	s.started = true
	return nil
}

// Stop stops the server
func (s *Server) Stop() error {
	if !s.started {
		return nil
	}

	// Stop API server
	if s.api != nil {
		if err := s.api.Stop(); err != nil {
			log.Printf("Error stopping API server: %v", err)
		}
	}

	// Stop VPN server
	if err := s.vpn.Stop(); err != nil {
		return fmt.Errorf("failed to stop VPN server: %w", err)
	}

	s.started = false
	return nil
}

// Status returns the server status
func (s *Server) Status() *Status {
	vpnStatus := s.vpn.Status()

	return &Status{
		VPNStatus:  vpnStatus,
		APIEnabled: s.config.EnableAPI && s.config.VPNConfig.EnableAPI,
		StartTime:  vpnStatus.StartTime,
	}
}

// Status represents the server status
type Status struct {
	VPNStatus  core.ServerStatus
	APIEnabled bool
	StartTime  int64
}
