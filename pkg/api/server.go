// Package api provides a REST API for GoVPN server management
package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/atlet99/govpn/pkg/auth"
	"github.com/atlet99/govpn/pkg/core"
)

const (
	// DefaultRateLimitRequests maximum number of requests in the time window
	DefaultRateLimitRequests = 100

	// DefaultRateLimitWindow time window for rate limiting
	DefaultRateLimitWindow = 1 * time.Minute

	// DefaultShutdownTimeout timeout for graceful server shutdown
	DefaultShutdownTimeout = 5 * time.Second
)

// Server represents the REST API server
type Server struct {
	config      Config
	httpServer  *http.Server
	vpnServer   *core.OpenVPNServer
	authManager *auth.AuthManager
	router      *http.ServeMux
	wg          sync.WaitGroup
	running     bool
	rateLimiter *rateLimiter
}

// Config represents the API server configuration
type Config struct {
	ListenAddress string
	Port          int
	BaseURL       string
	EnableAuth    bool
	JWTSecret     string
	CORSOrigins   []string
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
}

// DefaultConfig returns a default API server configuration
func DefaultConfig() Config {
	return Config{
		ListenAddress: "127.0.0.1",
		Port:          8080,
		BaseURL:       "/api/v1",
		EnableAuth:    true,
		ReadTimeout:   15 * time.Second,
		WriteTimeout:  15 * time.Second,
	}
}

// NewServer creates a new API server
func NewServer(config Config, vpnServer *core.OpenVPNServer, authManager *auth.AuthManager) *Server {
	server := &Server{
		config:      config,
		vpnServer:   vpnServer,
		authManager: authManager,
		router:      http.NewServeMux(),
		rateLimiter: newRateLimiter(DefaultRateLimitRequests, DefaultRateLimitWindow),
	}

	// Register routes
	server.registerRoutes()

	return server
}

// Start starts the API server
func (s *Server) Start() error {
	if s.running {
		return nil
	}

	addr := fmt.Sprintf("%s:%d", s.config.ListenAddress, s.config.Port)
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		log.Printf("REST API server starting on %s", addr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Error starting API server: %v", err)
		}
	}()

	s.running = true
	return nil
}

// Stop stops the API server
func (s *Server) Stop() error {
	if !s.running {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), DefaultShutdownTimeout)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return err
	}

	s.wg.Wait()
	s.running = false
	return nil
}

// registerRoutes registers all API routes
func (s *Server) registerRoutes() {
	base := s.config.BaseURL

	// Authentication endpoints
	s.router.HandleFunc(base+"/auth/login", s.handleLogin)
	s.router.HandleFunc(base+"/auth/oidc", s.handleOIDCAuth)
	s.router.HandleFunc(base+"/auth/oidc/callback", s.handleOIDCCallback)
	s.router.HandleFunc(base+"/auth/status", s.handleAuthStatus)

	// Status endpoints
	s.router.HandleFunc(base+"/status", s.handleGetStatus)

	// Client management endpoints
	s.router.HandleFunc(base+"/clients", s.handleGetClients)
	s.router.HandleFunc(base+"/clients/", s.handleClientOperations)

	// Certificate management endpoints
	s.router.HandleFunc(base+"/certificates", s.handleGetCertificates)
	s.router.HandleFunc(base+"/certificates/", s.handleCertificateOperations)

	// Configuration endpoints
	s.router.HandleFunc(base+"/config", s.handleGetConfig)
	s.router.HandleFunc(base+"/config/update", s.handleUpdateConfig)

	// User management endpoints
	s.router.HandleFunc(base+"/users", s.handleGetUsers)
	s.router.HandleFunc(base+"/users/", s.handleUserOperations)
}
