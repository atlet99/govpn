// Package api provides a REST API for GoVPN server management
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/atlet99/govpn/pkg/core"
)

// Server represents the REST API server
type Server struct {
	config     Config
	httpServer *http.Server
	vpnServer  *core.OpenVPNServer
	router     *http.ServeMux
	wg         sync.WaitGroup
	running    bool
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
func NewServer(config Config, vpnServer *core.OpenVPNServer) *Server {
	server := &Server{
		config:    config,
		vpnServer: vpnServer,
		router:    http.NewServeMux(),
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

// writeJSON is a helper function to write JSON responses
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			log.Printf("Error encoding JSON: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}
