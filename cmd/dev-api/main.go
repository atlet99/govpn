package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Mock API responses
type ApiResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type ServerStatus struct {
	Running      bool     `json:"running"`
	ClientCount  int      `json:"clientCount"`
	BytesIn      uint64   `json:"bytesIn"`
	BytesOut     uint64   `json:"bytesOut"`
	ActiveRoutes []string `json:"activeRoutes"`
	StartTime    int64    `json:"startTime"`
}

type User struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	LastLogin string `json:"lastLogin"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

type Connection struct {
	ID                string `json:"id"`
	Username          string `json:"username"`
	RealIP            string `json:"realIP"`
	VirtualIP         string `json:"virtualIP"`
	Protocol          string `json:"protocol"`
	ConnectedAt       string `json:"connectedAt"`
	BytesIn           uint64 `json:"bytesIn"`
	BytesOut          uint64 `json:"bytesOut"`
	Status            string `json:"status"`
	Location          string `json:"location"`
	ObfuscationMethod string `json:"obfuscationMethod"`
}

type Certificate struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	ValidFrom    string `json:"validFrom"`
	ValidTo      string `json:"validTo"`
	SerialNumber string `json:"serialNumber"`
	Algorithm    string `json:"algorithm"`
	Status       string `json:"status"`
}

var (
	startTime = time.Now().Unix()

	mockUsers = []User{
		{
			ID: "1", Username: "admin", Email: "admin@govpn.com", Role: "admin", Status: "active",
			LastLogin: "2024-03-20T15:30:00Z", CreatedAt: "2024-01-15T10:00:00Z", UpdatedAt: "2024-03-20T15:30:00Z",
		},
		{
			ID: "2", Username: "john.doe", Email: "john.doe@company.com", Role: "user", Status: "active",
			LastLogin: "2024-03-20T14:45:00Z", CreatedAt: "2024-02-01T09:15:00Z", UpdatedAt: "2024-03-15T11:20:00Z",
		},
		{
			ID: "3", Username: "jane.smith", Email: "jane.smith@company.com", Role: "user", Status: "inactive",
			LastLogin: "2024-03-18T16:20:00Z", CreatedAt: "2024-02-10T14:30:00Z", UpdatedAt: "2024-03-18T16:20:00Z",
		},
	}

	mockConnections = []Connection{
		{
			ID: "1", Username: "john.doe", RealIP: "203.0.113.10", VirtualIP: "10.8.0.2",
			Protocol: "UDP", ConnectedAt: "2024-03-20T14:45:00Z", BytesIn: 1024 * 1024 * 50, BytesOut: 1024 * 1024 * 120,
			Status: "connected", Location: "New York, US", ObfuscationMethod: "TLS Tunnel",
		},
		{
			ID: "2", Username: "jane.smith", RealIP: "198.51.100.25", VirtualIP: "10.8.0.3",
			Protocol: "TCP", ConnectedAt: "2024-03-20T16:20:00Z", BytesIn: 1024 * 1024 * 75, BytesOut: 1024 * 1024 * 200,
			Status: "connected", Location: "London, UK", ObfuscationMethod: "HTTP Mimicry",
		},
	}

	mockCertificates = []Certificate{
		{
			ID: "1", Name: "ca-cert", Type: "ca", Subject: "CN=GoVPN CA", Issuer: "CN=GoVPN CA",
			ValidFrom: "2024-01-01T00:00:00Z", ValidTo: "2025-01-01T00:00:00Z",
			SerialNumber: "01", Algorithm: "RSA-2048", Status: "valid",
		},
		{
			ID: "2", Name: "server-cert", Type: "server", Subject: "CN=govpn.example.com", Issuer: "CN=GoVPN CA",
			ValidFrom: "2024-01-01T00:00:00Z", ValidTo: "2024-12-31T23:59:59Z",
			SerialNumber: "02", Algorithm: "RSA-2048", Status: "expiring",
		},
	}
)

func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	status := ServerStatus{
		Running:      true,
		ClientCount:  len(mockConnections),
		BytesIn:      1024 * 1024 * 150, // 150MB
		BytesOut:     1024 * 1024 * 300, // 300MB
		ActiveRoutes: []string{"10.8.0.0/24", "192.168.1.0/24"},
		StartTime:    startTime,
	}

	writeJSON(w, http.StatusOK, ApiResponse{Success: true, Data: status})
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, http.StatusOK, ApiResponse{Success: true, Data: mockUsers})
	case "POST":
		var newUser User
		if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
			writeJSON(w, http.StatusBadRequest, ApiResponse{Success: false, Error: "Invalid JSON"})
			return
		}

		newUser.ID = fmt.Sprintf("%d", len(mockUsers)+1)
		newUser.CreatedAt = time.Now().Format(time.RFC3339)
		newUser.UpdatedAt = newUser.CreatedAt
		mockUsers = append(mockUsers, newUser)

		writeJSON(w, http.StatusCreated, ApiResponse{Success: true, Data: newUser, Message: "User created successfully"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func handleUserOperations(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	parts := strings.Split(path, "/")
	userID := parts[0]

	switch r.Method {
	case "GET":
		for _, user := range mockUsers {
			if user.ID == userID {
				writeJSON(w, http.StatusOK, ApiResponse{Success: true, Data: user})
				return
			}
		}
		writeJSON(w, http.StatusNotFound, ApiResponse{Success: false, Error: "User not found"})

	case "PATCH", "PUT":
		for i, user := range mockUsers {
			if user.ID == userID {
				var updates User
				if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
					writeJSON(w, http.StatusBadRequest, ApiResponse{Success: false, Error: "Invalid JSON"})
					return
				}

				// Update fields if provided
				if updates.Username != "" {
					user.Username = updates.Username
				}
				if updates.Email != "" {
					user.Email = updates.Email
				}
				if updates.Role != "" {
					user.Role = updates.Role
				}
				if updates.Status != "" {
					user.Status = updates.Status
				}
				user.UpdatedAt = time.Now().Format(time.RFC3339)

				mockUsers[i] = user
				writeJSON(w, http.StatusOK, ApiResponse{Success: true, Data: user, Message: "User updated successfully"})
				return
			}
		}
		writeJSON(w, http.StatusNotFound, ApiResponse{Success: false, Error: "User not found"})

	case "DELETE":
		for i, user := range mockUsers {
			if user.ID == userID {
				mockUsers = append(mockUsers[:i], mockUsers[i+1:]...)
				writeJSON(w, http.StatusOK, ApiResponse{Success: true, Message: "User deleted successfully"})
				return
			}
		}
		writeJSON(w, http.StatusNotFound, ApiResponse{Success: false, Error: "User not found"})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func handleClients(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, ApiResponse{Success: true, Data: mockConnections})
}

func handleCertificates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, http.StatusOK, ApiResponse{Success: true, Data: mockCertificates})
	case "POST":
		var newCert Certificate
		if err := json.NewDecoder(r.Body).Decode(&newCert); err != nil {
			writeJSON(w, http.StatusBadRequest, ApiResponse{Success: false, Error: "Invalid JSON"})
			return
		}

		newCert.ID = fmt.Sprintf("%d", len(mockCertificates)+1)
		newCert.ValidFrom = time.Now().Format(time.RFC3339)
		newCert.ValidTo = time.Now().AddDate(1, 0, 0).Format(time.RFC3339) // 1 year
		newCert.Status = "valid"
		mockCertificates = append(mockCertificates, newCert)

		writeJSON(w, http.StatusCreated, ApiResponse{Success: true, Data: newCert, Message: "Certificate created successfully"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"server": "10.8.0.0/24",
		"port":   1194,
		"proto":  "udp",
		"dev":    "tun",
		"ca":     "/etc/govpn/ca.crt",
		"cert":   "/etc/govpn/server.crt",
		"key":    "/etc/govpn/server.key",
		"dh":     "/etc/govpn/dh2048.pem",
	}

	writeJSON(w, http.StatusOK, ApiResponse{Success: true, Data: config})
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	logs := []map[string]interface{}{
		{
			"timestamp": time.Now().Add(-time.Hour).Format(time.RFC3339),
			"level":     "info",
			"component": "auth",
			"message":   "User john.doe authenticated successfully",
			"user":      "john.doe",
			"ip":        "203.0.113.10",
		},
		{
			"timestamp": time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
			"level":     "warning",
			"component": "network",
			"message":   "High bandwidth usage detected",
			"user":      "jane.smith",
			"ip":        "198.51.100.25",
		},
	}

	writeJSON(w, http.StatusOK, ApiResponse{Success: true, Data: logs})
}

func main() {
	port := flag.Int("port", 8080, "API port")
	host := flag.String("host", "127.0.0.1", "API host")

	flag.Parse()

	log.Printf("Starting GoVPN Development API Server...")
	log.Printf("This is a development-only server with mock data")

	mux := http.NewServeMux()

	// Register routes with CORS
	mux.HandleFunc("/api/v1/status", enableCORS(handleStatus))
	mux.HandleFunc("/api/v1/users", enableCORS(handleUsers))
	mux.HandleFunc("/api/v1/users/", enableCORS(handleUserOperations))
	mux.HandleFunc("/api/v1/clients", enableCORS(handleClients))
	mux.HandleFunc("/api/v1/certificates", enableCORS(handleCertificates))
	mux.HandleFunc("/api/v1/config", enableCORS(handleConfig))
	mux.HandleFunc("/api/v1/logs", enableCORS(handleLogs))

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", *host, *port),
		Handler: mux,
	}

	// Start server in background
	go func() {
		log.Printf("Development API server running at http://%s:%d/api/v1", *host, *port)
		log.Printf("Available endpoints:")
		log.Printf("  GET  /api/v1/status")
		log.Printf("  GET  /api/v1/users")
		log.Printf("  POST /api/v1/users")
		log.Printf("  GET  /api/v1/clients")
		log.Printf("  GET  /api/v1/certificates")
		log.Printf("  GET  /api/v1/config")
		log.Printf("  GET  /api/v1/logs")

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Setup graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Wait for signal
	<-c
	log.Println("Shutting down...")

	// Stop server
	if err := server.Shutdown(context.TODO()); err != nil {
		log.Printf("Error shutting down server: %v", err)
	}

	log.Println("Development API server stopped")
}
