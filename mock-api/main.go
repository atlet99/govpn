package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type ServerStatus struct {
	Status      string    `json:"status"`
	Uptime      string    `json:"uptime"`
	Clients     int       `json:"connected_clients"`
	Traffic     string    `json:"traffic"`
	LastUpdated time.Time `json:"last_updated"`
}

type ClientInfo struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	IP          string    `json:"ip"`
	ConnectedAt time.Time `json:"connected_at"`
	BytesIn     int64     `json:"bytes_in"`
	BytesOut    int64     `json:"bytes_out"`
}

var startTime = time.Now()

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "GoVPN Server",
		"version": "v0.1.0",
	}); err != nil {
		log.Printf("Error encoding health response: %v", err)
	}
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	uptime := time.Since(startTime)
	status := ServerStatus{
		Status:      "running",
		Uptime:      fmt.Sprintf("%.0f minutes", uptime.Minutes()),
		Clients:     3,
		Traffic:     "1.2 MB",
		LastUpdated: time.Now(),
	}

	if err := json.NewEncoder(w).Encode(status); err != nil {
		log.Printf("Error encoding status response: %v", err)
	}
}

func clientsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	clients := []ClientInfo{
		{
			ID:          "client-001",
			Username:    "user1@example.com",
			IP:          "10.8.0.2",
			ConnectedAt: time.Now().Add(-30 * time.Minute),
			BytesIn:     1024 * 256,
			BytesOut:    1024 * 512,
		},
		{
			ID:          "client-002",
			Username:    "user2@example.com",
			IP:          "10.8.0.3",
			ConnectedAt: time.Now().Add(-15 * time.Minute),
			BytesIn:     1024 * 128,
			BytesOut:    1024 * 256,
		},
		{
			ID:          "client-003",
			Username:    "user3@example.com",
			IP:          "10.8.0.4",
			ConnectedAt: time.Now().Add(-5 * time.Minute),
			BytesIn:     1024 * 64,
			BytesOut:    1024 * 128,
		},
	}

	if err := json.NewEncoder(w).Encode(clients); err != nil {
		log.Printf("Error encoding clients response: %v", err)
	}
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	config := map[string]interface{}{
		"server_network": "10.8.0.0/24",
		"port":           1194,
		"protocol":       "UDP",
		"cipher":         "AES-256-GCM",
		"auth":           "SHA256",
		"max_clients":    100,
		"compression":    true,
		"oidc_enabled":   false,
	}

	if err := json.NewEncoder(w).Encode(config); err != nil {
		log.Printf("Error encoding config response: %v", err)
	}
}

func main() {
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/api/status", statusHandler)
	http.HandleFunc("/api/clients", clientsHandler)
	http.HandleFunc("/api/config", configHandler)

	log.Println("GoVPN Mock API Server starting on :8080")
	log.Println("Endpoints:")
	log.Println("  GET /health - Health check")
	log.Println("  GET /api/status - Server status")
	log.Println("  GET /api/clients - Connected clients")
	log.Println("  GET /api/config - Server configuration")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
