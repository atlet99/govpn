package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/atlet99/govpn/pkg/auth"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// MaxIdentifierLength maximum length of an identifier
	MaxIdentifierLength = 64

	// MaxDomainNameLength maximum length of a domain name
	MaxDomainNameLength = 255

	// MaxUsernameLength maximum length of a username
	MaxUsernameLength = 32

	// MinPortNumber minimum port number
	MinPortNumber = 1

	// MaxPortNumber maximum port number
	MaxPortNumber = 65535
)

// Allowed values for encryption
var (
	// AllowedCiphers list of allowed encryption algorithms
	AllowedCiphers = map[string]bool{
		"AES-128-GCM":       true,
		"AES-256-GCM":       true,
		"CHACHA20-POLY1305": true,
	}

	// AllowedAuthDigests list of allowed authentication algorithms
	AllowedAuthDigests = map[string]bool{
		"SHA256": true,
		"SHA384": true,
		"SHA512": true,
	}

	// AllowedProtocols list of allowed protocols
	AllowedProtocols = map[string]bool{
		"tcp":  true,
		"udp":  true,
		"both": true,
	}
)

// Response represents a standardized API response
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// LoginRequest represents login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	MFACode  string `json:"mfa_code,omitempty"`
}

// LoginResponse represents login response
type LoginResponse struct {
	Token        string                 `json:"token"`
	RefreshToken string                 `json:"refresh_token,omitempty"`
	User         *auth.User             `json:"user"`
	RequiresMFA  bool                   `json:"requires_mfa"`
	MFAChallenge *auth.TOTPData         `json:"mfa_challenge,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// OIDCAuthRequest represents OIDC authentication request
type OIDCAuthRequest struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

// rateLimiter implements a simple rate limiting mechanism
type rateLimiter struct {
	mu          sync.Mutex
	ipHits      map[string][]time.Time
	maxRequests int           // Max requests allowed in time window
	window      time.Duration // Time window for rate limiting
}

// newRateLimiter creates a new rate limiter
func newRateLimiter(maxRequests int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		ipHits:      make(map[string][]time.Time),
		maxRequests: maxRequests,
		window:      window,
	}
}

// Allow checks if a request from the given IP should be allowed
func (rl *rateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Clean up old hits
	if hits, exists := rl.ipHits[ip]; exists {
		var newHits []time.Time
		for _, hit := range hits {
			if now.Sub(hit) < rl.window {
				newHits = append(newHits, hit)
			}
		}
		rl.ipHits[ip] = newHits
	}

	// Check if under the limit
	if len(rl.ipHits[ip]) < rl.maxRequests {
		rl.ipHits[ip] = append(rl.ipHits[ip], now)
		return true
	}

	return false
}

// middleware wraps an HTTP handler with common security checks
func (s *Server) middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")

		// Get client IP for rate limiting
		clientIP := getClientIP(r)
		if !s.rateLimiter.Allow(clientIP) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Check authentication if enabled
		if s.config.EnableAuth {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization required", http.StatusUnauthorized)
				return
			}

			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				// Validate algorithm
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(s.config.JWTSecret), nil
			})

			if err != nil || !token.Valid {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				log.Printf("Auth error: %v", err)
				return
			}
		}

		// Call the original handler
		next(w, r)
	}
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header first (if behind proxy)
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		// X-Forwarded-For can contain multiple IPs, use the first one
		parts := strings.Split(ip, ",")
		return strings.TrimSpace(parts[0])
	}

	// Fall back to RemoteAddr
	ip = r.RemoteAddr
	// Remove port if present
	if strings.Contains(ip, ":") {
		parts := strings.Split(ip, ":")
		ip = parts[0]
	}
	return ip
}

// handleGetStatus handles GET /status requests
func (s *Server) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	// Use middleware for security checks
	handler := s.middleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		status := s.vpnServer.Status()
		writeJSON(w, http.StatusOK, Response{
			Success: true,
			Data: map[string]interface{}{
				"running":      status.Running,
				"clientCount":  status.ClientCount,
				"bytesIn":      status.BytesIn,
				"bytesOut":     status.BytesOut,
				"activeRoutes": status.ActiveRoutes,
				"startTime":    status.StartTime,
			},
		})
	})

	handler(w, r)
}

// handleGetClients handles GET /clients requests
func (s *Server) handleGetClients(w http.ResponseWriter, r *http.Request) {
	handler := s.middleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// TODO: Get actual client data from VPN server
		clients := []map[string]interface{}{
			{
				"id":           "client1",
				"ipAddress":    "10.8.0.2",
				"bytesIn":      1024000,
				"bytesOut":     512000,
				"connectedAt":  "2023-06-01T15:30:22Z",
				"lastActivity": "2023-06-01T16:45:10Z",
			},
		}

		writeJSON(w, http.StatusOK, Response{
			Success: true,
			Data:    clients,
		})
	})

	handler(w, r)
}

// handleClientOperations handles operations on specific clients
func (s *Server) handleClientOperations(w http.ResponseWriter, r *http.Request) {
	handler := s.middleware(func(w http.ResponseWriter, r *http.Request) {
		pathParts := strings.Split(r.URL.Path, "/")
		if len(pathParts) < 4 {
			http.Error(w, "Invalid client ID", http.StatusBadRequest)
			return
		}

		clientID := pathParts[3]
		// Validate client ID - prevent path traversal and injection
		if !validateIdentifier(clientID) {
			http.Error(w, "Invalid client ID format", http.StatusBadRequest)
			return
		}

		switch r.Method {
		case http.MethodGet:
			// Get details for a specific client
			// TODO: Implement actual client data retrieval
			client := map[string]interface{}{
				"id":           clientID,
				"ipAddress":    "10.8.0.2",
				"bytesIn":      1024000,
				"bytesOut":     512000,
				"connectedAt":  "2023-06-01T15:30:22Z",
				"lastActivity": "2023-06-01T16:45:10Z",
			}

			writeJSON(w, http.StatusOK, Response{
				Success: true,
				Data:    client,
			})

		case http.MethodDelete:
			// Disconnect a client
			// TODO: Implement actual client disconnection
			writeJSON(w, http.StatusOK, Response{
				Success: true,
				Message: "Client disconnected successfully",
			})

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	handler(w, r)
}

// handleGetCertificates handles GET /certificates requests
func (s *Server) handleGetCertificates(w http.ResponseWriter, r *http.Request) {
	handler := s.middleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// TODO: Get actual certificate data from VPN server
		certificates := []map[string]interface{}{
			{
				"id":         "cert1",
				"commonName": "client1.govpn.example",
				"issuedAt":   "2023-05-01T10:00:00Z",
				"expiresAt":  "2024-05-01T10:00:00Z",
				"revoked":    false,
			},
		}

		writeJSON(w, http.StatusOK, Response{
			Success: true,
			Data:    certificates,
		})
	})

	handler(w, r)
}

// handleCertificateOperations handles operations on specific certificates
func (s *Server) handleCertificateOperations(w http.ResponseWriter, r *http.Request) {
	handler := s.middleware(func(w http.ResponseWriter, r *http.Request) {
		pathParts := strings.Split(r.URL.Path, "/")
		if len(pathParts) < 4 {
			http.Error(w, "Invalid certificate ID", http.StatusBadRequest)
			return
		}

		certID := pathParts[3]
		// Validate certificate ID
		if !validateIdentifier(certID) {
			http.Error(w, "Invalid certificate ID format", http.StatusBadRequest)
			return
		}

		switch r.Method {
		case http.MethodGet:
			// Get details for a specific certificate
			// TODO: Implement actual certificate data retrieval
			cert := map[string]interface{}{
				"id":         certID,
				"commonName": "client1.govpn.example",
				"issuedAt":   "2023-05-01T10:00:00Z",
				"expiresAt":  "2024-05-01T10:00:00Z",
				"revoked":    false,
				"serial":     "1234567890ABCDEF",
				"details": map[string]interface{}{
					"fingerprint": "12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0",
					"issuer":      "GoVPN Root CA",
				},
			}

			writeJSON(w, http.StatusOK, Response{
				Success: true,
				Data:    cert,
			})

		case http.MethodPost:
			if pathParts[3] == "revoke" && len(pathParts) > 4 {
				// Validate the revocation target
				if !validateIdentifier(pathParts[4]) {
					http.Error(w, "Invalid certificate ID format", http.StatusBadRequest)
					return
				}

				// Revoke a certificate
				// TODO: Implement actual certificate revocation
				writeJSON(w, http.StatusOK, Response{
					Success: true,
					Message: "Certificate revoked successfully",
				})
				return
			}

			// Create a new certificate
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}

			// Validate required fields
			commonName, ok := req["commonName"].(string)
			if !ok || commonName == "" {
				http.Error(w, "Missing required field: commonName", http.StatusBadRequest)
				return
			}

			// Validate the common name - prevent injection
			if !validateDomainName(commonName) {
				http.Error(w, "Invalid commonName format", http.StatusBadRequest)
				return
			}

			// TODO: Implement actual certificate creation
			writeJSON(w, http.StatusCreated, Response{
				Success: true,
				Message: "Certificate created successfully",
				Data: map[string]interface{}{
					"id":         "new-cert-id",
					"commonName": commonName,
					"issuedAt":   time.Now().Format(time.RFC3339),
					"expiresAt":  time.Now().AddDate(1, 0, 0).Format(time.RFC3339),
					"revoked":    false,
				},
			})

		case http.MethodDelete:
			// Delete a certificate
			// TODO: Implement actual certificate deletion
			writeJSON(w, http.StatusOK, Response{
				Success: true,
				Message: "Certificate deleted successfully",
			})

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	handler(w, r)
}

// handleGetConfig handles GET /config requests
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	handler := s.middleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// TODO: Get actual configuration from VPN server
		config := map[string]interface{}{
			"port":            1194,
			"protocol":        "udp",
			"cipher":          "AES-256-GCM",
			"auth":            "SHA512",
			"serverNetwork":   "10.8.0.0/24",
			"pushDns":         []string{"8.8.8.8", "8.8.4.4"},
			"keepAlive":       10,
			"keepAliveRetry":  120,
			"tlsVersion":      "1.3",
			"redirectGateway": true,
		}

		writeJSON(w, http.StatusOK, Response{
			Success: true,
			Data:    config,
		})
	})

	handler(w, r)
}

// handleUpdateConfig handles POST /config/update requests
func (s *Server) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	handler := s.middleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var config map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate configuration fields
		if err := validateConfigUpdate(config); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// TODO: Update VPN server configuration
		writeJSON(w, http.StatusOK, Response{
			Success: true,
			Message: "Configuration updated successfully",
		})
	})

	handler(w, r)
}

// handleGetUsers handles GET /users requests
func (s *Server) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	handler := s.middleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// TODO: Get actual user data
		users := []map[string]interface{}{
			{
				"id":        "user1",
				"username":  "john.doe",
				"createdAt": "2023-01-01T10:00:00Z",
				"active":    true,
				"groups":    []string{"admin", "users"},
			},
		}

		writeJSON(w, http.StatusOK, Response{
			Success: true,
			Data:    users,
		})
	})

	handler(w, r)
}

// handleUserOperations handles operations on specific users
func (s *Server) handleUserOperations(w http.ResponseWriter, r *http.Request) {
	handler := s.middleware(func(w http.ResponseWriter, r *http.Request) {
		pathParts := strings.Split(r.URL.Path, "/")
		if len(pathParts) < 4 {
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}

		userID := pathParts[3]
		// Validate user ID
		if !validateIdentifier(userID) {
			http.Error(w, "Invalid user ID format", http.StatusBadRequest)
			return
		}

		switch r.Method {
		case http.MethodGet:
			// Get details for a specific user
			// TODO: Implement actual user data retrieval
			user := map[string]interface{}{
				"id":        userID,
				"username":  "john.doe",
				"email":     "john.doe@example.com",
				"createdAt": "2023-01-01T10:00:00Z",
				"active":    true,
				"groups":    []string{"admin", "users"},
			}

			writeJSON(w, http.StatusOK, Response{
				Success: true,
				Data:    user,
			})

		case http.MethodPost:
			// Update a user
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}

			// Validate user data
			if err := validateUserData(req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// TODO: Implement actual user update
			writeJSON(w, http.StatusOK, Response{
				Success: true,
				Message: "User updated successfully",
			})

		case http.MethodPut:
			// Create a new user
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}

			// Validate username
			username, ok := req["username"].(string)
			if !ok || username == "" {
				http.Error(w, "Missing required field: username", http.StatusBadRequest)
				return
			}

			if !validateUsername(username) {
				http.Error(w, "Invalid username format", http.StatusBadRequest)
				return
			}

			// Validate user data
			if err := validateUserData(req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// TODO: Implement actual user creation
			writeJSON(w, http.StatusCreated, Response{
				Success: true,
				Message: "User created successfully",
				Data: map[string]interface{}{
					"id":        "new-user-id",
					"username":  username,
					"createdAt": time.Now().Format(time.RFC3339),
					"active":    true,
				},
			})

		case http.MethodDelete:
			// Delete a user
			// TODO: Implement actual user deletion
			writeJSON(w, http.StatusOK, Response{
				Success: true,
				Message: "User deleted successfully",
			})

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	handler(w, r)
}

// validateIdentifier checks if an ID is valid
func validateIdentifier(id string) bool {
	// Allow alphanumeric characters and some special characters, but no path traversal
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' || r == '@') {
			return false
		}
	}
	return id != "" && len(id) <= MaxIdentifierLength
}

// validateDomainName checks if a domain name is valid
func validateDomainName(domain string) bool {
	// Simple validation - more complex validation would use regex
	for _, r := range domain {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '.' || r == '*') {
			return false
		}
	}
	return domain != "" && len(domain) <= MaxDomainNameLength && !strings.Contains(domain, "..")
}

// validateUsername checks if a username is valid
func validateUsername(username string) bool {
	// Allow alphanumeric characters and some special characters
	for _, r := range username {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return username != "" && len(username) <= MaxUsernameLength
}

// validateConfigUpdate validates configuration update data
func validateConfigUpdate(config map[string]interface{}) error {
	// Check port
	if port, ok := config["port"].(float64); ok {
		if port < MinPortNumber || port > MaxPortNumber {
			return fmt.Errorf("invalid port number")
		}
	}

	// Check protocol
	if protocol, ok := config["protocol"].(string); ok {
		if !AllowedProtocols[protocol] {
			return fmt.Errorf("invalid protocol, must be tcp, udp, or both")
		}
	}

	// Check cipher
	if cipher, ok := config["cipher"].(string); ok {
		if !AllowedCiphers[cipher] {
			return fmt.Errorf("unsupported cipher")
		}
	}

	// Check auth digest
	if auth, ok := config["auth"].(string); ok {
		if !AllowedAuthDigests[auth] {
			return fmt.Errorf("unsupported auth digest")
		}
	}

	return nil
}

// validateUserData validates user data
func validateUserData(data map[string]interface{}) error {
	// Validate email if present
	if email, ok := data["email"].(string); ok && email != "" {
		if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
			return fmt.Errorf("invalid email format")
		}
	}

	// Validate groups if present
	if groups, ok := data["groups"].([]interface{}); ok {
		for _, g := range groups {
			group, ok := g.(string)
			if !ok || !validateIdentifier(group) {
				return fmt.Errorf("invalid group name")
			}
		}
	}

	return nil
}

// writeJSON is a helper function to write JSON responses
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// handleLogin handles user login with password/username
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Error:   "Method not allowed",
		})
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Invalid request body",
		})
		return
	}

	// Validate input
	if req.Username == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Username and password are required",
		})
		return
	}

	// Authenticate user
	authResult, err := s.authManager.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, Response{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	// Handle MFA if required
	if authResult.RequiresMFA {
		if req.MFACode == "" {
			// Return MFA challenge
			writeJSON(w, http.StatusOK, Response{
				Success: true,
				Data: LoginResponse{
					RequiresMFA:  true,
					MFAChallenge: authResult.MFAChallenge,
					User:         authResult.User,
				},
			})
			return
		}

		// Validate MFA code
		mfaResult, err := s.authManager.ValidateMFA(req.Username, req.MFACode)
		if err != nil || !mfaResult.Valid {
			writeJSON(w, http.StatusUnauthorized, Response{
				Success: false,
				Error:   "Invalid MFA code",
			})
			return
		}
	}

	// Generate JWT token
	token, err := s.generateJWTToken(authResult.User)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Error:   "Failed to generate token",
		})
		return
	}

	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Data: LoginResponse{
			Token:    token,
			User:     authResult.User,
			Metadata: authResult.Metadata,
		},
	})
}

// handleOIDCAuth handles OIDC authentication initiation
func (s *Server) handleOIDCAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Error:   "Method not allowed",
		})
		return
	}

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		userID = "web-user-" + fmt.Sprintf("%d", time.Now().Unix())
	}

	authURL, err := s.authManager.GetOIDCAuthURL(userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Data: map[string]string{
			"auth_url": authURL,
			"user_id":  userID,
		},
	})
}

// handleOIDCCallback handles OIDC callback
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Error:   "Method not allowed",
		})
		return
	}

	var req OIDCAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, Response{
			Success: false,
			Error:   "Invalid request body",
		})
		return
	}

	// Handle OIDC callback
	session, err := s.authManager.HandleOIDCCallback(req.Code, req.State)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, Response{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	// Authenticate OIDC user
	authResult, err := s.authManager.AuthenticateOIDCUser(session)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	// Generate JWT token
	token, err := s.generateJWTToken(authResult.User)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Response{
			Success: false,
			Error:   "Failed to generate token",
		})
		return
	}

	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Data: LoginResponse{
			Token:    token,
			User:     authResult.User,
			Metadata: authResult.Metadata,
		},
	})
}

// generateJWTToken generates JWT token for user
func (s *Server) generateJWTToken(user *auth.User) (string, error) {
	claims := jwt.MapClaims{
		"sub":      user.ID,
		"username": user.Username,
		"roles":    user.Roles,
		"source":   user.Source,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
		"iat":      time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWTSecret))
}

// handleAuthStatus returns current authentication status
func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, Response{
			Success: false,
			Error:   "Method not allowed",
		})
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		writeJSON(w, http.StatusUnauthorized, Response{
			Success: false,
			Error:   "Authorization header required",
		})
		return
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, Response{
			Success: false,
			Error:   "Invalid authorization format",
		})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWTSecret), nil
	})

	if err != nil || !token.Valid {
		writeJSON(w, http.StatusUnauthorized, Response{
			Success: false,
			Error:   "Invalid token",
		})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, Response{
			Success: false,
			Error:   "Invalid token claims",
		})
		return
	}

	writeJSON(w, http.StatusOK, Response{
		Success: true,
		Data: map[string]interface{}{
			"authenticated": true,
			"user_id":       claims["sub"],
			"username":      claims["username"],
			"roles":         claims["roles"],
			"source":        claims["source"],
		},
	})
}

// handleHealth returns server health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Simple health check - if we can respond, we're healthy
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// handlePublicStatus returns server status without authentication
func (s *Server) handlePublicStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Mock server status data (replace with real data later)
	status := map[string]interface{}{
		"status":            "running",
		"uptime":            "3 minutes",
		"connected_clients": 3,
		"traffic":           "1.2 MB",
		"last_updated":      time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(status)
}

// handlePublicClients returns client list without authentication
func (s *Server) handlePublicClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Mock client data (replace with real data later)
	clients := []map[string]interface{}{
		{
			"id":           "client-001",
			"username":     "user1@example.com",
			"ip":           "10.8.0.2",
			"connected_at": time.Now().Add(-30 * time.Minute).Format(time.RFC3339),
			"bytes_in":     262144,
			"bytes_out":    524288,
		},
		{
			"id":           "client-002",
			"username":     "user2@example.com",
			"ip":           "10.8.0.3",
			"connected_at": time.Now().Add(-15 * time.Minute).Format(time.RFC3339),
			"bytes_in":     131072,
			"bytes_out":    262144,
		},
		{
			"id":           "client-003",
			"username":     "user3@example.com",
			"ip":           "10.8.0.4",
			"connected_at": time.Now().Add(-5 * time.Minute).Format(time.RFC3339),
			"bytes_in":     65536,
			"bytes_out":    131072,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(clients)
}
