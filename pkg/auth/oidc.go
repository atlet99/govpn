package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCConfig configuration for OIDC authentication
type OIDCConfig struct {
	Enabled               bool              `json:"enabled"`
	ProviderURL           string            `json:"provider_url"`
	ClientID              string            `json:"client_id"`
	ClientSecret          string            `json:"client_secret"`
	RedirectURL           string            `json:"redirect_url"`
	Scopes                []string          `json:"scopes"`
	UserInfoEndpoint      string            `json:"user_info_endpoint"`
	TokenEndpoint         string            `json:"token_endpoint"`
	AuthorizationEndpoint string            `json:"authorization_endpoint"`
	JWKSEndpoint          string            `json:"jwks_endpoint"`
	IssuerValidation      bool              `json:"issuer_validation"`
	RequiredClaims        map[string]string `json:"required_claims"`
	ClaimMappings         ClaimMappings     `json:"claim_mappings"`
	SessionTimeout        time.Duration     `json:"session_timeout"`
	RefreshTokenEnabled   bool              `json:"refresh_token_enabled"`
	DeviceFlowEnabled     bool              `json:"device_flow_enabled"`
	PkceEnabled           bool              `json:"pkce_enabled"`
}

// ClaimMappings mapping of OIDC claims to local user attributes
type ClaimMappings struct {
	Username    string `json:"username"`     // Claim for username
	Email       string `json:"email"`        // Claim for email
	FirstName   string `json:"first_name"`   // Claim for first name
	LastName    string `json:"last_name"`    // Claim for last name
	Groups      string `json:"groups"`       // Claim for groups
	Roles       string `json:"roles"`        // Claim for roles
	DisplayName string `json:"display_name"` // Claim for display name
}

// OIDCProvider represents OIDC authentication provider using standard oauth2 library
type OIDCProvider struct {
	config    *OIDCConfig
	oauth2Cfg *oauth2.Config
	verifier  *oidc.IDTokenVerifier
	provider  *oidc.Provider
	mu        sync.RWMutex
	sessions  map[string]*OIDCSession
	states    map[string]*AuthState
	logger    Logger
}

// OIDCSession represents active OIDC user session
type OIDCSession struct {
	UserID       string                 `json:"user_id"`
	Username     string                 `json:"username"`
	Email        string                 `json:"email"`
	Claims       map[string]interface{} `json:"claims"`
	AccessToken  string                 `json:"access_token"`
	RefreshToken string                 `json:"refresh_token"`
	IDToken      string                 `json:"id_token"`
	ExpiresAt    time.Time              `json:"expires_at"`
	CreatedAt    time.Time              `json:"created_at"`
	LastAccess   time.Time              `json:"last_access"`
	Groups       []string               `json:"groups"`
	Roles        []string               `json:"roles"`
	OAuth2Token  *oauth2.Token          `json:"-"` // The underlying oauth2 token
}

// AuthState represents OAuth2 authorization state
type AuthState struct {
	State           string    `json:"state"`
	CodeVerifier    string    `json:"code_verifier"`
	CodeChallenge   string    `json:"code_challenge"`
	RedirectURI     string    `json:"redirect_uri"`
	Scopes          []string  `json:"scopes"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	UserID          string    `json:"user_id,omitempty"`
	DeviceCode      string    `json:"device_code,omitempty"`
	UserCode        string    `json:"user_code,omitempty"`
	VerificationURI string    `json:"verification_uri,omitempty"`
}

// TokenResponse represents token endpoint response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// UserInfo represents user information from OIDC provider
type UserInfo struct {
	Sub               string                 `json:"sub"`
	Name              string                 `json:"name,omitempty"`
	GivenName         string                 `json:"given_name,omitempty"`
	FamilyName        string                 `json:"family_name,omitempty"`
	PreferredUsername string                 `json:"preferred_username,omitempty"`
	Email             string                 `json:"email,omitempty"`
	EmailVerified     bool                   `json:"email_verified,omitempty"`
	Groups            []string               `json:"groups,omitempty"`
	Roles             []string               `json:"roles,omitempty"`
	CustomClaims      map[string]interface{} `json:"-"`
}

// DeviceAuthResponse represents device authorization endpoint response
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Logger interface for logging
type Logger interface {
	Printf(format string, v ...interface{})
	Errorf(format string, v ...interface{})
	Infof(format string, v ...interface{})
	Debugf(format string, v ...interface{})
}

// NewOIDCProvider creates new OIDC provider using standard oauth2 library
func NewOIDCProvider(config *OIDCConfig, logger Logger) (*OIDCProvider, error) {
	if config == nil {
		return nil, fmt.Errorf("OIDC config is required")
	}

	if !config.Enabled {
		return nil, fmt.Errorf("OIDC is disabled")
	}

	if config.ProviderURL == "" {
		return nil, fmt.Errorf("provider URL is required")
	}

	if config.ClientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}

	// Set default values
	if len(config.Scopes) == 0 {
		config.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	if config.SessionTimeout == 0 {
		config.SessionTimeout = 24 * time.Hour
	}

	// Setup default claims mapping
	setDefaultClaimMappings(config)

	ctx := context.Background()

	// Initialize OIDC provider using the standard library
	provider, err := oidc.NewProvider(ctx, config.ProviderURL)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OIDC provider: %w", err)
	}

	// Configure OAuth2
	oauth2Cfg := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       config.Scopes,
	}

	// Create ID token verifier
	oidcConfig := &oidc.Config{
		ClientID:             config.ClientID,
		SkipClientIDCheck:    !config.IssuerValidation,
		SkipExpiryCheck:      false,
		SkipIssuerCheck:      !config.IssuerValidation,
		SupportedSigningAlgs: []string{"RS256", "ES256", "PS256"},
	}
	verifier := provider.Verifier(oidcConfig)

	oidcProvider := &OIDCProvider{
		config:    config,
		oauth2Cfg: oauth2Cfg,
		verifier:  verifier,
		provider:  provider,
		sessions:  make(map[string]*OIDCSession),
		states:    make(map[string]*AuthState),
		logger:    logger,
	}

	// Automatic endpoint discovery via .well-known/openid_configuration
	if err := oidcProvider.discoverEndpoints(); err != nil {
		logger.Printf("Warning: failed to discover OIDC endpoints: %v", err)
	}

	// Start goroutine for cleaning expired sessions
	go oidcProvider.cleanupExpiredSessions()

	logger.Printf("Initialized OIDC provider for issuer: %s", config.ProviderURL)
	return oidcProvider, nil
}

// discoverEndpoints automatically discovers OIDC endpoints
func (p *OIDCProvider) discoverEndpoints() error {
	discoveryURL := strings.TrimSuffix(p.config.ProviderURL, "/") + "/.well-known/openid_configuration"

	resp, err := http.Get(discoveryURL)
	if err != nil {
		return fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery endpoint returned %d", resp.StatusCode)
	}

	var discovery struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		UserInfoEndpoint      string `json:"userinfo_endpoint"`
		JwksURI               string `json:"jwks_uri"`
		DeviceAuthEndpoint    string `json:"device_authorization_endpoint"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return fmt.Errorf("failed to decode discovery document: %w", err)
	}

	// Update configuration with discovered endpoints (if not set manually)
	if p.config.AuthorizationEndpoint == "" {
		p.config.AuthorizationEndpoint = discovery.AuthorizationEndpoint
	}
	if p.config.TokenEndpoint == "" {
		p.config.TokenEndpoint = discovery.TokenEndpoint
	}
	if p.config.UserInfoEndpoint == "" {
		p.config.UserInfoEndpoint = discovery.UserInfoEndpoint
	}
	if p.config.JWKSEndpoint == "" {
		p.config.JWKSEndpoint = discovery.JwksURI
	}

	p.logger.Printf("Discovered OIDC endpoints for issuer: %s", discovery.Issuer)
	return nil
}

// GetAuthorizationURL creates URL for user authorization
func (p *OIDCProvider) GetAuthorizationURL(userID string) (string, error) {
	state, err := generateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}

	authState := &AuthState{
		State:     state,
		Scopes:    p.config.Scopes,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(10 * time.Minute),
		UserID:    userID,
	}

	p.mu.Lock()
	p.states[state] = authState
	p.mu.Unlock()

	var authURL string
	if p.config.PkceEnabled {
		// Generate PKCE verifier
		verifier := oauth2.GenerateVerifier()
		authState.CodeVerifier = verifier
		authURL = p.oauth2Cfg.AuthCodeURL(
			state,
			oauth2.S256ChallengeOption(verifier),
			oauth2.AccessTypeOffline, // Request refresh token
		)
	} else {
		authURL = p.oauth2Cfg.AuthCodeURL(
			state,
			oauth2.AccessTypeOffline, // Request refresh token
		)
	}

	return authURL, nil
}

// HandleCallback handles callback from OIDC provider
func (p *OIDCProvider) HandleCallback(code, state string) (*OIDCSession, error) {
	p.mu.Lock()
	authState, exists := p.states[state]
	if !exists {
		p.mu.Unlock()
		return nil, fmt.Errorf("invalid or expired state")
	}
	delete(p.states, state)
	p.mu.Unlock()

	if time.Now().After(authState.ExpiresAt) {
		return nil, fmt.Errorf("authorization state expired")
	}

	ctx := context.Background()

	// Exchange authorization code for tokens using standard oauth2 library
	var token *oauth2.Token
	var err error

	if p.config.PkceEnabled && authState.CodeVerifier != "" {
		token, err = p.oauth2Cfg.Exchange(ctx, code, oauth2.VerifierOption(authState.CodeVerifier))
	} else {
		token, err = p.oauth2Cfg.Exchange(ctx, code)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for tokens: %w", err)
	}

	// Extract and verify ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Extract claims from ID token
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	// Get user information from userinfo endpoint if needed
	userInfo, err := p.getUserInfo(ctx, token)
	if err != nil {
		p.logger.Printf("Warning: failed to get user info: %v", err)
		// Continue without userinfo - ID token should be sufficient
	}

	// Create session
	session := &OIDCSession{
		UserID:       authState.UserID,
		Username:     p.extractClaim(userInfo, claims, p.config.ClaimMappings.Username),
		Email:        p.extractClaim(userInfo, claims, p.config.ClaimMappings.Email),
		Claims:       claims,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      rawIDToken,
		ExpiresAt:    token.Expiry,
		CreatedAt:    time.Now(),
		LastAccess:   time.Now(),
		Groups:       p.extractGroups(userInfo, claims),
		Roles:        p.extractRoles(userInfo, claims),
		OAuth2Token:  token,
	}

	// Save session
	sessionID := generateSessionID()
	p.mu.Lock()
	p.sessions[sessionID] = session
	p.mu.Unlock()

	p.logger.Printf("Created OIDC session for user: %s", session.Username)
	return session, nil
}

// StartDeviceFlow starts Device Authorization Flow
func (p *OIDCProvider) StartDeviceFlow() (*DeviceAuthResponse, error) {
	if !p.config.DeviceFlowEnabled {
		return nil, fmt.Errorf("device flow is disabled")
	}

	ctx := context.Background()

	// Use the standard oauth2 device flow
	deviceAuthResp, err := p.oauth2Cfg.DeviceAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start device flow: %w", err)
	}

	return &DeviceAuthResponse{
		DeviceCode:              deviceAuthResp.DeviceCode,
		UserCode:                deviceAuthResp.UserCode,
		VerificationURI:         deviceAuthResp.VerificationURI,
		VerificationURIComplete: deviceAuthResp.VerificationURIComplete,
		ExpiresIn:               int(time.Until(deviceAuthResp.Expiry).Seconds()),
		Interval:                int(deviceAuthResp.Interval),
	}, nil
}

// ValidateSession validates session validity
func (p *OIDCProvider) ValidateSession(sessionID string) (*OIDCSession, error) {
	p.mu.RLock()
	session, exists := p.sessions[sessionID]
	p.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	if time.Now().After(session.ExpiresAt) {
		p.mu.Lock()
		delete(p.sessions, sessionID)
		p.mu.Unlock()
		return nil, fmt.Errorf("session expired")
	}

	// Update last access time
	session.LastAccess = time.Now()

	return session, nil
}

// RefreshSession refreshes session using refresh token
func (p *OIDCProvider) RefreshSession(sessionID string) (*OIDCSession, error) {
	if !p.config.RefreshTokenEnabled {
		return nil, fmt.Errorf("refresh token is disabled")
	}

	session, err := p.ValidateSession(sessionID)
	if err != nil {
		return nil, err
	}

	if session.OAuth2Token == nil || session.OAuth2Token.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	ctx := context.Background()

	// Use the standard oauth2 token source for automatic refresh
	tokenSource := p.oauth2Cfg.TokenSource(ctx, session.OAuth2Token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh tokens: %w", err)
	}

	// Verify new ID token if present
	if rawIDToken, ok := newToken.Extra("id_token").(string); ok {
		idToken, err := p.verifier.Verify(ctx, rawIDToken)
		if err != nil {
			return nil, fmt.Errorf("failed to verify refreshed ID token: %w", err)
		}

		// Update claims
		var claims map[string]interface{}
		if err := idToken.Claims(&claims); err == nil {
			session.Claims = claims
		}
		session.IDToken = rawIDToken
	}

	// Update session with new token
	session.AccessToken = newToken.AccessToken
	session.RefreshToken = newToken.RefreshToken
	session.ExpiresAt = newToken.Expiry
	session.LastAccess = time.Now()
	session.OAuth2Token = newToken

	return session, nil
}

// RevokeSession revokes user session
func (p *OIDCProvider) RevokeSession(sessionID string) error {
	p.mu.Lock()
	session, exists := p.sessions[sessionID]
	if exists {
		delete(p.sessions, sessionID)
	}
	p.mu.Unlock()

	if !exists {
		return fmt.Errorf("session not found")
	}

	// Revoke tokens using oauth2 revocation if available
	ctx := context.Background()
	if session.OAuth2Token != nil {
		// Try to revoke the refresh token first
		if session.OAuth2Token.RefreshToken != "" {
			tokenSource := p.oauth2Cfg.TokenSource(ctx, session.OAuth2Token)
			if revoker, ok := tokenSource.(interface {
				RevokeToken(context.Context, *oauth2.Token) error
			}); ok {
				if err := revoker.RevokeToken(ctx, session.OAuth2Token); err != nil {
					p.logger.Printf("Failed to revoke token: %v", err)
				}
			}
		}
	}

	p.logger.Printf("Revoked OIDC session for user: %s", session.Username)
	return nil
}

// GetAllSessions returns all active sessions
func (p *OIDCProvider) GetAllSessions() map[string]*OIDCSession {
	p.mu.RLock()
	defer p.mu.RUnlock()

	sessions := make(map[string]*OIDCSession)
	for id, session := range p.sessions {
		sessions[id] = session
	}
	return sessions
}

// Private helper methods

func (p *OIDCProvider) getUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	userInfo, err := p.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return nil, err
	}

	var info UserInfo
	if err := userInfo.Claims(&info); err != nil {
		return nil, err
	}

	return &info, nil
}

func (p *OIDCProvider) extractClaim(userInfo *UserInfo, claims map[string]interface{}, claimName string) string {
	// First check ID token claims
	if claims != nil {
		if val, ok := claims[claimName]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}

	// Then check userinfo if available
	if userInfo != nil {
		switch claimName {
		case "sub":
			return userInfo.Sub
		case "email":
			return userInfo.Email
		case "preferred_username":
			return userInfo.PreferredUsername
		case "name":
			return userInfo.Name
		case "given_name":
			return userInfo.GivenName
		case "family_name":
			return userInfo.FamilyName
		}
	}

	return ""
}

func (p *OIDCProvider) extractGroups(userInfo *UserInfo, claims map[string]interface{}) []string {
	// Check userinfo first
	if userInfo != nil && len(userInfo.Groups) > 0 {
		return userInfo.Groups
	}

	// Check claims
	if claims != nil {
		if groupsVal, ok := claims[p.config.ClaimMappings.Groups]; ok {
			if groups, ok := groupsVal.([]interface{}); ok {
				result := make([]string, 0, len(groups))
				for _, group := range groups {
					if str, ok := group.(string); ok {
						result = append(result, str)
					}
				}
				return result
			}
		}
	}

	return []string{}
}

func (p *OIDCProvider) extractRoles(userInfo *UserInfo, claims map[string]interface{}) []string {
	// Check userinfo first
	if userInfo != nil && len(userInfo.Roles) > 0 {
		return userInfo.Roles
	}

	// Check claims
	if claims != nil {
		if rolesVal, ok := claims[p.config.ClaimMappings.Roles]; ok {
			if roles, ok := rolesVal.([]interface{}); ok {
				result := make([]string, 0, len(roles))
				for _, role := range roles {
					if str, ok := role.(string); ok {
						result = append(result, str)
					}
				}
				return result
			}
		}
	}

	return []string{}
}

func (p *OIDCProvider) cleanupExpiredSessions() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		now := time.Now()
		for sessionID, session := range p.sessions {
			if now.After(session.ExpiresAt) {
				delete(p.sessions, sessionID)
				p.logger.Printf("Cleaned up expired session for user: %s", session.Username)
			}
		}

		// Also clean expired authorization states
		for state, authState := range p.states {
			if now.After(authState.ExpiresAt) {
				delete(p.states, state)
			}
		}
		p.mu.Unlock()
	}
}

// Helper functions

func setDefaultClaimMappings(config *OIDCConfig) {
	if config.ClaimMappings.Username == "" {
		config.ClaimMappings.Username = "preferred_username"
	}
	if config.ClaimMappings.Email == "" {
		config.ClaimMappings.Email = "email"
	}
	if config.ClaimMappings.FirstName == "" {
		config.ClaimMappings.FirstName = "given_name"
	}
	if config.ClaimMappings.LastName == "" {
		config.ClaimMappings.LastName = "family_name"
	}
	if config.ClaimMappings.Groups == "" {
		config.ClaimMappings.Groups = "groups"
	}
	if config.ClaimMappings.Roles == "" {
		config.ClaimMappings.Roles = "roles"
	}
	if config.ClaimMappings.DisplayName == "" {
		config.ClaimMappings.DisplayName = "name"
	}
}

func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read doesn't return errors under normal conditions
	return base64.RawURLEncoding.EncodeToString(b)
}
