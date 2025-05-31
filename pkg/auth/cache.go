package auth

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// AuthCache provides caching for authentication operations
type AuthCache struct {
	passwordCache map[string]*PasswordCacheEntry
	sessionCache  map[string]*SessionCacheEntry
	mfaCache      map[string]*MFACacheEntry
	mu            sync.RWMutex

	// Configuration
	passwordCacheTTL time.Duration
	sessionCacheTTL  time.Duration
	mfaCacheTTL      time.Duration
	maxEntries       int

	// Cleanup
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// PasswordCacheEntry represents cached password verification
type PasswordCacheEntry struct {
	PasswordHash string
	Salt         string
	CreatedAt    time.Time
	LastUsed     time.Time
	HitCount     int64
}

// SessionCacheEntry represents cached session data
type SessionCacheEntry struct {
	UserID       string
	Username     string
	Roles        []string
	Source       string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	LastAccessed time.Time
	Metadata     map[string]interface{}
}

// MFACacheEntry represents cached MFA validation
type MFACacheEntry struct {
	Username  string
	TokenHash string // Hash of used tokens to prevent replay
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CacheConfig configures the authentication cache
type CacheConfig struct {
	PasswordCacheTTL time.Duration
	SessionCacheTTL  time.Duration
	MFACacheTTL      time.Duration
	MaxEntries       int
	CleanupInterval  time.Duration
}

// DefaultCacheConfig returns default cache configuration
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		PasswordCacheTTL: 30 * time.Minute, // Cache password verifications
		SessionCacheTTL:  24 * time.Hour,   // Cache sessions
		MFACacheTTL:      5 * time.Minute,  // Cache MFA tokens (short-lived)
		MaxEntries:       10000,            // Maximum cache entries
		CleanupInterval:  10 * time.Minute, // Cleanup frequency
	}
}

// NewAuthCache creates a new authentication cache
func NewAuthCache(config *CacheConfig) *AuthCache {
	if config == nil {
		config = DefaultCacheConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	cache := &AuthCache{
		passwordCache:    make(map[string]*PasswordCacheEntry),
		sessionCache:     make(map[string]*SessionCacheEntry),
		mfaCache:         make(map[string]*MFACacheEntry),
		passwordCacheTTL: config.PasswordCacheTTL,
		sessionCacheTTL:  config.SessionCacheTTL,
		mfaCacheTTL:      config.MFACacheTTL,
		maxEntries:       config.MaxEntries,
		ctx:              ctx,
		cancel:           cancel,
	}

	// Start cleanup goroutine
	cache.wg.Add(1)
	go cache.cleanupLoop(config.CleanupInterval)

	return cache
}

// VerifyPasswordCached checks if password verification can be served from cache
func (ac *AuthCache) VerifyPasswordCached(username, password, expectedHash, salt string) (bool, bool) {
	ac.mu.RLock()
	entry, exists := ac.passwordCache[username]
	ac.mu.RUnlock()

	if !exists {
		return false, false // Not in cache
	}

	// Check if entry is expired
	if time.Since(entry.CreatedAt) > ac.passwordCacheTTL {
		ac.mu.Lock()
		delete(ac.passwordCache, username)
		ac.mu.Unlock()
		return false, false
	}

	// Verify cached hash matches expected
	if subtle.ConstantTimeCompare([]byte(entry.PasswordHash), []byte(expectedHash)) != 1 ||
		subtle.ConstantTimeCompare([]byte(entry.Salt), []byte(salt)) != 1 {
		// Hash changed, remove from cache
		ac.mu.Lock()
		delete(ac.passwordCache, username)
		ac.mu.Unlock()
		return false, false
	}

	// Update access statistics
	ac.mu.Lock()
	entry.LastUsed = time.Now()
	entry.HitCount++
	ac.mu.Unlock()

	// Verify password against cached hash
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		return false, false
	}

	// Use Argon2 for verification (most common case)
	hash := argon2.IDKey([]byte(password), saltBytes, 1, 1024, 1, 32)
	computed := hex.EncodeToString(hash)

	return subtle.ConstantTimeCompare([]byte(expectedHash), []byte(computed)) == 1, true
}

// CachePasswordVerification caches a successful password verification
func (ac *AuthCache) CachePasswordVerification(username, passwordHash, salt string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// Check cache size limits
	if len(ac.passwordCache) >= ac.maxEntries {
		ac.evictOldestPassword()
	}

	ac.passwordCache[username] = &PasswordCacheEntry{
		PasswordHash: passwordHash,
		Salt:         salt,
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
		HitCount:     0,
	}
}

// GetCachedSession retrieves a cached session
func (ac *AuthCache) GetCachedSession(sessionID string) (*SessionCacheEntry, bool) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	entry, exists := ac.sessionCache[sessionID]
	if !exists {
		return nil, false
	}

	// Check expiration
	if time.Now().After(entry.ExpiresAt) {
		delete(ac.sessionCache, sessionID)
		return nil, false
	}

	// Update last accessed
	entry.LastAccessed = time.Now()
	return entry, true
}

// CacheSession stores a session in cache
func (ac *AuthCache) CacheSession(sessionID string, session *SessionCacheEntry) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// Check cache size limits
	if len(ac.sessionCache) >= ac.maxEntries {
		ac.evictOldestSession()
	}

	// Set expiration if not provided
	if session.ExpiresAt.IsZero() {
		session.ExpiresAt = time.Now().Add(ac.sessionCacheTTL)
	}

	ac.sessionCache[sessionID] = session
}

// InvalidateSession removes a session from cache
func (ac *AuthCache) InvalidateSession(sessionID string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	delete(ac.sessionCache, sessionID)
}

// IsMFATokenUsed checks if an MFA token was recently used (replay protection)
func (ac *AuthCache) IsMFATokenUsed(username, token string) bool {
	tokenHash := ac.hashToken(token)
	key := fmt.Sprintf("%s:%s", username, tokenHash)

	ac.mu.RLock()
	defer ac.mu.RUnlock()

	entry, exists := ac.mfaCache[key]
	if !exists {
		return false
	}

	return time.Now().Before(entry.ExpiresAt)
}

// MarkMFATokenUsed marks an MFA token as used
func (ac *AuthCache) MarkMFATokenUsed(username, token string) {
	tokenHash := ac.hashToken(token)
	key := fmt.Sprintf("%s:%s", username, tokenHash)

	ac.mu.Lock()
	defer ac.mu.Unlock()

	// Check cache size limits
	if len(ac.mfaCache) >= ac.maxEntries {
		ac.evictOldestMFA()
	}

	ac.mfaCache[key] = &MFACacheEntry{
		Username:  username,
		TokenHash: tokenHash,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ac.mfaCacheTTL),
	}
}

// Close stops the cache and cleanup goroutines
func (ac *AuthCache) Close() {
	ac.cancel()
	ac.wg.Wait()
}

// Stats returns cache statistics
func (ac *AuthCache) Stats() CacheStats {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	var totalPasswordHits int64
	for _, entry := range ac.passwordCache {
		totalPasswordHits += entry.HitCount
	}

	return CacheStats{
		PasswordCacheSize: len(ac.passwordCache),
		SessionCacheSize:  len(ac.sessionCache),
		MFACacheSize:      len(ac.mfaCache),
		PasswordCacheHits: totalPasswordHits,
	}
}

// CacheStats represents cache statistics
type CacheStats struct {
	PasswordCacheSize int
	SessionCacheSize  int
	MFACacheSize      int
	PasswordCacheHits int64
}

// Private helper methods

func (ac *AuthCache) hashToken(token string) string {
	// Simple hash for token deduplication
	hash := argon2.IDKey([]byte(token), []byte("mfa-salt"), 1, 1024, 1, 16)
	return hex.EncodeToString(hash)
}

func (ac *AuthCache) evictOldestPassword() {
	var oldestKey string
	var oldestTime time.Time = time.Now()

	for key, entry := range ac.passwordCache {
		if entry.LastUsed.Before(oldestTime) {
			oldestTime = entry.LastUsed
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(ac.passwordCache, oldestKey)
	}
}

func (ac *AuthCache) evictOldestSession() {
	var oldestKey string
	var oldestTime time.Time = time.Now()

	for key, entry := range ac.sessionCache {
		if entry.LastAccessed.Before(oldestTime) {
			oldestTime = entry.LastAccessed
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(ac.sessionCache, oldestKey)
	}
}

func (ac *AuthCache) evictOldestMFA() {
	var oldestKey string
	var oldestTime time.Time = time.Now()

	for key, entry := range ac.mfaCache {
		if entry.CreatedAt.Before(oldestTime) {
			oldestTime = entry.CreatedAt
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(ac.mfaCache, oldestKey)
	}
}

func (ac *AuthCache) cleanupLoop(interval time.Duration) {
	defer ac.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ac.ctx.Done():
			return
		case <-ticker.C:
			ac.cleanup()
		}
	}
}

func (ac *AuthCache) cleanup() {
	now := time.Now()

	ac.mu.Lock()
	defer ac.mu.Unlock()

	// Cleanup expired password cache entries
	for key, entry := range ac.passwordCache {
		if now.Sub(entry.CreatedAt) > ac.passwordCacheTTL {
			delete(ac.passwordCache, key)
		}
	}

	// Cleanup expired session cache entries
	for key, entry := range ac.sessionCache {
		if now.After(entry.ExpiresAt) {
			delete(ac.sessionCache, key)
		}
	}

	// Cleanup expired MFA cache entries
	for key, entry := range ac.mfaCache {
		if now.After(entry.ExpiresAt) {
			delete(ac.mfaCache, key)
		}
	}
}

// ClearCache clears all cache entries
func (ac *AuthCache) ClearCache() {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	ac.passwordCache = make(map[string]*PasswordCacheEntry)
	ac.sessionCache = make(map[string]*SessionCacheEntry)
	ac.mfaCache = make(map[string]*MFACacheEntry)
}

// ClearUserCache clears cache entries for a specific user
func (ac *AuthCache) ClearUserCache(username string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// Clear password cache
	delete(ac.passwordCache, username)

	// Clear MFA cache for user
	for key, entry := range ac.mfaCache {
		if entry.Username == username {
			delete(ac.mfaCache, key)
		}
	}

	// Clear sessions for user
	for key, entry := range ac.sessionCache {
		if entry.Username == username {
			delete(ac.sessionCache, key)
		}
	}
}

// GetCacheStats returns comprehensive cache statistics
func (ac *AuthCache) GetCacheStats() map[string]interface{} {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	uptime := time.Since(ac.ctx.Value("start_time").(time.Time))

	return map[string]interface{}{
		"password_cache": map[string]interface{}{
			"entries":     len(ac.passwordCache),
			"max_size":    ac.maxEntries,
			"ttl_seconds": ac.passwordCacheTTL.Seconds(),
		},
		"session_cache": map[string]interface{}{
			"entries":     len(ac.sessionCache),
			"max_size":    ac.maxEntries,
			"ttl_seconds": ac.sessionCacheTTL.Seconds(),
		},
		"mfa_cache": map[string]interface{}{
			"entries":     len(ac.mfaCache),
			"max_size":    ac.maxEntries,
			"ttl_seconds": ac.mfaCacheTTL.Seconds(),
		},
		"uptime_seconds": uptime.Seconds(),
	}
}

// WarmupCache pre-populates cache with frequently used data
func (ac *AuthCache) WarmupCache(users []string, authManager interface{}) {
	// This would be implemented based on specific auth manager interface
	// For now, it's a placeholder for cache warming functionality
}
