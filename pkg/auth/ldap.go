package auth

import (
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig configuration for LDAP authentication
type LDAPConfig struct {
	Enabled            bool            `json:"enabled"`
	Server             string          `json:"server"`
	Port               int             `json:"port"`
	UseSSL             bool            `json:"use_ssl"`
	UseTLS             bool            `json:"use_tls"`
	SkipVerify         bool            `json:"skip_verify"`
	Timeout            time.Duration   `json:"timeout"`
	BindDN             string          `json:"bind_dn"`
	BindPassword       string          `json:"bind_password"`
	BaseDN             string          `json:"base_dn"`
	UserFilter         string          `json:"user_filter"`
	GroupFilter        string          `json:"group_filter"`
	UserSearchBase     string          `json:"user_search_base"`
	GroupSearchBase    string          `json:"group_search_base"`
	UserAttributes     UserAttributes  `json:"user_attributes"`
	GroupAttributes    GroupAttributes `json:"group_attributes"`
	RequiredGroups     []string        `json:"required_groups"`
	AdminGroups        []string        `json:"admin_groups"`
	ConnectionPoolSize int             `json:"connection_pool_size"`
	MaxRetries         int             `json:"max_retries"`
	RetryDelay         time.Duration   `json:"retry_delay"`
	CacheTimeout       time.Duration   `json:"cache_timeout"`
	CacheEnabled       bool            `json:"cache_enabled"`
}

// UserAttributes mapping of LDAP user attributes
type UserAttributes struct {
	Username    string `json:"username"`     // sAMAccountName, uid
	Email       string `json:"email"`        // mail
	FirstName   string `json:"first_name"`   // givenName
	LastName    string `json:"last_name"`    // sn
	DisplayName string `json:"display_name"` // displayName, cn
	Groups      string `json:"groups"`       // memberOf
	DN          string `json:"dn"`           // distinguishedName
}

// GroupAttributes mapping of LDAP group attributes
type GroupAttributes struct {
	Name        string `json:"name"`        // cn
	Description string `json:"description"` // description
	Members     string `json:"members"`     // member
	DN          string `json:"dn"`          // distinguishedName
}

// LDAPProvider LDAP authentication provider
type LDAPProvider struct {
	config      *LDAPConfig
	logger      Logger
	mu          sync.RWMutex
	connections chan *ldap.Conn
	userCache   map[string]*CachedUser
	groupCache  map[string]*CachedGroup
}

// LDAPUser user information from LDAP
type LDAPUser struct {
	DN          string            `json:"dn"`
	Username    string            `json:"username"`
	Email       string            `json:"email"`
	FirstName   string            `json:"first_name"`
	LastName    string            `json:"last_name"`
	DisplayName string            `json:"display_name"`
	Groups      []string          `json:"groups"`
	IsAdmin     bool              `json:"is_admin"`
	Attributes  map[string]string `json:"attributes"`
}

// LDAPGroup group information from LDAP
type LDAPGroup struct {
	DN          string   `json:"dn"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Members     []string `json:"members"`
}

// CachedUser cached user information
type CachedUser struct {
	User      *LDAPUser `json:"user"`
	CachedAt  time.Time `json:"cached_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CachedGroup cached group information
type CachedGroup struct {
	Group     *LDAPGroup `json:"group"`
	CachedAt  time.Time  `json:"cached_at"`
	ExpiresAt time.Time  `json:"expires_at"`
}

// AuthResult LDAP authentication result
type AuthResult struct {
	Success     bool      `json:"success"`
	User        *LDAPUser `json:"user,omitempty"`
	Error       string    `json:"error,omitempty"`
	Groups      []string  `json:"groups,omitempty"`
	IsAdmin     bool      `json:"is_admin"`
	Permissions []string  `json:"permissions,omitempty"`
}

// NewLDAPProvider creates new LDAP provider
func NewLDAPProvider(config *LDAPConfig, logger Logger) (*LDAPProvider, error) {
	if config == nil {
		return nil, fmt.Errorf("LDAP config is required")
	}

	if !config.Enabled {
		return nil, fmt.Errorf("LDAP is disabled")
	}

	if config.Server == "" {
		return nil, fmt.Errorf("LDAP server is required")
	}

	// Set default values
	if config.Port == 0 {
		if config.UseSSL {
			config.Port = 636
		} else {
			config.Port = 389
		}
	}

	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}

	if config.ConnectionPoolSize == 0 {
		config.ConnectionPoolSize = 10
	}

	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}

	if config.RetryDelay == 0 {
		config.RetryDelay = time.Second
	}

	if config.CacheTimeout == 0 {
		config.CacheTimeout = 5 * time.Minute
	}

	// Set default values for attributes
	if config.UserAttributes.Username == "" {
		config.UserAttributes.Username = "sAMAccountName"
	}
	if config.UserAttributes.Email == "" {
		config.UserAttributes.Email = "mail"
	}
	if config.UserAttributes.FirstName == "" {
		config.UserAttributes.FirstName = "givenName"
	}
	if config.UserAttributes.LastName == "" {
		config.UserAttributes.LastName = "sn"
	}
	if config.UserAttributes.DisplayName == "" {
		config.UserAttributes.DisplayName = "displayName"
	}
	if config.UserAttributes.Groups == "" {
		config.UserAttributes.Groups = "memberOf"
	}
	if config.UserAttributes.DN == "" {
		config.UserAttributes.DN = "distinguishedName"
	}

	// Set default values for groups
	if config.GroupAttributes.Name == "" {
		config.GroupAttributes.Name = "cn"
	}
	if config.GroupAttributes.Description == "" {
		config.GroupAttributes.Description = "description"
	}
	if config.GroupAttributes.Members == "" {
		config.GroupAttributes.Members = "member"
	}
	if config.GroupAttributes.DN == "" {
		config.GroupAttributes.DN = "distinguishedName"
	}

	// Set default filters
	if config.UserFilter == "" {
		config.UserFilter = "(&(objectClass=user)(sAMAccountName=%s))"
	}
	if config.GroupFilter == "" {
		config.GroupFilter = "(&(objectClass=group)(cn=%s))"
	}

	if config.UserSearchBase == "" {
		config.UserSearchBase = config.BaseDN
	}
	if config.GroupSearchBase == "" {
		config.GroupSearchBase = config.BaseDN
	}

	provider := &LDAPProvider{
		config:      config,
		logger:      logger,
		connections: make(chan *ldap.Conn, config.ConnectionPoolSize),
		userCache:   make(map[string]*CachedUser),
		groupCache:  make(map[string]*CachedGroup),
	}

	// Initialize connection pool
	if err := provider.initConnectionPool(); err != nil {
		return nil, fmt.Errorf("failed to initialize connection pool: %w", err)
	}

	// Start goroutine for cache cleanup
	if config.CacheEnabled {
		go provider.cleanupCache()
	}

	return provider, nil
}

// Authenticate authenticates user by username and password
func (l *LDAPProvider) Authenticate(username, password string) (*AuthResult, error) {
	if !l.config.Enabled {
		return &AuthResult{Success: false, Error: "LDAP is disabled"}, nil
	}

	if username == "" || password == "" {
		return &AuthResult{Success: false, Error: "username and password are required"}, nil
	}

	// Check cache if enabled
	if l.config.CacheEnabled {
		if cachedUser := l.getCachedUser(username); cachedUser != nil {
			// Validate password via bind (cache is only for data, not passwords)
			if success := l.validatePassword(cachedUser.User.DN, password); success {
				return &AuthResult{
					Success: true,
					User:    cachedUser.User,
					Groups:  cachedUser.User.Groups,
					IsAdmin: cachedUser.User.IsAdmin,
				}, nil
			}
		}
	}

	var lastErr error
	for attempt := 0; attempt < l.config.MaxRetries; attempt++ {
		result, err := l.doAuthenticate(username, password)
		if err == nil {
			return result, nil
		}

		lastErr = err
		if attempt < l.config.MaxRetries-1 {
			time.Sleep(l.config.RetryDelay)
			l.logger.Printf("LDAP authentication attempt %d failed for user %s: %v", attempt+1, username, err)
		}
	}

	return &AuthResult{Success: false, Error: fmt.Sprintf("authentication failed after %d attempts: %v", l.config.MaxRetries, lastErr)}, nil
}

// GetUser gets user information
func (l *LDAPProvider) GetUser(username string) (*LDAPUser, error) {
	if !l.config.Enabled {
		return nil, fmt.Errorf("LDAP is disabled")
	}

	// Check cache if enabled
	if l.config.CacheEnabled {
		if cachedUser := l.getCachedUser(username); cachedUser != nil {
			return cachedUser.User, nil
		}
	}

	conn, err := l.getConnection()
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP connection: %w", err)
	}
	defer l.releaseConnection(conn)

	user, err := l.searchUser(conn, username)
	if err != nil {
		return nil, err
	}

	// Cache result
	if l.config.CacheEnabled {
		l.cacheUser(username, user)
	}

	return user, nil
}

// GetGroup gets group information
func (l *LDAPProvider) GetGroup(groupName string) (*LDAPGroup, error) {
	if !l.config.Enabled {
		return nil, fmt.Errorf("LDAP is disabled")
	}

	// Check cache if enabled
	if l.config.CacheEnabled {
		if cachedGroup := l.getCachedGroup(groupName); cachedGroup != nil {
			return cachedGroup.Group, nil
		}
	}

	conn, err := l.getConnection()
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP connection: %w", err)
	}
	defer l.releaseConnection(conn)

	group, err := l.searchGroup(conn, groupName)
	if err != nil {
		return nil, err
	}

	// Cache result
	if l.config.CacheEnabled {
		l.cacheGroup(groupName, group)
	}

	return group, nil
}

// SearchUsers searches users by filter
func (l *LDAPProvider) SearchUsers(filter string, limit int) ([]*LDAPUser, error) {
	if !l.config.Enabled {
		return nil, fmt.Errorf("LDAP is disabled")
	}

	conn, err := l.getConnection()
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP connection: %w", err)
	}
	defer l.releaseConnection(conn)

	searchRequest := ldap.NewSearchRequest(
		l.config.UserSearchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		limit,
		int(l.config.Timeout.Seconds()),
		false,
		filter,
		l.getUserAttributes(),
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	var users []*LDAPUser
	for _, entry := range sr.Entries {
		user := l.entryToUser(entry)
		users = append(users, user)
	}

	return users, nil
}

// ValidateConnection validates connection to LDAP server
func (l *LDAPProvider) ValidateConnection() error {
	conn, err := l.getConnection()
	if err != nil {
		return fmt.Errorf("failed to get LDAP connection: %w", err)
	}
	defer l.releaseConnection(conn)

	// Simple search to validate connection
	searchRequest := ldap.NewSearchRequest(
		l.config.BaseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		int(l.config.Timeout.Seconds()),
		false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)

	_, err = conn.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("LDAP connection validation failed: %w", err)
	}

	return nil
}

// Close closes all connections
func (l *LDAPProvider) Close() error {
	close(l.connections)
	for conn := range l.connections {
		conn.Close()
	}
	return nil
}

// Private methods

func (l *LDAPProvider) initConnectionPool() error {
	for i := 0; i < l.config.ConnectionPoolSize; i++ {
		conn, err := l.createConnection()
		if err != nil {
			return fmt.Errorf("failed to create connection %d: %w", i, err)
		}
		l.connections <- conn
	}
	return nil
}

func (l *LDAPProvider) createConnection() (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	address := fmt.Sprintf("%s:%d", l.config.Server, l.config.Port)

	var ldapURL string
	if l.config.UseSSL {
		ldapURL = fmt.Sprintf("ldaps://%s", address)
	} else {
		ldapURL = fmt.Sprintf("ldap://%s", address)
	}

	// Use new DialURL method
	conn, err = ldap.DialURL(ldapURL)
	if err == nil && l.config.UseTLS && !l.config.UseSSL {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: l.config.SkipVerify,
		}
		err = conn.StartTLS(tlsConfig)
	}

	if err != nil {
		return nil, err
	}

	// Set timeout
	conn.SetTimeout(l.config.Timeout)

	// Bind if credentials are provided
	if l.config.BindDN != "" && l.config.BindPassword != "" {
		err = conn.Bind(l.config.BindDN, l.config.BindPassword)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("bind failed: %w", err)
		}
	}

	return conn, nil
}

func (l *LDAPProvider) getConnection() (*ldap.Conn, error) {
	select {
	case conn := <-l.connections:
		// Check that connection is still active
		if conn.IsClosing() {
			newConn, err := l.createConnection()
			if err != nil {
				return nil, err
			}
			return newConn, nil
		}
		return conn, nil
	case <-time.After(l.config.Timeout):
		return nil, fmt.Errorf("timeout waiting for connection")
	}
}

func (l *LDAPProvider) releaseConnection(conn *ldap.Conn) {
	if !conn.IsClosing() {
		select {
		case l.connections <- conn:
		default:
			// Pool is full, close connection
			conn.Close()
		}
	}
}

func (l *LDAPProvider) doAuthenticate(username, password string) (*AuthResult, error) {
	conn, err := l.getConnection()
	if err != nil {
		return nil, fmt.Errorf("failed to get LDAP connection: %w", err)
	}
	defer l.releaseConnection(conn)

	// Search for user
	user, err := l.searchUser(conn, username)
	if err != nil {
		return &AuthResult{Success: false, Error: fmt.Sprintf("user not found: %v", err)}, nil
	}

	// Validate password via bind
	if !l.validatePassword(user.DN, password) {
		return &AuthResult{Success: false, Error: "invalid password"}, nil
	}

	// Check membership in required groups
	if len(l.config.RequiredGroups) > 0 {
		hasRequiredGroup := false
		for _, userGroup := range user.Groups {
			for _, requiredGroup := range l.config.RequiredGroups {
				if strings.EqualFold(userGroup, requiredGroup) {
					hasRequiredGroup = true
					break
				}
			}
			if hasRequiredGroup {
				break
			}
		}

		if !hasRequiredGroup {
			return &AuthResult{Success: false, Error: "user not in required groups"}, nil
		}
	}

	// Determine admin rights
	user.IsAdmin = l.isUserAdmin(user.Groups)

	// Cache result
	if l.config.CacheEnabled {
		l.cacheUser(username, user)
	}

	return &AuthResult{
		Success: true,
		User:    user,
		Groups:  user.Groups,
		IsAdmin: user.IsAdmin,
	}, nil
}

func (l *LDAPProvider) searchUser(conn *ldap.Conn, username string) (*LDAPUser, error) {
	filter := fmt.Sprintf(l.config.UserFilter, ldap.EscapeFilter(username))

	searchRequest := ldap.NewSearchRequest(
		l.config.UserSearchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		int(l.config.Timeout.Seconds()),
		false,
		filter,
		l.getUserAttributes(),
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	if len(sr.Entries) > 1 {
		return nil, fmt.Errorf("multiple users found")
	}

	return l.entryToUser(sr.Entries[0]), nil
}

func (l *LDAPProvider) searchGroup(conn *ldap.Conn, groupName string) (*LDAPGroup, error) {
	filter := fmt.Sprintf(l.config.GroupFilter, ldap.EscapeFilter(groupName))

	searchRequest := ldap.NewSearchRequest(
		l.config.GroupSearchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		int(l.config.Timeout.Seconds()),
		false,
		filter,
		l.getGroupAttributes(),
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP group search failed: %w", err)
	}

	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("group not found")
	}

	return l.entryToGroup(sr.Entries[0]), nil
}

func (l *LDAPProvider) validatePassword(userDN, password string) bool {
	conn, err := l.createConnection()
	if err != nil {
		l.logger.Printf("Failed to create connection for password validation: %v", err)
		return false
	}
	defer conn.Close()

	err = conn.Bind(userDN, password)
	return err == nil
}

func (l *LDAPProvider) entryToUser(entry *ldap.Entry) *LDAPUser {
	user := &LDAPUser{
		DN:         entry.DN,
		Attributes: make(map[string]string),
	}

	for _, attr := range entry.Attributes {
		switch attr.Name {
		case l.config.UserAttributes.Username:
			if len(attr.Values) > 0 {
				user.Username = attr.Values[0]
			}
		case l.config.UserAttributes.Email:
			if len(attr.Values) > 0 {
				user.Email = attr.Values[0]
			}
		case l.config.UserAttributes.FirstName:
			if len(attr.Values) > 0 {
				user.FirstName = attr.Values[0]
			}
		case l.config.UserAttributes.LastName:
			if len(attr.Values) > 0 {
				user.LastName = attr.Values[0]
			}
		case l.config.UserAttributes.DisplayName:
			if len(attr.Values) > 0 {
				user.DisplayName = attr.Values[0]
			}
		case l.config.UserAttributes.Groups:
			user.Groups = attr.Values
		}

		// Save all attributes
		if len(attr.Values) > 0 {
			user.Attributes[attr.Name] = attr.Values[0]
		}
	}

	// Extract group names from DN
	var groupNames []string
	for _, groupDN := range user.Groups {
		groupName := l.extractGroupName(groupDN)
		if groupName != "" {
			groupNames = append(groupNames, groupName)
		}
	}
	user.Groups = groupNames

	// Determine admin rights
	user.IsAdmin = l.isUserAdmin(user.Groups)

	return user
}

func (l *LDAPProvider) entryToGroup(entry *ldap.Entry) *LDAPGroup {
	group := &LDAPGroup{
		DN: entry.DN,
	}

	for _, attr := range entry.Attributes {
		switch attr.Name {
		case l.config.GroupAttributes.Name:
			if len(attr.Values) > 0 {
				group.Name = attr.Values[0]
			}
		case l.config.GroupAttributes.Description:
			if len(attr.Values) > 0 {
				group.Description = attr.Values[0]
			}
		case l.config.GroupAttributes.Members:
			group.Members = attr.Values
		}
	}

	return group
}

func (l *LDAPProvider) extractGroupName(groupDN string) string {
	// Extract CN from group DN
	parts := strings.Split(groupDN, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "cn=") {
			return part[3:]
		}
	}
	return ""
}

func (l *LDAPProvider) isUserAdmin(groups []string) bool {
	for _, userGroup := range groups {
		for _, adminGroup := range l.config.AdminGroups {
			if strings.EqualFold(userGroup, adminGroup) {
				return true
			}
		}
	}
	return false
}

func (l *LDAPProvider) getUserAttributes() []string {
	attrs := []string{
		l.config.UserAttributes.Username,
		l.config.UserAttributes.Email,
		l.config.UserAttributes.FirstName,
		l.config.UserAttributes.LastName,
		l.config.UserAttributes.DisplayName,
		l.config.UserAttributes.Groups,
		l.config.UserAttributes.DN,
	}

	// Remove empty attributes
	var result []string
	for _, attr := range attrs {
		if attr != "" {
			result = append(result, attr)
		}
	}

	return result
}

func (l *LDAPProvider) getGroupAttributes() []string {
	attrs := []string{
		l.config.GroupAttributes.Name,
		l.config.GroupAttributes.Description,
		l.config.GroupAttributes.Members,
		l.config.GroupAttributes.DN,
	}

	// Remove empty attributes
	var result []string
	for _, attr := range attrs {
		if attr != "" {
			result = append(result, attr)
		}
	}

	return result
}

func (l *LDAPProvider) getCachedUser(username string) *CachedUser {
	l.mu.RLock()
	defer l.mu.RUnlock()

	cachedUser, exists := l.userCache[username]
	if !exists {
		return nil
	}

	if time.Now().After(cachedUser.ExpiresAt) {
		return nil
	}

	return cachedUser
}

func (l *LDAPProvider) cacheUser(username string, user *LDAPUser) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.userCache[username] = &CachedUser{
		User:      user,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(l.config.CacheTimeout),
	}
}

func (l *LDAPProvider) getCachedGroup(groupName string) *CachedGroup {
	l.mu.RLock()
	defer l.mu.RUnlock()

	cachedGroup, exists := l.groupCache[groupName]
	if !exists {
		return nil
	}

	if time.Now().After(cachedGroup.ExpiresAt) {
		return nil
	}

	return cachedGroup
}

func (l *LDAPProvider) cacheGroup(groupName string, group *LDAPGroup) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.groupCache[groupName] = &CachedGroup{
		Group:     group,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(l.config.CacheTimeout),
	}
}

func (l *LDAPProvider) cleanupCache() {
	ticker := time.NewTicker(l.config.CacheTimeout / 2)
	defer ticker.Stop()

	for range ticker.C {
		l.mu.Lock()
		now := time.Now()

		// Clean expired users
		for username, cachedUser := range l.userCache {
			if now.After(cachedUser.ExpiresAt) {
				delete(l.userCache, username)
			}
		}

		// Clean expired groups
		for groupName, cachedGroup := range l.groupCache {
			if now.After(cachedGroup.ExpiresAt) {
				delete(l.groupCache, groupName)
			}
		}

		l.mu.Unlock()
	}
}
