package auth

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestNewLDAPProvider tests LDAP provider creation with different configurations
func TestNewLDAPProvider(t *testing.T) {
	// Note: These tests will skip actual connection creation as it requires real LDAP servers
	tests := []struct {
		name      string
		config    *LDAPConfig
		expectErr bool
		skipNet   bool // Skip tests that require network
	}{
		{
			name: "valid Active Directory configuration",
			config: &LDAPConfig{
				Enabled:            true,
				Server:             "dc.company.com",
				Port:               389,
				UseTLS:             true,
				BindDN:             "cn=ldap-reader,ou=service-accounts,dc=company,dc=com",
				BindPassword:       "secret-password",
				BaseDN:             "dc=company,dc=com",
				UserFilter:         "(&(objectClass=user)(sAMAccountName=%s))",
				GroupFilter:        "(&(objectClass=group)(member=%s))",
				RequiredGroups:     []string{"CN=VPN-Users,ou=groups,dc=company,dc=com"},
				Timeout:            30 * time.Second,
				ConnectionPoolSize: 10,
				MaxRetries:         3,
				RetryDelay:         2 * time.Second,
			},
			expectErr: true, // Will fail due to network connection
			skipNet:   true,
		},
		{
			name: "valid OpenLDAP configuration",
			config: &LDAPConfig{
				Enabled:            true,
				Server:             "ldap.company.com",
				Port:               636,
				UseTLS:             true,
				BindDN:             "cn=admin,dc=company,dc=com",
				BindPassword:       "admin-password",
				BaseDN:             "dc=company,dc=com",
				UserFilter:         "(&(objectClass=inetOrgPerson)(uid=%s))",
				GroupFilter:        "(&(objectClass=groupOfNames)(member=%s))",
				Timeout:            15 * time.Second,
				ConnectionPoolSize: 5,
			},
			expectErr: true, // Will fail due to network connection
			skipNet:   true,
		},
		{
			name:      "nil configuration",
			config:    nil,
			expectErr: true,
			skipNet:   false,
		},
		{
			name: "disabled LDAP",
			config: &LDAPConfig{
				Enabled: false,
			},
			expectErr: true,
			skipNet:   false,
		},
		{
			name: "missing server",
			config: &LDAPConfig{
				Enabled: true,
				Port:    389,
			},
			expectErr: true,
			skipNet:   false,
		},
		{
			name: "missing base DN",
			config: &LDAPConfig{
				Enabled: true,
				Server:  "ldap.example.com",
				Port:    389,
			},
			expectErr: true, // Will fail due to network connection
			skipNet:   true,
		},
		{
			name: "invalid port",
			config: &LDAPConfig{
				Enabled: true,
				Server:  "ldap.example.com",
				Port:    0, // Will be set to default
				BaseDN:  "dc=example,dc=com",
			},
			expectErr: true, // Will fail due to network connection
			skipNet:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipNet {
				t.Skip("Skipping test that requires network connection")
				return
			}

			provider, err := NewLDAPProvider(tt.config, NewTestLogger())
			if tt.expectErr && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if provider == nil && !tt.expectErr {
				t.Error("provider should not be nil")
			}
		})
	}
}

// TestLDAPConfig tests LDAP configuration validation and defaults
func TestLDAPConfig(t *testing.T) {
	config := &LDAPConfig{
		Enabled:      true,
		Server:       "ldap.example.com",
		Port:         389,
		UseTLS:       false,
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: "password",
		BaseDN:       "dc=example,dc=com",
		UserFilter:   "(&(objectClass=inetOrgPerson)(uid=%s))",
		GroupFilter:  "(&(objectClass=groupOfNames)(member=%s))",
	}

	// Test default timeout
	if config.Timeout != 0 {
		t.Errorf("initial timeout should be 0, got: %v", config.Timeout)
	}

	// Test default connection pool size
	if config.ConnectionPoolSize != 0 {
		t.Errorf("initial connection pool size should be 0, got: %d", config.ConnectionPoolSize)
	}

	// Test default retry attempts
	if config.MaxRetries != 0 {
		t.Errorf("initial max retries should be 0, got: %d", config.MaxRetries)
	}

	// Test filter format validation
	if !config.hasValidUserFilter() {
		t.Error("user filter should be valid")
	}

	if !config.hasValidGroupFilter() {
		t.Error("group filter should be valid")
	}
}

// TestLDAPUser tests LDAP user information structure
func TestLDAPUser(t *testing.T) {
	user := &LDAPUser{
		DN:          "cn=john.doe,ou=users,dc=company,dc=com",
		Username:    "john.doe",
		Email:       "john.doe@company.com",
		FirstName:   "John",
		LastName:    "Doe",
		DisplayName: "John Doe",
		Groups:      []string{"admin", "users", "developers"},
		IsAdmin:     true,
		Attributes: map[string]string{
			"mail":       "john.doe@company.com",
			"givenName":  "John",
			"sn":         "Doe",
			"cn":         "John Doe",
			"department": "Engineering",
			"title":      "Senior Developer",
		},
	}

	// Test basic fields
	if user.Username != "john.doe" {
		t.Errorf("username incorrect: %s", user.Username)
	}
	if user.Email != "john.doe@company.com" {
		t.Errorf("email incorrect: %s", user.Email)
	}
	if user.DisplayName != "John Doe" {
		t.Errorf("display name incorrect: %s", user.DisplayName)
	}

	// Test groups
	if len(user.Groups) != 3 {
		t.Errorf("expected 3 groups, got %d", len(user.Groups))
	}

	expectedGroups := []string{"admin", "users", "developers"}
	for i, group := range expectedGroups {
		if user.Groups[i] != group {
			t.Errorf("group %d should be %s, got %s", i, group, user.Groups[i])
		}
	}

	// Test admin status
	if !user.IsAdmin {
		t.Error("user should be admin")
	}

	// Test attributes
	if user.Attributes["mail"] != "john.doe@company.com" {
		t.Errorf("mail attribute incorrect: %v", user.Attributes["mail"])
	}
	if user.Attributes["department"] != "Engineering" {
		t.Errorf("department attribute incorrect: %v", user.Attributes["department"])
	}
}

// TestLDAPGroup tests LDAP group structure
func TestLDAPGroup(t *testing.T) {
	group := &LDAPGroup{
		DN:          "cn=developers,ou=groups,dc=company,dc=com",
		Name:        "developers",
		Description: "Development team members",
		Members: []string{
			"cn=john.doe,ou=users,dc=company,dc=com",
			"cn=jane.smith,ou=users,dc=company,dc=com",
		},
	}

	// Test basic fields
	if group.Name != "developers" {
		t.Errorf("group name incorrect: %s", group.Name)
	}
	if group.Description != "Development team members" {
		t.Errorf("group description incorrect: %s", group.Description)
	}

	// Test members
	if len(group.Members) != 2 {
		t.Errorf("expected 2 members, got %d", len(group.Members))
	}

	expectedMembers := []string{
		"cn=john.doe,ou=users,dc=company,dc=com",
		"cn=jane.smith,ou=users,dc=company,dc=com",
	}
	for i, member := range expectedMembers {
		if group.Members[i] != member {
			t.Errorf("member %d should be %s, got %s", i, member, group.Members[i])
		}
	}
}

// TestAuthResult tests LDAP authentication result structure
func TestAuthResult(t *testing.T) {
	user := &LDAPUser{
		Username:    "john.doe",
		Email:       "john.doe@company.com",
		DisplayName: "John Doe",
		Groups:      []string{"admin", "users"},
		IsAdmin:     true,
	}

	result := &AuthResult{
		Success:     true,
		User:        user,
		Groups:      user.Groups,
		IsAdmin:     user.IsAdmin,
		Permissions: []string{"read", "write", "admin"},
	}

	// Test basic result fields
	if !result.Success {
		t.Error("authentication should be successful")
	}
	if result.User == nil {
		t.Error("user should not be nil")
	}
	if result.Error != "" {
		t.Errorf("error should be empty for successful auth: %s", result.Error)
	}

	// Test user info in result
	if result.User.Username != "john.doe" {
		t.Errorf("username in result incorrect: %s", result.User.Username)
	}
	if !result.IsAdmin {
		t.Error("admin status should be true")
	}

	// Test groups
	if len(result.Groups) != 2 {
		t.Errorf("expected 2 groups in result, got %d", len(result.Groups))
	}

	// Test permissions
	if len(result.Permissions) != 3 {
		t.Errorf("expected 3 permissions, got %d", len(result.Permissions))
	}

	// Test failed authentication result
	failedResult := &AuthResult{
		Success: false,
		Error:   "Invalid credentials",
	}

	if failedResult.Success {
		t.Error("failed authentication should not be successful")
	}
	if failedResult.Error == "" {
		t.Error("failed authentication should have error message")
	}
	if failedResult.User != nil {
		t.Error("failed authentication should not have user")
	}
}

// TestUserAttributes tests user attribute mapping
func TestUserAttributes(t *testing.T) {
	attrs := UserAttributes{
		Username:    "sAMAccountName",
		Email:       "mail",
		FirstName:   "givenName",
		LastName:    "sn",
		DisplayName: "displayName",
		Groups:      "memberOf",
		DN:          "distinguishedName",
	}

	// Test all attributes are set correctly
	if attrs.Username != "sAMAccountName" {
		t.Errorf("username attribute incorrect: %s", attrs.Username)
	}
	if attrs.Email != "mail" {
		t.Errorf("email attribute incorrect: %s", attrs.Email)
	}
	if attrs.Groups != "memberOf" {
		t.Errorf("groups attribute incorrect: %s", attrs.Groups)
	}
	if attrs.DN != "distinguishedName" {
		t.Errorf("DN attribute incorrect: %s", attrs.DN)
	}
}

// TestGroupAttributes tests group attribute mapping
func TestGroupAttributes(t *testing.T) {
	attrs := GroupAttributes{
		Name:        "cn",
		Description: "description",
		Members:     "member",
		DN:          "distinguishedName",
	}

	// Test all attributes are set correctly
	if attrs.Name != "cn" {
		t.Errorf("name attribute incorrect: %s", attrs.Name)
	}
	if attrs.Description != "description" {
		t.Errorf("description attribute incorrect: %s", attrs.Description)
	}
	if attrs.Members != "member" {
		t.Errorf("members attribute incorrect: %s", attrs.Members)
	}
	if attrs.DN != "distinguishedName" {
		t.Errorf("DN attribute incorrect: %s", attrs.DN)
	}
}

// TestCachedUser tests cached user functionality
func TestCachedUser(t *testing.T) {
	now := time.Now()
	user := &LDAPUser{
		Username:    "john.doe",
		Email:       "john.doe@company.com",
		DisplayName: "John Doe",
	}

	cachedUser := &CachedUser{
		User:      user,
		CachedAt:  now,
		ExpiresAt: now.Add(5 * time.Minute),
	}

	// Test basic cached user fields
	if cachedUser.User == nil {
		t.Error("cached user should not be nil")
	}
	if cachedUser.User.Username != "john.doe" {
		t.Errorf("cached username incorrect: %s", cachedUser.User.Username)
	}

	// Test time fields
	if cachedUser.CachedAt.After(now.Add(time.Second)) {
		t.Error("cached time should be close to now")
	}
	if cachedUser.ExpiresAt.Before(now) {
		t.Error("expiration should be in the future")
	}

	// Test if cache is expired
	if time.Now().After(cachedUser.ExpiresAt) {
		t.Error("cache should not be expired yet")
	}
}

// TestCachedGroup tests cached group functionality
func TestCachedGroup(t *testing.T) {
	now := time.Now()
	group := &LDAPGroup{
		Name:        "developers",
		Description: "Development team",
		Members:     []string{"john.doe", "jane.smith"},
	}

	cachedGroup := &CachedGroup{
		Group:     group,
		CachedAt:  now,
		ExpiresAt: now.Add(10 * time.Minute),
	}

	// Test basic cached group fields
	if cachedGroup.Group == nil {
		t.Error("cached group should not be nil")
	}
	if cachedGroup.Group.Name != "developers" {
		t.Errorf("cached group name incorrect: %s", cachedGroup.Group.Name)
	}

	// Test time fields
	if cachedGroup.CachedAt.After(now.Add(time.Second)) {
		t.Error("cached time should be close to now")
	}
	if cachedGroup.ExpiresAt.Before(now) {
		t.Error("expiration should be in the future")
	}
}

// TestLDAPFilterValidation tests LDAP filter validation
func TestLDAPFilterValidation(t *testing.T) {
	testCases := []struct {
		name   string
		filter string
		valid  bool
	}{
		{
			name:   "valid user filter with sAMAccountName",
			filter: "(&(objectClass=user)(sAMAccountName=%s))",
			valid:  true,
		},
		{
			name:   "valid user filter with uid",
			filter: "(&(objectClass=inetOrgPerson)(uid=%s))",
			valid:  true,
		},
		{
			name:   "valid group filter",
			filter: "(&(objectClass=group)(member=%s))",
			valid:  true,
		},
		{
			name:   "filter without placeholder",
			filter: "(&(objectClass=user)(sAMAccountName=fixed))",
			valid:  false,
		},
		{
			name:   "empty filter",
			filter: "",
			valid:  false,
		},
		{
			name:   "malformed filter",
			filter: "(&(objectClass=user",
			valid:  false,
		},
		{
			name:   "filter with multiple placeholders",
			filter: "(&(objectClass=user)(sAMAccountName=%s)(mail=%s))",
			valid:  false, // Only one placeholder allowed
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid := isValidLDAPFilter(tc.filter)
			if valid != tc.valid {
				t.Errorf("filter validation failed for '%s': expected %v, got %v", tc.filter, tc.valid, valid)
			}
		})
	}
}

// TestLDAPDNParsing tests DN (Distinguished Name) parsing
func TestLDAPDNParsing(t *testing.T) {
	testCases := []struct {
		name     string
		dn       string
		expected map[string]string
	}{
		{
			name: "user DN",
			dn:   "cn=john.doe,ou=users,dc=company,dc=com",
			expected: map[string]string{
				"cn": "john.doe",
				"ou": "users",
				"dc": "company.com",
			},
		},
		{
			name: "group DN",
			dn:   "CN=VPN-Users,OU=Security Groups,DC=company,DC=com",
			expected: map[string]string{
				"cn": "VPN-Users",
				"ou": "Security Groups",
				"dc": "company.com",
			},
		},
		{
			name: "service account DN",
			dn:   "cn=ldap-reader,ou=service-accounts,ou=special,dc=company,dc=com",
			expected: map[string]string{
				"cn": "ldap-reader",
				"ou": "service-accounts", // Should get the first OU
				"dc": "company.com",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parsed := parseLDAPDN(tc.dn)

			for key, expectedValue := range tc.expected {
				if parsed[key] != expectedValue {
					t.Errorf("DN component %s: expected '%s', got '%s'", key, expectedValue, parsed[key])
				}
			}
		})
	}
}

// TestLDAPGroupMapping tests group DN to group name mapping
func TestLDAPGroupMapping(t *testing.T) {
	testCases := []struct {
		name     string
		groupDN  string
		expected string
	}{
		{
			name:     "simple group",
			groupDN:  "CN=admin,ou=groups,dc=company,dc=com",
			expected: "admin",
		},
		{
			name:     "group with spaces",
			groupDN:  "CN=VPN Users,ou=groups,dc=company,dc=com",
			expected: "VPN Users",
		},
		{
			name:     "nested group",
			groupDN:  "CN=Domain Admins,CN=Users,DC=company,DC=com",
			expected: "Domain Admins",
		},
		{
			name:     "group with special characters",
			groupDN:  "CN=App-Developers_Team,ou=groups,dc=company,dc=com",
			expected: "App-Developers_Team",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			groupName := extractGroupNameFromDN(tc.groupDN)
			if groupName != tc.expected {
				t.Errorf("group name extraction failed: expected '%s', got '%s'", tc.expected, groupName)
			}
		})
	}
}

// TestLDAPAttributeMapping tests attribute mapping for different LDAP schemas
func TestLDAPAttributeMapping(t *testing.T) {
	// Active Directory attributes
	adAttributes := map[string][]string{
		"sAMAccountName": {"john.doe"},
		"mail":           {"john.doe@company.com"},
		"givenName":      {"John"},
		"sn":             {"Doe"},
		"displayName":    {"John Doe"},
		"memberOf": {
			"CN=admin,ou=groups,dc=company,dc=com",
			"CN=users,ou=groups,dc=company,dc=com",
		},
		"department":      {"Engineering"},
		"title":           {"Senior Developer"},
		"telephoneNumber": {"555-1234"},
	}

	// OpenLDAP attributes
	openLDAPAttributes := map[string][]string{
		"uid":       {"john.doe"},
		"mail":      {"john.doe@company.com"},
		"givenName": {"John"},
		"sn":        {"Doe"},
		"cn":        {"John Doe"},
		"memberOf": {
			"cn=admin,ou=groups,dc=company,dc=com",
			"cn=users,ou=groups,dc=company,dc=com",
		},
		"departmentNumber": {"12345"},
		"employeeType":     {"Developer"},
	}

	testCases := []struct {
		name       string
		attributes map[string][]string
		schema     string
	}{
		{
			name:       "Active Directory mapping",
			attributes: adAttributes,
			schema:     "AD",
		},
		{
			name:       "OpenLDAP mapping",
			attributes: openLDAPAttributes,
			schema:     "OpenLDAP",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test username extraction
			var username string
			if tc.schema == "AD" {
				username = getFirstAttribute(tc.attributes, "sAMAccountName")
			} else {
				username = getFirstAttribute(tc.attributes, "uid")
			}

			if username != "john.doe" {
				t.Errorf("username extraction failed: expected 'john.doe', got '%s'", username)
			}

			// Test email extraction
			email := getFirstAttribute(tc.attributes, "mail")
			if email != "john.doe@company.com" {
				t.Errorf("email extraction failed: expected 'john.doe@company.com', got '%s'", email)
			}

			// Test name extraction
			firstName := getFirstAttribute(tc.attributes, "givenName")
			lastName := getFirstAttribute(tc.attributes, "sn")

			if firstName != "John" {
				t.Errorf("first name extraction failed: expected 'John', got '%s'", firstName)
			}
			if lastName != "Doe" {
				t.Errorf("last name extraction failed: expected 'Doe', got '%s'", lastName)
			}

			// Test group extraction
			groups := tc.attributes["memberOf"]
			if len(groups) != 2 {
				t.Errorf("expected 2 groups, got %d", len(groups))
			}
		})
	}
}

// TestLDAPSearchFilters tests LDAP search filter construction
func TestLDAPSearchFilters(t *testing.T) {
	testCases := []struct {
		name     string
		filter   string
		username string
		expected string
	}{
		{
			name:     "Active Directory user search",
			filter:   "(&(objectClass=user)(sAMAccountName=%s))",
			username: "john.doe",
			expected: "(&(objectClass=user)(sAMAccountName=john.doe))",
		},
		{
			name:     "OpenLDAP user search",
			filter:   "(&(objectClass=inetOrgPerson)(uid=%s))",
			username: "jane.smith",
			expected: "(&(objectClass=inetOrgPerson)(uid=jane.smith))",
		},
		{
			name:     "Group search by member DN",
			filter:   "(&(objectClass=group)(member=%s))",
			username: "cn=john.doe,ou=users,dc=company,dc=com",
			expected: "(&(objectClass=group)(member=cn=john.doe,ou=users,dc=company,dc=com))",
		},
		{
			name:     "Complex filter with multiple conditions",
			filter:   "(&(objectClass=user)(sAMAccountName=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
			username: "admin",
			expected: "(&(objectClass=user)(sAMAccountName=admin)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := fmt.Sprintf(tc.filter, tc.username)
			if result != tc.expected {
				t.Errorf("filter construction failed: expected '%s', got '%s'", tc.expected, result)
			}
		})
	}
}

// Helper functions for testing

// isValidLDAPFilter checks if LDAP filter is valid
func isValidLDAPFilter(filter string) bool {
	if filter == "" {
		return false
	}

	// Check for exactly one %s placeholder
	placeholderCount := 0
	for i := 0; i < len(filter)-1; i++ {
		if filter[i] == '%' && filter[i+1] == 's' {
			placeholderCount++
		}
	}

	if placeholderCount != 1 {
		return false
	}

	// Basic parentheses matching
	openCount := 0
	for _, char := range filter {
		if char == '(' {
			openCount++
		} else if char == ')' {
			openCount--
			if openCount < 0 {
				return false
			}
		}
	}

	return openCount == 0
}

// parseLDAPDN parses a DN into components
func parseLDAPDN(dn string) map[string]string {
	result := make(map[string]string)

	// Simple DN parsing (not handling escaped characters)
	parts := strings.Split(dn, ",")
	dcParts := []string{}

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "=") {
			kv := strings.SplitN(part, "=", 2)
			key := strings.ToLower(strings.TrimSpace(kv[0]))
			value := strings.TrimSpace(kv[1])

			if key == "dc" {
				dcParts = append(dcParts, value)
			} else if _, exists := result[key]; !exists {
				// Only store the first occurrence
				result[key] = value
			}
		}
	}

	// Combine DC parts into domain name
	if len(dcParts) > 0 {
		result["dc"] = strings.Join(dcParts, ".")
	}

	return result
}

// extractGroupNameFromDN extracts group name from group DN
func extractGroupNameFromDN(groupDN string) string {
	parts := strings.Split(groupDN, ",")
	if len(parts) > 0 {
		firstPart := strings.TrimSpace(parts[0])
		if strings.HasPrefix(strings.ToUpper(firstPart), "CN=") {
			return firstPart[3:] // Remove "CN="
		}
	}
	return ""
}

// getFirstAttribute gets first value of an attribute
func getFirstAttribute(attributes map[string][]string, key string) string {
	if values, exists := attributes[key]; exists && len(values) > 0 {
		return values[0]
	}
	return ""
}

// hasValidUserFilter checks if config has valid user filter
func (c *LDAPConfig) hasValidUserFilter() bool {
	return isValidLDAPFilter(c.UserFilter)
}

// hasValidGroupFilter checks if config has valid group filter
func (c *LDAPConfig) hasValidGroupFilter() bool {
	return c.GroupFilter == "" || isValidLDAPFilter(c.GroupFilter)
}
