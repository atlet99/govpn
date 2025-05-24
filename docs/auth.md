# GoVPN Authentication System

GoVPN provides a comprehensive authentication and authorization system with support for multiple authentication methods, multi-factor authentication (MFA), and enterprise integrations.

## Overview

The authentication system supports:
- **Local Authentication** - Username/password with secure hashing
- **LDAP Integration** - Active Directory and OpenLDAP support
- **OIDC/OAuth2** - Enterprise SSO with standard libraries
- **Multi-Factor Authentication** - TOTP/HOTP using industry-standard libraries
- **Role-Based Access Control** - Flexible user management
- **Session Management** - Secure token handling and refresh

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     AuthManager                            │
├─────────────────┬───────────────┬───────────────┬──────────┤
│  Local Auth     │  LDAP Auth    │  OIDC Auth    │   MFA    │
│  - Users        │  - AD/OpenLDP │  - OAuth2     │  - TOTP  │
│  - Passwords    │  - Groups     │  - Standard   │  - HOTP  │
│  - Roles        │  - Attributes │   Libraries   │  - QR    │
│  - Argon2/PBKDF2│  - Connection │  - JWT Tokens │  - Backup│
│                 │    Pooling    │  - PKCE       │   Codes  │
└─────────────────┴───────────────┴───────────────┴──────────┘
```

## Quick Start

### Basic Configuration

```go
import "github.com/atlet99/govpn/pkg/auth"

// Create authentication manager with default settings
config := auth.DefaultAuthConfig()
config.HashMethod = "argon2"  // Recommended for security

authManager, err := auth.NewAuthManager(config)
if err != nil {
    log.Fatal(err)
}
defer authManager.Close()
```

### Creating Users

```go
// Create a new user
user, err := authManager.CreateUser("alice", "secure_password_123")
if err != nil {
    log.Fatal(err)
}

// Add roles
err = authManager.AddUserRole("alice", "admin")
if err != nil {
    log.Fatal(err)
}
```

### Authentication

```go
// Authenticate user
result, err := authManager.AuthenticateUser("alice", "secure_password_123")
if err != nil {
    log.Printf("Authentication failed: %v", err)
    return
}

fmt.Printf("User authenticated: %s\n", result.User.Username)
fmt.Printf("Requires MFA: %t\n", result.RequiresMFA)
```

## Local Authentication

### Password Hashing

GoVPN supports two secure hashing algorithms:

#### Argon2 (Recommended)
- Modern password hashing algorithm
- Resistant to GPU and ASIC attacks
- Winner of the Password Hashing Competition

```go
config := auth.DefaultAuthConfig()
config.HashMethod = "argon2"
config.Argon2Memory = 65536    // 64 MB
config.Argon2Time = 3          // 3 iterations
config.Argon2Threads = 4       // 4 parallel threads
```

#### PBKDF2
- Standard algorithm with high iteration count
- Good compatibility with existing systems

```go
config := auth.DefaultAuthConfig()
config.HashMethod = "pbkdf2"
config.PBKDF2Iterations = 100000  // 100k iterations
config.PBKDF2KeyLength = 32       // 256-bit key
```

### User Management

```go
// Create user
user, err := authManager.CreateUser("username", "password")

// Update password
err = authManager.UpdatePassword("username", "new_password")

// Add/remove roles
err = authManager.AddUserRole("username", "admin")
err = authManager.RemoveUserRole("username", "guest")

// Activate/deactivate user
err = authManager.SetUserActive("username", false)

// Get user info
user, exists := authManager.GetUser("username")

// List all users
users := authManager.ListUsers()
```

## Multi-Factor Authentication (MFA)

GoVPN implements MFA using the industry-standard `github.com/pquerna/otp` library for maximum security and compatibility.

### Configuration

```go
config := auth.DefaultAuthConfig()
config.EnableMFA = true
config.MFA = &auth.MFAConfig{
    Enabled:          true,
    RequiredForAll:   false,  // MFA optional by default
    TOTPEnabled:      true,   // Time-based OTP
    HOTPEnabled:      false,  // Counter-based OTP (optional)
    BackupCodesCount: 10,     // Emergency backup codes
    TOTPSettings: auth.TOTPSettings{
        Period:    30,                    // 30 seconds
        Digits:    otp.DigitsSix,         // 6 digits
        Algorithm: otp.AlgorithmSHA1,     // SHA1 (most compatible)
        Skew:      1,                     // ±1 period tolerance
    },
    Issuer:          "GoVPN",
    GracePeriod:     5 * time.Minute,
    MaxAttempts:     5,                 // Brute force protection
    LockoutDuration: 15 * time.Minute,
}
```

### TOTP Setup

```go
// Setup TOTP for user
totpData, err := authManager.SetupMFA("username", "user@company.com")
if err != nil {
    log.Fatal(err)
}

// Display setup information
fmt.Printf("Secret: %s\n", totpData.Secret)
fmt.Printf("QR Code URL: %s\n", totpData.URL)
fmt.Printf("QR Code Image (base64): %s\n", totpData.QRCode)
fmt.Printf("Backup codes: %v\n", totpData.BackupCodes)

// User scans QR code with authenticator app and enters verification code
err = authManager.VerifyMFASetup("username", "123456")
if err != nil {
    log.Fatal(err)
}
```

### MFA Validation

```go
// Check if MFA is required
if authManager.IsMFARequired("username") {
    // Validate MFA code
    result, err := authManager.ValidateMFA("username", "123456")
    if err != nil {
        log.Printf("MFA validation failed: %v", err)
        return
    }
    
    if result.Valid {
        fmt.Printf("MFA successful via %s\n", result.Method)
        if result.Method == "backup" {
            fmt.Printf("Remaining backup codes: %d\n", result.RemainingCodes)
        }
    }
}
```

### MFA Management

```go
// Get MFA status
status := authManager.GetMFAStatus("username")
fmt.Printf("MFA enabled: %t\n", status["enabled"])
fmt.Printf("Setup complete: %t\n", status["setup_complete"])
fmt.Printf("TOTP enabled: %t\n", status["totp_enabled"])
fmt.Printf("Backup codes: %d\n", status["backup_codes"])

// Regenerate backup codes
newCodes, err := authManager.RegenerateBackupCodes("username")

// Disable MFA
err = authManager.DisableMFA("username")
```

## LDAP Integration

GoVPN supports integration with LDAP directories including Active Directory and OpenLDAP.

### Active Directory Configuration

```go
config := auth.DefaultAuthConfig()
config.EnableLDAP = true
config.LDAP = &auth.LDAPConfig{
    Enabled:         true,
    Server:          "dc.company.com",
    Port:            389,
    UseSSL:          false,
    UseTLS:          true,              // Use STARTTLS
    SkipVerify:      false,             // Verify certificates
    Timeout:         10 * time.Second,
    BindDN:          "cn=ldap-reader,ou=service-accounts,dc=company,dc=com",
    BindPassword:    "service-account-password",
    BaseDN:          "dc=company,dc=com",
    UserFilter:      "(&(objectClass=user)(sAMAccountName=%s))",
    UserSearchBase:  "ou=users,dc=company,dc=com",
    GroupSearchBase: "ou=groups,dc=company,dc=com",
    UserAttributes: auth.UserAttributes{
        Username:    "sAMAccountName",
        Email:       "mail",
        FirstName:   "givenName",
        LastName:    "sn",
        DisplayName: "displayName",
        Groups:      "memberOf",
    },
    RequiredGroups:     []string{"CN=VPN-Users,ou=groups,dc=company,dc=com"},
    AdminGroups:        []string{"CN=VPN-Admins,ou=groups,dc=company,dc=com"},
    ConnectionPoolSize: 10,
    MaxRetries:         3,
    RetryDelay:         time.Second,
    CacheEnabled:       true,
    CacheTimeout:       5 * time.Minute,
}
```

### OpenLDAP Configuration

```go
config.LDAP = &auth.LDAPConfig{
    Enabled:         true,
    Server:          "ldap.company.com",
    Port:            389,
    UseSSL:          false,
    UseTLS:          true,
    BindDN:          "cn=readonly,dc=company,dc=com",
    BindPassword:    "readonly-password",
    BaseDN:          "dc=company,dc=com",
    UserFilter:      "(&(objectClass=posixAccount)(uid=%s))",
    UserSearchBase:  "ou=people,dc=company,dc=com",
    GroupSearchBase: "ou=groups,dc=company,dc=com",
    UserAttributes: auth.UserAttributes{
        Username:    "uid",
        Email:       "mail",
        FirstName:   "givenName",
        LastName:    "sn",
        DisplayName: "cn",
        Groups:      "memberOf",
    },
    RequiredGroups: []string{"cn=vpn-users,ou=groups,dc=company,dc=com"},
    AdminGroups:    []string{"cn=vpn-admins,ou=groups,dc=company,dc=com"},
}
```

### LDAP Features

- **Connection Pooling**: Efficient connection reuse
- **Automatic Retries**: Resilient to network issues
- **Group Mapping**: Map LDAP groups to application roles
- **Attribute Mapping**: Flexible user attribute extraction
- **Caching**: Improve performance with configurable cache
- **SSL/TLS Support**: Secure connections
- **Certificate Validation**: Security hardening

## OIDC/OAuth2 Integration

GoVPN uses standard libraries (`golang.org/x/oauth2` and `github.com/coreos/go-oidc`) for secure and reliable OIDC integration.

### Keycloak Configuration

```go
config := auth.DefaultAuthConfig()
config.EnableOIDC = true
config.OIDC = &auth.OIDCConfig{
    Enabled:          true,
    ProviderURL:      "https://auth.company.com/realms/company",
    ClientID:         "govpn-client",
    ClientSecret:     "govpn-client-secret",
    RedirectURL:      "https://vpn.company.com/auth/callback",
    Scopes:           []string{"openid", "profile", "email", "groups"},
    IssuerValidation: true,
    RequiredClaims:   map[string]string{"email_verified": "true"},
    ClaimMappings: auth.ClaimMappings{
        Username:    "preferred_username",
        Email:       "email",
        FirstName:   "given_name",
        LastName:    "family_name",
        Groups:      "groups",
        Roles:       "realm_access.roles",
        DisplayName: "name",
    },
    SessionTimeout:      24 * time.Hour,
    RefreshTokenEnabled: true,
    DeviceFlowEnabled:   true,
    PkceEnabled:         true,  // PKCE for security
}
```

### Auth0 Configuration

```go
config.OIDC = &auth.OIDCConfig{
    Enabled:      true,
    ProviderURL:  "https://company.auth0.com",
    ClientID:     "your-auth0-client-id",
    ClientSecret: "your-auth0-client-secret",
    RedirectURL:  "https://vpn.company.com/auth/auth0/callback",
    Scopes:       []string{"openid", "profile", "email"},
    ClaimMappings: auth.ClaimMappings{
        Username:    "nickname",
        Email:       "email",
        FirstName:   "given_name",
        LastName:    "family_name",
        DisplayName: "name",
        Groups:      "https://company.com/groups",  // Custom claim
        Roles:       "https://company.com/roles",   // Custom claim
    },
    SessionTimeout:      8 * time.Hour,
    RefreshTokenEnabled: true,
    PkceEnabled:         true,
}
```

### OIDC Features

- **Standard Library Usage**: Uses `golang.org/x/oauth2` for reliability
- **Automatic Endpoint Discovery**: Via `.well-known/openid_configuration`
- **JWT Verification**: Secure token validation
- **PKCE Support**: Enhanced security for public clients
- **Device Flow**: Support for devices without browsers
- **Token Refresh**: Automatic token renewal
- **Claim Mapping**: Flexible user attribute extraction

### OIDC Authentication Flow

```go
// 1. Generate authorization URL
authURL := authManager.GetOIDCAuthURL("state-value")

// 2. User authenticates with provider and returns with code

// 3. Exchange code for tokens
tokens, err := authManager.ExchangeOIDCCode("authorization-code", "state-value")

// 4. Validate and extract user information
user, err := authManager.ValidateOIDCToken(tokens.IDToken)

// 5. Create local session
session, err := authManager.CreateSession(user)
```

## Role-Based Access Control (RBAC)

### Role Management

```go
// Define roles in configuration or create dynamically
roles := []string{"admin", "user", "operator", "guest"}

// Assign roles to users
err = authManager.AddUserRole("alice", "admin")
err = authManager.AddUserRole("bob", "user")
err = authManager.AddUserRole("charlie", "operator")

// Check user roles
user, _ := authManager.GetUser("alice")
fmt.Printf("User roles: %v\n", user.Roles)

// Remove roles
err = authManager.RemoveUserRole("alice", "admin")
```

### Permission Checking

```go
// Check if user has specific role
func hasRole(user *auth.User, role string) bool {
    for _, r := range user.Roles {
        if r == role {
            return true
        }
    }
    return false
}

// Example usage
if hasRole(user, "admin") {
    // Allow admin operations
}

// Role hierarchy (implement as needed)
func hasPermission(user *auth.User, permission string) bool {
    switch permission {
    case "read":
        return hasRole(user, "user") || hasRole(user, "admin")
    case "write":
        return hasRole(user, "admin")
    case "manage_users":
        return hasRole(user, "admin")
    default:
        return false
    }
}
```

## Session Management

### Session Configuration

```go
config := auth.DefaultAuthConfig()
config.SessionTimeout = 24 * time.Hour
config.RefreshTokenTimeout = 7 * 24 * time.Hour  // 7 days
config.MaxSessions = 5  // Maximum concurrent sessions per user
```

### Session Operations

```go
// Create session after successful authentication
session, err := authManager.CreateSession(user)
if err != nil {
    log.Fatal(err)
}

// Validate session token
user, err := authManager.ValidateSession(sessionToken)
if err != nil {
    log.Printf("Invalid session: %v", err)
    return
}

// Refresh session
newToken, err := authManager.RefreshSession(sessionToken)
if err != nil {
    log.Printf("Session refresh failed: %v", err)
    return
}

// Logout
err = authManager.RevokeSession(sessionToken)
if err != nil {
    log.Printf("Logout failed: %v", err)
}

// Logout all sessions for user
err = authManager.RevokeAllUserSessions("username")
```

## Security Best Practices

### Password Security

1. **Use Argon2** for new deployments
2. **High iteration counts** for PBKDF2 if required
3. **Minimum password requirements** in application logic
4. **Regular password updates** policies

### MFA Security

1. **Backup codes** for recovery scenarios
2. **Rate limiting** MFA attempts
3. **Secure QR code distribution**
4. **Regular secret rotation**

### LDAP Security

1. **Use TLS** for all connections
2. **Dedicated service accounts** with minimal privileges
3. **Certificate validation** enabled
4. **Connection pooling** for performance

### OIDC Security

1. **PKCE enabled** for public clients
2. **State parameter** validation
3. **Nonce verification** for ID tokens
4. **Regular key rotation**

### General Security

1. **Input validation** on all authentication inputs
2. **Rate limiting** on authentication endpoints
3. **Audit logging** of all authentication events
4. **Regular security updates**

## Configuration Reference

### Complete Configuration Example

```go
config := &auth.Config{
    // Basic settings
    HashMethod:           "argon2",
    SessionTimeout:       24 * time.Hour,
    RefreshTokenTimeout:  7 * 24 * time.Hour,
    MaxSessions:          5,
    
    // Argon2 settings
    Argon2Memory:   65536,  // 64 MB
    Argon2Time:     3,      // 3 iterations
    Argon2Threads:  4,      // 4 threads
    
    // PBKDF2 settings
    PBKDF2Iterations: 100000,  // 100k iterations
    PBKDF2KeyLength:  32,      // 256-bit key
    
    // MFA settings
    EnableMFA: true,
    MFA: &auth.MFAConfig{
        Enabled:          true,
        RequiredForAll:   false,
        TOTPEnabled:      true,
        HOTPEnabled:      false,
        BackupCodesCount: 10,
        TOTPSettings: auth.TOTPSettings{
            Period:    30,
            Digits:    otp.DigitsSix,
            Algorithm: otp.AlgorithmSHA1,
            Skew:      1,
        },
        Issuer:          "GoVPN",
        GracePeriod:     5 * time.Minute,
        MaxAttempts:     5,
        LockoutDuration: 15 * time.Minute,
    },
    
    // LDAP settings
    EnableLDAP: true,
    LDAP: &auth.LDAPConfig{
        // ... (see LDAP section above)
    },
    
    // OIDC settings
    EnableOIDC: true,
    OIDC: &auth.OIDCConfig{
        // ... (see OIDC section above)
    },
}
```

## Error Handling

### Common Errors

```go
// Authentication errors
if err != nil {
    switch {
    case errors.Is(err, auth.ErrUserNotFound):
        log.Printf("User not found")
    case errors.Is(err, auth.ErrInvalidCredentials):
        log.Printf("Invalid credentials")
    case errors.Is(err, auth.ErrUserDeactivated):
        log.Printf("User account deactivated")
    case errors.Is(err, auth.ErrMFARequired):
        log.Printf("MFA verification required")
    case errors.Is(err, auth.ErrMFAInvalid):
        log.Printf("Invalid MFA code")
    case errors.Is(err, auth.ErrSessionExpired):
        log.Printf("Session expired")
    default:
        log.Printf("Authentication error: %v", err)
    }
}
```

## Logging and Monitoring

### Audit Events

The authentication system logs the following events:

- User creation/modification/deletion
- Successful and failed authentication attempts
- MFA setup and validation
- Role changes
- Session creation/validation/revocation
- LDAP connection events
- OIDC token exchanges

### Metrics

Monitor these key metrics:

- Authentication success/failure rates
- MFA adoption rates
- Session duration statistics
- LDAP response times
- OIDC token refresh rates

## Testing

### Running Tests

```bash
# Run all authentication tests
go test ./pkg/auth/...

# Run with verbose output
go test -v ./pkg/auth/...

# Run specific tests
go test -run TestMFA ./pkg/auth/...
```

### Demo Application

```bash
# Run the complete demo
cd examples
go run obfuscation_demo.go

# The demo includes authentication section with:
# - Basic authentication
# - MFA setup and validation
# - User management
# - LDAP configuration examples
# - OIDC configuration examples
```

## Migration Guide

### Upgrading from Custom OIDC to Standard Libraries

If you're upgrading from a custom OIDC implementation:

1. **Update dependencies**: The new implementation uses `golang.org/x/oauth2` and `github.com/coreos/go-oidc`
2. **Configuration changes**: PKCE is now enabled by default
3. **Token handling**: Automatic refresh is now built-in
4. **Security improvements**: Better JWT validation and endpoint discovery

### Upgrading MFA Implementation

If upgrading from custom MFA:

1. **Library change**: Now uses `github.com/pquerna/otp`
2. **Configuration update**: Type changes for `Digits` and `Algorithm`
3. **QR generation**: Automatic QR code generation with standard library
4. **Backup codes**: Improved cryptographic generation

## Troubleshooting

### Common Issues

#### LDAP Connection Issues
```
Error: LDAP connection failed
Solution: Check network connectivity, credentials, and certificate validation
```

#### OIDC Discovery Issues
```
Error: Failed to discover OIDC endpoints
Solution: Verify provider URL and network access to .well-known/openid_configuration
```

#### MFA Setup Issues
```
Error: Invalid TOTP code during setup
Solution: Check system time synchronization between server and client
```

### Debug Mode

Enable debug logging for troubleshooting:

```go
import "log"

logger := log.New(os.Stdout, "[AUTH] ", log.LstdFlags|log.Lshortfile)
authManager, err := auth.NewAuthManager(config, logger)
```

## Support

For issues and questions:

1. Check the troubleshooting section above
2. Review the demo application for examples
3. Check GitHub issues for known problems
4. Enable debug logging for detailed error information

---

This documentation covers the complete GoVPN authentication system. For implementation details, refer to the source code and demo application in the `examples/` directory. 