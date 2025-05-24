# GoVPN

[![Go Report Card](https://goreportcard.com/badge/github.com/atlet99/govpn)](https://goreportcard.com/report/github.com/atlet99/govpn)

**GoVPN** is a modern evolution of OpenVPN, implemented in Go with a focus on compatibility, performance, and security.

## Project Vision

GoVPN aims to evolve OpenVPN, preserving its time-tested concepts while addressing its shortcomings:

- **Compatibility with the OpenVPN ecosystem** - support for existing clients
- **High performance** - optimized implementation in Go
- **Modern security** - OIDC, MFA, modern cryptography
- **Deployment flexibility** - from single installations to Kubernetes clusters
- **Ease of management** - powerful CLI, REST API, and web panel while maintaining familiar configuration

## Current Status

The project is in active development (Phase 1). Key implemented features:

### Core VPN Features
- Core VPN engine with OpenVPN protocol compatibility
- Support for classic OpenVPN configuration formats
- Modern cryptography with AES-GCM and ChaCha20-Poly1305
- TLSv1.3 support with secure ciphers
- Certificate management and PKI

### 🔐 Comprehensive Authentication System
- **Local Authentication** with secure password hashing (Argon2/PBKDF2)
- **Multi-Factor Authentication (MFA)** using industry-standard libraries:
  - TOTP/HOTP support with `github.com/pquerna/otp`
  - Automatic QR code generation for authenticator apps
  - Backup codes for recovery scenarios
  - Brute force protection with rate limiting
- **LDAP Integration** for enterprise environments:
  - Active Directory and OpenLDAP support
  - Connection pooling and automatic retries
  - Group mapping and attribute extraction
  - SSL/TLS connections with certificate validation
- **OIDC/OAuth2 Integration** using standard libraries:
  - `golang.org/x/oauth2` and `github.com/coreos/go-oidc`
  - Automatic endpoint discovery and JWT verification
  - PKCE support for enhanced security
  - Device flow for headless authentication
  - Support for Keycloak, Auth0, and other providers
- **Role-Based Access Control (RBAC)** with flexible user management
- **Session Management** with secure token handling and refresh

### 🎭 Advanced Traffic Obfuscation System
- **TLS Tunneling** for HTTPS-like traffic
- **HTTP Mimicry** for web request simulation
- **HTTP Steganography** for hiding data within HTTP traffic
- **DNS Tunneling** for emergency backup communication
- **Packet Padding** for size randomization
- **Timing Obfuscation** for temporal pattern masking
- **Traffic Padding** for volume pattern masking
- **Flow Watermarking** for statistical characteristic distortion
- Regional profiles optimized for different countries
- DPI detection and automatic method switching

### 🛠️ Management & Monitoring
- REST API for server management
- Robust command-line interface
- Comprehensive logging and audit trails
- Metrics for monitoring authentication and obfuscation

## Roadmap

See [IDEA.md](./IDEA.md) for a detailed roadmap and development plan.

## Key Features

### ✅ Implemented
- ✅ **Authentication System** - Local, MFA, LDAP, OIDC with standard libraries
- ✅ **Traffic Obfuscation** - Multiple methods with anti-detection capabilities
- ✅ **OpenVPN Compatibility** - Protocol and configuration support
- ✅ **Modern Cryptography** - TLSv1.3, AES-GCM, ChaCha20-Poly1305
- ✅ **REST API** - Complete server management interface
- ✅ **Certificate Management** - Full PKI support

### 🚧 In Development
- 🚧 Web interface for administration
- 🚧 PostgreSQL integration for enterprise deployments
- 🚧 Clustering and high availability
- 🚧 Prometheus monitoring integration
- 🚧 Advanced user provisioning

## Requirements

- **Go 1.24.2 or higher**
- (Optional) PostgreSQL 15 or higher for enterprise features
- Network access for LDAP/OIDC providers (if used)

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/atlet99/govpn.git
cd govpn

# Build the server
go build -o govpn-server ./cmd/server

# Build the client  
go build -o govpn-client ./cmd/client
```

### Basic Usage

```bash
# Start server with authentication and obfuscation
./govpn-server -config server.conf -auth -obfuscation

# Start with API interface
./govpn-server -api -api-port 8080 -api-listen 127.0.0.1
```

### Authentication Demo

```bash
# Run the comprehensive demo
cd examples
go run obfuscation_demo.go

# The demo includes:
# - Local authentication with secure hashing
# - MFA setup and validation
# - User management operations
# - LDAP configuration examples
# - OIDC configuration examples
# - Traffic obfuscation demonstrations
```

## Authentication Configuration Examples

### Local Authentication with MFA

```go
config := auth.DefaultAuthConfig()
config.HashMethod = "argon2"  // Recommended for security
config.EnableMFA = true
config.MFA = &auth.MFAConfig{
    Enabled:          true,
    TOTPEnabled:      true,
    BackupCodesCount: 10,
    TOTPSettings: auth.TOTPSettings{
        Period:    30,
        Digits:    otp.DigitsSix,
        Algorithm: otp.AlgorithmSHA1,
    },
}
```

### LDAP Integration

```go
config.EnableLDAP = true
config.LDAP = &auth.LDAPConfig{
    Server:          "dc.company.com",
    Port:            389,
    UseTLS:          true,
    BindDN:          "cn=ldap-reader,ou=service-accounts,dc=company,dc=com",
    BaseDN:          "dc=company,dc=com",
    UserFilter:      "(&(objectClass=user)(sAMAccountName=%s))",
    RequiredGroups:  []string{"CN=VPN-Users,ou=groups,dc=company,dc=com"},
}
```

### OIDC Configuration

```go
config.EnableOIDC = true
config.OIDC = &auth.OIDCConfig{
    ProviderURL:      "https://auth.company.com/realms/company",
    ClientID:         "govpn-client",
    ClientSecret:     "govpn-client-secret",
    RedirectURL:      "https://vpn.company.com/auth/callback",
    Scopes:           []string{"openid", "profile", "email", "groups"},
    PkceEnabled:      true,  // Enhanced security
}
```

## REST API

GoVPN provides a comprehensive REST API for managing authentication, users, and server configuration:

```bash
# Enable API with authentication
./govpn-server -api -api-port 8080 -api-auth -api-auth-secret "your-secret-key"
```

### Authentication Endpoints

- **POST /auth/login** - User authentication
- **POST /auth/mfa/setup** - Setup MFA for user
- **POST /auth/mfa/verify** - Verify MFA code
- **POST /auth/logout** - User logout
- **GET /users** - List all users
- **POST /users** - Create new user
- **PUT /users/:id** - Update user
- **DELETE /users/:id** - Delete user
- **POST /users/:id/roles** - Add user role
- **DELETE /users/:id/roles/:role** - Remove user role

### Server Management Endpoints

- **GET /status** - Get server status
- **GET /clients** - List connected clients
- **GET /certificates** - Certificate management
- **GET /config** - Server configuration
- **GET /metrics** - Authentication and obfuscation metrics

### Example Usage

```bash
# Authenticate user
curl -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "secure_password_123"}'

# Setup MFA for user
curl -X POST http://127.0.0.1:8080/api/v1/auth/mfa/setup \
  -H "Authorization: Bearer <token>" \
  -d '{"username": "alice", "email": "alice@company.com"}'

# Get server status
curl -H "Authorization: Bearer <token>" \
  http://127.0.0.1:8080/api/v1/status
```

## Security Features

### 🛡️ Authentication Security
- **Modern Password Hashing**: Argon2 (recommended) and PBKDF2 support
- **Multi-Factor Authentication**: Industry-standard TOTP/HOTP implementation
- **Enterprise Integration**: Secure LDAP and OIDC with standard libraries
- **Brute Force Protection**: Rate limiting and account lockout
- **Session Security**: Secure token handling with automatic refresh

### 🔒 Communication Security
- **Standard Libraries**: Uses `golang.org/x/oauth2`, `github.com/pquerna/otp`, `github.com/coreos/go-oidc`
- **PKCE Support**: Enhanced OAuth2 security for public clients
- **Certificate Validation**: Proper SSL/TLS verification
- **Audit Logging**: Comprehensive security event tracking

### 🎭 Traffic Obfuscation Security
- **Multiple Methods**: TLS, HTTP, DNS tunneling with automatic switching
- **Anti-Detection**: Statistical analysis resistance and regional profiles
- **Steganography**: Data hiding within legitimate traffic patterns

## Development

### Project Structure

```
govpn/
├── cmd/                    # Executable applications
│   ├── server/             # VPN server with comprehensive auth
│   └── client/             # Client application
├── pkg/                    # Library code
│   ├── auth/               # 🔐 Complete authentication system
│   │   ├── auth.go         # Main auth manager
│   │   ├── mfa.go          # MFA with standard libraries
│   │   ├── ldap.go         # LDAP integration
│   │   └── oidc.go         # OIDC with oauth2 library
│   ├── obfuscation/        # 🎭 Traffic obfuscation system
│   ├── core/               # VPN core with protocol compatibility
│   ├── api/                # REST API with auth endpoints
│   └── monitoring/         # Metrics and monitoring
├── examples/               # 🧪 Demo applications
│   └── obfuscation_demo.go # Complete auth & obfuscation demo
├── docs/                   # 📚 Comprehensive documentation
│   ├── auth.md             # Authentication system guide
│   └── obfuscation/        # Obfuscation documentation
└── deploy/                 # Deployment configurations
```

### Building and Testing

```bash
# Install dependencies
go mod tidy

# Run all tests
make test

# Run linting
make lint

# Complete check (tests + linting + static analysis)
make check-all

# Run demo with authentication examples
cd examples && go run obfuscation_demo.go
```

### Testing Authentication

```bash
# Run authentication tests
go test ./pkg/auth/...

# Run with verbose output
go test -v ./pkg/auth/...

# Run specific MFA tests  
go test -run TestMFA ./pkg/auth/...
```

## Documentation

Comprehensive documentation is available in the [docs/](docs/) directory:

- **[Authentication System](docs/auth.md)** - Complete guide covering:
  - Local authentication with secure hashing
  - MFA setup and management
  - LDAP integration for enterprises
  - OIDC/OAuth2 with standard libraries
  - Role-based access control
  - Security best practices and troubleshooting

- **[Obfuscation System](docs/obfuscation/)** - Traffic hiding techniques
- **[API Reference](docs/api.md)** - REST API documentation
- **[Deployment Guide](docs/deployment.md)** - Production setup

### Key Documentation Highlights

✅ **Real Working Examples** - All code examples are tested and functional  
✅ **Standard Libraries** - Uses `golang.org/x/oauth2`, `github.com/pquerna/otp`  
✅ **Security Best Practices** - Industry-standard implementations  
✅ **Troubleshooting Guides** - Common issues and solutions  
✅ **Migration Paths** - Upgrading from custom implementations  

## Contributing

We welcome contributors! Please:

1. Read the documentation in [docs/](docs/)
2. Run the demo to understand the system: `cd examples && go run obfuscation_demo.go`
3. Follow security best practices documented in [docs/auth.md](docs/auth.md)
4. Ensure tests pass: `make check-all`
5. Update documentation for new features

### Areas for Contribution

- 🔐 Authentication providers (SAML, custom OAuth2)
- 🎭 New obfuscation methods  
- 🌐 Web interface development
- 📊 Monitoring and metrics
- 🐳 Container and Kubernetes support
- 📚 Documentation improvements

## License

GoVPN is distributed under the [MIT](./LICENSE) license.

---

**🚀 Ready to get started?** Check out [docs/auth.md](docs/auth.md) for authentication setup or run `cd examples && go run obfuscation_demo.go` to see the system in action! 