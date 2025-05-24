# GoVPN

[![Go Report Card](https://goreportcard.com/badge/github.com/atlet99/govpn)](https://goreportcard.com/report/github.com/atlet99/govpn)

**GoVPN** is a modern evolution of OpenVPN, implemented in Go with a focus on compatibility, performance, and security.

## Project Vision

GoVPN aims to evolve OpenVPN, preserving its time-tested concepts while addressing its shortcomings:

- **Compatibility with the OpenVPN ecosystem** - support for existing clients and configurations
- **High performance** - optimized implementation in Go
- **Modern security** - OIDC, MFA, LDAP integration, and modern cryptography
- **Deployment flexibility** - from single installations to Kubernetes clusters
- **Ease of management** - powerful CLI, REST API, and web panel while maintaining familiar configuration
- **Advanced traffic obfuscation** - built-in anti-censorship capabilities

## Current Status

The project is in active development (Phase 2). Key implemented features:

### 🔧 Complete Configuration System
- **OpenVPN Configuration Compatibility** - full support for OpenVPN .conf files
- **Enhanced Configuration Parser** - 80+ new parameters for modern features
- **Modular Configuration Files** - organized auth.conf, mfa.conf, oidc.conf, ldap.conf, obfuscation.conf
- **Configuration Priority System** - proper OpenVPN-style precedence (config file → command line → defaults)
- **Comprehensive Examples** - 8 detailed configuration files with enterprise scenarios

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
  - Support for FreeIPA, 389 Directory, Oracle Internet Directory
- **OIDC/OAuth2 Integration** using standard libraries:
  - `golang.org/x/oauth2` and `github.com/coreos/go-oidc`
  - Automatic endpoint discovery and JWT verification
  - PKCE support for enhanced security
  - Device flow for headless authentication
  - Support for Keycloak, Google Workspace, Azure AD, Auth0, Okta, GitLab
- **Role-Based Access Control (RBAC)** with flexible user management
- **Session Management** with secure token handling and refresh

### 🎭 Advanced Traffic Obfuscation System
- **Complete Implementation** - 8 working obfuscation methods
- **TLS Tunneling** for HTTPS-like traffic masquerading
- **HTTP Mimicry** for web request simulation
- **HTTP Steganography** for hiding data within HTTP traffic
- **DNS Tunneling** for emergency backup communication
- **XOR Cipher** for fast packet-level obfuscation
- **Packet Padding** for size randomization and statistical analysis resistance
- **Timing Obfuscation** for temporal pattern masking
- **Traffic Padding** for volume pattern masking and constant traffic flow
- **Flow Watermarking** for statistical characteristic distortion
- **Regional Profiles** optimized for China, Iran, Russia with specific DPI bypass strategies
- **DPI Detection and Adaptive Switching** - automatic method switching on detection
- **Performance Monitoring** - detailed metrics for each obfuscation method

### 🛠️ Management & Monitoring
- REST API for server management with authentication endpoints
- Robust command-line interface with OpenVPN compatibility
- Comprehensive logging and audit trails
- Metrics for monitoring authentication and obfuscation performance

## Roadmap

See [IDEA.md](./IDEA.md) for a detailed roadmap and development plan.

## Key Features

### ✅ Implemented
- ✅ **Complete Configuration System** - Enhanced OpenVPN config parser with 80+ new parameters
- ✅ **Authentication System** - Local, MFA, LDAP, OIDC with standard libraries
- ✅ **Traffic Obfuscation** - 8 methods with anti-detection and regional profiles
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
# Start server with basic configuration
./govpn-server -config deploy/server.conf

# Start with authentication and obfuscation
./govpn-server -config deploy/server.conf -auth -obfuscation

# Start with API interface
./govpn-server -api -api-port 8080 -api-listen 127.0.0.1
```

### Configuration Examples

GoVPN provides modular configuration files for different scenarios:

```bash
# Corporate network with Active Directory and MFA
cp deploy/server.conf /etc/govpn/
cp deploy/ldap.conf /etc/govpn/
cp deploy/mfa.conf /etc/govpn/
# Edit server.conf and uncomment: include ldap.conf, include mfa.conf

# Public VPN with traffic obfuscation
cp deploy/obfuscation.conf /etc/govpn/
# Edit server.conf and uncomment: include obfuscation.conf

# High security setup
# Uncomment all authentication methods in server.conf
```

### Configuration Demo

```bash
# Run the comprehensive configuration demo
cd examples
go run obfuscation_demo.go

# The demo includes:
# - Configuration parsing examples
# - Local authentication with secure hashing
# - MFA setup and validation
# - User management operations
# - LDAP configuration examples
# - OIDC configuration examples
# - Complete traffic obfuscation demonstrations
```

## Configuration System

GoVPN features a comprehensive configuration system with OpenVPN compatibility:

### Main Configuration Files

- **`server.conf`** - Main server configuration with OpenVPN compatibility
- **`client.conf`** - Basic client configuration with all authentication methods
- **`auth.conf`** - Password authentication with Argon2/PBKDF2 hashing
- **`mfa.conf`** - Multi-factor authentication with TOTP/HOTP
- **`oidc.conf`** - OpenID Connect integration (Keycloak, Google, Microsoft, etc.)
- **`ldap.conf`** - LDAP authentication (Active Directory, OpenLDAP, FreeIPA)
- **`obfuscation.conf`** - Traffic obfuscation and censorship circumvention
- **`example-complete.conf`** - Complete demonstration of all features

### Configuration Examples

#### Basic Authentication with MFA

```conf
# server.conf
include auth.conf
include mfa.conf

# auth.conf
auth-hash-method argon2
auth-argon2-memory 65536
auth-session-timeout 3600

# mfa.conf
mfa-enabled true
mfa-totp-enabled true
mfa-backup-codes-count 10
```

#### Enterprise LDAP Integration

```conf
# ldap.conf
ldap-enabled true
ldap-server dc.company.com
ldap-use-tls true
ldap-bind-dn cn=ldap-reader,ou=service-accounts,dc=company,dc=com
ldap-user-filter (&(objectClass=user)(sAMAccountName=%s))
ldap-required-groups CN=VPN-Users,ou=groups,dc=company,dc=com
```

#### OIDC with Keycloak

```conf
# oidc.conf
oidc-enabled true
oidc-provider-url https://auth.company.com/realms/company
oidc-client-id govpn-client
oidc-scopes openid,profile,email,groups
oidc-pkce-enabled true
```

#### Traffic Obfuscation

```conf
# obfuscation.conf
obfuscation-enabled true
obfuscation-primary-method xor_cipher
xor-cipher-key "MySecretObfuscationKey2024"
packet-padding-enabled true
adaptive-obfuscation-enabled true

# Regional profile for China
china-profile-enabled false
china-profile-methods shadowsocks,v2ray
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
- **Adaptive Switching**: Automatic method changes on censorship detection

## Traffic Obfuscation

GoVPN includes a comprehensive traffic obfuscation system designed to bypass Deep Packet Inspection (DPI) and censorship:

### Available Methods

1. **XOR Cipher** - Fast packet-level obfuscation
2. **TLS Tunneling** - HTTPS traffic masquerading
3. **HTTP Mimicry** - Web request simulation
4. **HTTP Steganography** - Data hiding in HTTP traffic
5. **DNS Tunneling** - Emergency communication channel
6. **Packet Padding** - Size randomization
7. **Timing Obfuscation** - Temporal pattern masking
8. **Traffic Padding** - Volume pattern masking

### Regional Profiles

- **China Profile** - Great Firewall bypass strategies
- **Iran Profile** - Optimized for Iranian censorship
- **Russia Profile** - Adapted for Russian restrictions

### Usage Examples

```bash
# Enable basic obfuscation
./govpn-server -config deploy/server.conf -obfuscation

# Use China profile
./govpn-server -config deploy/server.conf -obfuscation -regional-profile=china

# Custom XOR key
./govpn-server -config deploy/server.conf -obfuscation -xor-key="my-secret-key"
```

## Development

### Project Structure

```
govpn/
├── cmd/                    # Executable applications
│   ├── server/             # VPN server with comprehensive auth
│   └── client/             # Client application
├── pkg/                    # Library code
│   ├── auth/               # 🔐 Complete authentication system
│   ├── compat/             # 🔧 OpenVPN configuration compatibility
│   ├── obfuscation/        # 🎭 Traffic obfuscation system
│   ├── core/               # VPN core with protocol compatibility
│   ├── api/                # REST API with auth endpoints
│   └── monitoring/         # Metrics and monitoring
├── examples/               # 🧪 Demo applications
├── docs/                   # 📚 Comprehensive documentation
├── deploy/                 # 🚀 Production-ready configurations
│   ├── server.conf         # Main server configuration
│   ├── auth.conf           # Authentication configuration
│   ├── mfa.conf            # Multi-factor authentication
│   ├── oidc.conf           # OpenID Connect settings
│   ├── ldap.conf           # LDAP/Active Directory
│   ├── obfuscation.conf    # Traffic obfuscation
│   ├── client.conf         # Client configuration
│   └── example-complete.conf # Complete feature demo
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

# Run configuration and authentication demo
cd examples && go run obfuscation_demo.go
```

### Testing Authentication

```bash
# Run authentication tests
go test ./pkg/auth/...

# Run configuration parser tests
go test ./pkg/compat/...

# Run obfuscation tests
go test ./pkg/obfuscation/...

# Run with verbose output
go test -v ./pkg/auth/... ./pkg/compat/... ./pkg/obfuscation/...
```

## Documentation

Comprehensive documentation is available in the [docs/](docs/) directory and [deploy/](deploy/) folder:

- **[Configuration Guide](deploy/README.md)** - Complete setup guide with examples:
  - Modular configuration system
  - Authentication methods (local, MFA, LDAP, OIDC)
  - Traffic obfuscation setup
  - Regional profiles and enterprise scenarios
  - Security best practices

- **[Authentication System](docs/auth.md)** - Enterprise authentication:
  - Local authentication with secure hashing
  - MFA setup and management
  - LDAP integration for enterprises
  - OIDC/OAuth2 with standard libraries
  - Role-based access control

- **[Obfuscation System](docs/obfuscation/)** - Traffic hiding techniques
- **[API Reference](docs/api.md)** - REST API documentation
- **[Deployment Guide](docs/deployment.md)** - Production setup

### Key Documentation Highlights

✅ **Production-Ready Configurations** - 8 detailed .conf files for enterprise use  
✅ **Real Working Examples** - All code examples are tested and functional  
✅ **Standard Libraries** - Uses `golang.org/x/oauth2`, `github.com/pquerna/otp`  
✅ **Security Best Practices** - Industry-standard implementations  
✅ **Troubleshooting Guides** - Common issues and solutions  
✅ **Migration Paths** - Upgrading from OpenVPN installations  

## Contributing

We welcome contributors! Please:

1. Read the documentation in [docs/](docs/) and [deploy/README.md](deploy/README.md)
2. Run the demo to understand the system: `cd examples && go run obfuscation_demo.go`
3. Follow security best practices documented in configuration files
4. Ensure tests pass: `make check-all`
5. Update documentation for new features

### Areas for Contribution

- 🔐 Authentication providers (SAML, custom OAuth2)
- 🎭 New obfuscation methods  
- 🌐 Web interface development
- 📊 Monitoring and metrics
- 🐳 Container and Kubernetes support
- 📚 Documentation improvements
- 🔧 Configuration system enhancements

## License

GoVPN is distributed under the [MIT](./LICENSE) license.

---

**🚀 Ready to get started?** 

- **Quick setup**: Copy configuration files from [deploy/](deploy/) folder
- **Enterprise setup**: Read [deploy/README.md](deploy/README.md) for LDAP/OIDC integration
- **Anti-censorship**: Configure traffic obfuscation with [deploy/obfuscation.conf](deploy/obfuscation.conf)
- **Full demo**: Run `cd examples && go run obfuscation_demo.go` to see everything in action! 