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

**Phase 1**: ✅ **COMPLETED** - Basic functionality and OpenVPN compatibility  
**Phase 2**: ✅ **COMPLETED** - Configuration system, obfuscation, authentication, testing  
**Web Interface**: ✅ **COMPLETED** - Full-featured administrative panel

### ✨ Latest Achievements

#### ✅ NEW: Full-Featured Web Interface
- ✅ **React + TypeScript** - modern architecture with Material-UI design
- ✅ **Internationalization** - complete support for Russian and English languages
- ✅ **User Management** - CRUD operations with roles and statuses
- ✅ **Real-time Monitoring** - server statistics and connections
- ✅ **Certificate Management** - creation, viewing, revocation of certificates
- ✅ **Authentication System** - JWT tokens and secure sessions
- ✅ **Responsive Design** - optimization for all devices
- ✅ **API Client** - typed integration with backend
- ✅ **Development API Server** - mock API for interface development

#### ✅ COMPLETED: Comprehensive Configuration System
- ✅ **Enhanced configuration parser** - support for 80+ new parameters with OpenVPN compatibility
- ✅ **Modular configuration files** - organized auth.conf, mfa.conf, oidc.conf, ldap.conf, obfuscation.conf
- ✅ **Priority system** - proper OpenVPN-like precedence (config file → command line → defaults)
- ✅ **8 ready-made configurations** - from basic to enterprise scenarios with detailed examples

#### ✅ COMPLETED: Full Authentication System
- ✅ **Basic authentication** - modern hashing algorithms Argon2/PBKDF2
- ✅ **Multi-factor authentication** - complete TOTP/HOTP support with backup codes
- ✅ **LDAP integration** - support for Active Directory, OpenLDAP, FreeIPA, 389 Directory, Oracle Internet Directory
- ✅ **OIDC integration** - works with Keycloak, Google Workspace, Azure AD, Auth0, Okta, GitLab

#### ✅ COMPLETED: Comprehensive Obfuscation System
- ✅ **Modular obfuscation system** with 8 methods (TLS Tunnel, HTTP Mimicry, DNS Tunnel, XOR, etc.)
- ✅ **Anti-statistical analysis** - Packet Padding, Timing Obfuscation, Traffic Padding, Flow Watermarking
- ✅ **Steganography methods** - HTTP Cover Traffic, DNS Tunneling
- ✅ **Regional profiles** for China, Iran, Russia with adaptive switching

## 📊 Web Interface

### Starting Development Environment

1. **Launch Development API Server:**
```bash
# Build and run API server with mock data
go build -o govpn-dev-api ./cmd/dev-api
./govpn-dev-api -port 8080 -host 127.0.0.1
```

2. **Launch Web Interface:**
```bash
cd web
npm install
npm run dev
# Open http://localhost:5173
```

### Available API Endpoints

Development API server provides:
- `GET /api/v1/status` - server status
- `GET /api/v1/users` - list users
- `POST /api/v1/users` - create user
- `GET|PATCH|DELETE /api/v1/users/{id}` - user operations
- `GET /api/v1/clients` - active connections
- `GET /api/v1/certificates` - certificate management
- `GET /api/v1/config` - server configuration
- `GET /api/v1/logs` - system logs

### Web Interface Features

- **Internationalization**: 483 lines of translations for Russian and English languages
- **Modern Material-UI design**: cards, chips, dialogs, snackbars
- **Typed API client**: full TypeScript integration
- **Responsiveness**: optimization for desktop and mobile devices
- **Security**: JWT authentication and protected routes

## 🏗️ Architecture

```
                   ┌──────────────────┐
                   │  Web Dashboard   │
                   │  (React + TS)    │
                   │  Port: 5173      │
                   └─────────┬────────┘
                             │ HTTP API
                             │
                    ┌────────┴────────┐
                    │   REST API      │
                    │   Port: 8080    │
                    │   /api/v1/*     │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
    ┌─────────┴─────────┐         ┌─────────┴──────────┐
    │ Development API   │         │ Production VPN     │
    │ (Mock Data)       │         │ Server             │
    │ cmd/dev-api       │         │ cmd/server         │
    └───────────────────┘         └────────────────────┘
```

## Key Features

### ✅ Implemented
- ✅ **Complete Configuration System** - Enhanced OpenVPN config parser with 80+ new parameters
- ✅ **Authentication System** - Local, MFA, LDAP, OIDC with standard libraries
- ✅ **Traffic Obfuscation** - 8 methods with anti-detection and regional profiles
- ✅ **OpenVPN Compatibility** - Protocol and configuration support
- ✅ **Modern Cryptography** - TLSv1.3, AES-GCM, ChaCha20-Poly1305
- ✅ **REST API** - Complete server management interface
- ✅ **Certificate Management** - Full PKI support
- ✅ **Web Interface** - Modern React-based administrative panel

### 🚧 In Development
- 🚧 PostgreSQL integration for enterprise deployments
- 🚧 Clustering and high availability
- 🚧 Prometheus monitoring integration
- 🚧 Advanced user provisioning

## Requirements

- **Go 1.24.2 or higher**
- **Node.js 18+ and npm** (for web interface development)
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

# Build development API server
go build -o govpn-dev-api ./cmd/dev-api
```

### Web Interface Development

```bash
# Start development environment (API + Web)
./scripts/dev-start.sh

# Or manually:
# 1. Start development API server
./govpn-dev-api -port 8080 -host 127.0.0.1

# 2. Start web interface
cd web && npm install && npm run dev
```

### Basic VPN Server Usage

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
│   ├── client/             # Client application
│   └── dev-api/            # Development API server with mock data
├── pkg/                    # Library code
│   ├── auth/               # 🔐 Complete authentication system
│   ├── compat/             # 🔧 OpenVPN configuration compatibility
│   ├── obfuscation/        # 🎭 Traffic obfuscation system
│   ├── core/               # VPN core with protocol compatibility
│   ├── api/                # REST API with auth endpoints
│   └── monitoring/         # Metrics and monitoring
├── web/                    # 🌐 React web interface
│   ├── src/pages/          # Application pages (Dashboard, Users, etc.)
│   ├── src/components/     # Reusable React components
│   ├── src/services/       # API client with TypeScript
│   └── src/locales/        # Internationalization (en/ru)
├── scripts/                # 🚀 Development and deployment scripts
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

# Start development web interface
./scripts/dev-start.sh
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

- **[Web Interface Guide](web/README.md)** - Frontend development guide:
  - React + TypeScript architecture
  - API integration patterns
  - Internationalization setup
  - Development environment

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
3. Try the web interface: `./scripts/dev-start.sh`
4. Follow security best practices documented in configuration files
5. Ensure tests pass: `make check-all`
6. Update documentation for new features

### Areas for Contribution

- 🔐 Authentication providers (SAML, custom OAuth2)
- 🎭 New obfuscation methods  
- 🌐 Web interface enhancements
- 📊 Monitoring and metrics
- 🐳 Container and Kubernetes support
- 📚 Documentation improvements
- 🔧 Configuration system enhancements

## License

GoVPN is distributed under the [MIT](./LICENSE) license. 

---

**🚀 Ready to get started?** 

- **Quick setup**: Copy configuration files from [deploy/](deploy/) folder
- **Web interface**: Run `./scripts/dev-start.sh` to start development environment
- **Enterprise setup**: Read [deploy/README.md](deploy/README.md) for LDAP/OIDC integration
- **Anti-censorship**: Configure traffic obfuscation with [deploy/obfuscation.conf](deploy/obfuscation.conf)
- **Full demo**: Run `cd examples && go run obfuscation_demo.go` to see everything in action! 

## Storage

The storage package provides a flexible and extensible data persistence layer for GoVPN. It implements a clean interface that can be backed by different storage engines.

### Features

- Clean interface design with clear separation of concerns
- PostgreSQL implementation with connection pooling
- Support for transactions
- Database migrations
- Optimized queries with proper indexing
- Comprehensive test coverage

### Data Models

#### User
- ID
- Username
- Email
- Password (hashed)
- Role
- Status
- Last login time
- Created/Updated timestamps

#### Certificate
- ID
- Type (CA, server, client)
- Common Name
- Serial number
- Validity period
- Revocation status
- Revocation reason
- Created/Updated timestamps

#### Connection
- ID
- Client ID
- Username
- IP Address
- Virtual IP
- Traffic statistics
- Connection time
- Last activity
- Obfuscation method
- Protocol
- Client version

### Operations

The storage interface supports the following operations:

#### User Management
- Create user
- Get user by ID and username
- Update user
- Delete user
- List users with pagination
- Count total users

#### Certificate Management
- Create certificate
- Get certificate by ID and serial number
- Update certificate
- Revoke certificate with reason
- List certificates by type with pagination
- Count certificates by type

#### Connection Management
- Create connection record
- Get connection info
- Update connection
- Delete connection
- List active connections with pagination
- Count active connections
- Update connection statistics

### Usage

```go
// Create a new PostgreSQL storage instance
config := storage.Config{
    Host:     "localhost",
    Port:     5432,
    User:     "govpn",
    Password: "secret",
    Database: "govpn",
    SSLMode:  "disable",
    MaxConns: 10,
    MinConns: 2,
}

store, err := postgres.New(config)
if err != nil {
    log.Fatal(err)
}

// Use the storage interface
ctx := context.Background()
user := &storage.User{
    Username: "john",
    Email:    "john@example.com",
    Role:     "user",
}

err = store.CreateUser(ctx, user)
``` 