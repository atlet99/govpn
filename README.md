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

**Phase 1**: **COMPLETED** - Basic functionality and OpenVPN compatibility  
**Phase 2**: **COMPLETED** - Configuration system, obfuscation, authentication, testing  
**Phase 3**: **COMPLETED** - Scaling, monitoring, and production readiness  
**Web Interface**: **COMPLETED** - Full-featured administrative panel

### Latest Achievements

#### Production-Ready Monitoring and Scaling (Phase 3)
- **Prometheus Metrics** - comprehensive metrics collection (40+ metric types)
- **Structured Logging** - JSON, Text, and OpenVPN-compatible formats with log rotation
- **Alert System** - automated notifications with customizable rules and cooldowns
- **Performance Monitoring** - system resources, goroutines, memory, and CPU tracking
- **Grafana Dashboards** - ready-to-use panels for all VPN server aspects
- **Kubernetes Deployment** - complete manifests with auto-scaling and load balancing
- **High Performance** - optimized monitoring with minimal overhead (555ns/op for metrics)
- **Production Documentation** - comprehensive guides for deployment and troubleshooting

#### Full-Featured Web Interface
- **React + TypeScript** - modern architecture with Material-UI design
- **Internationalization** - complete support for Russian and English languages
- **User Management** - CRUD operations with roles and statuses
- **Real-time Monitoring** - server statistics and connections
- **Certificate Management** - creation, viewing, revocation of certificates
- **Authentication System** - JWT tokens and secure sessions
- **Responsive Design** - optimization for all devices
- **API Client** - typed integration with backend
- **Development API Server** - mock API for interface development

#### Comprehensive Configuration System
- **Enhanced configuration parser** - support for 80+ new parameters with OpenVPN compatibility
- **Modular configuration files** - organized auth.conf, mfa.conf, oidc.conf, ldap.conf, obfuscation.conf
- **Priority system** - proper OpenVPN-like precedence (config file → command line → defaults)
- **8 ready-made configurations** - from basic to enterprise scenarios with detailed examples

#### Full Authentication System
- **Basic authentication** - modern hashing algorithms Argon2/PBKDF2
- **Multi-factor authentication** - complete TOTP/HOTP support with backup codes
- **LDAP integration** - support for Active Directory, OpenLDAP, FreeIPA, 389 Directory, Oracle Internet Directory
- **OIDC integration** - works with Keycloak, Google Workspace, Azure AD, Auth0, Okta, GitLab

#### Comprehensive Obfuscation System
- **Modular obfuscation system** with 9 methods (TLS Tunnel, HTTP Mimicry, DNS Tunnel, XOR, Obfsproxy, etc.)
- **OpenVPN obfsproxy compatibility** - Direct integration with OpenVPN obfsproxy plugins
- **Anti-statistical analysis** - Packet Padding, Timing Obfuscation, Traffic Padding, Flow Watermarking
- **Steganography methods** - HTTP Cover Traffic, DNS Tunneling
- **Regional profiles** for China, Iran, Russia with adaptive switching

## Web Interface

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

## Architecture

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

### Implemented
- **Complete Configuration System** - Enhanced OpenVPN config parser with 80+ new parameters
- **Authentication System** - Local, MFA, LDAP, OIDC with standard libraries
- **Traffic Obfuscation** - 9 methods with anti-detection and regional profiles
- **OpenVPN Compatibility** - Protocol and configuration support
- **Modern Cryptography** - TLSv1.3, AES-GCM, ChaCha20-Poly1305
- **REST API** - Complete server management interface
- **Certificate Management** - Full PKI support
- **Web Interface** - Modern React-based administrative panel
- **Production Monitoring** - Prometheus metrics, structured logging, Grafana dashboards
- **Kubernetes Deployment** - Complete manifests with auto-scaling and load balancing
- **Alert System** - Automated notifications with customizable rules and cooldowns
- **Performance Optimization** - High-performance monitoring (555ns/op for metrics)

### In Development
- PostgreSQL integration for enterprise deployments
- Clustering and high availability
- Advanced user provisioning

## Requirements

- **Go 1.24.2 or higher**
- **Node.js 18+ and npm** (for web interface development)
- (Optional) PostgreSQL 15 or higher for enterprise features
- Network access for LDAP/OIDC providers (if used)

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Go 1.21 or later (for building from source)
- Linux/macOS/Windows
- **For obfsproxy support**: obfsproxy or obfs4proxy installed

### Docker Quick Start (Recommended)

```bash
# Clone the repository
git clone https://github.com/atlet99/govpn.git
cd govpn

# For quick demo with mock API
docker-compose -f docker/docker-compose.demo.yml up -d

# For testing real VPN server
docker-compose up -d

# For production with full infrastructure
cd docker && docker-compose up -d
```

**Access services:**
- **Demo**: Web UI at http://localhost:3000, Mock API at http://localhost:8080
- **Real VPN**: VPN at udp://localhost:1194, API at http://localhost:8081, Web at http://localhost:3000
- **Production**: Full infrastructure with Keycloak, monitoring, etc.

See [Docker Configurations](docker/CONFIGURATIONS.md) for detailed information.

### Manual Installation

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

### Installation Check
```bash
# Check if obfsproxy is installed and working
./scripts/check_obfsproxy.sh

# Install obfsproxy if needed (macOS)
brew install obfs4proxy

# Install obfsproxy if needed (Ubuntu)
sudo apt-get install obfsproxy
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

# Start with monitoring enabled
./govpn-server -config deploy/server.conf -monitoring -metrics-port 9100
```

### Production Monitoring and Scaling

#### Kubernetes Deployment

```bash
# Deploy to Kubernetes cluster
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/deployment.yaml
kubectl apply -f deploy/kubernetes/service.yaml

# Check deployment status
kubectl get pods -n govpn
kubectl get services -n govpn
```

#### Monitoring Setup

```bash
# Run monitoring benchmarks
cd pkg/monitoring
go test -bench=. -benchmem

# Start server with monitoring
./govpn-server -config deploy/server.conf \
  -monitoring \
  -metrics-port 9100 \
  -log-format json
```

#### Grafana Dashboard Import

```bash
# Import ready-made Grafana dashboards
# 1. Access Grafana UI (default: http://localhost:3000)
# 2. Go to Dashboard > Import
# 3. Load from file: docs/monitoring/grafana-dashboard.json
# 4. Configure data source: Prometheus (http://localhost:9090)
```

### Certificates and PKI

Generate server and client certificates:

```bash
# Generate CA and server certificates
./scripts/generate_certs.sh

# Or use the built-in certificate generator
go run ./cmd/generate_certs -ca -server -client
```

### Configuration Examples

The project includes 8 ready-made configuration files in `deploy/` directory:

1. **basic.conf** - Minimal VPN server setup
2. **server.conf** - Standard server configuration with authentication
3. **auth.conf** - Authentication configuration (local users, passwords)
4. **mfa.conf** - Multi-factor authentication setup
5. **ldap.conf** - LDAP/Active Directory integration
6. **oidc.conf** - OpenID Connect provider integration
7. **obfuscation.conf** - Traffic obfuscation and anti-censorship
8. **monitoring.conf** - Comprehensive monitoring and logging setup

## Configuration

### Server Configuration

Basic server configuration file structure:

```conf
# Basic VPN server settings
port 1194
proto udp
dev tun

# Certificates and encryption
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
cipher AES-256-GCM

# Network settings
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

# Client configuration
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# Security
keepalive 10 120
comp-lzo
persist-key
persist-tun
status openvpn-status.log
verb 3
```

### Authentication Configuration

Configure various authentication methods:

```conf
# Local authentication with password file
auth-user-pass-verify /etc/govpn/auth.txt via-file

# LDAP authentication
ldap-enabled true
ldap-server ldap://your-ldap-server.com:389
ldap-bind-dn cn=admin,dc=example,dc=com
ldap-bind-password your-password
ldap-base-dn ou=users,dc=example,dc=com

# Multi-factor authentication
mfa-enabled true
mfa-issuer "GoVPN Server"
mfa-digits 6
mfa-period 30

# OIDC authentication
oidc-enabled true
oidc-issuer https://your-oidc-provider.com
oidc-client-id your-client-id
oidc-client-secret your-client-secret
```

### Obfuscation Configuration

Configure traffic obfuscation to bypass DPI:

```conf
# Enable obfuscation
obfuscation-enabled true

# XOR obfuscation
obfuscation-method xor
obfuscation-key mysecretkey123

# TLS tunnel obfuscation
obfuscation-method tls-tunnel
obfuscation-tls-host example.com

# HTTP mimicry
obfuscation-method http-mimicry
obfuscation-http-host www.google.com

# Obfsproxy integration
obfuscation-method obfsproxy
obfuscation-obfsproxy-transport obfs4
```

## API Reference

### Authentication

All API endpoints require JWT authentication. Obtain a token by posting credentials to `/api/v1/auth/login`.

```bash
# Login and get token
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'

# Use token in subsequent requests
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:8080/api/v1/status
```

### Endpoints

#### Server Status
```bash
GET /api/v1/status
```

Returns server status, uptime, and basic statistics.

#### User Management
```bash
# List all users
GET /api/v1/users

# Create new user
POST /api/v1/users
{
  "username": "john",
  "email": "john@example.com",
  "password": "securepassword",
  "role": "user"
}

# Get user details
GET /api/v1/users/{id}

# Update user
PATCH /api/v1/users/{id}
{
  "email": "newemail@example.com",
  "role": "admin"
}

# Delete user
DELETE /api/v1/users/{id}
```

#### Active Connections
```bash
GET /api/v1/clients
```

Returns list of currently connected VPN clients.

#### Certificate Management
```bash
# List certificates
GET /api/v1/certificates

# Generate new certificate
POST /api/v1/certificates
{
  "common_name": "client1",
  "email": "client1@example.com",
  "validity_days": 365
}

# Revoke certificate
DELETE /api/v1/certificates/{serial}
```

#### Configuration
```bash
# Get current configuration
GET /api/v1/config

# Update configuration
PUT /api/v1/config
{
  "port": 1194,
  "protocol": "udp",
  "cipher": "AES-256-GCM"
}
```

#### Logs
```bash
# Get recent logs
GET /api/v1/logs?limit=100&level=info
```

## Monitoring and Metrics

### Prometheus Metrics

GoVPN exposes comprehensive metrics for monitoring:

- **Connection metrics**: active connections, new connections per second, disconnections
- **Performance metrics**: CPU usage, memory consumption, goroutine count
- **Network metrics**: bytes transferred, packets processed, error rates
- **Authentication metrics**: login attempts, successful/failed authentications
- **Obfuscation metrics**: obfuscated packets, method distribution

Example metrics endpoint:
```bash
curl http://localhost:9100/metrics
```

### Grafana Integration

Import the provided Grafana dashboard for comprehensive monitoring:

1. Copy `docs/monitoring/grafana-dashboard.json`
2. Import in Grafana UI
3. Configure Prometheus data source
4. Monitor server performance, connections, and security events

### Log Formats

GoVPN supports multiple log formats:

```bash
# JSON format (structured logging)
./govpn-server -log-format json

# Text format (human-readable)
./govpn-server -log-format text

# OpenVPN compatible format
./govpn-server -log-format openvpn
```

## Testing

### Unit Tests

Run the complete test suite:

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run benchmarks
go test -bench=. ./pkg/monitoring/
```

### Integration Tests

Test with real VPN scenarios:

```bash
# Test authentication system
go test ./pkg/auth/... -v

# Test obfuscation methods
go test ./pkg/obfuscation/... -v

# Test monitoring and metrics
go test ./pkg/monitoring/... -bench=.
```

### Performance Tests

Benchmark critical components:

```bash
# Monitor performance benchmarks
cd pkg/monitoring
go test -bench=BenchmarkPerformanceMonitor -benchmem

# Obfuscation performance
cd pkg/obfuscation  
go test -bench=BenchmarkObfuscation -benchmem
```

## Production Deployment

### Docker Deployment

```bash
# Build Docker image
docker build -t govpn:latest .

# Run container
docker run -d \
  --name govpn-server \
  -p 1194:1194/udp \
  -p 8080:8080 \
  -v /path/to/config:/etc/govpn \
  -v /path/to/certs:/etc/govpn/certs \
  govpn:latest
```

### Systemd Service

Create systemd service file `/etc/systemd/system/govpn.service`:

```ini
[Unit]
Description=GoVPN Server
After=network.target

[Service]
Type=simple
User=govpn
WorkingDirectory=/opt/govpn
ExecStart=/opt/govpn/govpn-server -config /etc/govpn/server.conf
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl enable govpn
sudo systemctl start govpn
sudo systemctl status govpn
```

### Security Considerations

1. **Certificate Management**: Use strong RSA keys (minimum 2048-bit) or ECC curves
2. **Network Security**: Configure firewall rules, disable unnecessary services
3. **Authentication**: Enable MFA for administrative access
4. **Monitoring**: Set up alerts for failed authentication attempts and unusual traffic patterns
5. **Updates**: Keep the server and dependencies updated regularly

### Performance Tuning

1. **OS Tuning**: Increase file descriptor limits, optimize network buffers
2. **Go Runtime**: Set appropriate GOMAXPROCS, garbage collection targets
3. **Network**: Configure optimal MTU sizes, enable hardware offloading
4. **Monitoring**: Use lightweight monitoring configurations to minimize overhead

## Troubleshooting

### Common Issues

#### Connection Problems
```bash
# Check server status
./govpn-server -status

# Verify certificates
openssl x509 -in server.crt -text -noout

# Test network connectivity
nc -u server-ip 1194
```

#### Authentication Issues
```bash
# Check authentication logs
tail -f /var/log/govpn/auth.log

# Verify LDAP connectivity
ldapsearch -x -H ldap://your-ldap-server -D "cn=admin,dc=example,dc=com" -W

# Test OIDC configuration
curl https://your-oidc-provider/.well-known/openid_configuration
```

#### Performance Issues
```bash
# Monitor server performance
curl http://localhost:9100/metrics | grep govpn

# Check system resources
top -p $(pgrep govpn-server)

# Analyze connection patterns
./govpn-server -api -debug
curl http://localhost:8080/api/v1/clients
```

### Log Analysis

Enable detailed logging for troubleshooting:

```bash
# Enable debug logging
./govpn-server -config server.conf -log-level debug

# Monitor authentication events
tail -f /var/log/govpn/auth.log | grep "authentication"

# Track connection events
tail -f /var/log/govpn/server.log | grep "client"
```

## Contributing

### Development Setup

1. **Fork the repository**
2. **Clone your fork**:
   ```bash
   git clone https://github.com/your-username/govpn.git
   cd govpn
   ```
3. **Install dependencies**:
   ```bash
   go mod download
   cd web && npm install
   ```
4. **Run tests**:
   ```bash
   go test ./...
   cd web && npm test
   ```

### Code Standards

- **Go Code**: Follow Go conventions, use `gofmt`, `golint`, and `go vet`
- **Web Code**: Use ESLint and Prettier configurations
- **Comments**: Write clear, descriptive comments explaining the purpose
- **Tests**: Include unit tests for new functionality
- **Documentation**: Update relevant documentation for changes

### Pull Request Process

1. **Create feature branch**: `git checkout -b feature/your-feature-name`
2. **Make changes** with appropriate tests and documentation
3. **Run full test suite**: `make test`
4. **Submit pull request** with clear description of changes
5. **Address review feedback** if required

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: See `docs/` directory for detailed guides
- **Issues**: Report bugs and feature requests via GitHub Issues
- **Discussions**: Use GitHub Discussions for questions and community support

---

**GoVPN** - Modern OpenVPN implementation in Go with enhanced security, performance, and management capabilities. 