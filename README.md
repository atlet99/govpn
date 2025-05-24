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

- Core VPN engine with OpenVPN protocol compatibility
- Support for classic OpenVPN configuration formats
- Modern cryptography with AES-GCM and ChaCha20-Poly1305
- TLSv1.3 support with secure ciphers
- Certificate management and PKI
- **Advanced Traffic Obfuscation System** with multiple methods:
  - TLS Tunneling for HTTPS-like traffic
  - HTTP Mimicry for web request simulation
  - HTTP Steganography for hiding data within HTTP traffic
  - DNS Tunneling for emergency backup communication
  - Packet Padding for size randomization
  - Timing Obfuscation for temporal pattern masking
  - Traffic Padding for volume pattern masking
  - **Flow Watermarking** for statistical characteristic distortion
- Regional profiles optimized for different countries
- DPI detection and automatic method switching
- REST API for server management
- Robust command-line interface

Stay tuned for upcoming features!

## Roadmap

See [IDEA.md](./IDEA.md) for a detailed roadmap and development plan.

## Key Features (planned)

- Compatibility with OpenVPN protocol and existing clients
- Improved performance with Go
- Modern authentication (OIDC, LDAP, MFA)
- Hybrid data storage (PostgreSQL + file system)
- REST API and CLI for management
- Web interface for administration
- Scalability and clustering
- Prometheus monitoring and metrics

## Requirements

- Go 1.22 or higher
- (Optional) PostgreSQL 15 or higher

## Installation

*Coming soon*

## REST API

GoVPN provides a comprehensive REST API for managing the server. To enable it, use the `-api` flag when starting the server:

```bash
./govpn-server -api -api-port 8080 -api-listen 127.0.0.1
```

### API Endpoints

The API is available at `http://<api-listen>:<api-port>/api/v1/` and includes the following endpoints:

- **GET /status** - Get server status information
- **GET /clients** - List all connected clients
- **GET /clients/:id** - Get details for a specific client
- **DELETE /clients/:id** - Disconnect a client
- **GET /certificates** - List all certificates
- **GET /certificates/:id** - Get certificate details
- **POST /certificates** - Create a new certificate
- **POST /certificates/revoke/:id** - Revoke a certificate
- **DELETE /certificates/:id** - Delete a certificate
- **GET /config** - Get server configuration
- **POST /config/update** - Update server configuration
- **GET /users** - List all users
- **GET /users/:id** - Get user details
- **PUT /users/:id** - Create a new user
- **POST /users/:id** - Update a user
- **DELETE /users/:id** - Delete a user

### Authentication

API authentication can be enabled with the `-api-auth` flag, requiring a JWT token for requests:

```bash
./govpn-server -api -api-auth -api-auth-secret "your-secret-key"
```

### Example Usage

```bash
# Get server status
curl http://127.0.0.1:8080/api/v1/status

# List all connected clients
curl http://127.0.0.1:8080/api/v1/clients

# Disconnect a specific client
curl -X DELETE http://127.0.0.1:8080/api/v1/clients/client1
```

## Development

### Project Structure

```
govpn/
├── cmd/                # Executable applications
│   ├── server/         # VPN server with OpenVPN compatibility
│   └── client/         # Client application with OpenVPN config support
├── pkg/                # Library code
│   ├── core/           # VPN core with protocol compatibility
│   ├── compat/         # OpenVPN compatibility layer
│   ├── api/            # REST API as an addition to classic management
│   ├── auth/           # Support for various authentication methods
│   ├── storage/        # Hybrid data storage
│   └── monitoring/     # Metrics and monitoring
├── web/                # Web interface
├── deploy/             # Configuration for various deployment types
└── docs/               # Documentation, including migration from OpenVPN
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/atlet99/govpn.git
cd govpn

# Build the server
go build -o govpn-server ./cmd/server

# Build the client
go build -o govpn-client ./cmd/client
```

## Contributing

The project is open for contributors. Please familiarize yourself with the contribution guidelines before submitting PRs.

## License

GoVPN is distributed under the [MIT](./LICENSE) license. 