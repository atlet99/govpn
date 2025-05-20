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

The project is in early development (Phase 1). Stay tuned for updates!

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