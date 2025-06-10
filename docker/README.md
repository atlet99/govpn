# GoVPN Docker Test Environment

Complete Docker environment for testing GoVPN server with OIDC authentication via Keycloak.

## Components

- **GoVPN Server** - main VPN server with OIDC support
- **Keycloak** - OpenID Connect provider for authentication
- **PostgreSQL** - database for Keycloak
- **Prometheus** - performance metrics collection
- **Grafana** - metrics visualization
- **Nginx** - reverse proxy (optional)

## Quick Start

### Requirements

- Docker and Docker Compose
- Minimum 4GB RAM
- TUN device creation permissions

### 1. Build and Run

```bash
# Navigate to docker directory
cd docker

# Build and start all services
docker-compose up -d

# Check services status
docker-compose ps

# View logs
docker-compose logs -f govpn-server
```

### 2. Initial Setup

#### Keycloak Configuration

1. Open Keycloak Admin Console: http://localhost:8080
2. Login with credentials:
   - **Username**: admin
   - **Password**: admin123

3. The "govpn" realm will be automatically imported with pre-configured settings

#### Test Users

Automatically created users:

- **testuser** / password123 - regular VPN user
- **admin** / admin123 - VPN administrator

### 3. Generate Client Certificates

```bash
# Generate client certificates
docker exec -it govpn-server /usr/local/bin/generate-certs.sh

# Copy client configuration
docker cp govpn-server:/etc/govpn/certs/client-bundle.ovpn ./client-bundle.ovpn
```

## Client Connections

### Tunnelblick (macOS)

1. Download `client-bundle.ovpn` file
2. Open file in Tunnelblick
3. Enter credentials when prompted:
   - Server: localhost:1194
   - Username: testuser
   - Password: password123

### OpenVPN Connect

1. Import `client-bundle.ovpn` file
2. On first connection, you'll be redirected to Keycloak for authentication
3. After successful authentication, VPN connection will be established

### Console OpenVPN Client

```bash
# Install OpenVPN client
# Ubuntu/Debian:
sudo apt install openvpn

# macOS:
brew install openvpn

# Connect
sudo openvpn --config client-bundle.ovpn
```

## Services and Ports

| Service | Port | Description |
|---------|------|-------------|
| GoVPN Server | 1194/udp | VPN connections |
| GoVPN API | 8081/tcp | REST API management |
| GoVPN Metrics | 9090/tcp | Prometheus metrics |
| Keycloak | 8080/tcp | OIDC provider |
| Prometheus | 9091/tcp | Metrics collection |
| Grafana | 3000/tcp | Dashboards |
| Nginx | 80/tcp, 443/tcp | Proxy (optional) |

## Monitoring

### Prometheus Metrics

Available at: http://localhost:9091

Key metrics:
- Number of connected clients
- VPN tunnel traffic
- Authentication performance
- System status

### Grafana Dashboards

Available at: http://localhost:3000
- **Username**: admin
- **Password**: admin123

Pre-installed dashboards:
- GoVPN Server Overview
- OIDC Authentication Metrics
- System Performance

### GoVPN API

API Documentation: http://localhost:8081/swagger

Main endpoints:
- `GET /health` - server status
- `GET /stats` - connection statistics
- `GET /clients` - list of active clients
- `POST /clients/{id}/disconnect` - disconnect client

## Configuration

### Environment Variables

Main variables for GoVPN configuration:

```yaml
# OIDC settings
OIDC_ENABLED: "true"
OIDC_PROVIDER_URL: "http://keycloak:8080/realms/govpn"
OIDC_CLIENT_ID: "govpn-client" 
OIDC_CLIENT_SECRET: "govpn-client-secret-12345"

# Network settings
VPN_NETWORK: "10.8.0.0/24"
VPN_PORT: "1194"
API_PORT: "8081"
METRICS_PORT: "9090"
```

### Configuration Customization

1. Modify files in `docker/configs/`
2. Restart container:

```bash
docker-compose restart govpn-server
```

## Security

### Production Settings

**IMPORTANT**: This configuration is for testing only!

For production use:

1. Change all passwords and secrets
2. Enable HTTPS for all web interfaces
3. Use external databases
4. Configure firewalls and network segmentation
5. Enable audit logging

### Certificates

Self-signed certificates are used by default. For production:

1. Use certificates from trusted CA
2. Configure automatic certificate renewal
3. Use HSM for key storage

## OIDC Testing

### Authentication Check

```bash
# Test OIDC discovery
curl -s http://localhost:8080/realms/govpn/.well-known/openid_configuration | jq

# Test GoVPN API
curl -s http://localhost:8081/health | jq

# Check metrics
curl -s http://localhost:9090/metrics | grep govpn
```

### Test Scenarios

1. **Successful authentication**:
   - Connect with testuser/password123
   - Verify VPN tunnel creation

2. **Access denial**:
   - Attempt connection with invalid credentials
   - Verify access blocking

3. **Session timeout**:
   - Long-term connection
   - Verify automatic reconnection

## Troubleshooting

### Log Checking

```bash
# GoVPN server logs
docker-compose logs -f govpn-server

# Keycloak logs
docker-compose logs -f keycloak

# All services logs
docker-compose logs -f
```

### Common Issues

1. **TUN device error**:
   ```bash
   # Create TUN device on host
   sudo modprobe tun
   ```

2. **Permission issues**:
   ```bash
   # Run with privileged rights
   docker-compose run --privileged govpn-server
   ```

3. **Network conflicts**:
   - Check conflicts with local networks
   - Change VPN_NETWORK in docker-compose.yml

### Debugging

```bash
# Enter GoVPN container
docker exec -it govpn-server sh

# Check network interfaces
ip addr show

# Check iptables rules
iptables -L -n -v

# Test Keycloak connection
curl -v http://keycloak:8080/health
```

## Development and Contributing

### Project Structure

```
docker/
├── Dockerfile              # GoVPN server image
├── docker-compose.yml      # Service orchestration
├── configs/                # Configuration files
├── scripts/                # Utilities and scripts
├── keycloak/               # Keycloak settings
├── monitoring/             # Monitoring configuration
└── README.md               # Documentation
```

### Adding New Features

1. Fork the repository
2. Create feature branch
3. Make changes
4. Test in Docker environment
5. Create Pull Request

## License

MIT License - see LICENSE file in repository root. 