# GoVPN Testing Guide

This guide explains how to test the GoVPN server in a containerized environment.

## Quick Demo Setup

We have set up a demonstration environment with a mock API server and web dashboard to showcase the GoVPN functionality.

### 1. Start Demo Environment

```bash
docker-compose -f docker-compose.demo.yml up -d --build
```

This will start:
- **Mock API Server** on port 8080 (simulates GoVPN server API)
- **Web Dashboard** on port 3000 (React-based admin interface)

### 2. Access Services

#### Web Dashboard
Open your browser and navigate to: http://localhost:3000

The dashboard provides:
- Server status monitoring
- Connected clients list
- Configuration view
- Real-time statistics

#### API Endpoints
The mock API server responds to:

```bash
# Health check
curl http://localhost:8080/health

# Server status
curl http://localhost:8080/api/status

# Connected clients
curl http://localhost:8080/api/clients

# Server configuration
curl http://localhost:8080/api/config
```

### 3. API Testing Examples

```bash
# Test API directly
curl -s http://localhost:8080/api/status | jq

# Test API through web interface proxy
curl -s http://localhost:3000/api/status | jq

# View mock client connections
curl -s http://localhost:8080/api/clients | jq
```

## Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Browser   │───▶│  Web Dashboard   │───▶│   Mock API      │
│   (port 3000)   │    │    (nginx)       │    │  (port 8080)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Demo Features

The demonstration includes:

### Mock API Server
- **Status endpoint**: Shows server uptime and statistics
- **Clients endpoint**: Lists 3 mock connected clients
- **Config endpoint**: Displays server configuration
- **Health endpoint**: Service health check

### Web Dashboard
- **Real-time monitoring**: Server status updates
- **Client management**: View connected users
- **Configuration panel**: Server settings display
- **Responsive design**: Works on desktop and mobile

## Real VPN Server (Advanced)

For actual VPN functionality, you would need:

1. **TUN/TAP device support**
2. **Root privileges** for network configuration
3. **Real certificates** for secure connections
4. **Proper firewall rules**

The real server configuration would include:
```bash
# Run with full privileges
docker run --privileged \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -p 1194:1194/udp \
  -p 8080:8080/tcp \
  govpn-server
```

## VPN Client Configuration

A sample OpenVPN client configuration is provided in `vpn-client/client.ovpn`:

```
client
dev tun
proto udp
remote localhost 1194
cipher AES-256-GCM
auth SHA256
```

## Stopping the Demo

```bash
docker-compose -f docker-compose.demo.yml down
```

## Troubleshooting

### Common Issues

1. **Port conflicts**: Ensure ports 3000 and 8080 are free
2. **Docker not running**: Start Docker/OrbStack
3. **Permission errors**: Run with appropriate privileges

### Logs

```bash
# View API server logs
docker logs govpn-demo-api

# View web dashboard logs  
docker logs govpn-demo-web

# View all services
docker-compose -f docker-compose.demo.yml logs
```

## Security Notes

⚠️ **Important**: This is a demonstration setup only!

For production use:
- Enable proper authentication (OIDC/certificates)
- Use real TLS certificates
- Configure proper firewall rules
- Enable logging and monitoring
- Regular security updates

## Next Steps

1. **Explore the web interface** at http://localhost:3000
2. **Test API endpoints** using curl commands above
3. **Review the code** in `mock-api/` and `web/` directories
4. **Study Docker configurations** in `docker-compose.demo.yml` 