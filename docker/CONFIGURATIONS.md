# Docker Configurations

This directory contains various Docker configurations for GoVPN project.

## Available Configurations

### `docker-compose.yml` - Full Infrastructure
Complete production-ready setup including:
- GoVPN Server with OIDC authentication
- Keycloak OIDC provider
- PostgreSQL database
- Prometheus monitoring
- Grafana dashboards
- Nginx reverse proxy

**Usage:**
```bash
cd docker
docker-compose up -d
```

**Services:**
- GoVPN Server: `https://localhost:1194` (VPN), `http://localhost:8081` (API)
- Keycloak: `http://localhost:8080`
- Grafana: `http://localhost:3000` (admin/admin123)
- Prometheus: `http://localhost:9091`

### `docker-compose.full.yml` - GoVPN Server with Web UI
Standalone GoVPN server with web interface and mock API fallback:
- Real GoVPN Server (no OIDC)
- Web Dashboard
- Mock API (fallback)

**Usage:**
```bash
cd docker
docker-compose -f docker-compose.full.yml up -d
```

**Services:**
- GoVPN Server: `udp://localhost:1194` (VPN), `http://localhost:8081` (API)
- Web Dashboard: `http://localhost:3000`
- Mock API: `http://localhost:8080`

### `docker-compose.demo.yml` - Demo Version
Lightweight demo with mock API for development:
- Mock GoVPN API server
- Web Dashboard (connected to mock API)

**Usage:**
```bash
cd docker
docker-compose -f docker-compose.demo.yml up -d
```

**Services:**
- Mock API: `http://localhost:8080`
- Web Dashboard: `http://localhost:3000`

### `docker-compose.test.yml` - Testing Configuration
Testing environment with simplified configuration:
- GoVPN Server (testing mode)
- Web interface

**Usage:**
```bash
cd docker
docker-compose -f docker-compose.test.yml up -d
```

**Services:**
- GoVPN Server: `udp://localhost:1194` (VPN), `http://localhost:8080` (API)
- Web Dashboard: `http://localhost:3000`

## Quick Start

### For Development
```bash
# Demo with mock API
cd docker && docker-compose -f docker-compose.demo.yml up -d
```

### For Testing Real VPN
```bash
# Real GoVPN server
cd docker && docker-compose -f docker-compose.full.yml up -d
```

### For Production
```bash
# Full infrastructure
cd docker && docker-compose up -d
```

## From Project Root

You can also run the main configuration from project root:
```bash
# Uses docker/docker-compose.full.yml by default
docker-compose up -d
```

## Port Reference

| Service | Demo | Full | Test | Production |
|---------|------|------|------|------------|
| VPN Server | - | 1194/udp | 1194/udp | 1194/udp |
| GoVPN API | - | 8081/tcp | 8080/tcp | 8081/tcp |
| Mock API | 8080/tcp | 8080/tcp | - | - |
| Web Dashboard | 3000/tcp | 3000/tcp | 3000/tcp | - |
| Keycloak | - | - | - | 8080/tcp |
| Grafana | - | - | - | 3000/tcp |
| Prometheus | - | - | - | 9091/tcp |
| Nginx | - | - | - | 80/443/tcp |

## Data Persistence

All configurations use Docker volumes for data persistence:
- `govpn_*_data` - GoVPN server data
- `govpn_*_logs` - Log files
- `govpn_*_certs` - Certificates
- `postgres_data` - PostgreSQL data (production only)
- `prometheus_data` - Prometheus metrics (production only)
- `grafana_data` - Grafana dashboards (production only) 