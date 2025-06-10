#!/bin/sh
set -e

echo "Starting GoVPN Server..."

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Check required files
check_files() {
    log "Checking required files..."
    
    # Check all required certificates
    REQUIRED_CERTS="ca.crt server.crt server.key dh2048.pem"
    MISSING_CERTS=""
    
    for cert in $REQUIRED_CERTS; do
        if [ ! -f "/etc/govpn/certs/$cert" ]; then
            MISSING_CERTS="$MISSING_CERTS $cert"
        fi
    done
    
    if [ -n "$MISSING_CERTS" ]; then
        log "Missing certificates:$MISSING_CERTS"
        log "Generating self-signed certificates..."
        /usr/local/bin/generate-certs.sh
        
        # Verify generation was successful
        for cert in $REQUIRED_CERTS; do
            if [ ! -f "/etc/govpn/certs/$cert" ]; then
                log "ERROR: Failed to generate certificate: $cert"
                exit 1
            fi
        done
        log "All certificates generated successfully"
    fi
    
    # Check configuration
    if [ ! -f "${GOVPN_CONFIG:-/etc/govpn/server.conf}" ]; then
        log "WARNING: Default server configuration not found, will create runtime configuration"
    fi
    
    log "All required files are present"
}

# Clean up any existing TUN interfaces
cleanup_interfaces() {
    log "Cleaning up existing TUN interfaces..."
    
    # Remove any existing tun0 interface
    if ip link show tun0 >/dev/null 2>&1; then
        log "Removing existing tun0 interface..."
        ip link delete tun0 2>/dev/null || true
    fi
    
    log "Interface cleanup complete"
}

# Ensure TUN/TAP support is available
setup_tun() {
    log "Checking TUN/TAP support..."
    
    # Clean up first
    cleanup_interfaces
    
    # Ensure /dev/net/tun exists for TUN/TAP support
    if [ ! -c /dev/net/tun ]; then
        log "Creating /dev/net/tun device node..."
        mkdir -p /dev/net
        mknod /dev/net/tun c 10 200
        chmod 600 /dev/net/tun
    fi
    
    log "TUN/TAP support ready (Go code will create actual interface)"
}

# Network setup
setup_network() {
    log "Setting up network..."
    
    # Enable IP forwarding
    if [ -w /proc/sys/net/ipv4/ip_forward ]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward
        log "IP forwarding enabled"
    else
        log "WARNING: Cannot enable IP forwarding - check container privileges"
    fi
    
    # Setup iptables rules
    if command -v iptables >/dev/null 2>&1; then
        iptables -t nat -A POSTROUTING -s ${VPN_NETWORK:-10.8.0.0/24} -o eth0 -j MASQUERADE || log "WARNING: Failed to add NAT rule"
        iptables -A FORWARD -i tun0 -j ACCEPT || log "WARNING: Failed to add forward rule"
        iptables -A FORWARD -o tun0 -j ACCEPT || log "WARNING: Failed to add forward rule"
        log "iptables rules configured"
    else
        log "WARNING: iptables not available"
    fi
    
    log "Network setup complete"
}

# Wait for Keycloak readiness
wait_for_keycloak() {
    if [ "${OIDC_ENABLED}" = "true" ]; then
        log "Waiting for Keycloak to be ready..."
        
        KEYCLOAK_URL=$(echo ${OIDC_PROVIDER_URL} | sed 's|/realms/.*||')
        
        for i in $(seq 1 60); do
            if curl -s -f "${KEYCLOAK_URL}/health" > /dev/null 2>&1; then
                log "Keycloak is ready"
                break
            fi
            
            log "Waiting for Keycloak... (attempt $i/60)"
            sleep 5
        done
        
        if [ $i -eq 60 ]; then
            log "ERROR: Keycloak not ready after 5 minutes"
            exit 1
        fi
    fi
}

# Create configuration file
create_config() {
    log "Creating configuration file..."
    
    cat > /etc/govpn/runtime.conf << EOF
# GoVPN Runtime Configuration
# Generated at $(date)

# Basic settings
port ${VPN_PORT:-1194}
proto udp
dev tun
server ${VPN_NETWORK:-10.8.0.0/24}

# API settings
api-enabled true
api-port ${API_PORT:-8081}
api-address 0.0.0.0

# Metrics settings
metrics-enabled true
metrics-port ${METRICS_PORT:-9090}
metrics-address 0.0.0.0

# Certificates
ca /etc/govpn/certs/ca.crt
cert /etc/govpn/certs/server.crt
key /etc/govpn/certs/server.key
dh /etc/govpn/certs/dh2048.pem

# Security
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2

# Logging
log-file ${GOVPN_LOG_FILE:-/var/log/govpn/server.log}
log-level ${GOVPN_LOG_LEVEL:-info}
verb 4

# Connection settings
keepalive 10 120
max-clients 100
topology subnet
persist-key
persist-tun

# OIDC Configuration
EOF

    if [ "${OIDC_ENABLED}" = "true" ]; then
        cat >> /etc/govpn/runtime.conf << EOF

# OIDC Authentication
oidc-enabled true
oidc-provider-url ${OIDC_PROVIDER_URL}
oidc-client-id ${OIDC_CLIENT_ID}
oidc-client-secret ${OIDC_CLIENT_SECRET}
oidc-redirect-url ${OIDC_REDIRECT_URL}
oidc-scopes openid,profile,email
oidc-session-timeout 86400
oidc-claim-username preferred_username
oidc-claim-email email
oidc-cache-enabled true
oidc-cache-timeout 300
EOF
    fi
    
    log "Configuration file created"
}

# Main function
main() {
    log "GoVPN Server starting up..."
    log "Version: $(/usr/local/bin/govpn-server --version 2>/dev/null || echo 'unknown')"
    log "Build: $(/usr/local/bin/govpn-server --build-info 2>/dev/null || echo 'unknown')"
    
    # Checks and setup
    check_files
    setup_tun
    setup_network
    wait_for_keycloak
    create_config
    
    log "Starting GoVPN server..."
    log "Configuration: /etc/govpn/runtime.conf"
    log "VPN Network: ${VPN_NETWORK:-10.8.0.0/24}"
    log "VPN Port: ${VPN_PORT:-1194}"
    log "API Port: ${API_PORT:-8081}"
    log "Metrics Port: ${METRICS_PORT:-9090}"
    
    if [ "${OIDC_ENABLED}" = "true" ]; then
        log "OIDC Authentication: enabled"
        log "OIDC Provider: ${OIDC_PROVIDER_URL}"
    else
        log "OIDC Authentication: disabled"
    fi
    
    # Start server
    exec /usr/local/bin/govpn-server --config /etc/govpn/runtime.conf
}

# Signal handling
cleanup_on_exit() {
    log "Received shutdown signal, stopping..."
    if [ ! -z "$PID" ]; then
        kill -TERM $PID 2>/dev/null || true
        wait $PID 2>/dev/null || true
    fi
    cleanup_interfaces
    exit 0
}

trap cleanup_on_exit TERM INT

# Start
main "$@" &
PID=$!
wait $PID 