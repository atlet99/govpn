#!/bin/sh
set -e

CERT_DIR="/etc/govpn/certs"
CONFIG_DIR="/etc/govpn"
OUTPUT_DIR="/var/lib/govpn"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

log "Generating OIDC client configuration..."

# Generate basic client configuration with OIDC support
cat > "$OUTPUT_DIR/oidc-client.ovpn" << EOF
# GoVPN Client Configuration with OIDC Authentication
# Generated at $(date)

client
dev tun
proto udp
remote localhost 1194
resolv-retry infinite
nobind
persist-key
persist-tun

# Security settings
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
verb 3

# OIDC Authentication - no client certificates needed
auth-user-pass
auth-retry interact

# Server verification (CA certificate only)
ca [inline]

# Optional: TLS-auth for additional security
tls-auth [inline] 1

# Connection settings
keepalive 10 120
compress lz4

# DNS settings
dhcp-option DNS 8.8.8.8
dhcp-option DNS 8.8.4.4

# OIDC specific settings
setenv OIDC_ENABLED true
setenv OIDC_PROVIDER_URL http://localhost:8080/realms/govpn
setenv OIDC_CLIENT_ID govpn-client
setenv OIDC_REDIRECT_URL http://localhost:8081/auth/callback

<ca>
$(cat $CERT_DIR/ca.crt)
</ca>

<tls-auth>
$(cat $CERT_DIR/ta.key)
</tls-auth>
EOF

# Generate simplified client config for testing
cat > "$OUTPUT_DIR/oidc-client-simple.ovpn" << EOF
# Simplified GoVPN OIDC Client Configuration
client
dev tun
proto udp
remote localhost 1194
nobind
persist-key
persist-tun
auth-user-pass
cipher AES-256-GCM
auth SHA256
verb 3

ca [inline]

<ca>
$(cat $CERT_DIR/ca.crt)
</ca>
EOF

# Create client credentials file for automated testing
cat > "$OUTPUT_DIR/client-auth.txt" << EOF
testuser
password123
EOF

# Create Tunnelblick-specific configuration
cat > "$OUTPUT_DIR/tunnelblick-oidc.ovpn" << EOF
# Tunnelblick OIDC Configuration for GoVPN
# Import this file into Tunnelblick

client
dev tun
proto udp
remote localhost 1194
port 1194
resolv-retry infinite
nobind
persist-key
persist-tun

# Authentication via username/password (OIDC flow)
auth-user-pass

# Security
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
remote-cert-tls server

# Tunnelblick specific settings
block-outside-dns
route-metric 1

# DNS settings
dhcp-option DNS 8.8.8.8
dhcp-option DNS 1.1.1.1

# Logging
verb 3
mute 10

# Server CA certificate
ca [inline]

<ca>
$(cat $CERT_DIR/ca.crt)
</ca>
EOF

# Set proper permissions
chmod 644 "$OUTPUT_DIR"/*.ovpn
chmod 600 "$OUTPUT_DIR/client-auth.txt"

log "OIDC client configurations created:"
log "- Full OIDC config: $OUTPUT_DIR/oidc-client.ovpn"
log "- Simple config: $OUTPUT_DIR/oidc-client-simple.ovpn" 
log "- Tunnelblick config: $OUTPUT_DIR/tunnelblick-oidc.ovpn"
log "- Test credentials: $OUTPUT_DIR/client-auth.txt"

log "Usage instructions:"
log "1. Start the Docker environment: docker-compose up -d"
log "2. Import tunnelblick-oidc.ovpn into Tunnelblick"
log "3. Connect using testuser/password123"
log "4. OIDC authentication will be handled automatically" 