#!/bin/sh
set -e

CERT_DIR="/etc/govpn/certs"
CA_CN="GoVPN Test CA"
SERVER_CN="govpn-server"
KEY_SIZE=2048
DAYS=365

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Create certificate directory
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

log "Generating self-signed certificates for GoVPN..."

# Generate CA private key
log "Generating CA private key..."
openssl genrsa -out ca.key $KEY_SIZE

# Generate CA certificate
log "Generating CA certificate..."
openssl req -new -x509 -days $DAYS -key ca.key -out ca.crt -subj "/CN=$CA_CN"

# Generate server private key
log "Generating server private key..."
openssl genrsa -out server.key $KEY_SIZE

# Generate server certificate request
log "Generating server certificate request..."
openssl req -new -key server.key -out server.csr -subj "/CN=$SERVER_CN"

# Create server certificate configuration file
log "Creating server certificate configuration..."
cat > server.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = govpn-server
DNS.3 = *.local
IP.1 = 127.0.0.1
IP.2 = 10.8.0.1
IP.3 = 172.20.0.0/16
EOF

# Sign server certificate with CA
log "Signing server certificate with CA..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days $DAYS -extensions v3_req -extfile server.conf

# Generate Diffie-Hellman parameters
log "Generating Diffie-Hellman parameters..."
openssl dhparam -out dh2048.pem 2048

# Generate TLS-auth key (ta.key equivalent)
log "Generating TLS-auth key..."
openssl rand -base64 256 > ta.key

# Create client private key
log "Generating client private key..."
openssl genrsa -out client.key $KEY_SIZE

# Generate client certificate request
log "Generating client certificate request..."
openssl req -new -key client.key -out client.csr -subj "/CN=govpn-client"

# Sign client certificate with CA
log "Signing client certificate with CA..."
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days $DAYS

# Set proper permissions
log "Setting proper permissions..."
chmod 600 *.key
chmod 644 *.crt *.pem ta.key

# Clean up temporary files
log "Cleaning up temporary files..."
rm -f *.csr *.conf *.srl

# Create client bundle file
log "Creating client bundle..."
cat > client-bundle.ovpn << EOF
client
dev tun
proto udp
remote localhost 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca [inline]
cert [inline]
key [inline]
tls-auth [inline] 1
cipher AES-256-GCM
auth SHA256
verb 3

<ca>
$(cat ca.crt)
</ca>

<cert>
$(cat client.crt)
</cert>

<key>
$(cat client.key)
</key>

<tls-auth>
$(cat ta.key)
</tls-auth>
EOF

log "Certificate generation completed!"
log "Files created in $CERT_DIR:"
ls -la "$CERT_DIR"

log "Client configuration created: $CERT_DIR/client-bundle.ovpn"
log "This file can be used with OpenVPN clients like Tunnelblick" 