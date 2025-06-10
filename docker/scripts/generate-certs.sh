#!/bin/sh
set -e

CERT_DIR="/etc/govpn/certs"
CA_CN="GoVPN Test CA"
SERVER_CN="govpn-server"
KEY_SIZE=2048
DAYS=365

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] CERT-GEN: $1"
}

error_exit() {
    log "ERROR: $1"
    exit 1
}

# Create certificate directory
log "Setting up certificate directory: $CERT_DIR"
mkdir -p "$CERT_DIR" || error_exit "Failed to create certificate directory"
cd "$CERT_DIR" || error_exit "Failed to change to certificate directory"

log "Generating self-signed certificates for GoVPN..."

# Generate CA private key
log "Generating CA private key..."
openssl genrsa -out ca.key $KEY_SIZE || error_exit "Failed to generate CA private key"
[ -f ca.key ] || error_exit "CA private key file not created"

# Generate CA certificate
log "Generating CA certificate..."
openssl req -new -x509 -days $DAYS -key ca.key -out ca.crt -subj "/CN=$CA_CN" || error_exit "Failed to generate CA certificate"
[ -f ca.crt ] || error_exit "CA certificate file not created"

# Generate server private key
log "Generating server private key..."
openssl genrsa -out server.key $KEY_SIZE || error_exit "Failed to generate server private key"
[ -f server.key ] || error_exit "Server private key file not created"

# Generate server certificate request
log "Generating server certificate request..."
openssl req -new -key server.key -out server.csr -subj "/CN=$SERVER_CN" || error_exit "Failed to generate server certificate request"
[ -f server.csr ] || error_exit "Server certificate request file not created"

# Create server certificate configuration file
log "Creating server certificate configuration..."
cat > server.conf << EOF || error_exit "Failed to create server certificate configuration"
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
DNS.3 = govpn-real-server
DNS.4 = *.local
IP.1 = 127.0.0.1
IP.2 = 10.8.0.1
IP.3 = 172.22.0.2
EOF

# Sign server certificate with CA
log "Signing server certificate with CA..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days $DAYS -extensions v3_req -extfile server.conf || error_exit "Failed to sign server certificate"
[ -f server.crt ] || error_exit "Server certificate file not created"

# Generate Diffie-Hellman parameters
log "Generating Diffie-Hellman parameters..."
openssl dhparam -out dh2048.pem 2048 || error_exit "Failed to generate Diffie-Hellman parameters"
[ -f dh2048.pem ] || error_exit "Diffie-Hellman parameters file not created"

# Generate TLS-auth key (ta.key equivalent)
log "Generating TLS-auth key..."
openssl rand -base64 256 > ta.key || error_exit "Failed to generate TLS-auth key"
[ -f ta.key ] || error_exit "TLS-auth key file not created"

# Create client private key
log "Generating client private key..."
openssl genrsa -out client.key $KEY_SIZE || error_exit "Failed to generate client private key"
[ -f client.key ] || error_exit "Client private key file not created"

# Generate client certificate request
log "Generating client certificate request..."
openssl req -new -key client.key -out client.csr -subj "/CN=govpn-client" || error_exit "Failed to generate client certificate request"
[ -f client.csr ] || error_exit "Client certificate request file not created"

# Sign client certificate with CA
log "Signing client certificate with CA..."
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days $DAYS || error_exit "Failed to sign client certificate"
[ -f client.crt ] || error_exit "Client certificate file not created"

# Set proper permissions
log "Setting proper permissions..."
chmod 600 *.key || error_exit "Failed to set permissions on private keys"
chmod 644 *.crt *.pem ta.key || error_exit "Failed to set permissions on certificates"

# Clean up temporary files
log "Cleaning up temporary files..."
rm -f *.csr *.conf *.srl

# Create client bundle file
log "Creating client bundle..."
cat > client-bundle.ovpn << EOF || error_exit "Failed to create client bundle"
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

log "Certificate generation completed successfully!"
log "Files created in $CERT_DIR:"
ls -la "$CERT_DIR" || log "WARNING: Failed to list certificate directory"

log "Client configuration created: $CERT_DIR/client-bundle.ovpn"
log "This file can be used with OpenVPN clients like Tunnelblick"

# Final verification
REQUIRED_FILES="ca.crt server.crt server.key dh2048.pem ta.key client.crt client.key client-bundle.ovpn"
for file in $REQUIRED_FILES; do
    if [ ! -f "$file" ]; then
        error_exit "Required file missing after generation: $file"
    fi
done

log "All required files verified successfully" 