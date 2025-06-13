#!/bin/bash

# GoVPN Client Connection Script
set -euo pipefail

CLIENT_CONFIG="/etc/govpn/client/client.ovpn"
CLIENT_DIR="/etc/govpn/client"
LOG_FILE="/var/log/govpn/client.log"
PID_FILE="/var/run/govpn-client.pid"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [CLIENT] $1" | tee -a "$LOG_FILE"
}

# Error handler
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Check if running as root (required for TUN device)
if [ "$(id -u)" -ne 0 ]; then
    error_exit "This script must be run as root"
fi

# Ensure TUN device is available
if [ ! -c /dev/net/tun ]; then
    error_exit "/dev/net/tun device not available. Please run with --cap-add NET_ADMIN --device /dev/net/tun"
fi

# Auth file not needed - using certificate authentication only

# Check configuration file
if [ ! -f "$CLIENT_CONFIG" ]; then
    error_exit "Client configuration file not found: $CLIENT_CONFIG"
fi

# Check certificates
for cert_file in ca.crt client.crt client.key; do
    if [ ! -f "$CLIENT_DIR/$cert_file" ]; then
        error_exit "Certificate file not found: $CLIENT_DIR/$cert_file"
    fi
done

log "Starting GoVPN client..."
log "Configuration: $CLIENT_CONFIG"
log "Connecting to server..."

# Start OpenVPN client with absolute paths and error handling
openvpn \
    --config "$CLIENT_CONFIG" \
    --writepid "$PID_FILE" \
    --log-append "$LOG_FILE" \
    --verb 4 \
    --script-security 2 || {
    EXIT_CODE=$?
    log "OpenVPN exited with code: $EXIT_CODE"
    log "Last few lines from log file:"
    tail -5 "$LOG_FILE" 2>/dev/null | while read line; do
        log "LOG: $line"
    done
    exit $EXIT_CODE
} 