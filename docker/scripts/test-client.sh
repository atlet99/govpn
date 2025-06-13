#!/bin/bash

# Simple test script to diagnose OpenVPN connection issues
set -euo pipefail

CLIENT_CONFIG="/etc/govpn/client/client.ovpn"
LOG_FILE="/var/log/govpn/test-client.log"

echo "=== GoVPN Client Test ==="
echo "Time: $(date)"
echo "Config: $CLIENT_CONFIG"
echo "Log file: $LOG_FILE"
echo ""

# Check configuration exists
if [ ! -f "$CLIENT_CONFIG" ]; then
    echo "ERROR: Configuration file not found: $CLIENT_CONFIG"
    exit 1
fi

# Check certificates
echo "Checking certificates..."
for cert_file in /etc/govpn/client/ca.crt /etc/govpn/client/client.crt /etc/govpn/client/client.key; do
    if [ ! -f "$cert_file" ]; then
        echo "ERROR: Certificate file not found: $cert_file"
        exit 1
    else
        echo "OK: $cert_file"
    fi
done

# Check network connectivity to server
echo ""
echo "Testing network connectivity..."
if ping -c 3 govpn-real-server; then
    echo "OK: Can reach govpn-real-server"
else
    echo "ERROR: Cannot reach govpn-real-server"
    exit 1
fi

# Test port connectivity
echo ""
echo "Testing port 1194..."
if nc -u -z govpn-real-server 1194; then
    echo "OK: Port 1194 is reachable"
else
    echo "WARNING: Port 1194 may not be reachable (this is normal for UDP)"
fi

# Show configuration
echo ""
echo "=== Configuration ==="
cat "$CLIENT_CONFIG"
echo ""

# Try OpenVPN connection with timeout
echo "=== Testing OpenVPN Connection ==="
echo "Starting OpenVPN with 30 second timeout..."

timeout 30 openvpn \
    --config "$CLIENT_CONFIG" \
    --verb 4 \
    --connect-timeout 10 \
    --server-poll-timeout 20 2>&1 | tee "$LOG_FILE" || {
    EXIT_CODE=$?
    echo ""
    echo "=== OpenVPN Result ==="
    echo "Exit code: $EXIT_CODE"
    if [ $EXIT_CODE -eq 124 ]; then
        echo "Connection attempt timed out (this may be expected)"
    else
        echo "OpenVPN failed with error code: $EXIT_CODE"
    fi
    echo ""
    echo "=== Last 10 lines of log ==="
    tail -10 "$LOG_FILE" 2>/dev/null || echo "No log file found"
} 