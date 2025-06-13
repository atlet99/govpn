#!/bin/bash

# GoVPN Client Health Check Script
set -euo pipefail

PID_FILE="/var/run/govpn-client.pid"
LOG_FILE="/var/log/govpn/client.log"

# Check if OpenVPN process is running
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        # Process is running, check if we have VPN connection
        # Look for tun interface
        if ip link show | grep -q "tun[0-9]"; then
            # Check if we can reach VPN server's internal IP
            if ping -c 1 -W 2 10.8.0.1 >/dev/null 2>&1; then
                echo "VPN client is connected and healthy"
                exit 0
            else
                echo "VPN client running but cannot reach server"
                exit 1
            fi
        else
            echo "VPN client running but no TUN interface found"
            exit 1
        fi
    else
        echo "VPN client process not running (stale PID file)"
        rm -f "$PID_FILE"
        exit 1
    fi
else
    echo "VPN client not running (no PID file)"
    exit 1
fi 