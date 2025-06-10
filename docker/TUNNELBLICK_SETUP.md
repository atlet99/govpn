# Tunnelblick Setup for GoVPN

Step-by-step guide for connecting to GoVPN server via Tunnelblick on macOS.

## Requirements

- macOS 10.14 or newer
- Tunnelblick 3.8 or newer
- Running GoVPN Docker container

## Installing Tunnelblick

### 1. Download and Installation

```bash
# Option 1: Via Homebrew
brew install --cask tunnelblick

# Option 2: Direct download
# Download from https://tunnelblick.net/downloads.html
```

### 2. First Launch

1. Launch Tunnelblick
2. Grant administrative privileges when prompted
3. Select "I have configuration files" in the welcome dialog

## Configuration Preparation

### 1. Generate Client Certificates

```bash
# Navigate to docker directory
cd docker

# Start GoVPN environment
make up

# Generate client certificates
make certs

# client-bundle.ovpn file will be created in current directory
ls -la client-bundle.ovpn
```

### 2. Configuration Check

Open `client-bundle.ovpn` file in text editor for verification:

```bash
cat client-bundle.ovpn
```

File should contain:
- Basic connection settings
- Embedded certificates (`<ca>`, `<cert>`, `<key>`, `<tls-auth>`)
- Server address: `remote localhost 1194`

## Tunnelblick Setup

### 1. Configuration Import

**Method 1: Drag and Drop**
1. Find `client-bundle.ovpn` file in Finder
2. Drag it to Tunnelblick icon in menu bar
3. Choose "Install for all users" or "Install for me only"

**Method 2: Via Menu**
1. Click Tunnelblick icon in menu bar
2. Select "VPN Details..."
3. Click "+" button
4. Select `client-bundle.ovpn` file

### 2. Authentication Setup

After importing configuration:

1. Click Tunnelblick icon
2. Select "client-bundle" from connections list
3. Click "Connect"

**OIDC Authentication Setup:**

On first connection:
1. Browser window with Keycloak will open
2. Login with credentials:
   - **Username**: `testuser`
   - **Password**: `password123`
3. After successful authentication, return to Tunnelblick

### 3. Additional Settings

**Auto-connection:**
1. VPN Details → client-bundle → Settings
2. Check "Connect when Tunnelblick launches"

**DNS Settings:**
1. VPN Details → client-bundle → Settings → Advanced
2. DNS/WINS: "Set nameserver"
3. Monitor connections: enabled

**Security:**
1. Settings → Preferences → Security
2. "Check for updates automatically": enabled
3. "Do not allow changes to be saved": for production use

## Connection and Usage

### 1. First Connection

```bash
# Start GoVPN server
make up

# Check services status
make health

# Open Tunnelblick and connect
```

### 2. Connection Verification

After successful connection:

1. **Check IP address:**
   ```bash
   curl ifconfig.me
   # Should show server IP, not your real IP
   ```

2. **Check VPN interface:**
   ```bash
   ifconfig tun0
   # Should show tun0 interface with IP from 10.8.0.0/24 network
   ```

3. **Check DNS:**
   ```bash
   nslookup google.com
   # Should use DNS servers from VPN (8.8.8.8)
   ```

### 3. Monitoring

**Tunnelblick Logs:**
1. VPN Details → client-bundle → Log
2. Or: Tunnelblick → Utilities → Log

**Connection Statistics:**
- Click Tunnelblick icon
- Connection time and traffic volume displayed in menu

## Troubleshooting

### Common Issues

1. **"Could not connect to server" Error**
   ```bash
   # Check GoVPN server status
   make status
   
   # Check logs
   make logs-govpn
   
   # Check port availability
   nc -u -v localhost 1194
   ```

2. **Certificate Issues**
   ```bash
   # Regenerate certificates
   make certs
   
   # Check certificate validity dates
   openssl x509 -in certs/client.crt -dates -noout
   ```

3. **OIDC Authentication Not Working**
   ```bash
   # Check Keycloak
   curl -s http://localhost:8080/health
   
   # Check OIDC discovery
   curl -s http://localhost:8080/realms/govpn/.well-known/openid_configuration
   ```

4. **TUN/TAP Permission Issues**
   ```bash
   # Check TUN device permissions
   ls -la /dev/tun*
   
   # Restart with administrator privileges
   sudo tunnelblick
   ```

### Debugging

**Enable Verbose Logging:**

1. VPN Details → client-bundle → Settings → Advanced
2. OpenVPN version: select latest version
3. Log level: 4 (for debugging)

**View Detailed Logs:**
```bash
# System logs
sudo log stream --predicate 'process == "openvpn"'

# Tunnelblick logs
tail -f ~/Library/Application\ Support/Tunnelblick/Logs/*.log
```

## Advanced Settings

### 1. Configuration Customization

Create your custom configuration file:

```bash
cp client-bundle.ovpn my-custom.ovpn
```

Add additional options:
```
# Force redirect all traffic
redirect-gateway def1

# Custom DNS servers
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1

# Traffic compression
compress lz4

# Auto-reconnection
keepalive 10 60
persist-key
persist-tun

# Additional security
auth-nocache
```

### 2. Connection Scripts

Create scripts for automation:

**connect-govpn.sh:**
```bash
#!/bin/bash
echo "Connecting to GoVPN..."
osascript -e 'tell application "Tunnelblick" to connect "client-bundle"'
```

**disconnect-govpn.sh:**
```bash
#!/bin/bash
echo "Disconnecting from GoVPN..."
osascript -e 'tell application "Tunnelblick" to disconnect "client-bundle"'
```

### 3. Traffic Monitoring

Use built-in macOS tools:

```bash
# Monitor VPN interface traffic
sudo tcpdump -i tun0

# Network interface statistics
netstat -i

# Monitor active connections
lsof -i
```

## Security

### Recommendations

1. **Regularly Update Certificates**
   ```bash
   # Recreate certificates every 90 days
   make certs
   ```

2. **Use Strong Passwords**
   - Change default passwords in Keycloak
   - Enable two-factor authentication

3. **Monitor Connections**
   ```bash
   # Check active sessions in Keycloak
   # Admin Console → Sessions
   
   # Monitor GoVPN connections
   curl -s http://localhost:8081/clients
   ```

4. **Protect Configuration Files**
   ```bash
   # Set proper permissions
   chmod 600 client-bundle.ovpn
   
   # Store in protected directory
   mkdir -p ~/.tunnelblick-configs
   mv client-bundle.ovpn ~/.tunnelblick-configs/
   ```

## Conclusion

After completing all steps, you will have:

- ✅ Configured Tunnelblick client
- ✅ Connection to GoVPN server
- ✅ OIDC authentication via Keycloak
- ✅ Secure VPN tunnel
- ✅ Monitoring and debugging capabilities

For additional help:
- Check logs: `make logs`
- Run tests: `make test`
- Refer to main documentation: `docker/README.md` 