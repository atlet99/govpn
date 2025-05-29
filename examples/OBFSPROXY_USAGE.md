# Obfsproxy Integration with GoVPN

This document describes how to use OpenVPN obfsproxy plugins with GoVPN for traffic obfuscation.

## Prerequisites

### Installing obfsproxy

#### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install obfsproxy
```

#### CentOS/RHEL/Fedora:
```bash
sudo yum install obfsproxy
# or for newer versions:
sudo dnf install obfsproxy
```

#### macOS:
```bash
brew install obfsproxy
```

#### From source:
```bash
pip install obfsproxy
```

## Configuration

### Basic Configuration

To enable obfsproxy in GoVPN, configure your obfuscation engine as follows:

```json
{
  "enabled_methods": ["obfsproxy"],
  "primary_method": "obfsproxy",
  "obfsproxy": {
    "enabled": true,
    "executable": "obfsproxy",
    "mode": "client",
    "transport": "obfs4",
    "address": "127.0.0.1",
    "port": 9050,
    "log_level": "INFO"
  }
}
```

### Configuration Options

- **enabled**: Enable/disable obfsproxy (boolean)
- **executable**: Path to obfsproxy binary (default: "obfsproxy")
- **mode**: Operation mode - "client" or "server"
- **transport**: Transport protocol - "obfs3", "obfs4", or "scramblesuit"
- **address**: Listen address (for server mode) or proxy address (for client mode)
- **port**: Port number
- **options**: Additional obfsproxy command line options
- **log_level**: Logging level - "DEBUG", "INFO", "WARNING", "ERROR"

### Supported Transports

#### obfs3
Basic obfuscation protocol:
```json
{
  "transport": "obfs3",
  "address": "127.0.0.1",
  "port": 9050
}
```

#### obfs4
Advanced obfuscation with built-in pluggable transport:
```json
{
  "transport": "obfs4",
  "address": "127.0.0.1", 
  "port": 9050,
  "options": "--cert=your_cert_here --iat-mode=0"
}
```

#### scramblesuit
High-entropy obfuscation:
```json
{
  "transport": "scramblesuit",
  "address": "127.0.0.1",
  "port": 9050,
  "options": "--password=your_password_here"
}
```

## Usage Examples

### Client Configuration

```json
{
  "enabled_methods": ["obfsproxy", "tls_tunnel"],
  "primary_method": "obfsproxy",
  "fallback_methods": ["tls_tunnel"],
  "auto_detection": true,
  "obfsproxy": {
    "enabled": true,
    "executable": "obfsproxy",
    "mode": "client",
    "transport": "obfs4",
    "address": "your.server.com",
    "port": 443,
    "log_level": "INFO"
  }
}
```

### Server Configuration

```json
{
  "enabled_methods": ["obfsproxy"],
  "primary_method": "obfsproxy",
  "obfsproxy": {
    "enabled": true,
    "executable": "obfsproxy",
    "mode": "server", 
    "transport": "obfs4",
    "address": "0.0.0.0",
    "port": 443,
    "log_level": "INFO"
  }
}
```

## Integration with OpenVPN

GoVPN's obfsproxy integration is compatible with OpenVPN obfsproxy configurations. You can use the same transport settings that work with OpenVPN.

### Converting OpenVPN Config

If you have an OpenVPN config with obfsproxy:

```
# OpenVPN config
plugin obfsproxy obfs4 --cert=abc123... --iat-mode=0 --addr=server.com:443
```

Convert to GoVPN:

```json
{
  "obfsproxy": {
    "enabled": true,
    "transport": "obfs4",
    "address": "server.com",
    "port": 443,
    "options": "--cert=abc123... --iat-mode=0"
  }
}
```

## Troubleshooting

### Common Issues

1. **obfsproxy not found**
   - Ensure obfsproxy is installed and in PATH
   - Check executable path in configuration

2. **Connection failed**
   - Verify server address and port
   - Check transport compatibility between client and server
   - Review obfsproxy logs

3. **Transport-specific errors**
   - For obfs4: Ensure cert parameter is correct
   - For scramblesuit: Verify password matches
   - Check that both ends use same transport

### Debugging

Enable debug logging:
```json
{
  "obfsproxy": {
    "log_level": "DEBUG"
  }
}
```

Check obfsproxy availability:
```bash
which obfsproxy
obfsproxy --help
```

## Performance Considerations

- obfs4 provides the best balance of security and performance
- obfs3 has lower overhead but less sophisticated obfuscation
- scramblesuit provides high entropy but higher CPU usage
- Consider network latency when choosing transport protocols

## Security Notes

- Always use TLS/SSL for the underlying VPN connection
- Obfsproxy provides traffic obfuscation, not encryption
- Keep obfsproxy updated to latest version
- Use strong certificates and passwords for transport parameters 