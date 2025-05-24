# GoVPN Configuration Files

This folder contains all necessary configuration files for setting up GoVPN server and clients with support for modern authentication methods and traffic obfuscation.

## File Structure

### Main Configuration Files

- **`server.conf`** - Main server configuration file
- **`client.conf`** - Basic client configuration file

### Additional Authentication Modules

- **`auth.conf`** - Basic password authentication
- **`mfa.conf`** - Multi-factor authentication (TOTP/HOTP)
- **`oidc.conf`** - OIDC authentication (Google, Microsoft, Keycloak, etc.)
- **`ldap.conf`** - LDAP authentication (Active Directory, OpenLDAP)

### Obfuscation Modules

- **`obfuscation.conf`** - Traffic obfuscation and masking settings

## Quick Start

### 1. Basic Server Setup

```bash
# Copy main config
cp server.conf /etc/govpn/
cp client.conf /etc/govpn/

# Setup certificates
mkdir -p /etc/govpn/certs
# ... copy your certificates to /etc/govpn/certs/
```

### 2. Enable Additional Authentication Methods

To enable additional authentication methods, uncomment corresponding lines in `server.conf`:

```conf
# Enable basic password authentication
include auth.conf

# Enable multi-factor authentication
include mfa.conf

# Enable OIDC authentication
include oidc.conf

# Enable LDAP authentication
include ldap.conf
```

## Detailed Configuration Description

### Basic Server Configuration (`server.conf`)

Main file contains basic VPN server settings:

- **Network settings**: port, protocol, device type
- **VPN network**: IP address range, DNS servers
- **Security**: encryption and authentication algorithms
- **Certificates**: paths to certificate and key files
- **Connections**: client limits, keepalive settings

### Basic Authentication (`auth.conf`)

Configuration for password authentication:

- **Hashing**: Argon2 (recommended) or PBKDF2
- **Sessions**: session lifetime management
- **Security**: protection against attacks, reconnection tokens

#### Example Argon2 configuration:
```conf
auth-hash-method argon2
auth-argon2-memory 65536     # 64MB memory
auth-argon2-time 3           # 3 iterations
auth-argon2-threads 4        # 4 threads
```

### Multi-Factor Authentication (`mfa.conf`)

Configuration for two-factor authentication:

- **TOTP**: support for Google Authenticator, Microsoft Authenticator, Authy
- **Backup codes**: for access recovery
- **Security**: brute force protection, lockouts

#### App compatibility:
- ✅ Google Authenticator
- ✅ Microsoft Authenticator 
- ✅ Authy
- ✅ 1Password
- ✅ Bitwarden

### OIDC Authentication (`oidc.conf`)

Integration with modern single sign-on systems:

#### Supported providers:
- **Keycloak** - Open source enterprise solution
- **Google Workspace** - For Google organizations
- **Microsoft Azure AD/Entra** - For Microsoft organizations
- **Okta** - Commercial solution
- **Auth0** - Authentication platform
- **GitLab** - For GitLab integration

#### Security settings:
- **PKCE** - Authorization Code Flow protection
- **Token validation** - signature and issuer verification
- **Role mapping** - automatic permissions assignment

### LDAP Authentication (`ldap.conf`)

Integration with corporate directories:

#### Supported LDAP servers:
- **Microsoft Active Directory** - Primary support
- **OpenLDAP** - Open source solution
- **FreeIPA/Red Hat IdM** - For Linux environments
- **389 Directory Server** - Red Hat solution
- **Oracle Internet Directory** - For Oracle environments

#### Features:
- **Security groups** - access control through groups
- **Caching** - performance enhancement
- **Connection pooling** - scalability
- **Backup servers** - fault tolerance

### Traffic Obfuscation (`obfuscation.conf`)

Modern methods for VPN blocking circumvention:

#### Obfuscation methods:
- **XOR Cipher** - simple XOR encryption
- **Packet Padding** - packet size modification
- **Timing Obfuscation** - timing characteristics modification
- **TLS Tunnel** - HTTPS masquerading
- **HTTP Mimicry** - web traffic masquerading
- **DNS Tunnel** - DNS tunneling

#### Regional profiles:
- **China** - optimized for Great Firewall
- **Iran** - adapted for Iranian restrictions
- **Russia** - settings for Russian limitations

## Usage Examples

### Corporate Network with Active Directory

```conf
# server.conf
include ldap.conf

# ldap.conf
ldap-enabled true
ldap-server dc1.company.com
ldap-bind-dn cn=ldap-reader,ou=service-accounts,dc=company,dc=com
ldap-required-groups CN=VPN-Users,ou=groups,dc=company,dc=com
```

### Organization with Google Workspace

```conf
# server.conf  
include oidc.conf

# oidc.conf
oidc-enabled true
oidc-provider-url https://accounts.google.com
oidc-required-claims hd:company.com,email_verified:true
```

### High Security with MFA

```conf
# server.conf
include auth.conf
include mfa.conf

# mfa.conf
mfa-enabled true
mfa-required-for-all true
mfa-max-attempts 3
mfa-lockout-duration 1800
```

### Blocking Circumvention

```conf
# server.conf
include obfuscation.conf

# obfuscation.conf
obfuscation-enabled true
obfuscation-primary-method tls_tunnel
tls-tunnel-port 443
adaptive-obfuscation-enabled true
```

## Security

### Security Recommendations:

1. **Use strong algorithms**:
   - Encryption: AES-256-GCM
   - Authentication: SHA256 or SHA512
   - TLS: version 1.2 or higher

2. **Set correct access permissions**:
   ```bash
   chmod 600 /etc/govpn/*.conf
   chmod 600 /etc/govpn/certs/*
   chown root:root /etc/govpn/*
   ```

3. **Use MFA for critical accounts**

4. **Regularly update certificates**

5. **Monitor connection logs**

### Password and Key Protection:

- All passwords and secret keys must be stored securely
- Use environment variables for secret data
- Regularly change service account passwords

## Monitoring and Logging

### Log files:
- `/var/log/govpn.log` - main server logs
- `/var/log/govpn-auth.log` - authentication logs
- `/var/log/govpn-mfa.log` - MFA logs
- `/var/log/govpn-oidc.log` - OIDC logs
- `/var/log/govpn-ldap.log` - LDAP logs
- `/var/log/govpn-obfuscation.log` - obfuscation logs

### Metrics:
Enable metrics collection for monitoring:
```conf
obfuscation-metrics-enabled true
obfuscation-metrics-port 9090
```

## Performance

### Optimization for different loads:

**Small networks (up to 50 users):**
```conf
max-clients 50
ldap-connection-pool-size 5
obfuscation-threads 2
```

**Medium networks (up to 500 users):**
```conf
max-clients 500
ldap-connection-pool-size 20
obfuscation-threads 8
```

**Large networks (over 500 users):**
```conf
max-clients 1000
ldap-connection-pool-size 50
obfuscation-threads 16
```

## Troubleshooting

### Common issues:

1. **LDAP connection problems**:
   - Check network accessibility
   - Verify bind DN and password correctness
   - Check SSL/TLS settings

2. **OIDC problems**:
   - Check client_id and client_secret correctness
   - Verify provider availability
   - Check redirect URL

3. **MFA problems**:
   - Synchronize server time
   - Check TOTP settings (period, algorithm)
   - Verify secret key correctness

### Debugging:
Enable detailed logging for debugging:
```conf
verb 6                          # In main config
mfa-log-level debug            # For MFA
oidc-log-level debug           # For OIDC
ldap-log-level debug           # For LDAP
```

## Support

For support, refer to project documentation or create an issue in the repository.

## License

Configuration files are distributed under the same license as the main GoVPN project. 