# GoVPN Traffic Obfuscation

The GoVPN traffic obfuscation module is designed to bypass DPI (Deep Packet Inspection) blocking and censorship in various regions worldwide.

## Features

### ✅ Implemented Functions

- **XOR Obfuscation** - fast XOR encryption on top of main encryption
- **TLS Tunneling** - encapsulating VPN traffic in legitimate TLS connections
- **HTTP Mimicry** - masking VPN traffic as legitimate HTTP requests/responses
- **Packet Padding** - packet size randomization for anti-statistical analysis
- **Timing Obfuscation** - changing time intervals between packets to mask traffic patterns
- **Traffic Padding** - adding dummy traffic to mask activity patterns
- **Flow Watermarking** - adding hidden watermarks to distort statistical characteristics
- **Modular Architecture** - easy addition of new obfuscation methods
- **Automatic Switching** - DPI blocking detector with automatic method switching
- **Regional Profiles** - optimized settings for different countries (China, Iran, Russia)
- **Performance Metrics** - detailed statistics of obfuscator operation
- **Adaptive Obfuscation** - dynamic switching when blocking is detected

- **DNS Tunneling** - data transmission through DNS queries (backup communication channel)
- **HTTP Steganography** ✅ - hiding VPN data inside HTTP traffic using steganographic techniques

## Quick Start

### CLI Usage

```bash
# Enable obfuscation with XOR method
./govpn-server --obfuscation --obfuscation-method=xor_cipher

# Use regional profile for China
./govpn-server --obfuscation --regional-profile=china

# Specify custom XOR key
./govpn-server --obfuscation --xor-key="my-secret-key-123"
```

### Programmatic Usage

```go
package main

import (
    "log"
    "time"
    
    "github.com/atlet99/govpn/pkg/obfuscation"
)

func main() {
    // Obfuscation configuration
    config := &obfuscation.Config{
        EnabledMethods:   []obfuscation.ObfuscationMethod{obfuscation.MethodXORCipher},
        PrimaryMethod:    obfuscation.MethodXORCipher,
        FallbackMethods:  []obfuscation.ObfuscationMethod{},
        AutoDetection:    true,
        SwitchThreshold:  3,
        DetectionTimeout: 5 * time.Second,
        RegionalProfile:  "china",
        XORKey:          []byte("your-secret-key"),
    }
    
    // Create obfuscation engine
    engine, err := obfuscation.NewEngine(config, log.Default())
    if err != nil {
        log.Fatal(err)
    }
    defer engine.Close()
    
    // Data obfuscation
    data := []byte("Sensitive VPN traffic")
    obfuscated, err := engine.ObfuscateData(data)
    if err != nil {
        log.Fatal(err)
    }
    
    // Deobfuscation
    deobfuscated, err := engine.DeobfuscateData(obfuscated)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Success: %s", string(deobfuscated))
}
```

## Obfuscation Methods

### XOR Cipher

Simple and fast obfuscation method using XOR operation.

**Advantages:**
- Very high performance
- Minimal overhead
- Symmetric encryption

**Disadvantages:**
- Relatively simple to analyze
- Requires secure key exchange

**Usage:**
```go
cipher, err := obfuscation.NewXORCipher([]byte("your-key"), logger)
```

### TLS Tunneling ✅

Encapsulating VPN traffic in legitimate TLS connections.

**Advantages:**
- Looks like regular HTTPS traffic
- Difficult to block without blocking all HTTPS
- SNI and ALPN support
- Auto-generation of self-signed certificates
- Optional fake HTTP headers

**Usage:**
```go
config := &obfuscation.TLSTunnelConfig{
    ServerName:      "secure.example.com",
    ALPN:            []string{"h2", "http/1.1"},
    FakeHTTPHeaders: true,
}
tunnel, err := obfuscation.NewTLSTunnel(config, logger)
```

**Documentation:** [TLS Tunneling](tls_tunneling.md)

### Packet Padding ✅

Packet size randomization to mask statistical characteristics.

**Advantages:**
- Complicates statistical traffic analysis
- Cryptographically strong random data
- Configurable padding ranges
- Automatic padding addition/removal

**Usage:**
```go
config := &obfuscation.PacketPaddingConfig{
    Enabled:       true,
    MinPadding:    10,
    MaxPadding:    100,
    RandomizeSize: true,
}
padding, err := obfuscation.NewPacketPadding(config, logger)
```

**Documentation:** [Packet Padding](packet_padding.md)

### Timing Obfuscation ✅

Changing time intervals between packets to mask traffic patterns.

**Advantages:**
- Hides characteristic timing patterns of VPN traffic
- Uses exponential distribution for realism
- Configurable delay ranges (from microseconds to seconds)
- Does not change packet content, only timing intervals

**Usage:**
```go
config := &obfuscation.TimingObfsConfig{
    Enabled:      true,
    MinDelay:     1 * time.Millisecond,
    MaxDelay:     50 * time.Millisecond,
    RandomJitter: true,
}
timing, err := obfuscation.NewTimingObfuscation(config, logger)
```

**Documentation:** [Timing Obfuscation](timing_obfuscation.md)

### Traffic Padding ✅

Adding dummy traffic between real packets to mask activity patterns.

**Advantages:**
- Creates constant traffic flow to mask idle periods
- Supports burst mode to simulate real activity
- Adaptive intervals based on activity
- Automatic filtering of dummy packets on receiver side

**Usage:**
```go
config := &obfuscation.TrafficPaddingConfig{
    Enabled:      true,
    MinInterval:  100 * time.Millisecond,
    MaxInterval:  2 * time.Second,
    MinDummySize: 64,
    MaxDummySize: 1024,
    BurstMode:    true,
    BurstSize:    3,
    AdaptiveMode: true,
}
padding, err := obfuscation.NewTrafficPadding(config, logger)
```

**Documentation:** [Traffic Padding](traffic_padding.md)

### Flow Watermarking ✅

Adding hidden watermarks to distort statistical characteristics.

**Advantages:**
- Modifies statistical characteristics of data without compromising integrity
- Uses cryptographic keys to generate unique patterns
- Supports both statistical and simple XOR modes
- Periodic pattern rotation for increased security
- Configurable frequency bands for different traffic types
- Effective against correlation and frequency analysis

**Usage:**
```go
config := &obfuscation.FlowWatermarkConfig{
    Enabled:         true,
    WatermarkKey:    []byte("your-secret-watermark-key-32-bytes"),
    PatternInterval: 500 * time.Millisecond,
    PatternStrength: 0.3,
    NoiseLevel:      0.1,
    RotationPeriod:  5 * time.Minute,
    StatisticalMode: true,
    FrequencyBands:  []int{1, 2, 5, 10, 20, 50},
}
watermark, err := obfuscation.NewFlowWatermark(config, logger)
```

**Documentation:** [Flow Watermarking](flow_watermarking.md)

### HTTP Mimicry ✅

Masking VPN traffic as legitimate HTTP requests with realistic headers.

**Advantages:**
- Mimics real websites and API requests
- Adaptive data encoding (GET/POST methods)
- Modern User-Agent strings (2024)
- Supports various HTTP methods and headers

**Usage:**
```go
config := &obfuscation.HTTPMimicryConfig{
    UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0",
    FakeHost:      "api.github.com",
    CustomHeaders: map[string]string{"Authorization": "Bearer token"},
    MimicWebsite:  "https://api.github.com",
}
mimicry, err := obfuscation.NewHTTPMimicry(config, logger)
```

**Documentation:** [HTTP Mimicry](http_mimicry.md)

### DNS Tunneling ✅

Data transmission through DNS queries for providing backup communication channel in extremely restricted networks.

**Advantages:**
- Works through most firewalls (DNS traffic rarely gets blocked completely)
- Bypasses DPI in restricted networks
- Supports multiple DNS servers for reservation
- Configurable query delays to avoid detection
- Base32 encoding for compatibility with DNS
- Supports various types of DNS records (A, TXT, CNAME)

**Usage:**
```go
config := &obfuscation.DNSTunnelConfig{
    Enabled:        true,
    DomainSuffix:   "example.com",
    DNSServers:     []string{"8.8.8.8:53", "1.1.1.1:53"},
    QueryTypes:     []string{"A", "TXT", "CNAME"},
    EncodingMethod: "base32",
    MaxPayloadSize: 32,
    QueryDelay:     100 * time.Millisecond,
    Subdomain:      "vpn",
}
tunnel, err := obfuscation.NewDNSTunnel(config, logger)
```

**Documentation:** [DNS Tunneling](dns_tunneling.md)

### HTTP Steganography ✅

Hiding VPN data inside regular HTTP traffic using steganographic techniques.

**Advantages:**
- Five different methods of steganography for different scenarios
- Headers and Body: fast for small data (7.5x expansion)
- Multipart Forms: excellent for file upload masking (13.5x expansion)
- JSON API: indistinguishable from API traffic (6.8x expansion)
- CSS Comments: steganographically secure (9.5x expansion)
- JavaScript Variables: code application hiding (13.1x expansion)
- Realistic HTTP headers and structures
- Automatic data integrity check
- Configurable websites and User-Agent for authenticity

**Usage:**
```go
config := &obfuscation.HTTPStegoConfig{
    Enabled:       true,
    CoverWebsites: []string{"github.com", "stackoverflow.com", "reddit.com"},
    UserAgents:    []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
    ContentTypes:  []string{"text/html", "application/json", "text/css"},
    SteganoMethod: "json_api",  // headers_and_body, multipart_forms, json_api, css_comments, js_variables
    ChunkSize:     128,
    ErrorRate:     0.02,
    SessionTimeout: 15 * time.Minute,
    EnableMIME:     true,
    CachingEnabled: false,
}
stego, err := obfuscation.NewHTTPSteganography(config, logger)
```

**Documentation:** [HTTP Steganography](http_steganography.md)

## Regional Profiles

### China (china)

Optimized for Great Firewall bypass:
- Primary method: TLS Tunnel
- Backup methods: HTTP Mimicry, XOR Cipher
- Aggressive packet obfuscation
- Quick method switching (threshold: 2 errors)

### Iran (iran)

Configured for Iranian filtering:
- Primary method: HTTP Mimicry
- Backup methods: TLS Tunnel, HTTP Steganography
- Moderate obfuscation
- Medium switching threshold (3 errors)

### Russia (russia)

Focused on Russian DPI bypass:
- Primary method: TLS Tunnel
- Backup methods: HTTP Mimicry, Timing Obfuscation
- Light obfuscation for speed preservation
- Conservative switching threshold (4 errors)

## Automatic Switching

System automatically detects blockings based on the following signs:

- `connection reset by peer`
- `connection refused`
- `timeout`
- `certificate verify failed`
- `handshake failure`
- `protocol error`
- `unexpected EOF`
- `no route to host`

When specified number of consecutive errors occur (configurable via `SwitchThreshold`), system automatically switches to next available method from `FallbackMethods`.

## Performance Metrics and Monitoring

Each obfuscator provides detailed metrics:

```go
type ObfuscatorMetrics struct {
    PacketsProcessed int64         // Number of processed packets
    BytesProcessed   int64         // Number of processed bytes
    Errors           int64         // Number of errors
    AvgProcessTime   time.Duration // Average processing time
    LastUsed         time.Time     // Last usage time
}
```

Obfuscation engine also provides general metrics:

```go
type EngineMetrics struct {
    TotalPackets     int64                            // Total number of packets
    TotalBytes       int64                            // Total number of bytes
    MethodSwitches   int64                            // Number of method switches
    DetectionEvents  int64                            // Number of detection events
    MethodMetrics    map[ObfuscationMethod]*ObfuscatorMetrics // Metrics by methods
    StartTime        time.Time                        // Start time
}
```

## Performance

Benchmark results on Apple M3 Pro:

```
BenchmarkXORObfuscation-12           1000000      1041 ns/op     1408 B/op     1 allocs/op
BenchmarkTLSTunnelObfuscation-12    13950534        86.05 ns/op     0 B/op     0 allocs/op
BenchmarkHTTPMimicryObfuscation-12   1799318       671.4 ns/op  3494 B/op    15 allocs/op
BenchmarkPacketPaddingObfuscation-12 2720599       439.5 ns/op  2304 B/op     1 allocs/op
BenchmarkTimingObfuscation-12           5008      262179 ns/op     0 B/op     0 allocs/op
BenchmarkTrafficPadding-12           8616214       119.9 ns/op     0 B/op     0 allocs/op
BenchmarkFlowWatermark-12             607738      1937 ns/op    1152 B/op     1 allocs/op
BenchmarkHTTPSteganographyObfuscation-12  460210  2566 ns/op    4171 B/op    52 allocs/op
BenchmarkDNSTunnelObfuscation-12      470808      2658 ns/op    5291 B/op    48 allocs/op
```

### Comparison of Performance Methods

1. **TLS Tunneling**: Fastest (~86ns/op, 0 allocs)
2. **Traffic Padding**: Very fast (~120ns/op, 0 allocs)
3. **Packet Padding**: Good speed (~440ns/op, 1 alloc)
4. **HTTP Mimicry**: Medium speed (~671ns/op, 15 allocs)
5. **XOR Cipher**: Slow (~1041ns/op, 1 alloc)
6. **Flow Watermarking**: Slow (~1937ns/op, 1 alloc)
7. **HTTP Steganography**: Slow (~2566ns/op, 52 allocs)
8. **DNS Tunneling**: Slow (~2658ns/op, 48 allocs)
9. **Timing Obfuscation**: Slowest* (~262μs/op, 0 allocs)

*Note: High execution time for Timing Obfuscation is due to intentional delays, not computational complexity.

## Configuration

### Main Parameters

- `EnabledMethods` - list of enabled obfuscation methods
- `PrimaryMethod` - primary obfuscation method
- `FallbackMethods` - backup methods for switching
- `AutoDetection` - enable blocking detection
- `SwitchThreshold` - number of errors for method switching
- `DetectionTimeout` - timeout for blocking detection
- `RegionalProfile` - regional profile (china, iran, russia)

### Specific Settings

#### XOR Cipher
- `XORKey` - key for XOR obfuscation (byte array)

#### TLS Tunnel
- `ServerName` - server name for SNI
- `ALPN` - list of supported protocols
- `FakeHTTPHeaders` - add fake HTTP headers

#### Packet Padding
- `Enabled` - enable/disable Packet Padding
- `MinPadding` - minimum number of bytes to add
- `MaxPadding` - maximum number of bytes to add  
- `RandomizeSize` - randomize padding size

#### HTTP Mimicry
- `UserAgent` - User-Agent string
- `FakeHost` - fake host
- `CustomHeaders` - additional HTTP headers
- `MimicWebsite` - website for mimicry

#### Flow Watermarking
- `Enabled` - enable/disable Flow Watermarking
- `WatermarkKey` - cryptographic key for watermark generation
- `PatternInterval` - pattern update interval
- `PatternStrength` - watermark strength (0.0-1.0)
- `NoiseLevel` - noise level for randomization (0.0-1.0)
- `RotationPeriod` - pattern rotation period
- `StatisticalMode` - use statistical or simple XOR mode
- `FrequencyBands` - frequency bands for pattern generation

## Usage Examples

### Demonstration

Run demonstration to view all capabilities:

```bash
go run examples/obfuscation_demo.go
```

### Testing

Run obfuscation module tests:

```bash
go test ./pkg/obfuscation -v
```

### Benchmarks

Run performance benchmarks:

```bash
go test ./pkg/obfuscation -bench=. -v
```

## Security

### Recommendations

1. **Use Strong Keys** - for XOR obfuscation, use random keys of at least 32 bytes
2. **Regularly Change Keys** - periodically update obfuscation keys
3. **Combine Methods** - use multiple obfuscation methods for increased robustness
4. **Monitor Metrics** - watch method switching and error counts

### Limitations

- XOR obfuscation is not cryptographically secure and should only be used on top of main encryption VPN
- Some obfuscation methods may reduce performance
- Obfuscation effectiveness depends on specific blocking methods in the region

## Development

### Adding New Obfuscation Method

1. Implement `Obfuscator` interface:

```go
type Obfuscator interface {
    Name() ObfuscationMethod
    Obfuscate(data []byte) ([]byte, error)
    Deobfuscate(data []byte) ([]byte, error)
    WrapConn(conn net.Conn) (net.Conn, error)
    IsAvailable() bool
    GetMetrics() ObfuscatorMetrics
}
```

2. Add method constant:

```go
const MethodYourMethod ObfuscationMethod = "your_method"
```

3. Add constructor in `initializeObfuscators()`:

```go
case MethodYourMethod:
    obfuscator, err = NewYourMethod(&e.config.YourMethodConfig, e.logger)
```

4. Add tests in `obfuscation_test.go`

### Project Structure

```
pkg/obfuscation/
├── obfuscation.go      # Main module with engine and XOR obfuscator
├── obfuscation_test.go # Obfuscation module tests
└── README.md           # Documentation (this file)
```

## License

This module is part of GoVPN project and distributed under the same license. 