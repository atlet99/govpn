# Traffic Padding (Добавление фиктивного трафика)

## Overview

Traffic Padding is an advanced anti-statistical analysis technique that injects dummy packets at random intervals to mask real traffic patterns. Unlike Packet Padding which modifies the size of existing packets, Traffic Padding creates additional fake packets to maintain constant traffic flow and prevent traffic analysis attacks.

## How It Works

### Traffic Analysis Vulnerabilities
Network traffic often reveals patterns that can be analyzed:
- **Burst patterns**: Applications tend to send data in bursts
- **Idle periods**: Gaps between real packets can reveal application behavior
- **Timing correlations**: Predictable intervals between packets
- **Traffic volume**: Low traffic periods make real packets more identifiable

### Traffic Padding Mechanism
The Traffic Padding method:

1. **Dummy Packet Generation**: Creates fake packets with magic headers
2. **Interval Randomization**: Injects packets at random intervals
3. **Burst Mode**: Sends multiple dummy packets in clusters for realism
4. **Adaptive Timing**: Adjusts intervals based on real traffic activity
5. **Automatic Filtering**: Receiving end filters out dummy packets transparently

## Configuration

### Basic Configuration
```go
config := &obfuscation.TrafficPaddingConfig{
    Enabled:      true,
    MinInterval:  100 * time.Millisecond,
    MaxInterval:  2 * time.Second,
    MinDummySize: 64,
    MaxDummySize: 1024,
    BurstMode:    false,
    BurstSize:    3,
    AdaptiveMode: true,
}
```

### Configuration Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `Enabled` | bool | Enable/disable traffic padding | true |
| `MinInterval` | time.Duration | Minimum interval between dummy packets | 100ms |
| `MaxInterval` | time.Duration | Maximum interval between dummy packets | 2s |
| `MinDummySize` | int | Minimum size of dummy packets in bytes | 64 |
| `MaxDummySize` | int | Maximum size of dummy packets in bytes | 1024 |
| `BurstMode` | bool | Enable burst mode for multiple packets | false |
| `BurstSize` | int | Maximum packets per burst | 3 |
| `AdaptiveMode` | bool | Adjust intervals based on activity | true |

### Advanced Settings

#### High-Frequency Mode (Low Latency)
```go
config := &obfuscation.TrafficPaddingConfig{
    Enabled:      true,
    MinInterval:  50 * time.Millisecond,
    MaxInterval:  200 * time.Millisecond,
    MinDummySize: 32,
    MaxDummySize: 128,
    BurstMode:    false,
    BurstSize:    1,
    AdaptiveMode: true,
}
```

#### Burst Mode (Realistic Web Traffic)
```go
config := &obfuscation.TrafficPaddingConfig{
    Enabled:      true,
    MinInterval:  500 * time.Millisecond,
    MaxInterval:  5 * time.Second,
    MinDummySize: 256,
    MaxDummySize: 2048,
    BurstMode:    true,
    BurstSize:    5,
    AdaptiveMode: true,
}
```

#### Stealth Mode (Minimal Overhead)
```go
config := &obfuscation.TrafficPaddingConfig{
    Enabled:      true,
    MinInterval:  2 * time.Second,
    MaxInterval:  10 * time.Second,
    MinDummySize: 64,
    MaxDummySize: 256,
    BurstMode:    false,
    BurstSize:    1,
    AdaptiveMode: false,
}
```

## Usage Examples

### Basic Usage
```go
import (
    "log"
    "time"
    "github.com/atlet99/govpn/pkg/obfuscation"
)

// Create traffic padding configuration
config := &obfuscation.TrafficPaddingConfig{
    Enabled:      true,
    MinInterval:  200 * time.Millisecond,
    MaxInterval:  1 * time.Second,
    MinDummySize: 128,
    MaxDummySize: 512,
    BurstMode:    true,
    BurstSize:    3,
    AdaptiveMode: true,
}

// Create traffic padding obfuscator
logger := log.New(os.Stdout, "[TRAFFIC] ", log.LstdFlags)
padding, err := obfuscation.NewTrafficPadding(config, logger)
if err != nil {
    log.Fatalf("Failed to create traffic padding: %v", err)
}

// Process data (data remains unchanged)
data := []byte("VPN packet data")
obfuscated, err := padding.Obfuscate(data)
if err != nil {
    log.Fatalf("Obfuscation failed: %v", err)
}

fmt.Printf("Data unchanged: %v\n", string(data) == string(obfuscated))
fmt.Printf("Note: Dummy traffic is injected separately via connection wrapper\n")
```

### Engine Integration
```go
// Configure engine with traffic padding
engineConfig := &obfuscation.Config{
    EnabledMethods:  []obfuscation.ObfuscationMethod{obfuscation.MethodTrafficPadding},
    PrimaryMethod:   obfuscation.MethodTrafficPadding,
    FallbackMethods: []obfuscation.ObfuscationMethod{},
    AutoDetection:   false,
    TrafficPadding: obfuscation.TrafficPaddingConfig{
        Enabled:      true,
        MinInterval:  300 * time.Millisecond,
        MaxInterval:  2 * time.Second,
        MinDummySize: 128,
        MaxDummySize: 1024,
        BurstMode:    true,
        BurstSize:    4,
        AdaptiveMode: true,
    },
}

engine, err := obfuscation.NewEngine(engineConfig, logger)
if err != nil {
    log.Fatalf("Failed to create engine: %v", err)
}
defer engine.Close()

// Process packets with traffic padding
packets := [][]byte{
    []byte("Authentication packet"),
    []byte("Data transfer chunk 1"),
    []byte("Data transfer chunk 2"),
    []byte("Heartbeat signal"),
}

for i, packet := range packets {
    // Obfuscate (data unchanged, dummy traffic managed separately)
    obfuscated, err := engine.ObfuscateData(packet)
    if err != nil {
        log.Printf("Failed to obfuscate packet %d: %v", i, err)
        continue
    }
    
    fmt.Printf("Packet %d: %d bytes -> %d bytes (unchanged)\n", 
        i+1, len(packet), len(obfuscated))
    
    // Deobfuscate
    deobfuscated, err := engine.DeobfuscateData(obfuscated)
    if err != nil {
        log.Printf("Failed to deobfuscate packet %d: %v", i, err)
        continue
    }
    
    fmt.Printf("Round-trip success: %v\n", 
        string(packet) == string(deobfuscated))
}
```

### Connection Wrapping (Advanced)
```go
// Wrap network connection with traffic padding
wrappedConn, err := padding.WrapConn(originalConn)
if err != nil {
    log.Fatalf("Failed to wrap connection: %v", err)
}

// The connection wrapper automatically:
// 1. Injects dummy packets in background goroutine
// 2. Filters out dummy packets on read
// 3. Manages timing and burst patterns

// Normal read/write operations
data := make([]byte, 1024)
n, err := wrappedConn.Read(data)  // Dummy packets filtered automatically
if err != nil {
    log.Printf("Read error: %v", err)
}

_, err = wrappedConn.Write([]byte("real data"))  // Real traffic
if err != nil {
    log.Printf("Write error: %v", err)
}

// Background dummy traffic is injected automatically
// Close connection to stop dummy traffic generation
wrappedConn.Close()
```

## Performance Considerations

### Timing Overhead
```go
// Benchmark results (Apple M3 Pro):
BenchmarkTrafficPadding-12    10056230    119.5 ns/op    0 B/op    0 allocs/op
```

Traffic Padding has minimal processing overhead:
- **Processing time**: ~119ns per operation (mostly metadata updates)
- **Memory allocation**: 0 bytes per operation
- **CPU usage**: Minimal for data processing

### Network Overhead

Traffic padding introduces network overhead:
- **Dummy packet frequency**: Depends on interval configuration
- **Packet size overhead**: Based on dummy packet size range
- **Burst overhead**: Multiplied by burst size when enabled

#### Example Calculations
```go
// Configuration example
config := &TrafficPaddingConfig{
    MinInterval:  500 * time.Millisecond,  // Average ~750ms
    MaxInterval:  1 * time.Second,
    MinDummySize: 256,                      // Average ~640 bytes
    MaxDummySize: 1024,
    BurstSize:    3,                        // Average ~2 packets per burst
}

// Estimated overhead:
// - Frequency: ~1.33 intervals per second
// - Packets per second: ~2.66 dummy packets
// - Bytes per second: ~1,700 bytes additional traffic
```

### Bandwidth Impact

Consider bandwidth requirements:
- **Low activity periods**: Higher relative overhead
- **High activity periods**: Lower relative overhead
- **Adaptive mode**: Reduces overhead during high activity

## Security Analysis

### Effectiveness Against Traffic Analysis

**Strengths:**
- Masks traffic timing patterns effectively
- Prevents idle period analysis
- Creates constant traffic baseline
- Resists burst pattern detection
- Effective against statistical correlation attacks

**Limitations:**
- Does not hide packet content (combine with other methods)
- May increase total bandwidth usage
- Long-term patterns may still be detectable
- Not effective against size-based analysis alone

### Dummy Packet Detection Resistance

The magic header approach provides:
```go
// Dummy packet format
header := "DUMMY_TP"  // 8-byte magic header
// followed by random data
```

**Security features:**
- Simple and fast detection on receiving end
- Random data content prevents pattern analysis
- Configurable size makes detection harder
- Mixed with real traffic for better camouflage

## Regional Considerations

### China
- **Recommended settings**: Medium intervals (200ms-1s) with burst mode
- **Combine with**: TLS tunneling for content obfuscation

### Iran  
- **Recommended settings**: Variable intervals (100ms-2s) with adaptive mode
- **Combine with**: HTTP mimicry for protocol obfuscation

### Russia
- **Recommended settings**: Low intervals (50ms-500ms) for high frequency
- **Combine with**: Packet padding for size obfuscation

## Best Practices

### 1. Interval Selection
```go
// For interactive applications
config := &obfuscation.TrafficPaddingConfig{
    MinInterval:  100 * time.Millisecond,
    MaxInterval:  500 * time.Millisecond,
    AdaptiveMode: true,  // Reduce during high activity
}

// For bulk transfer applications
config := &obfuscation.TrafficPaddingConfig{
    MinInterval:  1 * time.Second,
    MaxInterval:  5 * time.Second,
    AdaptiveMode: false,  // Maintain constant cover
}

// For web browsing simulation
config := &obfuscation.TrafficPaddingConfig{
    MinInterval:  300 * time.Millisecond,
    MaxInterval:  2 * time.Second,
    BurstMode:    true,
    BurstSize:    5,
    AdaptiveMode: true,
}
```

### 2. Size Configuration
```go
// Match typical packet sizes for your protocol
func configureForProtocol(protocol string) *obfuscation.TrafficPaddingConfig {
    switch protocol {
    case "http":
        return &obfuscation.TrafficPaddingConfig{
            MinDummySize: 256,  // Typical HTTP header size
            MaxDummySize: 1500, // MTU size
        }
    case "ssh":
        return &obfuscation.TrafficPaddingConfig{
            MinDummySize: 64,   // Small SSH packets
            MaxDummySize: 256,  // Medium SSH packets
        }
    case "voip":
        return &obfuscation.TrafficPaddingConfig{
            MinDummySize: 160,  // Voice packet size
            MaxDummySize: 320,  // Video packet size
        }
    default:
        return &obfuscation.TrafficPaddingConfig{
            MinDummySize: 64,
            MaxDummySize: 1024,
        }
    }
}
```

### 3. Combination with Other Methods
```go
// Recommended combination for maximum effectiveness
config := &obfuscation.Config{
    EnabledMethods: []obfuscation.ObfuscationMethod{
        obfuscation.MethodTrafficPadding,  // Hide timing patterns
        obfuscation.MethodPacketPadding,   // Hide size patterns
        obfuscation.MethodHTTPMimicry,     // Hide content patterns
        obfuscation.MethodTimingObfs,      // Add timing jitter
    },
    PrimaryMethod:   obfuscation.MethodHTTPMimicry,
    FallbackMethods: []obfuscation.ObfuscationMethod{
        obfuscation.MethodTrafficPadding,
        obfuscation.MethodPacketPadding,
    },
    AutoDetection: true,
}
```

## Troubleshooting

### Common Issues

**High Bandwidth Usage:**
```go
// Reduce dummy traffic frequency
config.MinInterval = 2 * time.Second
config.MaxInterval = 10 * time.Second

// Reduce dummy packet sizes
config.MinDummySize = 32
config.MaxDummySize = 128

// Disable burst mode
config.BurstMode = false
```

**Detection Still Occurring:**
```go
// Combine with content obfuscation
config.EnabledMethods = []obfuscation.ObfuscationMethod{
    obfuscation.MethodTrafficPadding,
    obfuscation.MethodHTTPMimicry,  // Add content obfuscation
    obfuscation.MethodTimingObfs,   // Add timing variation
}
```

**Connection Issues:**
```go
// Ensure proper connection wrapping
wrappedConn, err := padding.WrapConn(originalConn)
if err != nil {
    log.Printf("Connection wrapping failed: %v", err)
}

// Always close wrapped connections properly
defer wrappedConn.Close()
```

### Monitoring and Metrics

```go
// Monitor traffic padding performance
metrics := padding.GetMetrics()
fmt.Printf("Packets processed: %d\n", metrics.PacketsProcessed)
fmt.Printf("Bytes processed: %d\n", metrics.BytesProcessed)
fmt.Printf("Average processing time: %v\n", metrics.AvgProcessTime)
fmt.Printf("Errors: %d\n", metrics.Errors)

// Calculate dummy packet statistics
engine := getObfuscationEngine()
engineMetrics := engine.GetMetrics()
if methodMetrics, exists := engineMetrics.MethodMetrics[obfuscation.MethodTrafficPadding]; exists {
    fmt.Printf("Traffic padding usage: %d packets\n", methodMetrics.PacketsProcessed)
    fmt.Printf("Average latency: %v\n", methodMetrics.AvgProcessTime)
}
```

## Implementation Details

### Dummy Packet Structure
```go
type DummyPacket struct {
    Header [8]byte  // "DUMMY_TP" magic header
    Data   []byte   // Random data of configurable size
}

func generateDummyPacket(minSize, maxSize int) []byte {
    size := minSize + rand.Intn(maxSize-minSize+1)
    packet := make([]byte, size)
    
    // Set magic header
    copy(packet[:8], []byte("DUMMY_TP"))
    
    // Fill with random data
    rand.Read(packet[8:])
    
    return packet
}
```

### Interval Calculation
```go
func calculateInterval(config *TrafficPaddingConfig, lastActivity time.Time) time.Duration {
    // Base random interval
    intervalRange := config.MaxInterval - config.MinInterval
    randomOffset := time.Duration(rand.Int63n(int64(intervalRange)))
    interval := config.MinInterval + randomOffset
    
    // Apply adaptive mode
    if config.AdaptiveMode {
        timeSinceActivity := time.Since(lastActivity)
        if timeSinceActivity > 5*time.Second {
            interval = interval / 2  // Increase frequency during idle
        }
    }
    
    return interval
}
```

### Connection Wrapper
```go
type trafficPaddingConn struct {
    net.Conn
    padding *TrafficPadding
    buffer  chan []byte
    mu      sync.Mutex
}

func (c *trafficPaddingConn) Read(b []byte) (n int, err error) {
    for {
        n, err = c.Conn.Read(b)
        if err != nil || n == 0 {
            return n, err
        }
        
        // Check for dummy packet
        if n >= 8 && string(b[:8]) == "DUMMY_TP" {
            // Skip dummy packet, read next
            continue
        }
        
        // Return real data
        return n, err
    }
}
```

## Related Documentation

- [Packet Padding](packet_padding.md) - Size-based obfuscation
- [Timing Obfuscation](timing_obfuscation.md) - Timing-based obfuscation  
- [HTTP Mimicry](http_mimicry.md) - Content-based obfuscation
- [Obfuscation Engine](README.md) - Main engine documentation
- [Regional Profiles](../regional_profiles.md) - Country-specific settings 