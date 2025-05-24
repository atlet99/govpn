# Timing Obfuscation (Обфускация временных интервалов)

## Overview

Timing Obfuscation is a traffic analysis countermeasure that modifies the timing patterns between network packets to prevent Deep Packet Inspection (DPI) systems from identifying VPN traffic based on timing characteristics. By introducing controlled delays, it masks the predictable timing patterns that could reveal the nature of the encrypted traffic.

## How It Works

### Timing Pattern Analysis
Network traffic often has characteristic timing patterns:
- **Interactive traffic** (SSH, messaging): Short, frequent packets with low latency
- **Bulk transfer** (file downloads): Large packets in bursts
- **Video streaming**: Regular packet intervals with consistent sizes
- **VPN traffic**: May have distinct timing signatures

### Obfuscation Mechanism
The Timing Obfuscation method:

1. **Delay Injection**: Adds random delays before sending packets
2. **Exponential Distribution**: Uses exponential delay distribution for realistic timing
3. **Configurable Ranges**: Allows setting minimum and maximum delay bounds
4. **Data Preservation**: Does not modify packet content, only timing

## Configuration

### Basic Configuration
```go
config := &obfuscation.TimingObfsConfig{
    Enabled:      true,
    MinDelay:     1 * time.Millisecond,
    MaxDelay:     50 * time.Millisecond,
    RandomJitter: true,
}
```

### Configuration Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `Enabled` | bool | Enable/disable timing obfuscation | true |
| `MinDelay` | time.Duration | Minimum delay between packets | 1ms |
| `MaxDelay` | time.Duration | Maximum delay between packets | 50ms |
| `RandomJitter` | bool | Use exponential distribution for delays | true |

### Advanced Settings

#### Fixed Delay Mode
```go
config := &obfuscation.TimingObfsConfig{
    Enabled:      true,
    MinDelay:     10 * time.Millisecond,
    MaxDelay:     10 * time.Millisecond, // Same as MinDelay
    RandomJitter: false,                 // Disable randomization
}
```

#### Adaptive Delay Mode
```go
config := &obfuscation.TimingObfsConfig{
    Enabled:      true,
    MinDelay:     1 * time.Millisecond,
    MaxDelay:     100 * time.Millisecond, // Large range
    RandomJitter: true,                   // Exponential distribution
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

// Create timing obfuscation configuration
config := &obfuscation.TimingObfsConfig{
    Enabled:      true,
    MinDelay:     5 * time.Millisecond,
    MaxDelay:     25 * time.Millisecond,
    RandomJitter: true,
}

// Create timing obfuscator
logger := log.New(os.Stdout, "[TIMING] ", log.LstdFlags)
timing, err := obfuscation.NewTimingObfuscation(config, logger)
if err != nil {
    log.Fatalf("Failed to create timing obfuscation: %v", err)
}

// Process data with timing delays
data := []byte("VPN packet data")
start := time.Now()

// This will add a random delay before returning
obfuscated, err := timing.Obfuscate(data)
delay := time.Since(start)

fmt.Printf("Added delay: %v\n", delay)
fmt.Printf("Data unchanged: %v\n", string(data) == string(obfuscated))
```

### Engine Integration
```go
// Configure engine with timing obfuscation
engineConfig := &obfuscation.Config{
    EnabledMethods:  []obfuscation.ObfuscationMethod{obfuscation.MethodTimingObfs},
    PrimaryMethod:   obfuscation.MethodTimingObfs,
    FallbackMethods: []obfuscation.ObfuscationMethod{},
    AutoDetection:   false,
    TimingObfuscation: obfuscation.TimingObfsConfig{
        Enabled:      true,
        MinDelay:     2 * time.Millisecond,
        MaxDelay:     20 * time.Millisecond,
        RandomJitter: true,
    },
}

engine, err := obfuscation.NewEngine(engineConfig, logger)
if err != nil {
    log.Fatalf("Failed to create engine: %v", err)
}
defer engine.Close()

// Process packets with timing obfuscation
packets := [][]byte{
    []byte("Control packet"),
    []byte("Data packet with payload"),
    []byte("Heartbeat"),
}

for i, packet := range packets {
    start := time.Now()
    
    // Obfuscate with timing delay
    obfuscated, err := engine.ObfuscateData(packet)
    if err != nil {
        log.Printf("Failed to obfuscate packet %d: %v", i, err)
        continue
    }
    
    delay := time.Since(start)
    fmt.Printf("Packet %d: %v delay\n", i+1, delay)
    
    // Deobfuscate (immediate, no delay)
    deobfuscated, err := engine.DeobfuscateData(obfuscated)
    if err != nil {
        log.Printf("Failed to deobfuscate packet %d: %v", i, err)
        continue
    }
    
    fmt.Printf("Round-trip success: %v\n", 
        string(packet) == string(deobfuscated))
}
```

### Connection Wrapping
```go
// Wrap network connection with timing obfuscation
wrappedConn, err := timing.WrapConn(originalConn)
if err != nil {
    log.Fatalf("Failed to wrap connection: %v", err)
}

// All reads and writes will have timing delays applied
data := make([]byte, 1024)
n, err := wrappedConn.Read(data)  // Includes timing delay
if err != nil {
    log.Printf("Read error: %v", err)
}

_, err = wrappedConn.Write([]byte("response"))  // Includes timing delay
if err != nil {
    log.Printf("Write error: %v", err)
}
```

## Performance Considerations

### Timing Overhead
```go
// Benchmark results (Apple M3 Pro):
BenchmarkTimingObfuscation-12    4876    263468 ns/op    0 B/op    0 allocs/op
```

The timing obfuscation introduces controlled delays:
- **Minimum overhead**: ~263µs per operation (mostly from timing delays)
- **Memory allocation**: 0 bytes per operation (no additional allocations)
- **CPU usage**: Minimal (just timing calculations)

### Delay Distribution

When `RandomJitter` is enabled, delays follow an exponential distribution:
```
f(x) = λe^(-λx)
```

This creates more realistic timing patterns that mimic natural network jitter.

### Throughput Impact

Timing obfuscation affects network throughput:
- **With 10ms average delay**: ~100 packets/second maximum
- **With 1ms average delay**: ~1000 packets/second maximum
- **Impact scales with delay values**

## Security Analysis

### Effectiveness Against DPI

**Strengths:**
- Masks timing-based traffic fingerprinting
- Prevents correlation attacks based on packet timing
- Creates natural-looking traffic patterns
- Effective against automated DPI classification

**Limitations:**
- Does not hide packet sizes or content
- May introduce noticeable latency
- Statistical analysis over long periods may still reveal patterns
- Not effective against content-based detection

### Timing Attack Resistance

The exponential distribution helps resist timing attacks:
```go
// Exponential delay calculation
randomFactor := mathrand.ExpFloat64()
if randomFactor > 3.0 {
    randomFactor = 3.0  // Cap extreme values
}

delay := minDelay + time.Duration(float64(delayRange)*randomFactor/3.0)
```

This approach:
- Prevents predictable timing patterns
- Mimics natural network behavior
- Makes timing correlation difficult

## Regional Considerations

### China
- **Recommended settings**: Medium delays (5-25ms) to mimic web browsing
- **Combine with**: TLS tunneling for double protection

### Iran
- **Recommended settings**: Variable delays (1-50ms) to avoid detection
- **Combine with**: HTTP mimicry for enhanced effectiveness

### Russia
- **Recommended settings**: Low delays (1-10ms) to maintain performance
- **Combine with**: Packet padding for size obfuscation

## Best Practices

### 1. Delay Selection
```go
// For interactive applications (SSH, messaging)
config := &obfuscation.TimingObfsConfig{
    MinDelay:     1 * time.Millisecond,
    MaxDelay:     10 * time.Millisecond,
    RandomJitter: true,
}

// For bulk transfer (file downloads)
config := &obfuscation.TimingObfsConfig{
    MinDelay:     5 * time.Millisecond,
    MaxDelay:     50 * time.Millisecond,
    RandomJitter: true,
}

// For video streaming
config := &obfuscation.TimingObfsConfig{
    MinDelay:     2 * time.Millisecond,
    MaxDelay:     15 * time.Millisecond,
    RandomJitter: true,
}
```

### 2. Combination with Other Methods
```go
// Recommended combination for maximum effectiveness
config := &obfuscation.Config{
    EnabledMethods: []obfuscation.ObfuscationMethod{
        obfuscation.MethodTimingObfs,     // Hide timing patterns
        obfuscation.MethodPacketPadding,  // Hide size patterns
        obfuscation.MethodHTTPMimicry,    // Hide content patterns
    },
    PrimaryMethod:   obfuscation.MethodHTTPMimicry,
    FallbackMethods: []obfuscation.ObfuscationMethod{
        obfuscation.MethodTimingObfs,
        obfuscation.MethodPacketPadding,
    },
    AutoDetection: true,
}
```

### 3. Performance Tuning
```go
// Balance security and performance
func calculateOptimalDelay(applicationMode string) (time.Duration, time.Duration) {
    switch applicationMode {
    case "gaming":
        return 1*time.Millisecond, 5*time.Millisecond   // Low latency
    case "browsing":
        return 5*time.Millisecond, 25*time.Millisecond  // Medium latency
    case "bulk":
        return 10*time.Millisecond, 100*time.Millisecond // High latency OK
    default:
        return 1*time.Millisecond, 50*time.Millisecond   // Balanced
    }
}
```

## Troubleshooting

### Common Issues

**High Latency:**
```go
// Problem: Delays too high for interactive applications
config.MaxDelay = 5 * time.Millisecond  // Reduce maximum delay

// Problem: Fixed delays too predictable
config.RandomJitter = true  // Enable randomization
```

**Detection Still Occurring:**
```go
// Combine with other obfuscation methods
config.EnabledMethods = []obfuscation.ObfuscationMethod{
    obfuscation.MethodTimingObfs,
    obfuscation.MethodHTTPMimicry,  // Add content obfuscation
}
```

**Performance Issues:**
```go
// Reduce delay ranges for better throughput
config.MinDelay = 100 * time.Microsecond  // Microsecond precision
config.MaxDelay = 5 * time.Millisecond    // Lower maximum
```

### Monitoring and Metrics

```go
// Monitor timing obfuscation performance
metrics := timing.GetMetrics()
fmt.Printf("Packets processed: %d\n", metrics.PacketsProcessed)
fmt.Printf("Average delay: %v\n", metrics.AvgProcessTime)
fmt.Printf("Errors: %d\n", metrics.Errors)

// Check if delays are within expected range
if metrics.AvgProcessTime < config.MinDelay {
    log.Println("Warning: Average delay below minimum")
}
if metrics.AvgProcessTime > config.MaxDelay {
    log.Println("Warning: Average delay above maximum")
}
```

## Implementation Details

### Core Algorithm
```go
func (t *TimingObfuscation) calculateDelay() time.Duration {
    if !t.config.RandomJitter {
        return t.config.MaxDelay  // Fixed delay
    }

    // Exponential distribution for realistic timing
    delayRange := t.config.MaxDelay - t.config.MinDelay
    randomFactor := mathrand.ExpFloat64()
    if randomFactor > 3.0 {
        randomFactor = 3.0  // Cap extreme values
    }

    delay := t.config.MinDelay + 
             time.Duration(float64(delayRange)*randomFactor/3.0)

    if delay > t.config.MaxDelay {
        delay = t.config.MaxDelay
    }

    return delay
}
```

### Connection Wrapper
```go
type timingObfuscationConn struct {
    net.Conn
    timing *TimingObfuscation
}

func (c *timingObfuscationConn) Write(b []byte) (n int, err error) {
    // Apply timing delay before writing
    if c.timing.config.Enabled {
        delay := c.timing.calculateDelay()
        if delay > 0 {
            time.Sleep(delay)
        }
    }
    return c.Conn.Write(b)
}
```

## Related Documentation

- [Packet Padding](packet_padding.md) - Size-based obfuscation
- [HTTP Mimicry](http_mimicry.md) - Content-based obfuscation
- [Obfuscation Engine](README.md) - Main engine documentation
- [Regional Profiles](../regional_profiles.md) - Country-specific settings 