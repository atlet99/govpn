# Flow Watermarking (Водяные знаки в трафике)

## Overview

Flow Watermarking - это продвинутый метод анти-статистического анализа, который добавляет скрытые водяные знаки в поток данных для искажения их статистических характеристик. В отличие от других методов обфускации, Flow Watermarking модифицирует сами данные таким образом, чтобы затруднить корреляционный анализ и обнаружение паттернов трафика системами DPI.

## How It Works

### Statistical Analysis Vulnerabilities
Системы анализа трафика используют статистические методы для выявления VPN:
- **Корреляционный анализ**: Поиск повторяющихся паттернов в данных
- **Частотный анализ**: Анализ распределения байтов в пакетах  
- **Энтропийный анализ**: Измерение случайности данных
- **Временной анализ**: Корреляция между временем и содержимым
- **Поточный анализ**: Анализ характеристик всего потока данных

### Flow Watermarking Mechanism
Метод Flow Watermarking работает следующим образом:

1. **Генерация водяного знака**: Создание уникальной последовательности на основе криптографического ключа
2. **Паттерн-генерация**: Создание статистических паттернов на основе частотных полос
3. **Детерминистичная модификация**: Применение водяного знака детерминистично для обеспечения обратимости
4. **Ротация паттернов**: Периодическое изменение паттернов для повышения безопасности
5. **Статистическое искажение**: Изменение статистических характеристик без нарушения целостности данных

## Configuration

### Basic Configuration
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
```

### Configuration Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `Enabled` | bool | Enable/disable flow watermarking | true |
| `WatermarkKey` | []byte | Cryptographic key for watermark generation | auto-generated (32 bytes) |
| `PatternInterval` | time.Duration | Interval for pattern updates | 500ms |
| `PatternStrength` | float64 | Strength of watermark patterns (0.0-1.0) | 0.3 |
| `NoiseLevel` | float64 | Noise level for randomization (0.0-1.0) | 0.1 |
| `RotationPeriod` | time.Duration | Period for pattern rotation | 5 minutes |
| `StatisticalMode` | bool | Use statistical or simple XOR mode | true |
| `FrequencyBands` | []int | Frequency bands for pattern generation | [1,2,5,10,20,50] |

### Advanced Settings

#### High Security Mode
```go
config := &obfuscation.FlowWatermarkConfig{
    Enabled:         true,
    WatermarkKey:    []byte("high-security-key-32-bytes-long!"),
    PatternInterval: 100 * time.Millisecond,
    PatternStrength: 0.8,
    NoiseLevel:      0.3,
    RotationPeriod:  1 * time.Minute,
    StatisticalMode: true,
    FrequencyBands:  []int{1, 2, 3, 5, 8, 13, 21, 34, 55, 89},
}
```

#### Performance Mode
```go
config := &obfuscation.FlowWatermarkConfig{
    Enabled:         true,
    WatermarkKey:    []byte("performance-key-for-speed-32b!"),
    PatternInterval: 2 * time.Second,
    PatternStrength: 0.2,
    NoiseLevel:      0.05,
    RotationPeriod:  10 * time.Minute,
    StatisticalMode: false, // Use faster XOR mode
    FrequencyBands:  []int{1, 5, 10},
}
```

#### Stealth Mode
```go
config := &obfuscation.FlowWatermarkConfig{
    Enabled:         true,
    WatermarkKey:    []byte("stealth-mode-watermark-key-32b!"),
    PatternInterval: 1 * time.Second,
    PatternStrength: 0.1, // Very subtle
    NoiseLevel:      0.02,
    RotationPeriod:  15 * time.Minute,
    StatisticalMode: true,
    FrequencyBands:  []int{2, 3, 7, 11},
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

// Create flow watermarking configuration
config := &obfuscation.FlowWatermarkConfig{
    Enabled:         true,
    WatermarkKey:    []byte("demo-watermark-key-32-bytes-!@#"),
    PatternInterval: 300 * time.Millisecond,
    PatternStrength: 0.4,
    NoiseLevel:      0.15,
    RotationPeriod:  3 * time.Minute,
    StatisticalMode: true,
    FrequencyBands:  []int{1, 2, 5, 10, 20},
}

// Create flow watermarking obfuscator
logger := log.New(os.Stdout, "[WATERMARK] ", log.LstdFlags)
watermark, err := obfuscation.NewFlowWatermark(config, logger)
if err != nil {
    log.Fatalf("Failed to create flow watermark: %v", err)
}

// Process data with watermarking
data := []byte("VPN packet data with sensitive information")
obfuscated, err := watermark.Obfuscate(data)
if err != nil {
    log.Fatalf("Obfuscation failed: %v", err)
}

// Data is modified but same length
fmt.Printf("Original:    %x\n", data)
fmt.Printf("Watermarked: %x\n", obfuscated)
fmt.Printf("Same length: %v\n", len(data) == len(obfuscated))

// Restore original data
deobfuscated, err := watermark.Deobfuscate(obfuscated)
if err != nil {
    log.Fatalf("Deobfuscation failed: %v", err)
}

fmt.Printf("Restored:    %x\n", deobfuscated)
fmt.Printf("Integrity:   %v\n", string(data) == string(deobfuscated))
```

### Engine Integration
```go
// Configure engine with flow watermarking
engineConfig := &obfuscation.Config{
    EnabledMethods:  []obfuscation.ObfuscationMethod{obfuscation.MethodFlowWatermark},
    PrimaryMethod:   obfuscation.MethodFlowWatermark,
    FallbackMethods: []obfuscation.ObfuscationMethod{},
    AutoDetection:   false,
    FlowWatermark: obfuscation.FlowWatermarkConfig{
        Enabled:         true,
        WatermarkKey:    []byte("engine-watermark-key-32-bytes!!"),
        PatternInterval: 400 * time.Millisecond,
        PatternStrength: 0.5,
        NoiseLevel:      0.2,
        RotationPeriod:  4 * time.Minute,
        StatisticalMode: true,
        FrequencyBands:  []int{1, 3, 7, 15, 31},
    },
}

engine, err := obfuscation.NewEngine(engineConfig, logger)
if err != nil {
    log.Fatalf("Failed to create engine: %v", err)
}
defer engine.Close()

// Process packets with flow watermarking
packets := [][]byte{
    []byte("Authentication packet"),
    []byte("VPN tunnel establishment"),
    []byte("Encrypted user data"),
    []byte("Keep-alive signal"),
}

for i, packet := range packets {
    // Apply watermarking
    obfuscated, err := engine.ObfuscateData(packet)
    if err != nil {
        log.Printf("Failed to obfuscate packet %d: %v", i, err)
        continue
    }
    
    // Show statistical modification
    originalSum := calculateChecksum(packet)
    watermarkedSum := calculateChecksum(obfuscated)
    
    fmt.Printf("Packet %d: checksum %d -> %d (Δ%d)\n", 
        i+1, originalSum, watermarkedSum, watermarkedSum-originalSum)
    
    // Verify integrity
    deobfuscated, err := engine.DeobfuscateData(obfuscated)
    if err != nil {
        log.Printf("Failed to deobfuscate packet %d: %v", i, err)
        continue
    }
    
    fmt.Printf("Integrity check: %v\n", 
        string(packet) == string(deobfuscated))
}

func calculateChecksum(data []byte) int {
    sum := 0
    for _, b := range data {
        sum += int(b)
    }
    return sum % 1000
}
```

### Connection Wrapping (Advanced)
```go
// Wrap network connection with flow watermarking
wrappedConn, err := watermark.WrapConn(originalConn)
if err != nil {
    log.Fatalf("Failed to wrap connection: %v", err)
}

// The connection wrapper automatically:
// 1. Applies watermarking to all outgoing data
// 2. Removes watermarking from all incoming data
// 3. Maintains flow state for continuous watermarking

// Normal read/write operations
data := make([]byte, 1024)
n, err := wrappedConn.Read(data)  // Automatic deobfuscation
if err != nil {
    log.Printf("Read error: %v", err)
}

_, err = wrappedConn.Write([]byte("real data"))  // Automatic obfuscation
if err != nil {
    log.Printf("Write error: %v", err)
}

// Close connection
wrappedConn.Close()
```

## Performance Considerations

### Timing Overhead
```go
// Benchmark results (Apple M3 Pro):
BenchmarkFlowWatermark-12         536376              2135 ns/op            1152 B/op          1 allocs/op
```

Flow Watermarking performance characteristics:
- **Processing time**: ~2.1μs per operation (includes statistical computation)
- **Memory allocation**: 1152 bytes per operation (result buffer)
- **CPU usage**: Moderate due to statistical calculations

### Performance Comparison

Relative performance ranking of obfuscation methods:
1. **TLS Tunneling**: ~86ns/op (fastest - passthrough)
2. **Traffic Padding**: ~120ns/op (metadata only)
3. **Packet Padding**: ~440ns/op (padding operations)
4. **HTTP Mimicry**: ~671ns/op (HTTP formatting)
5. **XOR Cipher**: ~1041ns/op (XOR operations)
6. **Flow Watermarking**: ~2135ns/op (statistical processing)
7. **Timing Obfuscation**: ~262μs/op (intentional delays)

### Optimization Strategies

#### Memory Optimization
```go
// Use smaller frequency bands for lower memory usage
config := &obfuscation.FlowWatermarkConfig{
    FrequencyBands: []int{1, 5, 10}, // Reduced from default 6 bands
    PatternStrength: 0.2,            // Lower computational complexity
}
```

#### CPU Optimization
```go
// Use non-statistical mode for faster processing
config := &obfuscation.FlowWatermarkConfig{
    StatisticalMode: false,           // Simple XOR mode
    PatternStrength: 0.3,             // Moderate strength
    NoiseLevel:      0.05,            // Lower noise
}
```

## Security Analysis

### Effectiveness Against Analysis

**Strengths:**
- Modifies actual data content, not just metadata
- Creates unique statistical fingerprints per key
- Resistant to frequency analysis attacks
- Effective against correlation analysis
- Pattern rotation prevents long-term analysis
- Supports both statistical and cryptographic modes

**Limitations:**
- Introduces computational overhead
- May affect data compressibility
- Not effective against payload inspection (combine with encryption)
- Requires secure key management
- Statistical modifications may be detectable with sophisticated analysis

### Cryptographic Security

The watermarking system provides:
```go
// Watermark sequence generation
keySum := int64(0)
for _, b := range watermarkKey {
    keySum += int64(b)
}
seqRng := mathrand.New(mathrand.NewSource(keySum))
```

**Security features:**
- Deterministic key-based watermark generation
- Cryptographically secure random key generation
- Pattern rotation for forward security
- Reversible statistical modifications
- No secret data leakage in watermarked output

### Attack Resistance

**Resistant to:**
- Frequency analysis attacks
- Statistical correlation analysis
- Pattern recognition systems
- Flow analysis attacks
- Replay attacks (due to pattern rotation)

**Vulnerable to:**
- Known plaintext attacks (if pattern discovered)
- Sophisticated statistical analysis with large datasets
- Timing analysis (use with timing obfuscation)
- Active probing attacks

## Regional Considerations

### China
- **Recommended settings**: High pattern strength (0.6-0.8) with frequent rotation (1-2 minutes)
- **Combine with**: TLS tunneling for additional protection

### Iran  
- **Recommended settings**: Moderate strength (0.4-0.6) with statistical mode
- **Combine with**: HTTP mimicry for protocol-level obfuscation

### Russia
- **Recommended settings**: Lower strength (0.2-0.4) for performance, longer rotation (10+ minutes)
- **Combine with**: Packet padding for size obfuscation

## Best Practices

### 1. Key Management
```go
// Generate cryptographically secure keys
key := make([]byte, 32)
if _, err := crypto/rand.Read(key); err != nil {
    log.Fatal("Failed to generate secure key")
}

// Store keys securely
config := &obfuscation.FlowWatermarkConfig{
    WatermarkKey: key,
    // ... other settings
}
```

### 2. Pattern Strength Selection
```go
// Choose strength based on threat model
func selectPatternStrength(threatLevel string) float64 {
    switch threatLevel {
    case "low":
        return 0.1  // Minimal statistical modification
    case "medium":
        return 0.3  // Balanced performance/security
    case "high":
        return 0.6  // Strong statistical distortion
    case "maximum":
        return 0.8  // Maximum distortion
    default:
        return 0.3
    }
}
```

### 3. Frequency Band Configuration
```go
// Optimize frequency bands for specific applications
func configureForApplication(appType string) []int {
    switch appType {
    case "web":
        return []int{1, 2, 5, 10, 20}     // Standard web traffic patterns
    case "streaming":
        return []int{2, 4, 8, 16, 32}     // Video streaming patterns
    case "gaming":
        return []int{1, 3, 7, 15}         // Low-latency gaming patterns
    case "file_transfer":
        return []int{5, 10, 20, 50, 100}  // Bulk transfer patterns
    default:
        return []int{1, 2, 5, 10, 20, 50}
    }
}
```

### 4. Combination with Other Methods
```go
// Recommended combination for maximum effectiveness
config := &obfuscation.Config{
    EnabledMethods: []obfuscation.ObfuscationMethod{
        obfuscation.MethodFlowWatermark,  // Statistical distortion
        obfuscation.MethodTLSTunnel,      // Protocol-level obfuscation
        obfuscation.MethodTimingObfs,     // Timing obfuscation
        obfuscation.MethodTrafficPadding, // Traffic volume masking
    },
    PrimaryMethod:   obfuscation.MethodTLSTunnel,
    FallbackMethods: []obfuscation.ObfuscationMethod{
        obfuscation.MethodFlowWatermark,
        obfuscation.MethodTimingObfs,
    },
    AutoDetection: true,
}
```

## Troubleshooting

### Common Issues

**High CPU Usage:**
```go
// Reduce computational complexity
config.StatisticalMode = false    // Use XOR mode
config.PatternStrength = 0.2      // Lower strength
config.FrequencyBands = []int{1, 5, 10}  // Fewer bands
```

**Memory Usage Concerns:**
```go
// Optimize memory allocation
config.PatternInterval = 1 * time.Second  // Less frequent updates
config.RotationPeriod = 15 * time.Minute  // Longer rotation
```

**Detection Still Occurring:**
```go
// Increase watermarking strength
config.PatternStrength = 0.7      // Higher strength
config.NoiseLevel = 0.3           // More noise
config.RotationPeriod = 30 * time.Second  // Faster rotation
```

**Data Corruption:**
```go
// Verify configuration
if config.PatternStrength > 1.0 {
    config.PatternStrength = 0.5  // Valid range: 0.0-1.0
}
if config.NoiseLevel > 1.0 {
    config.NoiseLevel = 0.2       // Valid range: 0.0-1.0
}
```

### Monitoring and Metrics

```go
// Monitor watermarking performance
metrics := watermark.GetMetrics()
fmt.Printf("Packets processed: %d\n", metrics.PacketsProcessed)
fmt.Printf("Bytes processed: %d\n", metrics.BytesProcessed)
fmt.Printf("Average processing time: %v\n", metrics.AvgProcessTime)
fmt.Printf("Errors: %d\n", metrics.Errors)

// Calculate statistical effectiveness
func calculateEffectiveness(original, watermarked []byte) float64 {
    differences := 0
    for i := 0; i < len(original) && i < len(watermarked); i++ {
        if original[i] != watermarked[i] {
            differences++
        }
    }
    return float64(differences) / float64(len(original)) * 100.0
}
```

## Implementation Details

### Watermark Sequence Generation
```go
func generateWatermarkSequence(key []byte) []byte {
    // Create deterministic sequence from key
    keySum := int64(0)
    for _, b := range key {
        keySum += int64(b)
    }
    
    rng := mathrand.New(mathrand.NewSource(keySum))
    sequence := make([]byte, 256)
    
    for i := range sequence {
        sequence[i] = byte(rng.Intn(256))
    }
    
    return sequence
}
```

### Statistical Pattern Generation
```go
func generateStatisticalPattern(key []byte, frequencyBands []int) []float64 {
    patternLength := len(frequencyBands) * 8
    pattern := make([]float64, patternLength)
    
    for i := range pattern {
        keyIndex := i % len(key)
        keyVal := float64(key[keyIndex]) / 255.0
        
        frequency := float64(frequencyBands[i%len(frequencyBands)])
        
        // Generate pattern with frequency-based scaling
        value := patternStrength * (0.5 + 0.5*keyVal)
        value *= (0.5 + 0.5*frequency/100.0)
        value += noiseLevel * (mathrand.Float64() - 0.5)
        
        pattern[i] = value
    }
    
    return pattern
}
```

### Deterministic Application
```go
func applyWatermarkDeterministic(data []byte, watermarkSeq []byte, pattern []float64) []byte {
    result := make([]byte, len(data))
    
    for i, b := range data {
        // Deterministic pattern index based on position and watermark
        patternIdx := (i + int(watermarkSeq[i%len(watermarkSeq)])) % len(pattern)
        patternVal := pattern[patternIdx]
        
        watermarkByte := watermarkSeq[i%len(watermarkSeq)]
        
        // Apply watermark adjustment
        adjustment := int(patternVal * float64(watermarkByte) / 255.0 * 16) - 8
        
        newVal := int(b) + adjustment
        if newVal < 0 {
            newVal += 256
        } else if newVal > 255 {
            newVal -= 256
        }
        
        result[i] = byte(newVal)
    }
    
    return result
}
```

## Related Documentation

- [Timing Obfuscation](timing_obfuscation.md) - Timing-based obfuscation
- [Traffic Padding](traffic_padding.md) - Volume-based obfuscation  
- [Packet Padding](packet_padding.md) - Size-based obfuscation
- [TLS Tunneling](tls_tunneling.md) - Protocol-level obfuscation
- [Obfuscation Engine](README.md) - Main engine documentation
- [Regional Profiles](../regional_profiles.md) - Country-specific settings 