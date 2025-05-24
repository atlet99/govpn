# Packet Padding Obfuscation (Рандомизация размеров пакетов)

## Описание

Packet Padding - это метод анти-статистической обфускации, который рандомизирует размеры пакетов VPN трафика путем добавления случайного количества байт padding'а. Этот метод эффективен против систем анализа трафика, которые используют статистические характеристики пакетов для идентификации VPN соединений.

## Принцип работы

1. **Добавление заголовка**: К каждому пакету добавляется 4-байтовый заголовок с размером оригинальных данных
2. **Случайный padding**: Добавляется случайное количество байт (в пределах MinPadding-MaxPadding)
3. **Криптографически стойкие случайные данные**: Padding заполняется криптографически случайными байтами
4. **Восстановление**: При деобфускации извлекается оригинальный размер из заголовка и отбрасывается padding

## Конфигурация

```go
config := &obfuscation.PacketPaddingConfig{
    Enabled:       true,  // Включить обфускацию размеров пакетов
    MinPadding:    10,    // Минимальное количество байт padding'а
    MaxPadding:    256,   // Максимальное количество байт padding'а
    RandomizeSize: true,  // Рандомизировать размер padding'а
}
```

### Параметры конфигурации

- **Enabled**: Включает/выключает Packet Padding. По умолчанию: `true`
- **MinPadding**: Минимальное количество байт для добавления. По умолчанию: `1`
- **MaxPadding**: Максимальное количество байт для добавления. По умолчанию: `256`
- **RandomizeSize**: Если `true`, размер padding'а рандомизируется между MinPadding и MaxPadding. Если `false`, всегда используется MinPadding

## Использование

### Создание Packet Padding обфускатора

```go
logger := log.New(os.Stdout, "[PADDING] ", log.LstdFlags)

config := &obfuscation.PacketPaddingConfig{
    Enabled:       true,
    MinPadding:    10,
    MaxPadding:    100,
    RandomizeSize: true,
}

padding, err := obfuscation.NewPacketPadding(config, logger)
if err != nil {
    log.Fatalf("Failed to create packet padding: %v", err)
}
```

### Использование с движком обфускации

```go
engineConfig := &obfuscation.Config{
    EnabledMethods:  []obfuscation.ObfuscationMethod{obfuscation.MethodPacketPadding},
    PrimaryMethod:   obfuscation.MethodPacketPadding,
    PacketPadding: obfuscation.PacketPaddingConfig{
        Enabled:       true,
        MinPadding:    20,
        MaxPadding:    200,
        RandomizeSize: true,
    },
}

engine, err := obfuscation.NewEngine(engineConfig, logger)
if err != nil {
    log.Fatalf("Failed to create engine: %v", err)
}
defer engine.Close()

// Обфускация данных
obfuscated, err := engine.ObfuscateData([]byte("VPN packet data"))
if err != nil {
    log.Printf("Obfuscation failed: %v", err)
}

// Деобфускация данных
deobfuscated, err := engine.DeobfuscateData(obfuscated)
if err != nil {
    log.Printf("Deobfuscation failed: %v", err)
}
```

### Обертка соединений

```go
// Оборачивание существующего соединения
wrappedConn, err := padding.WrapConn(originalConn)
if err != nil {
    log.Printf("Failed to wrap connection: %v", err)
}

// Использование обернутого соединения
_, err = wrappedConn.Write([]byte("VPN data"))
if err != nil {
    log.Printf("Write failed: %v", err)
}
```

## Метрики

Packet Padding обфускатор собирает следующие метрики:

- **PacketsProcessed**: Количество обработанных пакетов
- **BytesProcessed**: Количество обработанных байт (включая padding)
- **Errors**: Количество ошибок
- **AvgProcessTime**: Среднее время обработки
- **LastUsed**: Время последнего использования

```go
metrics := padding.GetMetrics()
fmt.Printf("Packets: %d, Bytes: %d, Errors: %d\n", 
    metrics.PacketsProcessed, 
    metrics.BytesProcessed, 
    metrics.Errors)
```

## Форматы данных

### Структура пакета с padding'ом

```
+-------------------+-------------------+-------------------+
| Original Length   | Original Data     | Random Padding    |
| (4 bytes)         | (variable length) | (variable length) |
+-------------------+-------------------+-------------------+
```

- **Original Length**: 32-битное число в big-endian формате, содержащее размер оригинальных данных
- **Original Data**: Оригинальные данные пакета
- **Random Padding**: Криптографически случайные байты для маскировки размера

### Пример

Для пакета "Hello" (5 байт) с 10 байтами padding'а:

```
[0x00, 0x00, 0x00, 0x05] + "Hello" + [random 10 bytes]
      ^                     ^              ^
   Размер (5)         Оригинальные    Случайный
                        данные         padding
```

## Производительность

Packet Padding имеет умеренные накладные расходы из-за необходимости генерации случайных данных и увеличения размера пакетов. Бенчмарки показывают:

```
BenchmarkPacketPaddingObfuscation-12    2734474    438.7 ns/op    2304 B/op    1 allocs/op
```

### Факторы влияющие на производительность

1. **Размер padding'а**: Чем больше padding, тем больше времени на генерацию случайных данных
2. **Размер исходного пакета**: Небольшие пакеты имеют больший относительный overhead
3. **Криптографическая генерация**: Использование `crypto/rand` медленнее обычного PRNG

### Рекомендации по настройке производительности

- Используйте умеренные размеры padding'а (10-200 байт) для баланса безопасности и производительности
- Для высоконагруженных систем рассмотрите уменьшение MaxPadding
- Комбинируйте с другими методами обфускации для уменьшения зависимости от больших размеров padding'а

## Безопасность

### Преимущества

1. **Маскировка статистических характеристик**: Рандомизация размеров пакетов затрудняет статистический анализ
2. **Криптографически стойкий padding**: Использование `crypto/rand` для генерации случайных данных
3. **Адаптивность**: Настраиваемые диапазоны padding'а для разных сценариев
4. **Прозрачность**: Автоматическое добавление/удаление padding'а без изменения логики приложения

### Рекомендации по безопасности

1. **Используйте достаточные размеры padding'а**: Минимум 10-20 байт для эффективной маскировки
2. **Рандомизируйте размеры**: Всегда включайте `RandomizeSize: true`
3. **Комбинируйте методы**: Используйте совместно с TLS Tunneling или другими методами
4. **Мониторьте производительность**: Балансируйте размер padding'а и производительность

### Ограничения

- **Увеличение трафика**: Добавляет overhead в размере MinPadding-MaxPadding байт на пакет
- **Не скрывает временные характеристики**: Только маскирует размеры пакетов
- **Возможность fingerprinting**: Постоянное добавление padding'а может быть обнаружено

## Региональные профили

Packet Padding может быть включен в региональные профили как дополнительный метод:

```go
// China Profile с агрессивным padding'ом
PacketPadding: obfuscation.PacketPaddingConfig{
    Enabled:       true,
    MinPadding:    50,
    MaxPadding:    300,
    RandomizeSize: true,
},

// Iran Profile с умеренным padding'ом
PacketPadding: obfuscation.PacketPaddingConfig{
    Enabled:       true,
    MinPadding:    20,
    MaxPadding:    100,
    RandomizeSize: true,
},

// Russia Profile с легким padding'ом для производительности
PacketPadding: obfuscation.PacketPaddingConfig{
    Enabled:       true,
    MinPadding:    10,
    MaxPadding:    50,
    RandomizeSize: true,
},
```

## Совместимость

- **Go версия**: 1.22+
- **Криптография**: `crypto/rand` для генерации случайных данных
- **Платформы**: Linux, macOS, Windows
- **Комбинирование**: Совместим со всеми другими методами обфускации

## Примеры использования

### Базовое использование

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/atlet99/govpn/pkg/obfuscation"
)

func main() {
    config := &obfuscation.PacketPaddingConfig{
        Enabled:       true,
        MinPadding:    10,
        MaxPadding:    50,
        RandomizeSize: true,
    }
    
    padding, err := obfuscation.NewPacketPadding(config, log.Default())
    if err != nil {
        log.Fatal(err)
    }
    
    data := []byte("Secret VPN data")
    obfuscated, err := padding.Obfuscate(data)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Original: %d bytes\n", len(data))
    fmt.Printf("Padded: %d bytes\n", len(obfuscated))
    
    deobfuscated, err := padding.Deobfuscate(obfuscated)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Success: %s\n", string(deobfuscated))
}
```

### Использование с движком

```go
package main

import (
    "log"
    "time"
    
    "github.com/atlet99/govpn/pkg/obfuscation"
)

func main() {
    config := &obfuscation.Config{
        EnabledMethods: []obfuscation.ObfuscationMethod{
            obfuscation.MethodPacketPadding,
            obfuscation.MethodXORCipher,
        },
        PrimaryMethod: obfuscation.MethodPacketPadding,
        FallbackMethods: []obfuscation.ObfuscationMethod{
            obfuscation.MethodXORCipher,
        },
        AutoDetection: true,
        SwitchThreshold: 3,
        DetectionTimeout: 5 * time.Second,
        PacketPadding: obfuscation.PacketPaddingConfig{
            Enabled:       true,
            MinPadding:    15,
            MaxPadding:    75,
            RandomizeSize: true,
        },
        XORKey: []byte("my-secret-key"),
    }
    
    engine, err := obfuscation.NewEngine(config, log.Default())
    if err != nil {
        log.Fatal(err)
    }
    defer engine.Close()
    
    // Обработка пакетов с автоматическим переключением
    for i := 0; i < 10; i++ {
        data := fmt.Sprintf("Packet %d data", i)
        
        obfuscated, err := engine.ObfuscateData([]byte(data))
        if err != nil {
            log.Printf("Obfuscation failed: %v", err)
            continue
        }
        
        deobfuscated, err := engine.DeobfuscateData(obfuscated)
        if err != nil {
            log.Printf("Deobfuscation failed: %v", err)
            continue
        }
        
        log.Printf("Processed packet %d successfully", i+1)
    }
    
    // Показать метрики
    metrics := engine.GetMetrics()
    log.Printf("Total packets: %d, switches: %d", 
        metrics.TotalPackets, metrics.MethodSwitches)
}
```

Полные примеры использования Packet Padding доступны в:
- `examples/obfuscation_demo.go` - демонстрация всех возможностей
- `pkg/obfuscation/obfuscation_test.go` - unit тесты 