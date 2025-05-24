# TLS Tunneling Obfuscation

## Описание

TLS Tunneling - это метод обфускации VPN трафика, который инкапсулирует данные в легитимные TLS соединения. Этот метод эффективен против DPI (Deep Packet Inspection) систем, поскольку трафик выглядит как обычные HTTPS соединения.

## Принцип работы

1. **Генерация сертификатов**: Автоматически создается самоподписанный сертификат для TLS соединения
2. **TLS обертка**: VPN трафик оборачивается в TLS записи
3. **ALPN поддержка**: Поддержка Application-Layer Protocol Negotiation (HTTP/2, HTTP/1.1)
4. **Fake HTTP headers**: Опциональное добавление поддельных HTTP заголовков для дополнительной маскировки

## Конфигурация

```go
config := &obfuscation.TLSTunnelConfig{
    ServerName:      "secure.example.com",  // Имя сервера для SNI
    ALPN:            []string{"h2", "http/1.1"}, // ALPN протоколы
    FakeHTTPHeaders: true,                   // Добавление поддельных HTTP заголовков
}
```

### Параметры конфигурации

- **ServerName**: Имя сервера для Server Name Indication (SNI). По умолчанию: "example.com"
- **ALPN**: Список протоколов для Application-Layer Protocol Negotiation. По умолчанию: ["h2", "http/1.1"]
- **FakeHTTPHeaders**: Включает добавление поддельных HTTP заголовков с 10% вероятностью

## Использование

### Создание TLS Tunnel обфускатора

```go
logger := log.New(os.Stdout, "[TLS] ", log.LstdFlags)

config := &obfuscation.TLSTunnelConfig{
    ServerName:      "secure.example.com",
    ALPN:            []string{"h2", "http/1.1"},
    FakeHTTPHeaders: true,
}

tunnel, err := obfuscation.NewTLSTunnel(config, logger)
if err != nil {
    log.Fatalf("Failed to create TLS tunnel: %v", err)
}
```

### Использование с движком обфускации

```go
engineConfig := &obfuscation.Config{
    EnabledMethods:  []obfuscation.ObfuscationMethod{obfuscation.MethodTLSTunnel},
    PrimaryMethod:   obfuscation.MethodTLSTunnel,
    TLSTunnel: obfuscation.TLSTunnelConfig{
        ServerName:      "secure.example.com",
        ALPN:            []string{"h2"},
        FakeHTTPHeaders: true,
    },
}

engine, err := obfuscation.NewEngine(engineConfig, logger)
if err != nil {
    log.Fatalf("Failed to create engine: %v", err)
}
defer engine.Close()

// Обфускация данных
obfuscated, err := engine.ObfuscateData([]byte("VPN traffic data"))
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
wrappedConn, err := tunnel.WrapConn(originalConn)
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

TLS Tunnel обфускатор собирает следующие метрики:

- **PacketsProcessed**: Количество обработанных пакетов
- **BytesProcessed**: Количество обработанных байт
- **Errors**: Количество ошибок
- **AvgProcessTime**: Среднее время обработки
- **LastUsed**: Время последнего использования

```go
metrics := tunnel.GetMetrics()
fmt.Printf("Packets: %d, Bytes: %d, Errors: %d\n", 
    metrics.PacketsProcessed, 
    metrics.BytesProcessed, 
    metrics.Errors)
```

## Региональные профили

TLS Tunneling используется в следующих региональных профилях:

### China Profile
- **Основной метод**: TLS Tunneling
- **Fallback**: HTTP Mimicry, XOR Cipher
- **Порог переключения**: 2 ошибки
- **Таймаут обнаружения**: 5 секунд

### Iran Profile
- **Fallback метод**: TLS Tunneling (после HTTP Mimicry)
- **Порог переключения**: 3 ошибки
- **Таймаут обнаружения**: 10 секунд

### Russia Profile
- **Основной метод**: TLS Tunneling
- **Fallback**: HTTP Mimicry, XOR Cipher
- **Порог переключения**: 4 ошибки
- **Таймаут обнаружения**: 15 секунд

## Безопасность

### Особенности реализации

1. **Самоподписанные сертификаты**: Автоматически генерируются для каждого экземпляра
2. **InsecureSkipVerify**: Используется для обфускации (не для продакшена без дополнительной проверки)
3. **Минимальная версия TLS**: TLS 1.2
4. **Поддержка IPv4/IPv6**: Сертификаты включают localhost и loopback адреса

### Рекомендации

- Используйте различные ServerName для разных серверов
- Настройте ALPN протоколы в соответствии с целевой средой
- Включите FakeHTTPHeaders для дополнительной маскировки
- Комбинируйте с другими методами обфускации для повышения эффективности

## Производительность

TLS Tunneling имеет минимальные накладные расходы на обработку данных, поскольку основная работа выполняется на уровне TLS соединения. Бенчмарки показывают:

```
BenchmarkTLSTunnelObfuscation-8    1000000    1200 ns/op    0 allocs/op
```

## Совместимость

- **Go версия**: 1.22+
- **TLS версии**: 1.2, 1.3
- **Протоколы**: HTTP/1.1, HTTP/2
- **Платформы**: Linux, macOS, Windows

## Примеры использования

Полные примеры использования TLS Tunneling доступны в:
- `examples/obfuscation_demo.go` - демонстрация всех возможностей
- `pkg/obfuscation/obfuscation_test.go` - unit тесты 