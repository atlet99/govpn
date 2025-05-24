# GoVPN Traffic Obfuscation

Модуль обфускации трафика GoVPN предназначен для обхода блокировок DPI (Deep Packet Inspection) и цензуры в различных регионах мира.

## Возможности

### ✅ Реализованные функции

- **XOR Obfuscation** - быстрое XOR шифрование поверх основного шифрования
- **TLS Tunneling** - инкапсуляция VPN трафика в легитимные TLS соединения
- **HTTP Mimicry** - маскировка VPN трафика под легитимные HTTP запросы/ответы
- **Packet Padding** - рандомизация размеров пакетов для анти-статистического анализа
- **Timing Obfuscation** - изменение временных интервалов между пакетами для маскировки паттернов трафика
- **Traffic Padding** - добавление фиктивного трафика для маскировки паттернов активности
- **Flow Watermarking** - добавление скрытых водяных знаков для искажения статистических характеристик
- **Модульная архитектура** - легко добавлять новые методы обфускации
- **Автоматическое переключение** - детектор DPI блокировок с автоматическим переключением методов
- **Региональные профили** - оптимизированные настройки для разных стран (Китай, Иран, Россия)
- **Метрики производительности** - детальная статистика работы обфускаторов
- **Адаптивная обфускация** - динамическое переключение при обнаружении блокировки

- **DNS Tunneling** - передача данных через DNS запросы (резервный канал связи)
- **HTTP Steganography** ✅ - скрытие VPN данных внутри HTTP трафика с использованием стеганографических техник

## Быстрый старт

### Использование в CLI

```bash
# Включить обфускацию с XOR методом
./govpn-server --obfuscation --obfuscation-method=xor_cipher

# Использовать региональный профиль для Китая
./govpn-server --obfuscation --regional-profile=china

# Указать собственный XOR ключ
./govpn-server --obfuscation --xor-key="my-secret-key-123"
```

### Программное использование

```go
package main

import (
    "log"
    "time"
    
    "github.com/atlet99/govpn/pkg/obfuscation"
)

func main() {
    // Конфигурация обфускации
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
    
    // Создание движка обфускации
    engine, err := obfuscation.NewEngine(config, log.Default())
    if err != nil {
        log.Fatal(err)
    }
    defer engine.Close()
    
    // Обфускация данных
    data := []byte("Sensitive VPN traffic")
    obfuscated, err := engine.ObfuscateData(data)
    if err != nil {
        log.Fatal(err)
    }
    
    // Деобфускация
    deobfuscated, err := engine.DeobfuscateData(obfuscated)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Success: %s", string(deobfuscated))
}
```

## Методы обфускации

### XOR Cipher

Простой и быстрый метод обфускации с использованием XOR операции.

**Преимущества:**
- Очень высокая производительность
- Минимальные накладные расходы
- Симметричное шифрование

**Недостатки:**
- Относительно простой для анализа
- Требует безопасного обмена ключами

**Использование:**
```go
cipher, err := obfuscation.NewXORCipher([]byte("your-key"), logger)
```

### TLS Tunneling ✅

Инкапсуляция VPN трафика в легитимные TLS соединения.

**Преимущества:**
- Выглядит как обычный HTTPS трафик
- Сложно заблокировать без блокировки всего HTTPS
- Поддержка SNI и ALPN
- Автогенерация самоподписанных сертификатов
- Опциональные поддельные HTTP заголовки

**Использование:**
```go
config := &obfuscation.TLSTunnelConfig{
    ServerName:      "secure.example.com",
    ALPN:            []string{"h2", "http/1.1"},
    FakeHTTPHeaders: true,
}
tunnel, err := obfuscation.NewTLSTunnel(config, logger)
```

**Документация:** [TLS Tunneling](tls_tunneling.md)

### Packet Padding ✅

Рандомизация размеров пакетов для маскировки статистических характеристик.

**Преимущества:**
- Затрудняет статистический анализ трафика
- Криптографически стойкие случайные данные
- Настраиваемые диапазоны padding'а
- Автоматическое добавление/удаление padding'а

**Использование:**
```go
config := &obfuscation.PacketPaddingConfig{
    Enabled:       true,
    MinPadding:    10,
    MaxPadding:    100,
    RandomizeSize: true,
}
padding, err := obfuscation.NewPacketPadding(config, logger)
```

**Документация:** [Packet Padding](packet_padding.md)

### Timing Obfuscation ✅

Изменение временных интервалов между пакетами для маскировки паттернов трафика.

**Преимущества:**
- Скрывает характерные временные паттерны VPN трафика
- Использует экспоненциальное распределение для реалистичности
- Настраиваемые диапазоны задержек (от микросекунд до секунд)
- Не изменяет содержимое пакетов, только временные интервалы

**Использование:**
```go
config := &obfuscation.TimingObfsConfig{
    Enabled:      true,
    MinDelay:     1 * time.Millisecond,
    MaxDelay:     50 * time.Millisecond,
    RandomJitter: true,
}
timing, err := obfuscation.NewTimingObfuscation(config, logger)
```

**Документация:** [Timing Obfuscation](timing_obfuscation.md)

### Traffic Padding ✅

Добавление фиктивного трафика между реальными пакетами для маскировки паттернов активности.

**Преимущества:**
- Создает постоянный поток трафика для маскировки простоев
- Поддерживает режим всплесков для имитации реальной активности
- Адаптивные интервалы в зависимости от активности
- Автоматическая фильтрация фиктивных пакетов на стороне получателя

**Использование:**
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

**Документация:** [Traffic Padding](traffic_padding.md)

### Flow Watermarking ✅

Добавление скрытых водяных знаков в поток данных для искажения статистических характеристик.

**Преимущества:**
- Модифицирует статистические характеристики данных, не нарушая целостность
- Использует криптографические ключи для генерации уникальных паттернов
- Поддерживает как статистический, так и простой XOR режимы
- Периодическая ротация паттернов для повышения безопасности
- Настраиваемые частотные полосы для различных типов трафика
- Эффективен против корреляционного и частотного анализа

**Использование:**
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

**Документация:** [Flow Watermarking](flow_watermarking.md)

### HTTP Mimicry ✅

Маскировка VPN трафика под обычные HTTP запросы с реалистичными заголовками.

**Преимущества:**
- Имитирует реальные веб-сайты и API запросы
- Адаптивное кодирование данных (GET/POST методы)
- Современные User-Agent строки (2024)
- Поддержка различных HTTP методов и заголовков

**Использование:**
```go
config := &obfuscation.HTTPMimicryConfig{
    UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0",
    FakeHost:      "api.github.com",
    CustomHeaders: map[string]string{"Authorization": "Bearer token"},
    MimicWebsite:  "https://api.github.com",
}
mimicry, err := obfuscation.NewHTTPMimicry(config, logger)
```

**Документация:** [HTTP Mimicry](http_mimicry.md)

### DNS Tunneling ✅

Передача данных через DNS запросы для обеспечения резервного канала связи в экстремально ограниченных сетях.

**Преимущества:**
- Работает через большинство файрволов (DNS трафик редко блокируется полностью)
- Обходит DPI в ограниченных сетях
- Поддержка множественных DNS серверов для резервирования
- Настраиваемые задержки запросов для избежания обнаружения
- Base32 кодирование для совместимости с DNS
- Поддержка различных типов DNS записей (A, TXT, CNAME)

**Использование:**
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

**Документация:** [DNS Tunneling](dns_tunneling.md)

### HTTP Steganography ✅

Скрытие VPN данных внутри обычного HTTP трафика с использованием стеганографических техник.

**Преимущества:**
- Пять различных методов стеганографии для разных сценариев
- Headers and Body: быстрый для небольших данных (7.5x расширение)
- Multipart Forms: отличная маскировка под загрузку файлов (13.5x расширение)
- JSON API: неотличим от API трафика (6.8x расширение)
- CSS Comments: стеганографически стойкий (9.5x расширение)
- JavaScript Variables: скрытность в коде приложения (13.1x расширение)
- Реалистичные HTTP заголовки и структуры
- Автоматическая проверка целостности данных
- Настраиваемые веб-сайты и User-Agent для аутентичности

**Использование:**
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

**Документация:** [HTTP Steganography](http_steganography.md)

## Региональные профили

### Китай (china)

Оптимизирован для обхода Великого Китайского Файрвола:
- Основной метод: TLS Tunnel
- Резервные методы: HTTP Mimicry, XOR Cipher
- Агрессивная обфускация пакетов
- Быстрое переключение методов (порог: 2 ошибки)

### Иран (iran)

Настроен для обхода иранских фильтров:
- Основной метод: HTTP Mimicry
- Резервные методы: TLS Tunnel, HTTP Steganography
- Умеренная обфускация
- Средний порог переключения (3 ошибки)

### Россия (russia)

Сфокусирован на обходе российских DPI:
- Основной метод: TLS Tunnel
- Резервные методы: HTTP Mimicry, Timing Obfuscation
- Легкая обфускация для сохранения скорости
- Консервативный порог переключения (4 ошибки)

## Автоматическое переключение

Система автоматически обнаруживает блокировки по следующим признакам:

- `connection reset by peer`
- `connection refused`
- `timeout`
- `certificate verify failed`
- `handshake failure`
- `protocol error`
- `unexpected EOF`
- `no route to host`

При обнаружении указанного количества ошибок подряд (настраивается через `SwitchThreshold`), система автоматически переключается на следующий доступный метод из списка `FallbackMethods`.

## Метрики и мониторинг

Каждый обфускатор предоставляет детальные метрики:

```go
type ObfuscatorMetrics struct {
    PacketsProcessed int64         // Количество обработанных пакетов
    BytesProcessed   int64         // Количество обработанных байт
    Errors           int64         // Количество ошибок
    AvgProcessTime   time.Duration // Среднее время обработки
    LastUsed         time.Time     // Время последнего использования
}
```

Движок обфускации также предоставляет общие метрики:

```go
type EngineMetrics struct {
    TotalPackets     int64                            // Общее количество пакетов
    TotalBytes       int64                            // Общее количество байт
    MethodSwitches   int64                            // Количество переключений методов
    DetectionEvents  int64                            // Количество событий обнаружения
    MethodMetrics    map[ObfuscationMethod]*ObfuscatorMetrics // Метрики по методам
    StartTime        time.Time                        // Время запуска
}
```

## Производительность

Результаты бенчмарков на Apple M3 Pro:

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

### Сравнение производительности методов

1. **TLS Tunneling**: Самый быстрый (~86ns/op, 0 аллокаций)
2. **Traffic Padding**: Очень быстрый (~120ns/op, 0 аллокаций)
3. **Packet Padding**: Хорошая скорость (~440ns/op, 1 аллокация)
4. **HTTP Mimicry**: Средняя скорость (~671ns/op, 15 аллокаций)
5. **XOR Cipher**: Медленный (~1041ns/op, 1 аллокация)
6. **Flow Watermarking**: Медленный (~1937ns/op, 1 аллокация)
7. **HTTP Steganography**: Медленный (~2566ns/op, 52 аллокации)
8. **DNS Tunneling**: Медленный (~2658ns/op, 48 аллокаций)
9. **Timing Obfuscation**: Самый медленный* (~262μs/op, 0 аллокаций)

*Примечание: Высокое время выполнения для Timing Obfuscation обусловлено намеренными задержками, а не вычислительной сложностью.

## Конфигурация

### Основные параметры

- `EnabledMethods` - список включенных методов обфускации
- `PrimaryMethod` - основной метод обфускации
- `FallbackMethods` - резервные методы для переключения
- `AutoDetection` - включить автоматическое обнаружение блокировок
- `SwitchThreshold` - количество ошибок для переключения метода
- `DetectionTimeout` - таймаут для обнаружения блокировок
- `RegionalProfile` - региональный профиль (china, iran, russia)

### Специфичные настройки

#### XOR Cipher
- `XORKey` - ключ для XOR обфускации (байтовый массив)

#### TLS Tunnel
- `ServerName` - имя сервера для SNI
- `ALPN` - список поддерживаемых протоколов
- `FakeHTTPHeaders` - добавлять поддельные HTTP заголовки

#### Packet Padding
- `Enabled` - включить/выключить Packet Padding
- `MinPadding` - минимальное количество байт для добавления
- `MaxPadding` - максимальное количество байт для добавления  
- `RandomizeSize` - рандомизировать размер padding'а

#### HTTP Mimicry
- `UserAgent` - строка User-Agent
- `FakeHost` - поддельный хост
- `CustomHeaders` - дополнительные HTTP заголовки
- `MimicWebsite` - веб-сайт для имитации

#### Flow Watermarking
- `Enabled` - включить/выключить Flow Watermarking
- `WatermarkKey` - криптографический ключ для генерации водяных знаков
- `PatternInterval` - интервал обновления паттернов
- `PatternStrength` - сила водяного знака (0.0-1.0)
- `NoiseLevel` - уровень шума для рандомизации (0.0-1.0)
- `RotationPeriod` - период ротации паттернов
- `StatisticalMode` - использовать статистический или простой XOR режим
- `FrequencyBands` - частотные полосы для генерации паттернов

## Примеры использования

### Демонстрация

Запустите демонстрацию для просмотра всех возможностей:

```bash
go run examples/obfuscation_demo.go
```

### Тестирование

Запустите тесты модуля обфускации:

```bash
go test ./pkg/obfuscation -v
```

### Бенчмарки

Запустите бенчмарки производительности:

```bash
go test ./pkg/obfuscation -bench=. -v
```

## Безопасность

### Рекомендации

1. **Используйте сильные ключи** - для XOR обфускации используйте случайные ключи длиной не менее 32 байт
2. **Регулярно меняйте ключи** - периодически обновляйте ключи обфускации
3. **Комбинируйте методы** - используйте несколько методов обфускации для повышения стойкости
4. **Мониторьте метрики** - следите за количеством переключений методов и ошибок

### Ограничения

- XOR обфускация не является криптографически стойкой и должна использоваться только поверх основного шифрования VPN
- Некоторые методы обфускации могут снижать производительность
- Эффективность обфускации зависит от конкретных методов блокировки в регионе

## Разработка

### Добавление нового метода обфускации

1. Реализуйте интерфейс `Obfuscator`:

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

2. Добавьте константу метода:

```go
const MethodYourMethod ObfuscationMethod = "your_method"
```

3. Добавьте конструктор в `initializeObfuscators()`:

```go
case MethodYourMethod:
    obfuscator, err = NewYourMethod(&e.config.YourMethodConfig, e.logger)
```

4. Добавьте тесты в `obfuscation_test.go`

### Структура проекта

```
pkg/obfuscation/
├── obfuscation.go      # Основной модуль с движком и XOR обфускатором
├── obfuscation_test.go # Тесты модуля обфускации
└── README.md           # Документация (этот файл)
```

## Лицензия

Этот модуль является частью проекта GoVPN и распространяется под той же лицензией. 