# GoVPN Traffic Obfuscation

Модуль обфускации трафика GoVPN предназначен для обхода блокировок DPI (Deep Packet Inspection) и цензуры в различных регионах мира.

## Возможности

### ✅ Реализованные функции

- **XOR Obfuscation** - быстрое XOR шифрование поверх основного шифрования
- **Модульная архитектура** - легко добавлять новые методы обфускации
- **Автоматическое переключение** - детектор DPI блокировок с автоматическим переключением методов
- **Региональные профили** - оптимизированные настройки для разных стран (Китай, Иран, Россия)
- **Метрики производительности** - детальная статистика работы обфускаторов
- **Адаптивная обфускация** - динамическое переключение при обнаружении блокировки

### 🚧 В разработке

- **TLS Tunneling** - инкапсуляция VPN трафика в легитимные TLS соединения
- **HTTP Mimicry** - маскировка VPN трафика под обычный HTTP/HTTPS трафик
- **DNS Tunneling** - передача данных через DNS запросы (резервный канал)
- **Packet Padding** - рандомизация размеров пакетов
- **Timing Obfuscation** - изменение временных интервалов между пакетами
- **HTTP Steganography** - сокрытие VPN данных в HTTP запросах/ответах

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

### TLS Tunnel (в разработке)

Инкапсуляция VPN трафика в легитимные TLS соединения.

**Преимущества:**
- Выглядит как обычный HTTPS трафик
- Сложно заблокировать без блокировки всего HTTPS
- Поддержка SNI и ALPN

### HTTP Mimicry (в разработке)

Маскировка VPN трафика под обычные HTTP запросы.

**Преимущества:**
- Имитирует реальные веб-сайты
- Настраиваемые User-Agent и заголовки
- Поддержка различных HTTP методов

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
BenchmarkXORObfuscation-12    1000000    1865 ns/op    804.12 MB/s
```

XOR обфускация показывает отличную производительность с пропускной способностью более 800 MB/s.

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

#### HTTP Mimicry
- `UserAgent` - строка User-Agent
- `FakeHost` - поддельный хост
- `CustomHeaders` - дополнительные HTTP заголовки
- `MimicWebsite` - веб-сайт для имитации

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