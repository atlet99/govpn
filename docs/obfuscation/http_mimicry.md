# HTTP Mimicry Obfuscation (Мимикрия HTTP трафика)

## Описание

HTTP Mimicry - это продвинутый метод обфускации VPN трафика, который маскирует зашифрованные данные под легитимные HTTP запросы и ответы. Этот метод чрезвычайно эффективен против систем DPI (Deep Packet Inspection), поскольку обфусцированный трафик неотличим от обычного веб-трафика.

## Принцип работы

### Основные компоненты

1. **Realistic HTTP Headers**: Использование реальных User-Agent строк и стандартных HTTP заголовков
2. **Request/Response Alternation**: Чередование HTTP запросов и ответов для имитации естественного веб-трафика  
3. **Multiple Encoding Methods**: Различные способы встраивания VPN данных в HTTP структуры
4. **Adaptive Payload Distribution**: Умное распределение данных между HTTP body и заголовками

### Методы встраивания данных

#### Для больших пакетов (POST/PUT/PATCH):
- VPN данные размещаются в HTTP body
- Используются реалистичные Content-Type заголовки
- Добавляются корректные Content-Length заголовки

#### Для малых пакетов (GET/HEAD/OPTIONS):
- VPN данные кодируются в Base64 и распределяются по custom headers
- Используются заголовки X-Request-ID, X-Trace-ID, X-Session-Token
- Данные разбиваются на чанки для естественного вида

## Конфигурация

```go
config := &obfuscation.HTTPMimicryConfig{
    UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    FakeHost:      "api.github.com",
    CustomHeaders: map[string]string{
        "Authorization": "Bearer token123",
        "X-API-Version": "v1",
    },
    MimicWebsite:  "https://api.github.com",
}
```

### Параметры конфигурации

- **UserAgent**: Строка User-Agent для HTTP заголовков. Если не указана, используется случайная из предустановленного набора
- **FakeHost**: Поддельный хост для заголовка Host. По умолчанию выбирается случайный из списка популярных API
- **CustomHeaders**: Дополнительные HTTP заголовки для повышения реалистичности
- **MimicWebsite**: Веб-сайт для имитации (используется для генерации реалистичных путей)

## Использование

### Создание HTTP Mimicry обфускатора

```go
logger := log.New(os.Stdout, "[HTTP] ", log.LstdFlags)

config := &obfuscation.HTTPMimicryConfig{
    UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    FakeHost:  "api.openai.com",
    CustomHeaders: map[string]string{
        "Authorization": "Bearer sk-example123",
        "OpenAI-Beta":   "assistants=v1",
    },
    MimicWebsite: "https://api.openai.com",
}

mimicry, err := obfuscation.NewHTTPMimicry(config, logger)
if err != nil {
    log.Fatalf("Failed to create HTTP mimicry: %v", err)
}
```

### Использование с движком обфускации

```go
engineConfig := &obfuscation.Config{
    EnabledMethods:  []obfuscation.ObfuscationMethod{obfuscation.MethodHTTPMimicry},
    PrimaryMethod:   obfuscation.MethodHTTPMimicry,
    HTTPMimicry: obfuscation.HTTPMimicryConfig{
        UserAgent: "Mozilla/5.0 (compatible; GoVPN/1.0)",
        FakeHost:  "api.stripe.com",
        CustomHeaders: map[string]string{
            "Stripe-Version": "2023-10-16",
            "Authorization":  "Bearer rk_test_example",
        },
    },
}

engine, err := obfuscation.NewEngine(engineConfig, logger)
if err != nil {
    log.Fatalf("Failed to create engine: %v", err)
}
defer engine.Close()

// Обфускация данных
obfuscated, err := engine.ObfuscateData([]byte("Secret VPN data"))
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
wrappedConn, err := mimicry.WrapConn(originalConn)
if err != nil {
    log.Printf("Failed to wrap connection: %v", err)
}

// Использование обернутого соединения
_, err = wrappedConn.Write([]byte("VPN traffic"))
if err != nil {
    log.Printf("Write failed: %v", err)
}
```

## Примеры сгенерированного трафика

### HTTP POST запрос (большие данные)
```http
POST /v1/chat/completions HTTP/1.1
Host: api.openai.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Authorization: Bearer sk-example123
OpenAI-Beta: assistants=v1
Content-Type: application/json
Content-Length: 245

[VPN encrypted data appears here as POST body]
```

### HTTP GET запрос (малые данные)
```http
GET /api/v1/data HTTP/1.1
Host: api.github.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Authorization: Bearer ghp_example123
X-GitHub-Api-Version: 2022-11-28
X-Request-ID: U2VjcmV0IFZQTIB0
X-Trace-ID: cmFmZmlrIGZvciB0
X-Session-Token: ZXN0aW5nIHB1cnBvc2Vz

```

### HTTP Response (нечетные пакеты)
```http
HTTP/1.1 200 OK
Server: nginx/1.20.2
Date: Sat, 24 May 2025 08:42:38 GMT
Content-Type: application/json
Content-Length: 156
Cache-Control: no-cache, private
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Connection: keep-alive

[VPN encrypted data appears here as response body]
```

## Предустановленные значения

### User-Agent строки (обновлено 2024)
```go
userAgents := []string{
    // Windows Desktop browsers
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/120.0.2210.144",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    
    // macOS Desktop browsers  
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:122.0) Gecko/20100101 Firefox/122.0",
    
    // Linux Desktop browsers
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    
    // Mobile browsers
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
}
```

### Популярные хосты
```go
commonHosts := []string{
    "api.github.com",
    "www.googleapis.com", 
    "cdn.jsdelivr.net",
    "fonts.googleapis.com",
    "ajax.googleapis.com",
    "api.openweathermap.org",
    "jsonplaceholder.typicode.com",
    "httpbin.org",
    "postman-echo.com",
}
```

### HTTP методы
```go
httpMethods := []string{
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
}
```

### Content-Type заголовки
```go
contentTypes := []string{
    "application/json",
    "application/x-www-form-urlencoded",
    "text/html; charset=utf-8",
    "text/plain; charset=utf-8",
    "application/javascript",
    "text/css",
    "image/png",
    "image/jpeg",
}
```

## Метрики

HTTP Mimicry обфускатор собирает следующие метрики:

- **PacketsProcessed**: Количество обработанных пакетов
- **BytesProcessed**: Количество обработанных байт (включая HTTP заголовки)
- **Errors**: Количество ошибок
- **AvgProcessTime**: Среднее время обработки
- **LastUsed**: Время последнего использования

```go
metrics := mimicry.GetMetrics()
fmt.Printf("Packets: %d, Bytes: %d, Errors: %d\n", 
    metrics.PacketsProcessed, 
    metrics.BytesProcessed, 
    metrics.Errors)
```

## Производительность

HTTP Mimicry показывает отличную производительность для сложного метода обфускации:

```
BenchmarkHTTPMimicryObfuscation-12    1798338    672.1 ns/op    3494 B/op    15 allocs/op
```

### Сравнение с другими методами

| Метод | Время (ns/op) | Аллокации (B/op) | Количество аллокаций |
|-------|---------------|-------------------|---------------------|
| TLS Tunneling | 86.85 | 0 | 0 |
| Packet Padding | 447.9 | 2304 | 1 |
| **HTTP Mimicry** | **672.1** | **3494** | **15** |
| XOR Cipher | 944.6 | 1408 | 1 |

HTTP Mimicry занимает третье место по скорости, что отлично для такого сложного метода обфускации.

### Факторы влияющие на производительность

1. **Размер данных**: Больше данных = больше HTTP структуры
2. **Тип запроса**: GET запросы требуют Base64 кодирования в заголовки
3. **Количество custom headers**: Больше заголовков = больше накладных расходов
4. **Генерация случайных элементов**: User-Agent, Host, HTTP method выбираются случайно

### Рекомендации по оптимизации

- Используйте фиксированные UserAgent и FakeHost для немного лучшей производительности
- Ограничьте количество CustomHeaders для снижения накладных расходов
- Комбинируйте с другими методами для баланса скорости и защиты

## Безопасность

### Преимущества

1. **Высокая стойкость к DPI**: Трафик неотличим от обычного HTTP
2. **Realistic Traffic Patterns**: Использование реальных User-Agent и HTTP структур
3. **Multiple Encoding Methods**: Различные способы встраивания данных усложняют анализ
4. **Dynamic Request/Response**: Чередование запросов и ответов имитирует естественный веб-трафик
5. **Legitimate HTTP Status Codes**: Использование реальных HTTP статус кодов (200, 404, 500, etc.)

### Рекомендации по безопасности

1. **Используйте реалистичные конфигурации**: Выбирайте известные API для FakeHost
2. **Комбинируйте с другими методами**: HTTP Mimicry + TLS Tunneling = двойная защита
3. **Регулярно обновляйте User-Agent**: Используйте актуальные версии браузеров
4. **Настройте meaningful headers**: CustomHeaders должны соответствовать имитируемому API
5. **Мониторьте размеры пакетов**: Слишком большие HTTP тела могут привлечь внимание

### Возможные векторы обнаружения

- **Statistical Analysis**: Анализ размеров HTTP body может выявить паттерны
- **API Behavioral Analysis**: Нереалистичные API запросы к известным сервисам
- **Header Inconsistencies**: Несоответствия между User-Agent и другими заголовками
- **Response Time Analysis**: VPN обфускация может добавлять задержки

## Региональные профили

HTTP Mimicry эффективно интегрируется в региональные профили:

### China Profile
```go
HTTPMimicry: obfuscation.HTTPMimicryConfig{
    UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    FakeHost:  "api.weixin.qq.com",  // Popular Chinese API
    CustomHeaders: map[string]string{
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    },
},
```

### Iran Profile  
```go
HTTPMimicry: obfuscation.HTTPMimicryConfig{
    UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    FakeHost:  "api.aparat.com",  // Popular Iranian service
    CustomHeaders: map[string]string{
        "Accept-Language": "fa-IR,fa;q=0.9,en;q=0.8",
    },
},
```

### Russia Profile
```go
HTTPMimicry: obfuscation.HTTPMimicryConfig{
    UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    FakeHost:  "api.vk.com",  // Popular Russian API
    CustomHeaders: map[string]string{
        "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
    },
},
```

## Совместимость

- **Go версия**: 1.22+
- **Зависимости**: Только стандартная библиотека Go (encoding/base64, strings, fmt)
- **Платформы**: Linux, macOS, Windows
- **Комбинирование**: Совместим со всеми другими методами обфускации

## Примеры использования

### Имитация GitHub API

```go
config := &obfuscation.HTTPMimicryConfig{
    UserAgent: "GitHub CLI 2.42.1",
    FakeHost:  "api.github.com",
    CustomHeaders: map[string]string{
        "Authorization":        "Bearer ghp_xxxxxxxxxxxxxxxxxxxx",
        "X-GitHub-Api-Version": "2022-11-28",
        "Accept":               "application/vnd.github+json",
    },
    MimicWebsite: "https://api.github.com",
}
```

### Имитация OpenAI API

```go
config := &obfuscation.HTTPMimicryConfig{
    UserAgent: "OpenAI/Python 1.10.0",
    FakeHost:  "api.openai.com",
    CustomHeaders: map[string]string{
        "Authorization": "Bearer sk-xxxxxxxxxxxxxxxxxxxxxxxx",
        "OpenAI-Beta":   "assistants=v2",
        "Content-Type":  "application/json",
    },
    MimicWebsite: "https://api.openai.com",
}
```

### Имитация REST API

```go
config := &obfuscation.HTTPMimicryConfig{
    UserAgent: "MyApp/1.0 (https://myapp.com)",
    FakeHost:  "jsonplaceholder.typicode.com",
    CustomHeaders: map[string]string{
        "Accept":       "application/json",
        "Content-Type": "application/json",
        "X-API-Key":    "abc123def456",
    },
}
```

### Интеграция с движком

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
            obfuscation.MethodHTTPMimicry,
            obfuscation.MethodTLSTunnel,
        },
        PrimaryMethod: obfuscation.MethodHTTPMimicry,
        FallbackMethods: []obfuscation.ObfuscationMethod{
            obfuscation.MethodTLSTunnel,
        },
        AutoDetection:    true,
        SwitchThreshold:  3,
        DetectionTimeout: 5 * time.Second,
        HTTPMimicry: obfuscation.HTTPMimicryConfig{
            UserAgent: "Mozilla/5.0 (custom)",
            FakeHost:  "api.example.com",
            CustomHeaders: map[string]string{
                "X-API-Key": "secret123",
            },
        },
    }
    
    engine, err := obfuscation.NewEngine(config, log.Default())
    if err != nil {
        log.Fatal(err)
    }
    defer engine.Close()
    
    // Обработка VPN трафика
    for {
        // Получение VPN пакета
        vpnData := getVPNPacket()
        
        // Обфускация под HTTP
        httpTraffic, err := engine.ObfuscateData(vpnData)
        if err != nil {
            log.Printf("Obfuscation error: %v", err)
            continue
        }
        
        // Отправка обфусцированного трафика
        sendHTTPTraffic(httpTraffic)
    }
}
```

Полные примеры использования HTTP Mimicry доступны в:
- `examples/obfuscation_demo.go` - демонстрация всех возможностей
- `pkg/obfuscation/obfuscation_test.go` - unit тесты 