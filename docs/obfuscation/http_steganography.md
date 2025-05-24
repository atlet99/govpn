# HTTP Steganography

HTTP Steganography - это продвинутый метод обфускации, который скрывает VPN данные внутри обычного HTTP трафика, используя стеганографические техники. Данный метод позволяет VPN трафику выглядеть как обычная веб-активность пользователя.

## Принцип работы

HTTP Steganography встраивает зашифрованные VPN данные в различные элементы HTTP трафика:

1. **Headers and Body** - данные в HTTP заголовках и теле запроса/ответа
2. **Multipart Forms** - скрытие в формах загрузки файлов
3. **JSON API** - встраивание в JSON API ответы
4. **CSS Comments** - сокрытие в CSS комментариях
5. **JavaScript Variables** - встраивание в JS переменные и комментарии

## Конфигурация

### Базовая настройка

```go
config := &obfuscation.HTTPStegoConfig{
    Enabled:       true,
    CoverWebsites: []string{"github.com", "stackoverflow.com", "reddit.com"},
    UserAgents:    []string{
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    },
    ContentTypes:   []string{"text/html", "application/json", "text/css"},
    SteganoMethod:  "headers_and_body",
    ChunkSize:      64,
    ErrorRate:      0.02,
    SessionTimeout: 15 * time.Minute,
    EnableMIME:     true,
    CachingEnabled: false,
}

stego, err := obfuscation.NewHTTPSteganography(config, logger)
```

### Параметры конфигурации

| Параметр | Тип | Описание | По умолчанию |
|----------|-----|----------|--------------|
| `Enabled` | bool | Включить HTTP стеганографию | true |
| `CoverWebsites` | []string | Список сайтов для имитации | Popular websites |
| `UserAgents` | []string | User-Agent строки | Current browsers |
| `ContentTypes` | []string | Типы контента | web content types |
| `SteganoMethod` | string | Метод стеганографии | "headers_and_body" |
| `ChunkSize` | int | Размер чанков данных | 64 |
| `ErrorRate` | float64 | Процент ошибок для реализма | 0.02 |
| `SessionTimeout` | time.Duration | Таймаут сессии | 30 min |
| `EnableMIME` | bool | Поддержка MIME типов | true |
| `CachingEnabled` | bool | Кеширование контента | false |

## Методы стеганографии

### 1. Headers and Body

Встраивает данные в HTTP заголовки и тело запроса.

**Преимущества:**
- Быстрая обработка
- Минимальные накладные расходы
- Хорошо подходит для небольших объемов данных

**Пример HTTP запроса:**
```http
GET /api/v1/data HTTP/1.1
Host: github.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
X-Request-ID: SGVsbG9Xb3JsZA==
X-Trace-ID: VlBORGF0YQ==
X-Session-Token: aGlkZGVu
X-Sequence: 42
X-Checksum: a1b2c3d4
```

### 2. Multipart Forms

Скрывает данные в формах загрузки файлов.

**Преимущества:**
- Отличная маскировка под загрузку файлов
- Высокая вместимость данных
- Естественный вид трафика

**Пример структуры:**
```http
POST /api/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="data.txt"

# Configuration file
data=SGVsbG9Xb3JsZEhpZGRlbkRhdGE=
# End of configuration
------WebKitFormBoundary--
```

### 3. JSON API

Встраивает данные в JSON API ответы.

**Преимущества:**
- Неотличим от обычного API трафика
- Структурированный формат
- Автоматическая валидация

**Пример JSON ответа:**
```json
{
  "status": "success",
  "data": {
    "session": "sess_1234567890",
    "timestamp": 1640995200,
    "payload": "SGVsbG9Xb3JsZEhpZGRlbkRhdGE=",
    "metadata": {
      "size": 64,
      "encoding": "base64",
      "checksum": "a1b2c3d4"
    }
  }
}
```

### 4. CSS Comments

Скрывает данные в CSS комментариях.

**Преимущества:**
- Стеганографически стойкий
- Естественный вид веб-ресурса
- Кешируемый контент

**Пример CSS:**
```css
/* Stylesheet v1.0 */
.main-container {
    width: 100%;
    /* data: SGVsbG9Xb3JsZEhpZGRlbkRhdGE= */
    max-width: 1200px;
    margin: 0 auto;
}
```

### 5. JavaScript Variables

Встраивает данные в JS переменные и комментарии.

**Преимущества:**
- Скрытность в коде приложения
- Большая вместимость
- Валидный JavaScript код

**Пример JavaScript:**
```javascript
var app = {
    version: '2.1.0',
    config: {
        // Embedded data: SGVsbG9Xb3JsZEhpZGRlbkRhdGE=
        apiEndpoint: 'https://api.example.com/v1',
        timeout: 5000
    }
};
```

## Использование

### Программное использование

```go
package main

import (
    "log"
    "time"
    
    "github.com/atlet99/govpn/pkg/obfuscation"
)

func main() {
    logger := log.Default()
    
    config := &obfuscation.HTTPStegoConfig{
        Enabled:       true,
        SteganoMethod: "json_api",
        ChunkSize:     128,
        CoverWebsites: []string{"api.github.com"},
    }
    
    stego, err := obfuscation.NewHTTPSteganography(config, logger)
    if err != nil {
        log.Fatal(err)
    }
    
    // Скрыть данные в HTTP трафике
    data := []byte("Confidential VPN data")
    obfuscated, err := stego.Obfuscate(data)
    if err != nil {
        log.Fatal(err)
    }
    
    // Извлечь данные из HTTP трафика
    recovered, err := stego.Deobfuscate(obfuscated)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Success: %s", string(recovered))
}
```

### Интеграция с движком

```go
config := &obfuscation.Config{
    EnabledMethods:  []obfuscation.ObfuscationMethod{obfuscation.MethodHTTPStego},
    PrimaryMethod:   obfuscation.MethodHTTPStego,
    AutoDetection:   true,
    HTTPStego: obfuscation.HTTPStegoConfig{
        Enabled:       true,
        SteganoMethod: "multipart_forms",
        ChunkSize:     256,
        ErrorRate:     0.01,
    },
}

engine, err := obfuscation.NewEngine(config, logger)
if err != nil {
    log.Fatal(err)
}
defer engine.Close()
```

## Производительность

### Характеристики производительности

| Метрика | Значение |
|---------|----------|
| Скорость обработки | ~2566 ns/op |
| Потребление памяти | ~4171 B/op |
| Аллокации | ~52 allocs/op |
| Расширение размера | 6.8x - 13.5x |

### Сравнение методов

| Метод | Скорость | Расширение | Стеганографичность |
|-------|----------|------------|-------------------|
| Headers and Body | Быстро | 7.5x | Средняя |
| Multipart Forms | Средне | 13.5x | Высокая |
| JSON API | Быстро | 6.8x | Высокая |
| CSS Comments | Средне | 9.5x | Очень высокая |
| JS Variables | Средне | 13.1x | Высокая |

### Бенчмарки

```bash
go test -bench=BenchmarkHTTPSteganography -benchmem ./pkg/obfuscation

BenchmarkHTTPSteganographyObfuscation-12    460210    2566 ns/op    4171 B/op    52 allocs/op
```

## Безопасность

### Преимущества

1. **Глубокая маскировка** - трафик неотличим от обычного веб-серфинга
2. **Множественные методы** - различные стеганографические техники
3. **Проверка целостности** - автоматическая верификация контрольных сумм
4. **Адаптивность** - настройка под различные сценарии использования
5. **Аутентичность** - реалистичные HTTP заголовки и структуры

### Устойчивость к анализу

- **Статистический анализ**: Высокая устойчивость за счет естественной структуры HTTP
- **Глубокий анализ пакетов**: Очень хорошая защита от DPI систем
- **Корреляционный анализ**: Затруднен из-за разнообразия методов
- **Частотный анализ**: Усложнен благодаря реалистичному HTTP контенту

### Региональные аспекты

HTTP Steganography особенно эффективен в регионах с интенсивным мониторингом интернет-трафика:

- **Китай**: Отличная маскировка под обычный веб-трафик
- **Иран**: Эффективен против систем фильтрации контента
- **Россия**: Хорошо работает с локальными сайтами в качестве cover

## Лучшие практики

### Настройка для максимальной эффективности

1. **Выбор cover сайтов**:
   ```go
   CoverWebsites: []string{
       "github.com",           // Техническое содержание
       "stackoverflow.com",    // Q&A трафик
       "medium.com",          // Статьи и блоги
   }
   ```

2. **Ротация методов**:
   ```go
   // Используйте разные методы для разных типов данных
   switch dataType {
   case "small_control":
       config.SteganoMethod = "headers_and_body"
   case "bulk_transfer":
       config.SteganoMethod = "multipart_forms"
   case "api_calls":
       config.SteganoMethod = "json_api"
   }
   ```

3. **Оптимизация размера чанков**:
   ```go
   ChunkSize: 64,  // Для небольших данных
   ChunkSize: 256, // Для больших объемов
   ```

### Рекомендации по развертыванию

1. **Мониторинг производительности** - следите за метриками обработки
2. **Тестирование методов** - проверяйте эффективность в вашей сети
3. **Кастомизация cover content** - адаптируйте под локальные веб-сайты
4. **Балансировка размера** - найдите оптимальное соотношение скорость/маскировка

## Устранение неполадок

### Частые проблемы

1. **Высокое расширение размера**:
   - Используйте более компактные методы (headers_and_body, json_api)
   - Уменьшите ChunkSize для небольших данных

2. **Низкая производительность**:
   - Выберите более быстрые методы
   - Отключите ненужные проверки

3. **Ошибки декодирования**:
   - Проверьте целостность HTTP структуры
   - Убедитесь в корректности base64 кодирования

### Отладка

```go
// Включите детальное логирование
logger := log.New(os.Stdout, "[STEGO] ", log.LstdFlags|log.Lshortfile)

// Проверьте метрики
metrics := stego.GetMetrics()
fmt.Printf("Errors: %d/%d packets\n", metrics.Errors, metrics.PacketsProcessed)
```

## Примеры использования

### Простая стеганография в заголовках

```go
config := &obfuscation.HTTPStegoConfig{
    SteganoMethod: "headers_and_body",
    ChunkSize:     32,
}

stego, _ := obfuscation.NewHTTPSteganography(config, logger)
hidden, _ := stego.Obfuscate([]byte("secret message"))
```

### Объемная передача через формы

```go
config := &obfuscation.HTTPStegoConfig{
    SteganoMethod: "multipart_forms",
    ChunkSize:     512,
}

stego, _ := obfuscation.NewHTTPSteganography(config, logger)
largefile, _ := ioutil.ReadFile("data.bin")
hidden, _ := stego.Obfuscate(largefile)
```

### API трафик

```go
config := &obfuscation.HTTPStegoConfig{
    SteganoMethod: "json_api",
    CoverWebsites: []string{"api.service.com"},
}

stego, _ := obfuscation.NewHTTPSteganography(config, logger)
apidata, _ := stego.Obfuscate([]byte(`{"command":"connect"}`))
```

HTTP Steganography представляет собой мощный инструмент для создания VPN соединений, неотличимых от обычного веб-трафика, предоставляя высокий уровень анонимности и обходных возможностей. 