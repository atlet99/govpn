# Тестирование Obfsproxy в GoVPN

Это руководство описывает различные способы тестирования интеграции obfsproxy с GoVPN.

## 🔍 Быстрая проверка установки

**Сначала проверьте, установлен ли obfsproxy:**

```bash
# Автоматическая проверка с рекомендациями по установке
./scripts/check_obfsproxy.sh

# Ручная проверка
which obfsproxy || which obfs4proxy

# Проверка через GoVPN тесты
go test ./pkg/obfuscation/ -v -run TestObfsproxyInstallation
```

## 🚀 Быстрый старт

### 1. Базовое тестирование (Mock)

```bash
# Запуск всех obfsproxy тестов
go test ./pkg/obfuscation/ -v -run TestObfsproxy

# Запуск только mock-тестов
go test ./pkg/obfuscation/ -v -run TestObfsproxyMock

# Бенчмарк производительности
go test ./pkg/obfuscation/ -bench=BenchmarkObfsproxy -benchmem
```

### 2. Демонстрация функциональности

```bash
cd examples
go run obfsproxy_demo.go
```

## 📋 Типы тестов

### Mock-тесты
- ✅ **TestObfsproxyMock** - Тестирование с поддельным obfsproxy
- ✅ **TestObfsproxyConfiguration** - Проверка различных конфигураций
- ✅ **TestObfsproxyConnection** - Тестирование соединений

### Тесты с реальными бинарными файлами
- ✅ **TestObfsproxyWithRealBinary** - Использование реального obfs4proxy/obfsproxy
- ✅ **TestObfsproxyEnvironment** - Проверка различных окружений

### Интеграционные тесты
- ✅ **TestObfsproxyIntegration** - Тестирование с движком обфускации

## 🔧 Установка obfsproxy для тестирования

### macOS
```bash
# obfs4proxy (рекомендуется)
brew install obfs4proxy

# Проверка установки
which obfs4proxy
obfs4proxy -help
```

### Ubuntu/Debian
```bash
# obfsproxy (оригинальный)
sudo apt-get update
sudo apt-get install obfsproxy

# obfs4proxy (более новый)
sudo apt-get install obfs4proxy
```

### CentOS/RHEL/Fedora
```bash
# obfsproxy
sudo yum install obfsproxy
# или для новых версий:
sudo dnf install obfsproxy

# obfs4proxy
sudo dnf install obfs4proxy
```

### Установка из исходного кода
```bash
# Python obfsproxy
pip install obfsproxy

# Go obfs4proxy
go install gitlab.com/yawning/obfs4.git/obfs4proxy@latest
```

## 🧪 Детальное тестирование

### 1. Mock-тестирование

Mock-тесты создают поддельный obfsproxy script и тестируют базовую функциональность:

```bash
go test ./pkg/obfuscation/ -v -run TestObfsproxyMock
```

**Что тестируется:**
- Создание obfsproxy с различными конфигурациями
- Обфускация и деобфускация данных
- Метрики производительности
- Обработка ошибок

### 2. Тестирование конфигураций

```bash
go test ./pkg/obfuscation/ -v -run TestObfsproxyConfiguration
```

**Тестируемые конфигурации:**
- **obfs3** - Оригинальный obfuscated transport
- **obfs4** - Улучшенная версия с сертификатами
- **scramblesuit** - Transport с паролями

### 3. Тестирование с реальными бинарными файлами

```bash
go test ./pkg/obfuscation/ -v -run TestObfsproxyWithRealBinary
```

**Автоматически определяет доступные инструменты:**
- obfsproxy (если установлен)
- obfs4proxy (если установлен)

### 4. Интеграционное тестирование

```bash
go test ./pkg/obfuscation/ -v -run TestObfsproxyIntegration
```

**Тестирует:**
- Интеграцию с движком обфускации
- Автоматическое переключение методов
- Fallback механизмы

## 📊 Бенчмарки производительности

```bash
# Базовый бенчмарк
go test ./pkg/obfuscation/ -bench=BenchmarkObfsproxy

# С детализацией памяти
go test ./pkg/obfuscation/ -bench=BenchmarkObfsproxy -benchmem

# Продолжительный тест
go test ./pkg/obfuscation/ -bench=BenchmarkObfsproxy -benchtime=10s
```

**Пример результатов:**
```
BenchmarkObfsproxy-12    13674634    87.43 ns/op    0 B/op    0 allocs/op
```

## 🔍 Отладка проблем

### Проблема: "obfsproxy is not available"

**Решение:**
1. Установите obfsproxy или obfs4proxy
2. Убедитесь, что binary находится в PATH
3. Проверьте права доступа

```bash
# Проверка доступности
which obfsproxy
which obfs4proxy

# Проверка прав
ls -la $(which obfs4proxy)

# Ручная проверка
obfs4proxy -help
```

### Проблема: "failed to start obfsproxy"

**Возможные причины:**
- Неправильная конфигурация
- Занятый порт
- Отсутствие прав

**Отладка:**
```bash
# Проверьте порт
netstat -an | grep :9050

# Запустите obfsproxy вручную
obfs4proxy -logLevel DEBUG
```

### Проблема: "connection failed"

**Проверьте:**
- Правильность адреса и порта
- Соответствие режима (client/server)
- Правильность transport протокола

## 📈 Метрики и мониторинг

### Получение метрик

```go
obfs, _ := obfuscation.NewObfsproxy(config, logger)
metrics := obfs.GetMetrics()

fmt.Printf("Пакетов обработано: %d\n", metrics.PacketsProcessed)
fmt.Printf("Байт обработано: %d\n", metrics.BytesProcessed)
fmt.Printf("Среднее время: %v\n", metrics.AvgProcessTime)
fmt.Printf("Ошибок: %d\n", metrics.Errors)
```

### Мониторинг производительности

```go
// Включение детального логирования
config := &ObfsproxyConfig{
    LogLevel: "DEBUG",
    // ...
}
```

## 🔧 Автоматизированное тестирование

### CI/CD Pipeline

Создайте script для автоматического тестирования:

```bash
#!/bin/bash
# test_obfsproxy.sh

echo "🧪 Starting obfsproxy tests..."

# Mock tests (всегда работают)
echo "📝 Running mock tests..."
go test ./pkg/obfuscation/ -v -run TestObfsproxyMock

# Real binary tests (если доступны)
echo "🔧 Checking for real binaries..."
if command -v obfs4proxy &> /dev/null; then
    echo "✅ obfs4proxy found - running real tests"
    go test ./pkg/obfuscation/ -v -run TestObfsproxyWithRealBinary
else
    echo "⚠️ obfs4proxy not found - skipping real tests"
fi

# Performance tests
echo "📊 Running performance tests..."
go test ./pkg/obfuscation/ -bench=BenchmarkObfsproxy -short

echo "✅ All tests completed!"
```

### Docker тестирование

```dockerfile
# Dockerfile.test
FROM golang:1.21-alpine

RUN apk add --no-cache git

# Установка obfs4proxy для тестирования
RUN go install gitlab.com/yawning/obfs4.git/obfs4proxy@latest

WORKDIR /app
COPY . .

RUN go mod tidy
RUN go test ./pkg/obfuscation/ -v -run TestObfsproxy
```

```bash
# Запуск тестов в Docker
docker build -f Dockerfile.test -t govpn-obfsproxy-test .
docker run --rm govpn-obfsproxy-test
```

## 📚 Примеры конфигураций

### Client Configuration
```json
{
  "obfsproxy": {
    "enabled": true,
    "executable": "obfs4proxy",
    "mode": "client",
    "transport": "obfs4",
    "address": "server.example.com",
    "port": 443,
    "options": "--cert=abc123 --iat-mode=0",
    "log_level": "INFO"
  }
}
```

### Server Configuration
```json
{
  "obfsproxy": {
    "enabled": true,
    "executable": "obfs4proxy",
    "mode": "server",
    "transport": "obfs4",
    "address": "0.0.0.0",
    "port": 443,
    "log_level": "INFO"
  }
}
```

## 🎯 Рекомендации по тестированию

### 1. Локальная разработка
- Используйте mock-тесты для быстрой итерации
- Установите obfs4proxy для реального тестирования
- Проверяйте производительность регулярно

### 2. CI/CD
- Всегда запускайте mock-тесты
- Условно запускайте real-binary тесты
- Мониторьте performance метрики

### 3. Production
- Тестируйте с реальными obfsproxy servers
- Мониторьте fallback механизмы
- Проверяйте совместимость версий

## 🚨 Устранение неполадок

### Частые проблемы

1. **obfsproxy not found**
   - Установите obfsproxy/obfs4proxy
   - Проверьте PATH

2. **Permission denied**
   - Проверьте права на исполняемый файл
   - Возможно нужны sudo права

3. **Connection refused**
   - Проверьте настройки сети
   - Убедитесь что порт свободен

4. **Transport not supported**
   - Проверьте версию obfsproxy
   - Убедитесь в поддержке протокола

### Логи для отладки

```bash
# Включение детального логирования
export TOR_PT_STATE_LOCATION=/tmp/obfs4proxy
obfs4proxy -logLevel DEBUG -enableLogging
```

## 📞 Поддержка

Если у вас возникли проблемы:

1. Проверьте этот документ
2. Запустите диагностический script
3. Создайте issue с подробной информацией:
   - Версия GoVPN
   - Версия obfsproxy/obfs4proxy
   - Операционная система
   - Полный лог ошибки 