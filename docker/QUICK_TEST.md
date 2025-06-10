# Быстрое тестирование GoVPN с OIDC

## Запуск окружения

1. **Запустите Docker** (если не запущен):
   ```bash
   # Убедитесь что Docker Desktop запущен
   docker --version
   ```

2. **Запустите все сервисы**:
   ```bash
   cd docker
   make dev-setup
   ```

   Эта команда:
   - Соберёт GoVPN сервер
   - Запустит все сервисы (GoVPN, Keycloak, PostgreSQL, Prometheus, Grafana)
   - Сгенерирует сертификаты
   - Создаст OIDC клиентские конфиги

## Файлы конфигурации

После выполнения `make dev-setup` у вас будут созданы:

- **`tunnelblick-oidc.ovpn`** - Конфиг для Tunnelblick с OIDC аутентификацией
- **`oidc-client-simple.ovpn`** - Упрощённый OIDC конфиг
- **`client-auth.txt`** - Тестовые учётные данные (testuser/password123)

## Подключение через Tunnelblick

1. **Импортируйте конфиг**:
   - Откройте файл `tunnelblick-oidc.ovpn` в Tunnelblick
   - Или перетащите его на иконку Tunnelblick

2. **Подключитесь**:
   - Выберите конфигурацию в Tunnelblick
   - Нажмите "Connect"
   - Введите учётные данные:
     - **Username**: `testuser`
     - **Password**: `password123`

3. **Проверка**:
   - После подключения проверьте IP: `curl ifconfig.me`
   - Должен показать IP VPN сервера

## Проверка web-интерфейсов

- **Keycloak Admin**: http://localhost:8080 (admin/admin123)
- **GoVPN API**: http://localhost:8081/health
- **Grafana**: http://localhost:3000 (admin/admin123)
- **Prometheus**: http://localhost:9091

## Устранение проблем

### Проверка статуса сервисов:
```bash
make status
make health
```

### Просмотр логов:
```bash
make logs              # Все сервисы
make logs-govpn        # Только GoVPN
make logs-keycloak     # Только Keycloak
```

### Если OIDC не работает:
```bash
# Проверьте OIDC discovery
curl -s http://localhost:8080/realms/govpn/.well-known/openid_configuration | jq

# Проверьте подключение к Keycloak
make test-auth
```

### Если VPN не подключается:
```bash
# Проверьте TUN устройство на хосте
ls -la /dev/net/tun

# Пересоздайте конфиги
make oidc-config
```

## Остановка

```bash
make down              # Остановить все сервисы
make clean             # Полная очистка (с подтверждением)
```

## Тестовые учётки

В Keycloak автоматически создаются:
- **testuser** / password123 - Обычный VPN пользователь
- **admin** / admin123 - Администратор VPN

## Помощь

```bash
make help              # Список всех команд
make info              # Информация об окружении
make docs              # Открыть документацию
``` 