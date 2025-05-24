# Конфигурационные файлы GoVPN

Данная папка содержит все необходимые конфигурационные файлы для настройки сервера и клиентов GoVPN с поддержкой современных методов аутентификации и обфускации трафика.

## Структура файлов

### Основные файлы конфигурации

- **`server.conf`** - Основной файл конфигурации сервера
- **`client.conf`** - Базовый файл конфигурации клиента

### Дополнительные модули аутентификации

- **`auth.conf`** - Базовая аутентификация по паролям
- **`mfa.conf`** - Многофакторная аутентификация (TOTP/HOTP)
- **`oidc.conf`** - OIDC аутентификация (Google, Microsoft, Keycloak и др.)
- **`ldap.conf`** - LDAP аутентификация (Active Directory, OpenLDAP)

### Модули обфускации

- **`obfuscation.conf`** - Настройки обфускации и маскировки трафика

## Быстрый старт

### 1. Базовая настройка сервера

```bash
# Скопируйте основной конфиг
cp server.conf /etc/govpn/
cp client.conf /etc/govpn/

# Настройте сертификаты
mkdir -p /etc/govpn/certs
# ... скопируйте ваши сертификаты в /etc/govpn/certs/
```

### 2. Включение дополнительных методов аутентификации

Для включения дополнительных методов аутентификации раскомментируйте соответствующие строки в `server.conf`:

```conf
# Включить базовую аутентификацию паролем
config auth.conf

# Включить многофакторную аутентификацию
config mfa.conf

# Включить OIDC аутентификацию
config oidc.conf

# Включить LDAP аутентификацию
config ldap.conf
```

## Детальное описание конфигураций

### Базовая конфигурация сервера (`server.conf`)

Основной файл содержит базовые настройки VPN сервера:

- **Сетевые настройки**: порт, протокол, тип устройства
- **VPN сеть**: диапазон IP адресов, DNS серверы
- **Безопасность**: алгоритмы шифрования и аутентификации
- **Сертификаты**: пути к файлам сертификатов и ключей
- **Подключения**: лимиты клиентов, keepalive настройки

### Базовая аутентификация (`auth.conf`)

Конфигурация для аутентификации по паролям:

- **Хеширование**: Argon2 (рекомендуется) или PBKDF2
- **Сессии**: управление временем жизни сессий
- **Безопасность**: защита от атак, токены переподключения

#### Пример настройки Argon2:
```conf
auth-hash-method argon2
auth-argon2-memory 65536     # 64MB памяти
auth-argon2-time 3           # 3 итерации
auth-argon2-threads 4        # 4 потока
```

### Многофакторная аутентификация (`mfa.conf`)

Конфигурация для двухфакторной аутентификации:

- **TOTP**: поддержка Google Authenticator, Microsoft Authenticator, Authy
- **Резервные коды**: для восстановления доступа
- **Безопасность**: защита от брутфорса, блокировки

#### Совместимость с приложениями:
- ✅ Google Authenticator
- ✅ Microsoft Authenticator 
- ✅ Authy
- ✅ 1Password
- ✅ Bitwarden

### OIDC аутентификация (`oidc.conf`)

Интеграция с современными системами единого входа:

#### Поддерживаемые провайдеры:
- **Keycloak** - Открытое решение для корпораций
- **Google Workspace** - Для Google организаций
- **Microsoft Azure AD/Entra** - Для Microsoft организаций
- **Okta** - Коммерческое решение
- **Auth0** - Платформа аутентификации
- **GitLab** - Для интеграции с GitLab

#### Настройки безопасности:
- **PKCE** - защита Authorization Code Flow
- **Валидация токенов** - проверка подписей и издателей
- **Маппинг ролей** - автоматическое назначение прав

### LDAP аутентификация (`ldap.conf`)

Интеграция с корпоративными каталогами:

#### Поддерживаемые LDAP серверы:
- **Microsoft Active Directory** - Основная поддержка
- **OpenLDAP** - Открытое решение
- **FreeIPA/Red Hat IdM** - Для Linux сред
- **389 Directory Server** - Red Hat решение
- **Oracle Internet Directory** - Для Oracle сред

#### Возможности:
- **Группы безопасности** - контроль доступа через группы
- **Кеширование** - повышение производительности
- **Пул подключений** - масштабируемость
- **Резервные серверы** - отказоустойчивость

### Обфускация трафика (`obfuscation.conf`)

Современные методы обхода блокировок VPN:

#### Методы обфускации:
- **XOR Cipher** - простое XOR шифрование
- **Packet Padding** - изменение размеров пакетов
- **Timing Obfuscation** - изменение временных характеристик
- **TLS Tunnel** - маскировка под HTTPS
- **HTTP Mimicry** - маскировка под веб-трафик
- **DNS Tunnel** - туннелирование через DNS

#### Региональные профили:
- **Китай** - оптимизировано для Great Firewall
- **Иран** - адаптировано для блокировок Ирана
- **Россия** - настройки для российских ограничений

## Примеры использования

### Корпоративная сеть с Active Directory

```conf
# server.conf
config ldap.conf

# ldap.conf
ldap-enabled true
ldap-server dc1.company.com
ldap-bind-dn cn=ldap-reader,ou=service-accounts,dc=company,dc=com
ldap-required-groups CN=VPN-Users,ou=groups,dc=company,dc=com
```

### Организация с Google Workspace

```conf
# server.conf  
config oidc.conf

# oidc.conf
oidc-enabled true
oidc-provider-url https://accounts.google.com
oidc-required-claims hd:company.com,email_verified:true
```

### Высокая безопасность с MFA

```conf
# server.conf
config auth.conf
config mfa.conf

# mfa.conf
mfa-enabled true
mfa-required-for-all true
mfa-max-attempts 3
mfa-lockout-duration 1800
```

### Обход блокировок

```conf
# server.conf
config obfuscation.conf

# obfuscation.conf
obfuscation-enabled true
obfuscation-primary-method tls_tunnel
tls-tunnel-port 443
adaptive-obfuscation-enabled true
```

## Безопасность

### Рекомендации по безопасности:

1. **Используйте сильные алгоритмы**:
   - Шифрование: AES-256-GCM
   - Аутентификация: SHA256 или SHA512
   - TLS: версия 1.2 или выше

2. **Настройте правильные права доступа**:
   ```bash
   chmod 600 /etc/govpn/*.conf
   chmod 600 /etc/govpn/certs/*
   chown root:root /etc/govpn/*
   ```

3. **Используйте MFA для критически важных аккаунтов**

4. **Регулярно обновляйте сертификаты**

5. **Мониторьте логи подключений**

### Защита паролей и ключей:

- Все пароли и секретные ключи должны храниться в безопасности
- Используйте переменные окружения для секретных данных
- Регулярно меняйте пароли сервисных аккаунтов

## Мониторинг и логирование

### Файлы логов:
- `/var/log/govpn.log` - основные логи сервера
- `/var/log/govpn-auth.log` - логи аутентификации
- `/var/log/govpn-mfa.log` - логи MFA
- `/var/log/govpn-oidc.log` - логи OIDC
- `/var/log/govpn-ldap.log` - логи LDAP
- `/var/log/govpn-obfuscation.log` - логи обфускации

### Метрики:
Включите сбор метрик для мониторинга:
```conf
obfuscation-metrics-enabled true
obfuscation-metrics-port 9090
```

## Производительность

### Оптимизация для различных нагрузок:

**Малые сети (до 50 пользователей):**
```conf
max-clients 50
ldap-connection-pool-size 5
obfuscation-threads 2
```

**Средние сети (до 500 пользователей):**
```conf
max-clients 500
ldap-connection-pool-size 20
obfuscation-threads 8
```

**Большие сети (свыше 500 пользователей):**
```conf
max-clients 1000
ldap-connection-pool-size 50
obfuscation-threads 16
```

## Устранение неполадок

### Частые проблемы:

1. **Проблемы с LDAP подключением**:
   - Проверьте сетевую доступность
   - Убедитесь в правильности bind DN и пароля
   - Проверьте SSL/TLS настройки

2. **Проблемы с OIDC**:
   - Проверьте правильность client_id и client_secret
   - Убедитесь в доступности провайдера
   - Проверьте redirect URL

3. **Проблемы с MFA**:
   - Синхронизируйте время на сервере
   - Проверьте настройки TOTP (период, алгоритм)
   - Убедитесь в правильности секретного ключа

### Отладка:
Включите детальное логирование для отладки:
```conf
verb 6                          # В основном конфиге
mfa-log-level debug            # Для MFA
oidc-log-level debug           # Для OIDC
ldap-log-level debug           # Для LDAP
```

## Поддержка

Для получения поддержки обратитесь к документации проекта или создайте issue в репозитории.

## Лицензия

Конфигурационные файлы распространяются под той же лицензией, что и основной проект GoVPN. 