# Flamix Server

Серверная часть системы управления файрволом Flamix. Централизованное управление клиентами, правилами и аналитикой.

## Установка

### Требования

- Python 3.8+
- Windows/Linux/macOS

### Установка зависимостей

```bash
pip install -r requirements.txt
```

## Запуск

### Базовый запуск

```bash
python run.py
```

### С параметрами

```bash
python run.py --host 0.0.0.0 --port 8443 --db-path data/server.db --cert-dir certs
```

### Параметры запуска

- `--host` - Хост для прослушивания (по умолчанию: 0.0.0.0)
- `--port` - Порт для прослушивания (по умолчанию: 8443)
- `--db-path` - Путь к файлу базы данных (по умолчанию: data/server.db)
- `--cert-dir` - Директория для сертификатов (по умолчанию: certs)
- `--web-enabled` - Включить веб-интерфейс (по умолчанию: включен)
- `--web-disable` - Отключить веб-интерфейс
- `--web-host` - Хост веб-интерфейса (по умолчанию: 127.0.0.1)
- `--web-port` - Порт веб-интерфейса (по умолчанию: 8080)

## Подключение клиентов

### Генерация сертификатов

При первом запуске сервер автоматически создаст:
- CA сертификат (`certs/ca.crt`, `certs/ca.key`)
- Серверный сертификат (`certs/server.crt`, `certs/server.key`)

### Получение сертификата для клиента

1. Запустите сервер
2. Откройте веб-интерфейс: `http://127.0.0.1:8080` (или `https://` если есть сертификаты)
3. Перейдите в раздел "Clients" → "Add Client"
4. Введите Client ID и имя клиента
5. Сервер сгенерирует клиентский сертификат
6. Скачайте сертификат и передайте его на клиентскую машину

### Альтернативный способ (через API)

```bash
# Получить список клиентов
curl http://127.0.0.1:8080/api/clients

# Создать нового клиента
curl -X POST http://127.0.0.1:8080/api/clients \
  -H "Content-Type: application/json" \
  -d '{"client_id": "my-client", "name": "My Client"}'

# Получить сертификат клиента
curl http://127.0.0.1:8080/api/clients/my-client/certificate
```

## Структура проекта

```
server/
├── flamix/
│   ├── server/          # Серверные модули
│   │   ├── server.py    # Главный сервер
│   │   ├── protocol.py   # Протокол связи
│   │   ├── rule_manager.py  # Управление правилами
│   │   ├── client_manager.py  # Управление клиентами
│   │   ├── web_api.py   # FastAPI веб-интерфейс
│   │   ├── security.py  # Безопасность и сертификаты
│   │   └── ...
│   ├── common/          # Общие модули
│   │   ├── protocol_types.py
│   │   ├── rule_format.py
│   │   ├── crypto.py
│   │   └── diffie_hellman.py
│   └── database/        # База данных
│       └── encrypted_db.py
├── run.py               # Точка входа
├── requirements.txt     # Зависимости
└── README.md           # Этот файл
```

## Веб-интерфейс

Веб-интерфейс доступен по адресу:
- HTTP: `http://127.0.0.1:8080` (если нет SSL сертификатов)
- HTTPS: `https://127.0.0.1:8080` (если есть SSL сертификаты)

### API Endpoints

- `GET /api/` - Информация об API
- `GET /api/clients` - Список клиентов
- `POST /api/clients` - Создать клиента
- `GET /api/clients/{client_id}` - Информация о клиенте
- `GET /api/clients/{client_id}/rules` - Правила клиента
- `POST /api/clients/{client_id}/rules` - Добавить правило
- `GET /api/analytics` - Аналитика
- `GET /api/change-requests` - Запросы на изменение

## Безопасность

- **Шифрование базы данных**: SQLCipher с автоматической ротацией ключей
- **TLS соединения**: Mutual TLS для клиент-сервер связи
- **Diffie-Hellman**: Обмен ключами для сессионного шифрования
- **HMAC**: Проверка целостности сообщений
- **Nonce и timestamps**: Защита от replay-атак

## База данных

База данных шифруется с помощью SQLCipher. Для тестирования можно отключить шифрование:

```bash
# Windows
set FLAMIX_DISABLE_ENCRYPTION=1
python run.py

# Linux/macOS
export FLAMIX_DISABLE_ENCRYPTION=1
python run.py
```

## Логирование

Логи выводятся в консоль. Для настройки уровня логирования измените `logging.basicConfig` в `run.py`.

## Разработка

### Запуск тестов

```bash
pytest
```

### Отладка

Для отладки можно запустить сервер с более подробным логированием:

```python
logging.basicConfig(level=logging.DEBUG)
```

## Поддержка

Документация: см. `docs/` в корне проекта
Вики: см. ветку `master` в репозитории
