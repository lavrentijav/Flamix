# Flamix

Flamix - система централизованного управления файрволом с клиент-серверной архитектурой.

## Структура проекта

Проект разделен на три независимые ветки:

### 📦 [Server](server/) - Серверная часть

Централизованное управление клиентами, правилами и аналитикой.

- Управление множеством клиентов
- Хранение и синхронизация правил
- Веб-интерфейс (FastAPI)
- Аналитика и статистика
- Авторизация изменений правил

**Документация:** [server/README.md](server/README.md)

### 💻 [Client](client/) - Клиентская часть

Клиент для подключения к серверу и применения правил.

- Подключение к серверу
- Синхронизация правил
- Мониторинг изменений
- Сбор аналитики (опционально)

**Документация:** [client/README.md](client/README.md)

### 🖥️ [App](app/) - GUI приложение

Графический интерфейс для управления сервером.

- Управление клиентами
- Управление правилами
- Просмотр аналитики
- Управление запросами на изменение

**Документация:** [app/README.md](app/README.md)

## Быстрый старт

### 1. Установка сервера

```bash
cd server
pip install -r requirements.txt
python run.py
```

Сервер будет доступен на:
- Клиентские соединения: `0.0.0.0:8443`
- Веб-интерфейс: `https://127.0.0.1:8080`

### 2. Подключение клиента

```bash
cd client
pip install -r requirements.txt
python run.py --client-id my-client
```

### 3. Запуск GUI приложения

```bash
cd app
pip install -r requirements.txt
python run.py
```

## Архитектура

```
┌─────────────┐
│   Server    │  ← Централизованное управление
│  (FastAPI)  │     - Правила
└──────┬──────┘     - Клиенты
       │            - Аналитика
       │ TLS
       │
┌──────┴──────┐
│   Client   │  ← Применение правил
│            │     - Синхронизация
└────────────┘     - Мониторинг
```

## Безопасность

- **Шифрование базы данных**: SQLCipher с автоматической ротацией ключей
- **TLS соединения**: Mutual TLS для клиент-сервер связи
- **Diffie-Hellman**: Обмен ключами для сессионного шифрования
- **HMAC**: Проверка целостности сообщений
- **Nonce и timestamps**: Защита от replay-атак

## Подключение новых клиентов

### Через веб-интерфейс

1. Запустите сервер
2. Откройте веб-интерфейс: `https://127.0.0.1:8080`
3. Перейдите в раздел "Clients" → "Add Client"
4. Введите Client ID и имя клиента
5. Скачайте сертификат клиента
6. Передайте сертификат на клиентскую машину
7. Запустите клиент с указанным Client ID

### Через API

```bash
# Создать клиента
curl -X POST https://127.0.0.1:8080/api/clients \
  -H "Content-Type: application/json" \
  -d '{"client_id": "my-client", "name": "My Client"}'

# Получить сертификат
curl https://127.0.0.1:8080/api/clients/my-client/certificate
```

### На клиентской машине

1. Поместите сертификаты в директорию `certs/`:
   - `ca.crt` - Сертификат CA
   - `client.crt` - Сертификат клиента
   - `client.key` - Приватный ключ клиента

2. Запустите клиент:
```bash
   python run.py --client-id my-client --server-host <server-ip>
   ```

## Ветки репозитория

Проект организован в следующие ветки:

- **`server`** - Серверная часть (директория `server/`)
- **`client`** - Клиентская часть (директория `client/`)
- **`app`** - GUI приложение (директория `app/`)
- **`plugins`** - Плагины для различных файрволов (директория `plugins/`)
- **`master`** - Документация и вики (директория `docs/`)

Каждая ветка содержит независимый код и может быть развернута отдельно.

**Инструкция по настройке веток:** [docs/BRANCHES_SETUP.md](docs/BRANCHES_SETUP.md)

## Документация

- **Вики:** [docs/WIKI.md](docs/WIKI.md) - Полная документация и руководства
- **Сервер:** [server/README.md](server/README.md)
- **Клиент:** [client/README.md](client/README.md)
- **GUI:** [app/README.md](app/README.md)
- **Плагины:** [plugins/README.md](plugins/README.md) - Разработка и использование плагинов
- **Сертификаты:** [docs/CERTIFICATES.md](docs/CERTIFICATES.md)
- **Разработка:** [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)
- **Плагины (детально):** [docs/PLUGINS.md](docs/PLUGINS.md) - Руководство по разработке плагинов
- **Настройка веток:** [docs/BRANCHES_SETUP.md](docs/BRANCHES_SETUP.md)

## Требования

- Python 3.8+
- Windows/Linux/macOS
- Права администратора (для клиента, для применения правил)

## Лицензия

См. [LICENSE](LICENSE)

## Поддержка

- Документация: `docs/`
- Вики: ветка `master`
- Issues: GitHub Issues

## Container deployment

Для self-hosted развертывания без внешних сервисов используйте Docker-контейнер для `server/`.
Веб-admin интерфейс уже входит в серверный контейнер, а desktop GUI из `app/` остаётся локальным приложением.

Быстрый старт:

```bash
mkdir -p data certs logs
cp .env.example .env
docker compose up -d --build
```

- Web/admin UI: `https://127.0.0.1:8080`
- Client/server port: `8443`

Подробная инструкция: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
