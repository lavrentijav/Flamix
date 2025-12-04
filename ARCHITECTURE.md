# Архитектура Flamix

## Обзор

Flamix построен на модульной архитектуре с четким разделением ответственности:

```
┌─────────────┐
│     GUI     │  PySide6 интерфейс
└──────┬──────┘
       │ IPC (JSON-RPC)
┌──────▼──────┐
│    Agent    │  Демон с правами root
└──────┬──────┘
       │
┌──────▼──────┐
│   Plugins   │  ZIP-архивы с манифестами
└─────────────┘
```

## Компоненты

### 1. Ядро (Core)

**Модули:**
- `PluginLoader`: Загрузка и валидация ZIP-плагинов
- `PluginManager`: Управление lifecycle плагинов
- `PermissionManager`: Проверка разрешений
- `RulesDB`: SQLite база данных для правил и аудита

**Ответственность:**
- Загрузка плагинов из ZIP
- Валидация манифестов
- Управление lifecycle (install/enable/disable/uninstall)
- Проверка разрешений перед выполнением операций
- Хранение правил и логов аудита

### 2. IPC (Inter-Process Communication)

**Протокол:** JSON-RPC 2.0

**Транспорт:**
- Linux/macOS: Unix Domain Socket (`/var/lib/flamix/flamix_agent.sock`)
- Windows: Named Pipe (`\\.\pipe\flamix_agent`)

**Безопасность:**
- Права доступа: `0600` (Unix), DACL (Windows)
- Таймауты: 30 сек на запрос
- Heartbeat: каждые 10 сек

### 3. Плагины

**Формат:** ZIP-архив с `manifest.json`

**Lifecycle:**
1. `on_install()` - при установке
2. `on_enable()` - при включении
3. `on_init(core_api)` - инициализация
4. `get_health()` - проверка здоровья (каждую минуту)
5. `on_disable()` - при отключении
6. `on_uninstall()` - при удалении

**API для плагинов:**
- `core_api.detect_firewalls()` - детект firewall
- `core_api.run_command_safely()` - безопасное выполнение команд
- `core_api.read_file()` / `core_api.write_file()` - работа с файлами
- `core_api.log_audit()` - логирование аудита

### 4. Безопасность

**Модель разрешений:**
- Каждый плагин имеет список `permissions` в манифесте
- Формат: `тип:детали` (например, `run_shell_commands:iptables`)
- Поддержка wildcard: `read_file:/etc/*`

**Валидация команд:**
- Белые списки разрешенных аргументов
- Проверка на опасные паттерны (`rm -rf`, `dd of=`, etc.)
- Специфичная валидация для каждой команды

**Sandboxing (Этап 2):**
- Linux: Seccomp-BPF + AppArmor
- Windows: Job Object + Restricted Token
- macOS: Sandbox-exec

### 5. База данных

**SQLite схема:**

```sql
-- Плагины
CREATE TABLE plugins (
    id TEXT PRIMARY KEY,
    enabled INTEGER,
    permissions TEXT,
    installed_at TEXT
);

-- Правила
CREATE TABLE rules (
    id INTEGER PRIMARY KEY,
    plugin_id TEXT,
    content TEXT,
    created_at TEXT
);

-- Аудит
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    event_time TEXT,
    plugin_id TEXT,
    action TEXT,
    target TEXT,
    result TEXT,
    details TEXT
);
```

## Поток данных

### Установка плагина

```
GUI/CLI → Agent (IPC) → PluginLoader.load_manifest()
                      → PluginLoader.extract_plugin()
                      → PermissionManager.register_plugin()
                      → RulesDB.add_plugin()
```

### Применение правила

```
GUI/CLI → Agent (IPC) → PluginManager._apply_rule()
                      → Plugin.apply_rule()
                      → CoreAPI.run_command_safely()
                      → PermissionManager.check_permission()
                      → PermissionManager.validate_command_args()
                      → subprocess.execute()
                      → RulesDB.add_rule()
                      → RulesDB.log_audit()
```

### Детект firewall

```
Plugin.on_init() → CoreAPI.detect_firewalls()
                → PluginManager.detect_firewalls()
                → Для каждого firewall_support:
                    - Выполнить detect.command/script
                    - Применить regex для версии
                    - Проверить диапазон версий
                    - Вернуть список найденных
```

## Расширяемость

### Добавление поддержки нового firewall

1. Создать плагин с `firewall_support` в манифесте
2. Реализовать `detect` (command или script)
3. Указать regex для извлечения версии
4. Реализовать `apply_rule()` для применения правил

### Добавление новых возможностей в Core API

1. Добавить метод в `CoreAPI`
2. Добавить проверку permissions в `PermissionManager`
3. Обновить документацию

## Производительность

- IPC: Асинхронный (asyncio)
- БД: SQLite с индексами на часто используемые поля
- Плагины: Загружаются по требованию, не все сразу

## Масштабируемость

- Поддержка множества плагинов одновременно
- Каждый плагин изолирован
- Масштабирование через добавление плагинов

