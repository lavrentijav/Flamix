# Windows Firewall Plugin

Плагин для управления Windows Firewall через `netsh advfirewall`.

## Возможности

- Добавление правил firewall
- Удаление правил
- Просмотр списка правил
- Проверка состояния firewall

## Установка

### 1. Создание ZIP

```bash
cd examples/windows_firewall_plugin
python ../../scripts/create_plugin_zip.py . ../../windows_firewall_plugin.zip
```

### 2. Установка через CLI

```bash
# Без установки Flamix
python run_cli.py install-plugin ../../windows_firewall_plugin.zip

# После установки
flamix-cli install-plugin ../../windows_firewall_plugin.zip
```

### 3. Включение плагина

```bash
python run_cli.py enable-plugin com.example.windows_firewall
# или
flamix-cli enable-plugin com.example.windows_firewall
```

## Использование

### Применение правила

Пример применения правила через API:

```python
rule = {
    "name": "Allow HTTP",
    "port": 80,
    "protocol": "tcp",
    "action": "allow",
    "direction": "in",
    "profile": "any"  # или "domain", "private", "public"
}

await plugin.apply_rule(rule)
```

### Параметры правила

- **name** (обязательно): Имя правила
- **port** (опционально): Порт (1-65535)
- **protocol**: Протокол ("tcp", "udp", "icmp", "any")
- **action**: Действие ("allow", "block")
- **direction**: Направление ("in", "out")
- **profile**: Профиль ("domain", "private", "public", "any")

### Примеры правил

```python
# Разрешить HTTP входящие соединения
{
    "name": "Allow HTTP Inbound",
    "port": 80,
    "protocol": "tcp",
    "action": "allow",
    "direction": "in",
    "profile": "any"
}

# Заблокировать исходящие соединения на порт 12345
{
    "name": "Block Outbound Port 12345",
    "port": 12345,
    "protocol": "tcp",
    "action": "block",
    "direction": "out",
    "profile": "private"
}

# Разрешить HTTPS только для доменного профиля
{
    "name": "Allow HTTPS Domain",
    "port": 443,
    "protocol": "tcp",
    "action": "allow",
    "direction": "in",
    "profile": "domain"
}
```

## Требования

- Windows с включенным Windows Firewall
- Права администратора для применения правил
- `netsh` доступен в PATH (стандартно в Windows)

## Проверка работы

После установки плагин автоматически проверит:
1. Наличие Windows Firewall
2. Состояние firewall (включен/выключен)
3. Доступность команды `netsh`

Статус можно проверить через:
```bash
python run_cli.py get-plugin-health com.example.windows_firewall
```

## Ограничения

- Плагин работает только на Windows
- Требуются права администратора
- Управление через `netsh` (не PowerShell cmdlets)

## Безопасность

Плагин использует безопасное выполнение команд через `core_api.run_command_safely()`:
- Валидация всех аргументов
- Белый список разрешенных операций
- Проверка на опасные паттерны

