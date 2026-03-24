# NetSh Windows Firewall Plugin

Плагин для управления Windows Firewall через утилиту NetSh (Network Shell).

## Описание

Этот плагин позволяет управлять правилами Windows Firewall через командную строку NetSh. Он поддерживает создание правил для входящего и исходящего трафика с различными параметрами.

## Требования

- Windows (любая версия с Windows Firewall)
- **Права администратора (обязательно!)** - для управления правилами firewall через NetSh
- NetSh (встроен в Windows)

**Важно:** Все операции с Windows Firewall требуют запуска с правами администратора. Запустите PowerShell или командную строку от имени администратора перед использованием плагина.

## Установка

1. Упакуйте плагин в ZIP-архив:
   ```bash
   cd plugins/netsh
   zip -r netsh-plugin.zip manifest.json plugin.py
   ```

2. Установите плагин через скрипт установки (из корневой директории проекта):
   ```bash
   cd D:\Projects\python\Flamix
   python install_plugin.py plugins/netsh/netsh-plugin.zip
   ```
   
   Скрипт автоматически установит и включит плагин.

## Использование

### Примеры правил

#### Разрешить входящий трафик на порт 80 (HTTP)
```json
{
  "name": "Allow HTTP Inbound",
  "direction": "in",
  "action": "allow",
  "protocol": "TCP",
  "local_port": "80",
  "profile": "any"
}
```

#### Заблокировать исходящий трафик на определенный IP
```json
{
  "name": "Block Outbound to IP",
  "direction": "out",
  "action": "block",
  "protocol": "ANY",
  "remote_ip": "192.168.1.100",
  "profile": "any"
}
```

#### Разрешить программе доступ в сеть
```json
{
  "name": "Allow Program",
  "direction": "out",
  "action": "allow",
  "protocol": "ANY",
  "program": "C:\\Program Files\\MyApp\\app.exe",
  "profile": "any"
}
```

#### Разрешить входящий трафик на порты 80 и 443
```json
{
  "name": "Allow Web Traffic",
  "direction": "in",
  "action": "allow",
  "protocol": "TCP",
  "local_port": "80,443",
  "profile": "any"
}
```

## Параметры правил

### Обязательные параметры

- **name** (string): Имя правила (уникальное)
- **direction** (string): Направление трафика - `"in"` (входящий) или `"out"` (исходящий)
- **action** (string): Действие - `"allow"` (разрешить) или `"block"` (заблокировать)
- **protocol** (string): Протокол - `"TCP"`, `"UDP"`, `"ICMP"` или `"ANY"`

### Опциональные параметры

- **local_port** (string): Локальный порт (например, `"80"`, `"80,443"` или `"any"`)
- **remote_port** (string): Удаленный порт
- **local_ip** (string): Локальный IP адрес (например, `"192.168.1.1"` или `"any"`)
- **remote_ip** (string): Удаленный IP адрес или подсеть (например, `"192.168.1.0/24"` или `"any"`)
- **profile** (string): Профиль Windows Firewall - `"domain"`, `"private"`, `"public"` или `"any"`
- **program** (string): Путь к программе (например, `"C:\\Program Files\\App\\app.exe"`)

## Проверка состояния

Проверить состояние плагина можно через метод `get_health()`:

```python
health = await plugin.get_health()
# Возвращает:
# {
#   "status": "ok",
#   "netsh_available": true,
#   "firewall_enabled": true,
#   "firewall_profiles": {
#     "domain": {"enabled": true},
#     "private": {"enabled": true},
#     "public": {"enabled": false}
#   }
# }
```

## Примечания

- **Плагин требует прав администратора для работы** - запускайте CLI/GUI от имени администратора
- Имена правил должны быть уникальными
- При создании правила с существующим именем NetSh может выдать ошибку
- Для удаления правил используйте стандартные команды NetSh или Windows Firewall GUI
- Если вы видите пустую ошибку при применении правила, это обычно означает, что команда требует прав администратора

## Пример команды NetSh

Плагин создает команды вида:
```cmd
netsh advfirewall firewall add rule name="Allow HTTP" dir=in action=allow protocol=TCP localport=80 profile=any
```

## Лицензия

Часть проекта Flamix.
