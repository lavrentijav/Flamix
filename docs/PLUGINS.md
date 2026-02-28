# Руководство по плагинам Flamix

## Обзор

Плагины Flamix позволяют расширять функциональность системы для работы с различными файрволами и платформами.

## Структура плагина

Плагин - это ZIP-архив, содержащий:

- `manifest.json` - Манифест плагина (обязательно)
- `plugin.py` - Код плагина (обязательно)
- Дополнительные файлы (опционально)

## Манифест плагина

Манифест описывает плагин и его возможности:

```json
{
  "id": "com.flamix.netsh",
  "name": "NetSh Windows Firewall Plugin",
  "version": "1.0.0",
  "author": "Flamix Team",
  "platforms": ["windows"],
  "entry_point": "plugin.py",
  "capabilities": ["manage_rules", "detect_firewall"],
  "permissions": [
    "run_shell_commands:netsh",
    "run_shell_commands:netsh advfirewall"
  ],
  "api_version": "1.0",
  "firewall_support": [
    {
      "name": "Windows Firewall",
      "detect": {
        "type": "command",
        "value": "netsh advfirewall show allprofiles state"
      },
      "requires_root": true,
      "priority": 100
    }
  ]
}
```

### Поля манифеста

- **id**: Уникальный идентификатор (формат: `com.flamix.pluginname`)
- **name**: Отображаемое имя
- **version**: Версия (семантическое версионирование)
- **author**: Автор
- **platforms**: Поддерживаемые платформы
- **entry_point**: Точка входа (обычно `plugin.py`)
- **capabilities**: Возможности плагина
- **permissions**: Требуемые разрешения
- **api_version**: Версия API Flamix
- **firewall_support**: Информация о поддерживаемых файрволах

## Интерфейс плагина

Плагины должны реализовать класс, наследующийся от `PluginInterface`:

```python
from flamix.api.plugin_interface import PluginInterface

class MyPlugin(PluginInterface):
    async def on_install(self):
        """Вызывается при установке плагина"""
        pass
    
    async def on_enable(self):
        """Вызывается при включении плагина"""
        pass
    
    async def on_init(self, core_api):
        """Инициализация плагина с доступом к Core API"""
        self.core_api = core_api
    
    async def on_disable(self):
        """Вызывается при отключении плагина"""
        pass
    
    async def on_uninstall(self):
        """Вызывается при удалении плагина"""
        pass
    
    async def get_health(self):
        """Проверка состояния плагина"""
        return {"status": "ok"}
    
    async def apply_rule(self, rule: dict):
        """Применение правила файрвола"""
        pass
```

## Core API

Плагины получают доступ к Core API через параметр `core_api`:

### detect_firewalls()

Обнаружение файрволов на системе:

```python
firewalls = await self.core_api.detect_firewalls()
```

### run_command_safely(command, args)

Безопасное выполнение команд:

```python
result = await self.core_api.run_command_safely(
    "netsh",
    ["advfirewall", "firewall", "add", "rule"]
)
```

### read_file(path)

Чтение файла:

```python
content = await self.core_api.read_file("/path/to/file")
```

### write_file(path, content)

Запись файла:

```python
await self.core_api.write_file("/path/to/file", content)
```

### log_audit(message)

Логирование аудита:

```python
await self.core_api.log_audit("Rule applied: block 192.168.1.1")
```

## Безопасность

### Правила безопасности

1. **Всегда используйте `core_api.run_command_safely()`** - это обеспечивает валидацию команд
2. **Валидируйте входные данные** - проверяйте все параметры перед использованием
3. **Используйте белые списки** - разрешайте только известные команды и аргументы
4. **Не выполняйте произвольные команды** - избегайте `eval()`, `exec()`, `os.system()`
5. **Проверяйте права доступа** - убедитесь, что у пользователя есть необходимые права

### Разрешения

Плагины должны объявлять все необходимые разрешения в манифесте:

```json
"permissions": [
  "run_shell_commands:netsh",
  "read_file:/etc/iptables/rules",
  "write_file:/etc/iptables/rules"
]
```

## Примеры плагинов

### Windows Firewall (NetSh)

См. [plugins/netsh/](../plugins/netsh/)

### Linux iptables

Пример плагина для iptables:

```python
class IPTablesPlugin(PluginInterface):
    async def apply_rule(self, rule: dict):
        action = rule.get("action")  # "allow" or "block"
        direction = rule.get("direction")  # "inbound" or "outbound"
        protocol = rule.get("protocol")
        port = rule.get("port")
        
        if action == "block":
            chain = "INPUT" if direction == "inbound" else "OUTPUT"
            cmd = ["iptables", "-A", chain, "-p", protocol]
            if port:
                cmd.extend(["--dport", str(port)])
            cmd.append("-j", "DROP")
            
            await self.core_api.run_command_safely("iptables", cmd)
```

## Тестирование плагинов

### Локальное тестирование

1. Установите Flamix Server или Client
2. Поместите плагин в директорию плагинов
3. Запустите сервер/клиент
4. Проверьте логи

### Unit тесты

```python
import pytest
from my_plugin.plugin import MyPlugin

@pytest.mark.asyncio
async def test_plugin_initialization():
    plugin = MyPlugin()
    assert plugin is not None

@pytest.mark.asyncio
async def test_apply_rule():
    plugin = MyPlugin()
    # Mock core_api
    rule = {"action": "block", "direction": "inbound"}
    # Тестирование
```

## Упаковка плагина

### Создание ZIP-архива

```bash
cd my_plugin
zip -r ../my_plugin.zip .
```

### Проверка манифеста

Убедитесь, что `manifest.json` валиден:

```python
import json

with open("manifest.json") as f:
    manifest = json.load(f)
    # Валидация
```

## Публикация плагина

1. Убедитесь, что плагин протестирован
2. Обновите версию в `manifest.json`
3. Упакуйте плагин в ZIP
4. Создайте release в репозитории плагинов
5. Обновите документацию

## Поддержка

- Документация плагинов: [plugins/README.md](../plugins/README.md)
- Примеры: [plugins/](../plugins/)
- API Reference: [DEVELOPMENT.md](DEVELOPMENT.md)
