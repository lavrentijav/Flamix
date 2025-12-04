# Flamix

Flamix - расширяемый менеджер firewall с плагинной архитектурой для централизованного управления любыми установленными firewall.

## Архитектура

Flamix построен на модульной архитектуре с системой плагинов:

- **Ядро (Core)**: Управление плагинами, безопасность, IPC
- **Плагины**: ZIP-архивы с манифестом и кодом для поддержки различных firewall
- **GUI**: Графический интерфейс на PySide6
- **CLI**: Командная строка для управления
- **Агент**: Демон для выполнения операций с правами root

## Установка

### Требования

- Python 3.8-3.11
- Linux/macOS/Windows

### Установка из исходников

```bash
pip install -r requirements.txt
pip install -e .
```

## Быстрый старт

### Установка (опционально)

Для установки пакета в систему:

```bash
pip install -r requirements.txt
pip install -e .
```

После установки можно использовать команды `flamix-agent`, `flamix-cli`, `flamix-gui`.

### Запуск без установки

Можно запускать напрямую из исходников без установки:

**Linux/macOS:**
```bash
# Сделать скрипты исполняемыми (один раз)
chmod +x run.sh run_agent.py run_cli.py run_gui.py

# Запуск агента
sudo ./run.sh agent
# или
sudo python3 run_agent.py

# Запуск GUI
./run.sh gui
# или
python3 run_gui.py

# Запуск CLI
./run.sh cli list-plugins
# или
python3 run_cli.py list-plugins
```

**Windows:**
```cmd
REM Запуск агента (от имени администратора)
run.bat agent
REM или
python run_agent.py

REM Запуск GUI
run.bat gui
REM или
python run_gui.py

REM Запуск CLI
run.bat cli list-plugins
REM или
python run_cli.py list-plugins
```

### Использование CLI

```bash
# Список плагинов
python3 run_cli.py list-plugins
# или после установки: flamix-cli list-plugins

# Установка плагина
python3 run_cli.py install-plugin ./plugin.zip

# Включение плагина
python3 run_cli.py enable-plugin com.example.plugin

# Отключение плагина
python3 run_cli.py disable-plugin com.example.plugin
```

## Создание плагина

### Структура плагина

Плагин - это ZIP-архив со следующей структурой:

```
my_plugin/
├── manifest.json      # Обязательный манифест
├── plugin.py          # Точка входа (указана в manifest)
├── scripts/           # Опционально: скрипты для детекта
└── resources/         # Опционально: статические файлы
```

### Пример manifest.json

```json
{
  "id": "com.example.iptables",
  "name": "Iptables Plugin",
  "version": "1.0.0",
  "author": "Your Name",
  "platforms": ["linux"],
  "entry_point": "plugin.py",
  "capabilities": ["manage_rules"],
  "permissions": ["run_shell_commands:iptables"],
  "dependencies": {},
  "signature": "",
  "checksum": "",
  "api_version": "1.0",
  "firewall_support": [
    {
      "name": "iptables",
      "versions": {"min": "1.4.0", "max": null, "exact": []},
      "detect": {"type": "command", "value": "iptables --version"},
      "regex": ["iptables v(\\d+\\.\\d+\\.\\d+)"],
      "requires_root": true,
      "priority": 100
    }
  ]
}
```

### Пример plugin.py

```python
from flamix.api import PluginInterface

class MyPlugin(PluginInterface):
    async def on_install(self):
        pass

    async def on_enable(self):
        pass

    async def on_init(self, core_api):
        self.core_api = core_api
        firewalls = await core_api.detect_firewalls()
        # Инициализация...

    async def on_disable(self):
        pass

    async def on_uninstall(self):
        pass

    async def get_health(self):
        return {"status": "ok"}

    async def apply_rule(self, rule: dict):
        # Применение правила через core_api.run_command_safely()
        pass
```

### Создание ZIP плагина

```bash
cd examples/iptables_plugin
zip -r ../../iptables_plugin.zip .
```

## Безопасность

Flamix реализует модель безопасности с минимальными привилегиями:

- **Sandboxing**: Изоляция плагинов (планируется для Этапа 2)
- **Permissions**: Строгий белый список операций
- **Валидация команд**: Проверка аргументов команд по белому списку
- **Подпись плагинов**: RSA подпись манифестов (планируется)

## Структура проекта

```
flamix/
├── api/              # API для плагинов
├── agent/            # Демон агента
├── cli/              # CLI инструмент
├── config.py         # Конфигурация
├── database/         # База данных правил
├── gui/              # GUI на PySide6
├── ipc/              # IPC механизм (JSON-RPC)
├── models/           # Модели данных
├── plugins/          # Загрузчик и менеджер плагинов
└── security/         # Менеджер разрешений

examples/
└── iptables_plugin/  # Пример плагина
```

## Разработка

### Запуск тестов

```bash
pytest
```

### Линтинг

```bash
pylint flamix/
black flamix/
bandit -r flamix/
```

## Лицензия

MIT License

## Roadmap

- **Этап 1 (MVP)**: ✅ Базовая архитектура, плагины, GUI
- **Этап 2**: Sandboxing, подпись плагинов, поддержка nftables/Windows Firewall
- **Этап 3**: Plugin marketplace, интеграция с SIEM
