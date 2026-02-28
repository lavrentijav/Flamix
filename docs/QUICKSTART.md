# Быстрый старт Flamix

## Установка

```bash
# Клонирование репозитория
git clone <repository>
cd Flamix

# Создание виртуального окружения
python -m venv venv
source venv/bin/activate  # Linux/macOS
# или
venv\Scripts\activate  # Windows

# Установка зависимостей
pip install -r requirements.txt
pip install -e .
```

## Запуск агента

Агент должен запускаться с правами root (для работы с firewall):

**Без установки:**
```bash
# Linux/macOS
sudo python3 run_agent.py
# или
sudo ./run.sh agent

# Windows (от имени администратора)
python run_agent.py
# или
run.bat agent
```

**После установки:**
```bash
# Linux/macOS
sudo flamix-agent

# Windows (от имени администратора)
flamix-agent
```

Агент будет слушать IPC соединения и готов к работе.

## Запуск GUI

В отдельном терминале (без root):

**Без установки:**
```bash
python3 run_gui.py
# или
./run.sh gui
```

**После установки:**
```bash
flamix-gui
```

## Установка примера плагина

### 1. Создание ZIP плагина

```bash
cd examples/iptables_plugin
python ../../scripts/create_plugin_zip.py . ../../iptables_plugin.zip
```

### 2. Установка через CLI

**Без установки:**
```bash
python3 run_cli.py install-plugin ../../iptables_plugin.zip
python3 run_cli.py enable-plugin com.example.minimal_iptables
```

**После установки:**
```bash
flamix-cli install-plugin ../../iptables_plugin.zip
flamix-cli enable-plugin com.example.minimal_iptables
```

### 3. Проверка установки

```bash
# Без установки
python3 run_cli.py list-plugins

# После установки
flamix-cli list-plugins
```

## Применение правила (через IPC/API)

Пример применения правила через Python:

```python
import asyncio
# TODO: Реализовать IPC клиент
# await client.apply_rule("com.example.minimal_iptables", {
#     "port": 80,
#     "protocol": "tcp",
#     "action": "accept",
#     "chain": "INPUT"
# })
```

## Структура директорий

После первого запуска будут созданы:

- Linux/macOS:
  - `/var/lib/flamix/` - данные плагинов
  - `/var/log/flamix/` - логи

- Windows:
  - `C:\ProgramData\flamix\` - данные плагинов
  - `C:\ProgramData\flamix\logs\` - логи

## Устранение проблем

### Агент не запускается

- Проверьте права доступа (нужен root/admin)
- Проверьте что порты/сокеты не заняты
- Проверьте логи в `/var/log/flamix/` или `C:\ProgramData\flamix\logs\`

### Плагин не загружается

- Проверьте формат `manifest.json`
- Убедитесь что `api_version` соответствует версии ядра
- Проверьте что все зависимости установлены

### Команды не выполняются

- Убедитесь что плагин имеет нужные `permissions` в манифесте
- Проверьте что команда есть в whitelist `PermissionManager`
- Проверьте логи агента

## Следующие шаги

1. Изучите [ARCHITECTURE.md](ARCHITECTURE.md) для понимания архитектуры
2. Прочитайте [CONTRIBUTING.md](CONTRIBUTING.md) для разработки плагинов
3. Создайте свой плагин по примеру в `examples/`

