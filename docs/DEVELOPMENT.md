# Руководство по разработке Flamix

## Запуск без установки

Flamix можно запускать напрямую из исходников без установки пакета. Это удобно для разработки и тестирования.

### Требования

Установите только зависимости:

```bash
pip install -r requirements.txt
```

### Запуск компонентов

#### Linux/macOS

```bash
# Сделать скрипты исполняемыми (один раз)
chmod +x run.sh run_agent.py run_cli.py run_gui.py

# Агент (требует root)
sudo python3 run_agent.py
# или через обертку
sudo ./run.sh agent

# CLI
python3 run_cli.py list-plugins
# или
./run.sh cli list-plugins

# GUI
python3 run_gui.py
# или
./run.sh gui
```

#### Windows

```cmd
REM Агент (требует права администратора)
python run_agent.py
REM или
run.bat agent

REM CLI
python run_cli.py list-plugins
REM или
run.bat cli list-plugins

REM GUI
python run_gui.py
REM или
run.bat gui
```

### Прямой запуск модулей

Также можно запускать напрямую через Python:

```bash
# Агент
python3 -m flamix.agent.main

# CLI
python3 -m flamix.cli.main list-plugins

# GUI
python3 -m flamix.gui.main
```

Но для этого нужно добавить путь к проекту в PYTHONPATH:

```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
python3 -m flamix.agent.main
```

## Структура скриптов запуска

Все скрипты (`run_agent.py`, `run_cli.py`, `run_gui.py`) работают одинаково:

1. Добавляют корневую директорию проекта в `sys.path`
2. Импортируют и запускают соответствующий модуль

Это позволяет запускать Flamix без установки пакета в систему.

## Разработка плагинов

При разработке плагинов удобно использовать запуск без установки:

```bash
# 1. Запустить агент
sudo python3 run_agent.py

# 2. В другом терминале - установить плагин
python3 run_cli.py install-plugin ./my_plugin.zip

# 3. Включить плагин
python3 run_cli.py enable-plugin com.example.my_plugin
```

## Отладка

Для отладки можно запускать с дополнительными опциями Python:

```bash
# С выводом всех исключений
python3 -u run_agent.py

# С профилированием
python3 -m cProfile run_agent.py

# С отладчиком
python3 -m pdb run_agent.py
```

## Переменные окружения

Можно настроить поведение через переменные окружения:

```bash
# Уровень логирования
export FLAMIX_LOG_LEVEL=DEBUG

# Путь к конфигурации (если будет добавлен)
export FLAMIX_CONFIG=/path/to/config.yaml

# Запуск агента
python3 run_agent.py
```

## Сравнение: с установкой vs без установки

| Действие | С установкой | Без установки |
|----------|--------------|---------------|
| Установка зависимостей | `pip install -r requirements.txt`<br>`pip install -e .` | `pip install -r requirements.txt` |
| Запуск агента | `sudo flamix-agent` | `sudo python3 run_agent.py` |
| Запуск CLI | `flamix-cli list-plugins` | `python3 run_cli.py list-plugins` |
| Запуск GUI | `flamix-gui` | `python3 run_gui.py` |
| Преимущества | Команды короче, в PATH | Не нужно устанавливать, быстрее для разработки |

## Рекомендации

- **Для разработки**: используйте запуск без установки
- **Для продакшена**: установите пакет через `pip install -e .`
- **Для тестирования**: можно использовать оба способа

