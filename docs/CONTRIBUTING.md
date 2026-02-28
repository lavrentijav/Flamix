# Руководство по разработке Flamix

## Установка для разработки

```bash
git clone <repository>
cd Flamix
python -m venv venv
source venv/bin/activate  # Linux/macOS
# или
venv\Scripts\activate  # Windows

pip install -r requirements.txt
pip install -e .
```

## Структура проекта

- `flamix/` - Основной код проекта
- `examples/` - Примеры плагинов
- `scripts/` - Вспомогательные скрипты
- `tests/` - Тесты (планируется)

## Создание плагина

1. Создайте директорию плагина:
```bash
mkdir my_plugin
cd my_plugin
```

2. Создайте `manifest.json` согласно спецификации

3. Создайте `plugin.py` с классом, наследующимся от `PluginInterface`

4. Упакуйте в ZIP:
```bash
python ../../scripts/create_plugin_zip.py . ../my_plugin.zip
```

## Тестирование

```bash
# Линтинг
pylint flamix/
black flamix/
bandit -r flamix/

# Тесты (когда будут добавлены)
pytest
```

## Правила безопасности

- **НИКОГДА** не выполняйте произвольные shell-команды
- Все команды должны проходить через `core_api.run_command_safely()`
- Валидируйте все входные данные
- Используйте белые списки для аргументов команд

## Коммиты

Используйте понятные сообщения коммитов:
- `feat: добавлена поддержка nftables`
- `fix: исправлена валидация аргументов iptables`
- `docs: обновлена документация`

