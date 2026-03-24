# Реорганизация GUI модулей

Код был реорганизован по логическим группам для более удобного редактирования.

## Структура модулей

### 1. `client_manager.py` - Управление клиентами
**Все функции работы с клиентами:**
- Создание вкладки клиентов (`create_tab()`)
- Обновление списка клиентов (`refresh_clients()`)
- Создание нового клиента (`show_add_client_dialog()`, `create_and_download_client()`)
- Скачивание пакета клиента (`download_client_package()`)
- Просмотр деталей клиента (`_show_client_details()`)
- Удаление клиента (`show_delete_client_dialog()`, `delete_client()`)
- Контекстное меню (`show_client_context_menu()`, `edit_client_from_menu()`, и т.д.)

### 2. `rules_manager.py` - Управление правилами
**Все CRUD операции с правилами:**
- Создание вкладки правил (`create_tab()`)
- Обновление списка правил (`refresh_rules()`)
- Создание правила (`show_add_rule_dialog()`, `create_rule()`)
- Редактирование правила (`show_edit_rule_dialog()`, `update_rule()`)
- Удаление правила (`delete_rule()`)

### 3. `analytics_manager.py` - Аналитика
**Графики и таблицы аналитики:**
- Создание вкладки аналитики (`create_tab()`)
- Обновление аналитики с графиками (`refresh_analytics()`)
- График событий по времени
- График событий по типу
- Таблица аналитических данных

### 4. `change_requests_manager.py` - Запросы на изменение
**Одобрение и отклонение запросов:**
- Создание вкладки запросов (`create_tab()`)
- Обновление списка запросов (`refresh_change_requests()`)
- Одобрение запроса (`approve_request()`)
- Отклонение запроса (`show_reject_dialog()`, `reject_request()`)

### 5. `monitoring_manager.py` - Мониторинг
**Статус, плагины, логи:**
- Создание вкладки мониторинга (`create_tab()`)
- Секция системного статуса (`refresh_monitoring_status()`)
- Секция плагинов (`refresh_monitoring_plugins()`)
- Секция логов (`refresh_monitoring_logs()`)
- Обновление всех данных мониторинга (`refresh_monitoring()`)

### 6. `settings_manager.py` - Настройки
**Шрифты, URL сервера, настройки:**
- Создание вкладки настроек (`create_tab()`)
- Управление шрифтами (`on_font_changed()`, `apply_selected_font()`)
- Управление размером шрифта (`on_font_size_changed()`)
- Сохранение настроек (`save_settings()`)
- Перезагрузка окна (`reload_window()`)

## Как использовать

Основной файл `gui.py` должен быть обновлен для использования этих модулей:

```python
from app.gui.client_manager import ClientManager
from app.gui.rules_manager import RulesManager
from app.gui.analytics_manager import AnalyticsManager
from app.gui.change_requests_manager import ChangeRequestsManager
from app.gui.monitoring_manager import MonitoringManager
from app.gui.settings_manager import SettingsManager

class FlamixGUI:
    def __init__(self, server_url: str = "https://127.0.0.1:8080"):
        # Инициализация менеджеров
        self.client_manager = ClientManager(
            api_client=self.api_client,
            refresh_rules_callback=self.rules_manager.refresh_rules,
            refresh_monitoring_callback=self.monitoring_manager.refresh_monitoring
        )
        self.rules_manager = RulesManager(
            api_client=self.api_client,
            get_current_client_id_callback=lambda: self.client_manager.current_client_id
        )
        # ... и т.д.
```

## Преимущества новой структуры

1. **Логическая группировка** - все функции работы с клиентами в одном месте
2. **Легче найти нужный код** - знаете что ищете клиента? Откройте `client_manager.py`
3. **Удобнее редактировать** - каждый модуль отвечает за свою область
4. **Проще тестировать** - можно тестировать каждый модуль отдельно
5. **Модульность** - можно легко добавлять новые функции в соответствующие модули

## Порядок работы с модулями

1. **Клиенты** - сначала создание окна клиентов, потом дополнительные функции
2. **Правила** - создание окна правил, потом CRUD операции
3. **Аналитика** - создание графиков, потом обновление данных
4. **Запросы** - создание окна, потом одобрение/отклонение
5. **Мониторинг** - создание секций, потом обновление данных
6. **Настройки** - создание окна, потом управление настройками
