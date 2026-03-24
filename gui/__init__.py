"""GUI модули для Flamix приложения"""

# Экспортируем менеджеры для использования в основном gui.py
from .client_manager import ClientManager
from .rules_manager import RulesManager
from .analytics_manager import AnalyticsManager
from .change_requests_manager import ChangeRequestsManager
from .monitoring_manager import MonitoringManager
from .settings_manager import SettingsManager

# Импортируем FlamixGUI из родительского модуля (app/gui.py)
# Используем прямой импорт из файла, чтобы избежать конфликта имен
import importlib.util
from pathlib import Path

def _import_flamix_gui():
    """Импорт FlamixGUI из app/gui.py"""
    gui_file = Path(__file__).parent.parent / "gui.py"
    if gui_file.exists():
        spec = importlib.util.spec_from_file_location("app_gui_main", gui_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.FlamixGUI
    raise ImportError(f"Could not find gui.py at {gui_file}")

# Ленивая загрузка FlamixGUI
_FlamixGUI = None

def __getattr__(name):
    """Ленивая загрузка FlamixGUI"""
    global _FlamixGUI
    if name == 'FlamixGUI':
        if _FlamixGUI is None:
            _FlamixGUI = _import_flamix_gui()
        return _FlamixGUI
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

__all__ = [
    'ClientManager',
    'RulesManager',
    'AnalyticsManager',
    'ChangeRequestsManager',
    'MonitoringManager',
    'SettingsManager',
    'FlamixGUI'
]
