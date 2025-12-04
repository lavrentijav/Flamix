"""API для плагинов"""

from .plugin_interface import PluginInterface
from .core_api import CoreAPI, SecurityError

__all__ = ["PluginInterface", "CoreAPI", "SecurityError"]

