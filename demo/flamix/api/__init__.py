"""API для плагинов Flamix"""

from flamix.api.core_api import CoreAPI, SecurityError
from flamix.api.plugin_interface import PluginInterface

__all__ = ["CoreAPI", "PluginInterface", "SecurityError"]
