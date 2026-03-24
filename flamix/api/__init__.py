"""API interfaces for plugins"""

from flamix.api.plugin_interface import PluginInterface
from flamix.api.core_api import CoreAPI, SecurityError

__all__ = ['PluginInterface', 'CoreAPI', 'SecurityError']
