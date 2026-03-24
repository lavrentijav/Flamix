"""Plugin system for firewall management"""

from flamix.client.plugins.base import FirewallPlugin
from flamix.client.plugins.manager import PluginManager

__all__ = ['FirewallPlugin', 'PluginManager']
