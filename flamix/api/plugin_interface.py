"""Base interface for plugins loaded from zip archives"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class PluginInterface(ABC):
    """Base interface for plugins loaded from zip archives"""
    
    def __init__(self):
        """Initialize the plugin"""
        self.plugin_id: Optional[str] = None
        self.core_api: Optional['CoreAPI'] = None
        self.enabled: bool = False
    
    @abstractmethod
    async def on_install(self):
        """Called when plugin is installed"""
        pass
    
    @abstractmethod
    async def on_enable(self):
        """Called when plugin is enabled"""
        pass
    
    @abstractmethod
    async def on_init(self, core_api: 'CoreAPI'):
        """
        Initialize plugin with Core API access
        
        Args:
            core_api: Core API instance for safe operations
        """
        self.core_api = core_api
    
    @abstractmethod
    async def on_disable(self):
        """Called when plugin is disabled"""
        pass
    
    @abstractmethod
    async def on_uninstall(self):
        """Called when plugin is uninstalled"""
        pass
    
    @abstractmethod
    async def get_health(self) -> Dict[str, Any]:
        """
        Check plugin health
        
        Returns:
            Dict with 'status' (ok/warning/error) and other health info
        """
        pass
    
    @abstractmethod
    async def apply_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply a firewall rule
        
        Args:
            rule: Rule dictionary with fields like name, direction, action, protocol, etc.
        
        Returns:
            Dict with 'success' (bool), 'rule_id' (str), and optionally 'error' (str)
        """
        pass
    
    async def remove_rule(self, rule_name: str) -> Dict[str, Any]:
        """
        Remove a firewall rule (optional, default implementation returns error)
        
        Args:
            rule_name: Name of the rule to remove
        
        Returns:
            Dict with 'success' (bool) and optionally 'error' (str)
        """
        return {
            "success": False,
            "error": "remove_rule not implemented by this plugin"
        }
    
    async def get_current_rules(self) -> List[Dict[str, Any]]:
        """
        Get list of currently active firewall rules (optional)
        
        Returns:
            List of rule dictionaries
        """
        return []
    
    async def get_traffic_stats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent traffic statistics from firewall logs (optional)
        
        Args:
            limit: Maximum number of entries to return
        
        Returns:
            List of traffic stat dictionaries
        """
        return []
    
    def is_available(self) -> bool:
        """
        Check if this plugin can run on the current system (optional)
        
        Returns:
            True if plugin is available on this platform
        """
        return True
