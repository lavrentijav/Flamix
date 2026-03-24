"""Adapter to convert PluginInterface to FirewallPlugin"""

import asyncio
import logging
from typing import Dict, Any, List, Optional

from flamix.client.plugins.base import FirewallPlugin
from flamix.api.plugin_interface import PluginInterface
from flamix.api.core_api import CoreAPI

logger = logging.getLogger(__name__)


class PluginAdapter(FirewallPlugin):
    """Adapter that wraps PluginInterface to make it compatible with FirewallPlugin"""
    
    def __init__(self, plugin: PluginInterface, plugin_id: str, manifest: Dict[str, Any]):
        """
        Initialize adapter
        
        Args:
            plugin: PluginInterface instance to wrap
            plugin_id: ID of the plugin
            manifest: Plugin manifest dictionary
        """
        super().__init__()
        self.plugin = plugin
        self.plugin_id = plugin_id
        self.manifest = manifest
        self.plugin.plugin_id = plugin_id
        self._initialized = False
        self._enabled = False
        self._initialization_error: Optional[str] = None
        self._init_lock = asyncio.Lock()
        
        # Initialize CoreAPI with permissions from manifest
        permissions = manifest.get('permissions', [])
        self.core_api = CoreAPI(plugin_id, permissions)
        
        logger.debug(f"PluginAdapter created for plugin {plugin_id}")
    
    async def _ensure_initialized(self):
        """Ensure plugin is initialized with CoreAPI"""
        if self._initialized:
            return

        async with self._init_lock:
            if self._initialized:
                return

            try:
                await self.plugin.on_init(self.core_api)
                await self.plugin.on_enable()
                self.plugin.enabled = True
                self._enabled = True
                self._initialized = True
                self._initialization_error = None
                logger.debug(f"Plugin {self.plugin_id} initialized and enabled")
            except Exception as e:
                self.plugin.enabled = False
                self._enabled = False
                self._initialization_error = str(e)
                logger.error(f"Error initializing plugin {self.plugin_id}: {e}", exc_info=True)
                raise
    
    async def apply_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Apply a firewall rule"""
        try:
            await self._ensure_initialized()
            return await self.plugin.apply_rule(rule)
        except Exception as e:
            logger.error(f"Error in plugin.apply_rule: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "rule_id": None
            }
    
    async def remove_rule(self, rule_name: str) -> Dict[str, Any]:
        """Remove a firewall rule"""
        try:
            await self._ensure_initialized()
            return await self.plugin.remove_rule(rule_name)
        except Exception as e:
            logger.error(f"Error in plugin.remove_rule: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_current_rules(self) -> List[Dict[str, Any]]:
        """Get list of currently active firewall rules"""
        try:
            await self._ensure_initialized()
            return await self.plugin.get_current_rules()
        except Exception as e:
            logger.error(f"Error in plugin.get_current_rules: {e}", exc_info=True)
            return []
    
    async def get_traffic_stats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent traffic statistics from firewall logs"""
        try:
            await self._ensure_initialized()
            return await self.plugin.get_traffic_stats(limit)
        except Exception as e:
            logger.error(f"Error in plugin.get_traffic_stats: {e}", exc_info=True)
            return []
    
    async def get_health(self) -> Dict[str, Any]:
        """Check plugin health"""
        try:
            await self._ensure_initialized()
            return await self.plugin.get_health()
        except Exception as e:
            logger.error(f"Error in plugin.get_health: {e}", exc_info=True)
            return {
                "status": "error",
                "error": str(e)
            }
    
    def is_available(self) -> bool:
        """Check if this plugin can run on the current system"""
        try:
            if self._initialization_error:
                return False

            # Check platform compatibility from manifest
            import sys
            platform_name = sys.platform.lower()
            
            # Normalize platform names
            if platform_name.startswith('win'):
                platform_name = 'windows'
            elif platform_name.startswith('linux'):
                platform_name = 'linux'
            elif platform_name.startswith('darwin'):
                platform_name = 'macos'
            
            # Check if current platform is supported
            supported_platforms = self.manifest.get('platforms', [])
            if supported_platforms and platform_name not in [p.lower() for p in supported_platforms]:
                logger.debug(f"Plugin {self.plugin_id} does not support platform {platform_name}")
                return False
            
            # Call plugin's is_available if it's implemented
            return self.plugin.is_available()
        except Exception as e:
            logger.error(f"Error checking plugin availability: {e}", exc_info=True)
            return False
