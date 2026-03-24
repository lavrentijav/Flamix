"""Base interface for firewall plugins"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class FirewallPlugin(ABC):
    """Abstract base class for firewall plugins"""

    def __init__(self):
        """Initialize the plugin"""
        self.plugin_id = None
        self.enabled = False

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

    @abstractmethod
    async def remove_rule(self, rule_name: str) -> Dict[str, Any]:
        """
        Remove a firewall rule

        Args:
            rule_name: Name of the rule to remove

        Returns:
            Dict with 'success' (bool) and optionally 'error' (str)
        """
        pass

    @abstractmethod
    async def get_current_rules(self) -> List[Dict[str, Any]]:
        """
        Get list of currently active firewall rules

        Returns:
            List of rule dictionaries
        """
        pass

    @abstractmethod
    async def get_traffic_stats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent traffic statistics from firewall logs

        Args:
            limit: Maximum number of entries to return

        Returns:
            List of traffic stat dictionaries with fields:
            - timestamp: ISO format timestamp
            - src_ip: Source IP address
            - dst_ip: Destination IP address
            - src_port: Source port (optional)
            - dst_port: Destination port (optional)
            - protocol: Protocol (TCP/UDP/ICMP)
            - action: Action taken (allow/block)
            - bytes_in: Bytes received (optional)
            - bytes_out: Bytes sent (optional)
        """
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
    def is_available(self) -> bool:
        """
        Check if this plugin can run on the current system

        Returns:
            True if plugin is available on this platform
        """
        pass
