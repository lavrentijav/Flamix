"""Модель манифеста плагина"""

from typing import Dict, List, Optional, Any
import json


class FirewallSupport:
    """Поддержка файрвола в манифесте"""
    
    def __init__(self, **kwargs):
        self.name = kwargs.get("name", "")
        self.versions = kwargs.get("versions", {})
        self.detect = kwargs.get("detect", {})
        self.regex = kwargs.get("regex", [])
        self.requires_root = kwargs.get("requires_root", False)
        self.priority = kwargs.get("priority", 100)


class PluginManifest:
    """Манифест плагина"""
    
    def __init__(self, **kwargs):
        self.id = kwargs.get("id", "")
        self.name = kwargs.get("name", "")
        self.version = kwargs.get("version", "1.0.0")
        self.author = kwargs.get("author", "")
        self.platforms = kwargs.get("platforms", [])
        self.entry_point = kwargs.get("entry_point", "plugin.py")
        self.capabilities = kwargs.get("capabilities", [])
        self.permissions = kwargs.get("permissions", [])
        self.dependencies = kwargs.get("dependencies", {})
        self.signature = kwargs.get("signature", "")
        self.checksum = kwargs.get("checksum", "")
        self.api_version = kwargs.get("api_version", "1.0")
        self.firewall_support = kwargs.get("firewall_support", [])
        self.rule_schema = kwargs.get("rule_schema")
    
    def dict(self) -> Dict[str, Any]:
        """Преобразование в словарь"""
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "platforms": self.platforms,
            "entry_point": self.entry_point,
            "capabilities": self.capabilities,
            "permissions": self.permissions,
            "dependencies": self.dependencies,
            "signature": self.signature,
            "checksum": self.checksum,
            "api_version": self.api_version,
            "firewall_support": self.firewall_support,
            "rule_schema": self.rule_schema,
        }
