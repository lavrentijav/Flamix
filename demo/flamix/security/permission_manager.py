"""Менеджер разрешений для плагинов"""

import logging
from typing import Dict, List, Set, Optional
import re

logger = logging.getLogger(__name__)


class PermissionManager:
    """Управление разрешениями плагинов"""

    def __init__(self):
        self._plugin_permissions: Dict[str, Set[str]] = {}
        self._allowed_commands: Set[str] = {"netsh", "iptables", "ufw", "firewalld"}
        self._allowed_patterns: Dict[str, List[re.Pattern]] = {}

    def register_plugin(self, plugin_id: str, permissions: List[str]):
        """
        Регистрация разрешений для плагина
        
        Args:
            plugin_id: ID плагина
            permissions: Список разрешений
        """
        self._plugin_permissions[plugin_id] = set(permissions)
        logger.info(f"Registered permissions for plugin {plugin_id}: {permissions}")

    def check_permission(self, plugin_id: str, permission: str) -> bool:
        """
        Проверка разрешения для плагина
        
        Args:
            plugin_id: ID плагина
            permission: Разрешение для проверки
            
        Returns:
            True если разрешение есть
        """
        plugin_perms = self._plugin_permissions.get(plugin_id, set())
        
        # Точное совпадение
        if permission in plugin_perms:
            return True
        
        # Проверка паттернов (например, run_shell_commands:*)
        for perm in plugin_perms:
            if perm.endswith(":*"):
                prefix = perm[:-2]
                if permission.startswith(prefix + ":"):
                    return True
        
        return False

    def validate_command_args(self, command: str, args: List[str]) -> bool:
        """
        Валидация аргументов команды по белому списку
        
        Args:
            command: Имя команды
            args: Список аргументов
            
        Returns:
            True если аргументы валидны
        """
        # Базовые проверки безопасности
        if not args:
            return True
        
        # Проверка на опасные паттерны
        dangerous_patterns = [
            r'[;&|`]',  # Command injection
            r'\$\(',    # Command substitution
            r'<|>',     # Redirection
        ]
        
        args_str = " ".join(args)
        for pattern in dangerous_patterns:
            if re.search(pattern, args_str):
                logger.warning(f"Dangerous pattern detected in command args: {pattern}")
                return False
        
        return True

    def get_plugin_permissions(self, plugin_id: str) -> Set[str]:
        """
        Получение всех разрешений плагина
        
        Args:
            plugin_id: ID плагина
            
        Returns:
            Множество разрешений
        """
        return self._plugin_permissions.get(plugin_id, set()).copy()
