"""Менеджер разрешений для плагинов"""

import re
from typing import List, Dict, Set
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class PermissionManager:
    """Управление разрешениями плагинов"""

    # Белые списки разрешенных аргументов для команд
    COMMAND_WHITELIST: Dict[str, List[List[str]]] = {
        "iptables": [
            ["-A", "INPUT"],  # Добавить правило в цепочку INPUT
            ["-A", "OUTPUT"],
            ["-A", "FORWARD"],
            ["-D", "INPUT"],  # Удалить правило
            ["-D", "OUTPUT"],
            ["-D", "FORWARD"],
            ["-I", "INPUT"],  # Вставить правило
            ["-I", "OUTPUT"],
            ["-I", "FORWARD"],
            ["-p", "tcp"],  # Протокол
            ["-p", "udp"],
            ["--dport"],  # Порт назначения
            ["--sport"],  # Порт источника
            ["-j", "ACCEPT"],  # Действие
            ["-j", "DROP"],
            ["-j", "REJECT"],
            ["-s"],  # Источник
            ["-d"],  # Назначение
        ],
        "nft": [
            ["add", "rule"],
            ["delete", "rule"],
            ["list", "ruleset"],
        ],
        "netsh": [
            ["advfirewall", "firewall", "add", "rule"],
            ["advfirewall", "firewall", "delete", "rule"],
            ["advfirewall", "firewall", "show", "rule"],
            ["advfirewall", "show", "allprofiles"],
        ],
        "powershell": [
            ["-Command", "Get-NetFirewallRule"],
            ["-Command", "New-NetFirewallRule"],
            ["-Command", "Remove-NetFirewallRule"],
        ],
    }

    def __init__(self):
        self.plugin_permissions: Dict[str, Set[str]] = {}

    def register_plugin(self, plugin_id: str, permissions: List[str]):
        """Регистрация разрешений плагина"""
        self.plugin_permissions[plugin_id] = set(permissions)
        logger.info(f"Registered permissions for plugin {plugin_id}: {permissions}")

    def unregister_plugin(self, plugin_id: str):
        """Удаление регистрации плагина"""
        if plugin_id in self.plugin_permissions:
            del self.plugin_permissions[plugin_id]
            logger.info(f"Unregistered plugin {plugin_id}")

    def check_permission(self, plugin_id: str, permission: str) -> bool:
        """
        Проверка разрешения
        
        Args:
            plugin_id: ID плагина
            permission: Разрешение в формате "тип:детали"
            
        Returns:
            True если разрешено, False иначе
        """
        if plugin_id not in self.plugin_permissions:
            logger.warning(f"Plugin {plugin_id} not registered")
            return False

        permissions = self.plugin_permissions[plugin_id]

        # Точное совпадение
        if permission in permissions:
            return True

        # Проверка паттернов (например, read_file:/etc/nftables.conf)
        for perm in permissions:
            if self._match_permission_pattern(perm, permission):
                return True

        logger.warning(f"Permission denied: {plugin_id} -> {permission}")
        return False

    def _match_permission_pattern(self, pattern: str, permission: str) -> bool:
        """
        Проверка соответствия паттерну разрешения
        
        Поддерживает:
        - read_file:/etc/* -> read_file:/etc/nftables.conf
        - run_shell_commands:iptables -> run_shell_commands:iptables
        """
        if pattern == permission:
            return True

        # Простая поддержка wildcard
        if "*" in pattern:
            pattern_regex = pattern.replace("*", ".*")
            if re.match(pattern_regex, permission):
                return True

        return False

    def validate_command_args(self, command: str, args: List[str]) -> bool:
        """
        Валидация аргументов команды по белому списку
        
        Args:
            command: Имя команды
            args: Список аргументов
            
        Returns:
            True если аргументы разрешены
        """
        if command not in self.COMMAND_WHITELIST:
            logger.warning(f"Command {command} not in whitelist")
            return False

        # Проверка на опасные паттерны
        if not self._is_safe_args(args):
            return False

        # Для каждой команды своя валидация
        if command == "iptables":
            return self._validate_iptables_args(args)
        elif command == "nft":
            return self._validate_nft_args(args)
        elif command == "netsh":
            return self._validate_netsh_args(args)
        elif command == "powershell":
            return self._validate_powershell_args(args)

        # Если команда в whitelist, но нет специальной валидации
        return True

    def _validate_iptables_args(self, args: List[str]) -> bool:
        """Валидация аргументов iptables"""
        if not args:
            return False

        # Первый аргумент должен быть операция (-A, -D, -I)
        if args[0] not in ["-A", "-D", "-I"]:
            return False

        # Второй аргумент должен быть цепочка
        if len(args) < 2 or args[1] not in ["INPUT", "OUTPUT", "FORWARD"]:
            return False

        # Проверка остальных аргументов
        i = 2
        while i < len(args):
            arg = args[i]
            if arg == "-p":
                if i + 1 >= len(args) or args[i + 1] not in ["tcp", "udp", "icmp"]:
                    return False
                i += 2
            elif arg in ["--dport", "--sport"]:
                if i + 1 >= len(args):
                    return False
                # Проверка что порт - число
                try:
                    port = int(args[i + 1])
                    if not (1 <= port <= 65535):
                        return False
                except ValueError:
                    return False
                i += 2
            elif arg == "-j":
                if i + 1 >= len(args) or args[i + 1] not in ["ACCEPT", "DROP", "REJECT"]:
                    return False
                i += 2
            elif arg in ["-s", "-d"]:
                # IP адрес или сеть - базовая проверка
                if i + 1 >= len(args):
                    return False
                i += 2
            else:
                # Неизвестный аргумент
                return False

        return True

    def _validate_nft_args(self, args: List[str]) -> bool:
        """Валидация аргументов nft"""
        if not args:
            return False

        # Разрешенные операции
        allowed_ops = ["add", "delete", "list"]
        if args[0] not in allowed_ops:
            return False

        # Базовая проверка структуры
        if args[0] == "list" and len(args) >= 2 and args[1] == "ruleset":
            return True
        if args[0] in ["add", "delete"] and len(args) >= 2 and args[1] == "rule":
            return True

        return False

    def _validate_netsh_args(self, args: List[str]) -> bool:
        """Валидация аргументов netsh"""
        if not args or len(args) < 2:
            return False

        # Первый аргумент должен быть "advfirewall"
        if args[0] != "advfirewall":
            return False

        # Второй аргумент - операция
        if args[1] == "firewall":
            if len(args) < 4:
                return False
            # Операции: add rule, delete rule, show rule
            if args[2] in ["add", "delete", "show"] and args[3] == "rule":
                # Дополнительная проверка параметров
                return self._validate_netsh_rule_args(args[2:])
        elif args[1] == "show":
            # show allprofiles state
            if len(args) >= 3 and args[2] in ["allprofiles"]:
                return True

        return False

    def _validate_netsh_rule_args(self, args: List[str]) -> bool:
        """Валидация аргументов для операций с правилами netsh"""
        if not args or args[0] not in ["add", "delete", "show"]:
            return False

        operation = args[0]
        if operation == "add":
            # add rule name=... dir=... action=... protocol=... localport=...
            # Проверяем наличие обязательных параметров
            has_name = any("name" in arg for arg in args)
            has_dir = any("dir" in arg for arg in args)
            has_action = any("action" in arg for arg in args)
            return has_name and has_dir and has_action
        elif operation == "delete":
            # delete rule name=...
            return any("name" in arg for arg in args)
        elif operation == "show":
            # show rule name=all или name=...
            return True  # show всегда безопасен

        return False

    def _validate_powershell_args(self, args: List[str]) -> bool:
        """Валидация аргументов PowerShell"""
        if not args:
            return False

        # Проверяем что используется -Command с безопасными командами
        if args[0] != "-Command":
            return False

        if len(args) < 2:
            return False

        command = args[1].lower()
        # Разрешенные команды для работы с firewall
        allowed_commands = [
            "get-netfirewallrule",
            "new-netfirewallrule",
            "remove-netfirewallrule",
        ]

        for allowed in allowed_commands:
            if command.startswith(allowed):
                return True

        return False

    def _is_safe_args(self, args: List[str]) -> bool:
        """Проверка на опасные аргументы"""
        dangerous_patterns = [
            "rm -rf",
            "dd of=",
            "mkfs",
            "/dev/",
            "> /dev/",
            "|",
            "&&",
            "||",
            ";",
        ]

        args_str = " ".join(args).lower()
        for pattern in dangerous_patterns:
            if pattern in args_str:
                logger.error(f"Dangerous pattern detected: {pattern}")
                return False

        return True

