"""Core API для плагинов"""

import asyncio
import subprocess
from typing import Dict, Any, List, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Ошибка безопасности"""
    pass


class CoreAPI:
    """Безопасный API для взаимодействия плагинов с ядром"""

    def __init__(self, plugin_id: str, permissions: List[str], permission_manager, plugin_manager=None):
        self.plugin_id = plugin_id
        self.permissions = permissions
        self.permission_manager = permission_manager
        self.plugin_manager = plugin_manager
        self.logger = logging.getLogger(f"flamix.core_api.{plugin_id}")

    async def detect_firewalls(self) -> List[Dict[str, Any]]:
        """
        Детект доступных firewall на системе
        
        Returns:
            Список словарей с информацией о найденных firewall
        """
        if self.plugin_manager:
            # PluginManager теперь синхронный, но вызывается из async контекста плагина
            # Используем asyncio.to_thread для вызова синхронного метода
            try:
                return await asyncio.to_thread(self.plugin_manager.detect_firewalls, self.plugin_id)
            except AttributeError:
                # Для старых версий Python без to_thread
                import concurrent.futures
                loop = asyncio.get_event_loop()
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    return await loop.run_in_executor(executor, self.plugin_manager.detect_firewalls, self.plugin_id)
        return []

    async def run_command_safely(self, command: str, args: List[str]) -> Dict[str, Any]:
        """
        Безопасное выполнение команды с проверкой permissions
        
        Args:
            command: Имя команды (например, "iptables")
            args: Список аргументов
            
        Returns:
            dict с ключами: returncode, stdout, stderr
            
        Raises:
            SecurityError: Если команда не разрешена в permissions
        """
        permission = f"run_shell_commands:{command}"
        if not self.permission_manager.check_permission(self.plugin_id, permission):
            raise SecurityError(f"Permission denied: {permission}")

        # Валидация аргументов по белому списку
        if not self.permission_manager.validate_command_args(command, args):
            raise SecurityError(f"Invalid arguments for command: {command}")

        try:
            process = await asyncio.create_subprocess_exec(
                command,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=30.0
            )

            return {
                "returncode": process.returncode,
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
            }
        except asyncio.TimeoutError:
            raise SecurityError(f"Command timeout: {command}")
        except Exception as e:
            self.logger.error(f"Error executing command {command}: {e}")
            raise SecurityError(f"Command execution failed: {e}")

    async def read_file(self, filepath: str) -> str:
        """
        Безопасное чтение файла
        
        Args:
            filepath: Путь к файлу
            
        Returns:
            Содержимое файла
            
        Raises:
            SecurityError: Если чтение файла не разрешено
        """
        permission = f"read_file:{filepath}"
        if not self.permission_manager.check_permission(self.plugin_id, permission):
            raise SecurityError(f"Permission denied: {permission}")

        try:
            path = Path(filepath)
            if not path.exists():
                raise SecurityError(f"File not found: {filepath}")
            return path.read_text(encoding="utf-8")
        except Exception as e:
            self.logger.error(f"Error reading file {filepath}: {e}")
            raise SecurityError(f"File read failed: {e}")

    async def write_file(self, filepath: str, content: str) -> None:
        """
        Безопасная запись файла
        
        Args:
            filepath: Путь к файлу
            content: Содержимое для записи
            
        Raises:
            SecurityError: Если запись файла не разрешена
        """
        permission = f"write_file:{filepath}"
        if not self.permission_manager.check_permission(self.plugin_id, permission):
            raise SecurityError(f"Permission denied: {permission}")

        try:
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        except Exception as e:
            self.logger.error(f"Error writing file {filepath}: {e}")
            raise SecurityError(f"File write failed: {e}")

    async def log_audit(self, action: str, target: str, details: Dict[str, Any]) -> None:
        """
        Логирование аудита
        
        Args:
            action: Действие (например, "apply_rule")
            target: Цель действия (например, "iptables")
            details: Дополнительные детали
        """
        # Реализация будет в AuditLogger
        logger.info(f"[AUDIT] {self.plugin_id}: {action} -> {target} | {details}")

