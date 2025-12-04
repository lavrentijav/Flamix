"""Главный модуль агента"""

import asyncio
import logging
import sys
from pathlib import Path

from flamix.config import ensure_directories, SOCKET_PATH, NAMED_PIPE_NAME
from flamix.security import PermissionManager
from flamix.plugins.manager import PluginManager
from flamix.database.rules_db import RulesDB
from flamix.ipc.jsonrpc_server import JSONRPCServer, UnixSocketServer, NamedPipeServer
import os

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


class FlamixAgent:
    """Главный класс агента"""

    def __init__(self):
        ensure_directories()

        self.permission_manager = PermissionManager()
        self.plugin_manager = PluginManager(self.permission_manager)
        self.db = RulesDB()
        self.rpc_server = JSONRPCServer()
        self.ipc_server = None

        # Регистрация JSON-RPC методов
        self._register_rpc_methods()

    def _register_rpc_methods(self):
        """Регистрация методов JSON-RPC"""
        self.rpc_server.register_method("flamix.list_plugins", self._list_plugins)
        self.rpc_server.register_method("flamix.install_plugin", self._install_plugin)
        self.rpc_server.register_method("flamix.enable_plugin", self._enable_plugin)
        self.rpc_server.register_method("flamix.disable_plugin", self._disable_plugin)
        self.rpc_server.register_method("flamix.uninstall_plugin", self._uninstall_plugin)
        self.rpc_server.register_method("flamix.get_plugin_health", self._get_plugin_health)
        self.rpc_server.register_method("flamix.get_plugin_manifest", self._get_plugin_manifest)
        self.rpc_server.register_method("flamix.detect_firewalls", self._detect_firewalls)
        self.rpc_server.register_method("flamix.apply_rule", self._apply_rule)
        self.rpc_server.register_method("flamix.get_rules", self._get_rules)
        self.rpc_server.register_method("flamix.get_audit_log", self._get_audit_log)

    async def _list_plugins(self):
        """Список плагинов"""
        return self.plugin_manager.list_plugins()

    async def _install_plugin(self, zip_path: str):
        """Установка плагина"""
        plugin_id = await self.plugin_manager.install_plugin(Path(zip_path))
        manifest = self.plugin_manager.plugins[plugin_id]["manifest"]
        await self.db.add_plugin(plugin_id, manifest.permissions)
        return {"plugin_id": plugin_id}

    async def _enable_plugin(self, plugin_id: str):
        """Включение плагина"""
        await self.plugin_manager.enable_plugin(plugin_id)
        return {"status": "enabled"}

    async def _disable_plugin(self, plugin_id: str):
        """Отключение плагина"""
        await self.plugin_manager.disable_plugin(plugin_id)
        return {"status": "disabled"}

    async def _uninstall_plugin(self, plugin_id: str):
        """Удаление плагина"""
        await self.plugin_manager.uninstall_plugin(plugin_id)
        return {"status": "uninstalled"}

    async def _get_plugin_health(self, plugin_id: str):
        """Статус здоровья плагина"""
        return await self.plugin_manager.get_plugin_health(plugin_id)

    async def _get_plugin_manifest(self, plugin_id: str):
        """Получение манифеста плагина"""
        if plugin_id not in self.plugin_manager.plugins:
            raise Exception(f"Plugin {plugin_id} not found")
        
        plugin_info = self.plugin_manager.plugins[plugin_id]
        manifest = plugin_info["manifest"]
        
        # Преобразуем Pydantic модель в dict
        return manifest.dict()

    async def _detect_firewalls(self, plugin_id: str):
        """Детект firewall для плагина"""
        # Обновляем detect_firewalls в CoreAPI
        firewalls = await self.plugin_manager.detect_firewalls(plugin_id)
        return firewalls

    async def _apply_rule(self, plugin_id: str, rule: dict):
        """Применение правила через плагин"""
        if plugin_id not in self.plugin_manager.plugins:
            raise Exception(f"Plugin {plugin_id} not found")

        plugin_info = self.plugin_manager.plugins[plugin_id]
        if not plugin_info["enabled"]:
            raise Exception(f"Plugin {plugin_id} is not enabled")

        instance = plugin_info["instance"]
        await instance.apply_rule(rule)

        # Сохранение в БД
        import json
        rule_id = await self.db.add_rule(plugin_id, json.dumps(rule))
        await self.db.log_audit(
            plugin_id,
            "apply_rule",
            "firewall",
            "success",
            {"rule_id": rule_id, "rule": rule}
        )

        return {"rule_id": rule_id, "status": "applied"}

    async def _get_rules(self, plugin_id: str = None, limit: int = 100):
        """Получение правил"""
        return await self.db.get_rules(plugin_id, limit)

    async def _get_audit_log(self, plugin_id: str = None, limit: int = 100):
        """Получение логов аудита"""
        return await self.db.get_audit_log(plugin_id, limit)

    async def start(self):
        """Запуск агента"""
        logger.info("Starting Flamix Agent...")

        # Инициализация БД
        await self.db.initialize()

        # Запуск IPC сервера
        if os.name == "nt":  # Windows
            self.ipc_server = NamedPipeServer(NAMED_PIPE_NAME, self.rpc_server)
        else:  # Linux/macOS
            self.ipc_server = UnixSocketServer(SOCKET_PATH, self.rpc_server)

        await self.ipc_server.start()

        logger.info("Flamix Agent started successfully")

        # Основной цикл
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")

    async def stop(self):
        """Остановка агента"""
        if self.ipc_server:
            await self.ipc_server.stop()
        logger.info("Flamix Agent stopped")


def main():
    """Точка входа"""
    agent = FlamixAgent()
    try:
        asyncio.run(agent.start())
    except KeyboardInterrupt:
        asyncio.run(agent.stop())


if __name__ == "__main__":
    main()

