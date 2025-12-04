"""IPC клиент для связи GUI с агентом"""

import json
import asyncio
import struct
from pathlib import Path
from typing import Dict, Any, Optional
import os
import logging

from flamix.config import SOCKET_PATH, NAMED_PIPE_NAME

logger = logging.getLogger(__name__)


class IPCClient:
    """Клиент для связи с агентом через IPC"""

    def __init__(self):
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connected = False
        self._connection_lock = asyncio.Lock()

    async def connect(self):
        """Подключение к агенту"""
        if self.connected:
            return
            
        async with self._connection_lock:
            if self.connected:
                return
                
            try:
                if os.name == "nt":  # Windows
                    # Для Windows Named Pipe пока не реализован полностью
                    # GUI будет работать без подключения
                    logger.info("Named Pipe client for Windows not fully implemented")
                    logger.info("GUI will work in offline mode. Full IPC support coming soon.")
                    self.connected = False
                    return
                else:  # Linux/macOS
                    if not SOCKET_PATH or not SOCKET_PATH.exists():
                        logger.warning(f"Socket not found: {SOCKET_PATH}")
                        self.connected = False
                        return

                    self.reader, self.writer = await asyncio.open_unix_connection(
                        str(SOCKET_PATH)
                    )
                    self.connected = True
                    logger.info("Connected to agent via Unix socket")
            except Exception as e:
                logger.error(f"Failed to connect to agent: {e}")
                self.connected = False
                # Не выбрасываем исключение, чтобы GUI мог запуститься

    async def disconnect(self):
        """Отключение от агента"""
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
        self.connected = False

    async def call(self, method: str, *params) -> Any:
        """
        Вызов JSON-RPC метода
        
        Args:
            method: Имя метода
            *params: Параметры метода
            
        Returns:
            Результат вызова
        """
        if not self.connected:
            await self.connect()
        
        if not self.connected:
            raise ConnectionError("Not connected to agent. Please start the agent first.")

        try:
            request_id = 1
            request = {
                "jsonrpc": "2.0",
                "method": method,
                "params": list(params) if params else [],
                "id": request_id,
            }

            request_data = json.dumps(request).encode("utf-8")

            # Отправка: длина (4 байта) + данные
            self.writer.write(len(request_data).to_bytes(4, "big"))
            self.writer.write(request_data)
            await self.writer.drain()

            # Чтение ответа: длина (4 байта) + данные
            length_data = await self.reader.readexactly(4)
            length = int.from_bytes(length_data, "big")

            if length > 10 * 1024 * 1024:  # Макс 10 МБ
                raise ValueError("Response too large")

            response_data = await self.reader.readexactly(length)
            response = json.loads(response_data.decode("utf-8"))

            if "error" in response:
                error = response["error"]
                raise Exception(f"RPC Error: {error.get('message', 'Unknown error')}")

            return response.get("result")
        except Exception as e:
            logger.error(f"RPC call failed: {e}")
            self.connected = False
            raise

    # Удобные методы для работы с плагинами
    async def list_plugins(self):
        """Список плагинов"""
        return await self.call("flamix.list_plugins")

    async def get_plugin_manifest(self, plugin_id: str) -> Dict[str, Any]:
        """Получение манифеста плагина"""
        return await self.call("flamix.get_plugin_manifest", plugin_id)

    async def get_rules(self, plugin_id: Optional[str] = None, limit: int = 100):
        """Получение правил"""
        return await self.call("flamix.get_rules", plugin_id, limit)

    async def apply_rule(self, plugin_id: str, rule: Dict[str, Any]):
        """Применение правила"""
        return await self.call("flamix.apply_rule", plugin_id, rule)

    async def get_audit_log(self, plugin_id: Optional[str] = None, limit: int = 100):
        """Получение логов аудита"""
        return await self.call("flamix.get_audit_log", plugin_id, limit)


# Глобальный экземпляр клиента
_client: Optional[IPCClient] = None


def get_client() -> IPCClient:
    """Получение глобального экземпляра клиента"""
    global _client
    if _client is None:
        _client = IPCClient()
    return _client

