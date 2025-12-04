"""JSON-RPC 2.0 сервер для IPC"""

import json
import asyncio
import logging
from typing import Dict, Any, Optional, Callable
from pathlib import Path
import os

logger = logging.getLogger(__name__)


class JSONRPCError(Exception):
    """Ошибка JSON-RPC"""
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(message)


class JSONRPCServer:
    """JSON-RPC 2.0 сервер"""

    # JSON-RPC коды ошибок
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    # Кастомные коды
    PERMISSION_DENIED = -32001
    TIMEOUT = -32002
    INVALID_ARGUMENTS = -32003

    def __init__(self):
        self.methods: Dict[str, Callable] = {}
        self.timeout = 30.0

    def register_method(self, name: str, handler: Callable):
        """Регистрация метода JSON-RPC"""
        self.methods[name] = handler
        logger.debug(f"Registered JSON-RPC method: {name}")

    async def handle_request(self, request_data: bytes) -> bytes:
        """
        Обработка JSON-RPC запроса
        
        Args:
            request_data: JSON-строка запроса
            
        Returns:
            JSON-строка ответа
        """
        try:
            request = json.loads(request_data.decode("utf-8"))
        except json.JSONDecodeError:
            return self._error_response(
                None, self.PARSE_ERROR, "Parse error"
            )

        # Проверка формата запроса
        if not isinstance(request, dict):
            return self._error_response(
                None, self.INVALID_REQUEST, "Invalid Request"
            )

        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params", [])

        if not method or not isinstance(method, str):
            return self._error_response(
                request_id, self.INVALID_REQUEST, "Invalid Request"
            )

        # Поиск метода
        if method not in self.methods:
            return self._error_response(
                request_id, self.METHOD_NOT_FOUND, f"Method not found: {method}"
            )

        # Вызов метода
        try:
            handler = self.methods[method]
            if asyncio.iscoroutinefunction(handler):
                result = await asyncio.wait_for(
                    handler(*params if isinstance(params, list) else [params]),
                    timeout=self.timeout
                )
            else:
                result = handler(*params if isinstance(params, list) else [params])

            return self._success_response(request_id, result)

        except asyncio.TimeoutError:
            return self._error_response(
                request_id, self.TIMEOUT, "Request timeout"
            )
        except JSONRPCError as e:
            return self._error_response(request_id, e.code, e.message, e.data)
        except Exception as e:
            logger.error(f"Error handling method {method}: {e}", exc_info=True)
            return self._error_response(
                request_id, self.INTERNAL_ERROR, str(e)
            )

    def _success_response(self, request_id: Any, result: Any) -> bytes:
        """Формирование успешного ответа"""
        response = {
            "jsonrpc": "2.0",
            "result": result,
            "id": request_id,
        }
        return json.dumps(response).encode("utf-8")

    def _error_response(
        self,
        request_id: Any,
        code: int,
        message: str,
        data: Any = None
    ) -> bytes:
        """Формирование ответа с ошибкой"""
        error = {"code": code, "message": message}
        if data is not None:
            error["data"] = data

        response = {
            "jsonrpc": "2.0",
            "error": error,
            "id": request_id,
        }
        return json.dumps(response).encode("utf-8")


class UnixSocketServer:
    """Unix Domain Socket сервер для Linux/macOS"""

    def __init__(self, socket_path: Path, rpc_server: JSONRPCServer):
        self.socket_path = socket_path
        self.rpc_server = rpc_server
        self.server: Optional[Any] = None  # asyncio.Server

    async def start(self):
        """Запуск сервера"""
        # Удаление старого сокета если существует
        if self.socket_path.exists():
            self.socket_path.unlink()

        self.server = await asyncio.start_unix_server(
            self._handle_client,
            str(self.socket_path)
        )

        # Установка прав доступа
        os.chmod(self.socket_path, 0o600)

        logger.info(f"Unix socket server started at {self.socket_path}")

    async def stop(self):
        """Остановка сервера"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            if self.socket_path.exists():
                self.socket_path.unlink()
            logger.info("Unix socket server stopped")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Обработка клиента"""
        try:
            while True:
                # Чтение длины сообщения (4 байта)
                length_data = await reader.readexactly(4)
                if not length_data:
                    break

                length = int.from_bytes(length_data, "big")
                if length > 1024 * 1024:  # Макс 1 МБ
                    logger.error("Message too large")
                    break

                # Чтение данных
                data = await reader.readexactly(length)

                # Обработка запроса
                response = await self.rpc_server.handle_request(data)

                # Отправка ответа (длина + данные)
                writer.write(len(response).to_bytes(4, "big"))
                writer.write(response)
                await writer.drain()

        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            logger.error(f"Error handling client: {e}", exc_info=True)
        finally:
            writer.close()
            await writer.wait_closed()


class NamedPipeServer:
    """Named Pipe сервер для Windows"""

    def __init__(self, pipe_name: str, rpc_server: JSONRPCServer):
        self.pipe_name = pipe_name
        self.rpc_server = rpc_server
        self.running = False

    async def start(self):
        """Запуск сервера"""
        # На Windows используем asyncio для работы с named pipes
        # Это упрощенная реализация
        self.running = True
        logger.info(f"Named pipe server started at {self.pipe_name}")
        # TODO: Реализация для Windows

    async def stop(self):
        """Остановка сервера"""
        self.running = False
        logger.info("Named pipe server stopped")

