"""FastAPI веб-интерфейс для сервера"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional
from pathlib import Path
from pydantic import BaseModel
import logging
import sys
import asyncio

from flamix.server.rule_manager import RuleManager
from flamix.server.rule_authorization import RuleAuthorization
from flamix.database.encrypted_db import EncryptedDB
from flamix.common.rule_format import FirewallRule

logger = logging.getLogger(__name__)


def _suppress_connection_reset_error():
    """Подавляет ошибки ConnectionResetError в asyncio callback'ах на Windows"""
    def exception_handler(loop, context):
        """Обработчик исключений для asyncio event loop"""
        exception = context.get('exception')
        if isinstance(exception, ConnectionResetError):
            # Игнорируем ошибки разрыва соединения - это нормальное поведение
            # когда клиент закрывает соединение до завершения обработки
            # Логируем только на уровне DEBUG, чтобы не засорять логи
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Connection reset by peer (normal): {context.get('message', '')}")
            return
        
        # Для других исключений используем стандартную обработку
        try:
            if hasattr(loop, 'default_exception_handler'):
                loop.default_exception_handler(context)
            else:
                # Если нет default_exception_handler, логируем ошибку
                logger.error(f"Unhandled exception in asyncio: {context.get('message', '')}", 
                            exc_info=exception)
        except Exception:
            # Если стандартный обработчик не работает, просто логируем
            logger.error(f"Unhandled exception in asyncio: {context.get('message', '')}", 
                        exc_info=exception)
    
    # Устанавливаем обработчик для текущего event loop, если он существует
    # Это будет работать когда uvicorn создаст свой event loop
    try:
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(exception_handler)
    except RuntimeError:
        # Если нет запущенного event loop, обработчик будет установлен позже
        # через uvicorn's event loop
        pass


class WebAPI:
    """Веб-интерфейс FastAPI"""

    def __init__(
        self,
        rule_manager: RuleManager,
        rule_authorization: RuleAuthorization,
        db: EncryptedDB,
        host: str = "127.0.0.1",
        port: int = 8080
    ):
        """
        Инициализация веб-интерфейса

        Args:
            rule_manager: Менеджер правил
            rule_authorization: Система авторизации
            db: База данных
            host: Хост для веб-сервера
            port: Порт для веб-сервера
        """
        self.rule_manager = rule_manager
        self.rule_authorization = rule_authorization
        self.db = db
        self.host = host
        self.port = port
        self.app = FastAPI(title="Flamix Server API")

        # Настройка CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # В продакшене должно быть ограничено
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Устанавливаем обработчик исключений при старте приложения
        @self.app.on_event("startup")
        async def setup_exception_handler():
            """Устанавливает обработчик исключений для asyncio event loop"""
            try:
                loop = asyncio.get_running_loop()
                def exception_handler(loop, context):
                    exception = context.get('exception')
                    if isinstance(exception, ConnectionResetError):
                        # Игнорируем ошибки разрыва соединения
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug(f"Connection reset by peer (normal): {context.get('message', '')}")
                        return
                    # Для других исключений используем стандартную обработку
                    try:
                        if hasattr(loop, 'default_exception_handler'):
                            loop.default_exception_handler(context)
                        else:
                            logger.error(f"Unhandled exception in asyncio: {context.get('message', '')}", 
                                        exc_info=exception)
                    except Exception:
                        logger.error(f"Unhandled exception in asyncio: {context.get('message', '')}", 
                                    exc_info=exception)
                
                loop.set_exception_handler(exception_handler)
            except RuntimeError:
                pass

        self._setup_routes()

    def _setup_routes(self):
        """Настройка маршрутов API"""

        @self.app.get("/")
        async def root():
            return {"message": "Flamix Server API"}

        @self.app.get("/api/clients")
        async def get_clients():
            """Получение списка клиентов"""
            clients = self.db.execute("SELECT * FROM clients ORDER BY last_seen DESC")
            return {"clients": clients}

        @self.app.get("/api/clients/{client_id}/rules")
        async def get_client_rules(client_id: str):
            """Получение правил клиента"""
            rules = self.rule_manager.get_all_rules(client_id)
            return {"rules": [rule.to_dict() for rule in rules]}

        @self.app.post("/api/rules")
        async def create_rule(rule_data: dict):
            """Создание правила"""
            try:
                rule = FirewallRule.from_dict(rule_data)
                client_id = rule_data.get('client_id')
                if not client_id:
                    raise HTTPException(status_code=400, detail="client_id is required")

                rule_id = self.rule_manager.add_rule(client_id, rule)
                return {"rule_id": rule_id, "success": True}
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.app.put("/api/rules/{rule_id}")
        async def update_rule(rule_id: str, rule_data: dict):
            """Обновление правила"""
            try:
                rule = FirewallRule.from_dict(rule_data)
                rule.id = rule_id
                client_id = rule_data.get('client_id')
                if not client_id:
                    raise HTTPException(status_code=400, detail="client_id is required")

                success = self.rule_manager.update_rule(client_id, rule)
                if not success:
                    raise HTTPException(status_code=404, detail="Rule not found")
                return {"success": True}
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.app.delete("/api/rules/{rule_id}")
        async def delete_rule(rule_id: str, client_id: str):
            """Удаление правила"""
            success = self.rule_manager.delete_rule(client_id, rule_id)
            if not success:
                raise HTTPException(status_code=404, detail="Rule not found")
            return {"success": True}

        @self.app.get("/api/analytics")
        async def get_analytics(
            client_id: Optional[str] = None,
            limit: int = 1000
        ):
            """Получение аналитики"""
            query = "SELECT * FROM analytics WHERE 1=1"
            params = []
            if client_id:
                query += " AND client_id = ?"
                params.append(client_id)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            analytics = self.db.execute(query, tuple(params))
            return {"analytics": analytics}

        @self.app.get("/api/rules/diff")
        async def get_rules_diff(client_id1: str, client_id2: str):
            """Сравнение правил между клиентами"""
            diff = self.rule_manager.compare_rules(client_id1, client_id2)
            return diff

        @self.app.get("/api/change-requests")
        async def get_change_requests(status: Optional[str] = None):
            """Получение запросов на изменение"""
            query = "SELECT * FROM rule_change_requests WHERE 1=1"
            params = []
            if status:
                query += " AND status = ?"
                params.append(status)
            query += " ORDER BY requested_at DESC"

            requests = self.db.execute(query, tuple(params))
            return {"requests": requests}

        @self.app.post("/api/change-requests/{request_id}/approve")
        async def approve_request(request_id: str, reviewer: str = "admin"):
            """Одобрение запроса на изменение"""
            success = self.rule_authorization.approve_request(request_id, reviewer)
            if not success:
                raise HTTPException(status_code=404, detail="Request not found")
            return {"success": True}

        @self.app.post("/api/change-requests/{request_id}/reject")
        async def reject_request(request_id: str, reason: str, reviewer: str = "admin"):
            """Отклонение запроса на изменение"""
            success = self.rule_authorization.reject_request(request_id, reviewer, reason)
            if not success:
                raise HTTPException(status_code=404, detail="Request not found")
            return {"success": True}

    def run(self, cert_dir: Optional[Path] = None):
        """
        Запуск веб-сервера
        
        Args:
            cert_dir: Директория с сертификатами (опционально)
        """
        import uvicorn
        
        # Настраиваем обработку ошибок соединений для Windows
        _suppress_connection_reset_error()
        
        # Проверяем наличие сертификатов
        use_ssl = False
        ssl_keyfile = None
        ssl_certfile = None
        
        if cert_dir:
            cert_dir = Path(cert_dir)
            server_cert = cert_dir / "server.crt"
            server_key = cert_dir / "server.key"
            
            if server_cert.exists() and server_key.exists():
                use_ssl = True
                ssl_certfile = str(server_cert.resolve())
                ssl_keyfile = str(server_key.resolve())
                logger.info(f"Using SSL certificates: {ssl_certfile}")
                logger.info(f"Web interface available at: https://{self.host}:{self.port}")
            else:
                logger.warning(
                    f"SSL certificates not found in {cert_dir}. "
                    f"Starting web interface without SSL (HTTP only)."
                )
                logger.info(f"Web interface available at: http://{self.host}:{self.port}")
        else:
            logger.warning(
                "No certificate directory provided. "
                "Starting web interface without SSL (HTTP only)."
            )
            logger.info(f"Web interface available at: http://{self.host}:{self.port}")
        
        # Запуск uvicorn сервера
        # Используем uvicorn.run() который правильно работает в отдельном потоке
        try:
            # Настройки для предотвращения ошибок соединений на Windows
            uvicorn_config = {
                "app": self.app,
                "host": self.host,
                "port": self.port,
                "log_level": "info",
                "access_log": True,
                "timeout_keep_alive": 5,  # Таймаут для keep-alive соединений
                "timeout_graceful_shutdown": 5,  # Таймаут для graceful shutdown
            }
            
            if use_ssl:
                logger.info(f"Starting web interface with SSL on https://{self.host}:{self.port}")
                uvicorn_config["ssl_keyfile"] = ssl_keyfile
                uvicorn_config["ssl_certfile"] = ssl_certfile
            else:
                logger.info(f"Starting web interface without SSL on http://{self.host}:{self.port}")
            
            uvicorn.run(**uvicorn_config)
        except Exception as e:
            logger.error(f"Error running web server: {e}", exc_info=True)
            raise
