"""Главный сервер Flamix"""

import asyncio
import logging
import uuid
import json
from pathlib import Path
from typing import Optional

from flamix.database.encrypted_db import EncryptedDB
from flamix.server.protocol import ServerProtocol
from flamix.server.client_manager import ClientManager
from flamix.server.rule_manager import RuleManager
from flamix.server.security import ServerSecurity
from flamix.server.rule_authorization import RuleAuthorization
from flamix.server.web_api import WebAPI
from flamix.common.protocol_types import MessageType, ProtocolMessage
from flamix.common.rule_format import FirewallRule

logger = logging.getLogger(__name__)


class FlamixServer:
    """Главный сервер Flamix"""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8443,
        db_path: Path = None,
        cert_dir: Path = None,
        web_enabled: bool = True,
        web_host: str = "127.0.0.1",
        web_port: int = 8080
    ):
        """
        Инициализация сервера

        Args:
            host: Хост для прослушивания
            port: Порт для прослушивания
            db_path: Путь к базе данных
            cert_dir: Директория с сертификатами
            web_enabled: Включить ли веб-интерфейс
            web_host: Хост для веб-интерфейса
            web_port: Порт для веб-интерфейса
        """
        self.host = host
        self.port = port
        self.db_path = db_path or Path("data/server.db")
        self.cert_dir = cert_dir or Path("certs")
        self.web_enabled = web_enabled
        self.web_host = web_host
        self.web_port = web_port
        self.running = False
        self.server: Optional[asyncio.Server] = None
        self.web_api: Optional[WebAPI] = None

        # Инициализация компонентов
        self.db = EncryptedDB(self.db_path)
        self.security = ServerSecurity(self.cert_dir)
        self.client_manager = ClientManager(self.db)
        self.rule_manager = RuleManager(self.db)
        self.rule_authorization = RuleAuthorization(self.db, self.rule_manager)
        
        # Инициализация веб-интерфейса
        if self.web_enabled:
            self.web_api = WebAPI(
                rule_manager=self.rule_manager,
                rule_authorization=self.rule_authorization,
                db=self.db,
                host=self.web_host,
                port=self.web_port
            )

    async def start(self):
        """Запуск сервера"""
        logger.info("Starting Flamix server...")

        # Инициализация БД
        self.db.initialize()

        # Генерация сертификатов для клиентских подключений (TLS)
        # Методы generate_ca() и generate_server_cert() автоматически проверяют
        # наличие файлов и создают только если их нет (не пересоздают!)
        logger.info("Checking certificates for client connections...")
        self.security.generate_ca()  # Создаст только если нет
        self.security.generate_server_cert()  # Создаст только если нет
        logger.info("Certificates ready (existing certificates are reused, not regenerated)")

        # Создание SSL контекста для клиентских подключений
        # (веб-интерфейс использует свою логику)
        ssl_context = self.security.create_ssl_context(require_client_cert=True)

        # Запуск сервера
        self.server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port,
            ssl=ssl_context
        )

        self.running = True
        logger.info(f"Server started on {self.host}:{self.port}")

        # Запуск веб-интерфейса если включен
        if self.web_enabled and self.web_api:
            import threading
            import time
            
            def start_web():
                """Запуск веб-интерфейса в отдельном потоке"""
                # Небольшая задержка, чтобы основной сервер успел запуститься
                time.sleep(1)
                try:
                    logger.info("Starting web interface...")
                    self.web_api.run(self.cert_dir)
                except Exception as e:
                    logger.error(f"Web interface error: {e}", exc_info=True)
            
            web_thread = threading.Thread(
                target=start_web,
                daemon=True,
                name="WebInterface"
            )
            web_thread.start()
            logger.info(f"Web interface thread started (will be available at http://{self.web_host}:{self.web_port} or https if certificates found)")

        # Запуск периодических задач
        asyncio.create_task(self._periodic_tasks())

    async def stop(self):
        """Остановка сервера"""
        logger.info("Stopping Flamix server...")
        self.running = False

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        # Закрываем все сессии
        for session_id in list(self.client_manager.sessions.keys()):
            await self.client_manager.close_session(session_id)

        logger.info("Server stopped")

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Обработка подключения клиента"""
        client_id = None
        session_id = None

        try:
            # Получаем информацию о клиенте из SSL
            peername = writer.get_extra_info('peername')
            logger.info(f"New client connection from {peername}")

            # Читаем первый запрос (должен быть AUTH_REQUEST или DH_KEY_EXCHANGE)
            # Пока что упрощенная версия без полной аутентификации
            # В реальной версии здесь будет полный процесс аутентификации

            # Создаем временную сессию для DH обмена
            temp_client_id = f"temp-{uuid.uuid4()}"
            session = await self.client_manager.create_session(
                temp_client_id,
                reader,
                writer
            )
            session_id = session.session_id

            # Ожидаем DH_KEY_EXCHANGE
            protocol = ServerProtocol(session.session_key, session_id)
            message = await protocol.read_message(reader)

            if not message or message.header.message_type != MessageType.DH_KEY_EXCHANGE:
                logger.error("Expected DH_KEY_EXCHANGE message")
                return

            # Получаем публичный ключ клиента
            client_public_key = bytes.fromhex(message.payload.get('public_key', ''))
            if not client_public_key:
                logger.error("No public key in DH_KEY_EXCHANGE")
                return

            # Завершаем DH обмен
            session_key = await self.client_manager.complete_dh_exchange(
                session_id,
                client_public_key
            )

            # Обновляем протокол с новым ключом
            protocol = ServerProtocol(session_key, session_id)

            # Отправляем ответ с публичным ключом сервера
            server_public_key = session.dh.get_public_key_bytes()
            response = protocol.create_message(
                MessageType.DH_KEY_RESPONSE,
                {
                    'public_key': server_public_key.hex(),
                    'session_id': session_id
                }
            )
            writer.write(response)
            await writer.drain()

            # Ожидаем AUTH_REQUEST
            message = await protocol.read_message(reader)
            if not message or message.header.message_type != MessageType.AUTH_REQUEST:
                logger.error("Expected AUTH_REQUEST message")
                return

            # Извлекаем client_id из запроса
            client_id = message.payload.get('client_id')
            if not client_id:
                logger.error("No client_id in AUTH_REQUEST")
                return

            # Регистрируем или обновляем клиента
            self._register_client(client_id, peername[0] if peername else "unknown")

            # Обновляем сессию с реальным client_id
            session.client_id = client_id
            self.client_manager.client_sessions[client_id] = session_id

            # Отправляем AUTH_RESPONSE
            response = protocol.create_message(
                MessageType.AUTH_RESPONSE,
                {
                    'success': True,
                    'client_id': client_id,
                    'session_id': session_id
                }
            )
            writer.write(response)
            await writer.drain()

            logger.info(f"Client {client_id} authenticated, session {session_id}")

            # Основной цикл обработки сообщений
            await self._handle_client_messages(protocol, session, reader, writer)

        except Exception as e:
            logger.error(f"Error handling client: {e}", exc_info=True)
        finally:
            if session_id:
                await self.client_manager.close_session(session_id)

    async def _handle_client_messages(
        self,
        protocol: ServerProtocol,
        session,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        """Обработка сообщений от клиента"""
        while self.running:
            try:
                message = await asyncio.wait_for(
                    protocol.read_message(reader),
                    timeout=60.0
                )

                if not message:
                    break

                # Обновляем активность
                self.client_manager.update_activity(session.session_id)

                # Обработка сообщений
                await self._process_message(protocol, session, message, writer)

            except asyncio.TimeoutError:
                # Отправляем heartbeat
                heartbeat = protocol.create_message(MessageType.HEARTBEAT, {})
                writer.write(heartbeat)
                await writer.drain()
            except Exception as e:
                logger.error(f"Error handling message: {e}", exc_info=True)
                break

    async def _process_message(
        self,
        protocol: ServerProtocol,
        session,
        message: ProtocolMessage,
        writer: asyncio.StreamWriter
    ):
        """Обработка конкретного сообщения"""
        msg_type = message.header.message_type
        payload = message.payload

        if msg_type == MessageType.SYNC_REQUEST:
            # Синхронизация правил
            rules = self.rule_manager.get_all_rules(session.client_id)
            rules_data = [rule.to_dict() for rule in rules]

            response = protocol.create_message(
                MessageType.SYNC_RESPONSE,
                {'rules': rules_data}
            )
            writer.write(response)
            await writer.drain()

        elif msg_type == MessageType.RULE_UPDATE_REQUEST:
            # Запрос на обновление правила
            rule_data = payload.get('new_rule')
            if rule_data:
                rule = FirewallRule.from_dict(rule_data)
                # Здесь будет авторизация (пока просто применяем)
                self.rule_manager.update_rule(session.client_id, rule)

                response = protocol.create_message(
                    MessageType.RULE_UPDATE_APPROVED,
                    {'rule_id': rule.id}
                )
            else:
                response = protocol.create_message(
                    MessageType.RULE_UPDATE_REJECTED,
                    {'reason': 'Invalid rule data'}
                )
            writer.write(response)
            await writer.drain()

        elif msg_type == MessageType.HEARTBEAT:
            # Heartbeat ответ
            response = protocol.create_message(MessageType.HEARTBEAT_RESPONSE, {})
            writer.write(response)
            await writer.drain()

        elif msg_type == MessageType.ANALYTICS_REPORT:
            # Сохранение аналитики
            self._save_analytics(session.client_id, payload)
            # Не отправляем ответ для аналитики

    def _register_client(self, client_id: str, ip_address: str):
        """Регистрация клиента в БД"""
        from datetime import datetime
        self.db.execute_write(
            """
            INSERT OR REPLACE INTO clients 
            (id, name, ip_address, last_seen, enabled)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                client_id,
                client_id,  # Имя по умолчанию
                ip_address,
                datetime.utcnow().isoformat() + "Z",
                1
            )
        )

    def _save_analytics(self, client_id: str, data: dict):
        """Сохранение аналитики"""
        from datetime import datetime
        self.db.execute_write(
            """
            INSERT INTO analytics 
            (client_id, timestamp, event_type, target_ip, target_domain, target_port, protocol, action, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client_id,
                datetime.utcnow().isoformat() + "Z",
                data.get('event_type', 'unknown'),
                data.get('target_ip'),
                data.get('target_domain'),
                data.get('target_port'),
                data.get('protocol'),
                data.get('action'),
                json.dumps(data.get('details', {}))
            )
        )

    async def _periodic_tasks(self):
        """Периодические задачи"""
        while self.running:
            await asyncio.sleep(60)  # Каждую минуту
            self.client_manager.cleanup_expired_sessions()


async def main():
    """Точка входа сервера"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    server = FlamixServer()
    await server.start()

    try:
        await asyncio.Event().wait()  # Бесконечное ожидание
    except KeyboardInterrupt:
        pass
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
