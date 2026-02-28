"""Главный клиент Flamix"""

import asyncio
import logging
import uuid
import json
from pathlib import Path
from typing import Optional, Dict, Any, List

from flamix.client.protocol import ClientProtocol
from flamix.client.security import ClientSecurity
from flamix.common.protocol_types import MessageType, ProtocolMessage
from flamix.common.diffie_hellman import DiffieHellman
from flamix.common.rule_format import FirewallRule

logger = logging.getLogger(__name__)


class FlamixClient:
    """Главный клиент Flamix"""

    def __init__(
        self,
        client_id: str,
        server_host: str = "localhost",
        server_port: int = 8443,
        cert_dir: Path = None
    ):
        """
        Инициализация клиента

        Args:
            client_id: ID клиента
            server_host: Хост сервера
            server_port: Порт сервера
            cert_dir: Директория с сертификатами
        """
        self.client_id = client_id
        self.server_host = server_host
        self.server_port = server_port
        self.cert_dir = cert_dir or Path("certs")
        self.connected = False
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.protocol: Optional[ClientProtocol] = None
        self.session_id: Optional[str] = None
        self.session_key: Optional[bytes] = None

        self.security = ClientSecurity(self.cert_dir)
        self.rules: Dict[str, FirewallRule] = {}  # rule_id -> rule

    async def connect(self) -> bool:
        """
        Подключение к серверу

        Returns:
            True если успешно
        """
        try:
            logger.info(f"Connecting to server {self.server_host}:{self.server_port}...")

            # Создание SSL контекста
            ssl_context = self.security.create_ssl_context()

            # Подключение
            self.reader, self.writer = await asyncio.open_connection(
                self.server_host,
                self.server_port,
                ssl=ssl_context
            )

            # Инициализация DH обмена
            dh = DiffieHellman()
            client_public_key = dh.get_public_key_bytes()

            # Создаем временный протокол для DH обмена
            temp_key = b'\x00' * 32
            temp_session_id = str(uuid.uuid4())
            temp_protocol = ClientProtocol(temp_key, temp_session_id)

            # Отправляем DH_KEY_EXCHANGE
            dh_message = temp_protocol.create_message(
                MessageType.DH_KEY_EXCHANGE,
                {'public_key': client_public_key.hex()}
            )
            self.writer.write(dh_message)
            await self.writer.drain()

            # Ожидаем DH_KEY_RESPONSE
            response = await temp_protocol.read_message(self.reader)
            if not response or response.header.message_type != MessageType.DH_KEY_RESPONSE:
                logger.error("Expected DH_KEY_RESPONSE")
                return False

            # Получаем публичный ключ сервера
            server_public_key = bytes.fromhex(response.payload.get('public_key', ''))
            if not server_public_key:
                logger.error("No public key in DH_KEY_RESPONSE")
                return False

            # Вычисляем общий секрет
            shared_secret = dh.compute_shared_secret(server_public_key)

            # Генерируем сессионный ключ
            self.session_key = DiffieHellman.generate_session_key(shared_secret)
            self.session_id = response.payload.get('session_id', str(uuid.uuid4()))

            # Создаем протокол с реальным ключом
            self.protocol = ClientProtocol(self.session_key, self.session_id)

            # Отправляем AUTH_REQUEST
            auth_message = self.protocol.create_message(
                MessageType.AUTH_REQUEST,
                {'client_id': self.client_id}
            )
            self.writer.write(auth_message)
            await self.writer.drain()

            # Ожидаем AUTH_RESPONSE
            auth_response = await self.protocol.read_message(self.reader)
            if not auth_response or auth_response.header.message_type != MessageType.AUTH_RESPONSE:
                logger.error("Expected AUTH_RESPONSE")
                return False

            if not auth_response.payload.get('success', False):
                logger.error("Authentication failed")
                return False

            self.connected = True
            logger.info(f"Connected to server, session {self.session_id}")

            # Запускаем обработку сообщений
            asyncio.create_task(self._message_handler())

            return True

        except Exception as e:
            logger.error(f"Error connecting to server: {e}", exc_info=True)
            return False

    async def disconnect(self):
        """Отключение от сервера"""
        self.connected = False
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
        logger.info("Disconnected from server")

    async def sync_rules(self) -> List[FirewallRule]:
        """
        Синхронизация правил с сервером

        Returns:
            Список правил
        """
        if not self.connected or not self.protocol:
            raise RuntimeError("Not connected to server")

        # Отправляем SYNC_REQUEST
        sync_message = self.protocol.create_message(MessageType.SYNC_REQUEST, {})
        self.writer.write(sync_message)
        await self.writer.drain()

        # Ожидаем SYNC_RESPONSE
        response = await self.protocol.read_message(self.reader)
        if not response or response.header.message_type != MessageType.SYNC_RESPONSE:
            logger.error("Expected SYNC_RESPONSE")
            return []

        # Парсим правила
        rules_data = response.payload.get('rules', [])
        rules = []
        for rule_dict in rules_data:
            try:
                rule = FirewallRule.from_dict(rule_dict)
                rules.append(rule)
                self.rules[rule.id] = rule
            except Exception as e:
                logger.error(f"Error parsing rule: {e}")
                continue

        logger.info(f"Synced {len(rules)} rules from server")
        return rules

    async def request_rule_update(self, rule: FirewallRule) -> bool:
        """
        Запрос на обновление правила

        Args:
            rule: Обновленное правило

        Returns:
            True если одобрено
        """
        if not self.connected or not self.protocol:
            raise RuntimeError("Not connected to server")

        # Получаем старое правило
        old_rule = self.rules.get(rule.id)
        old_rule_dict = old_rule.to_dict() if old_rule else None

        # Отправляем RULE_UPDATE_REQUEST
        update_message = self.protocol.create_message(
            MessageType.RULE_UPDATE_REQUEST,
            {
                'rule_id': rule.id,
                'old_rule': old_rule_dict,
                'new_rule': rule.to_dict(),
                'change_source': 'manual',
                'checksum_old': old_rule.calculate_checksum() if old_rule else None,
                'checksum_new': rule.calculate_checksum()
            }
        )
        self.writer.write(update_message)
        await self.writer.drain()

        # Ожидаем ответ
        response = await self.protocol.read_message(self.reader)
        if not response:
            return False

        if response.header.message_type == MessageType.RULE_UPDATE_APPROVED:
            # Обновляем локальное правило
            self.rules[rule.id] = rule
            logger.info(f"Rule {rule.id} update approved")
            return True
        elif response.header.message_type == MessageType.RULE_UPDATE_REJECTED:
            reason = response.payload.get('reason', 'Unknown reason')
            logger.warning(f"Rule {rule.id} update rejected: {reason}")
            return False

        return False

    async def send_analytics(self, analytics_data: Dict[str, Any]):
        """
        Отправка аналитики на сервер

        Args:
            analytics_data: Данные аналитики
        """
        if not self.connected or not self.protocol:
            return

        message = self.protocol.create_message(
            MessageType.ANALYTICS_REPORT,
            analytics_data
        )
        self.writer.write(message)
        await self.writer.drain()

    async def _message_handler(self):
        """Обработчик входящих сообщений"""
        while self.connected:
            try:
                if not self.protocol or not self.reader:
                    break

                message = await asyncio.wait_for(
                    self.protocol.read_message(self.reader),
                    timeout=60.0
                )

                if not message:
                    break

                await self._process_message(message)

            except asyncio.TimeoutError:
                # Отправляем heartbeat
                if self.protocol:
                    heartbeat = self.protocol.create_message(MessageType.HEARTBEAT, {})
                    self.writer.write(heartbeat)
                    await self.writer.drain()
            except Exception as e:
                logger.error(f"Error in message handler: {e}", exc_info=True)
                break

    async def _process_message(self, message: ProtocolMessage):
        """Обработка конкретного сообщения"""
        msg_type = message.header.message_type

        if msg_type == MessageType.RULE_UPDATE:
            # Обновление правила с сервера
            rule_data = message.payload.get('rule')
            if rule_data:
                try:
                    rule = FirewallRule.from_dict(rule_data)
                    self.rules[rule.id] = rule
                    logger.info(f"Rule {rule.id} updated from server")
                except Exception as e:
                    logger.error(f"Error processing rule update: {e}")

        elif msg_type == MessageType.RULE_DELETE:
            # Удаление правила
            rule_id = message.payload.get('rule_id')
            if rule_id and rule_id in self.rules:
                del self.rules[rule_id]
                logger.info(f"Rule {rule_id} deleted by server")

        elif msg_type == MessageType.HEARTBEAT:
            # Heartbeat ответ
            if self.protocol:
                response = self.protocol.create_message(MessageType.HEARTBEAT_RESPONSE, {})
                self.writer.write(response)
                await self.writer.drain()


async def main():
    """Точка входа клиента"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    client = FlamixClient(client_id="test-client")
    if await client.connect():
        rules = await client.sync_rules()
        print(f"Synced {len(rules)} rules")
        await asyncio.sleep(10)
        await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
