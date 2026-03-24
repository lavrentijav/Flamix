"""Главный клиент Flamix"""

import asyncio
import logging
import uuid
import json
import shutil
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime
from collections import deque

from flamix.client.protocol import ClientProtocol
from flamix.client.security import ClientSecurity
from flamix.client.system_monitor import SystemMonitor
from flamix.common.protocol_types import MessageType, ProtocolMessage
from flamix.common.diffie_hellman import DiffieHellman
from flamix.common.rule_format import FirewallRule

logger = logging.getLogger(__name__)

TRANSPORT_LOG_FUNCTIONS = {
    "send_logs",
    "send_system_status",
    "_message_handler",
    "_periodic_tasks_loop",
    "_start_periodic_tasks",
    "start_message_handler",
}


class FlamixClient:
    """Главный клиент Flamix"""

    def __init__(
        self,
        client_id: str,
        server_host: str = "localhost",
        server_port: int = 8443,
        cert_dir: Path = None,
        verify_ssl: bool = True,
        plugin_manager = None,
        system_status_enabled: bool = True,
        logs_enabled: bool = True,
        status_send_interval: int = 60,
        log_send_interval: int = 30
    ):
        """
        Инициализация клиента

        Args:
            client_id: ID клиента
            server_host: Хост сервера
            server_port: Порт сервера
            cert_dir: Директория с сертификатами
            verify_ssl: Проверять ли SSL сертификат сервера (по умолчанию True)
            plugin_manager: Optional PluginManager instance for plugin status reporting
            system_status_enabled: Включена ли отправка системного статуса
            logs_enabled: Включена ли отправка логов
            status_send_interval: Интервал отправки системного статуса в секундах
            log_send_interval: Интервал отправки логов в секундах
        """
        self.client_id = client_id
        self.server_host = server_host
        self.server_port = server_port
        self.cert_dir = cert_dir or Path("certs")
        self.verify_ssl = verify_ssl
        self.connected = False
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.protocol: Optional[ClientProtocol] = None
        self.session_id: Optional[str] = None
        self.session_key: Optional[bytes] = None
        self.config_path: Optional[Path] = None  # Путь к config.json
        self.config_sync_callback: Optional[Callable] = None  # Callback для применения нового конфига

        self.security = ClientSecurity(self.cert_dir, client_id=self.client_id)
        self.rules: Dict[str, FirewallRule] = {}  # rule_id -> rule
        self.plugin_manager = plugin_manager  # PluginManager for plugin status

        # System monitoring
        self.system_monitor = SystemMonitor()
        self._last_status_send = None
        self._status_send_interval = status_send_interval
        self._system_status_enabled = system_status_enabled
        self._logs_enabled = logs_enabled
        self._log_send_interval = log_send_interval
        self._last_log_send = None

        # Log capturing
        self._log_buffer: deque = deque(maxlen=1000)  # Keep last 1000 log entries
        self._log_handler = None
        self._log_send_lock = asyncio.Lock()
        self._setup_log_handler()

        # Для потокобезопасного чтения: _message_handler — единственный reader,
        # request-response методы регистрируют ожидаемые ответы через _pending_responses
        self._message_handler_task: Optional[asyncio.Task] = None
        self._pending_responses: Dict[MessageType, asyncio.Future] = {}
        self._read_lock = asyncio.Lock()
        
        # Periodic tasks
        self._periodic_tasks_task: Optional[asyncio.Task] = None

    async def connect(self) -> bool:
        """
        Подключение к серверу

        Returns:
            True если успешно
        """
        try:
            # Проверяем, что server_host установлен
            if not self.server_host or self.server_host == "None":
                logger.error("Server host is not set. Please check config.json")
                return False
            
            logger.info(f"Connecting to server {self.server_host}:{self.server_port}...")

            # Создание SSL контекста
            ssl_context = self.security.create_ssl_context(verify_ssl=self.verify_ssl)

            # Подключение с явным указанием server_hostname для SSL
            logger.info(f"Opening connection to {self.server_host}:{self.server_port} with SSL...")
            self.reader, self.writer = await asyncio.open_connection(
                self.server_host,
                self.server_port,
                ssl=ssl_context,
                server_hostname=self.server_host if self.verify_ssl else None
            )
            logger.info("SSL connection established successfully")

            # Инициализация DH обмена
            dh = DiffieHellman()
            client_public_key = dh.get_public_key_bytes()
            logger.info(f"DH public key generated, length: {len(client_public_key)} bytes")

            # Создаем временный протокол для DH обмена
            # Используем фиксированный session_id для начального обмена (известен обеим сторонам)
            temp_key = b'\x00' * 32
            temp_session_id = "handshake-init"
            temp_protocol = ClientProtocol(temp_key, temp_session_id)

            # Отправляем DH_KEY_EXCHANGE
            logger.info("Sending DH_KEY_EXCHANGE message...")
            dh_message = temp_protocol.create_message(
                MessageType.DH_KEY_EXCHANGE,
                {'public_key': client_public_key.hex()}
            )
            self.writer.write(dh_message)
            await self.writer.drain()
            logger.info(f"DH_KEY_EXCHANGE sent ({len(dh_message)} bytes), waiting for response...")

            # Ожидаем DH_KEY_RESPONSE
            try:
                response = await temp_protocol.read_message(self.reader)
                logger.info(f"Received response: {response}")
            except (ConnectionResetError, BrokenPipeError, OSError, asyncio.IncompleteReadError) as e:
                logger.error(f"Connection lost while waiting for DH_KEY_RESPONSE: {e}")
                return False
            except asyncio.TimeoutError:
                logger.error("Timeout waiting for DH_KEY_RESPONSE")
                return False
            except Exception as e:
                logger.error(f"Error reading DH_KEY_RESPONSE: {e}")
                return False
            
            if not response:
                logger.error("No response received (connection closed by server)")
                return False
            
            if response.header.message_type != MessageType.DH_KEY_RESPONSE:
                logger.error(f"Expected DH_KEY_RESPONSE, got {response.header.message_type}")
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
            try:
                auth_response = await self.protocol.read_message(self.reader)
            except (ConnectionResetError, BrokenPipeError, OSError, asyncio.IncompleteReadError) as e:
                logger.error(f"Connection lost while waiting for AUTH_RESPONSE: {e}")
                return False
            except asyncio.TimeoutError:
                logger.error("Timeout waiting for AUTH_RESPONSE")
                return False
            
            if not auth_response or auth_response.header.message_type != MessageType.AUTH_RESPONSE:
                logger.error("Expected AUTH_RESPONSE")
                return False

            if not auth_response.payload.get('success', False):
                logger.error("Authentication failed")
                return False

            self.connected = True
            logger.info(f"Connected to server, session {self.session_id}")
            
            # Отправляем начальный системный статус и логи сразу после подключения
            if self._system_status_enabled:
                await self.send_system_status()
            if self._logs_enabled:
                await self.send_logs()
            
            # Запускаем периодические задачи
            if self.connected:
                self.start_message_handler()
                self._start_periodic_tasks()

            return True

        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            logger.error(f"Connection error: {e}")
            return False
        except Exception as e:
            logger.error(f"Error connecting to server: {e}", exc_info=True)
            return False

    def start_message_handler(self):
        """Запуск фонового обработчика входящих сообщений.
        
        Вызывайте ПОСЛЕ завершения начальной синхронизации (sync_rules и т.д.),
        чтобы избежать конкурентного чтения из StreamReader.
        """
        if self._message_handler_task is None or self._message_handler_task.done():
            self._message_handler_task = asyncio.create_task(self._message_handler())

    async def _send_and_wait(
        self,
        message_type: MessageType,
        payload: Dict[str, Any],
        expected_responses: "MessageType | tuple[MessageType, ...]",
        timeout: float = 30.0
    ) -> Optional[ProtocolMessage]:
        """Отправка запроса и ожидание конкретного ответа.

        Args:
            message_type: Тип отправляемого сообщения
            payload: Данные сообщения
            expected_responses: Один или несколько типов ожидаемых ответов
            timeout: Таймаут ожидания в секундах
        
        Если _message_handler работает — регистрирует Future и ждёт,
        иначе выполняет прямое чтение.
        """
        logger.debug(f"_send_and_wait called: message_type={message_type}, timeout={timeout}")
        
        if not self.connected or not self.protocol:
            logger.error(f"Cannot send message: connected={self.connected}, protocol={self.protocol is not None}")
            raise RuntimeError("Not connected to server")

        # Нормализуем в кортеж
        if isinstance(expected_responses, MessageType):
            expected_responses = (expected_responses,)

        handler_running = (
            self._message_handler_task is not None
            and not self._message_handler_task.done()
        )
        
        logger.debug(f"Message handler running: {handler_running}")
        logger.debug(f"Expected response types: {expected_responses}")
        logger.debug(f"Payload: {json.dumps(payload, indent=2, default=str)}")

        try:
            msg = self.protocol.create_message(message_type, payload)
            logger.debug(f"Message created: length={len(msg)} bytes")
        except Exception as e:
            logger.error(f"Failed to create message: {e}", exc_info=True)
            return None

        if handler_running:
            # Регистрируем общий Future для всех ожидаемых типов ответа
            loop = asyncio.get_running_loop()
            future: asyncio.Future[Optional[ProtocolMessage]] = loop.create_future()
            for resp_type in expected_responses:
                logger.debug(f"Registering pending response for type: {resp_type}")
                self._pending_responses[resp_type] = future

            try:
                logger.info(f"Sending {message_type} message ({len(msg)} bytes) via message handler...")
                self.writer.write(msg)
                await self.writer.drain()
                logger.debug(f"Message sent successfully, waiting for response (timeout={timeout}s)...")
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                logger.error(f"Connection lost while sending message: {e}", exc_info=True)
                self.connected = False
                for resp_type in expected_responses:
                    self._pending_responses.pop(resp_type, None)
                return None

            try:
                response = await asyncio.wait_for(future, timeout=timeout)
                if response:
                    logger.info(f"Response received: type={response.header.message_type}")
                    logger.debug(f"Response payload keys: {list(response.payload.keys()) if response.payload else 'None'}")
                else:
                    logger.warning("Response future resolved but response is None")
                return response
            except asyncio.TimeoutError:
                for resp_type in expected_responses:
                    self._pending_responses.pop(resp_type, None)
                logger.error(f"TIMEOUT: No response received for {message_type} after {timeout} seconds")
                logger.error(f"Expected response types: {expected_responses}")
                logger.error(f"Pending responses registered: {list(self._pending_responses.keys())}")
                return None
        else:
            # Прямое чтение (message_handler не запущен)
            logger.debug("Using direct read (message handler not running)")
            async with self._read_lock:
                try:
                    logger.info(f"Sending {message_type} message ({len(msg)} bytes) via direct write...")
                    self.writer.write(msg)
                    await self.writer.drain()
                    logger.debug(f"Message sent, waiting for direct response (timeout={timeout}s)...")
                except (ConnectionResetError, BrokenPipeError, OSError) as e:
                    logger.error(f"Connection lost while sending message: {e}", exc_info=True)
                    self.connected = False
                    return None
                try:
                    response = await asyncio.wait_for(
                        self.protocol.read_message(self.reader),
                        timeout=timeout
                    )
                    if response:
                        logger.info(f"Direct response received: type={response.header.message_type}")
                        logger.debug(f"Response payload keys: {list(response.payload.keys()) if response.payload else 'None'}")
                    return response
                except asyncio.TimeoutError:
                    logger.error(f"TIMEOUT: No direct response received for {message_type} after {timeout} seconds")
                    return None
                except (ConnectionResetError, BrokenPipeError, OSError) as e:
                    logger.error(f"Connection lost while reading message: {e}", exc_info=True)
                    self.connected = False
                    return None

    async def disconnect(self):
        """Отключение от сервера"""
        self.connected = False
        # Отменяем фоновый обработчик
        if self._message_handler_task and not self._message_handler_task.done():
            self._message_handler_task.cancel()
            try:
                await self._message_handler_task
            except asyncio.CancelledError:
                pass
        
        # Отменяем периодические задачи
        if self._periodic_tasks_task and not self._periodic_tasks_task.done():
            self._periodic_tasks_task.cancel()
            try:
                await self._periodic_tasks_task
            except asyncio.CancelledError:
                pass
        
        # Очищаем pending futures
        for fut in self._pending_responses.values():
            if not fut.done():
                fut.cancel()
        self._pending_responses.clear()

        # Remove log handler
        if self._log_handler:
            logging.getLogger().removeHandler(self._log_handler)
            self._log_handler = None

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
        logger.info("=" * 60)
        logger.info("Starting rule synchronization with server")
        logger.info(f"Client ID: {self.client_id}")
        logger.info(f"Connected: {self.connected}")
        logger.info(f"Session ID: {self.session_id}")
        logger.info(f"Current local rules count: {len(self.rules)}")
        logger.info("=" * 60)
        
        logger.debug("Creating SYNC_REQUEST message...")
        try:
            response = await self._send_and_wait(
                MessageType.SYNC_REQUEST, {},
                MessageType.SYNC_RESPONSE,
                timeout=30.0
            )
            logger.debug(f"Received response: {response is not None}")
        except Exception as e:
            logger.error(f"Exception during _send_and_wait in sync_rules: {e}", exc_info=True)
            return []

        if not response:
            logger.error("No response received from server (response is None)")
            logger.error("Possible causes:")
            logger.error("  - Server did not respond within timeout (30 seconds)")
            logger.error("  - Connection was lost during request")
            logger.error("  - Message handler is not running or failed")
            return []

        logger.info(f"Response received: message_type={response.header.message_type}")
        logger.debug(f"Response header: {response.header}")
        logger.debug(f"Response payload keys: {list(response.payload.keys()) if response.payload else 'None'}")

        if response.header.message_type != MessageType.SYNC_RESPONSE:
            logger.error(f"Expected SYNC_RESPONSE, but got: {response.header.message_type}")
            logger.error(f"Full response header: {response.header}")
            logger.error(f"Full response payload: {response.payload}")
            return []

        # Парсим правила
        rules_data = response.payload.get('rules', [])
        logger.info(f"Rules data received: {len(rules_data)} rules in payload")
        logger.debug(f"Rules data type: {type(rules_data)}")
        
        if not rules_data:
            logger.warning("No rules in response payload (rules list is empty)")
            logger.debug(f"Full payload: {response.payload}")
            return []

        logger.info(f"Parsing {len(rules_data)} rules from server...")
        rules = []
        parse_errors = 0
        
        for idx, rule_dict in enumerate(rules_data):
            logger.debug(f"Parsing rule {idx + 1}/{len(rules_data)}: {rule_dict.get('id', 'NO_ID')}")
            try:
                logger.debug(f"Rule dict keys: {list(rule_dict.keys())}")
                logger.debug(f"Rule dict content: {json.dumps(rule_dict, indent=2, default=str)}")
                
                rule = FirewallRule.from_dict(rule_dict)
                logger.debug(f"Successfully parsed rule: id={rule.id}, name={rule.name}, action={rule.action}")
                
                rules.append(rule)
                self.rules[rule.id] = rule
                logger.debug(f"Added rule {rule.id} to local rules cache (total: {len(self.rules)})")
            except Exception as e:
                parse_errors += 1
                logger.error(f"Error parsing rule {idx + 1}: {e}", exc_info=True)
                logger.error(f"Failed rule dict: {json.dumps(rule_dict, indent=2, default=str)}")
                continue

        logger.info("=" * 60)
        logger.info(f"Rule synchronization completed:")
        logger.info(f"  - Total rules received: {len(rules_data)}")
        logger.info(f"  - Successfully parsed: {len(rules)}")
        logger.info(f"  - Parse errors: {parse_errors}")
        logger.info(f"  - Local rules cache size: {len(self.rules)}")
        logger.info("=" * 60)
        
        if parse_errors > 0:
            logger.warning(f"WARNING: {parse_errors} rule(s) failed to parse and were skipped!")
        
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

        payload = {
            'rule_id': rule.id,
            'old_rule': old_rule_dict,
            'new_rule': rule.to_dict(),
            'change_source': 'manual',
            'checksum_old': old_rule.calculate_checksum() if old_rule else None,
            'checksum_new': rule.calculate_checksum()
        }

        # Ожидаем RULE_UPDATE_APPROVED или RULE_UPDATE_REJECTED
        response = await self._send_and_wait(
            MessageType.RULE_UPDATE_REQUEST, payload,
            (MessageType.RULE_UPDATE_APPROVED, MessageType.RULE_UPDATE_REJECTED),
            timeout=30.0
        )

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

    async def request_config(self) -> Optional[Dict[str, Any]]:
        """
        Запрос конфигурации с сервера

        Returns:
            Конфигурация или None при ошибке
        """
        if not self.connected or not self.protocol:
            logger.warning("Not connected to server")
            return None

        try:
            response = await self._send_and_wait(
                MessageType.CONFIG_REQUEST,
                {'client_id': self.client_id},
                MessageType.CONFIG_RESPONSE,
                timeout=10.0
            )

            if response and response.header.message_type == MessageType.CONFIG_RESPONSE:
                config_data = response.payload.get('config')
                if config_data:
                    return config_data
                else:
                    logger.warning("No config data in response")
            else:
                logger.warning(f"Unexpected response type: {response.header.message_type if response else None}")

        except Exception as e:
            logger.error(f"Error requesting config: {e}", exc_info=True)

        return None

    async def _apply_config(self, config_data: Dict[str, Any]):
        """
        Применение новой конфигурации

        Args:
            config_data: Новые данные конфигурации
        """
        if not self.config_path:
            logger.warning("Config path not set, cannot apply config")
            return

        backup_path = self.config_path.with_suffix('.json.bak')
        try:
            # Создаем резервную копию текущего конфига
            if self.config_path.exists():
                shutil.copy2(self.config_path, backup_path)
                logger.info(f"Created config backup: {backup_path}")

            # Сохраняем новый конфиг
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)

            logger.info(f"Configuration saved to {self.config_path}")

            # Применяем изменения
            if 'server_host' in config_data:
                self.server_host = config_data['server_host']
            if 'server_port' in config_data:
                self.server_port = config_data['server_port']
            if 'verify_ssl' in config_data:
                # Обновляем SSL контекст при следующем подключении
                self.verify_ssl = config_data['verify_ssl']

            # Вызываем callback для применения других настроек
            if self.config_sync_callback:
                try:
                    await self.config_sync_callback(config_data)
                except Exception as e:
                    logger.error(f"Error in config sync callback: {e}", exc_info=True)

            logger.info("Configuration applied successfully")

        except Exception as e:
            logger.error(f"Error applying config: {e}", exc_info=True)
            # Восстанавливаем из резервной копии при ошибке
            if backup_path.exists():
                try:
                    shutil.copy2(backup_path, self.config_path)
                    logger.info("Restored config from backup")
                except Exception as restore_error:
                    logger.error(f"Failed to restore config: {restore_error}")

    def _setup_log_handler(self):
        """Setup log handler to capture logs for sending to server"""
        class LogCaptureHandler(logging.Handler):
            def __init__(self, log_buffer):
                super().__init__()
                self.log_buffer = log_buffer

            def emit(self, record):
                try:
                    if (
                        record.name == logger.name
                        and record.funcName in TRANSPORT_LOG_FUNCTIONS
                    ):
                        return
                    log_entry = {
                        'timestamp': datetime.utcnow().isoformat() + "Z",
                        'level': record.levelname,
                        'logger_name': record.name,
                        'message': self.format(record)
                    }
                    self.log_buffer.append(log_entry)
                except Exception:
                    pass  # Ignore errors in log handler

        self._log_handler = LogCaptureHandler(self._log_buffer)
        self._log_handler.setLevel(logging.DEBUG)
        # Add to root logger to capture all logs
        logging.getLogger().addHandler(self._log_handler)

    async def send_system_status(self):
        """Send system status report to server"""
        if not self._system_status_enabled:
            return
            
        if not self.connected or not self.protocol:
            return

        try:
            # Get plugin status if plugin_manager is available
            plugins_status = []
            if self.plugin_manager:
                try:
                    plugins_status = await self.plugin_manager.get_status_report()
                except Exception as e:
                    logger.debug(f"Error getting plugin status: {e}")

            # Collect system status
            status = self.system_monitor.collect_system_status(plugins_status)

            # Send to server
            message = self.protocol.create_message(
                MessageType.SYSTEM_STATUS_REPORT,
                status
            )
            self.writer.write(message)
            await self.writer.drain()
            self._last_status_send = datetime.utcnow()
            logger.info("System status report sent to server (includes CPU, memory, disk, OS info, and plugin status)")
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            logger.warning(f"Connection lost while sending system status: {e}")
            self.connected = False
        except Exception as e:
            logger.error(f"Error sending system status: {e}", exc_info=True)

    async def send_logs(self):
        """Send buffered logs to server"""
        if not self._logs_enabled:
            return
            
        if not self.connected or not self.protocol:
            return

        async with self._log_send_lock:
            if not self._log_buffer:
                return

            try:
                # Keep buffered logs until the transport confirms delivery.
                logs_to_send = list(self._log_buffer)
                if not logs_to_send:
                    return

                message = self.protocol.create_message(
                    MessageType.LOG_REPORT,
                    {'logs': logs_to_send}
                )
                self.writer.write(message)
                await self.writer.drain()

                for _ in range(min(len(logs_to_send), len(self._log_buffer))):
                    self._log_buffer.popleft()

                self._last_log_send = datetime.utcnow()
                logger.info(f"Sent {len(logs_to_send)} log entries to server")
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                logger.warning(f"Connection lost while sending logs: {e}")
                self.connected = False
            except Exception as e:
                logger.error(f"Error sending logs: {e}", exc_info=True)

    async def _message_handler(self):
        """Обработчик входящих сообщений.
        
        Является единственным читателем из self.reader.
        Если пришёл ответ на ожидающий запрос (_pending_responses),
        резолвит соответствующий Future вместо обработки через _process_message.
        """
        logger.info("Message handler started")
        logger.debug(f"Message handler: connected={self.connected}, protocol={self.protocol is not None}, reader={self.reader is not None}")
        
        while self.connected:
            try:
                if not self.protocol or not self.reader:
                    logger.warning("Message handler: protocol or reader is None, stopping")
                    break

                logger.debug("Message handler: waiting for message (timeout=60s)...")
                message = await asyncio.wait_for(
                    self.protocol.read_message(self.reader),
                    timeout=60.0
                )

                if not message:
                    logger.warning("Message handler: received None message, stopping")
                    break
                
                logger.debug(f"Message handler: received message type={message.header.message_type}")

                # Проверяем, ждёт ли кто-то этот тип ответа
                msg_type = message.header.message_type
                logger.debug(f"Message handler received: type={msg_type}")
                
                future = self._pending_responses.pop(msg_type, None)
                if future is not None and not future.done():
                    logger.info(f"Found pending future for {msg_type}, resolving it")
                    # Удаляем остальные ключи, ссылающиеся на тот же future
                    # (для случая когда ожидалось несколько типов ответа)
                    to_remove = [
                        k for k, v in self._pending_responses.items() if v is future
                    ]
                    for k in to_remove:
                        self._pending_responses.pop(k, None)
                    future.set_result(message)
                    logger.debug(f"Future resolved for {msg_type}")
                else:
                    if future is None:
                        logger.debug(f"No pending future for {msg_type}, processing as regular message")
                    else:
                        logger.warning(f"Future for {msg_type} already done, processing as regular message")
                    await self._process_message(message)

            except asyncio.CancelledError:
                break
            except asyncio.TimeoutError:
                # Отправляем heartbeat
                if self.protocol and self.connected:
                    try:
                        heartbeat = self.protocol.create_message(MessageType.HEARTBEAT, {})
                        self.writer.write(heartbeat)
                        await self.writer.drain()
                    except (ConnectionResetError, BrokenPipeError, OSError) as e:
                        logger.warning(f"Connection lost while sending heartbeat: {e}")
                        self.connected = False
                        break
                
                # Периодическая отправка статуса и логов теперь выполняется в _periodic_tasks_loop
                # Здесь оставляем только как резервный механизм
                if self.connected:
                    now = datetime.utcnow()
                    # Отправляем статус только если прошло достаточно времени
                    if (self._last_status_send is None or 
                        (now - self._last_status_send).total_seconds() >= self._status_send_interval):
                        await self.send_system_status()
                    
                    # Отправляем логи только если прошло достаточно времени
                    if (self._last_log_send is None or 
                        (now - self._last_log_send).total_seconds() >= self._log_send_interval):
                        await self.send_logs()
            except (ConnectionResetError, BrokenPipeError, OSError, asyncio.IncompleteReadError) as e:
                logger.warning(f"Connection lost in message handler: {e}")
                self.connected = False
                break
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

        elif msg_type == MessageType.CONFIG_UPDATE:
            # Обновление конфигурации с сервера
            config_data = message.payload.get('config')
            if config_data:
                try:
                    await self._apply_config(config_data)
                    logger.info("Configuration updated from server")
                    # Отправляем подтверждение
                    if self.protocol:
                        response = self.protocol.create_message(
                            MessageType.CONFIG_RESPONSE,
                            {'status': 'applied', 'timestamp': datetime.utcnow().isoformat()}
                        )
                        self.writer.write(response)
                        await self.writer.drain()
                except Exception as e:
                    logger.error(f"Error applying config update: {e}", exc_info=True)
                    # Отправляем ошибку
                    if self.protocol:
                        response = self.protocol.create_message(
                            MessageType.CONFIG_RESPONSE,
                            {'status': 'error', 'error': str(e)}
                        )
                        self.writer.write(response)
                        await self.writer.drain()
    
    def _start_periodic_tasks(self):
        """Запуск периодических задач для отправки статуса и логов"""
        if self._periodic_tasks_task is None or self._periodic_tasks_task.done():
            self._periodic_tasks_task = asyncio.create_task(self._periodic_tasks_loop())
    
    async def _periodic_tasks_loop(self):
        """Цикл периодических задач"""
        logger.info("Periodic tasks loop started")
        while self.connected:
            try:
                await asyncio.sleep(10)  # Проверяем каждые 10 секунд
                
                if not self.connected:
                    logger.debug("Periodic tasks: client disconnected, stopping loop")
                    break
                
                now = datetime.utcnow()
                
                # Отправляем системный статус
                if self._system_status_enabled:
                    if (self._last_status_send is None or 
                        (now - self._last_status_send).total_seconds() >= self._status_send_interval):
                        logger.info(f"Periodic task: sending system status (interval: {self._status_send_interval}s)")
                        await self.send_system_status()
                
                # Отправляем логи
                if self._logs_enabled:
                    if (self._last_log_send is None or 
                        (now - self._last_log_send).total_seconds() >= self._log_send_interval):
                        log_count = len(self._log_buffer)
                        if log_count > 0:
                            logger.info(f"Periodic task: sending {log_count} log entries (interval: {self._log_send_interval}s)")
                        await self.send_logs()
                        
            except asyncio.CancelledError:
                logger.debug("Periodic tasks loop cancelled")
                break
            except Exception as e:
                logger.error(f"Error in periodic tasks loop: {e}", exc_info=True)
                await asyncio.sleep(10)  # Небольшая задержка перед повтором
        
        logger.info("Periodic tasks loop stopped")
    
    async def send_current_config(self):
        """Отправка текущей конфигурации клиента на сервер"""
        if not self.connected or not self.protocol:
            return
        
        if not self.config_path or not self.config_path.exists():
            logger.debug("Config path not set or file doesn't exist, skipping config send")
            return
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # Отправляем конфигурацию на сервер
            message = self.protocol.create_message(
                MessageType.CONFIG_RESPONSE,
                {
                    'status': 'current',
                    'config': config_data,
                    'timestamp': datetime.utcnow().isoformat()
                }
            )
            self.writer.write(message)
            await self.writer.drain()
            logger.debug("Current configuration sent to server")
        except Exception as e:
            logger.error(f"Error sending current config: {e}", exc_info=True)


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
