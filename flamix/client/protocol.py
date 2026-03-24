"""Протокол связи клиента"""

import asyncio
import json
import logging
import struct
import time
from typing import Optional, Dict, Any
from datetime import datetime

from flamix.common.protocol_types import MessageType, MessageHeader, ProtocolMessage
from flamix.common.crypto import (
    encrypt_aes_gcm, decrypt_aes_gcm,
    calculate_hmac, verify_hmac,
    generate_nonce
)

logger = logging.getLogger(__name__)


class ClientProtocol:
    """Протокол обработки сообщений на клиенте"""

    MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB
    MESSAGE_TIMEOUT = 30.0  # секунд

    def __init__(self, session_key: bytes, session_id: str):
        """
        Инициализация протокола

        Args:
            session_key: Сессионный ключ для шифрования
            session_id: ID сессии
        """
        self.session_key = session_key
        self.session_id = session_id
        self.sequence_number = 0
        self.expected_sequence_number = 0

    async def read_message(self, reader: asyncio.StreamReader) -> Optional[ProtocolMessage]:
        """
        Чтение сообщения из потока

        Args:
            reader: Поток для чтения

        Returns:
            Расшифрованное сообщение или None при ошибке
        """
        try:
            # Читаем заголовок
            header_data = await asyncio.wait_for(
                reader.readexactly(MessageHeader.HEADER_SIZE),
                timeout=self.MESSAGE_TIMEOUT
            )

            header = MessageHeader.from_bytes(header_data)

            # Проверка размера payload
            if header.payload_length > self.MAX_MESSAGE_SIZE:
                logger.error(f"Message too large: {header.payload_length}")
                return None

            # Читаем payload
            encrypted_payload = await asyncio.wait_for(
                reader.readexactly(header.payload_length),
                timeout=self.MESSAGE_TIMEOUT
            )

            # Расшифровка
            # Формат: [nonce_length: 1 byte][nonce: 12 bytes][hmac: 32 bytes][ciphertext: variable]
            nonce_length = encrypted_payload[0]
            if nonce_length != 12:
                logger.error(f"Invalid nonce length: {nonce_length}")
                return None

            nonce = encrypted_payload[1:13]
            hmac_signature = encrypted_payload[13:45]
            ciphertext = encrypted_payload[45:]

            # Проверка HMAC
            header_bytes = header.to_bytes()
            data_to_verify = header_bytes + nonce + ciphertext
            if not verify_hmac(self.session_key, data_to_verify, hmac_signature):
                logger.error("HMAC verification failed")
                return None

            # Расшифровка (без AAD, как при шифровании)
            try:
                plaintext = decrypt_aes_gcm(self.session_key, nonce, ciphertext, b'')
            except Exception as e:
                logger.error(f"Decryption failed: {e}")
                return None

            # Парсинг JSON
            try:
                payload = json.loads(plaintext.decode('utf-8'))
            except Exception as e:
                logger.error(f"JSON parsing failed: {e}")
                return None

            # Проверка последовательности (для клиента менее строгая)
            if header.sequence_number < self.expected_sequence_number:
                logger.warning(f"Out of order message: {header.sequence_number} < {self.expected_sequence_number}")
            else:
                self.expected_sequence_number = header.sequence_number + 1

            message = ProtocolMessage(
                header=header,
                payload=payload,
                timestamp=datetime.fromtimestamp(payload.get('timestamp', time.time())),
                nonce=nonce
            )

            return message

        except asyncio.TimeoutError:
            # Let timeout propagate so the caller can handle it
            # (e.g. send heartbeat and continue)
            raise
        except (ConnectionResetError, BrokenPipeError, OSError, asyncio.IncompleteReadError) as e:
            # Connection was closed/reset - this is normal when server disconnects
            # Re-raise so caller can handle it properly (break the loop)
            raise
        except Exception as e:
            logger.error(f"Error reading message: {e}", exc_info=True)
            return None

    def create_message(
        self,
        message_type: MessageType,
        payload: Dict[str, Any],
        sequence_number: Optional[int] = None
    ) -> bytes:
        """
        Создание зашифрованного сообщения

        Args:
            message_type: Тип сообщения
            payload: Данные сообщения
            sequence_number: Номер последовательности (автоматически если None)

        Returns:
            Байты сообщения для отправки
        """
        if sequence_number is None:
            sequence_number = self.sequence_number + 1
            self.sequence_number = sequence_number

        # Добавляем timestamp и session_id (не перезаписываем, если уже задан)
        payload['timestamp'] = time.time()
        payload.setdefault('session_id', self.session_id)

        # Сериализация JSON
        plaintext = json.dumps(payload).encode('utf-8')

        # Шифрование (без использования заголовка как AAD)
        # Шифруем с пустым AAD, HMAC защитит заголовок отдельно
        nonce, ciphertext = encrypt_aes_gcm(self.session_key, plaintext, b'')
        
        # Вычисляем размер payload: [nonce_length: 1][nonce: 12][hmac: 32][ciphertext: variable]
        total_payload_size = 1 + len(nonce) + 32 + len(ciphertext)  # 32 = HMAC size
        
        # Создаём финальный заголовок с правильным размером
        header = MessageHeader(
            version=1,
            message_type=message_type,
            payload_length=total_payload_size,
            sequence_number=sequence_number,
            checksum=0,
            reserved=0
        )
        header_bytes = header.to_bytes()
        
        # Вычисляем HMAC от заголовка + nonce + ciphertext
        data_to_sign = header_bytes + nonce + ciphertext
        hmac_signature = calculate_hmac(self.session_key, data_to_sign)

        # Собираем финальное сообщение
        message = (
            header_bytes +
            bytes([len(nonce)]) +  # nonce_length
            nonce +
            hmac_signature +
            ciphertext
        )

        return message
