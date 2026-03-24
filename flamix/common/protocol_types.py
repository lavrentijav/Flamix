"""Типы протокола связи"""

from enum import IntEnum
from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import struct


class MessageType(IntEnum):
    """Типы сообщений протокола"""

    # Аутентификация
    AUTH_REQUEST = 0x01
    AUTH_RESPONSE = 0x02

    # Обмен ключами
    DH_KEY_EXCHANGE = 0x10
    DH_KEY_RESPONSE = 0x11

    # Синхронизация правил
    SYNC_REQUEST = 0x20
    SYNC_RESPONSE = 0x21

    # Обновление правил
    RULE_UPDATE = 0x30
    RULE_UPDATE_REQUEST = 0x31
    RULE_UPDATE_APPROVED = 0x32
    RULE_UPDATE_REJECTED = 0x33

    # Удаление правил
    RULE_DELETE = 0x40
    RULE_DELETE_REQUEST = 0x41

    # Аналитика
    ANALYTICS_REPORT = 0x50

    # Управление соединением
    HEARTBEAT = 0x60
    HEARTBEAT_RESPONSE = 0x61

    # Ротация ключей
    KEY_ROTATION = 0x70
    KEY_ROTATION_RESPONSE = 0x71

    # Синхронизация конфигурации
    CONFIG_REQUEST = 0x80
    CONFIG_UPDATE = 0x81
    CONFIG_RESPONSE = 0x82

    # Системный мониторинг
    SYSTEM_STATUS_REPORT = 0x90
    LOG_REPORT = 0x91

    # Ошибки
    ERROR = 0xFF


@dataclass
class MessageHeader:
    """Заголовок сообщения"""

    version: int = 1
    message_type: MessageType = MessageType.HEARTBEAT
    payload_length: int = 0
    sequence_number: int = 0
    checksum: int = 0
    reserved: int = 0

    HEADER_SIZE = 16

    def to_bytes(self) -> bytes:
        """Преобразование заголовка в байты"""
        return struct.pack(
            '!BBIIIH',
            self.version,
            self.message_type.value,
            self.payload_length,
            self.sequence_number,
            self.checksum,
            self.reserved
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> 'MessageHeader':
        """Создание заголовка из байтов"""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"Header data too short: {len(data)} < {cls.HEADER_SIZE}")

        version, msg_type, payload_len, seq_num, checksum, reserved = struct.unpack(
            '!BBIIIH',
            data[:cls.HEADER_SIZE]
        )
        return cls(
            version=version,
            message_type=MessageType(msg_type),
            payload_length=payload_len,
            sequence_number=seq_num,
            checksum=checksum,
            reserved=reserved
        )


@dataclass
class ProtocolMessage:
    """Сообщение протокола"""

    header: MessageHeader
    payload: Dict[str, Any]
    timestamp: Optional[datetime] = None
    nonce: Optional[bytes] = None

    def __post_init__(self):
        """Инициализация после создания"""
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
        if self.nonce is None:
            from flamix.common.crypto import generate_nonce
            self.nonce = generate_nonce()
