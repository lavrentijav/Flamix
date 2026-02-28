"""Реализация Диффи-Хеллмана для обмена ключами"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from typing import Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class DiffieHellman:
    """Класс для обмена ключами по алгоритму Диффи-Хеллмана (ECDH)"""

    # Используем кривую secp256r1 (P-256) для баланса безопасности и производительности
    CURVE = ec.SECP256R1()

    def __init__(self):
        """Инициализация с генерацией пары ключей"""
        self.private_key = ec.generate_private_key(self.CURVE, default_backend())
        self.public_key = self.private_key.public_key()
        self.shared_secret: Optional[bytes] = None

    def get_public_key_bytes(self) -> bytes:
        """
        Получение публичного ключа в виде байтов

        Returns:
            Сериализованный публичный ключ
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def public_key_from_bytes(data: bytes) -> ec.EllipticCurvePublicKey:
        """
        Восстановление публичного ключа из байтов

        Args:
            data: Сериализованный публичный ключ

        Returns:
            Публичный ключ
        """
        return serialization.load_pem_public_key(data, backend=default_backend())

    def compute_shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        """
        Вычисление общего секрета с использованием публичного ключа другой стороны

        Args:
            peer_public_key_bytes: Публичный ключ другой стороны

        Returns:
            Общий секрет
        """
        peer_public_key = self.public_key_from_bytes(peer_public_key_bytes)
        self.shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        return self.shared_secret

    def get_shared_secret(self) -> Optional[bytes]:
        """
        Получение вычисленного общего секрета

        Returns:
            Общий секрет или None если еще не вычислен
        """
        return self.shared_secret

    @staticmethod
    def generate_session_key(shared_secret: bytes, salt: Optional[bytes] = None, info: Optional[bytes] = None) -> bytes:
        """
        Генерация сессионного ключа из общего секрета используя HKDF

        Args:
            shared_secret: Общий секрет из Диффи-Хеллмана
            salt: Соль для HKDF (опционально)
            info: Дополнительная информация для HKDF (опционально)

        Returns:
            Сессионный ключ (32 байта для AES-256)
        """
        from flamix.common.crypto import derive_key
        return derive_key(shared_secret, salt, info)
