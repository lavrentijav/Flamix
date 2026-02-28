"""Криптографические утилиты"""

import hashlib
import hmac
import secrets
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


def generate_nonce(size: int = 12) -> bytes:
    """
    Генерация случайного nonce

    Args:
        size: Размер nonce в байтах

    Returns:
        Случайный nonce
    """
    return secrets.token_bytes(size)


def derive_key(shared_secret: bytes, salt: Optional[bytes] = None, info: Optional[bytes] = None) -> bytes:
    """
    Деривация ключа из общего секрета используя HKDF

    Args:
        shared_secret: Общий секрет (например, из Диффи-Хеллмана)
        salt: Соль (опционально)
        info: Дополнительная информация (опционально)

    Returns:
        Деривированный ключ (32 байта для AES-256)
    """
    if salt is None:
        salt = b'flamix_key_derivation'
    if info is None:
        info = b'flamix_session_key'

    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 бит для AES-256
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return kdf.derive(shared_secret)


def encrypt_aes_gcm(key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Шифрование данных используя AES-256-GCM

    Args:
        key: Ключ шифрования (32 байта)
        plaintext: Открытый текст
        associated_data: Дополнительные данные для аутентификации

    Returns:
        Кортеж (nonce, ciphertext + tag)
    """
    aesgcm = AESGCM(key)
    nonce = generate_nonce()
    if associated_data is None:
        associated_data = b''
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """
    Расшифровка данных используя AES-256-GCM

    Args:
        key: Ключ шифрования (32 байта)
        nonce: Nonce использованный при шифровании
        ciphertext: Зашифрованный текст (включая tag)
        associated_data: Дополнительные данные для аутентификации

    Returns:
        Открытый текст
    """
    aesgcm = AESGCM(key)
    if associated_data is None:
        associated_data = b''
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


def calculate_hmac(key: bytes, data: bytes) -> bytes:
    """
    Вычисление HMAC-SHA256

    Args:
        key: Ключ HMAC
        data: Данные для подписи

    Returns:
        HMAC подпись
    """
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, signature: bytes) -> bool:
    """
    Проверка HMAC подписи

    Args:
        key: Ключ HMAC
        data: Данные
        signature: Подпись для проверки

    Returns:
        True если подпись валидна
    """
    expected = calculate_hmac(key, data)
    return hmac.compare_digest(expected, signature)


def hash_data(data: bytes) -> str:
    """
    Хеширование данных используя SHA-256

    Args:
        data: Данные для хеширования

    Returns:
        Hex строка хеша
    """
    return hashlib.sha256(data).hexdigest()
