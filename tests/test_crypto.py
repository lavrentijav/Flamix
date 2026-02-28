"""Тесты для криптографии"""

import pytest
from flamix.common.crypto import (
    generate_nonce, encrypt_aes_gcm, decrypt_aes_gcm,
    calculate_hmac, verify_hmac, derive_key
)


def test_nonce_generation():
    """Тест генерации nonce"""
    nonce1 = generate_nonce()
    nonce2 = generate_nonce()
    assert len(nonce1) == 12
    assert len(nonce2) == 12
    assert nonce1 != nonce2  # Должны быть разными


def test_aes_gcm_encryption():
    """Тест шифрования AES-GCM"""
    key = b'\x00' * 32  # 256 бит
    plaintext = b"Hello, World!"

    nonce, ciphertext = encrypt_aes_gcm(key, plaintext)
    decrypted = decrypt_aes_gcm(key, nonce, ciphertext)

    assert decrypted == plaintext


def test_hmac():
    """Тест HMAC"""
    key = b"test_key"
    data = b"test_data"

    signature = calculate_hmac(key, data)
    assert verify_hmac(key, data, signature)
    assert not verify_hmac(key, data, b"wrong_signature")


def test_key_derivation():
    """Тест деривации ключа"""
    shared_secret = b'\x00' * 32
    key1 = derive_key(shared_secret)
    key2 = derive_key(shared_secret)

    assert len(key1) == 32
    assert key1 == key2  # Одинаковый секрет -> одинаковый ключ
