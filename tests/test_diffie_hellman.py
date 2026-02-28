"""Тесты для Диффи-Хеллмана"""

import pytest
from flamix.common.diffie_hellman import DiffieHellman


def test_dh_key_exchange():
    """Тест обмена ключами"""
    alice = DiffieHellman()
    bob = DiffieHellman()

    # Обмен публичными ключами
    alice_public = alice.get_public_key_bytes()
    bob_public = bob.get_public_key_bytes()

    # Вычисление общего секрета
    alice_secret = alice.compute_shared_secret(bob_public)
    bob_secret = bob.compute_shared_secret(alice_public)

    # Общий секрет должен быть одинаковым
    assert alice_secret == bob_secret
    assert len(alice_secret) > 0


def test_session_key_generation():
    """Тест генерации сессионного ключа"""
    alice = DiffieHellman()
    bob = DiffieHellman()

    alice_public = alice.get_public_key_bytes()
    bob_public = bob.get_public_key_bytes()

    alice_shared = alice.compute_shared_secret(bob_public)
    bob_shared = bob.compute_shared_secret(alice_public)

    # Генерация сессионных ключей
    alice_key = DiffieHellman.generate_session_key(alice_shared)
    bob_key = DiffieHellman.generate_session_key(bob_shared)

    assert alice_key == bob_key
    assert len(alice_key) == 32  # 256 бит
