"""Система безопасности клиента"""

import ssl
import logging
import os
from pathlib import Path
from typing import Optional

import keyring
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

CLIENT_KEY_PASSWORD_ENV = "FLAMIX_CLIENT_KEY_PASSWORD"
CLIENT_KEY_PASSWORD_SERVICE = "flamix-client"


class ClientSecurity:
    """Управление безопасностью клиента"""

    CLIENT_KEY_PASSWORD_SERVICE = CLIENT_KEY_PASSWORD_SERVICE

    def __init__(self, cert_dir: Path, client_id: Optional[str] = None):
        """
        Инициализация системы безопасности

        Args:
            cert_dir: Директория с сертификатами
        """
        self.cert_dir = cert_dir
        self.client_id = str(client_id) if client_id is not None else None
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        self.client_cert_path = cert_dir / "client.crt"
        self.client_key_path = cert_dir / "client.key"
        self.ca_cert_path = cert_dir / "ca.crt"

    @classmethod
    def get_keyring_name(cls, client_id: str) -> str:
        """Return the keyring slot used for the encrypted client key password."""
        return f"client-key-password:{client_id}"

    @classmethod
    def store_client_key_password(cls, client_id: str, password: str):
        """Persist the local client-key password in the OS keyring."""
        keyring.set_password(cls.CLIENT_KEY_PASSWORD_SERVICE, cls.get_keyring_name(str(client_id)), password)

    def _load_client_key_password(self) -> Optional[str]:
        """Load the client key password from env or keyring."""
        password = os.getenv(CLIENT_KEY_PASSWORD_ENV)
        if password:
            return password
        if self.client_id:
            return keyring.get_password(
                self.CLIENT_KEY_PASSWORD_SERVICE,
                self.get_keyring_name(self.client_id),
            )
        return None

    def save_generated_client_materials(
        self,
        client_id: str,
        client_cert_pem: bytes,
        client_key,
        ca_cert_pem: bytes,
        password: str,
    ):
        """Persist freshly enrolled client credentials locally."""
        client_id = str(client_id)
        encrypted_key = client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
        )
        self.client_cert_path.write_bytes(client_cert_pem)
        self.client_key_path.write_bytes(encrypted_key)
        self.ca_cert_path.write_bytes(ca_cert_pem)
        self.store_client_key_password(client_id, password)
        self.client_id = client_id

    def create_ssl_context(self, verify_ssl: bool = True) -> ssl.SSLContext:
        """
        Создание SSL контекста для клиента
        
        Важно: Использует ТОЛЬКО наш корневой CA для проверки сервера,
        а не системные CA сертификаты. Это обеспечивает взаимную проверку:
        - Клиент проверяет сервер используя корневой CA
        - Сервер проверяет клиента используя корневой CA

        Args:
            verify_ssl: Проверять ли SSL сертификат сервера (по умолчанию True)

        Returns:
            SSL контекст
        """
        if verify_ssl:
            # Создаём контекст БЕЗ системных CA - используем только наш корневой CA
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Загружаем ТОЛЬКО наш корневой CA для проверки сервера
            if self.ca_cert_path.exists():
                try:
                    context.load_verify_locations(str(self.ca_cert_path))
                    logger.debug(f"Loaded root CA certificate from {self.ca_cert_path} for server verification")
                except Exception as e:
                    logger.error(f"Failed to load CA certificate: {e}. Server verification will fail.")
                    raise
            else:
                logger.error("Root CA certificate not found. Cannot verify server certificate.")
                raise FileNotFoundError(f"Root CA certificate not found at {self.ca_cert_path}")
        else:
            # Для режима разработки - отключаем проверку сертификата
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            logger.warning("SSL certificate verification is DISABLED (development mode)")

        # Загружаем клиентский сертификат для mutual TLS (сервер проверяет клиента)
        if self.client_cert_path.exists() and self.client_key_path.exists():
            try:
                client_key_password = self._load_client_key_password()
                key_is_encrypted = b"ENCRYPTED PRIVATE KEY" in self.client_key_path.read_bytes()
                if key_is_encrypted and not client_key_password:
                    raise RuntimeError(
                        f"Encrypted client key requires {CLIENT_KEY_PASSWORD_ENV}"
                    )
                context.load_cert_chain(
                    str(self.client_cert_path),
                    str(self.client_key_path),
                    password=client_key_password
                )
                logger.info(f"Loaded client certificate from {self.client_cert_path} for mutual TLS")
            except Exception as e:
                logger.error(f"Failed to load client certificate: {e}")
                if not os.getenv(CLIENT_KEY_PASSWORD_ENV):
                    logger.error(
                        "If the client key is encrypted, set %s before starting the client",
                        CLIENT_KEY_PASSWORD_ENV,
                    )
                # ?????? mutual TLS ???????????????????? ???????????????????? ????????????????????
                if verify_ssl:
                    raise
        else:
            logger.warning(f"Client certificate not found at {self.client_cert_path} or key not found at {self.client_key_path}")
            if verify_ssl:
                logger.error("Client certificate is required for mutual TLS")
                raise FileNotFoundError("Client certificate not found")

        return context

    def has_certificates(self) -> bool:
        """
        Проверка наличия сертификатов

        Returns:
            True если сертификаты есть
        """
        return (
            self.client_cert_path.exists() and
            self.client_key_path.exists() and
            self.ca_cert_path.exists()
        )
