"""Система безопасности клиента"""

import ssl
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class ClientSecurity:
    """Управление безопасностью клиента"""

    def __init__(self, cert_dir: Path):
        """
        Инициализация системы безопасности

        Args:
            cert_dir: Директория с сертификатами
        """
        self.cert_dir = cert_dir
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        self.client_cert_path = cert_dir / "client.crt"
        self.client_key_path = cert_dir / "client.key"
        self.ca_cert_path = cert_dir / "ca.crt"

    def create_ssl_context(self) -> ssl.SSLContext:
        """
        Создание SSL контекста для клиента

        Returns:
            SSL контекст
        """
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        # Загружаем CA сертификат для проверки сервера
        if self.ca_cert_path.exists():
            context.load_verify_locations(str(self.ca_cert_path))
        else:
            logger.warning("CA certificate not found, using default verification")

        # Загружаем клиентский сертификат если есть
        if self.client_cert_path.exists() and self.client_key_path.exists():
            context.load_cert_chain(
                str(self.client_cert_path),
                str(self.client_key_path)
            )

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
