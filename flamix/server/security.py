"""Система безопасности сервера"""

import ssl
import logging
import ipaddress
from pathlib import Path
from typing import Optional, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

from flamix.common.diffie_hellman import DiffieHellman

logger = logging.getLogger(__name__)


class ServerSecurity:
    """Управление безопасностью сервера"""

    def __init__(self, cert_dir: Path):
        """
        Инициализация системы безопасности

        Args:
            cert_dir: Директория с сертификатами
        """
        self.cert_dir = cert_dir
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        self.ca_cert_path = cert_dir / "ca.crt"
        self.ca_key_path = cert_dir / "ca.key"
        self.server_cert_path = cert_dir / "server.crt"
        self.server_key_path = cert_dir / "server.key"

    def generate_ca(self) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """
        Генерация CA сертификата (создает только если не существует)

        Returns:
            Кортеж (сертификат, приватный ключ)
        """
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            logger.debug("CA certificate already exists, loading existing...")
            return self._load_ca()

        logger.info("CA certificate not found, generating new one (this is a one-time operation)...")

        # Генерация приватного ключа
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Создание сертификата
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Flamix"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Flamix CA"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)  # 10 лет
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("flamix-ca")]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).sign(private_key, hashes.SHA256())

        # Сохранение
        self._save_certificate(cert, self.ca_cert_path)
        self._save_private_key(private_key, self.ca_key_path)

        logger.info("CA certificate generated successfully")
        return cert, private_key

    def generate_server_cert(self, hostname: str = "localhost") -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """
        Генерация серверного сертификата (создает только если не существует)

        Args:
            hostname: Имя хоста сервера

        Returns:
            Кортеж (сертификат, приватный ключ)
        """
        if self.server_cert_path.exists() and self.server_key_path.exists():
            logger.debug("Server certificate already exists, loading existing...")
            return self._load_server_cert()

        logger.info(f"Server certificate not found, generating new one for {hostname} (this is a one-time operation)...")

        # Загружаем CA
        ca_cert, ca_key = self.generate_ca()

        # Генерация приватного ключа сервера
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Создание сертификата
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Flamix"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)  # 1 год
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(ca_key, hashes.SHA256())

        # Сохранение
        self._save_certificate(cert, self.server_cert_path)
        self._save_private_key(private_key, self.server_key_path)

        logger.info("Server certificate generated successfully")
        return cert, private_key

    def create_ssl_context(self, require_client_cert: bool = True) -> ssl.SSLContext:
        """
        Создание SSL контекста для сервера

        Args:
            require_client_cert: Требовать ли клиентский сертификат (mutual TLS)

        Returns:
            SSL контекст
        """
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(
            str(self.server_cert_path),
            str(self.server_key_path)
        )

        if require_client_cert:
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(str(self.ca_cert_path))

        return context

    def _load_ca(self) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Загрузка CA сертификата"""
        with open(self.ca_cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        with open(self.ca_key_path, 'rb') as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        return cert, key

    def _load_server_cert(self) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Загрузка серверного сертификата"""
        with open(self.server_cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        with open(self.server_key_path, 'rb') as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        return cert, key

    def _save_certificate(self, cert: x509.Certificate, path: Path):
        """Сохранение сертификата"""
        with open(path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def _save_private_key(self, key: rsa.RSAPrivateKey, path: Path):
        """Сохранение приватного ключа"""
        with open(path, 'wb') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

    def sign_client_certificate(
        self,
        client_id: str,
        client_public_key: rsa.RSAPublicKey
    ) -> x509.Certificate:
        """
        Подпись клиентского сертификата

        Args:
            client_id: ID клиента
            client_public_key: Публичный ключ клиента

        Returns:
            Подписанный сертификат
        """
        ca_cert, ca_key = self._load_ca()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Flamix"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"client-{client_id}"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            client_public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).sign(ca_key, hashes.SHA256())

        return cert
