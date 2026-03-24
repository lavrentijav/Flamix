"""Система безопасности сервера"""

import ssl
import logging
import socket
import ipaddress
import secrets
from pathlib import Path
from typing import Optional, Tuple, List, Union
import keyring
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

from flamix.common.diffie_hellman import DiffieHellman

logger = logging.getLogger(__name__)

CLIENT_CERT_URI_PREFIX = "urn:flamix:client:"


def build_client_certificate_identity(client_id: str) -> str:
    """Return the canonical client identity embedded into client certificates."""
    return str(client_id)


def extract_client_id_from_certificate(
    certificate: Optional[Union[x509.Certificate, bytes]]
) -> Optional[str]:
    """Extract the Flamix client_id from a client certificate."""
    if certificate is None:
        return None

    cert = (
        x509.load_der_x509_certificate(certificate)
        if isinstance(certificate, bytes)
        else certificate
    )

    candidates = set()

    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
            if uri.startswith(CLIENT_CERT_URI_PREFIX):
                candidates.add(uri[len(CLIENT_CERT_URI_PREFIX):])
        for dns_name in san.get_values_for_type(x509.DNSName):
            if dns_name.startswith("client-"):
                candidates.add(dns_name[len("client-"):])
    except x509.ExtensionNotFound:
        pass

    for attribute in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        if attribute.value.startswith("client-"):
            candidates.add(attribute.value[len("client-"):])

    if not candidates:
        return None
    if len(candidates) > 1:
        raise ValueError(f"Certificate contains conflicting client identities: {sorted(candidates)}")
    return candidates.pop()


def get_server_ip_address(host: str = "0.0.0.0") -> str:
    """
    Определение IP адреса сервера
    
    Args:
        host: Хост сервера (если "0.0.0.0", определяется реальный IP)
    
    Returns:
        IP адрес сервера
    """
    if host != "0.0.0.0":
        return host
    
    # Определяем реальный IP адрес
    try:
        # Подключаемся к внешнему адресу чтобы узнать наш IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        server_ip = s.getsockname()[0]
        s.close()
        return server_ip
    except Exception as e:
        logger.warning(f"Failed to determine server IP address: {e}, using 127.0.0.1")
        return "127.0.0.1"


class ServerSecurity:
    """Управление безопасностью сервера"""

    SERVICE_NAME = "flamix"
    CA_KEY_PASSWORD_NAME = "ca_private_key_password"
    SERVER_KEY_PASSWORD_NAME = "server_private_key_password"

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

    def _get_private_key_password(self, key_name: str) -> bytes:
        """Return a stable password for an encrypted PEM private key."""
        password = keyring.get_password(self.SERVICE_NAME, key_name)
        if not password:
            password = secrets.token_urlsafe(32)
            keyring.set_password(self.SERVICE_NAME, key_name, password)
            logger.info("Generated private-key password for %s", key_name)
        return password.encode("utf-8")

    def _serialize_private_key(self, key: rsa.RSAPrivateKey, password: Optional[str] = None) -> bytes:
        """Serialize a private key, encrypting it when a password is provided."""
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode("utf-8"))
        else:
            encryption_algorithm = serialization.NoEncryption()

        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )

    def create_client_key_password(self) -> str:
        """Generate a one-time password used for exporting a client private key."""
        return secrets.token_urlsafe(24)

    def export_client_private_key(self, key: rsa.RSAPrivateKey, password: str) -> bytes:
        """Serialize a client private key for transport in an encrypted PEM."""
        return self._serialize_private_key(key, password=password)

    def _load_private_key_with_fallback(self, path: Path, password_name: str) -> rsa.RSAPrivateKey:
        """Load an encrypted private key, migrating legacy plaintext PEM files in place."""
        key_data = path.read_bytes()
        password = self._get_private_key_password(password_name)
        try:
            return serialization.load_pem_private_key(key_data, password=password)
        except TypeError:
            legacy_key = serialization.load_pem_private_key(key_data, password=None)
            self._save_private_key(legacy_key, path)
            logger.info("Migrated legacy plaintext private key at %s to encrypted PEM", path)
            return legacy_key


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
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        # Сохранение
        self._save_certificate(cert, self.ca_cert_path)
        self._save_private_key(private_key, self.ca_key_path)

        logger.info("CA certificate generated successfully")
        return cert, private_key

    def generate_server_cert(
        self, 
        hostname: str = "localhost",
        server_ip: Optional[str] = None
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """
        Генерация серверного сертификата (создает только если не существует)

        Args:
            hostname: Имя хоста сервера
            server_ip: IP адрес сервера (если None, определяется автоматически)

        Returns:
            Кортеж (сертификат, приватный ключ)
        """
        # Определяем IP адрес если не передан
        if server_ip is None:
            server_ip = get_server_ip_address()
        
        # Проверяем существующий сертификат
        if self.server_cert_path.exists() and self.server_key_path.exists():
            try:
                # Загружаем существующий сертификат и ключ
                existing_cert, existing_key = self._load_server_cert()
                
                # Проверяем, содержит ли он нужный IP адрес
                try:
                    san_ext = existing_cert.extensions.get_extension_for_oid(
                        x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                    )
                    san = san_ext.value
                    
                    # Проверяем наличие IP адреса в SAN
                    ip_found = False
                    if server_ip and server_ip != "127.0.0.1" and server_ip != "localhost":
                        try:
                            required_ip = ipaddress.IPv4Address(server_ip)
                            for name in san:
                                if isinstance(name, x509.IPAddress):
                                    if name == required_ip:
                                        ip_found = True
                                        break
                        except ValueError:
                            pass
                    
                    if ip_found or server_ip in ("127.0.0.1", "localhost"):
                        logger.debug(f"Server certificate already exists and contains IP {server_ip}, using existing...")
                        return existing_cert, existing_key
                    else:
                        logger.info(f"Existing certificate does not contain IP {server_ip}, regenerating...")
                        # Удаляем старый сертификат для пересоздания
                        self.server_cert_path.unlink()
                        self.server_key_path.unlink()
                except x509.ExtensionNotFound:
                    logger.info("Existing certificate does not have SAN extension, regenerating...")
                    self.server_cert_path.unlink()
                    self.server_key_path.unlink()
            except Exception as e:
                logger.warning(f"Error checking existing certificate: {e}, will regenerate")
                if self.server_cert_path.exists():
                    self.server_cert_path.unlink()
                if self.server_key_path.exists():
                    self.server_key_path.unlink()
        
        logger.info(f"Server certificate not found or needs update, generating new one for {hostname} (IP: {server_ip})...")

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

        # Получаем Subject Key Identifier из CA для Authority Key Identifier
        ca_ski = None
        try:
            ca_ski_ext = ca_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            ca_ski = ca_ski_ext.value
        except x509.ExtensionNotFound:
            # Если у CA нет SKI, создаем его из публичного ключа
            ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_cert.public_key())
        
        # Создаём список для SubjectAlternativeName
        san_list = [
            x509.DNSName(hostname),
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]
        
        # Добавляем IP адрес сервера если он указан и не является localhost
        if server_ip and server_ip != "127.0.0.1" and server_ip != "localhost":
            try:
                ip_addr = ipaddress.IPv4Address(server_ip)
                san_list.append(x509.IPAddress(ip_addr))
                logger.debug(f"Added server IP {server_ip} to certificate")
            except ValueError:
                logger.warning(f"Invalid IP address: {server_ip}, skipping")
        
        cert_builder = x509.CertificateBuilder().subject_name(
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
            x509.SubjectAlternativeName(san_list),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        
        # Добавляем Authority Key Identifier
        if ca_ski:
            cert_builder = cert_builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                critical=False,
            )
        
        cert = cert_builder.sign(ca_key, hashes.SHA256())

        # Сохранение
        self._save_certificate(cert, self.server_cert_path)
        self._save_private_key(private_key, self.server_key_path)

        logger.info(f"Server certificate generated successfully with IP {server_ip}")
        return cert, private_key

    def update_server_certificate_ip(self, server_ip: str) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """
        Принудительное обновление серверного сертификата с новым IP адресом
        
        Args:
            server_ip: IP адрес для включения в сертификат
        
        Returns:
            Кортеж (сертификат, приватный ключ)
        """
        logger.info(f"Updating server certificate with IP {server_ip}...")
        
        # Удаляем старый сертификат если существует
        if self.server_cert_path.exists():
            self.server_cert_path.unlink()
        if self.server_key_path.exists():
            self.server_key_path.unlink()
        
        # Создаём новый сертификат с указанным IP
        return self.generate_server_cert(hostname="localhost", server_ip=server_ip)

    def create_ssl_context(self, require_client_cert: bool = True) -> ssl.SSLContext:
        """
        Создание SSL контекста для сервера
        
        Важно: Использует ТОЛЬКО наш корневой CA для проверки клиентских сертификатов,
        а не системные CA. Это обеспечивает взаимную проверку:
        - Сервер использует зависимый сертификат (server.crt), подписанный корневым CA
        - Сервер проверяет клиента используя ТОЛЬКО корневой CA
        - Клиент проверяет сервер используя ТОЛЬКО корневой CA

        Args:
            require_client_cert: Требовать ли клиентский сертификат (mutual TLS)

        Returns:
            SSL контекст
        """
        # Создаём контекст БЕЗ системных CA - используем только наш корневой CA
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # Загружаем зависимый серверный сертификат (подписанный корневым CA)
        logger.info(f"Loading server certificate from {self.server_cert_path}")
        context.load_cert_chain(
            str(self.server_cert_path),
            str(self.server_key_path),
            password=self._get_private_key_password(self.SERVER_KEY_PASSWORD_NAME).decode("utf-8")
        )
        logger.info("Server certificate loaded successfully")

        if require_client_cert:
            # Требуем клиентский сертификат и проверяем его ТОЛЬКО нашим корневым CA
            logger.info("Configuring mutual TLS (client certificate required)")
            context.verify_mode = ssl.CERT_REQUIRED
            if not self.ca_cert_path.exists():
                logger.error(f"Root CA certificate not found at {self.ca_cert_path}. Cannot verify client certificates.")
                raise FileNotFoundError(f"Root CA certificate not found at {self.ca_cert_path}")
            context.load_verify_locations(str(self.ca_cert_path))
            logger.info(f"Loaded root CA certificate from {self.ca_cert_path} for client verification")

        return context

    def _load_ca(self) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Загрузка CA сертификата"""
        with open(self.ca_cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        key = self._load_private_key_with_fallback(self.ca_key_path, self.CA_KEY_PASSWORD_NAME)
        return cert, key

    def _load_server_cert(self) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Загрузка серверного сертификата"""
        with open(self.server_cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        key = self._load_private_key_with_fallback(self.server_key_path, self.SERVER_KEY_PASSWORD_NAME)
        return cert, key

    def _save_certificate(self, cert: x509.Certificate, path: Path):
        """Сохранение сертификата"""
        with open(path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def _save_private_key(self, key: rsa.RSAPrivateKey, path: Path):
        """???????????????????? ???????????????????? ??????????"""
        password_name = self.CA_KEY_PASSWORD_NAME if path == self.ca_key_path else self.SERVER_KEY_PASSWORD_NAME
        with open(path, 'wb') as f:
            f.write(self._serialize_private_key(
                key,
                password=self._get_private_key_password(password_name).decode("utf-8")
            ))

    def _build_client_subject(self, client_id: str) -> x509.Name:
        identity = build_client_certificate_identity(client_id)
        return x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Flamix"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"client-{identity}"),
        ])

    def _build_client_san(self, client_id: str) -> x509.SubjectAlternativeName:
        identity = build_client_certificate_identity(client_id)
        return x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(f"{CLIENT_CERT_URI_PREFIX}{identity}"),
            x509.DNSName(f"client-{identity}"),
        ])

    def sign_client_certificate(
        self,
        client_id: str,
        client_public_key: rsa.RSAPublicKey
    ) -> x509.Certificate:
        """
        ?????????????? ?????????????????????? ??????????????????????

        Args:
            client_id: ID ??????????????
            client_public_key: ?????????????????? ???????? ??????????????

        Returns:
            ?????????????????????? ????????????????????
        """
        ca_cert, ca_key = self._load_ca()

        subject = self._build_client_subject(client_id)
        san = self._build_client_san(client_id)

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
        ).add_extension(
            san,
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(client_public_key),
            critical=False,
        ).sign(ca_key, hashes.SHA256())

        return cert

    def generate_client_certificate(self, client_id: str) -> Tuple[x509.Certificate, rsa.RSAPrivateKey, bytes]:
        """
        ?????????????????? ?????????????????????? ?????????????????????? ?? ??????????

        Args:
            client_id: ID ??????????????

        Returns:
            ???????????? (????????????????????, ?????????????????? ????????, CA ???????????????????? ?? PEM ??????????????)
        """
        ca_cert, ca_key = self._load_ca()

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        subject = self._build_client_subject(client_id)
        san = self._build_client_san(client_id)

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
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            san,
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        ).sign(ca_key, hashes.SHA256())

        ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

        return cert, private_key, ca_cert_pem

    def sign_client_csr(
        self,
        client_id: str,
        csr_pem: bytes,
    ) -> Tuple[x509.Certificate, bytes]:
        """Issue a client certificate from a CSR generated on the endpoint."""
        ca_cert, ca_key = self._load_ca()

        csr = x509.load_pem_x509_csr(csr_pem)
        is_valid = getattr(csr, "is_signature_valid", None)
        if callable(is_valid):
            is_valid = is_valid()
        if is_valid is False:
            raise ValueError("CSR signature is invalid")

        cert = x509.CertificateBuilder().subject_name(
            self._build_client_subject(client_id)
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            self._build_client_san(client_id),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        ).sign(ca_key, hashes.SHA256())

        return cert, ca_cert.public_bytes(serialization.Encoding.PEM)

    def get_certificate_info(self) -> dict:
        """
        Получение информации о серверном сертификате
        
        Returns:
            Словарь с информацией о сертификате
        """
        try:
            if not self.server_cert_path.exists():
                return {"error": "Server certificate not found"}
            
            cert, _ = self._load_server_cert()
            
            # Получаем Subject Alternative Names
            san_list = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                san = san_ext.value
                for name in san:
                    if isinstance(name, x509.DNSName):
                        san_list.append(f"DNS:{name.value}")
                    elif isinstance(name, x509.IPAddress):
                        san_list.append(f"IP:{name.value}")
            except x509.ExtensionNotFound:
                san_list.append("No SAN extension")
            
            return {
                "subject": str(cert.subject),
                "issuer": str(cert.issuer),
                "not_valid_before": cert.not_valid_before_utc.isoformat(),
                "not_valid_after": cert.not_valid_after_utc.isoformat(),
                "san": san_list,
                "serial_number": str(cert.serial_number),
            }
        except Exception as e:
            return {"error": str(e)}
