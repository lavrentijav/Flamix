import importlib.util
import io
import json
from pathlib import Path
import zipfile

import keyring
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import HTTPException

from flamix.database.encrypted_db import EncryptedDB
from flamix.server.runtime_config import ServerRuntimeConfig
from flamix.server.client_manager import ClientManager, ClientSession
from flamix.server.key_rotation import KeyRotation
from flamix.server.security import (
    ServerSecurity,
    extract_client_id_from_certificate,
)
from flamix.server.web_api import WebAPI


CLIENT_SECURITY_PATH = (
    Path(__file__).resolve().parents[2] / "client" / "flamix" / "client" / "security.py"
)
_client_security_spec = importlib.util.spec_from_file_location(
    "flamix_client_security",
    CLIENT_SECURITY_PATH,
)
_client_security_module = importlib.util.module_from_spec(_client_security_spec)
assert _client_security_spec.loader is not None
_client_security_spec.loader.exec_module(_client_security_module)
ClientSecurity = _client_security_module.ClientSecurity
CLIENT_KEY_PASSWORD_ENV = _client_security_module.CLIENT_KEY_PASSWORD_ENV


@pytest.fixture(autouse=True)
def in_memory_keyring(monkeypatch):
    store = {}

    def get_password(service_name, key_name):
        return store.get((service_name, key_name))

    def set_password(service_name, key_name, value):
        store[(service_name, key_name)] = value

    monkeypatch.setattr(keyring, "get_password", get_password)
    monkeypatch.setattr(keyring, "set_password", set_password)
    return store


@pytest.fixture
def protected_db(tmp_path):
    db = EncryptedDB(tmp_path / "server.db", use_encryption=True)
    db.initialize()
    return db


def test_client_session_identity_binding_and_no_session_key_persistence(protected_db):
    protected_db.execute_write(
        "INSERT INTO clients (id, name) VALUES (?, ?)",
        ("123", "client-123"),
    )

    manager = ClientManager(protected_db)
    session = ClientSession(
        "temp-session",
        "session-1",
        b"\xAA" * 32,
        certificate_client_id="123",
    )
    session.client_id = "123"
    manager._save_session_to_db(session)

    row = protected_db.execute_one(
        "SELECT session_key, client_id FROM client_sessions WHERE id = ?",
        ("session-1",),
    )
    assert row["client_id"] == "123"
    assert row["session_key"] is None

    mismatched = ClientSession(
        "temp-other",
        "session-2",
        b"\xBB" * 32,
        certificate_client_id="123",
    )
    with pytest.raises(ValueError):
        mismatched.client_id = "999"


def test_initialize_scrubs_legacy_persisted_session_keys(protected_db):
    protected_db.execute_write(
        "INSERT INTO clients (id, name) VALUES (?, ?)",
        ("321", "client-321"),
    )
    protected_db.execute_write(
        """
        INSERT INTO client_sessions (id, client_id, session_key, expires_at, last_activity)
        VALUES (?, ?, ?, ?, ?)
        """,
        ("legacy-session", "321", "plaintext-session-key", "2099-01-01T00:00:00Z", "2099-01-01T00:00:00Z"),
    )

    protected_db.initialize()

    row = protected_db.execute_one(
        "SELECT session_key FROM client_sessions WHERE id = ?",
        ("legacy-session",),
    )
    assert row["session_key"] is None


@pytest.mark.asyncio
async def test_key_rotation_wraps_old_keys_before_storing(protected_db):
    keyring.set_password(KeyRotation.SERVICE_NAME, KeyRotation.KEY_NAME, "legacy-active-key")

    rotation = KeyRotation(protected_db, rotation_hours=1)
    assert await rotation.rotate_key() is True

    row = protected_db.execute_one("SELECT id, key_data FROM encryption_keys", ())
    assert row is not None
    assert row["key_data"].startswith(protected_db.SECRET_PREFIX)
    assert row["key_data"] != "legacy-active-key"
    assert rotation.get_old_key(row["id"]) == "legacy-active-key"


def test_private_keys_are_encrypted_and_client_identity_is_embedded(tmp_path):
    security = ServerSecurity(tmp_path)
    security.generate_ca()
    security.generate_server_cert(hostname="localhost", server_ip="127.0.0.1")

    assert b"ENCRYPTED PRIVATE KEY" in (tmp_path / "ca.key").read_bytes()
    assert b"ENCRYPTED PRIVATE KEY" in (tmp_path / "server.key").read_bytes()

    cert, private_key, ca_cert_pem = security.generate_client_certificate("42")
    assert extract_client_id_from_certificate(cert) == "42"

    export_password = security.create_client_key_password()
    encrypted_client_key = security.export_client_private_key(private_key, export_password)
    assert b"ENCRYPTED PRIVATE KEY" in encrypted_client_key
    assert ca_cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")


def test_client_security_loads_encrypted_client_key_from_env(tmp_path, monkeypatch):
    security = ServerSecurity(tmp_path / "server-certs")
    security.generate_ca()
    cert, private_key, ca_cert_pem = security.generate_client_certificate("77")
    export_password = security.create_client_key_password()
    encrypted_client_key = security.export_client_private_key(private_key, export_password)

    client_cert_dir = tmp_path / "client-certs"
    client_cert_dir.mkdir()
    (client_cert_dir / "client.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (client_cert_dir / "client.key").write_bytes(encrypted_client_key)
    (client_cert_dir / "ca.crt").write_bytes(ca_cert_pem)

    monkeypatch.setenv(CLIENT_KEY_PASSWORD_ENV, export_password)
    context = ClientSecurity(client_cert_dir).create_ssl_context(verify_ssl=True)
    assert context.verify_mode is not None

    monkeypatch.delenv(CLIENT_KEY_PASSWORD_ENV)
    with pytest.raises(Exception):
        ClientSecurity(client_cert_dir).create_ssl_context(verify_ssl=True)


def test_client_security_loads_encrypted_client_key_from_keyring(tmp_path):
    security = ServerSecurity(tmp_path / "server-certs")
    security.generate_ca()
    cert, private_key, ca_cert_pem = security.generate_client_certificate("78")

    client_cert_dir = tmp_path / "client-certs"
    client_security = ClientSecurity(client_cert_dir, client_id="78")
    client_security.save_generated_client_materials(
        client_id="78",
        client_cert_pem=cert.public_bytes(serialization.Encoding.PEM),
        client_key=private_key,
        ca_cert_pem=ca_cert_pem,
        password="bootstrap-password-78",
    )

    context = ClientSecurity(client_cert_dir, client_id="78").create_ssl_context(verify_ssl=True)
    assert context.verify_mode is not None


def test_generated_client_package_uses_plugin_manager_bootstrap(tmp_path):
    security = ServerSecurity(tmp_path / "server-certs")
    security.generate_ca()
    cert, private_key, ca_cert_pem = security.generate_client_certificate("88")
    export_password = security.create_client_key_password()
    encrypted_client_key = security.export_client_private_key(private_key, export_password)

    web_api = object.__new__(WebAPI)
    zip_buffer = WebAPI._create_client_zip(
        web_api,
        client_id="88",
        config={
            "client_id": "88",
            "server_host": "127.0.0.1",
            "server_port": 8443,
            "cert_dir": "certs",
        },
        client_cert=cert,
        client_key_pem=encrypted_client_key,
        ca_cert_pem=ca_cert_pem,
    )

    with zipfile.ZipFile(io.BytesIO(zip_buffer.getvalue()), "r") as archive:
        run_script = archive.read("run.py").decode("utf-8")

    assert "RuleConverter(None)" not in run_script
    assert "from flamix.client.plugins.manager import PluginManager" in run_script
    assert "from flamix.client.bootstrap import ensure_bootstrap_enrollment" in run_script
    assert "plugin_manager=plugin_manager" in run_script
    assert "rule_converter = rule_converter_cls(plugin_manager)" in run_script
    assert 'logger.info(f"Active firewall plugin: {active_plugin.plugin_id}")' in run_script


def test_bootstrap_token_consumption_and_csr_signing(protected_db, tmp_path):
    security = ServerSecurity(tmp_path / "server-certs")
    security.generate_ca()

    protected_db.execute_write(
        "INSERT INTO clients (id, name) VALUES (?, ?)",
        ("501", "client-501"),
    )

    web_api = object.__new__(WebAPI)
    web_api.db = protected_db
    web_api.security = security

    bootstrap = WebAPI._create_bootstrap_token(web_api, "501", expires_in_hours=1)
    assert bootstrap["token"]

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client-501")])
    ).sign(private_key, hashes.SHA256())

    consumed = WebAPI._consume_bootstrap_token(web_api, "501", bootstrap["token"])
    assert consumed["used_at"]

    cert, ca_cert_pem = security.sign_client_csr("501", csr.public_bytes(serialization.Encoding.PEM))
    assert extract_client_id_from_certificate(cert) == "501"
    assert ca_cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")

    with pytest.raises(HTTPException):
        WebAPI._consume_bootstrap_token(web_api, "501", bootstrap["token"])


def test_bootstrap_client_package_contains_tokenized_config(tmp_path):
    security = ServerSecurity(tmp_path / "server-certs")
    security.generate_ca()

    web_api = object.__new__(WebAPI)
    web_api.security = security

    zip_buffer = WebAPI._create_bootstrap_client_zip(
        web_api,
        client_id="91",
        config={
            "client_id": "91",
            "server_host": "127.0.0.1",
            "server_port": 8443,
            "web_port": 8080,
            "cert_dir": "certs",
            "bootstrap": {
                "enabled": True,
                "token": "demo-token",
                "enroll_url": "https://127.0.0.1:8080/api/bootstrap/enroll",
            },
        },
        ca_cert_pem=security.ca_cert_path.read_bytes(),
    )

    with zipfile.ZipFile(io.BytesIO(zip_buffer.getvalue()), "r") as archive:
        config = json.loads(archive.read("config.json").decode("utf-8"))
        run_script = archive.read("run.py").decode("utf-8")

    assert config["bootstrap"]["enabled"] is True
    assert config["bootstrap"]["token"] == "demo-token"
    assert "ensure_bootstrap_enrollment" in run_script


def test_gui_connection_bundle_contains_private_ca_bootstrap(tmp_path):
    security = ServerSecurity(tmp_path / "server-certs")
    security.generate_ca()
    security.generate_server_cert(hostname="localhost", server_ip="127.0.0.1")

    web_api = object.__new__(WebAPI)
    web_api.security = security
    web_api.server_instance = None
    web_api.runtime_config = ServerRuntimeConfig(
        server_host="0.0.0.0",
        server_port=8443,
        web_enabled=True,
        web_host="127.0.0.1",
        web_port=8080,
        db_path=tmp_path / "server.db",
        cert_dir=tmp_path / "server-certs",
    )

    bundle_path = WebAPI.ensure_gui_connection_bundle(web_api, force=True)
    assert bundle_path.exists()

    with zipfile.ZipFile(bundle_path, "r") as archive:
        settings = json.loads(archive.read("gui-settings.json").decode("utf-8"))
        ca_cert = archive.read("trust/ca.crt")
        server_cert = archive.read("trust/server.crt")

    assert settings["connection"]["verify_ssl"] is True
    assert settings["connection"]["trust_store_mode"] == "custom"
    assert settings["connection"]["ca_cert_path"] == "trust/ca.crt"
    assert settings["connection"]["server_url"] == "https://127.0.0.1:8080"
    assert ca_cert.startswith(b"-----BEGIN CERTIFICATE-----")
    assert server_cert.startswith(b"-----BEGIN CERTIFICATE-----")
