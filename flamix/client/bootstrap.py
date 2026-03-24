"""Bootstrap enrollment flow for first-time client provisioning."""

import json
import logging
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import NameOID

from flamix.client.security import ClientSecurity

logger = logging.getLogger(__name__)

CLIENT_CERT_URI_PREFIX = "urn:flamix:client:"


def _build_enroll_url(config: Dict[str, Any]) -> str:
    bootstrap = config.get("bootstrap") or {}
    enroll_url = bootstrap.get("enroll_url")
    if enroll_url:
        return str(enroll_url)

    server_host = str(config["server_host"])
    web_port = int(bootstrap.get("web_port") or config.get("web_port") or 8080)
    return f"https://{server_host}:{web_port}/api/bootstrap/enroll"


def _build_client_csr(client_id: str, private_key: rsa.RSAPrivateKey) -> bytes:
    client_id = str(client_id)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Flamix Clients"),
                x509.NameAttribute(NameOID.COMMON_NAME, f"client-{client_id}"),
            ]
        )
    ).add_extension(
        x509.SubjectAlternativeName(
            [
                x509.DNSName(f"client-{client_id}"),
                x509.UniformResourceIdentifier(f"{CLIENT_CERT_URI_PREFIX}{client_id}"),
            ]
        ),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM)


def _extract_client_id_from_local_certificate(cert_pem: bytes) -> Optional[str]:
    """Best-effort extraction of client identity from an existing client certificate."""
    cert = x509.load_pem_x509_certificate(cert_pem)

    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
            if uri.startswith(CLIENT_CERT_URI_PREFIX):
                return uri[len(CLIENT_CERT_URI_PREFIX):]
        for dns_name in san.get_values_for_type(x509.DNSName):
            if dns_name.startswith("client-"):
                return dns_name[len("client-"):]
    except x509.ExtensionNotFound:
        pass

    for attribute in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        if attribute.value.startswith("client-"):
            return attribute.value[len("client-"):]
    return None


def ensure_bootstrap_enrollment(
    config: Dict[str, Any],
    base_dir: Path,
    config_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Enroll the client and fetch its long-lived mTLS certificate if needed."""
    client_id = str(config["client_id"])
    cert_dir = base_dir / config.get("cert_dir", "certs")
    security = ClientSecurity(cert_dir, client_id=client_id)

    bootstrap = config.get("bootstrap") or {}
    if security.has_certificates():
        existing_identity = _extract_client_id_from_local_certificate(
            security.client_cert_path.read_bytes()
        )
        if existing_identity == client_id:
            return config
        if bootstrap.get("enabled"):
            logger.warning(
                "Existing client certificate belongs to %s, but config expects %s. Re-enrolling via bootstrap.",
                existing_identity,
                client_id,
            )
        else:
            raise RuntimeError(
                f"Existing client certificate belongs to {existing_identity!r}, "
                f"but config expects {client_id!r}"
            )

    if not bootstrap.get("enabled"):
        raise RuntimeError("Client certificates are missing and bootstrap enrollment is not enabled")

    bootstrap_token = bootstrap.get("token")
    if not bootstrap_token:
        raise RuntimeError("Bootstrap enrollment token is missing")

    if not security.ca_cert_path.exists():
        raise FileNotFoundError(f"Bootstrap CA certificate not found at {security.ca_cert_path}")

    enroll_url = _build_enroll_url(config)
    logger.info("No client certificate found, starting bootstrap enrollment against %s", enroll_url)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr_pem = _build_client_csr(client_id, private_key)

    response = requests.post(
        enroll_url,
        json={
            "client_id": client_id,
            "bootstrap_token": bootstrap_token,
            "csr_pem": csr_pem.decode("utf-8"),
        },
        timeout=(5, 20),
        verify=str(security.ca_cert_path),
    )
    response.raise_for_status()
    payload = response.json()

    client_cert_pem = payload.get("client_cert_pem")
    ca_cert_pem = payload.get("ca_cert_pem")
    if not client_cert_pem or not ca_cert_pem:
        raise RuntimeError("Bootstrap enrollment response is incomplete")

    password = secrets.token_urlsafe(24)
    security.save_generated_client_materials(
        client_id=client_id,
        client_cert_pem=client_cert_pem.encode("utf-8"),
        client_key=private_key,
        ca_cert_pem=ca_cert_pem.encode("utf-8"),
        password=password,
    )

    bootstrap["enabled"] = False
    bootstrap["token"] = None
    bootstrap["enrolled_at"] = datetime.now(timezone.utc).isoformat()
    config["bootstrap"] = bootstrap

    config_path = config_path or (base_dir / "config.json")
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    logger.info("Bootstrap enrollment completed successfully for client %s", client_id)
    return config
