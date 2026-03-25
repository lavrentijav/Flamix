"""FastAPI РІРµР±-РёРЅС‚РµСЂС„РµР№СЃ РґР»СЏ СЃРµСЂРІРµСЂР°"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import HTMLResponse, Response, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional
from pathlib import Path
from pydantic import BaseModel
import logging
import sys
import asyncio
import zipfile
import json
import tempfile
import io
import socket
import hashlib
import secrets
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization

from flamix.server.rule_manager import RuleManager
from flamix.server.rule_authorization import RuleAuthorization
from flamix.server.traffic_analytics import TrafficAnalytics
from flamix.server.runtime_config import ServerRuntimeConfig
from flamix.database.encrypted_db import EncryptedDB
from flamix.common.rule_format import FirewallRule

logger = logging.getLogger(__name__)


def _suppress_connection_reset_error():
    """РџРѕРґР°РІР»СЏРµС‚ РѕС€РёР±РєРё ConnectionResetError РІ asyncio callback'Р°С… РЅР° Windows"""
    def exception_handler(loop, context):
        """РћР±СЂР°Р±РѕС‚С‡РёРє РёСЃРєР»СЋС‡РµРЅРёР№ РґР»СЏ asyncio event loop"""
        exception = context.get('exception')
        if isinstance(exception, ConnectionResetError):
            # РРіРЅРѕСЂРёСЂСѓРµРј РѕС€РёР±РєРё СЂР°Р·СЂС‹РІР° СЃРѕРµРґРёРЅРµРЅРёСЏ - СЌС‚Рѕ РЅРѕСЂРјР°Р»СЊРЅРѕРµ РїРѕРІРµРґРµРЅРёРµ
            # РєРѕРіРґР° РєР»РёРµРЅС‚ Р·Р°РєСЂС‹РІР°РµС‚ СЃРѕРµРґРёРЅРµРЅРёРµ РґРѕ Р·Р°РІРµСЂС€РµРЅРёСЏ РѕР±СЂР°Р±РѕС‚РєРё
            # Р›РѕРіРёСЂСѓРµРј С‚РѕР»СЊРєРѕ РЅР° СѓСЂРѕРІРЅРµ DEBUG, С‡С‚РѕР±С‹ РЅРµ Р·Р°СЃРѕСЂСЏС‚СЊ Р»РѕРіРё
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Connection reset by peer (normal): {context.get('message', '')}")
            return
        
        # Р”Р»СЏ РґСЂСѓРіРёС… РёСЃРєР»СЋС‡РµРЅРёР№ РёСЃРїРѕР»СЊР·СѓРµРј СЃС‚Р°РЅРґР°СЂС‚РЅСѓСЋ РѕР±СЂР°Р±РѕС‚РєСѓ
        try:
            if hasattr(loop, 'default_exception_handler'):
                loop.default_exception_handler(context)
            else:
                # Р•СЃР»Рё РЅРµС‚ default_exception_handler, Р»РѕРіРёСЂСѓРµРј РѕС€РёР±РєСѓ
                logger.error(f"Unhandled exception in asyncio: {context.get('message', '')}", 
                            exc_info=exception)
        except Exception:
            # Р•СЃР»Рё СЃС‚Р°РЅРґР°СЂС‚РЅС‹Р№ РѕР±СЂР°Р±РѕС‚С‡РёРє РЅРµ СЂР°Р±РѕС‚Р°РµС‚, РїСЂРѕСЃС‚Рѕ Р»РѕРіРёСЂСѓРµРј
            logger.error(f"Unhandled exception in asyncio: {context.get('message', '')}", 
                        exc_info=exception)
    
    # РЈСЃС‚Р°РЅР°РІР»РёРІР°РµРј РѕР±СЂР°Р±РѕС‚С‡РёРє РґР»СЏ С‚РµРєСѓС‰РµРіРѕ event loop, РµСЃР»Рё РѕРЅ СЃСѓС‰РµСЃС‚РІСѓРµС‚
    # Р­С‚Рѕ Р±СѓРґРµС‚ СЂР°Р±РѕС‚Р°С‚СЊ РєРѕРіРґР° uvicorn СЃРѕР·РґР°СЃС‚ СЃРІРѕР№ event loop
    try:
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(exception_handler)
    except RuntimeError:
        # Р•СЃР»Рё РЅРµС‚ Р·Р°РїСѓС‰РµРЅРЅРѕРіРѕ event loop, РѕР±СЂР°Р±РѕС‚С‡РёРє Р±СѓРґРµС‚ СѓСЃС‚Р°РЅРѕРІР»РµРЅ РїРѕР·Р¶Рµ
        # С‡РµСЂРµР· uvicorn's event loop
        pass


class WebAPI:
    """Р’РµР±-РёРЅС‚РµСЂС„РµР№СЃ FastAPI"""

    def __init__(
        self,
        rule_manager: RuleManager,
        rule_authorization: RuleAuthorization,
        db: EncryptedDB,
        host: str = "0.0.0.0",
        port: int = 8080,
        security=None,
        server_host: str = "0.0.0.0",
        server_port: int = 8443,
        cert_dir: Optional[Path] = None,
        runtime_config: Optional[ServerRuntimeConfig] = None,
        server_instance=None
    ):
        """
        РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ РІРµР±-РёРЅС‚РµСЂС„РµР№СЃР°

        Args:
            rule_manager: РњРµРЅРµРґР¶РµСЂ РїСЂР°РІРёР»
            rule_authorization: РЎРёСЃС‚РµРјР° Р°РІС‚РѕСЂРёР·Р°С†РёРё
            db: Р‘Р°Р·Р° РґР°РЅРЅС‹С…
            host: РҐРѕСЃС‚ РґР»СЏ РІРµР±-СЃРµСЂРІРµСЂР°
            port: РџРѕСЂС‚ РґР»СЏ РІРµР±-СЃРµСЂРІРµСЂР°
            security: РћР±СЉРµРєС‚ ServerSecurity РґР»СЏ РіРµРЅРµСЂР°С†РёРё СЃРµСЂС‚РёС„РёРєР°С‚РѕРІ
            server_host: РҐРѕСЃС‚ СЃРµСЂРІРµСЂР° РґР»СЏ РєР»РёРµРЅС‚СЃРєРёС… РїРѕРґРєР»СЋС‡РµРЅРёР№
            server_port: РџРѕСЂС‚ СЃРµСЂРІРµСЂР° РґР»СЏ РєР»РёРµРЅС‚СЃРєРёС… РїРѕРґРєР»СЋС‡РµРЅРёР№
            cert_dir: Р”РёСЂРµРєС‚РѕСЂРёСЏ СЃ СЃРµСЂС‚РёС„РёРєР°С‚Р°РјРё
        """
        self.rule_manager = rule_manager
        self.rule_authorization = rule_authorization
        self.db = db
        self.traffic_analytics = TrafficAnalytics(db)
        self.host = host
        self.port = port
        self.security = security
        self.server_host = server_host
        self.server_port = server_port
        self.cert_dir = cert_dir
        db_path = Path(getattr(db, "db_path", Path("data/server.db")))
        self.runtime_config = runtime_config or ServerRuntimeConfig(
            server_host=server_host,
            server_port=server_port,
            web_enabled=True,
            web_host=host,
            web_port=port,
            db_path=db_path,
            cert_dir=Path(cert_dir or "certs"),
        )
        self.server_instance = server_instance  # РЎСЃС‹Р»РєР° РЅР° FlamixServer РґР»СЏ РѕС‚РїСЂР°РІРєРё РєРѕРЅС„РёРіРѕРІ
        self.app = FastAPI(title="Flamix Server API")

        # РќР°СЃС‚СЂРѕР№РєР° CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Р’ РїСЂРѕРґР°РєС€РµРЅРµ РґРѕР»Р¶РЅРѕ Р±С‹С‚СЊ РѕРіСЂР°РЅРёС‡РµРЅРѕ
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # РЈСЃС‚Р°РЅР°РІР»РёРІР°РµРј РѕР±СЂР°Р±РѕС‚С‡РёРє РёСЃРєР»СЋС‡РµРЅРёР№ РїСЂРё СЃС‚Р°СЂС‚Рµ РїСЂРёР»РѕР¶РµРЅРёСЏ
        @self.app.on_event("startup")
        async def setup_exception_handler():
            """РЈСЃС‚Р°РЅР°РІР»РёРІР°РµС‚ РѕР±СЂР°Р±РѕС‚С‡РёРє РёСЃРєР»СЋС‡РµРЅРёР№ РґР»СЏ asyncio event loop"""
            try:
                loop = asyncio.get_running_loop()
                def exception_handler(loop, context):
                    exception = context.get('exception')
                    if isinstance(exception, ConnectionResetError):
                        # РРіРЅРѕСЂРёСЂСѓРµРј РѕС€РёР±РєРё СЂР°Р·СЂС‹РІР° СЃРѕРµРґРёРЅРµРЅРёСЏ
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug(f"Connection reset by peer (normal): {context.get('message', '')}")
                        return
                    # Р”Р»СЏ РґСЂСѓРіРёС… РёСЃРєР»СЋС‡РµРЅРёР№ РёСЃРїРѕР»СЊР·СѓРµРј СЃС‚Р°РЅРґР°СЂС‚РЅСѓСЋ РѕР±СЂР°Р±РѕС‚РєСѓ
                    try:
                        if hasattr(loop, 'default_exception_handler'):
                            loop.default_exception_handler(context)
                        else:
                            logger.error(f"Unhandled exception in asyncio: {context.get('message', '')}", 
                                        exc_info=exception)
                    except Exception:
                        logger.error(f"Unhandled exception in asyncio: {context.get('message', '')}", 
                                    exc_info=exception)
                
                loop.set_exception_handler(exception_handler)
            except RuntimeError:
                pass

        self._setup_routes()

    def _get_runtime_config(self) -> ServerRuntimeConfig:
        if self.server_instance and getattr(self.server_instance, "runtime_config", None):
            return self.server_instance.runtime_config
        return self.runtime_config

    def _get_effective_server_info(self) -> Dict[str, Any]:
        if self.server_instance and hasattr(self.server_instance, "get_server_info"):
            try:
                return self.server_instance.get_server_info()
            except Exception as exc:
                logger.warning("Falling back to local server info snapshot: %s", exc)

        runtime_config = self._get_runtime_config()
        return {
            "name": "Flamix Server",
            "running": False,
            "listen": {
                "host": runtime_config.server_host,
                "port": runtime_config.server_port,
                "advertised_host": runtime_config.server_host,
            },
            "web": {
                "enabled": runtime_config.web_enabled,
                "host": runtime_config.web_host,
                "port": runtime_config.web_port,
            },
            "paths": {
                "db_path": str(runtime_config.db_path),
                "cert_dir": str(runtime_config.cert_dir),
                "log_dir": str(runtime_config.log_dir),
                "config_path": str(runtime_config.config_path),
            },
            "features": {
                "require_client_cert": runtime_config.require_client_cert,
                "persist_runtime_config": runtime_config.persist_runtime_config,
            },
            "runtime": runtime_config.to_public_dict(),
            "bootstrap": {
                "gui_bundle_path": str(self._get_gui_bundle_path()),
            },
        }

    def _build_gui_server_url(self) -> str:
        runtime_config = self._get_runtime_config()
        host = runtime_config.web_host
        if host in {"0.0.0.0", "::", ""}:
            if self.server_instance and hasattr(self.server_instance, "_detect_server_ip"):
                host = self.server_instance._detect_server_ip()
            else:
                host = "127.0.0.1"
        return f"https://{host}:{runtime_config.web_port}"

    def _get_gui_bundle_path(self) -> Path:
        return Path(self._get_runtime_config().cert_dir) / "flamix-gui-connection.zip"

    def _create_gui_connection_zip(self) -> io.BytesIO:
        if not self.security:
            raise RuntimeError("Security module not initialized")

        ca_cert_pem = self.security.ca_cert_path.read_bytes()
        server_cert_pem = self.security.server_cert_path.read_bytes()
        server_url = self._build_gui_server_url()
        gui_settings = {
            "connection": {
                "server_url": server_url,
                "verify_ssl": True,
                "trust_store_mode": "custom",
                "ca_cert_path": "trust/ca.crt",
                "timeout_connect": 3.05,
                "timeout_read": 10.0,
                "auto_connect": False,
            }
        }
        metadata = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "server_url": server_url,
            "server_info": self._get_effective_server_info(),
        }
        readme = (
            "Flamix GUI trust bundle\n\n"
            "1. Unpack this archive on the GUI workstation.\n"
            "2. Import gui-settings.json in the GUI Settings tab.\n"
            "3. The imported settings will enable TLS verification and point to trust/ca.crt.\n"
            "4. Keep trust/ca.crt and trust/server.crt together with gui-settings.json.\n"
        )

        bundle = io.BytesIO()
        with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as zipf:
            zipf.writestr("trust/ca.crt", ca_cert_pem)
            zipf.writestr("trust/server.crt", server_cert_pem)
            zipf.writestr("gui-settings.json", json.dumps(gui_settings, indent=2, ensure_ascii=False))
            zipf.writestr("server-info.json", json.dumps(metadata, indent=2, ensure_ascii=False, default=str))
            zipf.writestr("README.txt", readme)

        bundle.seek(0)
        return bundle

    def ensure_gui_connection_bundle(self, force: bool = False) -> Path:
        bundle_path = self._get_gui_bundle_path()
        if bundle_path.exists() and not force:
            return bundle_path

        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        bundle_path.write_bytes(self._create_gui_connection_zip().getvalue())
        logger.info("Prepared GUI trust bundle at %s", bundle_path)
        return bundle_path

    def _get_effective_health(self) -> Dict[str, Any]:
        if self.server_instance and hasattr(self.server_instance, "get_health_report"):
            try:
                return self.server_instance.get_health_report()
            except Exception as exc:
                logger.warning("Falling back to local health snapshot: %s", exc)

        runtime_config = self._get_runtime_config()
        return {
            "status": "unknown",
            "checks": {
                "server": {"ok": False, "host": runtime_config.server_host, "port": runtime_config.server_port},
                "database": {"ok": False, "path": str(runtime_config.db_path)},
                "certificates": {"ok": False},
                "web": {"ok": True if not runtime_config.web_enabled else runtime_config.web_enabled, "enabled": runtime_config.web_enabled, "host": runtime_config.web_host, "port": runtime_config.web_port},
                "runtime": {
                    "ok": True,
                    "periodic_task_interval_seconds": runtime_config.periodic_task_interval_seconds,
                    "session_timeout_seconds": runtime_config.session_timeout_seconds,
                },
            },
            "config": runtime_config.to_public_dict(),
        }

    def _get_persisted_runtime_config(self) -> Optional[Dict[str, Any]]:
        runtime_config = self._get_runtime_config()
        config_path = runtime_config.config_path
        if not config_path.exists():
            return None
        return ServerRuntimeConfig.from_file(config_path, base=runtime_config).to_public_dict()

    def _update_runtime_config(self, patch: Dict[str, Any], persist: bool = True) -> Dict[str, Any]:
        if self.server_instance and hasattr(self.server_instance, "update_runtime_config"):
            return self.server_instance.update_runtime_config(patch, persist=persist)

        updated_config, changes = self.runtime_config.with_updates(patch)
        restart_required_fields = []
        applied_live = []
        mutable_fields = {
            "periodic_task_interval_seconds",
            "session_timeout_seconds",
            "client_log_retention_days",
            "analytics_retention_days",
            "traffic_stats_retention_days",
            "system_status_retention_days",
            "persist_runtime_config",
            "log_level",
        }

        for field_name in changes:
            if field_name in mutable_fields:
                setattr(self.runtime_config, field_name, getattr(updated_config, field_name))
                applied_live.append(field_name)
            else:
                restart_required_fields.append(field_name)

        if "config_path" in changes:
            self.runtime_config.config_path = updated_config.config_path

        if persist:
            updated_config.save(updated_config.config_path)

        return {
            "config": self.runtime_config.to_public_dict(),
            "stored_config": self._get_persisted_runtime_config(),
            "changed_fields": list(changes.keys()),
            "applied_live": applied_live,
            "restart_required": bool(restart_required_fields),
            "restart_required_fields": restart_required_fields,
        }

    @staticmethod
    def _hash_bootstrap_token(token: str) -> str:
        """Hash a bootstrap token before storing it in SQLite."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _create_bootstrap_token(self, client_id: str, expires_in_hours: int = 24) -> Dict[str, str]:
        """Create and persist a one-time bootstrap token."""
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.utcnow() + timedelta(hours=expires_in_hours)).isoformat() + "Z"
        self.db.execute_write(
            """
            INSERT INTO client_bootstrap_tokens (client_id, token_hash, expires_at, metadata)
            VALUES (?, ?, ?, ?)
            """,
            (
                str(client_id),
                self._hash_bootstrap_token(token),
                expires_at,
                json.dumps({"purpose": "bootstrap-enrollment"}),
            ),
        )
        return {"token": token, "expires_at": expires_at}

    def _consume_bootstrap_token(self, client_id: str, token: str) -> Dict[str, Any]:
        """Validate and consume a one-time bootstrap token."""
        row = self.db.execute_one(
            """
            SELECT id, client_id, expires_at, used_at
            FROM client_bootstrap_tokens
            WHERE client_id = ? AND token_hash = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (str(client_id), self._hash_bootstrap_token(token)),
        )
        if not row:
            raise HTTPException(status_code=403, detail="Invalid bootstrap token")
        if row.get("used_at"):
            raise HTTPException(status_code=403, detail="Bootstrap token has already been used")

        expires_at = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
        if expires_at < datetime.utcnow().replace(tzinfo=expires_at.tzinfo):
            raise HTTPException(status_code=403, detail="Bootstrap token has expired")

        used_at = datetime.utcnow().isoformat() + "Z"
        self.db.execute_write(
            "UPDATE client_bootstrap_tokens SET used_at = ? WHERE id = ?",
            (used_at, row["id"]),
        )
        row["used_at"] = used_at
        return row

    def _build_client_config(self, client_id: str, server_ip: str) -> Dict[str, Any]:
        """Build the client runtime configuration shipped in provisioning packages."""
        return {
            "client_id": client_id,
            "server_host": server_ip,
            "server_port": self.server_port,
            "web_port": self.port,
            "cert_dir": "certs",
            "verify_ssl": True,
            "sync_interval": 30,
            "monitor_interval": 10,
            "analytics_enabled": True,
            "analytics_interval": 5,
            "traffic_collection_interval": 5,
            "config_sync_interval": 300,
            "font": "default",
            "font_size": 13,
            "ui_theme": "default",
        }

    def _build_bootstrap_enroll_url(self, advertised_server_host: str) -> str:
        """Build an enrollment URL that is reachable from the client node."""
        runtime_config = self.runtime_config
        web_host = str(runtime_config.web_host or "").strip()
        advertised_server_host = str(advertised_server_host or "").strip() or "127.0.0.1"

        if web_host in {"", "0.0.0.0", "::"}:
            enroll_host = advertised_server_host
        elif web_host in {"127.0.0.1", "localhost", "::1"}:
            if advertised_server_host in {"127.0.0.1", "localhost", "::1"}:
                enroll_host = "127.0.0.1"
            else:
                enroll_host = advertised_server_host
        else:
            enroll_host = web_host

        return f"https://{enroll_host}:{runtime_config.web_port}/api/bootstrap/enroll"

    def _create_bootstrap_client_zip(
        self,
        client_id: str,
        config: dict,
        ca_cert_pem: bytes
    ) -> bytes:
        """Create a bootstrap package that enrolls for mTLS on first launch."""
        import os

        zip_buffer = io.BytesIO()
        client_modules_path = None
        current_file = Path(__file__)
        project_root = current_file.parents[3]
        possible_paths = [
            project_root / "client" / "flamix",
            project_root.parent / "client" / "flamix",
            Path("client") / "flamix",
            Path("../client/flamix"),
        ]
        for path in possible_paths:
            abs_path = path.resolve() if path.is_absolute() else (current_file.parent / path).resolve()
            if abs_path.exists() and (abs_path / "client").exists() and (abs_path / "common").exists():
                client_modules_path = abs_path
                break

        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.writestr("config.json", json.dumps(config, indent=2))
            zipf.writestr("certs/ca.crt", ca_cert_pem)

            run_script_candidates = [
                project_root / "client" / "run.py",
                project_root.parent / "client" / "run.py",
                Path("client") / "run.py",
                Path("../client/run.py"),
            ]
            for candidate in run_script_candidates:
                run_script_path = candidate.resolve() if candidate.is_absolute() else (current_file.parent / candidate).resolve()
                if run_script_path.exists():
                    zipf.writestr("run.py", run_script_path.read_text(encoding="utf-8"))
                    break

            requirements_candidates = [
                project_root / "client" / "requirements.txt",
                project_root.parent / "client" / "requirements.txt",
                Path("client") / "requirements.txt",
                Path("../client/requirements.txt"),
            ]
            for candidate in requirements_candidates:
                requirements_path = candidate.resolve() if candidate.is_absolute() else (current_file.parent / candidate).resolve()
                if requirements_path.exists():
                    zipf.writestr("requirements.txt", requirements_path.read_text(encoding="utf-8"))
                    break

            if client_modules_path:
                for root, dirs, files in os.walk(client_modules_path):
                    dirs[:] = [d for d in dirs if d != '__pycache__']
                    for file in files:
                        if file.endswith('.py'):
                            file_path = Path(root) / file
                            rel_path = file_path.relative_to(client_modules_path)
                            zipf.writestr(f"flamix/{rel_path}", file_path.read_bytes())

            zipf.writestr(
                "README.md",
                (
                    f"# Flamix Client Bootstrap Package - {client_id}\n\n"
                    "Run `python run.py` after installing dependencies. "
                    "On first launch the client will authenticate with its one-time bootstrap token, "
                    "generate a local private key, request a signed certificate, and then continue using mTLS.\n"
                ),
            )

        zip_buffer.seek(0)
        return zip_buffer

    def _create_client_zip(
        self,
        client_id: str,
        config: dict,
        client_cert,
        client_key_pem: bytes,
        ca_cert_pem: bytes
    ) -> bytes:
        """???????????????? ZIP ???????????? ?????? ??????????????"""
        from cryptography.hazmat.primitives import serialization
        import os

        zip_buffer = io.BytesIO()
        
        # РџСѓС‚СЊ Рє РјРѕРґСѓР»СЏРј РєР»РёРµРЅС‚Р° (РµСЃР»Рё РѕРЅРё РґРѕСЃС‚СѓРїРЅС‹)
        client_modules_path = None
        # РџС‹С‚Р°РµРјСЃСЏ РЅР°Р№С‚Рё РјРѕРґСѓР»Рё РєР»РёРµРЅС‚Р° РІ СЂР°Р·Р»РёС‡РЅС‹С… РјРµСЃС‚Р°С…
        current_file = Path(__file__)
        # РћС‚ server/flamix/server/web_api.py РёРґРµРј РІРІРµСЂС… РґРѕ РєРѕСЂРЅСЏ РїСЂРѕРµРєС‚Р°
        project_root = current_file.parents[3]
        possible_paths = [
            project_root / "client" / "flamix",  # Р•СЃР»Рё client/ СЂСЏРґРѕРј СЃ server/
            project_root.parent / "client" / "flamix",  # Р•СЃР»Рё РЅР° СѓСЂРѕРІРµРЅСЊ РІС‹С€Рµ
            Path("client") / "flamix",  # РћС‚РЅРѕСЃРёС‚РµР»СЊРЅС‹Р№ РїСѓС‚СЊ
            Path("../client/flamix"),  # РћС‚РЅРѕСЃРёС‚РµР»СЊРЅС‹Р№ РїСѓС‚СЊ РІРІРµСЂС…
        ]
        for path in possible_paths:
            abs_path = path.resolve() if path.is_absolute() else (current_file.parent / path).resolve()
            if abs_path.exists() and (abs_path / "client").exists() and (abs_path / "common").exists():
                client_modules_path = abs_path
                logger.info(f"Found client modules at: {client_modules_path}")
                break
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # РљРѕРЅС„РёРі
            zipf.writestr("config.json", json.dumps(config, indent=2))
            
            # РЎРµСЂС‚РёС„РёРєР°С‚С‹
            zipf.writestr("certs/ca.crt", ca_cert_pem)
            zipf.writestr(
                "certs/client.crt",
                client_cert.public_bytes(serialization.Encoding.PEM)
            )
            zipf.writestr(
                "certs/client.key",
                client_key_pem
            )
            
            # РЎРєСЂРёРїС‚ Р·Р°РїСѓСЃРєР°
            run_script = '''#!/usr/bin/env python3
"""Client entry point for Flamix."""

import sys
import json
import asyncio
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

logger = logging.getLogger(__name__)


def build_runtime_components(
    config,
    base_dir,
    flamix_client_cls,
    rule_sync_cls,
    rule_converter_cls,
    rule_monitor_cls,
    analytics_collector_cls,
    plugin_manager_cls,
):
    """Create runtime components with a shared plugin manager."""
    cert_dir = base_dir / config.get("cert_dir", "certs")
    plugin_manager = plugin_manager_cls(base_dir)
    client = flamix_client_cls(
        client_id=config["client_id"],
        server_host=config["server_host"],
        server_port=config["server_port"],
        cert_dir=cert_dir,
        plugin_manager=plugin_manager,
    )
    rule_converter = rule_converter_cls(plugin_manager)
    rule_sync = rule_sync_cls(client, rule_converter, config.get("sync_interval", 30))
    rule_monitor = rule_monitor_cls(client, rule_converter, config.get("monitor_interval", 10))
    analytics_collector = analytics_collector_cls(
        client,
        config.get("analytics_enabled", False),
        config.get("analytics_interval", 60),
    )

    return {
        "plugin_manager": plugin_manager,
        "client": client,
        "rule_converter": rule_converter,
        "rule_sync": rule_sync,
        "rule_monitor": rule_monitor,
        "analytics_collector": analytics_collector,
    }


async def main():
    """Start Flamix client."""
    config_path = Path(__file__).parent / "config.json"
    if not config_path.exists():
        logger.error(f"Config file not found: {config_path}")
        sys.exit(1)

    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)

    logger.info("=" * 60)
    logger.info("Starting Flamix Client")
    logger.info(f"Client ID: {config['client_id']}")
    logger.info(f"Server: {config['server_host']}:{config['server_port']}")
    logger.info("=" * 60)

    base_dir = Path(__file__).parent
    sys.path.insert(0, str(base_dir))

    try:
        from flamix.client.client import FlamixClient
        from flamix.client.bootstrap import ensure_bootstrap_enrollment
        from flamix.client.rule_sync import RuleSync
        from flamix.client.rule_converter import RuleConverter
        from flamix.client.rule_monitor import RuleMonitor
        from flamix.client.analytics_collector import AnalyticsCollector
        from flamix.client.plugins.manager import PluginManager
    except ImportError as e:
        logger.error(f"Failed to import client modules: {e}")
        logger.error("Make sure you have:")
        logger.error("  1. Installed dependencies: pip install -r requirements.txt")
        logger.error("  2. Copied flamix/ directory from client branch if modules are not in archive")
        sys.exit(1)

    try:
        config = ensure_bootstrap_enrollment(config, base_dir, config_path=config_path)
    except Exception as e:
        logger.error(f"Bootstrap enrollment failed: {e}", exc_info=True)
        sys.exit(1)

    runtime = build_runtime_components(
        config,
        base_dir,
        FlamixClient,
        RuleSync,
        RuleConverter,
        RuleMonitor,
        AnalyticsCollector,
        PluginManager,
    )
    plugin_manager = runtime["plugin_manager"]
    client = runtime["client"]
    rule_sync = runtime["rule_sync"]
    rule_monitor = runtime["rule_monitor"]
    analytics_collector = runtime["analytics_collector"]

    active_plugin = plugin_manager.get_active_plugin()
    if active_plugin:
        logger.info(f"Active firewall plugin: {active_plugin.plugin_id}")
    else:
        logger.warning("No active firewall plugin available at startup")

    logger.info("Connecting to server...")
    if not await client.connect():
        logger.error("Failed to connect to server")
        sys.exit(1)

    logger.info("Connected to server successfully")

    try:
        logger.info("Performing initial rule sync...")
        rules = await rule_sync.sync()
        logger.info(f"Synced {len(rules)} rules from server")

        rule_monitor.initialize_checksums(rules)

        await rule_sync.start()
        await rule_monitor.start()
        await analytics_collector.start()

        logger.info("Client is running. Press Ctrl+C to stop.")

        while client.connected:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
    except Exception as e:
        logger.error(f"Client error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        await rule_sync.stop()
        await rule_monitor.stop()
        await analytics_collector.stop()

        await client.disconnect()
        logger.info("Client stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutdown complete")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)'''
            zipf.writestr("run.py", run_script)
            
            # requirements.txt
            requirements = '''# Core dependencies
pydantic>=2.0.0
cryptography>=41.0.0

# Security
keyring>=24.2.0

# Utilities
semantic-version>=2.10.0
netaddr>=0.8.0
psutil>=5.9.0
watchdog>=3.0.0

# Development
pytest>=7.4.0
pytest-asyncio>=0.21.0
'''
            zipf.writestr("requirements.txt", requirements)
            
            # РљРѕРїРёСЂСѓРµРј РјРѕРґСѓР»Рё РєР»РёРµРЅС‚Р° РµСЃР»Рё РґРѕСЃС‚СѓРїРЅС‹
            if client_modules_path:
                logger.info(f"Including client modules from {client_modules_path}")
                for root, dirs, files in os.walk(client_modules_path):
                    # РџСЂРѕРїСѓСЃРєР°РµРј __pycache__
                    dirs[:] = [d for d in dirs if d != '__pycache__']
                    for file in files:
                        if file.endswith('.py'):
                            file_path = Path(root) / file
                            # РћС‚РЅРѕСЃРёС‚РµР»СЊРЅС‹Р№ РїСѓС‚СЊ РѕС‚ client_modules_path
                            rel_path = file_path.relative_to(client_modules_path)
                            zip_path = f"flamix/{rel_path}"
                            with open(file_path, 'rb') as f:
                                zipf.writestr(zip_path, f.read())
            else:
                logger.warning("Client modules not found, ZIP will not include client code")
                # Р”РѕР±Р°РІР»СЏРµРј РёРЅСЃС‚СЂСѓРєС†РёСЋ РІ README Рѕ РЅРµРѕР±С…РѕРґРёРјРѕСЃС‚Рё РєРѕРїРёСЂРѕРІР°РЅРёСЏ РјРѕРґСѓР»РµР№
            
            # README
            readme = f'''# Flamix Client - {client_id}

## Р‘С‹СЃС‚СЂР°СЏ СѓСЃС‚Р°РЅРѕРІРєР°

1. **Р Р°СЃРїР°РєСѓР№С‚Рµ СЌС‚РѕС‚ Р°СЂС…РёРІ** РІ Р»СЋР±СѓСЋ РґРёСЂРµРєС‚РѕСЂРёСЋ
2. **РЈСЃС‚Р°РЅРѕРІРёС‚Рµ Р·Р°РІРёСЃРёРјРѕСЃС‚Рё:**
   ```bash
   pip install -r requirements.txt
   ```
3. **??????? ?????? ??? `client.key`:**
   ```bash
   # Windows PowerShell
   $env:FLAMIX_CLIENT_KEY_PASSWORD="<password from X-Flamix-Client-Key-Password>"

   # Linux/macOS
   export FLAMIX_CLIENT_KEY_PASSWORD="<password from X-Flamix-Client-Key-Password>"
   ```
4. **????????? ??????:**
   ```bash
   python run.py
   ```

Р’СЃС‘ РіРѕС‚РѕРІРѕ! РљР»РёРµРЅС‚ Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё РїРѕРґРєР»СЋС‡РёС‚СЃСЏ Рє СЃРµСЂРІРµСЂСѓ Рё РЅР°С‡РЅРµС‚ СЃРёРЅС…СЂРѕРЅРёР·Р°С†РёСЋ РїСЂР°РІРёР».

**РџСЂРёРјРµС‡Р°РЅРёРµ:** Р•СЃР»Рё РјРѕРґСѓР»Рё РєР»РёРµРЅС‚Р° РЅРµ РІРєР»СЋС‡РµРЅС‹ РІ Р°СЂС…РёРІ, СЃРєРѕРїРёСЂСѓР№С‚Рµ РґРёСЂРµРєС‚РѕСЂРёСЋ `flamix/` РёР· РІРµС‚РєРё `client/` РІ СЂР°СЃРїР°РєРѕРІР°РЅРЅСѓСЋ РґРёСЂРµРєС‚РѕСЂРёСЋ.

## РљРѕРЅС„РёРіСѓСЂР°С†РёСЏ

РљРѕРЅС„РёРіСѓСЂР°С†РёСЏ РЅР°С…РѕРґРёС‚СЃСЏ РІ С„Р°Р№Р»Рµ `config.json`. Р’С‹ РјРѕР¶РµС‚Рµ РёР·РјРµРЅРёС‚СЊ РЅР°СЃС‚СЂРѕР№РєРё РїРµСЂРµРґ Р·Р°РїСѓСЃРєРѕРј:
- `server_host` - IP Р°РґСЂРµСЃ РёР»Рё РґРѕРјРµРЅ СЃРµСЂРІРµСЂР°
- `server_port` - РџРѕСЂС‚ СЃРµСЂРІРµСЂР° (РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ 8443)
- `cert_dir` - Р”РёСЂРµРєС‚РѕСЂРёСЏ СЃ СЃРµСЂС‚РёС„РёРєР°С‚Р°РјРё (РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ "certs")
- `sync_interval` - РРЅС‚РµСЂРІР°Р» СЃРёРЅС…СЂРѕРЅРёР·Р°С†РёРё РїСЂР°РІРёР» (СЃРµРєСѓРЅРґС‹)
- `monitor_interval` - РРЅС‚РµСЂРІР°Р» РїСЂРѕРІРµСЂРєРё РёР·РјРµРЅРµРЅРёР№ (СЃРµРєСѓРЅРґС‹)
- `analytics_enabled` - Р’РєР»СЋС‡РёС‚СЊ СЃР±РѕСЂ Р°РЅР°Р»РёС‚РёРєРё
- `analytics_interval` - РРЅС‚РµСЂРІР°Р» РѕС‚РїСЂР°РІРєРё Р°РЅР°Р»РёС‚РёРєРё (СЃРµРєСѓРЅРґС‹)
- `font` - РќР°Р·РІР°РЅРёРµ С€СЂРёС„С‚Р° РґР»СЏ РёРЅС‚РµСЂС„РµР№СЃР° (РµСЃР»Рё РїСЂРёРјРµРЅРёРјРѕ)
- `font_size` - Р Р°Р·РјРµСЂ С€СЂРёС„С‚Р° (РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ 13)
- `ui_theme` - РўРµРјР° РёРЅС‚РµСЂС„РµР№СЃР° (РµСЃР»Рё РїСЂРёРјРµРЅРёРјРѕ)

## РЎРµСЂС‚РёС„РёРєР°С‚С‹

РЎРµСЂС‚РёС„РёРєР°С‚С‹ РЅР°С…РѕРґСЏС‚СЃСЏ РІ РґРёСЂРµРєС‚РѕСЂРёРё `certs/`:
- `ca.crt` - РЎРµСЂС‚РёС„РёРєР°С‚ CA (РґР»СЏ РїСЂРѕРІРµСЂРєРё СЃРµСЂРІРµСЂР°)
- `client.crt` - РЎРµСЂС‚РёС„РёРєР°С‚ РєР»РёРµРЅС‚Р°
- `client.key` - Р—Р°С€РёС„СЂРѕРІР°РЅРЅС‹Р№ PEM-С„Р°Р№Р» СЃ РїСЂРёРІР°С‚РЅС‹Рј РєР»СЋС‡РѕРј РєР»РёРµРЅС‚Р°

**Р’Р°Р¶РЅРѕ:** РџР°СЂРѕР»СЊ Рє `client.key` РЅРµ Р»РµР¶РёС‚ РІ Р°СЂС…РёРІРµ. РЎРѕС…СЂР°РЅРёС‚Рµ РѕРґРЅРѕСЂР°Р·РѕРІС‹Р№ РїР°СЂРѕР»СЊ РёР· HTTP-Р·Р°РіРѕР»РѕРІРєР° `X-Flamix-Client-Key-Password` Рё Р·Р°РґР°Р№С‚Рµ РµРіРѕ РїРµСЂРµРґ Р·Р°РїСѓСЃРєРѕРј РєР»РёРµРЅС‚Р°.

## РЎС‚СЂСѓРєС‚СѓСЂР°

```
flamix-client-{client_id}/
в”њв”Ђв”Ђ config.json          # РљРѕРЅС„РёРіСѓСЂР°С†РёСЏ РєР»РёРµРЅС‚Р°
в”њв”Ђв”Ђ certs/              # РЎРµСЂС‚РёС„РёРєР°С‚С‹
в”‚   в”њв”Ђв”Ђ ca.crt
в”‚   в”њв”Ђв”Ђ client.crt
в”‚   в””в”Ђв”Ђ client.key
в”њв”Ђв”Ђ flamix/             # РњРѕРґСѓР»Рё РєР»РёРµРЅС‚Р° (РµСЃР»Рё РІРєР»СЋС‡РµРЅС‹ РІ Р°СЂС…РёРІ)
в”‚   в”њв”Ђв”Ђ client/
в”‚   в””в”Ђв”Ђ common/
в”њв”Ђв”Ђ run.py              # РЎРєСЂРёРїС‚ Р·Р°РїСѓСЃРєР°
в”њв”Ђв”Ђ requirements.txt    # Р—Р°РІРёСЃРёРјРѕСЃС‚Рё Python
в””в”Ђв”Ђ README.md           # Р­С‚РѕС‚ С„Р°Р№Р»
```

**РџСЂРёРјРµС‡Р°РЅРёРµ:** Р•СЃР»Рё РјРѕРґСѓР»Рё `flamix/` РЅРµ РІРєР»СЋС‡РµРЅС‹ РІ Р°СЂС…РёРІ, СЃРєРѕРїРёСЂСѓР№С‚Рµ РґРёСЂРµРєС‚РѕСЂРёСЋ `flamix/` РёР· РІРµС‚РєРё `client/` РІ СЂР°СЃРїР°РєРѕРІР°РЅРЅСѓСЋ РґРёСЂРµРєС‚РѕСЂРёСЋ.

## РЈСЃС‚СЂР°РЅРµРЅРёРµ РЅРµРїРѕР»Р°РґРѕРє

Р•СЃР»Рё РєР»РёРµРЅС‚ РЅРµ РјРѕР¶РµС‚ РїРѕРґРєР»СЋС‡РёС‚СЊСЃСЏ:
1. РџСЂРѕРІРµСЂСЊС‚Рµ, С‡С‚Рѕ СЃРµСЂРІРµСЂ Р·Р°РїСѓС‰РµРЅ
2. РџСЂРѕРІРµСЂСЊС‚Рµ РїСЂР°РІРёР»СЊРЅРѕСЃС‚СЊ `server_host` РІ `config.json`
3. РЈР±РµРґРёС‚РµСЃСЊ, С‡С‚Рѕ РїРѕСЂС‚ `server_port` РЅРµ Р·Р°Р±Р»РѕРєРёСЂРѕРІР°РЅ С„Р°Р№СЂРІРѕР»РѕРј
4. РџСЂРѕРІРµСЂСЊС‚Рµ, С‡С‚Рѕ СЃРµСЂС‚РёС„РёРєР°С‚С‹ РЅР°С…РѕРґСЏС‚СЃСЏ РІ РґРёСЂРµРєС‚РѕСЂРёРё `certs/`
'''
            zipf.writestr("README.md", readme)
        
        zip_buffer.seek(0)
        return zip_buffer

    def _setup_routes(self):
        """РќР°СЃС‚СЂРѕР№РєР° РјР°СЂС€СЂСѓС‚РѕРІ API"""

        @self.app.get("/", response_class=HTMLResponse)
        async def root():
            """Р“Р»Р°РІРЅР°СЏ СЃС‚СЂР°РЅРёС†Р° РІРµР±-РёРЅС‚РµСЂС„РµР№СЃР°"""
            html_content = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Flamix Server</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { opacity: 0.9; }
        .content {
            padding: 40px;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
        }
        .form-group input, .form-group select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: #667eea;
        }
        .form-group small {
            display: block;
            margin-top: 5px;
            color: #888;
            font-size: 0.9em;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 30px;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            width: 100%;
            margin-top: 10px;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .btn:active {
            transform: translateY(0);
        }
        .clients-list {
            margin-top: 20px;
        }
        .client-item {
            background: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .client-item strong {
            color: #667eea;
        }
        .message {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: none;
        }
        .message.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .message.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .message.show {
            display: block;
        }
        .loading {
            display: none;
            text-align: center;
            padding: 20px;
        }
        .loading.show {
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>рџ›ЎпёЏ Flamix Server</h1>
            <p>Р¦РµРЅС‚СЂР°Р»РёР·РѕРІР°РЅРЅРѕРµ СѓРїСЂР°РІР»РµРЅРёРµ С„Р°Р№СЂРІРѕР»РѕРј</p>
        </div>
        <div class="content">
            <div id="message" class="message"></div>
            
            <div class="section">
                <h2>РЎРѕР·РґР°С‚СЊ РЅРѕРІРѕРіРѕ РєР»РёРµРЅС‚Р°</h2>
                <form id="createClientForm">
                    <div class="form-group">
                        <label for="client_id">Client ID *</label>
                        <input type="number" id="client_id" name="client_id" required>
                        <small>РЈРЅРёРєР°Р»СЊРЅС‹Р№ С‡РёСЃР»РѕРІРѕР№ РёРґРµРЅС‚РёС„РёРєР°С‚РѕСЂ РєР»РёРµРЅС‚Р°</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="client_name">РРјСЏ РєР»РёРµРЅС‚Р°</label>
                        <input type="text" id="client_name" name="name" placeholder="РћРїС†РёРѕРЅР°Р»СЊРЅРѕ">
                        <small>РћС‚РѕР±СЂР°Р¶Р°РµРјРѕРµ РёРјСЏ РєР»РёРµРЅС‚Р° (РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ РёСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ Client ID)</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="server_ip">IP Р°РґСЂРµСЃ СЃРµСЂРІРµСЂР° РґР»СЏ РєРѕРЅС„РёРіР°</label>
                        <input type="text" id="server_ip" name="server_ip" placeholder="РђРІС‚РѕРјР°С‚РёС‡РµСЃРєРё РѕРїСЂРµРґРµР»СЏРµС‚СЃСЏ">
                        <small>IP Р°РґСЂРµСЃ, РєРѕС‚РѕСЂС‹Р№ Р±СѓРґРµС‚ СѓРєР°Р·Р°РЅ РІ РєРѕРЅС„РёРіРµ РєР»РёРµРЅС‚Р°. Р•СЃР»Рё РЅРµ СѓРєР°Р·Р°РЅ, Р±СѓРґРµС‚ Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё РѕРїСЂРµРґРµР»С‘РЅ РёР· РёРЅС‚РµСЂРЅРµС‚Р°.</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="certificate_ip">IP Р°РґСЂРµСЃ РґР»СЏ СЃРµСЂС‚РёС„РёРєР°С‚Р°</label>
                        <input type="text" id="certificate_ip" name="certificate_ip" placeholder="РћРїС†РёРѕРЅР°Р»СЊРЅРѕ">
                        <small>IP Р°РґСЂРµСЃ РґР»СЏ РІРєР»СЋС‡РµРЅРёСЏ РІ СЃРµСЂРІРµСЂРЅС‹Р№ СЃРµСЂС‚РёС„РёРєР°С‚. Р•СЃР»Рё СѓРєР°Р·Р°РЅ, СЃРµСЂС‚РёС„РёРєР°С‚ Р±СѓРґРµС‚ РѕР±РЅРѕРІР»С‘РЅ.</small>
                    </div>
                    
                    <button type="submit" class="btn">РЎРѕР·РґР°С‚СЊ РєР»РёРµРЅС‚Р° Рё СЃРєР°С‡Р°С‚СЊ ZIP</button>
                </form>
                <div id="loading" class="loading">РЎРѕР·РґР°РЅРёРµ РєР»РёРµРЅС‚Р°...</div>
            </div>
            
            <div class="section">
                <h2>РЎРїРёСЃРѕРє РєР»РёРµРЅС‚РѕРІ</h2>
                <div id="clientsList" class="clients-list">
                    <p>Р—Р°РіСЂСѓР·РєР°...</p>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Р¤СѓРЅРєС†РёСЏ РґР»СЏ РѕС‚РѕР±СЂР°Р¶РµРЅРёСЏ СЃРѕРѕР±С‰РµРЅРёР№
        function showMessage(text, type) {
            const messageDiv = document.getElementById('message');
            messageDiv.textContent = text;
            messageDiv.className = 'message ' + type + ' show';
            setTimeout(() => {
                messageDiv.classList.remove('show');
            }, 5000);
        }
        
        // Р—Р°РіСЂСѓР·РєР° СЃРїРёСЃРєР° РєР»РёРµРЅС‚РѕРІ
        async function loadClients() {
            try {
                const response = await fetch('/api/clients');
                const data = await response.json();
                const clientsList = document.getElementById('clientsList');
                
                if (data.clients && data.clients.length > 0) {
                    clientsList.innerHTML = await Promise.all(data.clients.map(async (client) => {
                        // Р—Р°РіСЂСѓР¶Р°РµРј РїРѕСЃР»РµРґРЅРёР№ СЃС‚Р°С‚СѓСЃ РґР»СЏ РєР°Р¶РґРѕРіРѕ РєР»РёРµРЅС‚Р°
                        let statusHtml = '';
                        try {
                            const statusResponse = await fetch(`/api/clients/${client.id}/status/latest`);
                            if (statusResponse.ok) {
                                const status = await statusResponse.json();
                                statusHtml = `
                                    <div style="font-size: 0.9em; color: #666; margin-top: 5px;">
                                        CPU: ${status.cpu_percent ? status.cpu_percent.toFixed(1) : 'N/A'}% | 
                                        Memory: ${status.memory_percent ? status.memory_percent.toFixed(1) : 'N/A'}% | 
                                        Last seen: ${new Date(status.timestamp).toLocaleString()}
                                    </div>
                                `;
                            }
                        } catch (e) {
                            console.error(`Error loading status for client ${client.id}:`, e);
                        }
                        
                        return `
                            <div class="client-item" style="flex-direction: column; align-items: flex-start;">
                                <div style="width: 100%; display: flex; justify-content: space-between; align-items: center;">
                                    <div>
                                        <strong>ID: ${client.id}</strong> - ${client.name || client.id}
                                        ${statusHtml}
                                    </div>
                                    <div>
                                        <a href="/api/clients/${client.id}/package" class="btn" style="width: auto; padding: 10px 20px; text-decoration: none; display: inline-block; margin-right: 10px;">
                                            РЎРєР°С‡Р°С‚СЊ ZIP
                                        </a>
                                        <a href="/client/${client.id}" class="btn" style="width: auto; padding: 10px 20px; text-decoration: none; display: inline-block; background: #28a745;">
                                            РџСЂРѕСЃРјРѕС‚СЂ
                                        </a>
                                    </div>
                                </div>
                            </div>
                        `;
                    })).then(htmls => htmls.join(''));
                } else {
                    clientsList.innerHTML = '<p>РљР»РёРµРЅС‚С‹ РЅРµ РЅР°Р№РґРµРЅС‹</p>';
                }
            } catch (error) {
                console.error('РћС€РёР±РєР° Р·Р°РіСЂСѓР·РєРё РєР»РёРµРЅС‚РѕРІ:', error);
                document.getElementById('clientsList').innerHTML = '<p>РћС€РёР±РєР° Р·Р°РіСЂСѓР·РєРё РєР»РёРµРЅС‚РѕРІ</p>';
            }
        }
        
        // РћР±СЂР°Р±РѕС‚РєР° С„РѕСЂРјС‹ СЃРѕР·РґР°РЅРёСЏ РєР»РёРµРЅС‚Р°
        document.getElementById('createClientForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = {
                client_id: document.getElementById('client_id').value,
                name: document.getElementById('client_name').value || undefined,
                server_ip: document.getElementById('server_ip').value || undefined,
                certificate_ip: document.getElementById('certificate_ip').value || undefined
            };
            
            // РЈРґР°Р»СЏРµРј undefined Р·РЅР°С‡РµРЅРёСЏ
            Object.keys(formData).forEach(key => {
                if (formData[key] === undefined || formData[key] === '') {
                    delete formData[key];
                }
            });
            
            const loadingDiv = document.getElementById('loading');
            loadingDiv.classList.add('show');
            
            try {
                const response = await fetch('/api/clients', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(formData)
                });
                
                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `flamix-client-${formData.client_id}.zip`;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    document.body.removeChild(a);
                    
                    showMessage('РљР»РёРµРЅС‚ СѓСЃРїРµС€РЅРѕ СЃРѕР·РґР°РЅ Рё ZIP Р°СЂС…РёРІ СЃРєР°С‡Р°РЅ!', 'success');
                    document.getElementById('createClientForm').reset();
                    loadClients();
                } else {
                    const error = await response.json();
                    showMessage('РћС€РёР±РєР°: ' + (error.detail || 'РќРµРёР·РІРµСЃС‚РЅР°СЏ РѕС€РёР±РєР°'), 'error');
                }
            } catch (error) {
                showMessage('РћС€РёР±РєР° СЃРѕР·РґР°РЅРёСЏ РєР»РёРµРЅС‚Р°: ' + error.message, 'error');
            } finally {
                loadingDiv.classList.remove('show');
            }
        });
        
        // Р—Р°РіСЂСѓР¶Р°РµРј СЃРїРёСЃРѕРє РєР»РёРµРЅС‚РѕРІ РїСЂРё Р·Р°РіСЂСѓР·РєРµ СЃС‚СЂР°РЅРёС†С‹
        loadClients();
        setInterval(loadClients, 30000); // РћР±РЅРѕРІР»СЏРµРј РєР°Р¶РґС‹Рµ 30 СЃРµРєСѓРЅРґ
    </script>
</body>
</html>
            """
            return html_content

        @self.app.get("/traffic", response_class=HTMLResponse)
        async def traffic_dashboard():
            """Traffic statistics dashboard"""
            html_content = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Traffic Statistics - Flamix</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .content {
            padding: 40px;
        }
        .controls {
            margin-bottom: 30px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        .control-group {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }
        .control-group label {
            font-weight: 500;
            color: #555;
            font-size: 0.9em;
        }
        .control-group select, .control-group input {
            padding: 10px;
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 14px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: #f5f5f5;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        .stat-card h3 {
            color: #667eea;
            font-size: 0.9em;
            margin-bottom: 10px;
        }
        .stat-card .value {
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }
        .chart-container {
            margin-bottom: 40px;
            padding: 20px;
            background: #fafafa;
            border-radius: 8px;
        }
        .chart-container h2 {
            margin-bottom: 20px;
            color: #333;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }
        th {
            background: #667eea;
            color: white;
            font-weight: 500;
        }
        tr:hover {
            background: #f5f5f5;
        }
        .loading {
            text-align: center;
            padding: 40px;
            color: #888;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>рџ“Љ Traffic Statistics</h1>
            <p>Real-time network traffic monitoring</p>
        </div>
        <div class="content">
            <div class="controls">
                <div class="control-group">
                    <label>Client ID</label>
                    <input type="text" id="client_id" placeholder="All clients">
                </div>
                <div class="control-group">
                    <label>Period</label>
                    <select id="period">
                        <option value="1h">Last Hour</option>
                        <option value="24h" selected>Last 24 Hours</option>
                        <option value="7d">Last 7 Days</option>
                    </select>
                </div>
                <div class="control-group">
                    <label>Interval</label>
                    <select id="interval">
                        <option value="1m" selected>1 Minute</option>
                        <option value="5m">5 Minutes</option>
                        <option value="15m">15 Minutes</option>
                        <option value="1h">1 Hour</option>
                    </select>
                </div>
                <div class="control-group" style="justify-content: flex-end;">
                    <button onclick="loadData()" style="padding: 10px 20px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 14px;">Refresh</button>
                </div>
            </div>

            <div class="stats-grid" id="statsGrid">
                <div class="stat-card">
                    <h3>Total Bytes In</h3>
                    <div class="value" id="totalBytesIn">0</div>
                </div>
                <div class="stat-card">
                    <h3>Total Bytes Out</h3>
                    <div class="value" id="totalBytesOut">0</div>
                </div>
                <div class="stat-card">
                    <h3>Total Connections</h3>
                    <div class="value" id="totalConnections">0</div>
                </div>
                <div class="stat-card">
                    <h3>Current Bandwidth</h3>
                    <div class="value" id="currentBandwidth">0 bps</div>
                </div>
            </div>

            <div class="chart-container">
                <h2>Bandwidth Over Time</h2>
                <canvas id="bandwidthChart"></canvas>
            </div>

            <div class="chart-container">
                <h2>Top Source IPs</h2>
                <canvas id="topSrcIPsChart"></canvas>
            </div>

            <div class="chart-container">
                <h2>Top Destination IPs</h2>
                <table id="topDstIPsTable">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Bytes</th>
                            <th>Connections</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        let bandwidthChart, topSrcIPsChart;

        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
        }

        function formatBps(bps) {
            if (bps === 0) return '0 bps';
            const k = 1024;
            const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps'];
            const i = Math.floor(Math.log(bps) / Math.log(k));
            return Math.round(bps / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
        }

        async function loadData() {
            const clientId = document.getElementById('client_id').value || null;
            const period = document.getElementById('period').value;
            const interval = document.getElementById('interval').value;

            try {
                // Load summary
                const summaryUrl = `/api/traffic/summary?period=${period}` + (clientId ? `&client_id=${clientId}` : '');
                const summary = await fetch(summaryUrl).then(r => r.json());
                
                // Update stats
                document.getElementById('totalBytesIn').textContent = formatBytes(summary.total_bytes_in || 0);
                document.getElementById('totalBytesOut').textContent = formatBytes(summary.total_bytes_out || 0);
                document.getElementById('totalConnections').textContent = (summary.total_connections || 0).toLocaleString();

                // Load bandwidth stats
                const bandwidthUrl = `/api/traffic/bandwidth?period=${period}` + (clientId ? `&client_id=${clientId}` : '');
                const bandwidth = await fetch(bandwidthUrl).then(r => r.json());
                document.getElementById('currentBandwidth').textContent = formatBps(bandwidth.current_bps || 0);

                // Load timeline
                const timelineUrl = `/api/traffic/timeline?interval=${interval}&period=${period}` + (clientId ? `&client_id=${clientId}` : '');
                const timeline = await fetch(timelineUrl).then(r => r.json());
                
                // Update bandwidth chart
                updateBandwidthChart(timeline);

                // Update top IPs
                updateTopSrcIPsChart(summary.top_source_ips || {});
                updateTopDstIPsTable(summary.top_destination_ips || {});

            } catch (error) {
                console.error('Error loading data:', error);
            }
        }

        function updateBandwidthChart(timeline) {
            const ctx = document.getElementById('bandwidthChart').getContext('2d');
            
            if (bandwidthChart) {
                bandwidthChart.destroy();
            }

            bandwidthChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: timeline.timestamps || [],
                    datasets: [{
                        label: 'Bandwidth (bps)',
                        data: timeline.bandwidth || [],
                        borderColor: '#667eea',
                        backgroundColor: 'rgba(102, 126, 234, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }

        function updateTopSrcIPsChart(topIPs) {
            const ctx = document.getElementById('topSrcIPsChart').getContext('2d');
            const labels = Object.keys(topIPs).slice(0, 10);
            const data = labels.map(ip => topIPs[ip].bytes || topIPs[ip] || 0);

            if (topSrcIPsChart) {
                topSrcIPsChart.destroy();
            }

            topSrcIPsChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Bytes',
                        data: data,
                        backgroundColor: '#667eea'
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }

        function updateTopDstIPsTable(topIPs) {
            const tbody = document.querySelector('#topDstIPsTable tbody');
            tbody.innerHTML = '';

            const entries = Object.entries(topIPs).slice(0, 20);
            entries.forEach(([ip, data]) => {
                const row = tbody.insertRow();
                row.insertCell(0).textContent = ip;
                row.insertCell(1).textContent = formatBytes(data.bytes || data || 0);
                row.insertCell(2).textContent = (data.connections || 0).toLocaleString();
            });
        }

        // Auto-refresh every 5 seconds for real-time updates
        loadData();
        setInterval(loadData, 5000);
    </script>
</body>
</html>
            """
            return html_content

        @self.app.get("/client/{client_id}", response_class=HTMLResponse)
        async def client_dashboard(client_id: str):
            """Р”РµС‚Р°Р»СЊРЅР°СЏ СЃС‚СЂР°РЅРёС†Р° РєР»РёРµРЅС‚Р° СЃ Р»РѕРіР°РјРё, СЃС‚Р°С‚СѓСЃРѕРј Рё РїСЂР°РІРёР»Р°РјРё"""
            html_content = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Client {client_id} - Flamix</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header a {{
            color: white;
            text-decoration: none;
            padding: 10px 20px;
            background: rgba(255,255,255,0.2);
            border-radius: 5px;
        }}
        .content {{
            padding: 40px;
        }}
        .tabs {{
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
            border-bottom: 2px solid #e0e0e0;
        }}
        .tab {{
            padding: 15px 30px;
            background: #f5f5f5;
            border: none;
            border-radius: 5px 5px 0 0;
            cursor: pointer;
            font-size: 16px;
            transition: all 0.3s;
        }}
        .tab.active {{
            background: #667eea;
            color: white;
        }}
        .tab-content {{
            display: none;
        }}
        .tab-content.active {{
            display: block;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: #f5f5f5;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        .stat-card h3 {{
            color: #667eea;
            font-size: 0.9em;
            margin-bottom: 10px;
        }}
        .stat-card .value {{
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }}
        th {{
            background: #667eea;
            color: white;
            font-weight: 500;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
        .log-entry {{
            font-family: monospace;
            font-size: 0.9em;
        }}
        .log-level-ERROR {{ color: #dc3545; }}
        .log-level-WARNING {{ color: #ffc107; }}
        .log-level-INFO {{ color: #28a745; }}
        .log-level-DEBUG {{ color: #6c757d; }}
        .chart-container {{
            margin-bottom: 40px;
            padding: 20px;
            background: #fafafa;
            border-radius: 8px;
        }}
        .loading {{
            text-align: center;
            padding: 40px;
            color: #888;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>рџ–ҐпёЏ Client {client_id}</h1>
                <p>Р”РµС‚Р°Р»СЊРЅР°СЏ РёРЅС„РѕСЂРјР°С†РёСЏ Рѕ РєР»РёРµРЅС‚Рµ</p>
            </div>
            <a href="/">в†ђ РќР°Р·Р°Рґ Рє СЃРїРёСЃРєСѓ</a>
        </div>
        <div class="content">
            <div class="tabs">
                <button class="tab active" onclick="showTab('status')">РЎРёСЃС‚РµРјРЅС‹Р№ СЃС‚Р°С‚СѓСЃ</button>
                <button class="tab" onclick="showTab('logs')">Р›РѕРіРё</button>
                <button class="tab" onclick="showTab('rules')">РџСЂР°РІРёР»Р°</button>
                <button class="tab" onclick="showTab('plugins')">РџР»Р°РіРёРЅС‹</button>
            </div>

            <div id="status-tab" class="tab-content active">
                <div class="stats-grid" id="statusStats">
                    <div class="stat-card">
                        <h3>CPU Usage</h3>
                        <div class="value" id="cpuPercent">-</div>
                    </div>
                    <div class="stat-card">
                        <h3>Memory Usage</h3>
                        <div class="value" id="memoryPercent">-</div>
                    </div>
                    <div class="stat-card">
                        <h3>Last Update</h3>
                        <div class="value" id="lastUpdate" style="font-size: 1em;">-</div>
                    </div>
                </div>
                <div class="chart-container">
                    <h2>System Metrics Over Time</h2>
                    <canvas id="statusChart"></canvas>
                </div>
            </div>

            <div id="logs-tab" class="tab-content">
                <div style="margin-bottom: 20px;">
                    <label>Filter by level: </label>
                    <select id="logLevelFilter" onchange="loadLogs()">
                        <option value="">All</option>
                        <option value="ERROR">ERROR</option>
                        <option value="WARNING">WARNING</option>
                        <option value="INFO">INFO</option>
                        <option value="DEBUG">DEBUG</option>
                    </select>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Level</th>
                            <th>Logger</th>
                            <th>Message</th>
                        </tr>
                    </thead>
                    <tbody id="logsTableBody">
                        <tr><td colspan="4" class="loading">Р—Р°РіСЂСѓР·РєР° Р»РѕРіРѕРІ...</td></tr>
                    </tbody>
                </table>
            </div>

            <div id="rules-tab" class="tab-content">
                <table>
                    <thead>
                        <tr>
                            <th>Rule ID</th>
                            <th>Name</th>
                            <th>Action</th>
                            <th>Direction</th>
                            <th>Enabled</th>
                        </tr>
                    </thead>
                    <tbody id="rulesTableBody">
                        <tr><td colspan="5" class="loading">Р—Р°РіСЂСѓР·РєР° РїСЂР°РІРёР»...</td></tr>
                    </tbody>
                </table>
            </div>

            <div id="plugins-tab" class="tab-content">
                <table>
                    <thead>
                        <tr>
                            <th>Plugin ID</th>
                            <th>Enabled</th>
                            <th>Available</th>
                            <th>Health Status</th>
                        </tr>
                    </thead>
                    <tbody id="pluginsTableBody">
                        <tr><td colspan="4" class="loading">Р—Р°РіСЂСѓР·РєР° РїР»Р°РіРёРЅРѕРІ...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        const clientId = '{client_id}';
        let statusChart;

        function showTab(tabName) {{
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(btn => btn.classList.remove('active'));
            
            // Show selected tab
            document.getElementById(tabName + '-tab').classList.add('active');
            event.target.classList.add('active');
            
            // Load data for the tab
            if (tabName === 'status') loadStatus();
            else if (tabName === 'logs') loadLogs();
            else if (tabName === 'rules') loadRules();
            else if (tabName === 'plugins') loadPlugins();
        }}

        async function loadStatus() {{
            try {{
                const response = await fetch(`/api/clients/${{clientId}}/status/latest`);
                if (response.ok) {{
                    const status = await response.json();
                    document.getElementById('cpuPercent').textContent = (status.cpu_percent || 0).toFixed(1) + '%';
                    document.getElementById('memoryPercent').textContent = (status.memory_percent || 0).toFixed(1) + '%';
                    document.getElementById('lastUpdate').textContent = new Date(status.timestamp).toLocaleString();
                }}
                
                // Load history for chart
                const historyResponse = await fetch(`/api/clients/${{clientId}}/status?limit=100`);
                if (historyResponse.ok) {{
                    const data = await historyResponse.json();
                    updateStatusChart(data.statuses || []);
                }}
            }} catch (error) {{
                console.error('Error loading status:', error);
            }}
        }}

        function updateStatusChart(statuses) {{
            const ctx = document.getElementById('statusChart').getContext('2d');
            const labels = statuses.map(s => new Date(s.timestamp).toLocaleTimeString()).reverse();
            const cpuData = statuses.map(s => s.cpu_percent || 0).reverse();
            const memoryData = statuses.map(s => s.memory_percent || 0).reverse();
            
            if (statusChart) statusChart.destroy();
            
            statusChart = new Chart(ctx, {{
                type: 'line',
                data: {{
                    labels: labels,
                    datasets: [
                        {{
                            label: 'CPU %',
                            data: cpuData,
                            borderColor: '#667eea',
                            backgroundColor: 'rgba(102, 126, 234, 0.1)',
                            tension: 0.4
                        }},
                        {{
                            label: 'Memory %',
                            data: memoryData,
                            borderColor: '#764ba2',
                            backgroundColor: 'rgba(118, 75, 162, 0.1)',
                            tension: 0.4
                        }}
                    ]
                }},
                options: {{
                    responsive: true,
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            max: 100
                        }}
                    }}
                }}
            }});
        }}

        async function loadLogs() {{
            try {{
                const level = document.getElementById('logLevelFilter').value;
                const url = `/api/clients/${{clientId}}/logs?limit=1000` + (level ? `&level=${{level}}` : '');
                const response = await fetch(url);
                if (response.ok) {{
                    const data = await response.json();
                    const tbody = document.getElementById('logsTableBody');
                    if (data.logs && data.logs.length > 0) {{
                        tbody.innerHTML = data.logs.map(log => `
                            <tr>
                                <td>${{new Date(log.timestamp).toLocaleString()}}</td>
                                <td><span class="log-level-${{log.level}}">${{log.level}}</span></td>
                                <td>${{log.logger_name || '-'}}</td>
                                <td class="log-entry">${{log.message}}</td>
                            </tr>
                        `).join('');
                    }} else {{
                        tbody.innerHTML = '<tr><td colspan="4">Р›РѕРіРё РЅРµ РЅР°Р№РґРµРЅС‹</td></tr>';
                    }}
                }}
            }} catch (error) {{
                console.error('Error loading logs:', error);
            }}
        }}

        async function loadRules() {{
            try {{
                const response = await fetch(`/api/clients/${{clientId}}/rules`);
                if (response.ok) {{
                    const data = await response.json();
                    const tbody = document.getElementById('rulesTableBody');
                    if (data.rules && data.rules.length > 0) {{
                        tbody.innerHTML = data.rules.map(rule => `
                            <tr>
                                <td>${{rule.id}}</td>
                                <td>${{rule.name || '-'}}</td>
                                <td>${{rule.action || '-'}}</td>
                                <td>${{rule.direction || '-'}}</td>
                                <td>${{rule.enabled ? 'Yes' : 'No'}}</td>
                            </tr>
                        `).join('');
                    }} else {{
                        tbody.innerHTML = '<tr><td colspan="5">РџСЂР°РІРёР»Р° РЅРµ РЅР°Р№РґРµРЅС‹</td></tr>';
                    }}
                }}
            }} catch (error) {{
                console.error('Error loading rules:', error);
            }}
        }}

        async function loadPlugins() {{
            try {{
                const response = await fetch(`/api/clients/${{clientId}}/plugins`);
                if (response.ok) {{
                    const data = await response.json();
                    const tbody = document.getElementById('pluginsTableBody');
                    if (data.plugins && data.plugins.length > 0) {{
                        tbody.innerHTML = data.plugins.map(plugin => `
                            <tr>
                                <td>${{plugin.id}}</td>
                                <td>${{plugin.enabled ? 'Yes' : 'No'}}</td>
                                <td>${{plugin.available ? 'Yes' : 'No'}}</td>
                                <td>${{plugin.health?.status || 'N/A'}}</td>
                            </tr>
                        `).join('');
                    }} else {{
                        tbody.innerHTML = '<tr><td colspan="4">РџР»Р°РіРёРЅС‹ РЅРµ РЅР°Р№РґРµРЅС‹</td></tr>';
                    }}
                }}
            }} catch (error) {{
                console.error('Error loading plugins:', error);
            }}
        }}

        // Auto-refresh
        function autoRefresh() {{
            const activeTab = document.querySelector('.tab-content.active');
            if (activeTab.id === 'status-tab') loadStatus();
            else if (activeTab.id === 'logs-tab') loadLogs();
            else if (activeTab.id === 'rules-tab') loadRules();
            else if (activeTab.id === 'plugins-tab') loadPlugins();
        }}

        // Initial load
        loadStatus();
        setInterval(autoRefresh, 10000); // Refresh every 10 seconds
    </script>
</body>
</html>
            """
            return html_content

        @self.app.get("/api/")
        async def api_root():
            """High-level API summary for operators and GUI bootstrap."""
            info = self._get_effective_server_info()
            health = self._get_effective_health()
            return {
                "success": True,
                "name": info.get("name", "Flamix Server"),
                "health": health,
                "info": info,
                "config": self._get_runtime_config().to_public_dict(),
            }

        @self.app.get("/api/server/info")
        async def get_server_info():
            """Return server and deployment diagnostics."""
            return {
                "success": True,
                "info": self._get_effective_server_info(),
            }

        @self.app.get("/api/server/health")
        @self.app.get("/api/health")
        async def get_server_health():
            """Return readiness/liveness style health information."""
            return {
                "success": True,
                "health": self._get_effective_health(),
            }

        @self.app.get("/api/server/config")
        @self.app.get("/api/config")
        async def get_server_config():
            """Return the current effective server configuration."""
            current = self._get_runtime_config().to_public_dict()
            stored = self._get_persisted_runtime_config()
            return {
                "success": True,
                "config": current,
                "stored_config": stored,
                "restart_required": stored is not None and stored != current,
            }

        @self.app.put("/api/server/config")
        @self.app.patch("/api/server/config")
        async def update_server_config(config_data: dict):
            """Update server runtime settings and persist them for the next restart."""
            if not isinstance(config_data, dict):
                raise HTTPException(status_code=400, detail="config_data must be a JSON object")
            result = self._update_runtime_config(config_data, persist=True)
            return {
                "success": True,
                **result,
            }

        @self.app.get("/api/server/gui-package")
        async def get_gui_connection_package():
            """Download a trust bundle for GUI connections to a self-signed server."""
            try:
                bundle_path = self.ensure_gui_connection_bundle(force=True)
                return Response(
                    content=bundle_path.read_bytes(),
                    media_type="application/zip",
                    headers={
                        "Content-Disposition": 'attachment; filename="flamix-gui-connection.zip"',
                        "Cache-Control": "no-store",
                    }
                )
            except Exception as exc:
                logger.error("Failed to provide GUI connection package: %s", exc, exc_info=True)
                raise HTTPException(status_code=500, detail=f"Failed to build GUI package: {exc}")

        @self.app.post("/api/bootstrap/enroll")
        async def bootstrap_enroll(payload: dict):
            """Redeem a one-time bootstrap token and issue a client certificate from a CSR."""
            client_id = str(payload.get("client_id") or "").strip()
            bootstrap_token = str(payload.get("bootstrap_token") or "").strip()
            csr_pem = payload.get("csr_pem")

            if not client_id or not bootstrap_token or not csr_pem:
                raise HTTPException(
                    status_code=400,
                    detail="client_id, bootstrap_token and csr_pem are required",
                )
            if not self.security:
                raise HTTPException(status_code=500, detail="Security module not initialized")

            client_row = self.db.execute_one(
                "SELECT id FROM clients WHERE id = ?",
                (client_id,),
            )
            if not client_row:
                raise HTTPException(status_code=404, detail="Client not found")

            self._consume_bootstrap_token(client_id, bootstrap_token)

            try:
                cert, ca_cert_pem = self.security.sign_client_csr(
                    client_id,
                    csr_pem.encode("utf-8"),
                )
            except Exception as exc:
                logger.error("Bootstrap enrollment failed for client %s: %s", client_id, exc, exc_info=True)
                raise HTTPException(status_code=400, detail=f"Failed to sign CSR: {exc}")

            return {
                "success": True,
                "client_id": client_id,
                "client_cert_pem": cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
                "ca_cert_pem": ca_cert_pem.decode("utf-8"),
            }

        @self.app.get("/api/clients")
        async def get_clients():
            """РџРѕР»СѓС‡РµРЅРёРµ СЃРїРёСЃРєР° РєР»РёРµРЅС‚РѕРІ"""
            clients = self.db.execute("SELECT * FROM clients ORDER BY last_seen DESC")
            logger.debug(f"API /api/clients: returning {len(clients)} clients")
            if clients:
                logger.debug(f"Sample client data: {clients[0] if clients else 'None'}")
            return {"clients": clients}

        @self.app.post("/api/clients")
        async def create_client(client_data: dict):
            """
            РЎРѕР·РґР°РЅРёРµ РЅРѕРІРѕРіРѕ РєР»РёРµРЅС‚Р° СЃ РіРµРЅРµСЂР°С†РёРµР№ СЃРµСЂС‚РёС„РёРєР°С‚РѕРІ Рё ZIP Р°СЂС…РёРІР°
            
            РџР°СЂР°РјРµС‚СЂС‹ РІ body:
            - client_id (РѕР±СЏР·Р°С‚РµР»СЊРЅС‹Р№): ID РєР»РёРµРЅС‚Р°
            - name (РѕРїС†РёРѕРЅР°Р»СЊРЅРѕ): РРјСЏ РєР»РёРµРЅС‚Р°
            - server_ip (РѕРїС†РёРѕРЅР°Р»СЊРЅРѕ): IP Р°РґСЂРµСЃ СЃРµСЂРІРµСЂР° РґР»СЏ РєРѕРЅС„РёРіР° РєР»РёРµРЅС‚Р°
            - certificate_ip (РѕРїС†РёРѕРЅР°Р»СЊРЅРѕ): IP Р°РґСЂРµСЃ РґР»СЏ РІРєР»СЋС‡РµРЅРёСЏ РІ СЃРµСЂРІРµСЂРЅС‹Р№ СЃРµСЂС‚РёС„РёРєР°С‚
            """
            client_id = client_data.get('client_id')
            client_name = client_data.get('name', client_id)
            server_ip_for_config = client_data.get('server_ip')  # IP РґР»СЏ РєРѕРЅС„РёРіР°
            certificate_ip = client_data.get('certificate_ip')  # IP РґР»СЏ СЃРµСЂРІРµСЂРЅРѕРіРѕ СЃРµСЂС‚РёС„РёРєР°С‚Р°
            provisioning_mode = str(client_data.get('provisioning_mode') or 'bootstrap').lower()
            
            if not client_id:
                raise HTTPException(status_code=400, detail="client_id is required")
            
            # Р’Р°Р»РёРґР°С†РёСЏ ID РєР°Рє int
            try:
                client_id_int = int(client_id)
                client_id = str(client_id_int)  # РќРѕСЂРјР°Р»РёР·СѓРµРј РєР°Рє СЃС‚СЂРѕРєСѓ РґР»СЏ Р‘Р”
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail="client_id must be an integer")
            
            # РџСЂРѕРІРµСЂСЏРµРј, СЃСѓС‰РµСЃС‚РІСѓРµС‚ Р»Рё РєР»РёРµРЅС‚
            existing = self.db.execute(
                "SELECT id FROM clients WHERE id = ?",
                (client_id,)
            )
            if existing:
                raise HTTPException(status_code=400, detail=f"Client {client_id} already exists")
            
            # РћР±РЅРѕРІР»СЏРµРј СЃРµСЂРІРµСЂРЅС‹Р№ СЃРµСЂС‚РёС„РёРєР°С‚ РµСЃР»Рё СѓРєР°Р·Р°РЅ certificate_ip
            if certificate_ip and self.security:
                try:
                    logger.info(f"Updating server certificate with IP {certificate_ip} as requested")
                    self.security.update_server_certificate_ip(certificate_ip)
                    # РќСѓР¶РЅРѕ РїРµСЂРµСЃРѕР·РґР°С‚СЊ SSL РєРѕРЅС‚РµРєСЃС‚, РЅРѕ СЌС‚Рѕ РґРµР»Р°РµС‚СЃСЏ РїСЂРё СЃР»РµРґСѓСЋС‰РµРј РїРѕРґРєР»СЋС‡РµРЅРёРё
                    logger.info("Server certificate updated. Note: server restart may be required for changes to take effect.")
                except Exception as e:
                    logger.error(f"Failed to update server certificate: {e}", exc_info=True)
                    raise HTTPException(status_code=500, detail=f"Failed to update server certificate: {str(e)}")
            
            # Р“РµРЅРµСЂРёСЂСѓРµРј СЃРµСЂС‚РёС„РёРєР°С‚С‹
            if not self.security:
                raise HTTPException(status_code=500, detail="Security module not initialized")

            from datetime import datetime
            now = datetime.utcnow().isoformat() + "Z"
            self.db.execute(
                """INSERT INTO clients (id, name, enabled, registered_at, last_seen)
                   VALUES (?, ?, ?, ?, ?)""",
                (client_id, client_name, True, now, now)
            )

            if server_ip_for_config:
                server_ip = server_ip_for_config
                logger.info(f"Using provided server IP for config: {server_ip}")
            else:
                server_ip = self.server_host
                if server_ip == "0.0.0.0":
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.connect(("8.8.8.8", 80))
                        server_ip = s.getsockname()[0]
                        s.close()
                        logger.info(f"Auto-detected server IP from internet: {server_ip}")
                    except Exception as e:
                        logger.warning(f"Failed to detect server IP: {e}, using 127.0.0.1")
                        server_ip = "127.0.0.1"

            config = self._build_client_config(client_id, server_ip)

            if provisioning_mode == "bootstrap":
                ca_cert_pem = self.security.ca_cert_path.read_bytes()
                bootstrap = self._create_bootstrap_token(client_id)
                config["bootstrap"] = {
                    "enabled": True,
                    "token": bootstrap["token"],
                    "expires_at": bootstrap["expires_at"],
                    "enroll_url": self._build_bootstrap_enroll_url(server_ip),
                    "mode": "csr",
                }

                if self.server_instance:
                    self.server_instance._save_client_config(client_id, config)

                zip_buffer = self._create_bootstrap_client_zip(
                    client_id=client_id,
                    config=config,
                    ca_cert_pem=ca_cert_pem
                )

                return Response(
                    content=zip_buffer.getvalue(),
                    media_type="application/zip",
                    headers={
                        "Content-Disposition": f'attachment; filename="flamix-client-{client_id}.zip"',
                        "X-Flamix-Provisioning-Mode": "bootstrap",
                        "Access-Control-Expose-Headers": "Content-Disposition, X-Flamix-Provisioning-Mode",
                        "Cache-Control": "no-store",
                    }
                )

            try:
                cert, private_key, ca_cert_pem = self.security.generate_client_certificate(client_id)
                client_key_password = self.security.create_client_key_password()
                client_key_pem = self.security.export_client_private_key(private_key, client_key_password)
            except Exception as e:
                logger.error(f"Failed to generate client certificate: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=f"Failed to generate certificate: {str(e)}")

            if self.server_instance:
                self.server_instance._save_client_config(client_id, config)

            zip_buffer = self._create_client_zip(
                client_id=client_id,
                config=config,
                client_cert=cert,
                client_key_pem=client_key_pem,
                ca_cert_pem=ca_cert_pem
            )

            return Response(
                content=zip_buffer.getvalue(),
                media_type="application/zip",
                headers={
                    "Content-Disposition": f'attachment; filename="flamix-client-{client_id}.zip"',
                    "X-Flamix-Client-Key-Password": client_key_password,
                    "X-Flamix-Provisioning-Mode": "preissued",
                    "Access-Control-Expose-Headers": "Content-Disposition, X-Flamix-Client-Key-Password, X-Flamix-Provisioning-Mode",
                    "Cache-Control": "no-store",
                }
            )
        @self.app.get("/api/clients/{client_id}")
        async def get_client(client_id: str):
            """РџРѕР»СѓС‡РµРЅРёРµ РёРЅС„РѕСЂРјР°С†РёРё Рѕ РєР»РёРµРЅС‚Рµ"""
            client = self.db.execute(
                "SELECT * FROM clients WHERE id = ?",
                (client_id,)
            )
            if not client:
                raise HTTPException(status_code=404, detail="Client not found")
            return client[0] if isinstance(client, list) else client

        @self.app.get("/api/clients/{client_id}/package")
        async def get_client_package(
            client_id: str,
            server_ip: Optional[str] = None,
            certificate_ip: Optional[str] = None
        ):
            """
            РџРѕР»СѓС‡РµРЅРёРµ ZIP Р°СЂС…РёРІР° РґР»СЏ СЃСѓС‰РµСЃС‚РІСѓСЋС‰РµРіРѕ РєР»РёРµРЅС‚Р°
            
            Query РїР°СЂР°РјРµС‚СЂС‹:
            - server_ip (РѕРїС†РёРѕРЅР°Р»СЊРЅРѕ): IP Р°РґСЂРµСЃ СЃРµСЂРІРµСЂР° РґР»СЏ РєРѕРЅС„РёРіР° РєР»РёРµРЅС‚Р°
            - certificate_ip (РѕРїС†РёРѕРЅР°Р»СЊРЅРѕ): IP Р°РґСЂРµСЃ РґР»СЏ РІРєР»СЋС‡РµРЅРёСЏ РІ СЃРµСЂРІРµСЂРЅС‹Р№ СЃРµСЂС‚РёС„РёРєР°С‚
            """
            # РџСЂРѕРІРµСЂСЏРµРј СЃСѓС‰РµСЃС‚РІРѕРІР°РЅРёРµ РєР»РёРµРЅС‚Р°
            client = self.db.execute(
                "SELECT * FROM clients WHERE id = ?",
                (client_id,)
            )
            if not client:
                raise HTTPException(status_code=404, detail="Client not found")
            
            client_data = client[0] if isinstance(client, list) else client
            client_name = client_data.get('name', client_id)
            
            # РћР±РЅРѕРІР»СЏРµРј СЃРµСЂРІРµСЂРЅС‹Р№ СЃРµСЂС‚РёС„РёРєР°С‚ РµСЃР»Рё СѓРєР°Р·Р°РЅ certificate_ip
            if certificate_ip and self.security:
                try:
                    logger.info(f"Updating server certificate with IP {certificate_ip} as requested")
                    self.security.update_server_certificate_ip(certificate_ip)
                    logger.info("Server certificate updated. Note: server restart may be required for changes to take effect.")
                except Exception as e:
                    logger.error(f"Failed to update server certificate: {e}", exc_info=True)
                    raise HTTPException(status_code=500, detail=f"Failed to update server certificate: {str(e)}")
            
            # Р“РµРЅРµСЂРёСЂСѓРµРј СЃРµСЂС‚РёС„РёРєР°С‚С‹ (РёР»Рё РїРµСЂРµРёСЃРїРѕР»СЊР·СѓРµРј СЃСѓС‰РµСЃС‚РІСѓСЋС‰РёРµ)
            if not self.security:
                raise HTTPException(status_code=500, detail="Security module not initialized")
            
            try:
                cert, private_key, ca_cert_pem = self.security.generate_client_certificate(client_id)
                client_key_password = self.security.create_client_key_password()
                client_key_pem = self.security.export_client_private_key(private_key, client_key_password)
            except Exception as e:
                logger.error(f"Failed to generate client certificate: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=f"Failed to generate certificate: {str(e)}")
            
            # РћРїСЂРµРґРµР»СЏРµРј IP СЃРµСЂРІРµСЂР° (РёСЃРїРѕР»СЊР·СѓРµРј РїРµСЂРµРґР°РЅРЅС‹Р№ РёР»Рё РѕРїСЂРµРґРµР»СЏРµРј Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё)
            if server_ip:
                server_ip_for_config = server_ip
                logger.info(f"Using provided server IP for config: {server_ip_for_config}")
            else:
                server_ip_for_config = self.server_host
                if server_ip_for_config == "0.0.0.0":
                    # РџРѕР»СѓС‡Р°РµРј СЂРµР°Р»СЊРЅС‹Р№ IP РёР· РёРЅС‚РµСЂРЅРµС‚Р°
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.connect(("8.8.8.8", 80))
                        server_ip_for_config = s.getsockname()[0]
                        s.close()
                        logger.info(f"Auto-detected server IP from internet: {server_ip_for_config}")
                    except Exception as e:
                        logger.warning(f"Failed to detect server IP: {e}, using 127.0.0.1")
                        server_ip_for_config = "127.0.0.1"
            
            # РЎРѕР·РґР°РµРј РєРѕРЅС„РёРі
            config = {
                "client_id": client_id,
                "server_host": server_ip_for_config,
                "server_port": self.server_port,
                "cert_dir": "certs",
                "verify_ssl": True,  # РџСЂРѕРІРµСЂРєР° SSL СЃРµСЂС‚РёС„РёРєР°С‚Р° (РјРѕР¶РЅРѕ РѕС‚РєР»СЋС‡РёС‚СЊ РґР»СЏ СЂР°Р·СЂР°Р±РѕС‚РєРё)
                "sync_interval": 30,
                "monitor_interval": 10,
                "analytics_enabled": True,  # Р’РєР»СЋС‡РµРЅРѕ РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ РґР»СЏ СЃР±РѕСЂР° СЃС‚Р°С‚РёСЃС‚РёРєРё С‚СЂР°С„РёРєР°
                "analytics_interval": 5,  # 5 СЃРµРєСѓРЅРґ РґР»СЏ Р±РѕР»РµРµ С‡Р°СЃС‚РѕР№ РѕС‚РїСЂР°РІРєРё РѕР±С‹С‡РЅС‹С… СЃРѕР±С‹С‚РёР№
                "traffic_collection_interval": 5,  # 5 СЃРµРєСѓРЅРґ РґР»СЏ СЃР±РѕСЂР° СЃС‚Р°С‚РёСЃС‚РёРєРё С‚СЂР°С„РёРєР° РІ СЂРµР°Р»СЊРЅРѕРј РІСЂРµРјРµРЅРё
                "config_sync_interval": 300,  # РРЅС‚РµСЂРІР°Р» СЃРёРЅС…СЂРѕРЅРёР·Р°С†РёРё РєРѕРЅС„РёРіР° (5 РјРёРЅСѓС‚)
                # РќР°СЃС‚СЂРѕР№РєРё РёРЅС‚РµСЂС„РµР№СЃР° (РµСЃР»Рё РєР»РёРµРЅС‚ РёРјРµРµС‚ GUI)
                "font": "default",
                "font_size": 13,
                "ui_theme": "default"
            }
            
            # РЎРѕС…СЂР°РЅСЏРµРј РєРѕРЅС„РёРі РІ Р‘Р” (РµСЃР»Рё РµСЃС‚СЊ РґРѕСЃС‚СѓРї Рє server_instance)
            if self.server_instance:
                self.server_instance._save_client_config(client_id, config)
            
            # РЎРѕР·РґР°РµРј ZIP Р°СЂС…РёРІ
            zip_buffer = self._create_client_zip(
                client_id=client_id,
                config=config,
                client_cert=cert,
                client_key_pem=client_key_pem,
                ca_cert_pem=ca_cert_pem
            )
            
            return Response(
                content=zip_buffer.getvalue(),
                media_type="application/zip",
                headers={
                    "Content-Disposition": f'attachment; filename="flamix-client-{client_id}.zip"',
                    "X-Flamix-Client-Key-Password": client_key_password,
                    "Access-Control-Expose-Headers": "Content-Disposition, X-Flamix-Client-Key-Password",
                    "Cache-Control": "no-store",
                }
            )

        @self.app.delete("/api/clients/{client_id}")
        async def delete_client(client_id: str):
            """РЈРґР°Р»РµРЅРёРµ РєР»РёРµРЅС‚Р° Рё РІСЃРµС… СЃРІСЏР·Р°РЅРЅС‹С… РґР°РЅРЅС‹С…"""
            # РџСЂРѕРІРµСЂСЏРµРј СЃСѓС‰РµСЃС‚РІРѕРІР°РЅРёРµ РєР»РёРµРЅС‚Р°
            client = self.db.execute_one(
                "SELECT * FROM clients WHERE id = ?",
                (client_id,)
            )
            if not client:
                logger.warning(f"Client {client_id} not found for deletion")
                raise HTTPException(status_code=404, detail="Client not found")
            
            try:
                # РЈРґР°Р»СЏРµРј checksums РґР»СЏ РїСЂР°РІРёР» РєР»РёРµРЅС‚Р° (РѕРЅРё РЅРµ РёРјРµСЋС‚ CASCADE)
                self.db.execute_delete(
                    "DELETE FROM rule_checksums WHERE client_id = ?",
                    (client_id,)
                )
                
                # РЈРґР°Р»СЏРµРј РєР»РёРµРЅС‚Р° РёР· Р‘Р”
                # РЎРІСЏР·Р°РЅРЅС‹Рµ РґР°РЅРЅС‹Рµ (РїСЂР°РІРёР»Р°, СЃРµСЃСЃРёРё, РёСЃС‚РѕСЂРёСЏ, Р·Р°РїСЂРѕСЃС‹) СѓРґР°Р»СЏС‚СЃСЏ Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё
                # Р±Р»Р°РіРѕРґР°СЂСЏ FOREIGN KEY СЃ ON DELETE CASCADE
                rows_deleted = self.db.execute_delete(
                    "DELETE FROM clients WHERE id = ?",
                    (client_id,)
                )
                
                if rows_deleted == 0:
                    logger.warning(f"Failed to delete client {client_id}: no rows affected")
                    raise HTTPException(status_code=404, detail="Client not found")
                
                logger.info(f"Deleted client {client_id} and all related data")
                return {"success": True, "message": f"Client {client_id} deleted successfully"}
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Failed to delete client {client_id}: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=f"Failed to delete client: {str(e)}")

        @self.app.get("/api/clients/{client_id}/rules")
        async def get_client_rules(client_id: str):
            """РџРѕР»СѓС‡РµРЅРёРµ РїСЂР°РІРёР» РєР»РёРµРЅС‚Р°"""
            rules = self.rule_manager.get_all_rules(client_id)
            return {"rules": [rule.to_dict() for rule in rules]}

        @self.app.post("/api/rules")
        async def create_rule(rule_data: dict):
            """РЎРѕР·РґР°РЅРёРµ РїСЂР°РІРёР»Р°"""
            try:
                rule = FirewallRule.from_dict(rule_data)
                client_id = rule_data.get('client_id')
                if not client_id:
                    raise HTTPException(status_code=400, detail="client_id is required")

                review = self.rule_authorization.review_rule_change(
                    client_id=client_id,
                    rule_id=rule.id,
                    old_rule=None,
                    new_rule=rule,
                    change_source="api",
                )

                if not review.allowed:
                    if review.status == "pending":
                        return JSONResponse(
                            status_code=202,
                            content={
                                "success": False,
                                "pending": True,
                                "rule_id": rule.id,
                                "rule_name": rule.name,
                                "request_id": review.request_id,
                                "reason": review.reason,
                                "warnings": review.warnings,
                                "limitations": review.limitations,
                            },
                        )
                    raise HTTPException(status_code=409, detail=review.to_dict())

                rule_id = self.rule_manager.add_rule(client_id, rule)
                return {
                    "rule_id": rule_id,
                    "success": True,
                    "warnings": review.warnings,
                    "limitations": review.limitations,
                }
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.app.put("/api/rules/{rule_id}")
        async def update_rule(rule_id: str, rule_data: dict):
            """РћР±РЅРѕРІР»РµРЅРёРµ РїСЂР°РІРёР»Р°"""
            try:
                rule = FirewallRule.from_dict(rule_data)
                rule.id = rule_id
                client_id = rule_data.get('client_id')
                if not client_id:
                    raise HTTPException(status_code=400, detail="client_id is required")

                existing_rule = self.rule_manager.get_rule(client_id, rule_id)
                if not existing_rule:
                    raise HTTPException(status_code=404, detail="Rule not found")

                review = self.rule_authorization.review_rule_change(
                    client_id=client_id,
                    rule_id=rule_id,
                    old_rule=existing_rule,
                    new_rule=rule,
                    change_source="api",
                )

                if not review.allowed:
                    if review.status == "pending":
                        return JSONResponse(
                            status_code=202,
                            content={
                                "success": False,
                                "pending": True,
                                "rule_id": rule.id,
                                "rule_name": rule.name,
                                "request_id": review.request_id,
                                "reason": review.reason,
                                "warnings": review.warnings,
                                "limitations": review.limitations,
                            },
                        )
                    raise HTTPException(status_code=409, detail=review.to_dict())

                success = self.rule_manager.update_rule(client_id, rule)
                if not success:
                    raise HTTPException(status_code=404, detail="Rule not found")
                return {
                    "success": True,
                    "warnings": review.warnings,
                    "limitations": review.limitations,
                }
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.app.delete("/api/rules/{rule_id}")
        async def delete_rule(rule_id: str, client_id: str):
            """РЈРґР°Р»РµРЅРёРµ РїСЂР°РІРёР»Р°"""
            success = self.rule_manager.delete_rule(client_id, rule_id)
            if not success:
                raise HTTPException(status_code=404, detail="Rule not found")
            return {"success": True}

        @self.app.get("/api/analytics")
        async def get_analytics(
            client_id: Optional[str] = None,
            limit: int = 1000
        ):
            """РџРѕР»СѓС‡РµРЅРёРµ Р°РЅР°Р»РёС‚РёРєРё"""
            query = "SELECT * FROM analytics WHERE 1=1"
            params = []
            if client_id:
                query += " AND client_id = ?"
                params.append(client_id)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            analytics = self.db.execute(query, tuple(params))
            return {"analytics": analytics}

        @self.app.get("/api/rules/diff")
        async def get_rules_diff(client_id1: str, client_id2: str):
            """РЎСЂР°РІРЅРµРЅРёРµ РїСЂР°РІРёР» РјРµР¶РґСѓ РєР»РёРµРЅС‚Р°РјРё"""
            diff = self.rule_manager.compare_rules(client_id1, client_id2)
            return diff

        @self.app.get("/api/change-requests")
        async def get_change_requests(status: Optional[str] = None):
            """РџРѕР»СѓС‡РµРЅРёРµ Р·Р°РїСЂРѕСЃРѕРІ РЅР° РёР·РјРµРЅРµРЅРёРµ"""
            query = "SELECT * FROM rule_change_requests WHERE 1=1"
            params = []
            if status:
                query += " AND status = ?"
                params.append(status)
            query += " ORDER BY requested_at DESC"

            requests = self.db.execute(query, tuple(params))
            return {"requests": requests}

        @self.app.post("/api/change-requests/{request_id}/approve")
        async def approve_request(request_id: str, reviewer: str = "admin"):
            """РћРґРѕР±СЂРµРЅРёРµ Р·Р°РїСЂРѕСЃР° РЅР° РёР·РјРµРЅРµРЅРёРµ"""
            success, reason = self.rule_authorization.approve_request(request_id, reviewer)
            if not success:
                raise HTTPException(status_code=409, detail=reason or "Request not found")
            return {"success": True}

        @self.app.post("/api/change-requests/{request_id}/reject")
        async def reject_request(request_id: str, reason: str, reviewer: str = "admin"):
            """РћС‚РєР»РѕРЅРµРЅРёРµ Р·Р°РїСЂРѕСЃР° РЅР° РёР·РјРµРЅРµРЅРёРµ"""
            success = self.rule_authorization.reject_request(request_id, reviewer, reason)
            if not success:
                raise HTTPException(status_code=404, detail="Request not found")
            return {"success": True}

        @self.app.get("/api/clients/{client_id}/config")
        async def get_client_config(client_id: str):
            """РџРѕР»СѓС‡РµРЅРёРµ РєРѕРЅС„РёРіСѓСЂР°С†РёРё РєР»РёРµРЅС‚Р°"""
            if not self.server_instance:
                raise HTTPException(status_code=500, detail="Server instance not available")
            
            config = self.server_instance._get_client_config(client_id)
            if config:
                return {"success": True, "config": config}
            else:
                return {"success": False, "message": "Config not found"}

        @self.app.put("/api/clients/{client_id}/config")
        async def update_client_config(client_id: str, config_data: dict):
            """РћР±РЅРѕРІР»РµРЅРёРµ РєРѕРЅС„РёРіСѓСЂР°С†РёРё РєР»РёРµРЅС‚Р°"""
            if not self.server_instance:
                raise HTTPException(status_code=500, detail="Server instance not available")
            
            try:
                # Р’Р°Р»РёРґР°С†РёСЏ РєРѕРЅС„РёРіР°
                required_fields = ["client_id", "server_host", "server_port"]
                for field in required_fields:
                    if field not in config_data:
                        raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
                
                # РЈР±РµР¶РґР°РµРјСЃСЏ, С‡С‚Рѕ client_id СЃРѕРІРїР°РґР°РµС‚
                if config_data.get("client_id") != client_id:
                    config_data["client_id"] = client_id
                
                # РЎРѕС…СЂР°РЅСЏРµРј РєРѕРЅС„РёРі РІ Р‘Р”
                self.server_instance._save_client_config(client_id, config_data)
                
                # РћС‚РїСЂР°РІР»СЏРµРј РѕР±РЅРѕРІР»РµРЅРёРµ РєР»РёРµРЅС‚Сѓ, РµСЃР»Рё РѕРЅ РїРѕРґРєР»СЋС‡РµРЅ
                sent = await self.server_instance.send_config_update(client_id, config_data)
                
                return {
                    "success": True,
                    "message": f"Config updated. {'Sent to client.' if sent else 'Client not connected, will receive on next sync.'}"
                }
            except Exception as e:
                logger.error(f"Error updating client config: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=f"Failed to update config: {str(e)}")

        @self.app.get("/api/traffic/summary")
        async def get_traffic_summary(
            client_id: Optional[str] = None,
            period: str = "24h"
        ):
            """РџРѕР»СѓС‡РµРЅРёРµ Р°РіСЂРµРіРёСЂРѕРІР°РЅРЅРѕР№ СЃС‚Р°С‚РёСЃС‚РёРєРё С‚СЂР°С„РёРєР°"""
            try:
                summary = self.traffic_analytics.get_traffic_summary(client_id, period)
                return summary
            except Exception as e:
                logger.error(f"Error getting traffic summary: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/traffic/timeline")
        async def get_traffic_timeline(
            client_id: Optional[str] = None,
            interval: str = "1m",
            period: str = "1h"
        ):
            """РџРѕР»СѓС‡РµРЅРёРµ РІСЂРµРјРµРЅРЅРѕР№ СЃРµСЂРёРё С‚СЂР°С„РёРєР°"""
            try:
                timeline = self.traffic_analytics.get_time_series(client_id, interval, period)
                return timeline
            except Exception as e:
                logger.error(f"Error getting traffic timeline: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/traffic/top-ips")
        async def get_top_ips(
            client_id: Optional[str] = None,
            limit: int = 20,
            period: str = "24h"
        ):
            """РџРѕР»СѓС‡РµРЅРёРµ С‚РѕРї IP Р°РґСЂРµСЃРѕРІ РїРѕ РѕР±СЉРµРјСѓ С‚СЂР°С„РёРєР°"""
            try:
                summary = self.traffic_analytics.get_traffic_summary(client_id, period)
                top_src = dict(list(summary.get('top_source_ips', {}).items())[:limit])
                top_dst = dict(list(summary.get('top_destination_ips', {}).items())[:limit])
                return {
                    "top_source_ips": top_src,
                    "top_destination_ips": top_dst,
                    "period": period
                }
            except Exception as e:
                logger.error(f"Error getting top IPs: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/traffic/ip/{ip}")
        async def get_ip_details(
            ip: str,
            client_id: Optional[str] = None,
            period: str = "24h"
        ):
            """РџРѕР»СѓС‡РµРЅРёРµ РґРµС‚Р°Р»СЊРЅРѕР№ СЃС‚Р°С‚РёСЃС‚РёРєРё РїРѕ IP Р°РґСЂРµСЃСѓ"""
            try:
                details = self.traffic_analytics.get_ip_details(client_id, ip, period)
                return details
            except Exception as e:
                logger.error(f"Error getting IP details: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/traffic/bandwidth")
        async def get_bandwidth_stats(
            client_id: Optional[str] = None,
            period: str = "1h"
        ):
            """РџРѕР»СѓС‡РµРЅРёРµ СЃС‚Р°С‚РёСЃС‚РёРєРё РїСЂРѕРїСѓСЃРєРЅРѕР№ СЃРїРѕСЃРѕР±РЅРѕСЃС‚Рё"""
            try:
                stats = self.traffic_analytics.get_bandwidth_stats(client_id, period)
                return stats
            except Exception as e:
                logger.error(f"Error getting bandwidth stats: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/traffic/anomalies")
        async def get_anomalies(
            client_id: Optional[str] = None,
            period: str = "24h"
        ):
            """РћР±РЅР°СЂСѓР¶РµРЅРёРµ Р°РЅРѕРјР°Р»РёР№ РІ С‚СЂР°С„РёРєРµ"""
            try:
                anomalies = self.traffic_analytics.detect_anomalies(client_id, period)
                return {"anomalies": anomalies, "count": len(anomalies)}
            except Exception as e:
                logger.error(f"Error detecting anomalies: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/clients/{client_id}/status")
        async def get_client_status(client_id: str, limit: int = 100):
            """РџРѕР»СѓС‡РµРЅРёРµ СЃРёСЃС‚РµРјРЅРѕРіРѕ СЃС‚Р°С‚СѓСЃР° РєР»РёРµРЅС‚Р°"""
            try:
                statuses = self.db.execute(
                    """
                    SELECT * FROM client_system_status 
                    WHERE client_id = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                    """,
                    (client_id, limit)
                )
                return {"statuses": statuses}
            except Exception as e:
                logger.error(f"Error getting client status: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/clients/{client_id}/status/latest")
        async def get_client_status_latest(client_id: str):
            """РџРѕР»СѓС‡РµРЅРёРµ РїРѕСЃР»РµРґРЅРµРіРѕ СЃРёСЃС‚РµРјРЅРѕРіРѕ СЃС‚Р°С‚СѓСЃР° РєР»РёРµРЅС‚Р°"""
            try:
                status = self.db.execute_one(
                    """
                    SELECT * FROM client_system_status 
                    WHERE client_id = ? 
                    ORDER BY timestamp DESC 
                    LIMIT 1
                    """,
                    (client_id,)
                )
                if not status:
                    raise HTTPException(status_code=404, detail="No status found for client")
                return status
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Error getting latest client status: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/clients/{client_id}/plugins")
        async def get_client_plugins(client_id: str):
            """РџРѕР»СѓС‡РµРЅРёРµ СЃС‚Р°С‚СѓСЃР° РїР»Р°РіРёРЅРѕРІ РєР»РёРµРЅС‚Р° РёР· РїРѕСЃР»РµРґРЅРµРіРѕ СЃРёСЃС‚РµРјРЅРѕРіРѕ СЃС‚Р°С‚СѓСЃР°"""
            try:
                status = self.db.execute_one(
                    """
                    SELECT plugins_status FROM client_system_status 
                    WHERE client_id = ? 
                    ORDER BY timestamp DESC 
                    LIMIT 1
                    """,
                    (client_id,)
                )
                if not status or not status.get('plugins_status'):
                    return {"plugins": []}
                
                plugins = json.loads(status['plugins_status'])
                return {"plugins": plugins}
            except Exception as e:
                logger.error(f"Error getting client plugins: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/clients/{client_id}/logs")
        async def get_client_logs(
            client_id: str,
            level: Optional[str] = None,
            limit: int = 1000,
            since: Optional[str] = None
        ):
            """РџРѕР»СѓС‡РµРЅРёРµ Р»РѕРіРѕРІ РєР»РёРµРЅС‚Р°"""
            try:
                query = "SELECT * FROM client_logs WHERE client_id = ?"
                params = [client_id]
                
                if level:
                    query += " AND level = ?"
                    params.append(level)
                
                if since:
                    query += " AND timestamp >= ?"
                    params.append(since)
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                logs = self.db.execute(query, tuple(params))
                return {"logs": logs}
            except Exception as e:
                logger.error(f"Error getting client logs: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/monitoring/overview")
        async def get_monitoring_overview():
            """РџРѕР»СѓС‡РµРЅРёРµ РѕР±Р·РѕСЂР° РјРѕРЅРёС‚РѕСЂРёРЅРіР° РІСЃРµС… РєР»РёРµРЅС‚РѕРІ"""
            try:
                # Get latest status for each client
                clients = self.db.execute("SELECT id, name FROM clients WHERE enabled = 1")
                logger.debug(f"Monitoring overview: found {len(clients)} enabled clients")
                overview = []
                
                for client in clients:
                    client_id = client['id']
                    latest_status = self.db.execute_one(
                        """
                        SELECT cpu_percent, memory_percent, disk_usage, timestamp, os_info
                        FROM client_system_status 
                        WHERE client_id = ? 
                        ORDER BY timestamp DESC 
                        LIMIT 1
                        """,
                        (client_id,)
                    )
                    
                    # Calculate disk usage from first partition if available
                    disk_percent = None
                    if latest_status and latest_status.get('disk_usage'):
                        try:
                            disk_data = json.loads(latest_status['disk_usage'])
                            if disk_data.get('partitions'):
                                # Get first partition's percent
                                first_partition = list(disk_data['partitions'].values())[0]
                                disk_percent = first_partition.get('percent')
                        except Exception:
                            pass
                    
                    # Check if client is online (status from last 2 minutes)
                    is_online = False
                    if latest_status:
                        from datetime import datetime, timedelta
                        try:
                            status_time = datetime.fromisoformat(latest_status['timestamp'].replace('Z', '+00:00'))
                            if (datetime.now(status_time.tzinfo) - status_time) < timedelta(minutes=2):
                                is_online = True
                        except Exception:
                            pass
                    
                    overview.append({
                        "client_id": client_id,
                        "client_name": client.get('name', client_id),
                        "cpu_percent": latest_status.get('cpu_percent') if latest_status else None,
                        "memory_percent": latest_status.get('memory_percent') if latest_status else None,
                        "disk_percent": disk_percent,
                        "is_online": is_online,
                        "last_seen": latest_status.get('timestamp') if latest_status else None,
                        "os_info": json.loads(latest_status['os_info']) if latest_status and latest_status.get('os_info') else None
                    })
                
                return {"clients": overview}
            except Exception as e:
                logger.error(f"Error getting monitoring overview: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))

    def run(self, cert_dir: Optional[Path] = None):
        """
        Р—Р°РїСѓСЃРє РІРµР±-СЃРµСЂРІРµСЂР°
        
        Args:
            cert_dir: Р”РёСЂРµРєС‚РѕСЂРёСЏ СЃ СЃРµСЂС‚РёС„РёРєР°С‚Р°РјРё (РѕРїС†РёРѕРЅР°Р»СЊРЅРѕ)
        """
        import uvicorn
        
        # РќР°СЃС‚СЂР°РёРІР°РµРј РѕР±СЂР°Р±РѕС‚РєСѓ РѕС€РёР±РѕРє СЃРѕРµРґРёРЅРµРЅРёР№ РґР»СЏ Windows
        _suppress_connection_reset_error()
        
        # РџСЂРѕРІРµСЂСЏРµРј РЅР°Р»РёС‡РёРµ СЃРµСЂС‚РёС„РёРєР°С‚РѕРІ
        use_ssl = False
        ssl_keyfile = None
        ssl_certfile = None
        
        if cert_dir:
            cert_dir = Path(cert_dir)
            server_cert = cert_dir / "server.crt"
            server_key = cert_dir / "server.key"
            
            if server_cert.exists() and server_key.exists():
                use_ssl = True
                ssl_certfile = str(server_cert.resolve())
                ssl_keyfile = str(server_key.resolve())
                logger.info(f"Using SSL certificates: {ssl_certfile}")
                logger.info(f"Web interface available at: https://{self.host}:{self.port}")
            else:
                logger.warning(
                    f"SSL certificates not found in {cert_dir}. "
                    f"Starting web interface without SSL (HTTP only)."
                )
                logger.info(f"Web interface available at: http://{self.host}:{self.port}")
        else:
            logger.warning(
                "No certificate directory provided. "
                "Starting web interface without SSL (HTTP only)."
            )
            logger.info(f"Web interface available at: http://{self.host}:{self.port}")
        
        # Р—Р°РїСѓСЃРє uvicorn СЃРµСЂРІРµСЂР°
        # РСЃРїРѕР»СЊР·СѓРµРј uvicorn.run() РєРѕС‚РѕСЂС‹Р№ РїСЂР°РІРёР»СЊРЅРѕ СЂР°Р±РѕС‚Р°РµС‚ РІ РѕС‚РґРµР»СЊРЅРѕРј РїРѕС‚РѕРєРµ
        try:
            # РќР°СЃС‚СЂРѕР№РєРё РґР»СЏ РїСЂРµРґРѕС‚РІСЂР°С‰РµРЅРёСЏ РѕС€РёР±РѕРє СЃРѕРµРґРёРЅРµРЅРёР№ РЅР° Windows
            uvicorn_config = {
                "app": self.app,
                "host": self.host,
                "port": self.port,
                "log_level": "info",
                "access_log": True,
                "timeout_keep_alive": 5,  # РўР°Р№РјР°СѓС‚ РґР»СЏ keep-alive СЃРѕРµРґРёРЅРµРЅРёР№
                "timeout_graceful_shutdown": 5,  # РўР°Р№РјР°СѓС‚ РґР»СЏ graceful shutdown
            }
            
            if use_ssl:
                logger.info(f"Starting web interface with SSL on https://{self.host}:{self.port}")
                uvicorn_config["ssl_keyfile"] = ssl_keyfile
                uvicorn_config["ssl_certfile"] = ssl_certfile
                if self.security:
                    uvicorn_config["ssl_keyfile_password"] = (
                        self.security._get_private_key_password(
                            self.security.SERVER_KEY_PASSWORD_NAME
                        ).decode("utf-8")
                    )
            else:
                logger.info(f"Starting web interface without SSL on http://{self.host}:{self.port}")
            
            uvicorn.run(**uvicorn_config)
        except Exception as e:
            logger.error(f"Error running web server: {e}", exc_info=True)
            raise




