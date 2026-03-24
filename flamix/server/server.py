"""Р“Р»Р°РІРЅС‹Р№ СЃРµСЂРІРµСЂ Flamix"""

import asyncio
import json
import logging
import os
import platform
import socket
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Any, Dict, Mapping

from flamix.database.encrypted_db import EncryptedDB
from flamix.server.runtime_config import ServerRuntimeConfig, load_runtime_config
from flamix.server.protocol import ServerProtocol
from flamix.server.client_manager import ClientManager
from flamix.server.rule_manager import RuleManager
from flamix.server.security import ServerSecurity
from flamix.server.rule_authorization import RuleAuthorization
from flamix.server.web_api import WebAPI
from flamix.common.protocol_types import MessageType, ProtocolMessage
from flamix.common.rule_format import FirewallRule

logger = logging.getLogger(__name__)


class FlamixServer:
    """Р“Р»Р°РІРЅС‹Р№ СЃРµСЂРІРµСЂ Flamix"""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8443,
        db_path: Path = None,
        cert_dir: Path = None,
        web_enabled: bool = True,
        web_host: str = "127.0.0.1",
        web_port: int = 8080,
        runtime_config: Optional[ServerRuntimeConfig] = None
    ):
        """
        РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ СЃРµСЂРІРµСЂР°

        Args:
            host: РҐРѕСЃС‚ РґР»СЏ РїСЂРѕСЃР»СѓС€РёРІР°РЅРёСЏ
            port: РџРѕСЂС‚ РґР»СЏ РїСЂРѕСЃР»СѓС€РёРІР°РЅРёСЏ
            db_path: РџСѓС‚СЊ Рє Р±Р°Р·Рµ РґР°РЅРЅС‹С…
            cert_dir: Р”РёСЂРµРєС‚РѕСЂРёСЏ СЃ СЃРµСЂС‚РёС„РёРєР°С‚Р°РјРё
            web_enabled: Р’РєР»СЋС‡РёС‚СЊ Р»Рё РІРµР±-РёРЅС‚РµСЂС„РµР№СЃ
            web_host: РҐРѕСЃС‚ РґР»СЏ РІРµР±-РёРЅС‚РµСЂС„РµР№СЃР°
            web_port: РџРѕСЂС‚ РґР»СЏ РІРµР±-РёРЅС‚РµСЂС„РµР№СЃР°
        """
        self.runtime_config = runtime_config or ServerRuntimeConfig(
            server_host=host,
            server_port=port,
            db_path=Path(db_path or "data/server.db"),
            cert_dir=Path(cert_dir or "certs"),
            web_enabled=web_enabled,
            web_host=web_host,
            web_port=web_port,
        )
        self.host = self.runtime_config.server_host
        self.port = self.runtime_config.server_port
        self.db_path = self.runtime_config.db_path
        self.cert_dir = self.runtime_config.cert_dir
        self.web_enabled = self.runtime_config.web_enabled
        self.web_host = self.runtime_config.web_host
        self.web_port = self.runtime_config.web_port
        self.running = False
        self.server: Optional[asyncio.Server] = None
        self.web_api: Optional[WebAPI] = None
        self.started_at: Optional[datetime] = None
        self._last_retention_cleanup: Optional[datetime] = None

        # РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ РєРѕРјРїРѕРЅРµРЅС‚РѕРІ
        self.db = EncryptedDB(self.db_path)
        self.security = ServerSecurity(self.cert_dir)
        self.client_manager = ClientManager(self.db)
        self.rule_manager = RuleManager(self.db)
        self.rule_authorization = RuleAuthorization(self.db, self.rule_manager)
        
        # РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ РІРµР±-РёРЅС‚РµСЂС„РµР№СЃР°
        if self.web_enabled:
            self.web_api = WebAPI(
                rule_manager=self.rule_manager,
                rule_authorization=self.rule_authorization,
                db=self.db,
                host=self.web_host,
                port=self.web_port,
                security=self.security,
                server_host=self.host,
                server_port=self.port,
                cert_dir=self.cert_dir,
                runtime_config=self.runtime_config,
                server_instance=self
            )

    def get_effective_config(self) -> Dict[str, Any]:
        """Return the current active runtime configuration."""
        return self.runtime_config.to_public_dict()

    def get_stored_config(self) -> Optional[Dict[str, Any]]:
        """Return the persisted runtime config if it exists."""
        config_path = self.runtime_config.config_path
        if not config_path.exists():
            return None
        return ServerRuntimeConfig.from_file(config_path, base=self.runtime_config).to_public_dict()

    def save_runtime_config(self, path: Optional[Path] = None, config: Optional[ServerRuntimeConfig] = None) -> Path:
        """Persist a runtime configuration snapshot."""
        target_config = config or self.runtime_config
        return target_config.save(path or target_config.config_path)

    def update_runtime_config(self, patch: Mapping[str, Any], persist: bool = True) -> Dict[str, Any]:
        """
        Update runtime configuration and persist the merged snapshot.

        Interval and retention knobs are live-applied; network and path changes
        are stored for the next restart and reported to the caller.
        """
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
            self.save_runtime_config(config=updated_config)

        return {
            "config": self.get_effective_config(),
            "stored_config": self.get_stored_config(),
            "changed_fields": list(changes.keys()),
            "applied_live": applied_live,
            "restart_required": bool(restart_required_fields),
            "restart_required_fields": restart_required_fields,
        }

    def _detect_server_ip(self) -> str:
        """Best-effort advertised IP for diagnostics."""
        if self.host and self.host not in {"0.0.0.0", "::"}:
            return self.host
        try:
            from flamix.server.security import get_server_ip_address
            return get_server_ip_address(self.host)
        except Exception:
            return "127.0.0.1"

    def get_server_info(self) -> Dict[str, Any]:
        """Build a diagnostics snapshot for API consumers."""
        certificate_info = {}
        if self.security:
            certificate_info = self.security.get_certificate_info()

        try:
            active_clients = self.db.execute_one("SELECT COUNT(*) AS count FROM clients")
        except Exception:
            active_clients = None

        try:
            active_sessions = self.db.execute_one("SELECT COUNT(*) AS count FROM client_sessions")
        except Exception:
            active_sessions = None

        uptime_seconds = None
        if self.started_at:
            uptime_seconds = int((datetime.utcnow() - self.started_at).total_seconds())

        return {
            "name": "Flamix Server",
            "running": self.running,
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "started_at": self.started_at.isoformat() + "Z" if self.started_at else None,
            "uptime_seconds": uptime_seconds,
            "listen": {
                "host": self.host,
                "port": self.port,
                "advertised_host": self._detect_server_ip(),
            },
            "web": {
                "enabled": self.web_enabled,
                "host": self.web_host,
                "port": self.web_port,
            },
            "paths": {
                "db_path": str(self.db_path),
                "cert_dir": str(self.cert_dir),
                "log_dir": str(self.runtime_config.log_dir),
                "config_path": str(self.runtime_config.config_path),
            },
            "counts": {
                "clients": active_clients.get("count", 0) if active_clients else 0,
                "sessions": active_sessions.get("count", 0) if active_sessions else 0,
            },
            "certificate": certificate_info,
            "bootstrap": {
                "gui_bundle_path": str(self.cert_dir / "flamix-gui-connection.zip"),
            },
            "features": {
                "require_client_cert": self.runtime_config.require_client_cert,
                "persist_runtime_config": self.runtime_config.persist_runtime_config,
            },
            "runtime": self.get_effective_config(),
        }

    def get_health_report(self) -> Dict[str, Any]:
        """Return a health/status payload suitable for API endpoints."""
        checks: Dict[str, Dict[str, Any]] = {}

        checks["server"] = {
            "ok": bool(self.running and self.server is not None),
            "host": self.host,
            "port": self.port,
        }

        try:
            self.db.execute_one("SELECT 1 AS ok")
            checks["database"] = {"ok": True, "path": str(self.db_path)}
        except Exception as exc:
            checks["database"] = {"ok": False, "error": str(exc), "path": str(self.db_path)}

        try:
            certificate_info = self.security.get_certificate_info() if self.security else {}
            checks["certificates"] = {
                "ok": "error" not in certificate_info,
                "info": certificate_info,
            }
        except Exception as exc:
            checks["certificates"] = {"ok": False, "error": str(exc)}

        checks["web"] = {
            "ok": bool((not self.web_enabled) or self.web_api is not None),
            "enabled": self.web_enabled,
            "host": self.web_host,
            "port": self.web_port,
        }

        checks["runtime"] = {
            "ok": True,
            "periodic_task_interval_seconds": self.runtime_config.periodic_task_interval_seconds,
            "session_timeout_seconds": self.runtime_config.session_timeout_seconds,
        }

        overall_ok = all(check.get("ok", False) for check in checks.values())
        if overall_ok:
            status = "ok"
        elif checks["server"]["ok"] and checks["database"]["ok"]:
            status = "degraded"
        else:
            status = "unhealthy"

        uptime_seconds = None
        if self.started_at:
            uptime_seconds = int((datetime.utcnow() - self.started_at).total_seconds())

        return {
            "status": status,
            "checks": checks,
            "started_at": self.started_at.isoformat() + "Z" if self.started_at else None,
            "uptime_seconds": uptime_seconds,
            "config": self.get_effective_config(),
        }

    async def start(self):
        """Р—Р°РїСѓСЃРє СЃРµСЂРІРµСЂР°"""
        logger.info("Starting Flamix server...")

        # РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ Р‘Р”
        self.db.initialize()

        # Р“РµРЅРµСЂР°С†РёСЏ СЃРµСЂС‚РёС„РёРєР°С‚РѕРІ РґР»СЏ РєР»РёРµРЅС‚СЃРєРёС… РїРѕРґРєР»СЋС‡РµРЅРёР№ (TLS)
        # РњРµС‚РѕРґС‹ generate_ca() Рё generate_server_cert() Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё РїСЂРѕРІРµСЂСЏСЋС‚
        # РЅР°Р»РёС‡РёРµ С„Р°Р№Р»РѕРІ Рё СЃРѕР·РґР°СЋС‚ С‚РѕР»СЊРєРѕ РµСЃР»Рё РёС… РЅРµС‚ (РЅРµ РїРµСЂРµСЃРѕР·РґР°СЋС‚!)
        logger.info("Checking certificates for client connections...")
        self.security.generate_ca()  # РЎРѕР·РґР°СЃС‚ С‚РѕР»СЊРєРѕ РµСЃР»Рё РЅРµС‚
        
        # РћРїСЂРµРґРµР»СЏРµРј IP Р°РґСЂРµСЃ СЃРµСЂРІРµСЂР° РґР»СЏ РІРєР»СЋС‡РµРЅРёСЏ РІ СЃРµСЂС‚РёС„РёРєР°С‚
        from flamix.server.security import get_server_ip_address
        server_ip = get_server_ip_address(self.host)
        logger.info(f"Server IP address: {server_ip}")
        
        server_cert, _ = self.security.generate_server_cert(server_ip=server_ip)  # РЎРѕР·РґР°СЃС‚ С‚РѕР»СЊРєРѕ РµСЃР»Рё РЅРµС‚
        
        # Р’С‹РІРѕРґРёРј РёРЅС„РѕСЂРјР°С†РёСЋ Рѕ СЃРµСЂС‚РёС„РёРєР°С‚Рµ
        cert_info = self.security.get_certificate_info()
        logger.info(f"Server certificate info: {cert_info}")
        
        logger.info("Certificates ready (existing certificates are reused, not regenerated)")
        if self.web_api:
            try:
                bundle_path = self.web_api.ensure_gui_connection_bundle(force=True)
                logger.info("GUI connection bundle available at %s", bundle_path)
            except Exception as exc:
                logger.warning("Failed to prepare GUI connection bundle: %s", exc)

        # РЎРѕР·РґР°РЅРёРµ SSL РєРѕРЅС‚РµРєСЃС‚Р° РґР»СЏ РєР»РёРµРЅС‚СЃРєРёС… РїРѕРґРєР»СЋС‡РµРЅРёР№
        # (РІРµР±-РёРЅС‚РµСЂС„РµР№СЃ РёСЃРїРѕР»СЊР·СѓРµС‚ СЃРІРѕСЋ Р»РѕРіРёРєСѓ)
        ssl_context = self.security.create_ssl_context(require_client_cert=True)

        # Р—Р°РїСѓСЃРє СЃРµСЂРІРµСЂР°
        self.server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port,
            ssl=ssl_context
        )

        self.running = True
        self.started_at = datetime.utcnow()
        logger.info(f"Server started on {self.host}:{self.port}")

        # Р—Р°РїСѓСЃРє РІРµР±-РёРЅС‚РµСЂС„РµР№СЃР° РµСЃР»Рё РІРєР»СЋС‡РµРЅ
        if self.web_enabled and self.web_api:
            import threading
            import time
            
            def start_web():
                """Р—Р°РїСѓСЃРє РІРµР±-РёРЅС‚РµСЂС„РµР№СЃР° РІ РѕС‚РґРµР»СЊРЅРѕРј РїРѕС‚РѕРєРµ"""
                # РќРµР±РѕР»СЊС€Р°СЏ Р·Р°РґРµСЂР¶РєР°, С‡С‚РѕР±С‹ РѕСЃРЅРѕРІРЅРѕР№ СЃРµСЂРІРµСЂ СѓСЃРїРµР» Р·Р°РїСѓСЃС‚РёС‚СЊСЃСЏ
                time.sleep(1)
                try:
                    logger.info("Starting web interface...")
                    self.web_api.run(self.cert_dir)
                except Exception as e:
                    logger.error(f"Web interface error: {e}", exc_info=True)
            
            web_thread = threading.Thread(
                target=start_web,
                daemon=True,
                name="WebInterface"
            )
            web_thread.start()
            logger.info(f"Web interface thread started (will be available at http://{self.web_host}:{self.web_port} or https if certificates found)")

        # Р—Р°РїСѓСЃРє РїРµСЂРёРѕРґРёС‡РµСЃРєРёС… Р·Р°РґР°С‡
        asyncio.create_task(self._periodic_tasks())

    async def stop(self):
        """РћСЃС‚Р°РЅРѕРІРєР° СЃРµСЂРІРµСЂР°"""
        logger.info("Stopping Flamix server...")
        self.running = False

        if self.server:
            self.server.close()
            await self.server.wait_closed()

        # Р—Р°РєСЂС‹РІР°РµРј РІСЃРµ СЃРµСЃСЃРёРё
        for session_id in list(self.client_manager.sessions.keys()):
            await self.client_manager.close_session(session_id)

        logger.info("Server stopped")

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """РћР±СЂР°Р±РѕС‚РєР° РїРѕРґРєР»СЋС‡РµРЅРёСЏ РєР»РёРµРЅС‚Р°"""
        client_id = None
        session_id = None

        try:
            # РџРѕР»СѓС‡Р°РµРј РёРЅС„РѕСЂРјР°С†РёСЋ Рѕ РєР»РёРµРЅС‚Рµ РёР· SSL
            peername = writer.get_extra_info('peername')
            logger.info(f"New client connection from {peername}")
            
            # РџРѕР»СѓС‡Р°РµРј SSL РёРЅС„РѕСЂРјР°С†РёСЋ Рѕ РєР»РёРµРЅС‚Рµ
            try:
                ssl_object = writer.get_extra_info('ssl_object')
                if ssl_object:
                    cipher = ssl_object.cipher()
                    version = ssl_object.version()
                    logger.info(f"SSL connection established: {version}, cipher: {cipher}")
                    
                    # РџСЂРѕРІРµСЂСЏРµРј РєР»РёРµРЅС‚СЃРєРёР№ СЃРµСЂС‚РёС„РёРєР°С‚ (mutual TLS)
                    client_cert = ssl_object.getpeercert()
                    if client_cert:
                        logger.info(f"Client certificate received: {client_cert.get('subject')}")
                    else:
                        logger.warning("No client certificate received (mutual TLS may be disabled)")
            except Exception as e:
                logger.warning(f"Could not get SSL info: {e}")

            # РЎРѕР·РґР°РµРј РІСЂРµРјРµРЅРЅСѓСЋ СЃРµСЃСЃРёСЋ РґР»СЏ DH РѕР±РјРµРЅР°
            temp_client_id = f"temp-{uuid.uuid4()}"
            logger.info(f"Creating temporary session for {temp_client_id}")
            session = await self.client_manager.create_session(
                temp_client_id,
                reader,
                writer
            )
            session_id = session.session_id
            logger.info(f"Session {session_id} created, waiting for DH_KEY_EXCHANGE...")

            # РћР¶РёРґР°РµРј DH_KEY_EXCHANGE
            # РСЃРїРѕР»СЊР·СѓРµРј С„РёРєСЃРёСЂРѕРІР°РЅРЅС‹Р№ session_id РґР»СЏ РЅР°С‡Р°Р»СЊРЅРѕРіРѕ РѕР±РјРµРЅР° (С‚Р°РєРѕР№ Р¶Рµ РєР°Рє Сѓ РєР»РёРµРЅС‚Р°)
            temp_key = b'\x00' * 32
            temp_session_id = "handshake-init"
            protocol = ServerProtocol(temp_key, temp_session_id)
            try:
                message = await protocol.read_message(reader)
            except asyncio.TimeoutError:
                logger.error("Timeout waiting for DH_KEY_EXCHANGE")
                return
            except (ConnectionResetError, BrokenPipeError, OSError, asyncio.IncompleteReadError) as e:
                logger.info(f"Client disconnected during handshake (DH_KEY_EXCHANGE): {e}")
                return

            if not message or message.header.message_type != MessageType.DH_KEY_EXCHANGE:
                logger.error("Expected DH_KEY_EXCHANGE message")
                return

            # РџРѕР»СѓС‡Р°РµРј РїСѓР±Р»РёС‡РЅС‹Р№ РєР»СЋС‡ РєР»РёРµРЅС‚Р°
            client_public_key = bytes.fromhex(message.payload.get('public_key', ''))
            if not client_public_key:
                logger.error("No public key in DH_KEY_EXCHANGE")
                return

            # Р—Р°РІРµСЂС€Р°РµРј DH РѕР±РјРµРЅ
            session_key = await self.client_manager.complete_dh_exchange(
                session_id,
                client_public_key
            )

            # РћС‚РїСЂР°РІР»СЏРµРј РѕС‚РІРµС‚ СЃ РїСѓР±Р»РёС‡РЅС‹Рј РєР»СЋС‡РѕРј СЃРµСЂРІРµСЂР°
            # РСЃРїРѕР»СЊР·СѓРµРј С‚РѕС‚ Р¶Рµ temp_protocol (handshake-init) РґР»СЏ РѕС‚РІРµС‚Р°
            server_public_key = session.dh.get_public_key_bytes()
            response = protocol.create_message(
                MessageType.DH_KEY_RESPONSE,
                {
                    'public_key': server_public_key.hex(),
                    'session_id': session_id
                }
            )
            writer.write(response)
            await writer.drain()
            logger.info(f"DH_KEY_RESPONSE sent with session_id {session_id}")
            
            # РўРµРїРµСЂСЊ РѕР±РЅРѕРІР»СЏРµРј РїСЂРѕС‚РѕРєРѕР» СЃ РЅРѕРІС‹Рј РєР»СЋС‡РѕРј РґР»СЏ РґР°Р»СЊРЅРµР№С€РµР№ РєРѕРјРјСѓРЅРёРєР°С†РёРё
            protocol = ServerProtocol(session_key, session_id)

            # РћР¶РёРґР°РµРј AUTH_REQUEST
            try:
                message = await protocol.read_message(reader)
            except asyncio.TimeoutError:
                logger.error("Timeout waiting for AUTH_REQUEST")
                return
            except (ConnectionResetError, BrokenPipeError, OSError, asyncio.IncompleteReadError) as e:
                logger.info(f"Client disconnected during handshake (AUTH_REQUEST): {e}")
                return
            if not message or message.header.message_type != MessageType.AUTH_REQUEST:
                logger.error("Expected AUTH_REQUEST message")
                return

            # РР·РІР»РµРєР°РµРј client_id РёР· Р·Р°РїСЂРѕСЃР°
            client_id_raw = message.payload.get('client_id')
            if not client_id_raw:
                logger.error("No client_id in AUTH_REQUEST")
                return

            # РќРѕСЂРјР°Р»РёР·СѓРµРј client_id РєР°Рє СЃС‚СЂРѕРєСѓ (РЅР° СЃР»СѓС‡Р°Р№ РµСЃР»Рё РїСЂРёС€Р»Рѕ С‡РёСЃР»Рѕ)
            client_id = str(client_id_raw)
            logger.info(f"AUTH_REQUEST received with client_id={client_id} (original type: {type(client_id_raw).__name__})")

            # Р РµРіРёСЃС‚СЂРёСЂСѓРµРј РёР»Рё РѕР±РЅРѕРІР»СЏРµРј РєР»РёРµРЅС‚Р°
            self._register_client(client_id, peername[0] if peername else "unknown")

            # РћР±РЅРѕРІР»СЏРµРј СЃРµСЃСЃРёСЋ СЃ СЂРµР°Р»СЊРЅС‹Рј client_id (РІСЃРµРіРґР° СЃС‚СЂРѕРєР°)
            old_temp_id = session.client_id
            session.client_id = client_id
            self.client_manager.client_sessions[client_id] = session_id
            # РЈРґР°Р»СЏРµРј РјР°РїРїРёРЅРі РІСЂРµРјРµРЅРЅРѕРіРѕ client_id
            self.client_manager.client_sessions.pop(old_temp_id, None)

            # РўРµРїРµСЂСЊ РєР»РёРµРЅС‚ Р·Р°СЂРµРіРёСЃС‚СЂРёСЂРѕРІР°РЅ РІ Р‘Р” вЂ” СЃРѕС…СЂР°РЅСЏРµРј СЃРµСЃСЃРёСЋ
            self.client_manager._save_session_to_db(session)

            # РћС‚РїСЂР°РІР»СЏРµРј AUTH_RESPONSE
            response = protocol.create_message(
                MessageType.AUTH_RESPONSE,
                {
                    'success': True,
                    'client_id': client_id,
                    'session_id': session_id
                }
            )
            writer.write(response)
            await writer.drain()

            logger.info(f"Client {client_id} authenticated, session {session_id}")

            # РћСЃРЅРѕРІРЅРѕР№ С†РёРєР» РѕР±СЂР°Р±РѕС‚РєРё СЃРѕРѕР±С‰РµРЅРёР№
            await self._handle_client_messages(protocol, session, reader, writer)

        except (ConnectionResetError, BrokenPipeError, OSError, asyncio.IncompleteReadError) as e:
            # Normal disconnection - log at info level, not error
            logger.info(f"Client {client_id or 'unknown'} disconnected: {e}")
        except Exception as e:
            logger.error(f"Error handling client: {e}", exc_info=True)
        finally:
            if session_id:
                await self.client_manager.close_session(session_id)

    async def _handle_client_messages(
        self,
        protocol: ServerProtocol,
        session,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        """РћР±СЂР°Р±РѕС‚РєР° СЃРѕРѕР±С‰РµРЅРёР№ РѕС‚ РєР»РёРµРЅС‚Р°"""
        while self.running:
            try:
                message = await protocol.read_message(reader)

                if not message:
                    # read_message returned None due to a protocol error
                    # (decryption failure, HMAC mismatch, etc.) вЂ” not a timeout
                    logger.warning(f"Invalid message from client {session.client_id}, ignoring")
                    continue

                # РћР±РЅРѕРІР»СЏРµРј Р°РєС‚РёРІРЅРѕСЃС‚СЊ
                self.client_manager.update_activity(session.session_id)

                # РћР±СЂР°Р±РѕС‚РєР° СЃРѕРѕР±С‰РµРЅРёР№
                await self._process_message(protocol, session, message, writer)

            except asyncio.TimeoutError:
                # No message within MESSAGE_TIMEOUT вЂ” send heartbeat to keep alive
                try:
                    heartbeat = protocol.create_message(MessageType.HEARTBEAT, {})
                    writer.write(heartbeat)
                    await writer.drain()
                except (ConnectionResetError, BrokenPipeError, OSError) as e:
                    logger.warning(f"Connection lost sending heartbeat to {session.client_id}: {e}")
                    break
            except (ConnectionResetError, BrokenPipeError, OSError,
                    asyncio.IncompleteReadError) as e:
                logger.info(f"Client {session.client_id} disconnected: {e}")
                break
            except Exception as e:
                logger.error(f"Error handling message: {e}", exc_info=True)
                break

    async def _process_message(
        self,
        protocol: ServerProtocol,
        session,
        message: ProtocolMessage,
        writer: asyncio.StreamWriter
    ):
        """РћР±СЂР°Р±РѕС‚РєР° РєРѕРЅРєСЂРµС‚РЅРѕРіРѕ СЃРѕРѕР±С‰РµРЅРёСЏ"""
        msg_type = message.header.message_type
        payload = message.payload

        if msg_type == MessageType.SYNC_REQUEST:
            # РЎРёРЅС…СЂРѕРЅРёР·Р°С†РёСЏ РїСЂР°РІРёР»
            # РЈР±РµР¶РґР°РµРјСЃСЏ, С‡С‚Рѕ client_id СѓСЃС‚Р°РЅРѕРІР»РµРЅ Рё РЅРѕСЂРјР°Р»РёР·РѕРІР°РЅ РєР°Рє СЃС‚СЂРѕРєР°
            if not session.client_id:
                logger.error("SYNC_REQUEST received but session.client_id is not set!")
                response = protocol.create_message(
                    MessageType.SYNC_RESPONSE,
                    {'rules': []}
                )
                writer.write(response)
                await writer.drain()
                return
            
            client_id = str(session.client_id) if session.client_id else None
            logger.info(f"SYNC_REQUEST received from client_id={client_id} (type: {type(client_id).__name__})")
            
            if client_id.startswith("temp-"):
                logger.warning(f"SYNC_REQUEST received with temporary client_id={client_id}, client may not be authenticated yet")
            
            rules = self.rule_manager.get_all_rules(client_id)
            logger.info(f"Found {len(rules)} rules for client_id={client_id}")
            rules_data = [rule.to_dict() for rule in rules]
            logger.debug(f"Serialized {len(rules_data)} rules to send to client")

            response = protocol.create_message(
                MessageType.SYNC_RESPONSE,
                {'rules': rules_data}
            )
            writer.write(response)
            await writer.drain()
            logger.info(f"SYNC_RESPONSE sent to client_id={client_id} with {len(rules_data)} rules")

        elif msg_type == MessageType.RULE_UPDATE_REQUEST:
            # Р—Р°РїСЂРѕСЃ РЅР° РѕР±РЅРѕРІР»РµРЅРёРµ РїСЂР°РІРёР»Р°
            rule_data = payload.get('new_rule')
            if rule_data:
                rule = FirewallRule.from_dict(rule_data)
                current_rule = self.rule_manager.get_rule(session.client_id, rule.id)
                review = self.rule_authorization.review_rule_change(
                    client_id=session.client_id,
                    rule_id=rule.id,
                    old_rule=current_rule,
                    new_rule=rule,
                    change_source="client",
                )

                if not review.allowed:
                    response = protocol.create_message(
                        MessageType.RULE_UPDATE_REJECTED,
                        {
                            'reason': review.reason or 'Rule change rejected',
                            'rule_id': rule.id,
                            'rule_name': rule.name,
                            'request_id': review.request_id,
                            'warnings': review.warnings,
                            'limitations': review.limitations,
                        }
                    )
                else:
                    if current_rule:
                        self.rule_manager.update_rule(session.client_id, rule)
                    else:
                        self.rule_manager.add_rule(session.client_id, rule)

                    response = protocol.create_message(
                        MessageType.RULE_UPDATE_APPROVED,
                        {
                            'rule_id': rule.id,
                            'rule_name': rule.name,
                            'warnings': review.warnings,
                            'limitations': review.limitations,
                        }
                    )
            else:
                response = protocol.create_message(
                    MessageType.RULE_UPDATE_REJECTED,
                    {'reason': 'Invalid rule data'}
                )
            writer.write(response)
            await writer.drain()

        elif msg_type == MessageType.HEARTBEAT:
            # Heartbeat РѕС‚РІРµС‚
            response = protocol.create_message(MessageType.HEARTBEAT_RESPONSE, {})
            writer.write(response)
            await writer.drain()

        elif msg_type == MessageType.ANALYTICS_REPORT:
            # РЎРѕС…СЂР°РЅРµРЅРёРµ Р°РЅР°Р»РёС‚РёРєРё (РґР°РЅРЅС‹Рµ СЃРѕР±СЂР°РЅС‹ РљР›РР•РќРўРћРњ С‡РµСЂРµР· psutil Рё РїР»Р°РіРёРЅС‹)
            logger.debug(f"Received ANALYTICS_REPORT from client {session.client_id}")
            self._save_analytics(session.client_id, payload)
            # РЎРѕС…СЂР°РЅРµРЅРёРµ СЃС‚Р°С‚РёСЃС‚РёРєРё С‚СЂР°С„РёРєР° РµСЃР»Рё РµСЃС‚СЊ (РєР»РёРµРЅС‚ РѕС‚РїСЂР°РІРёР» С‡РµСЂРµР· TrafficCollector)
            if 'events' in payload:
                traffic_events = [e for e in payload['events'] if e.get('event_type') == 'traffic_stats']
                if traffic_events:
                    logger.info(f"Saving {len(traffic_events)} traffic stats events from client {session.client_id}")
                for event in payload['events']:
                    if event.get('event_type') == 'traffic_stats':
                        # Р”Р°РЅРЅС‹Рµ СѓР¶Рµ СЃРѕР±СЂР°РЅС‹ РєР»РёРµРЅС‚РѕРј, РїСЂРѕСЃС‚Рѕ СЃРѕС…СЂР°РЅСЏРµРј РІ Р‘Р”
                        self._save_traffic_stats(session.client_id, event)
            # РќРµ РѕС‚РїСЂР°РІР»СЏРµРј РѕС‚РІРµС‚ РґР»СЏ Р°РЅР°Р»РёС‚РёРєРё

        elif msg_type == MessageType.CONFIG_REQUEST:
            # Р—Р°РїСЂРѕСЃ РєРѕРЅС„РёРіСѓСЂР°С†РёРё РєР»РёРµРЅС‚Р°
            config = self._get_client_config(session.client_id)
            if config:
                response = protocol.create_message(
                    MessageType.CONFIG_RESPONSE,
                    {'config': config}
                )
            else:
                # Р•СЃР»Рё РєРѕРЅС„РёРіР° РЅРµС‚, РІРѕР·РІСЂР°С‰Р°РµРј РїСѓСЃС‚РѕР№ РѕС‚РІРµС‚
                response = protocol.create_message(
                    MessageType.CONFIG_RESPONSE,
                    {'config': None, 'message': 'No configuration available'}
                )
            writer.write(response)
            await writer.drain()

        elif msg_type == MessageType.CONFIG_RESPONSE:
            # РџРѕРґС‚РІРµСЂР¶РґРµРЅРёРµ РїСЂРёРјРµРЅРµРЅРёСЏ РєРѕРЅС„РёРіР° РѕС‚ РєР»РёРµРЅС‚Р°
            status = payload.get('status', 'unknown')
            if status == 'applied':
                logger.info(f"Client {session.client_id} applied configuration successfully")
            elif status == 'error':
                error = payload.get('error', 'Unknown error')
                logger.warning(f"Client {session.client_id} failed to apply config: {error}")

        elif msg_type == MessageType.SYSTEM_STATUS_REPORT:
            # РЎРѕС…СЂР°РЅРµРЅРёРµ СЃРёСЃС‚РµРјРЅРѕРіРѕ СЃС‚Р°С‚СѓСЃР° РєР»РёРµРЅС‚Р°
            self._save_system_status(session.client_id, payload)
            # РќРµ РѕС‚РїСЂР°РІР»СЏРµРј РѕС‚РІРµС‚ РґР»СЏ СЃС‚Р°С‚СѓСЃР°

        elif msg_type == MessageType.LOG_REPORT:
            # РЎРѕС…СЂР°РЅРµРЅРёРµ Р»РѕРіРѕРІ РєР»РёРµРЅС‚Р°
            log_count = len(payload.get('logs', []))
            if log_count > 0:
                logger.info(f"Received LOG_REPORT from client {session.client_id}: {log_count} log entries")
            self._save_client_logs(session.client_id, payload)
            # РќРµ РѕС‚РїСЂР°РІР»СЏРµРј РѕС‚РІРµС‚ РґР»СЏ Р»РѕРіРѕРІ

    def _register_client(self, client_id: str, ip_address: str):
        """Р РµРіРёСЃС‚СЂР°С†РёСЏ РєР»РёРµРЅС‚Р° РІ Р‘Р” (UPSERT Р±РµР· СѓРґР°Р»РµРЅРёСЏ СЃРІСЏР·Р°РЅРЅС‹С… РґР°РЅРЅС‹С…)"""
        from datetime import datetime
        try:
            # РџСЂРѕРІРµСЂСЏРµРј, СЃСѓС‰РµСЃС‚РІСѓРµС‚ Р»Рё РєР»РёРµРЅС‚
            existing = self.db.execute_one(
                "SELECT id, name FROM clients WHERE id = ?",
                (client_id,)
            )
            
            if existing:
                # РћР±РЅРѕРІР»СЏРµРј СЃСѓС‰РµСЃС‚РІСѓСЋС‰РµРіРѕ РєР»РёРµРЅС‚Р°
                self.db.execute_write(
                    """
                    UPDATE clients 
                    SET ip_address = ?, last_seen = ?, enabled = ?
                    WHERE id = ?
                    """,
                    (
                        ip_address,
                        datetime.utcnow().isoformat() + "Z",
                        1,
                        client_id
                    )
                )
                logger.debug(f"Updated existing client {client_id} in database")
            else:
                # РЎРѕР·РґР°РµРј РЅРѕРІРѕРіРѕ РєР»РёРµРЅС‚Р°
                self.db.execute_write(
                    """
                    INSERT INTO clients (id, name, ip_address, last_seen, enabled)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        client_id,
                        client_id,  # РРјСЏ РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ
                        ip_address,
                        datetime.utcnow().isoformat() + "Z",
                        1
                    )
                )
                logger.info(f"Registered new client {client_id} in database")
        except Exception as e:
            logger.error(f"Error registering client {client_id}: {e}", exc_info=True)

    def _save_analytics(self, client_id: str, data: dict):
        """РЎРѕС…СЂР°РЅРµРЅРёРµ Р°РЅР°Р»РёС‚РёРєРё"""
        from datetime import datetime
        self.db.execute_write(
            """
            INSERT INTO analytics 
            (client_id, timestamp, event_type, target_ip, target_domain, target_port, protocol, action, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client_id,
                datetime.utcnow().isoformat() + "Z",
                data.get('event_type', 'unknown'),
                data.get('target_ip'),
                data.get('target_domain'),
                data.get('target_port'),
                data.get('protocol'),
                data.get('action'),
                json.dumps(data.get('details', {}))
            )
        )

    def _save_traffic_stats(self, client_id: str, event: dict):
        """
        РЎРѕС…СЂР°РЅРµРЅРёРµ СЃС‚Р°С‚РёСЃС‚РёРєРё С‚СЂР°С„РёРєР° РІ Р‘Р”.
        
        Р’РђР–РќРћ: Р­С‚Рё РґР°РЅРЅС‹Рµ СѓР¶Рµ СЃРѕР±СЂР°РЅС‹ РљР›РР•РќРўРћРњ С‡РµСЂРµР·:
        - psutil (Р°РєС‚РёРІРЅС‹Рµ СЃРѕРµРґРёРЅРµРЅРёСЏ, СЃРµС‚РµРІРѕР№ I/O)
        - РїР»Р°РіРёРЅС‹ С„Р°Р№СЂРІРѕР»Р° (Р»РѕРіРё iptables/Windows Firewall)
        
        РЎРµСЂРІРµСЂ С‚РѕР»СЊРєРѕ СЃРѕС…СЂР°РЅСЏРµС‚ Рё Р°РіСЂРµРіРёСЂСѓРµС‚ РґР°РЅРЅС‹Рµ, РќР• С‡РёС‚Р°РµС‚ С‚СЂР°С„РёРє РЅР°РїСЂСЏРјСѓСЋ.
        """
        from datetime import datetime
        import json

        try:
            timestamp = event.get('timestamp', datetime.utcnow().isoformat() + "Z")
            aggregated = event.get('aggregated', {})
            network_io = event.get('network_io', {})
            firewall_events = event.get('firewall_events', [])

            # Save aggregated snapshot
            if aggregated:
                logger.debug(f"Saving traffic stats for client {client_id}: {len(aggregated)} aggregated metrics")
                self.db.execute_write(
                """
                INSERT INTO traffic_stats
                (client_id, timestamp, bytes_in, bytes_out, connections, bandwidth_bps)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    client_id,
                    timestamp,
                    aggregated.get('total_bytes_sent', 0),
                    aggregated.get('total_bytes_recv', 0),
                    aggregated.get('total_connections', 0),
                    aggregated.get('bandwidth_bps', 0)
                )
                )
                logger.debug(f"Traffic stats saved for client {client_id}")

            # Save individual firewall events
            for fw_event in firewall_events:
                self.db.execute_write(
                    """
                    INSERT INTO traffic_stats
                    (client_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, action, bytes_in, bytes_out)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        client_id,
                        fw_event.get('timestamp', timestamp),
                        fw_event.get('src_ip'),
                        fw_event.get('dst_ip'),
                        fw_event.get('src_port'),
                        fw_event.get('dst_port'),
                        fw_event.get('protocol'),
                        fw_event.get('action'),
                        fw_event.get('bytes_in', 0),
                        fw_event.get('bytes_out', 0)
                    )
                    )
            logger.info(f"Saved {len(firewall_events)} firewall events for client {client_id}")
        except Exception as e:
            logger.error(f"Error saving traffic stats for client {client_id}: {e}", exc_info=True)

    def _save_system_status(self, client_id: str, status_data: Dict[str, Any]):
        """
        РЎРѕС…СЂР°РЅРµРЅРёРµ СЃРёСЃС‚РµРјРЅРѕРіРѕ СЃС‚Р°С‚СѓСЃР° РєР»РёРµРЅС‚Р° РІ Р‘Р”

        Args:
            client_id: ID РєР»РёРµРЅС‚Р°
            status_data: Р”Р°РЅРЅС‹Рµ СЃРёСЃС‚РµРјРЅРѕРіРѕ СЃС‚Р°С‚СѓСЃР°
        """
        from datetime import datetime
        import json
        try:
            timestamp = status_data.get('timestamp', datetime.utcnow().isoformat() + "Z")
            cpu = status_data.get('cpu', {})
            memory = status_data.get('memory', {})
            disk = status_data.get('disk', {})
            os_info = status_data.get('os', {})
            plugins_status = status_data.get('plugins', [])

            logger.info(f"Saving system status for client {client_id}: CPU={cpu.get('percent')}%, Memory={memory.get('percent')}%")

            result = self.db.execute_write(
                """
                INSERT INTO client_system_status
                (client_id, timestamp, cpu_percent, cpu_per_core, memory_total, memory_used, memory_percent, disk_usage, os_info, plugins_status, extra)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_id,
                    timestamp,
                    cpu.get('percent'),
                    json.dumps(cpu.get('per_core', [])),
                    memory.get('total'),
                    memory.get('used'),
                    memory.get('percent'),
                    json.dumps(disk),
                    json.dumps(os_info),
                    json.dumps(plugins_status),
                    json.dumps(status_data.get('network', {}))  # Store network info in extra for now
                )
            )
            logger.info(f"System status saved successfully for client {client_id} (rowid: {result})")
        except Exception as e:
            logger.error(f"Error saving system status for client {client_id}: {e}", exc_info=True)

    def _save_client_logs(self, client_id: str, log_data: Dict[str, Any]):
        """
        РЎРѕС…СЂР°РЅРµРЅРёРµ Р»РѕРіРѕРІ РєР»РёРµРЅС‚Р° РІ Р‘Р”

        Args:
            client_id: ID РєР»РёРµРЅС‚Р°
            log_data: Р”Р°РЅРЅС‹Рµ Р»РѕРіРѕРІ (СЃРѕРґРµСЂР¶РёС‚ СЃРїРёСЃРѕРє 'logs')
        """
        from datetime import datetime
        try:
            logs = log_data.get('logs', [])
            if not logs:
                logger.debug(f"No logs to save for client {client_id}")
                return
            
            logger.info(f"Saving {len(logs)} log entries for client {client_id}")
            for log_entry in logs:
                result = self.db.execute_write(
                    """
                    INSERT INTO client_logs
                    (client_id, timestamp, level, logger_name, message)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        client_id,
                        log_entry.get('timestamp', datetime.utcnow().isoformat() + "Z"),
                        log_entry.get('level', 'INFO'),
                        log_entry.get('logger_name'),
                        log_entry.get('message', '')
                    )
                )
            logger.info(f"Saved {len(logs)} log entries for client {client_id}")
        except Exception as e:
            logger.error(f"Error saving logs for client {client_id}: {e}", exc_info=True)

    def _get_client_config(self, client_id: str) -> Optional[Dict[str, Any]]:
        """
        РџРѕР»СѓС‡РµРЅРёРµ РєРѕРЅС„РёРіСѓСЂР°С†РёРё РєР»РёРµРЅС‚Р° РёР· Р‘Р”

        Args:
            client_id: ID РєР»РёРµРЅС‚Р°

        Returns:
            РљРѕРЅС„РёРіСѓСЂР°С†РёСЏ РёР»Рё None
        """
        try:
            result = self.db.execute_one(
                "SELECT config_data, version FROM client_configs WHERE client_id = ?",
                (client_id,)
            )
            if result:
                config_data = json.loads(result[0])
                return config_data
        except Exception as e:
            logger.error(f"Error getting client config: {e}", exc_info=True)
        return None

    def _save_client_config(self, client_id: str, config: Dict[str, Any]):
        """
        РЎРѕС…СЂР°РЅРµРЅРёРµ РєРѕРЅС„РёРіСѓСЂР°С†РёРё РєР»РёРµРЅС‚Р° РІ Р‘Р”

        Args:
            client_id: ID РєР»РёРµРЅС‚Р°
            config: РљРѕРЅС„РёРіСѓСЂР°С†РёСЏ
        """
        try:
            from datetime import datetime
            config_json = json.dumps(config, ensure_ascii=False)
            now = datetime.utcnow().isoformat() + "Z"
            
            # РџРѕР»СѓС‡Р°РµРј С‚РµРєСѓС‰СѓСЋ РІРµСЂСЃРёСЋ
            result = self.db.execute_one(
                "SELECT version FROM client_configs WHERE client_id = ?",
                (client_id,)
            )
            version = (result[0] + 1) if result else 1
            
            self.db.execute_write(
                """
                INSERT OR REPLACE INTO client_configs 
                (client_id, config_data, version, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (client_id, config_json, version, now)
            )
            logger.info(f"Saved config for client {client_id} (version {version})")
        except Exception as e:
            logger.error(f"Error saving client config: {e}", exc_info=True)

    async def send_config_update(self, client_id: str, config: Dict[str, Any]) -> bool:
        """
        РћС‚РїСЂР°РІРєР° РѕР±РЅРѕРІР»РµРЅРёСЏ РєРѕРЅС„РёРіСѓСЂР°С†РёРё РєР»РёРµРЅС‚Сѓ

        Args:
            client_id: ID РєР»РёРµРЅС‚Р°
            config: РќРѕРІР°СЏ РєРѕРЅС„РёРіСѓСЂР°С†РёСЏ

        Returns:
            True РµСЃР»Рё РѕС‚РїСЂР°РІР»РµРЅРѕ СѓСЃРїРµС€РЅРѕ
        """
        try:
            # РЎРѕС…СЂР°РЅСЏРµРј РєРѕРЅС„РёРі РІ Р‘Р”
            self._save_client_config(client_id, config)
            
            # РќР°С…РѕРґРёРј СЃРµСЃСЃРёСЋ РєР»РёРµРЅС‚Р°
            session_id = self.client_manager.client_sessions.get(client_id)
            if not session_id:
                logger.warning(f"Client {client_id} is not connected")
                return False
            
            session = self.client_manager.get_session(session_id)
            if not session or not session.protocol or not session.writer:
                logger.warning(f"Session {session_id} not found or invalid")
                return False
            
            # РћС‚РїСЂР°РІР»СЏРµРј РѕР±РЅРѕРІР»РµРЅРёРµ РєРѕРЅС„РёРіР°
            message = session.protocol.create_message(
                MessageType.CONFIG_UPDATE,
                {'config': config}
            )
            session.writer.write(message)
            await session.writer.drain()
            
            logger.info(f"Sent config update to client {client_id}")
            return True
        except Exception as e:
            logger.error(f"Error sending config update: {e}", exc_info=True)
            return False

    async def _periodic_tasks(self):
        """РџРµСЂРёРѕРґРёС‡РµСЃРєРёРµ Р·Р°РґР°С‡Рё"""
        while self.running:
            interval = max(1, int(self.runtime_config.periodic_task_interval_seconds or 60))
            await asyncio.sleep(interval)
            self.client_manager.cleanup_expired_sessions(self.runtime_config.session_timeout_seconds)
            self._cleanup_retention()

    def _cleanup_retention(self):
        """Remove old diagnostic rows when retention has been configured."""
        now = datetime.utcnow()
        self._last_retention_cleanup = now

        retention_jobs = [
            ("client_logs", self.runtime_config.client_log_retention_days),
            ("analytics", self.runtime_config.analytics_retention_days),
            ("traffic_stats", self.runtime_config.traffic_stats_retention_days),
            ("client_system_status", self.runtime_config.system_status_retention_days),
        ]

        for table_name, retention_days in retention_jobs:
            if retention_days is None or retention_days <= 0:
                continue

            cutoff = (now - timedelta(days=retention_days)).isoformat() + "Z"
            try:
                deleted = self.db.execute_delete(
                    f"DELETE FROM {table_name} WHERE timestamp < ?",
                    (cutoff,)
                )
                if deleted:
                    logger.info(
                        "Retention cleanup removed %s rows from %s older than %s days",
                        deleted,
                        table_name,
                        retention_days,
                    )
            except Exception as exc:
                logger.warning("Retention cleanup skipped for %s: %s", table_name, exc)

async def main():
    """РўРѕС‡РєР° РІС…РѕРґР° СЃРµСЂРІРµСЂР°"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    runtime_config = load_runtime_config()
    runtime_config.db_path.parent.mkdir(parents=True, exist_ok=True)
    runtime_config.cert_dir.mkdir(parents=True, exist_ok=True)
    runtime_config.log_dir.mkdir(parents=True, exist_ok=True)

    server = FlamixServer(runtime_config=runtime_config)
    await server.start()

    try:
        await asyncio.Event().wait()  # Р‘РµСЃРєРѕРЅРµС‡РЅРѕРµ РѕР¶РёРґР°РЅРёРµ
    except KeyboardInterrupt:
        pass
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())


