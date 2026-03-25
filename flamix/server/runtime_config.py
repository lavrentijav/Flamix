"""Runtime configuration helpers for the Flamix server."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple
import json
import os


DEFAULT_CONFIG_PATH = Path("data/server-runtime.json")


def _as_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    raise ValueError(f"Cannot interpret {value!r} as a boolean")


def _as_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError("Boolean value cannot be used as an integer")
    return int(value)


def _as_path(value: Any) -> Optional[Path]:
    if value is None or value == "":
        return None
    if isinstance(value, Path):
        return value
    return Path(str(value))


def _deep_update(base: Dict[str, Any], patch: Mapping[str, Any]) -> Dict[str, Any]:
    result = dict(base)
    for key, value in patch.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), dict):
            result[key] = _deep_update(result[key], value)
        else:
            result[key] = value
    return result


@dataclass
class ServerRuntimeConfig:
    """Resolved runtime configuration for a Flamix server process."""

    server_host: str = "0.0.0.0"
    server_port: int = 8443
    web_enabled: bool = True
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    db_path: Path = Path("data/server.db")
    cert_dir: Path = Path("certs")
    log_dir: Path = Path("logs")
    config_path: Path = DEFAULT_CONFIG_PATH
    periodic_task_interval_seconds: int = 60
    session_timeout_seconds: int = 3600
    client_log_retention_days: Optional[int] = None
    analytics_retention_days: Optional[int] = None
    traffic_stats_retention_days: Optional[int] = None
    system_status_retention_days: Optional[int] = None
    require_client_cert: bool = True
    persist_runtime_config: bool = True
    log_level: str = "INFO"
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def defaults(cls) -> "ServerRuntimeConfig":
        return cls()

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None, base: Optional["ServerRuntimeConfig"] = None) -> "ServerRuntimeConfig":
        env = os.environ if env is None else env
        base = base or cls.defaults()
        patch: Dict[str, Any] = {}

        def maybe_add(name: str, env_name: str, parser):
            if env_name in env and env[env_name] != "":
                patch[name] = parser(env[env_name])

        maybe_add("server_host", "FLAMIX_SERVER_HOST", str)
        maybe_add("server_port", "FLAMIX_SERVER_PORT", _as_int)
        maybe_add("web_enabled", "FLAMIX_WEB_ENABLED", _as_bool)
        maybe_add("web_enabled", "FLAMIX_ENABLE_WEB", _as_bool)
        maybe_add("web_enabled", "FLAMIX_WEB_DISABLE", lambda value: not _as_bool(value))
        maybe_add("web_host", "FLAMIX_WEB_HOST", str)
        maybe_add("web_port", "FLAMIX_WEB_PORT", _as_int)
        maybe_add("db_path", "FLAMIX_DB_PATH", _as_path)
        maybe_add("cert_dir", "FLAMIX_CERT_DIR", _as_path)
        maybe_add("log_dir", "FLAMIX_LOG_DIR", _as_path)
        maybe_add("config_path", "FLAMIX_SERVER_CONFIG_PATH", _as_path)
        maybe_add("periodic_task_interval_seconds", "FLAMIX_PERIODIC_TASK_INTERVAL_SECONDS", _as_int)
        maybe_add("session_timeout_seconds", "FLAMIX_SESSION_TIMEOUT_SECONDS", _as_int)
        maybe_add("client_log_retention_days", "FLAMIX_CLIENT_LOG_RETENTION_DAYS", _as_int)
        maybe_add("analytics_retention_days", "FLAMIX_ANALYTICS_RETENTION_DAYS", _as_int)
        maybe_add("traffic_stats_retention_days", "FLAMIX_TRAFFIC_STATS_RETENTION_DAYS", _as_int)
        maybe_add("system_status_retention_days", "FLAMIX_SYSTEM_STATUS_RETENTION_DAYS", _as_int)
        maybe_add("require_client_cert", "FLAMIX_REQUIRE_CLIENT_CERT", _as_bool)
        maybe_add("persist_runtime_config", "FLAMIX_PERSIST_RUNTIME_CONFIG", _as_bool)
        maybe_add("log_level", "FLAMIX_LOG_LEVEL", str)

        return cls.from_mapping(patch, base=base)

    @classmethod
    def from_file(cls, path: Path, base: Optional["ServerRuntimeConfig"] = None) -> "ServerRuntimeConfig":
        base = base or cls.defaults()
        if not path.exists():
            return base

        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)

        config = cls.from_mapping(data, base=base)
        config.config_path = path
        return config

    @classmethod
    def from_mapping(
        cls,
        data: Mapping[str, Any],
        base: Optional["ServerRuntimeConfig"] = None,
    ) -> "ServerRuntimeConfig":
        base = base or cls.defaults()
        values = base.to_storage_dict()

        if not isinstance(data, Mapping):
            raise TypeError("Configuration data must be a mapping")

        merged = _deep_update(values, data)

        server_section = merged.get("server", {})
        web_section = merged.get("web", {})
        paths_section = merged.get("paths", {})
        runtime_section = merged.get("runtime", {})
        retention_section = merged.get("retention", {})
        features_section = merged.get("features", {})

        flat_overrides = {
            "server_host": merged.get("server_host"),
            "server_port": merged.get("server_port"),
            "web_enabled": merged.get("web_enabled"),
            "web_host": merged.get("web_host"),
            "web_port": merged.get("web_port"),
            "db_path": merged.get("db_path"),
            "cert_dir": merged.get("cert_dir"),
            "log_dir": merged.get("log_dir"),
            "config_path": merged.get("config_path"),
            "periodic_task_interval_seconds": merged.get("periodic_task_interval_seconds"),
            "session_timeout_seconds": merged.get("session_timeout_seconds"),
            "client_log_retention_days": merged.get("client_log_retention_days"),
            "analytics_retention_days": merged.get("analytics_retention_days"),
            "traffic_stats_retention_days": merged.get("traffic_stats_retention_days"),
            "system_status_retention_days": merged.get("system_status_retention_days"),
            "require_client_cert": merged.get("require_client_cert"),
            "persist_runtime_config": merged.get("persist_runtime_config"),
            "log_level": merged.get("log_level"),
        }

        normalized = cls(
            server_host=str(flat_overrides["server_host"] or server_section.get("host") or base.server_host),
            server_port=_as_int(flat_overrides["server_port"] if flat_overrides["server_port"] is not None else server_section.get("port")) or base.server_port,
            web_enabled=_as_bool(flat_overrides["web_enabled"] if flat_overrides["web_enabled"] is not None else web_section.get("enabled"))
            if (flat_overrides["web_enabled"] is not None or web_section.get("enabled") is not None)
            else base.web_enabled,
            web_host=str(flat_overrides["web_host"] or web_section.get("host") or base.web_host),
            web_port=_as_int(flat_overrides["web_port"] if flat_overrides["web_port"] is not None else web_section.get("port")) or base.web_port,
            db_path=_as_path(flat_overrides["db_path"] or paths_section.get("db_path")) or base.db_path,
            cert_dir=_as_path(flat_overrides["cert_dir"] or paths_section.get("cert_dir")) or base.cert_dir,
            log_dir=_as_path(flat_overrides["log_dir"] or paths_section.get("log_dir")) or base.log_dir,
            config_path=_as_path(flat_overrides["config_path"] or paths_section.get("config_path")) or base.config_path,
            periodic_task_interval_seconds=_as_int(flat_overrides["periodic_task_interval_seconds"] if flat_overrides["periodic_task_interval_seconds"] is not None else runtime_section.get("periodic_task_interval_seconds")) or base.periodic_task_interval_seconds,
            session_timeout_seconds=_as_int(flat_overrides["session_timeout_seconds"] if flat_overrides["session_timeout_seconds"] is not None else runtime_section.get("session_timeout_seconds")) or base.session_timeout_seconds,
            client_log_retention_days=_as_int(flat_overrides["client_log_retention_days"] if flat_overrides["client_log_retention_days"] is not None else retention_section.get("client_log_retention_days")),
            analytics_retention_days=_as_int(flat_overrides["analytics_retention_days"] if flat_overrides["analytics_retention_days"] is not None else retention_section.get("analytics_retention_days")),
            traffic_stats_retention_days=_as_int(flat_overrides["traffic_stats_retention_days"] if flat_overrides["traffic_stats_retention_days"] is not None else retention_section.get("traffic_stats_retention_days")),
            system_status_retention_days=_as_int(flat_overrides["system_status_retention_days"] if flat_overrides["system_status_retention_days"] is not None else retention_section.get("system_status_retention_days")),
            require_client_cert=_as_bool(flat_overrides["require_client_cert"] if flat_overrides["require_client_cert"] is not None else features_section.get("require_client_cert"))
            if (flat_overrides["require_client_cert"] is not None or features_section.get("require_client_cert") is not None)
            else base.require_client_cert,
            persist_runtime_config=_as_bool(flat_overrides["persist_runtime_config"] if flat_overrides["persist_runtime_config"] is not None else features_section.get("persist_runtime_config"))
            if (flat_overrides["persist_runtime_config"] is not None or features_section.get("persist_runtime_config") is not None)
            else base.persist_runtime_config,
            log_level=str(flat_overrides["log_level"] or merged.get("logging", {}).get("level") or base.log_level).upper(),
            extra=dict(merged.get("extra", {})) if isinstance(merged.get("extra", {}), Mapping) else {},
        )

        return normalized

    def merged(self, patch: Mapping[str, Any]) -> "ServerRuntimeConfig":
        return self.from_mapping(patch, base=self)

    def to_storage_dict(self) -> Dict[str, Any]:
        return {
            "version": 1,
            "server": {
                "host": self.server_host,
                "port": self.server_port,
            },
            "web": {
                "enabled": self.web_enabled,
                "host": self.web_host,
                "port": self.web_port,
            },
            "paths": {
                "db_path": str(self.db_path),
                "cert_dir": str(self.cert_dir),
                "log_dir": str(self.log_dir),
                "config_path": str(self.config_path),
            },
            "runtime": {
                "periodic_task_interval_seconds": self.periodic_task_interval_seconds,
                "session_timeout_seconds": self.session_timeout_seconds,
            },
            "retention": {
                "client_log_retention_days": self.client_log_retention_days,
                "analytics_retention_days": self.analytics_retention_days,
                "traffic_stats_retention_days": self.traffic_stats_retention_days,
                "system_status_retention_days": self.system_status_retention_days,
            },
            "features": {
                "require_client_cert": self.require_client_cert,
                "persist_runtime_config": self.persist_runtime_config,
            },
            "logging": {
                "level": self.log_level,
            },
            "extra": self.extra,
        }

    def to_public_dict(self) -> Dict[str, Any]:
        data = self.to_storage_dict()
        data.update({
            "server_host": self.server_host,
            "server_port": self.server_port,
            "web_enabled": self.web_enabled,
            "web_host": self.web_host,
            "web_port": self.web_port,
            "db_path": str(self.db_path),
            "cert_dir": str(self.cert_dir),
            "log_dir": str(self.log_dir),
            "config_path": str(self.config_path),
            "periodic_task_interval_seconds": self.periodic_task_interval_seconds,
            "session_timeout_seconds": self.session_timeout_seconds,
            "client_log_retention_days": self.client_log_retention_days,
            "analytics_retention_days": self.analytics_retention_days,
            "traffic_stats_retention_days": self.traffic_stats_retention_days,
            "system_status_retention_days": self.system_status_retention_days,
            "require_client_cert": self.require_client_cert,
            "persist_runtime_config": self.persist_runtime_config,
            "log_level": self.log_level,
        })
        return data

    def save(self, path: Optional[Path] = None) -> Path:
        target = Path(path or self.config_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as handle:
            json.dump(self.to_storage_dict(), handle, indent=2, ensure_ascii=False)
        return target

    def with_updates(self, patch: Mapping[str, Any]) -> Tuple["ServerRuntimeConfig", Dict[str, Any]]:
        updated = self.merged(patch)
        changes: Dict[str, Any] = {}

        for field_name in (
            "server_host",
            "server_port",
            "web_enabled",
            "web_host",
            "web_port",
            "db_path",
            "cert_dir",
            "log_dir",
            "config_path",
            "periodic_task_interval_seconds",
            "session_timeout_seconds",
            "client_log_retention_days",
            "analytics_retention_days",
            "traffic_stats_retention_days",
            "system_status_retention_days",
            "require_client_cert",
            "persist_runtime_config",
            "log_level",
        ):
            old_value = getattr(self, field_name)
            new_value = getattr(updated, field_name)
            if old_value != new_value:
                changes[field_name] = {"old": old_value, "new": new_value}

        return updated, changes


def load_runtime_config(
    *,
    config_path: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
    overrides: Optional[Mapping[str, Any]] = None,
    base: Optional[ServerRuntimeConfig] = None,
) -> ServerRuntimeConfig:
    """Resolve runtime config using defaults -> config file -> env -> explicit overrides."""
    base = base or ServerRuntimeConfig.defaults()
    env = os.environ if env is None else env

    resolved_config_path = Path(
        config_path
        or env.get("FLAMIX_SERVER_CONFIG_PATH")
        or DEFAULT_CONFIG_PATH
    )

    config = base
    if resolved_config_path.exists():
        config = ServerRuntimeConfig.from_file(resolved_config_path, base=config)

    config = ServerRuntimeConfig.from_env(env=env, base=config)

    if overrides:
        config = config.merged(overrides)

    config.config_path = resolved_config_path
    return config
