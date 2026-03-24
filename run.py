#!/usr/bin/env python3
"""Entry point for starting the Flamix server."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

# Add local modules to import path
sys.path.insert(0, str(Path(__file__).parent))

from flamix.server.runtime_config import DEFAULT_CONFIG_PATH, ServerRuntimeConfig, load_runtime_config
from flamix.server.server import FlamixServer

logger = logging.getLogger(__name__)


def _asyncio_exception_handler(loop, context):
    """Handle noisy connection reset errors on Windows cleanly."""
    exception = context.get("exception")
    if isinstance(exception, ConnectionResetError):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Connection reset by peer (normal): %s", context.get("message", ""))
        return

    if "exception" in context:
        logger.error(
            "Unhandled exception in asyncio: %s",
            context.get("message", ""),
            exc_info=context.get("exception"),
        )
    else:
        logger.error("Unhandled error in asyncio: %s", context.get("message", ""))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Flamix Server")
    parser.add_argument("--config-file", type=str, default=None, help="Server runtime config file")
    parser.add_argument("--host", type=str, default=None, help="Server host to bind to")
    parser.add_argument("--port", type=int, default=None, help="Server port to bind to")
    parser.add_argument("--db-path", type=str, default=None, help="Path to SQLite database")
    parser.add_argument("--cert-dir", type=str, default=None, help="Directory for certificates")
    parser.add_argument("--log-dir", type=str, default=None, help="Directory for logs")
    parser.add_argument("--web-host", type=str, default=None, help="Web interface host")
    parser.add_argument("--web-port", type=int, default=None, help="Web interface port")
    parser.add_argument("--web-enabled", action="store_true", default=None, help="Enable web interface")
    parser.add_argument("--web-disable", action="store_true", default=None, help="Disable web interface")
    parser.add_argument("--periodic-task-interval-seconds", type=int, default=None, help="Server maintenance interval")
    parser.add_argument("--session-timeout-seconds", type=int, default=None, help="Inactive session timeout")
    parser.add_argument("--client-log-retention-days", type=int, default=None, help="Retention for client logs")
    parser.add_argument("--analytics-retention-days", type=int, default=None, help="Retention for analytics data")
    parser.add_argument("--traffic-stats-retention-days", type=int, default=None, help="Retention for traffic stats")
    parser.add_argument("--system-status-retention-days", type=int, default=None, help="Retention for client system status")
    parser.add_argument("--require-client-cert", action="store_true", default=None, help="Require client certificates")
    parser.add_argument("--no-require-client-cert", action="store_true", default=None, help="Disable client certificate requirement")
    parser.add_argument("--persist-runtime-config", action="store_true", default=None, help="Persist runtime config changes")
    parser.add_argument("--no-persist-runtime-config", action="store_true", default=None, help="Do not persist runtime config changes")
    parser.add_argument("--log-level", type=str, default=None, help="Logging level")
    return parser


def _determine_config_path(argv: list[str]) -> Path:
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--config-file", type=str, default=None)
    pre_args, _ = pre_parser.parse_known_args(argv)

    env_config_path = os.getenv("FLAMIX_SERVER_CONFIG_PATH")
    config_path = pre_args.config_file or env_config_path or str(DEFAULT_CONFIG_PATH)
    return Path(config_path)


def _build_runtime_config(args: argparse.Namespace, config_path: Path) -> ServerRuntimeConfig:
    overrides = {}
    for field_name, value in (
        ("server_host", args.host),
        ("server_port", args.port),
        ("db_path", Path(args.db_path) if args.db_path else None),
        ("cert_dir", Path(args.cert_dir) if args.cert_dir else None),
        ("log_dir", Path(args.log_dir) if args.log_dir else None),
        ("web_host", args.web_host),
        ("web_port", args.web_port),
        ("periodic_task_interval_seconds", args.periodic_task_interval_seconds),
        ("session_timeout_seconds", args.session_timeout_seconds),
        ("client_log_retention_days", args.client_log_retention_days),
        ("analytics_retention_days", args.analytics_retention_days),
        ("traffic_stats_retention_days", args.traffic_stats_retention_days),
        ("system_status_retention_days", args.system_status_retention_days),
        ("log_level", args.log_level),
    ):
        if value is not None:
            overrides[field_name] = value

    if args.web_disable:
        overrides["web_enabled"] = False
    elif args.web_enabled is True:
        overrides["web_enabled"] = True

    if args.no_require_client_cert:
        overrides["require_client_cert"] = False
    elif args.require_client_cert is True:
        overrides["require_client_cert"] = True

    if args.no_persist_runtime_config:
        overrides["persist_runtime_config"] = False
    elif args.persist_runtime_config is True:
        overrides["persist_runtime_config"] = True

    return load_runtime_config(config_path=config_path, overrides=overrides)


async def main():
    """Main entry point for the server process."""
    argv = sys.argv[1:]
    config_path = _determine_config_path(argv)
    parser = _build_parser()
    args = parser.parse_args(argv)

    runtime_config = _build_runtime_config(args, config_path)

    logging.basicConfig(
        level=getattr(logging, runtime_config.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        force=True,
    )

    # Make sure runtime directories exist before startup.
    runtime_config.db_path.parent.mkdir(parents=True, exist_ok=True)
    runtime_config.cert_dir.mkdir(parents=True, exist_ok=True)
    runtime_config.log_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("Starting Flamix Server")
    logger.info("Config file: %s", runtime_config.config_path)
    logger.info("Host: %s", runtime_config.server_host)
    logger.info("Port: %s", runtime_config.server_port)
    logger.info("Database: %s", runtime_config.db_path)
    logger.info("Certificates: %s", runtime_config.cert_dir)
    logger.info("Logs: %s", runtime_config.log_dir)
    logger.info("Web interface: %s", "enabled" if runtime_config.web_enabled else "disabled")
    if runtime_config.web_enabled:
        logger.info("Web interface: http://%s:%s", runtime_config.web_host, runtime_config.web_port)
    logger.info("=" * 60)

    server = FlamixServer(runtime_config=runtime_config)
    asyncio.get_running_loop().set_exception_handler(_asyncio_exception_handler)

    try:
        await server.start()
        logger.info("Server is running. Press Ctrl+C to stop.")
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
    except Exception as exc:
        logger.error("Server error: %s", exc, exc_info=True)
        sys.exit(1)
    finally:
        await server.stop()
        logger.info("Server stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutdown complete")
    except Exception as exc:
        logger.error("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)
