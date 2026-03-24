#!/usr/bin/env python3
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
        sys.exit(1)
