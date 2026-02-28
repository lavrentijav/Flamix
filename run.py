#!/usr/bin/env python3
"""Точка входа для запуска клиента Flamix"""

import asyncio
import logging
import sys
from pathlib import Path

# Добавляем путь к модулям
sys.path.insert(0, str(Path(__file__).parent))

from flamix.client.client import FlamixClient
from flamix.client.rule_sync import RuleSync
from flamix.client.rule_converter import RuleConverter
from flamix.client.rule_monitor import RuleMonitor
from flamix.client.analytics_collector import AnalyticsCollector
from flamix.plugins.manager import PluginManager
from flamix.security.permission_manager import PermissionManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

logger = logging.getLogger(__name__)


async def main():
    """Главная функция запуска клиента"""
    import argparse

    parser = argparse.ArgumentParser(description="Flamix Client")
    parser.add_argument(
        "--client-id",
        type=str,
        required=True,
        help="Client ID (required)"
    )
    parser.add_argument(
        "--server-host",
        type=str,
        default="localhost",
        help="Server host (default: localhost)"
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=8443,
        help="Server port (default: 8443)"
    )
    parser.add_argument(
        "--cert-dir",
        type=str,
        default="certs",
        help="Directory for certificates (default: certs)"
    )
    parser.add_argument(
        "--sync-interval",
        type=int,
        default=30,
        help="Rule sync interval in seconds (default: 30)"
    )
    parser.add_argument(
        "--monitor-interval",
        type=int,
        default=10,
        help="Rule monitoring interval in seconds (default: 10)"
    )
    parser.add_argument(
        "--analytics-enabled",
        action="store_true",
        help="Enable analytics collection"
    )
    parser.add_argument(
        "--analytics-interval",
        type=int,
        default=60,
        help="Analytics report interval in seconds (default: 60)"
    )

    args = parser.parse_args()

    # Создаем директории если нужно
    Path(args.cert_dir).mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("Starting Flamix Client")
    logger.info(f"Client ID: {args.client_id}")
    logger.info(f"Server: {args.server_host}:{args.server_port}")
    logger.info(f"Certificates: {args.cert_dir}")
    logger.info(f"Sync interval: {args.sync_interval}s")
    logger.info(f"Monitor interval: {args.monitor_interval}s")
    logger.info(f"Analytics: {'enabled' if args.analytics_enabled else 'disabled'}")
    logger.info("=" * 60)

    # Инициализация компонентов
    permission_manager = PermissionManager()
    plugin_manager = PluginManager(permission_manager)
    rule_converter = RuleConverter(plugin_manager)

    # Создание клиента
    client = FlamixClient(
        client_id=args.client_id,
        server_host=args.server_host,
        server_port=args.server_port,
        cert_dir=Path(args.cert_dir)
    )

    # Подключение к серверу
    logger.info("Connecting to server...")
    if not await client.connect():
        logger.error("Failed to connect to server")
        sys.exit(1)

    logger.info("Connected to server successfully")

    # Инициализация синхронизации
    rule_sync = RuleSync(
        client=client,
        rule_converter=rule_converter,
        sync_interval=args.sync_interval
    )

    # Инициализация мониторинга
    rule_monitor = RuleMonitor(
        client=client,
        rule_converter=rule_converter,
        check_interval=args.monitor_interval
    )

    # Инициализация аналитики
    analytics_collector = AnalyticsCollector(
        client=client,
        enabled=args.analytics_enabled,
        report_interval=args.analytics_interval
    )

    try:
        # Первоначальная синхронизация
        logger.info("Performing initial rule sync...")
        rules = await rule_sync.sync()
        logger.info(f"Synced {len(rules)} rules from server")

        # Инициализация checksum для мониторинга
        rule_monitor.initialize_checksums(rules)

        # Запуск фоновых задач
        await rule_sync.start()
        await rule_monitor.start()
        await analytics_collector.start()

        logger.info("Client is running. Press Ctrl+C to stop.")

        # Основной цикл
        while client.connected:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
    except Exception as e:
        logger.error(f"Client error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        # Остановка фоновых задач
        await rule_sync.stop()
        await rule_monitor.stop()
        await analytics_collector.stop()

        # Отключение от сервера
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
