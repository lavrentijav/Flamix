"""CLI для управления Flamix"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FlamixCLI:
    """CLI клиент для Flamix"""

    def __init__(self):
        # TODO: Реализовать IPC клиент для связи с агентом
        pass

    async def install_plugin(self, zip_path: Path):
        """Установка плагина"""
        print(f"Installing plugin from {zip_path}...")
        # TODO: Реализовать через IPC
        print("Plugin installed successfully")

    async def list_plugins(self):
        """Список плагинов"""
        print("Installed plugins:")
        # TODO: Реализовать через IPC
        print("No plugins installed")

    async def enable_plugin(self, plugin_id: str):
        """Включение плагина"""
        print(f"Enabling plugin {plugin_id}...")
        # TODO: Реализовать через IPC
        print("Plugin enabled")

    async def disable_plugin(self, plugin_id: str):
        """Отключение плагина"""
        print(f"Disabling plugin {plugin_id}...")
        # TODO: Реализовать через IPC
        print("Plugin disabled")

    async def uninstall_plugin(self, plugin_id: str):
        """Удаление плагина"""
        print(f"Uninstalling plugin {plugin_id}...")
        # TODO: Реализовать через IPC
        print("Plugin uninstalled")


def main():
    """Точка входа CLI"""
    parser = argparse.ArgumentParser(description="Flamix CLI")
    subparsers = parser.add_subparsers(dest="command", help="Command")

    # install-plugin
    install_parser = subparsers.add_parser("install-plugin", help="Install a plugin")
    install_parser.add_argument("zip_path", type=Path, help="Path to plugin ZIP file")

    # list-plugins
    subparsers.add_parser("list-plugins", help="List installed plugins")

    # enable-plugin
    enable_parser = subparsers.add_parser("enable-plugin", help="Enable a plugin")
    enable_parser.add_argument("plugin_id", help="Plugin ID")

    # disable-plugin
    disable_parser = subparsers.add_parser("disable-plugin", help="Disable a plugin")
    disable_parser.add_argument("plugin_id", help="Plugin ID")

    # uninstall-plugin
    uninstall_parser = subparsers.add_parser("uninstall-plugin", help="Uninstall a plugin")
    uninstall_parser.add_argument("plugin_id", help="Plugin ID")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    cli = FlamixCLI()

    async def run():
        if args.command == "install-plugin":
            await cli.install_plugin(args.zip_path)
        elif args.command == "list-plugins":
            await cli.list_plugins()
        elif args.command == "enable-plugin":
            await cli.enable_plugin(args.plugin_id)
        elif args.command == "disable-plugin":
            await cli.disable_plugin(args.plugin_id)
        elif args.command == "uninstall-plugin":
            await cli.uninstall_plugin(args.plugin_id)

    asyncio.run(run())


if __name__ == "__main__":
    main()

