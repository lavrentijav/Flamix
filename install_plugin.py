"""Скрипт для установки плагинов Flamix"""

import sys
import asyncio
from pathlib import Path

def install_plugin(zip_path: str):
    """Установка плагина из ZIP-архива"""
    from flamix.config import ensure_directories
    from flamix.security import PermissionManager
    from flamix.plugins.manager import PluginManager
    from flamix.database.rules_db import RulesDB
    
    # Инициализация
    ensure_directories()
    permission_manager = PermissionManager()
    plugin_manager = PluginManager(permission_manager)
    db = RulesDB()
    
    # Инициализация БД (если нужно)
    if not db._initialized:
        db.initialize()
    
    # Установка плагина
    zip_file = Path(zip_path)
    if not zip_file.exists():
        print(f"Error: File not found: {zip_path}")
        return 1
    
    try:
        print(f"Installing plugin from {zip_path}...")
        plugin_id = plugin_manager.install_plugin(zip_file)
        print(f"Plugin '{plugin_id}' installed successfully!")
        
        # Сохранение в БД (опционально, может не работать из-за прав доступа)
        try:
            manifest = plugin_manager.plugins[plugin_id]["manifest"]
            db.add_plugin(plugin_id, manifest.permissions)
            print(f"Plugin '{plugin_id}' registered in database")
        except Exception as db_error:
            print(f"Warning: Could not register plugin in database: {db_error}")
            print("Plugin is still installed and can be used, but won't be persisted in database")
        
        # Включение плагина
        print(f"Enabling plugin '{plugin_id}'...")
        plugin_manager.enable_plugin(plugin_id)
        print(f"Plugin '{plugin_id}' enabled successfully!")
        
        print(f"\nPlugin '{plugin_id}' is ready to use!")
        return 0
        
    except Exception as e:
        print(f"Error installing plugin: {e}")
        import traceback
        traceback.print_exc()
        return 1


def main():
    """Главная функция"""
    if len(sys.argv) < 2:
        print("Usage: python install_plugin.py <path_to_plugin.zip>")
        print("\nExample:")
        print("  python install_plugin.py plugins/netsh/netsh-plugin.zip")
        return 1
    
    zip_path = sys.argv[1]
    return install_plugin(zip_path)


if __name__ == "__main__":
    sys.exit(main())
