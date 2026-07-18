"""Загрузчик плагинов"""

import zipfile
import json
import importlib.util
import sys
from pathlib import Path
from typing import Dict, Any, Optional
import logging

from flamix.models.manifest import PluginManifest, FirewallSupport
from flamix.config import PLUGINS_DIR

logger = logging.getLogger(__name__)


class PluginLoadError(Exception):
    """Ошибка загрузки плагина"""
    pass


class PluginLoader:
    """Загрузчик плагинов"""

    def __init__(self):
        self.plugins_dir = PLUGINS_DIR

    def load_manifest(self, zip_path: Path) -> PluginManifest:
        """
        Загрузка манифеста из ZIP-архива
        
        Args:
            zip_path: Путь к ZIP-архиву
            
        Returns:
            PluginManifest объект
        """
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_file:
                if 'manifest.json' not in zip_file.namelist():
                    raise PluginLoadError("manifest.json not found in plugin archive")
                
                manifest_data = json.loads(zip_file.read('manifest.json').decode('utf-8'))
                
                # Преобразуем firewall_support в объекты
                firewall_support = []
                for fw_data in manifest_data.get("firewall_support", []):
                    firewall_support.append(FirewallSupport(**fw_data))
                manifest_data["firewall_support"] = firewall_support
                
                return PluginManifest(**manifest_data)
        except zipfile.BadZipFile:
            raise PluginLoadError(f"Invalid ZIP file: {zip_path}")
        except json.JSONDecodeError as e:
            raise PluginLoadError(f"Invalid manifest.json: {e}")

    def extract_plugin(self, zip_path: Path, plugin_id: str) -> Path:
        """
        Распаковка плагина
        
        Args:
            zip_path: Путь к ZIP-архиву
            plugin_id: ID плагина
            
        Returns:
            Путь к директории плагина
        """
        plugin_dir = self.plugins_dir / plugin_id
        plugin_dir.mkdir(parents=True, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_file:
            zip_file.extractall(plugin_dir)
        
        return plugin_dir

    def load_plugin_module(self, plugin_dir: Path, entry_point: str):
        """
        Загрузка модуля плагина
        
        Args:
            plugin_dir: Директория плагина
            entry_point: Точка входа (например, plugin.py)
            
        Returns:
            Загруженный модуль
        """
        plugin_file = plugin_dir / entry_point
        if not plugin_file.exists():
            raise PluginLoadError(f"Entry point {entry_point} not found in {plugin_dir}")
        
        spec = importlib.util.spec_from_file_location("plugin_module", plugin_file)
        if spec is None or spec.loader is None:
            raise PluginLoadError(f"Failed to create module spec for {plugin_file}")
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        
        return module

    def get_plugin_class(self, module) -> type:
        """
        Получение класса плагина из модуля
        
        Args:
            module: Загруженный модуль
            
        Returns:
            Класс плагина (наследник PluginInterface)
        """
        from flamix.api import PluginInterface
        
        # Ищем класс, наследующийся от PluginInterface
        for name in dir(module):
            obj = getattr(module, name)
            if (isinstance(obj, type) and 
                issubclass(obj, PluginInterface) and 
                obj is not PluginInterface):
                return obj
        
        raise PluginLoadError("No PluginInterface subclass found in plugin module")
