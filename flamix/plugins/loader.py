"""Загрузчик плагинов"""

import zipfile
import json
import hashlib
import importlib.util
import sys
from pathlib import Path
from typing import Optional, Dict, Any
import logging

from flamix.models.manifest import PluginManifest
from flamix.config import PLUGINS_DIR

logger = logging.getLogger(__name__)


class PluginLoadError(Exception):
    """Ошибка загрузки плагина"""
    pass


class PluginLoader:
    """Загрузчик ZIP-плагинов"""

    def __init__(self):
        self.loaded_plugins: Dict[str, Any] = {}

    def load_manifest(self, zip_path: Path) -> PluginManifest:
        """
        Загрузка и валидация manifest.json из ZIP
        
        Args:
            zip_path: Путь к ZIP-архиву плагина
            
        Returns:
            Валидированный PluginManifest
            
        Raises:
            PluginLoadError: При ошибке загрузки или валидации
        """
        try:
            with zipfile.ZipFile(zip_path, "r") as zip_file:
                # Проверка наличия manifest.json
                if "manifest.json" not in zip_file.namelist():
                    raise PluginLoadError("manifest.json not found in plugin archive")

                # Чтение manifest.json
                manifest_data = json.loads(zip_file.read("manifest.json").decode("utf-8"))
                manifest = PluginManifest(**manifest_data)

                # Проверка checksum (если указан)
                if manifest.checksum:
                    calculated_checksum = self._calculate_zip_checksum(zip_path)
                    if calculated_checksum != manifest.checksum.replace("sha256:", ""):
                        raise PluginLoadError("Checksum mismatch")

                return manifest

        except zipfile.BadZipFile:
            raise PluginLoadError("Invalid ZIP archive")
        except json.JSONDecodeError as e:
            raise PluginLoadError(f"Invalid JSON in manifest.json: {e}")
        except Exception as e:
            raise PluginLoadError(f"Error loading manifest: {e}")

    def extract_plugin(self, zip_path: Path, plugin_id: str) -> Path:
        """
        Распаковка плагина в директорию плагинов
        
        Args:
            zip_path: Путь к ZIP-архиву
            plugin_id: ID плагина
            
        Returns:
            Путь к распакованной директории плагина
        """
        plugin_dir = PLUGINS_DIR / plugin_id
        plugin_dir.mkdir(parents=True, exist_ok=True)

        try:
            with zipfile.ZipFile(zip_path, "r") as zip_file:
                zip_file.extractall(plugin_dir)

            logger.info(f"Extracted plugin {plugin_id} to {plugin_dir}")
            return plugin_dir

        except Exception as e:
            raise PluginLoadError(f"Error extracting plugin: {e}")

    def load_plugin_module(self, plugin_dir: Path, entry_point: str) -> Any:
        """
        Загрузка модуля плагина
        
        Args:
            plugin_dir: Директория плагина
            entry_point: Точка входа (например, "plugin.py")
            
        Returns:
            Загруженный модуль
        """
        entry_path = plugin_dir / entry_point
        if not entry_path.exists():
            raise PluginLoadError(f"Entry point not found: {entry_point}")

        spec = importlib.util.spec_from_file_location(
            f"flamix_plugin_{plugin_dir.name}",
            entry_path
        )
        if spec is None or spec.loader is None:
            raise PluginLoadError(f"Failed to create module spec for {entry_point}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module.__name__] = module
        spec.loader.exec_module(module)

        return module

    def get_plugin_class(self, module: Any) -> Any:
        """
        Получение класса плагина из модуля
        
        Ищет класс, наследующийся от PluginInterface
        """
        from flamix.api import PluginInterface

        for name in dir(module):
            obj = getattr(module, name)
            if (
                isinstance(obj, type)
                and issubclass(obj, PluginInterface)
                and obj != PluginInterface
            ):
                return obj

        raise PluginLoadError("Plugin class not found (must inherit from PluginInterface)")

    def _calculate_zip_checksum(self, zip_path: Path) -> str:
        """Вычисление SHA-256 хеша ZIP-архива"""
        sha256 = hashlib.sha256()
        with open(zip_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

