"""Менеджер плагинов - управление lifecycle"""

import asyncio
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

from flamix.plugins.loader import PluginLoader, PluginLoadError
from flamix.models.manifest import PluginManifest, FirewallSupport
from flamix.api import PluginInterface, CoreAPI
from flamix.security import PermissionManager
from flamix.config import PLUGINS_DIR

logger = logging.getLogger(__name__)


class PluginManager:
    """Управление lifecycle плагинов"""

    def __init__(self, permission_manager: PermissionManager):
        self.permission_manager = permission_manager
        self.loader = PluginLoader()
        self.plugins: Dict[str, Dict[str, Any]] = {}  # plugin_id -> {manifest, instance, enabled}
        self.core_api_instances: Dict[str, CoreAPI] = {}

    def install_plugin(self, zip_path: Path) -> str:
        """
        Установка плагина из ZIP (синхронный метод)
        
        Args:
            zip_path: Путь к ZIP-архиву
            
        Returns:
            ID установленного плагина
        """
        # Загрузка и валидация manifest
        manifest = self.loader.load_manifest(zip_path)
        plugin_id = manifest.id

        logger.info(f"Installing plugin {plugin_id} v{manifest.version}")

        # Проверка, не установлен ли уже
        if plugin_id in self.plugins:
            raise PluginLoadError(f"Plugin {plugin_id} already installed")

        # Распаковка
        plugin_dir = self.loader.extract_plugin(zip_path, plugin_id)

        # Регистрация разрешений
        self.permission_manager.register_plugin(plugin_id, manifest.permissions)

        # Сохранение информации о плагине
        self.plugins[plugin_id] = {
            "manifest": manifest,
            "plugin_dir": plugin_dir,
            "instance": None,
            "enabled": False,
        }

        logger.info(f"Plugin {plugin_id} installed successfully")
        return plugin_id

    def enable_plugin(self, plugin_id: str) -> None:
        """Включение плагина (синхронный метод)"""
        import asyncio
        
        if plugin_id not in self.plugins:
            raise PluginLoadError(f"Plugin {plugin_id} not installed")

        plugin_info = self.plugins[plugin_id]
        if plugin_info["enabled"]:
            logger.warning(f"Plugin {plugin_id} already enabled")
            return

        manifest = plugin_info["manifest"]
        plugin_dir = plugin_info["plugin_dir"]

        # Загрузка модуля
        module = self.loader.load_plugin_module(plugin_dir, manifest.entry_point)
        plugin_class = self.loader.get_plugin_class(module)

        # Создание экземпляра
        instance: PluginInterface = plugin_class()
        instance.plugin_id = plugin_id

        # Создание CoreAPI
        core_api = CoreAPI(
            plugin_id,
            manifest.permissions,
            self.permission_manager,
            plugin_manager=self
        )
        instance.core_api = core_api
        self.core_api_instances[plugin_id] = core_api

        # Lifecycle hooks - запускаем async методы через asyncio.run
        try:
            # Создаем новый event loop для этого потока
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            # Запускаем async методы
            loop.run_until_complete(instance.on_install())
            loop.run_until_complete(instance.on_enable())
            loop.run_until_complete(instance.on_init(core_api))

            plugin_info["instance"] = instance
            plugin_info["enabled"] = True

            logger.info(f"Plugin {plugin_id} enabled successfully")

        except Exception as e:
            logger.error(f"Error enabling plugin {plugin_id}: {e}", exc_info=True)
            # Очищаем состояние при ошибке
            plugin_info["instance"] = None
            plugin_info["enabled"] = False
            # Удаляем core_api instance если он был создан
            if plugin_id in self.core_api_instances:
                del self.core_api_instances[plugin_id]
            # Пробрасываем исключение дальше
            raise

    def disable_plugin(self, plugin_id: str) -> None:
        """Отключение плагина (синхронный метод)"""
        import asyncio
        
        if plugin_id not in self.plugins:
            raise PluginLoadError(f"Plugin {plugin_id} not installed")

        plugin_info = self.plugins[plugin_id]
        if not plugin_info["enabled"]:
            return

        instance = plugin_info["instance"]
        if instance:
            try:
                # Запускаем async метод через asyncio
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                loop.run_until_complete(instance.on_disable())
            except Exception as e:
                logger.error(f"Error in on_disable for {plugin_id}: {e}")

        plugin_info["instance"] = None
        plugin_info["enabled"] = False

        logger.info(f"Plugin {plugin_id} disabled")

    def uninstall_plugin(self, plugin_id: str) -> None:
        """Удаление плагина (синхронный метод)"""
        import asyncio
        
        if plugin_id not in self.plugins:
            raise PluginLoadError(f"Plugin {plugin_id} not installed")

        # Отключение перед удалением
        if self.plugins[plugin_id]["enabled"]:
            self.disable_plugin(plugin_id)

        instance = self.plugins[plugin_id]["instance"]
        if instance:
            try:
                # Запускаем async метод через asyncio
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                loop.run_until_complete(instance.on_uninstall())
            except Exception as e:
                logger.error(f"Error in on_uninstall for {plugin_id}: {e}")

        # Удаление директории
        plugin_dir = self.plugins[plugin_id]["plugin_dir"]
        if plugin_dir.exists():
            import shutil
            shutil.rmtree(plugin_dir)

        # Удаление регистрации
        self.permission_manager.unregister_plugin(plugin_id)
        del self.plugins[plugin_id]
        if plugin_id in self.core_api_instances:
            del self.core_api_instances[plugin_id]

        logger.info(f"Plugin {plugin_id} uninstalled")

    def detect_firewalls(self, plugin_id: str) -> List[Dict[str, Any]]:
        """
        Детект firewall для конкретного плагина (синхронный метод)
        
        Args:
            plugin_id: ID плагина
            
        Returns:
            Список найденных firewall с информацией
        """
        if plugin_id not in self.plugins:
            return []

        manifest = self.plugins[plugin_id]["manifest"]
        detected = []

        for firewall_support in manifest.firewall_support:
            try:
                result = self._detect_single_firewall(
                    firewall_support,
                    self.plugins[plugin_id]["plugin_dir"]
                )
                if result:
                    detected.append(result)
            except Exception as e:
                logger.warning(f"Error detecting {firewall_support.name}: {e}")

        # Сортировка по priority
        detected.sort(key=lambda x: x.get("priority", 0), reverse=True)
        return detected

    def _detect_single_firewall(
        self,
        firewall_support: FirewallSupport,
        plugin_dir: Path
    ) -> Optional[Dict[str, Any]]:
        """Детект одного firewall (синхронный метод)"""
        detect = firewall_support.detect

        try:
            if detect.type == "command":
                # Выполнение команды (синхронно)
                import subprocess
                try:
                    result = subprocess.run(
                        detect.value.split(),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5.0,
                        text=True
                    )
                    if result.returncode != 0:
                        return None
                    output = result.stdout.strip()
                except subprocess.TimeoutExpired:
                    logger.warning(f"Timeout detecting {firewall_support.name}")
                    return None

            elif detect.type == "script":
                # Запуск скрипта из плагина (синхронно)
                script_path = plugin_dir / detect.value
                if not script_path.exists():
                    logger.warning(f"Script not found: {script_path}")
                    return None

                import subprocess
                try:
                    result = subprocess.run(
                        ["bash", str(script_path)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5.0,
                        text=True
                    )
                    if result.returncode != 0:
                        return None
                    output = result.stdout.strip()
                except subprocess.TimeoutExpired:
                    logger.warning(f"Timeout detecting {firewall_support.name}")
                    return None

            else:
                return None

            # Применение regex для извлечения версии
            version = None
            for regex_pattern in firewall_support.regex:
                match = re.search(regex_pattern, output)
                if match:
                    version = match.group(1)
                    break

            if not version:
                return None

            # Проверка версии
            if not self._check_version(version, firewall_support.versions):
                logger.warning(
                    f"Version {version} of {firewall_support.name} "
                    f"not in supported range"
                )
                return None

            return {
                "name": firewall_support.name,
                "version": version,
                "priority": firewall_support.priority,
                "requires_root": firewall_support.requires_root,
            }

        except asyncio.TimeoutError:
            logger.warning(f"Timeout detecting {firewall_support.name}")
            return None
        except Exception as e:
            logger.error(f"Error detecting {firewall_support.name}: {e}")
            return None

    def _check_version(self, version: str, version_range) -> bool:
        """Проверка версии на соответствие диапазону"""
        try:
            from semantic_version import Version

            v = Version(version)

            # Проверка exact
            if version_range.exact:
                return str(v) in version_range.exact

            # Проверка min
            if version_range.min:
                min_v = Version(version_range.min)
                if v < min_v:
                    return False

            # Проверка max
            if version_range.max:
                max_v = Version(version_range.max)
                if v > max_v:
                    return False

            return True

        except Exception as e:
            logger.error(f"Error checking version {version}: {e}")
            return False

    def get_plugin_health(self, plugin_id: str) -> Dict[str, Any]:
        """Получение статуса здоровья плагина (синхронный метод)"""
        import asyncio
        
        if plugin_id not in self.plugins or not self.plugins[plugin_id]["enabled"]:
            return {"status": "critical"}

        instance = self.plugins[plugin_id]["instance"]
        if not instance:
            return {"status": "critical"}

        try:
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            return loop.run_until_complete(asyncio.wait_for(instance.get_health(), timeout=5.0))
        except Exception as e:
            logger.error(f"Error getting health for {plugin_id}: {e}")
            return {"status": "critical"}

    def list_plugins(self) -> List[Dict[str, Any]]:
        """Список всех установленных плагинов"""
        result = []
        for plugin_id, plugin_info in self.plugins.items():
            manifest = plugin_info["manifest"]
            result.append({
                "id": plugin_id,
                "name": manifest.name,
                "version": manifest.version,
                "enabled": plugin_info["enabled"],
                "author": manifest.author,
            })
        return result

