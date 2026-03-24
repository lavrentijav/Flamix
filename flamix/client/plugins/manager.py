"""Plugin manager for firewall plugins"""

import sys
import json
import zipfile
import shutil
import importlib.util
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any

from flamix.client.plugins.base import FirewallPlugin
from flamix.client.plugins.plugin_adapter import PluginAdapter

logger = logging.getLogger(__name__)


class PluginManager:
    """Manages firewall plugins and auto-detects the appropriate one"""

    def __init__(self, base_dir: Optional[Path] = None):
        """
        Initialize the plugin manager
        
        Args:
            base_dir: Base directory of the client (where plugins/ and temp/ are located)
                     If None, will try to detect from sys.path or current directory
        """
        self.plugins: Dict[str, FirewallPlugin] = {}
        self.active_plugin: Optional[FirewallPlugin] = None
        self._loaded_zip_sources: Dict[str, Path] = {}
        
        # Determine base directory
        if base_dir is None:
            # Try to find base directory from common locations
            # Usually it's the directory containing run.py
            possible_paths = [
                Path.cwd(),
                Path(__file__).parent.parent.parent.parent,  # From flamix/client/plugins/manager.py
            ]
            for path in possible_paths:
                if (path / "plugins").exists() or (path / "config.json").exists():
                    self.base_dir = path
                    break
            else:
                self.base_dir = Path.cwd()
        else:
            self.base_dir = Path(base_dir)
        
        self.plugins_dir = self.base_dir / "plugins"
        self.temp_dir = self.base_dir / "temp" / "plugins"
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        logger.debug(f"PluginManager initialized with base_dir={self.base_dir}")
        logger.debug(f"Plugins directory: {self.plugins_dir}")
        logger.debug(f"Temp directory: {self.temp_dir}")
        
        self._load_plugins()

    def _load_plugins(self):
        """Load available plugins based on platform"""
        platform = sys.platform.lower()

        # First, load built-in plugins
        if platform.startswith('win'):
            # Windows
            try:
                from flamix.client.plugins.windows_firewall import WindowsFirewallPlugin
                plugin = WindowsFirewallPlugin()
                plugin.plugin_id = "windows_firewall"
                self.plugins["windows_firewall"] = plugin
                if plugin.is_available():
                    self.active_plugin = plugin
                    logger.info("Windows Firewall plugin loaded and active")
            except Exception as e:
                logger.warning(f"Failed to load Windows Firewall plugin: {e}")

        elif platform.startswith('linux'):
            # Linux - try iptables
            try:
                from flamix.client.plugins.iptables_plugin import IptablesPlugin
                plugin = IptablesPlugin()
                plugin.plugin_id = "iptables"
                self.plugins["iptables"] = plugin
                if plugin.is_available():
                    self.active_plugin = plugin
                    logger.info("iptables plugin loaded and active")
            except Exception as e:
                logger.warning(f"Failed to load iptables plugin: {e}")

        # Then, load plugins from zip archives
        try:
            self._load_plugins_from_zips()
        except Exception as e:
            logger.error(f"Error loading plugins from zip archives: {e}", exc_info=True)

        # Select active plugin if none is selected yet
        if not self.active_plugin:
            # Try to find any available plugin
            for plugin_id, plugin in self.plugins.items():
                if plugin.is_available():
                    self.active_plugin = plugin
                    logger.info(f"Selected {plugin_id} as active plugin")
                    break
            
            if not self.active_plugin:
                logger.warning("No firewall plugin available for this platform")
    
    def _scan_plugin_zips(self) -> List[Path]:
        """
        Scan plugins directory for zip archives
        
        Returns:
            List of paths to zip files
        """
        zip_files = []
        
        if not self.plugins_dir.exists():
            logger.debug(f"Plugins directory does not exist: {self.plugins_dir}")
            return zip_files
        
        # Look for zip files in plugins directory
        for item in self.plugins_dir.iterdir():
            if item.is_file() and item.suffix.lower() == '.zip':
                zip_files.append(item)
                logger.debug(f"Found plugin zip: {item}")
        
        # Also check subdirectories (e.g., plugins/netsh/netsh-plugin.zip)
        for item in self.plugins_dir.iterdir():
            if item.is_dir():
                for subitem in item.iterdir():
                    if subitem.is_file() and subitem.suffix.lower() == '.zip':
                        zip_files.append(subitem)
                        logger.debug(f"Found plugin zip in subdirectory: {subitem}")
        
        zip_files = sorted(
            zip_files,
            key=lambda path: (len(path.relative_to(self.plugins_dir).parts), str(path).lower())
        )

        logger.info(f"Found {len(zip_files)} plugin zip file(s)")
        return zip_files
    
    def _load_plugins_from_zips(self):
        """Load plugins from zip archives in plugins directory"""
        zip_files = self._scan_plugin_zips()
        
        for zip_path in zip_files:
            try:
                self._load_plugin_from_zip(zip_path)
            except Exception as e:
                logger.error(f"Failed to load plugin from {zip_path}: {e}", exc_info=True)
                continue
    
    def _load_plugin_from_zip(self, zip_path: Path):
        """
        Load a plugin from a zip archive
        
        Args:
            zip_path: Path to the zip archive
        """
        logger.info(f"Loading plugin from zip: {zip_path}")
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_file:
                # Check if manifest.json exists
                if 'manifest.json' not in zip_file.namelist():
                    logger.warning(f"No manifest.json found in {zip_path}, skipping")
                    return
                
                # Read and parse manifest
                manifest_data = zip_file.read('manifest.json')
                try:
                    manifest = json.loads(manifest_data.decode('utf-8'))
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in manifest.json of {zip_path}: {e}")
                    return
                
                # Validate manifest
                if not self._validate_manifest(manifest, zip_path):
                    return
                
                # Check platform compatibility
                if not self._check_platform_compatibility(manifest):
                    logger.debug(f"Plugin {manifest.get('id')} is not compatible with current platform, skipping")
                    return
                
                plugin_id = manifest.get('id')
                if not plugin_id:
                    logger.error(f"Plugin manifest missing 'id' field: {zip_path}")
                    return
                
                # Skip if plugin already loaded
                if plugin_id in self.plugins:
                    existing_source = self._loaded_zip_sources.get(plugin_id)
                    logger.info(
                        f"Plugin {plugin_id} already loaded from {existing_source or 'an earlier source'}, "
                        f"skipping duplicate archive {zip_path}"
                    )
                    return
                
                # Extract to temp directory
                extract_dir = self.temp_dir / plugin_id
                if extract_dir.exists():
                    # Remove old version
                    shutil.rmtree(extract_dir)
                extract_dir.mkdir(parents=True, exist_ok=True)
                
                logger.debug(f"Extracting plugin to {extract_dir}")
                zip_file.extractall(extract_dir)
                
                # Import plugin module
                entry_point = manifest.get('entry_point', 'plugin.py')
                plugin_module_path = extract_dir / entry_point
                
                if not plugin_module_path.exists():
                    logger.error(f"Entry point {entry_point} not found in plugin {plugin_id}")
                    return
                
                # Import the module
                plugin_instance = self._import_plugin_module(plugin_module_path, plugin_id, manifest)
                if not plugin_instance:
                    return
                
                # Wrap in adapter
                adapter = PluginAdapter(plugin_instance, plugin_id, manifest)
                self.plugins[plugin_id] = adapter
                self._loaded_zip_sources[plugin_id] = zip_path
                
                # Check if this plugin should be active
                if adapter.is_available():
                    # If no active plugin yet, or this one has higher priority, use it
                    if not self.active_plugin:
                        self.active_plugin = adapter
                        logger.info(f"Plugin {plugin_id} loaded and set as active")
                    else:
                        logger.info(f"Plugin {plugin_id} loaded (available but not active)")
                else:
                    logger.info(f"Plugin {plugin_id} loaded but not available on this system")
                
        except zipfile.BadZipFile:
            logger.error(f"Invalid zip file: {zip_path}")
        except Exception as e:
            logger.error(f"Error loading plugin from {zip_path}: {e}", exc_info=True)
    
    def _validate_manifest(self, manifest: Dict[str, Any], zip_path: Path) -> bool:
        """
        Validate plugin manifest
        
        Args:
            manifest: Manifest dictionary
            zip_path: Path to zip file (for error messages)
        
        Returns:
            True if manifest is valid
        """
        required_fields = ['id', 'platforms', 'entry_point']
        
        for field in required_fields:
            if field not in manifest:
                logger.error(f"Manifest missing required field '{field}' in {zip_path}")
                return False
        
        # Validate entry_point is a string
        if not isinstance(manifest['entry_point'], str):
            logger.error(f"Manifest field 'entry_point' must be a string in {zip_path}")
            return False
        
        # Validate platforms is a list
        if not isinstance(manifest['platforms'], list):
            logger.error(f"Manifest field 'platforms' must be a list in {zip_path}")
            return False
        
        return True
    
    def _check_platform_compatibility(self, manifest: Dict[str, Any]) -> bool:
        """
        Check if plugin is compatible with current platform
        
        Args:
            manifest: Plugin manifest dictionary
        
        Returns:
            True if compatible
        """
        import sys
        platform_name = sys.platform.lower()
        
        # Normalize platform names
        if platform_name.startswith('win'):
            platform_name = 'windows'
        elif platform_name.startswith('linux'):
            platform_name = 'linux'
        elif platform_name.startswith('darwin'):
            platform_name = 'macos'
        
        supported_platforms = manifest.get('platforms', [])
        if not supported_platforms:
            return True  # No platform restriction
        
        # Check if current platform is in supported list
        normalized_supported = [p.lower() for p in supported_platforms]
        return platform_name in normalized_supported
    
    def _import_plugin_module(self, plugin_path: Path, plugin_id: str, manifest: Dict[str, Any]):
        """
        Import plugin module from file path
        
        Args:
            plugin_path: Path to plugin.py file
            plugin_id: Plugin ID
            manifest: Plugin manifest
        
        Returns:
            PluginInterface instance or None
        """
        try:
            # Create module spec
            module_name = f"flamix_plugin_{plugin_id.replace('.', '_').replace('-', '_')}"
            spec = importlib.util.spec_from_file_location(module_name, plugin_path)
            
            if spec is None or spec.loader is None:
                logger.error(f"Failed to create module spec for {plugin_path}")
                return None
            
            # Load module
            module = importlib.util.module_from_spec(spec)
            
            # Add plugin directory to sys.path temporarily for imports
            plugin_dir = plugin_path.parent
            if str(plugin_dir) not in sys.path:
                sys.path.insert(0, str(plugin_dir))
            
            try:
                spec.loader.exec_module(module)
            finally:
                # Remove from sys.path after import
                if str(plugin_dir) in sys.path:
                    sys.path.remove(str(plugin_dir))
            
            # Find plugin class
            # Usually exported as 'Plugin' or class name from manifest
            plugin_class = None
            
            # Try to find class named 'Plugin'
            if hasattr(module, 'Plugin'):
                plugin_class = getattr(module, 'Plugin')
            # Try to find class with name from manifest
            elif 'name' in manifest:
                class_name = manifest['name'].replace(' ', '').replace('-', '')
                if hasattr(module, class_name):
                    plugin_class = getattr(module, class_name)
            
            # If still not found, look for any class that inherits from PluginInterface
            if plugin_class is None:
                from flamix.api.plugin_interface import PluginInterface
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and 
                        issubclass(attr, PluginInterface) and 
                        attr != PluginInterface):
                        plugin_class = attr
                        break
            
            if plugin_class is None:
                logger.error(f"No plugin class found in {plugin_path}")
                return None
            
            # Create instance
            plugin_instance = plugin_class()
            logger.debug(f"Successfully imported plugin class {plugin_class.__name__} from {plugin_path}")
            
            return plugin_instance
            
        except Exception as e:
            logger.error(f"Error importing plugin module {plugin_path}: {e}", exc_info=True)
            return None

    def get_active_plugin(self) -> Optional[FirewallPlugin]:
        """
        Get the active firewall plugin

        Returns:
            Active plugin instance or None
        """
        return self.active_plugin

    def get_plugin(self, plugin_id: Optional[str] = None) -> Optional[FirewallPlugin]:
        """Get a specific plugin or the active one if no id is provided."""
        if plugin_id:
            return self.plugins.get(plugin_id)
        return self.active_plugin

    def list_plugins(self) -> List[Dict[str, Any]]:
        """
        List all available plugins

        Returns:
            List of plugin info dictionaries
        """
        result = []
        for plugin_id, plugin in self.plugins.items():
            result.append({
                'id': plugin_id,
                'enabled': plugin == self.active_plugin,
                'available': plugin.is_available()
            })
        return result

    async def get_status_report(self) -> List[Dict[str, Any]]:
        """
        Get detailed status report for all plugins including health information

        Returns:
            List of plugin status dictionaries with id, enabled, available, and health
        """
        result = []
        for plugin_id, plugin in self.plugins.items():
            plugin_status = {
                'id': plugin_id,
                'enabled': plugin == self.active_plugin,
                'available': plugin.is_available()
            }
            
            # Get health information if plugin is available
            if plugin.is_available():
                try:
                    health = await plugin.get_health()
                    plugin_status['health'] = health
                except Exception as e:
                    logger.warning(f"Error getting health for plugin {plugin_id}: {e}")
                    plugin_status['health'] = {
                        'status': 'error',
                        'error': str(e)
                    }
            else:
                plugin_status['health'] = {
                    'status': 'unavailable'
                }
            
            result.append(plugin_status)
        
        return result
