"""GUI РїСЂРёР»РѕР¶РµРЅРёРµ РЅР° dearpygui РґР»СЏ СѓРїСЂР°РІР»РµРЅРёСЏ Flamix Server"""

import json
import copy
import logging
import queue
import threading
import time
from pathlib import Path
from typing import Optional, Dict, Any, List

import dearpygui.dearpygui as dpg
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from app.api_client import FlamixAPIClient
from app.gui.client_manager import ClientManager, filter_numeric_input
from app.gui.rules_manager import RulesManager
from app.gui.analytics_manager import AnalyticsManager
from app.gui.change_requests_manager import ChangeRequestsManager
from app.gui.monitoring_manager import MonitoringManager
from app.gui.settings_manager import SettingsManager, on_server_url_changed

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


DEFAULT_SETTINGS: Dict[str, Any] = {
    "connection": {
        "server_url": "https://127.0.0.1:8080",
        "verify_ssl": True,
        "trust_store_mode": "system",
        "ca_cert_path": "",
        "timeout_connect": 3.05,
        "timeout_read": 10.0,
        "auto_connect": False,
    },
    "refresh": {
        "auto_refresh": True,
        "refresh_interval": 30,
        "monitoring_interval": 30,
        "analytics_interval": 60,
        "monitoring_status_limit": 1000,
        "monitoring_logs_limit": 500,
        "monitoring_logs_level": "all",
        "monitoring_client_scope": "all",
    },
    "analytics": {
        "limit": 1000,
        "table_limit": 250,
        "default_client": "all",
    },
    "logging": {
        "level": "INFO",
        "max_entries": 1000,
    },
    "downloads": {
        "directory": str(Path.home() / "Downloads"),
        "package_prefix": "flamix-client",
        "open_folder_after_download": False,
        "overwrite_existing": False,
    },
    "ui": {
        "font_name": None,
        "font_size": 13,
        "compact_mode": False,
        "theme": "system",
        "table_row_limit": 200,
    },
    "diagnostics": {
        "last_export_path": "",
        "last_import_path": "",
    },
}

DEFAULT_SERVER_RUNTIME_SNAPSHOT: Dict[str, Any] = {
    "config": {},
    "stored_config": None,
    "restart_required": False,
    "info": {},
    "health": {},
    "last_loaded_at": "",
}


def _deep_merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merges dictionaries without mutating inputs."""
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge_dicts(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


class FlamixGUI:
    """GUI РїСЂРёР»РѕР¶РµРЅРёРµ Flamix - РіР»Р°РІРЅС‹Р№ РєР»Р°СЃСЃ РєРѕРѕСЂРґРёРЅР°С†РёРё"""

    def __init__(self, server_url: str = "https://127.0.0.1:8080"):
        """Initializes the GUI."""
        self.monitoring_client_id: Optional[str] = "all"
        self.refresh_thread: Optional[threading.Thread] = None
        self.monitoring_refresh_thread: Optional[threading.Thread] = None
        self.running = False
        self.monitoring_running = False
        self.connecting = False
        self.connected = False
        self._refresh_queue: queue.Queue = queue.Queue()

        self.fonts_dir = Path(__file__).parent / "fonts"
        self.available_fonts: List[Path] = []
        self.current_font: Optional[int] = None
        self.font_size: int = 13
        self.selected_font_name: Optional[str] = None

        self.settings_file = Path(__file__).parent / "settings.json"
        self.settings: Dict[str, Any] = {}
        self.server_runtime_snapshot: Dict[str, Any] = copy.deepcopy(DEFAULT_SERVER_RUNTIME_SNAPSHOT)

        dpg.create_context()
        self._load_settings()

        connection_settings = self.settings.get("connection", {})
        ui_settings = self.settings.get("ui", {})
        refresh_settings = self.settings.get("refresh", {})

        final_server_url = connection_settings.get("server_url", server_url)
        self.font_size = int(ui_settings.get("font_size", self.font_size))
        self.selected_font_name = ui_settings.get("font_name", self.selected_font_name)
        self.monitoring_client_id = None if refresh_settings.get("monitoring_client_scope", "all") == "default" else "all"

        self.api_client = FlamixAPIClient(
            base_url=final_server_url,
            verify_ssl=self._resolve_verify_target(connection_settings),
            request_timeout=(
                float(connection_settings.get("timeout_connect", 3.05)),
                float(connection_settings.get("timeout_read", 10.0)),
            ),
        )

        self._init_managers()

    def _init_managers(self):
        """Initializes all manager classes."""
        self.client_manager = ClientManager(
            api_client=self.api_client,
            refresh_rules_callback=self._refresh_rules_callback,
            refresh_monitoring_callback=self._refresh_monitoring_callback,
            get_download_settings_callback=self._get_download_settings,
        )

        self.rules_manager = RulesManager(
            api_client=self.api_client,
            get_current_client_id_callback=self._get_current_client_id,
        )

        self.analytics_manager = AnalyticsManager(
            api_client=self.api_client,
            get_clients_data_callback=self._get_clients_data,
            get_analytics_settings_callback=self._get_analytics_settings,
            get_ui_settings_callback=self._get_ui_settings,
        )

        self.change_requests_manager = ChangeRequestsManager(
            api_client=self.api_client
        )

        self.monitoring_manager = MonitoringManager(
            api_client=self.api_client,
            get_clients_data_callback=self._get_clients_data,
            get_monitoring_client_id_callback=self._get_monitoring_client_id,
            set_monitoring_client_id_callback=self._set_monitoring_client_id,
            show_client_status_details_callback=self._show_client_status_details,
            get_monitoring_settings_callback=self._get_monitoring_settings,
            get_ui_settings_callback=self._get_ui_settings,
        )

        self.settings_manager = SettingsManager(
            settings_file=self.settings_file,
            fonts_dir=self.fonts_dir,
            get_current_font_callback=lambda: self.current_font,
            set_current_font_callback=lambda f: setattr(self, 'current_font', f),
            get_font_size_callback=lambda: self.font_size,
            set_font_size_callback=lambda s: setattr(self, 'font_size', s),
            get_selected_font_name_callback=lambda: self.selected_font_name,
            set_selected_font_name_callback=lambda n: setattr(self, 'selected_font_name', n),
            get_available_fonts_callback=lambda: self.available_fonts,
            apply_font_callback=self._apply_font,
            save_settings_callback=self._save_settings,
            reload_window_callback=self.reload_window,
            show_server_url_dialog_callback=self.show_server_url_dialog,
            on_connect_callback=self.on_connect,
            get_settings_callback=self._get_settings_snapshot,
            apply_settings_callback=self._apply_settings_snapshot,
            test_connection_callback=self._test_connection_with_snapshot,
            connect_callback=self._connect_with_snapshot,
            export_settings_callback=self._export_settings,
            import_settings_callback=self._import_settings,
            reset_settings_callback=self._reset_settings_to_defaults,
            get_server_runtime_callback=self._get_server_runtime_snapshot,
            refresh_server_runtime_callback=self._refresh_server_runtime_snapshot,
            apply_server_runtime_callback=self._apply_server_runtime_patch,
        )
    # Callback РјРµС‚РѕРґС‹ РґР»СЏ РјРµРЅРµРґР¶РµСЂРѕРІ
    def _get_current_client_id(self) -> Optional[str]:
        """РџРѕР»СѓС‡РµРЅРёРµ С‚РµРєСѓС‰РµРіРѕ ID РєР»РёРµРЅС‚Р°"""
        return self.client_manager.current_client_id

    def _get_clients_data(self) -> List[Dict[str, Any]]:
        """РџРѕР»СѓС‡РµРЅРёРµ РґР°РЅРЅС‹С… РєР»РёРµРЅС‚РѕРІ"""
        return self.client_manager.clients_data

    def _get_monitoring_client_id(self) -> Optional[str]:
        """РџРѕР»СѓС‡РµРЅРёРµ ID РєР»РёРµРЅС‚Р° РґР»СЏ РјРѕРЅРёС‚РѕСЂРёРЅРіР°"""
        return self.monitoring_client_id

    def _set_monitoring_client_id(self, client_id: Optional[str]):
        """РЈСЃС‚Р°РЅРѕРІРєР° ID РєР»РёРµРЅС‚Р° РґР»СЏ РјРѕРЅРёС‚РѕСЂРёРЅРіР°"""
        self.monitoring_client_id = client_id

    def _refresh_rules_callback(self):
        """Callback РґР»СЏ РѕР±РЅРѕРІР»РµРЅРёСЏ РїСЂР°РІРёР»"""
        self.rules_manager.refresh_rules()

    def _refresh_monitoring_callback(self):
        """Callback РґР»СЏ РѕР±РЅРѕРІР»РµРЅРёСЏ РјРѕРЅРёС‚РѕСЂРёРЅРіР°"""
        self.monitoring_manager.refresh_monitoring()

    def _show_client_status_details(self, client_id: str):
        """РџРѕРєР°Р· РґРµС‚Р°Р»СЊРЅРѕРіРѕ СЃС‚Р°С‚СѓСЃР° РєР»РёРµРЅС‚Р°"""
        status = self.api_client.get_client_status_latest(client_id)
        if not status:
            logger.warning(f"No status found for client {client_id}")
            return

        # Create a modal window with details
        if dpg.does_item_exist("client_status_details_window"):
            dpg.delete_item("client_status_details_window")

        with dpg.window(
                label=f"Client {client_id} Status Details",
                modal=True,
                tag="client_status_details_window",
                width=800,
                height=600
        ):
            dpg.add_text("System Status Details", color=(100, 150, 255))
            dpg.add_separator()

            # Parse JSON fields
            cpu_per_core = json.loads(status.get('cpu_per_core', '[]')) if status.get('cpu_per_core') else []
            disk_usage = json.loads(status.get('disk_usage', '{}')) if status.get('disk_usage') else {}
            os_info = json.loads(status.get('os_info', '{}')) if status.get('os_info') else {}
            plugins_status = json.loads(status.get('plugins_status', '[]')) if status.get('plugins_status') else []

            dpg.add_text(f"CPU: {status.get('cpu_percent', 0):.1f}%")
            if cpu_per_core:
                dpg.add_text(f"CPU per core: {', '.join([f'{c:.1f}%' for c in cpu_per_core])}")
            dpg.add_text(
                f"Memory: {status.get('memory_percent', 0):.1f}% ({status.get('memory_used', 0) / (1024 ** 3):.2f} GB / {status.get('memory_total', 0) / (1024 ** 3):.2f} GB)")

            if disk_usage.get('partitions'):
                dpg.add_text("Disk Usage:")
                for mount, info in list(disk_usage['partitions'].items())[:5]:  # Show first 5 partitions
                    dpg.add_text(
                        f"  {mount}: {info.get('percent', 0):.1f}% ({info.get('used', 0) / (1024 ** 3):.2f} GB / {info.get('total', 0) / (1024 ** 3):.2f} GB)")

            if os_info:
                dpg.add_separator()
                dpg.add_text(f"OS: {os_info.get('platform', 'N/A')} {os_info.get('platform_release', '')}")
                dpg.add_text(f"Hostname: {os_info.get('hostname', 'N/A')}")
                uptime_hours = os_info.get('uptime_seconds', 0) / 3600
                dpg.add_text(f"Uptime: {uptime_hours:.1f} hours")

            if plugins_status:
                dpg.add_separator()
                dpg.add_text("Plugins:")
                for plugin in plugins_status:
                    health = plugin.get('health', {})
                    status_text = f"  {plugin.get('id', 'N/A')}: {health.get('status', 'unknown')}"
                    dpg.add_text(status_text)

            dpg.add_separator()
            dpg.add_button(label="Close", callback=lambda: dpg.delete_item("client_status_details_window"), width=-1)

    def _build_default_settings(self) -> Dict[str, Any]:
        return copy.deepcopy(DEFAULT_SETTINGS)

    def _normalize_settings(self, raw_settings: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Merges legacy and nested settings into a validated snapshot."""
        settings = self._build_default_settings()
        raw_settings = raw_settings if isinstance(raw_settings, dict) else {}

        for section_name in list(settings.keys()):
            section_value = raw_settings.get(section_name)
            if isinstance(section_value, dict):
                settings[section_name] = _deep_merge_dicts(settings[section_name], section_value)

        legacy_map = {
            "server_url": ("connection", "server_url"),
            "verify_ssl": ("connection", "verify_ssl"),
            "trust_store_mode": ("connection", "trust_store_mode"),
            "ca_cert_path": ("connection", "ca_cert_path"),
            "timeout_connect": ("connection", "timeout_connect"),
            "timeout_read": ("connection", "timeout_read"),
            "auto_connect": ("connection", "auto_connect"),
            "auto_refresh": ("refresh", "auto_refresh"),
            "refresh_interval": ("refresh", "refresh_interval"),
            "monitoring_interval": ("refresh", "monitoring_interval"),
            "analytics_interval": ("refresh", "analytics_interval"),
            "monitoring_status_limit": ("refresh", "monitoring_status_limit"),
            "monitoring_logs_limit": ("refresh", "monitoring_logs_limit"),
            "monitoring_logs_level": ("refresh", "monitoring_logs_level"),
            "monitoring_client_scope": ("refresh", "monitoring_client_scope"),
            "analytics_limit": ("analytics", "limit"),
            "analytics_table_limit": ("analytics", "table_limit"),
            "analytics_default_client": ("analytics", "default_client"),
            "log_level": ("logging", "level"),
            "log_limit": ("logging", "max_entries"),
            "download_dir": ("downloads", "directory"),
            "package_prefix": ("downloads", "package_prefix"),
            "open_folder_after_download": ("downloads", "open_folder_after_download"),
            "overwrite_existing": ("downloads", "overwrite_existing"),
            "font_name": ("ui", "font_name"),
            "font_size": ("ui", "font_size"),
            "compact_mode": ("ui", "compact_mode"),
            "theme": ("ui", "theme"),
            "table_row_limit": ("ui", "table_row_limit"),
            "last_export_path": ("diagnostics", "last_export_path"),
            "last_import_path": ("diagnostics", "last_import_path"),
        }

        for legacy_key, (section_name, setting_name) in legacy_map.items():
            if legacy_key in raw_settings:
                settings[section_name][setting_name] = raw_settings.get(legacy_key)

        if isinstance(raw_settings.get("request_timeout"), (list, tuple)) and len(raw_settings["request_timeout"]) == 2:
            settings["connection"]["timeout_connect"] = raw_settings["request_timeout"][0]
            settings["connection"]["timeout_read"] = raw_settings["request_timeout"][1]

        connection = settings["connection"]
        refresh = settings["refresh"]
        analytics = settings["analytics"]
        logging_cfg = settings["logging"]
        downloads = settings["downloads"]
        ui = settings["ui"]
        diagnostics = settings["diagnostics"]

        server_url = str(connection.get("server_url") or DEFAULT_SETTINGS["connection"]["server_url"]).strip()
        connection["server_url"] = server_url or DEFAULT_SETTINGS["connection"]["server_url"]
        connection["verify_ssl"] = bool(connection.get("verify_ssl", DEFAULT_SETTINGS["connection"]["verify_ssl"]))
        connection["trust_store_mode"] = str(connection.get("trust_store_mode", "") or "").strip().lower() or DEFAULT_SETTINGS["connection"]["trust_store_mode"]
        if connection["trust_store_mode"] not in {"system", "custom"}:
            connection["trust_store_mode"] = "custom" if str(connection.get("ca_cert_path", "") or "").strip() else DEFAULT_SETTINGS["connection"]["trust_store_mode"]
        connection["ca_cert_path"] = str(connection.get("ca_cert_path", "") or "").strip()
        connection["timeout_connect"] = max(0.1, float(connection.get("timeout_connect", 3.05)))
        connection["timeout_read"] = max(0.1, float(connection.get("timeout_read", 10.0)))
        connection["auto_connect"] = bool(connection.get("auto_connect", False))

        refresh["auto_refresh"] = bool(refresh.get("auto_refresh", True))
        refresh["refresh_interval"] = max(5, int(refresh.get("refresh_interval", 30)))
        refresh["monitoring_interval"] = max(5, int(refresh.get("monitoring_interval", 30)))
        refresh["analytics_interval"] = max(5, int(refresh.get("analytics_interval", 60)))
        refresh["monitoring_status_limit"] = max(10, int(refresh.get("monitoring_status_limit", 1000)))
        refresh["monitoring_logs_limit"] = max(10, int(refresh.get("monitoring_logs_limit", 500)))
        refresh["monitoring_logs_level"] = str(refresh.get("monitoring_logs_level", "all"))
        if refresh["monitoring_logs_level"] not in {"all", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            refresh["monitoring_logs_level"] = "all"
        refresh["monitoring_client_scope"] = str(refresh.get("monitoring_client_scope", "all"))
        if refresh["monitoring_client_scope"] not in {"all", "default"}:
            refresh["monitoring_client_scope"] = "all"

        analytics["limit"] = max(10, int(analytics.get("limit", 1000)))
        analytics["table_limit"] = max(10, int(analytics.get("table_limit", 250)))
        analytics["default_client"] = str(analytics.get("default_client", "all"))
        if analytics["default_client"] not in {"all", "selected"}:
            analytics["default_client"] = "all"

        logging_cfg["level"] = str(logging_cfg.get("level", "INFO"))
        if logging_cfg["level"] not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            logging_cfg["level"] = "INFO"
        logging_cfg["max_entries"] = max(100, int(logging_cfg.get("max_entries", 1000)))

        downloads["directory"] = str(Path(downloads.get("directory") or DEFAULT_SETTINGS["downloads"]["directory"]).expanduser())
        downloads["package_prefix"] = str(downloads.get("package_prefix", "flamix-client")).strip() or "flamix-client"
        downloads["open_folder_after_download"] = bool(downloads.get("open_folder_after_download", False))
        downloads["overwrite_existing"] = bool(downloads.get("overwrite_existing", False))

        ui["font_name"] = ui.get("font_name") or None
        ui["font_size"] = min(36, max(8, int(ui.get("font_size", 13))))
        ui["compact_mode"] = bool(ui.get("compact_mode", False))
        ui["theme"] = str(ui.get("theme", "system"))
        if ui["theme"] not in {"system", "light", "dark"}:
            ui["theme"] = "system"
        ui["table_row_limit"] = max(10, int(ui.get("table_row_limit", 200)))

        diagnostics["last_export_path"] = str(diagnostics.get("last_export_path", ""))
        diagnostics["last_import_path"] = str(diagnostics.get("last_import_path", ""))

        self._sync_legacy_aliases(settings)
        return settings

    def _sync_legacy_aliases(self, settings: Optional[Dict[str, Any]] = None):
        """Keeps old flat keys available for compatibility."""
        settings = settings or self.settings
        settings["server_url"] = settings.get("connection", {}).get("server_url", DEFAULT_SETTINGS["connection"]["server_url"])
        settings["verify_ssl"] = settings.get("connection", {}).get("verify_ssl", DEFAULT_SETTINGS["connection"]["verify_ssl"])
        settings["trust_store_mode"] = settings.get("connection", {}).get("trust_store_mode", DEFAULT_SETTINGS["connection"]["trust_store_mode"])
        settings["ca_cert_path"] = settings.get("connection", {}).get("ca_cert_path", "")
        settings["timeout_connect"] = settings.get("connection", {}).get("timeout_connect", 3.05)
        settings["timeout_read"] = settings.get("connection", {}).get("timeout_read", 10.0)
        settings["auto_connect"] = settings.get("connection", {}).get("auto_connect", False)
        settings["auto_refresh"] = settings.get("refresh", {}).get("auto_refresh", True)
        settings["refresh_interval"] = settings.get("refresh", {}).get("refresh_interval", 30)
        settings["monitoring_interval"] = settings.get("refresh", {}).get("monitoring_interval", 30)
        settings["analytics_interval"] = settings.get("refresh", {}).get("analytics_interval", 60)
        settings["analytics_limit"] = settings.get("analytics", {}).get("limit", 1000)
        settings["font_name"] = settings.get("ui", {}).get("font_name")
        settings["font_size"] = settings.get("ui", {}).get("font_size", 13)
        settings["download_dir"] = settings.get("downloads", {}).get("directory", str(Path.home() / "Downloads"))
        settings["package_prefix"] = settings.get("downloads", {}).get("package_prefix", "flamix-client")
        settings["open_folder_after_download"] = settings.get("downloads", {}).get("open_folder_after_download", False)
        settings["overwrite_existing"] = settings.get("downloads", {}).get("overwrite_existing", False)

    def _load_settings(self):
        """Loads settings from JSON file and migrates old layouts."""
        try:
            if self.settings_file.exists():
                with open(self.settings_file, "r", encoding="utf-8") as f:
                    raw_settings = json.load(f)
                self.settings = self._normalize_settings(raw_settings)
                logger.info(f"Settings loaded from {self.settings_file}")
            else:
                self.settings = self._normalize_settings({})
                self._save_settings()
                logger.info(f"Created default settings file: {self.settings_file}")
        except Exception as e:
            logger.error(f"Failed to load settings: {e}", exc_info=True)
            self.settings = self._normalize_settings({})

    def _save_settings(self, capture_ui: bool = True):
        """Persists the current settings snapshot to disk."""
        try:
            if capture_ui:
                if dpg.does_item_exist("server_url_input"):
                    self.settings.setdefault("connection", {})["server_url"] = dpg.get_value("server_url_input")
                if dpg.does_item_exist("settings_server_url_input"):
                    self.settings.setdefault("connection", {})["server_url"] = dpg.get_value("settings_server_url_input")
                if dpg.does_item_exist("settings_verify_ssl_checkbox"):
                    self.settings.setdefault("connection", {})["verify_ssl"] = bool(dpg.get_value("settings_verify_ssl_checkbox"))
                if dpg.does_item_exist("settings_trust_store_mode_combo"):
                    self.settings.setdefault("connection", {})["trust_store_mode"] = dpg.get_value("settings_trust_store_mode_combo")
                if dpg.does_item_exist("settings_ca_cert_path_input"):
                    self.settings.setdefault("connection", {})["ca_cert_path"] = dpg.get_value("settings_ca_cert_path_input")
                if dpg.does_item_exist("settings_connect_timeout_input"):
                    self.settings.setdefault("connection", {})["timeout_connect"] = dpg.get_value("settings_connect_timeout_input")
                if dpg.does_item_exist("settings_read_timeout_input"):
                    self.settings.setdefault("connection", {})["timeout_read"] = dpg.get_value("settings_read_timeout_input")
                if dpg.does_item_exist("settings_auto_connect_checkbox"):
                    self.settings.setdefault("connection", {})["auto_connect"] = bool(dpg.get_value("settings_auto_connect_checkbox"))

                if dpg.does_item_exist("settings_auto_refresh_checkbox"):
                    self.settings.setdefault("refresh", {})["auto_refresh"] = bool(dpg.get_value("settings_auto_refresh_checkbox"))
                if dpg.does_item_exist("settings_refresh_interval_input"):
                    self.settings.setdefault("refresh", {})["refresh_interval"] = dpg.get_value("settings_refresh_interval_input")
                if dpg.does_item_exist("settings_monitoring_interval_input"):
                    self.settings.setdefault("refresh", {})["monitoring_interval"] = dpg.get_value("settings_monitoring_interval_input")
                if dpg.does_item_exist("settings_analytics_interval_input"):
                    self.settings.setdefault("refresh", {})["analytics_interval"] = dpg.get_value("settings_analytics_interval_input")
                if dpg.does_item_exist("settings_analytics_limit_input"):
                    self.settings.setdefault("analytics", {})["limit"] = dpg.get_value("settings_analytics_limit_input")
                if dpg.does_item_exist("settings_analytics_table_limit_input"):
                    self.settings.setdefault("analytics", {})["table_limit"] = dpg.get_value("settings_analytics_table_limit_input")
                if dpg.does_item_exist("settings_analytics_default_client_combo"):
                    self.settings.setdefault("analytics", {})["default_client"] = dpg.get_value("settings_analytics_default_client_combo")
                if dpg.does_item_exist("settings_monitoring_status_limit_input"):
                    self.settings.setdefault("refresh", {})["monitoring_status_limit"] = dpg.get_value("settings_monitoring_status_limit_input")
                if dpg.does_item_exist("settings_monitoring_logs_limit_input"):
                    self.settings.setdefault("refresh", {})["monitoring_logs_limit"] = dpg.get_value("settings_monitoring_logs_limit_input")
                if dpg.does_item_exist("settings_monitoring_logs_level_combo"):
                    self.settings.setdefault("refresh", {})["monitoring_logs_level"] = dpg.get_value("settings_monitoring_logs_level_combo")
                if dpg.does_item_exist("settings_monitoring_scope_combo"):
                    self.settings.setdefault("refresh", {})["monitoring_client_scope"] = dpg.get_value("settings_monitoring_scope_combo")
                if dpg.does_item_exist("settings_log_level_combo"):
                    self.settings.setdefault("logging", {})["level"] = dpg.get_value("settings_log_level_combo")
                if dpg.does_item_exist("settings_log_entry_limit_input"):
                    self.settings.setdefault("logging", {})["max_entries"] = dpg.get_value("settings_log_entry_limit_input")
                if dpg.does_item_exist("settings_download_dir_input"):
                    self.settings.setdefault("downloads", {})["directory"] = dpg.get_value("settings_download_dir_input")
                if dpg.does_item_exist("settings_package_prefix_input"):
                    self.settings.setdefault("downloads", {})["package_prefix"] = dpg.get_value("settings_package_prefix_input")
                if dpg.does_item_exist("settings_open_folder_checkbox"):
                    self.settings.setdefault("downloads", {})["open_folder_after_download"] = bool(dpg.get_value("settings_open_folder_checkbox"))
                if dpg.does_item_exist("settings_overwrite_checkbox"):
                    self.settings.setdefault("downloads", {})["overwrite_existing"] = bool(dpg.get_value("settings_overwrite_checkbox"))
                if dpg.does_item_exist("settings_font_selector"):
                    self.settings.setdefault("ui", {})["font_name"] = dpg.get_value("settings_font_selector")
                if dpg.does_item_exist("settings_font_size_input"):
                    self.settings.setdefault("ui", {})["font_size"] = dpg.get_value("settings_font_size_input")
                if dpg.does_item_exist("settings_compact_mode_checkbox"):
                    self.settings.setdefault("ui", {})["compact_mode"] = bool(dpg.get_value("settings_compact_mode_checkbox"))
                if dpg.does_item_exist("settings_theme_combo"):
                    self.settings.setdefault("ui", {})["theme"] = dpg.get_value("settings_theme_combo")
                if dpg.does_item_exist("settings_table_row_limit_input"):
                    self.settings.setdefault("ui", {})["table_row_limit"] = dpg.get_value("settings_table_row_limit_input")
                if dpg.does_item_exist("settings_export_path_input"):
                    self.settings.setdefault("diagnostics", {})["last_export_path"] = dpg.get_value("settings_export_path_input")
                if dpg.does_item_exist("settings_import_path_input"):
                    self.settings.setdefault("diagnostics", {})["last_import_path"] = dpg.get_value("settings_import_path_input")

            self.settings = self._normalize_settings(self.settings)
            with open(self.settings_file, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, indent=4, ensure_ascii=False)
            logger.info(f"Settings saved to {self.settings_file}")
        except Exception as e:
            logger.error(f"Failed to save settings: {e}", exc_info=True)

    def _get_settings_snapshot(self) -> Dict[str, Any]:
        """Returns the current validated settings snapshot."""
        snapshot = self._normalize_settings(self.settings)
        self.settings = snapshot
        return snapshot

    def _capture_settings_from_ui(self) -> Dict[str, Any]:
        """Collects settings from visible controls when they exist."""
        snapshot = self._get_settings_snapshot()
        connection = snapshot.setdefault("connection", {})
        refresh = snapshot.setdefault("refresh", {})
        analytics = snapshot.setdefault("analytics", {})
        logging_cfg = snapshot.setdefault("logging", {})
        downloads = snapshot.setdefault("downloads", {})
        ui = snapshot.setdefault("ui", {})
        diagnostics = snapshot.setdefault("diagnostics", {})

        if dpg.does_item_exist("server_url_input"):
            connection["server_url"] = dpg.get_value("server_url_input")
        if dpg.does_item_exist("settings_server_url_input"):
            connection["server_url"] = dpg.get_value("settings_server_url_input")
        if dpg.does_item_exist("settings_verify_ssl_checkbox"):
            connection["verify_ssl"] = bool(dpg.get_value("settings_verify_ssl_checkbox"))
        if dpg.does_item_exist("settings_trust_store_mode_combo"):
            connection["trust_store_mode"] = dpg.get_value("settings_trust_store_mode_combo")
        if dpg.does_item_exist("settings_ca_cert_path_input"):
            connection["ca_cert_path"] = dpg.get_value("settings_ca_cert_path_input")
        if dpg.does_item_exist("settings_connect_timeout_input"):
            connection["timeout_connect"] = dpg.get_value("settings_connect_timeout_input")
        if dpg.does_item_exist("settings_read_timeout_input"):
            connection["timeout_read"] = dpg.get_value("settings_read_timeout_input")
        if dpg.does_item_exist("settings_auto_connect_checkbox"):
            connection["auto_connect"] = bool(dpg.get_value("settings_auto_connect_checkbox"))

        if dpg.does_item_exist("settings_auto_refresh_checkbox"):
            refresh["auto_refresh"] = bool(dpg.get_value("settings_auto_refresh_checkbox"))
        if dpg.does_item_exist("settings_refresh_interval_input"):
            refresh["refresh_interval"] = dpg.get_value("settings_refresh_interval_input")
        if dpg.does_item_exist("settings_monitoring_interval_input"):
            refresh["monitoring_interval"] = dpg.get_value("settings_monitoring_interval_input")
        if dpg.does_item_exist("settings_monitoring_status_limit_input"):
            refresh["monitoring_status_limit"] = dpg.get_value("settings_monitoring_status_limit_input")
        if dpg.does_item_exist("settings_monitoring_logs_limit_input"):
            refresh["monitoring_logs_limit"] = dpg.get_value("settings_monitoring_logs_limit_input")
        if dpg.does_item_exist("settings_monitoring_logs_level_combo"):
            refresh["monitoring_logs_level"] = dpg.get_value("settings_monitoring_logs_level_combo")
        if dpg.does_item_exist("settings_monitoring_scope_combo"):
            refresh["monitoring_client_scope"] = dpg.get_value("settings_monitoring_scope_combo")
        if dpg.does_item_exist("settings_analytics_interval_input"):
            refresh["analytics_interval"] = dpg.get_value("settings_analytics_interval_input")

        if dpg.does_item_exist("settings_analytics_limit_input"):
            analytics["limit"] = dpg.get_value("settings_analytics_limit_input")
        if dpg.does_item_exist("settings_analytics_table_limit_input"):
            analytics["table_limit"] = dpg.get_value("settings_analytics_table_limit_input")
        if dpg.does_item_exist("settings_analytics_default_client_combo"):
            analytics["default_client"] = dpg.get_value("settings_analytics_default_client_combo")

        if dpg.does_item_exist("settings_log_level_combo"):
            logging_cfg["level"] = dpg.get_value("settings_log_level_combo")
        if dpg.does_item_exist("settings_log_entry_limit_input"):
            logging_cfg["max_entries"] = dpg.get_value("settings_log_entry_limit_input")

        if dpg.does_item_exist("settings_download_dir_input"):
            downloads["directory"] = dpg.get_value("settings_download_dir_input")
        if dpg.does_item_exist("settings_package_prefix_input"):
            downloads["package_prefix"] = dpg.get_value("settings_package_prefix_input")
        if dpg.does_item_exist("settings_open_folder_checkbox"):
            downloads["open_folder_after_download"] = bool(dpg.get_value("settings_open_folder_checkbox"))
        if dpg.does_item_exist("settings_overwrite_checkbox"):
            downloads["overwrite_existing"] = bool(dpg.get_value("settings_overwrite_checkbox"))

        if dpg.does_item_exist("settings_font_selector"):
            ui["font_name"] = dpg.get_value("settings_font_selector")
        if dpg.does_item_exist("settings_font_size_input"):
            ui["font_size"] = dpg.get_value("settings_font_size_input")
        if dpg.does_item_exist("settings_compact_mode_checkbox"):
            ui["compact_mode"] = bool(dpg.get_value("settings_compact_mode_checkbox"))
        if dpg.does_item_exist("settings_theme_combo"):
            ui["theme"] = dpg.get_value("settings_theme_combo")
        if dpg.does_item_exist("settings_table_row_limit_input"):
            ui["table_row_limit"] = dpg.get_value("settings_table_row_limit_input")

        if dpg.does_item_exist("settings_export_path_input"):
            diagnostics["last_export_path"] = dpg.get_value("settings_export_path_input")
        if dpg.does_item_exist("settings_import_path_input"):
            diagnostics["last_import_path"] = dpg.get_value("settings_import_path_input")

        return self._normalize_settings(snapshot)

    def _get_connection_settings(self) -> Dict[str, Any]:
        return self._get_settings_snapshot().get("connection", {})

    def _get_refresh_settings(self) -> Dict[str, Any]:
        return self._get_settings_snapshot().get("refresh", {})

    def _get_analytics_settings(self) -> Dict[str, Any]:
        return self._get_settings_snapshot().get("analytics", {})

    def _get_monitoring_settings(self) -> Dict[str, Any]:
        return self._get_settings_snapshot().get("refresh", {})

    def _get_download_settings(self) -> Dict[str, Any]:
        return self._get_settings_snapshot().get("downloads", {})

    def _get_ui_settings(self) -> Dict[str, Any]:
        return self._get_settings_snapshot().get("ui", {})

    def _resolve_verify_target(self, connection: Dict[str, Any]) -> Any:
        """Build requests-compatible TLS verification config from GUI settings."""
        if not connection.get("verify_ssl", DEFAULT_SETTINGS["connection"]["verify_ssl"]):
            return False

        trust_store_mode = str(connection.get("trust_store_mode", DEFAULT_SETTINGS["connection"]["trust_store_mode"]) or "").strip().lower()
        if trust_store_mode == "custom":
            ca_cert_path = str(connection.get("ca_cert_path", "") or "").strip()
            if ca_cert_path:
                return ca_cert_path
        return True

    def _validate_connection_config(self, connection: Dict[str, Any]) -> tuple[bool, str]:
        """Validate TLS-related connection settings before applying them."""
        if not connection.get("verify_ssl", DEFAULT_SETTINGS["connection"]["verify_ssl"]):
            return True, "TLS verification disabled"

        trust_store_mode = str(connection.get("trust_store_mode", DEFAULT_SETTINGS["connection"]["trust_store_mode"]) or "").strip().lower()
        if trust_store_mode != "custom":
            return True, "Using system trust store"

        ca_cert_path = str(connection.get("ca_cert_path", "") or "").strip()
        if not ca_cert_path:
            return False, "Custom trust store mode requires a CA certificate path"

        cert_path = Path(ca_cert_path).expanduser()
        if not cert_path.exists():
            return False, f"CA certificate file not found: {cert_path}"
        if not cert_path.is_file():
            return False, f"CA certificate path is not a file: {cert_path}"

        try:
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        except Exception as exc:
            return False, f"Failed to read CA certificate: {exc}"

        try:
            basic_constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            if not basic_constraints.ca:
                return False, (
                    "Selected certificate is not a CA certificate. "
                    "Use certs\\ca.crt, not server.crt"
                )
        except x509.ExtensionNotFound:
            return False, (
                "Selected certificate does not declare CA capability. "
                "Use certs\\ca.crt, not server.crt"
            )

        return True, f"Using custom CA: {cert_path}"

    def _get_server_runtime_snapshot(self) -> Dict[str, Any]:
        return copy.deepcopy(self.server_runtime_snapshot)

    def _apply_settings_snapshot(self, snapshot: Dict[str, Any]):
        """Validates, stores, and applies a new settings snapshot."""
        normalized_snapshot = self._normalize_settings(snapshot)
        connection_ok, connection_message = self._validate_connection_config(
            normalized_snapshot.get("connection", {})
        )
        if not connection_ok:
            return False, connection_message, self._get_settings_snapshot()

        self.settings = normalized_snapshot
        self._sync_top_bar_from_settings()
        self._apply_runtime_settings()
        self._save_settings(capture_ui=False)
        self._update_settings_controls_from_state()
        return True, "Settings applied", self._get_settings_snapshot()

    def _refresh_server_runtime_snapshot(self, silent: bool = False):
        """Loads the current server runtime config and diagnostics."""
        if not self.connected:
            return False, "Connect to the server first", self._get_server_runtime_snapshot()

        try:
            config_payload = self.api_client.get_server_config() or {}
            info_payload = self.api_client.get_server_info() or {}
            health_payload = self.api_client.get_server_health() or {}

            self.server_runtime_snapshot = {
                "config": config_payload.get("config", {}),
                "stored_config": config_payload.get("stored_config"),
                "restart_required": bool(config_payload.get("restart_required", False)),
                "info": info_payload.get("info", {}),
                "health": health_payload.get("health", {}),
                "last_loaded_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
            self._update_settings_controls_from_state()
            message = "Server runtime settings loaded"
            if not silent:
                logger.info(message)
            return True, message, self._get_server_runtime_snapshot()
        except Exception as e:
            logger.error(f"Failed to load server runtime settings: {e}", exc_info=True)
            return False, f"Failed to load server runtime settings: {e}", self._get_server_runtime_snapshot()

    def _apply_server_runtime_patch(self, patch: Dict[str, Any]):
        """Applies runtime config changes to the server."""
        if not self.connected:
            return False, "Connect to the server first", self._get_server_runtime_snapshot()

        try:
            result = self.api_client.update_server_config(patch or {})
            if not result or not result.get("success", False):
                return False, "Server rejected runtime config update", self._get_server_runtime_snapshot()

            self.server_runtime_snapshot = {
                "config": result.get("config", self.server_runtime_snapshot.get("config", {})),
                "stored_config": result.get("stored_config", self.server_runtime_snapshot.get("stored_config")),
                "restart_required": bool(result.get("restart_required", False)),
                "info": self.server_runtime_snapshot.get("info", {}),
                "health": self.server_runtime_snapshot.get("health", {}),
                "last_loaded_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
            self._update_settings_controls_from_state()

            restart_fields = result.get("restart_required_fields") or []
            applied_live = result.get("applied_live") or []
            parts = []
            if applied_live:
                parts.append(f"Applied live: {', '.join(applied_live)}")
            if restart_fields:
                parts.append(f"Restart required for: {', '.join(restart_fields)}")
            message = "; ".join(parts) if parts else "Server runtime settings updated"
            return True, message, self._get_server_runtime_snapshot()
        except Exception as e:
            logger.error(f"Failed to update server runtime settings: {e}", exc_info=True)
            return False, f"Failed to update server runtime settings: {e}", self._get_server_runtime_snapshot()

    def _apply_runtime_settings(self):
        connection = self.settings.get("connection", {})
        ui = self.settings.get("ui", {})
        refresh = self.settings.get("refresh", {})

        self.api_client.update_connection_options(
            base_url=connection.get("server_url"),
            verify_ssl=self._resolve_verify_target(connection),
            request_timeout=(connection.get("timeout_connect", 3.05), connection.get("timeout_read", 10.0)),
        )

        self.font_size = int(ui.get("font_size", self.font_size))
        self.selected_font_name = ui.get("font_name")
        if refresh.get("monitoring_client_scope", "all") == "default":
            self.monitoring_client_id = self.client_manager.current_client_id or self.monitoring_client_id or "all"
        else:
            self.monitoring_client_id = "all"

        self.client_manager.api_client = self.api_client
        self.rules_manager.api_client = self.api_client
        self.analytics_manager.api_client = self.api_client
        self.change_requests_manager.api_client = self.api_client
        self.monitoring_manager.api_client = self.api_client

        if refresh.get("auto_refresh", True) and self.connected:
            if self.api_client and self.api_client.base_url:
                self.start_auto_refresh()
        else:
            self.stop_auto_refresh()

    def _sync_top_bar_from_settings(self):
        connection = self.settings.get("connection", {})
        if dpg.does_item_exist("server_url_input"):
            dpg.set_value("server_url_input", connection.get("server_url", DEFAULT_SETTINGS["connection"]["server_url"]))
        if dpg.does_item_exist("status_text") and not self.connecting:
            status = f"Status: Connected to {connection.get('server_url')}" if self.connected else "Status: Disconnected"
            dpg.set_value("status_text", status)

    def _update_settings_controls_from_state(self):
        if dpg.does_item_exist("settings_server_url_input"):
            snapshot = self._get_settings_snapshot()
            self.settings_manager._sync_controls_from_snapshot(snapshot)
            self.settings_manager._sync_server_runtime_controls(self._get_server_runtime_snapshot())
            refresh = snapshot.get("refresh", {})
            analytics = snapshot.get("analytics", {})

            if dpg.does_item_exist("monitoring_logs_level_combo"):
                dpg.set_value("monitoring_logs_level_combo", refresh.get("monitoring_logs_level", "all"))
            if dpg.does_item_exist("monitoring_global_client_combo"):
                if refresh.get("monitoring_client_scope", "all") == "default" and self.client_manager.current_client_id:
                    dpg.set_value("monitoring_global_client_combo", str(self.client_manager.current_client_id))
                else:
                    dpg.set_value("monitoring_global_client_combo", "all")
            if dpg.does_item_exist("analytics_client_combo"):
                if analytics.get("default_client", "all") == "selected" and self.client_manager.current_client_id:
                    dpg.set_value("analytics_client_combo", str(self.client_manager.current_client_id))
                else:
                    dpg.set_value("analytics_client_combo", "all")

    def _test_connection_with_snapshot(self, snapshot: Dict[str, Any]):
        settings = self._normalize_settings(snapshot)
        connection = settings.get("connection", {})
        connection_ok, connection_message = self._validate_connection_config(connection)
        if not connection_ok:
            return False, connection_message
        temp_client = FlamixAPIClient(
            base_url=connection.get("server_url"),
            verify_ssl=self._resolve_verify_target(connection),
            request_timeout=(connection.get("timeout_connect", 3.05), connection.get("timeout_read", 10.0)),
        )
        connected = temp_client.test_connection()
        message = f"Connection OK: {connection.get('server_url')}" if connected else f"Connection failed: {connection.get('server_url')}"
        return connected, message

    def _connect_with_snapshot(self, snapshot: Dict[str, Any]):
        result = self._apply_settings_snapshot(snapshot)
        if isinstance(result, tuple) and len(result) >= 2 and not bool(result[0]):
            return False, str(result[1])
        self.on_connect()
        return True, "Connection request started"

    def _export_settings(self, path: str):
        try:
            target = Path(path).expanduser()
            target.parent.mkdir(parents=True, exist_ok=True)
            snapshot = self._get_settings_snapshot()
            with open(target, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=4, ensure_ascii=False)
            self.settings.setdefault("diagnostics", {})["last_export_path"] = str(target)
            self._save_settings(capture_ui=False)
            return True, f"Exported settings to {target}"
        except Exception as e:
            logger.error(f"Failed to export settings: {e}", exc_info=True)
            return False, f"Export failed: {e}"

    def _import_settings(self, path: str):
        try:
            source = Path(path).expanduser()
            with open(source, "r", encoding="utf-8") as f:
                imported = json.load(f)
            if isinstance(imported, dict):
                imported_connection = imported.get("connection")
                if isinstance(imported_connection, dict):
                    imported_ca_cert_path = str(imported_connection.get("ca_cert_path", "") or "").strip()
                    if imported_ca_cert_path:
                        ca_path = Path(imported_ca_cert_path)
                        if not ca_path.is_absolute():
                            imported_connection["ca_cert_path"] = str((source.parent / ca_path).resolve())
                        imported_connection.setdefault("trust_store_mode", "custom")
            snapshot = self._normalize_settings(imported)
            self.settings = snapshot
            self.settings.setdefault("diagnostics", {})["last_import_path"] = str(source)
            self.connected = False
            self.stop_auto_refresh()
            self._apply_runtime_settings()
            self._save_settings(capture_ui=False)
            self._update_settings_controls_from_state()
            return True, f"Imported settings from {source}", self._get_settings_snapshot()
        except Exception as e:
            logger.error(f"Failed to import settings: {e}", exc_info=True)
            return False, f"Import failed: {e}"

    def _reset_settings_to_defaults(self):
        self.settings = self._normalize_settings({})
        self.connected = False
        self.stop_auto_refresh()
        self._apply_runtime_settings()
        self._save_settings(capture_ui=False)
        self._update_settings_controls_from_state()
        return True, "Defaults restored", self._get_settings_snapshot()

    def _load_fonts(self):
        """Р—Р°РіСЂСѓР·РєР° РґРѕСЃС‚СѓРїРЅС‹С… TTF С€СЂРёС„С‚РѕРІ РёР· РґРёСЂРµРєС‚РѕСЂРёРё fonts"""
        if not self.fonts_dir.exists():
            logger.warning(f"Fonts directory not found: {self.fonts_dir}")
            return

        # РС‰РµРј РІСЃРµ TTF С„Р°Р№Р»С‹
        ttf_files = list(self.fonts_dir.glob("*.ttf"))
        if not ttf_files:
            logger.info("No TTF fonts found in fonts directory")
            return

        self.available_fonts = ttf_files
        logger.info(f"Found {len(ttf_files)} font(s): {[f.name for f in ttf_files]}")

        # Р—Р°РіСЂСѓР¶Р°РµРј С€СЂРёС„С‚ РёР· РЅР°СЃС‚СЂРѕРµРє РёР»Рё РїРµСЂРІС‹Р№ РЅР°Р№РґРµРЅРЅС‹Р№ РїРѕ СѓРјРѕР»С‡Р°РЅРёСЋ
        if ttf_files:
            # РџС‹С‚Р°РµРјСЃСЏ РЅР°Р№С‚Рё СЃРѕС…СЂР°РЅРµРЅРЅС‹Р№ С€СЂРёС„С‚
            font_path = None
            if self.selected_font_name:
                for font_file in ttf_files:
                    if font_file.name == self.selected_font_name:
                        font_path = font_file
                        break

            # Р•СЃР»Рё СЃРѕС…СЂР°РЅРµРЅРЅС‹Р№ С€СЂРёС„С‚ РЅРµ РЅР°Р№РґРµРЅ, РёС‰РµРј "cyclic" РёР»Рё РёСЃРїРѕР»СЊР·СѓРµРј РїРµСЂРІС‹Р№ РґРѕСЃС‚СѓРїРЅС‹Р№
            if font_path is None:
                for font_file in ttf_files:
                    if "cyclic" in font_file.name.lower():
                        font_path = font_file
                        self.selected_font_name = font_path.name
                        break

                # Р•СЃР»Рё РЅРµ РЅР°С€Р»Рё cyclic, РёСЃРїРѕР»СЊР·СѓРµРј РїРµСЂРІС‹Р№ РґРѕСЃС‚СѓРїРЅС‹Р№
                if font_path is None:
                    font_path = ttf_files[0]
                    self.selected_font_name = font_path.name

            try:
                # РЈРґР°Р»СЏРµРј СЃС‚Р°СЂС‹Р№ С€СЂРёС„С‚, РµСЃР»Рё РѕРЅ СЃСѓС‰РµСЃС‚РІСѓРµС‚ (С‚РѕР»СЊРєРѕ РїСЂРё РїРѕРІС‚РѕСЂРЅРѕР№ Р·Р°РіСЂСѓР·РєРµ)
                if self.current_font is not None:
                    dpg.delete_item(self.current_font)

                # РЎРѕР·РґР°РµРј РЅРѕРІС‹Р№ С€СЂРёС„С‚ РІ font_registry
                with dpg.font_registry():
                    self.current_font = dpg.add_font(str(font_path), self.font_size)
                    logger.info(f"Loaded font: {font_path.name} (size: {self.font_size})")
            except Exception as e:
                logger.error(f"Failed to load font {font_path.name if font_path else 'unknown'}: {e}", exc_info=True)

    def _apply_font(self, font_tag: Optional[int] = None):
        """РџСЂРёРјРµРЅРµРЅРёРµ С€СЂРёС„С‚Р° РєРѕ РІСЃРµРјСѓ РёРЅС‚РµСЂС„РµР№СЃСѓ"""
        if font_tag is None:
            font_tag = self.current_font
        if font_tag is not None:
            try:
                dpg.bind_font(font_tag)
            except Exception as e:
                logger.error(f"Failed to apply font: {e}")

    def create_window(self):
        """Creates the main window."""
        self._load_fonts()

        dpg.create_viewport(title="Flamix Management", width=1400, height=900)

        ui_settings = self.settings.get("ui", {})
        compact_mode = bool(ui_settings.get("compact_mode", False))
        with dpg.theme() as global_theme:
            with dpg.theme_component(dpg.mvAll):
                dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 5, category=dpg.mvThemeCat_Core)
                dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 5, category=dpg.mvThemeCat_Core)
                if compact_mode:
                    dpg.add_theme_style(dpg.mvStyleVar_ItemSpacing, 6, 4, category=dpg.mvThemeCat_Core)
                    dpg.add_theme_style(dpg.mvStyleVar_FramePadding, 4, 3, category=dpg.mvThemeCat_Core)

        dpg.bind_theme(global_theme)

        if self.current_font is not None:
            self._apply_font()

        with dpg.window(label="Flamix Server Management", tag="main_window"):
            with dpg.group(horizontal=True):
                dpg.add_text("Server URL:")
                server_url = self.settings.get("connection", {}).get("server_url", DEFAULT_SETTINGS["connection"]["server_url"])
                with dpg.group(horizontal=True):
                    dpg.add_input_text(
                        default_value=server_url,
                        tag="server_url_input",
                        width=300,
                        callback=on_server_url_changed,
                    )
                    dpg.add_button(label="...", callback=self.show_server_url_dialog, width=30)
                dpg.add_button(label="Connect", callback=self.on_connect)
                dpg.add_text("Status: Disconnected", tag="status_text")

            dpg.add_separator()

            with dpg.tab_bar():
                with dpg.tab(label="Clients"):
                    self.client_manager.create_tab()

                with dpg.tab(label="Rules"):
                    self.rules_manager.create_tab()
                    if self.client_manager.current_client_id:
                        self.rules_manager.refresh_rules()

                with dpg.tab(label="Analytics"):
                    self.analytics_manager.create_tab()
                    self.analytics_manager.refresh_analytics()

                with dpg.tab(label="Change Requests"):
                    self.change_requests_manager.create_tab()
                    self.change_requests_manager.refresh_change_requests()

                with dpg.tab(label="Monitoring"):
                    self.monitoring_manager.create_tab()

                with dpg.tab(label="Settings"):
                    self.settings_manager.create_tab()

            if dpg.does_item_exist("client_context_menu"):
                dpg.delete_item("client_context_menu")

            with dpg.window(
                    tag="client_context_menu",
                    modal=True,
                    no_title_bar=True,
                    width=200,
                    height=120,
                    show=False,
                    on_close=self.client_manager.close_context_menu
            ):
                dpg.add_button(label="Edit Client", width=-1, callback=self.client_manager.edit_client_from_menu)
                dpg.add_button(label="Download Package", width=-1, callback=self.client_manager.download_client_package_from_menu)
                dpg.add_separator()
                dpg.add_button(label="Delete Client", width=-1, callback=self.client_manager.delete_client_from_menu)

        dpg.setup_dearpygui()
        dpg.show_viewport()
        dpg.set_primary_window("main_window", True)

        if self.settings.get("connection", {}).get("auto_connect", False):
            self.on_connect()

    def show_server_url_dialog(self):
        """Opens a multiline dialog for editing the top-bar server URL."""
        if dpg.does_item_exist("server_url_dialog"):
            dpg.delete_item("server_url_dialog")

        current_url = dpg.get_value("server_url_input") if dpg.does_item_exist("server_url_input") else self.settings.get("connection", {}).get("server_url", DEFAULT_SETTINGS["connection"]["server_url"])

        with dpg.window(
                label="Edit Server URL",
                modal=True,
                tag="server_url_dialog",
                width=700,
                height=150,
                pos=[400, 300]
        ):
            dpg.add_text("Server URL:")
            dpg.add_input_text(
                default_value=current_url,
                tag="server_url_dialog_input",
                width=-1,
                multiline=True
            )
            with dpg.group(horizontal=True):
                dpg.add_button(label="OK", callback=lambda: self.apply_server_url_from_dialog())
                dpg.add_button(label="Cancel", callback=lambda: dpg.delete_item("server_url_dialog"))

    def apply_server_url_from_dialog(self):
        """Applies the URL from the dialog to the settings snapshot."""
        new_url = str(dpg.get_value("server_url_dialog_input")).strip()
        dpg.delete_item("server_url_dialog")
        snapshot = self._capture_settings_from_ui()
        snapshot.setdefault("connection", {})["server_url"] = new_url or DEFAULT_SETTINGS["connection"]["server_url"]
        self._apply_settings_snapshot(snapshot)
        if dpg.does_item_exist("server_url_input"):
            dpg.set_value("server_url_input", snapshot["connection"]["server_url"])
    def on_connect(self):
        """Connects to the server using the current UI snapshot."""
        if self.connecting:
            logger.info("Connection attempt is already in progress")
            return

        snapshot = self._capture_settings_from_ui()
        connection = snapshot.get("connection", {})
        server_url = connection.get("server_url", DEFAULT_SETTINGS["connection"]["server_url"])
        dpg.set_value("status_text", f"Status: Connecting to {server_url}...")
        self.connecting = True

        def connect_worker():
            api_client = FlamixAPIClient(
                base_url=server_url,
                verify_ssl=self._resolve_verify_target(connection),
                request_timeout=(
                    float(connection.get("timeout_connect", 3.05)),
                    float(connection.get("timeout_read", 10.0)),
                ),
            )
            connected = False
            clients = []
            server_runtime_snapshot = copy.deepcopy(DEFAULT_SERVER_RUNTIME_SNAPSHOT)

            try:
                connected = api_client.test_connection()
                clients = api_client.get_clients() if connected else []
                if connected:
                    config_payload = api_client.get_server_config() or {}
                    info_payload = api_client.get_server_info() or {}
                    health_payload = api_client.get_server_health() or {}
                    server_runtime_snapshot = {
                        "config": config_payload.get("config", {}),
                        "stored_config": config_payload.get("stored_config"),
                        "restart_required": bool(config_payload.get("restart_required", False)),
                        "info": info_payload.get("info", {}),
                        "health": health_payload.get("health", {}),
                        "last_loaded_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    }
            except Exception as e:
                logger.error(f"Connection worker failed: {e}", exc_info=True)

            def apply_connection_result():
                self.connecting = False

                if connected:
                    self.connected = True
                    self.api_client = api_client
                    self.settings = self._normalize_settings(snapshot)
                    self.server_runtime_snapshot = server_runtime_snapshot
                    self._save_settings(capture_ui=False)
                    self._apply_runtime_settings()
                    dpg.set_value("status_text", f"Status: Connected to {server_url}")
                    logger.info(f"Connected to server: {server_url}")
                    self.client_manager.apply_clients(clients)
                else:
                    self.connected = False
                    self.server_runtime_snapshot = copy.deepcopy(DEFAULT_SERVER_RUNTIME_SNAPSHOT)
                    self.stop_auto_refresh()
                    dpg.set_value("status_text", "Status: Connection failed")
                    logger.error("Failed to connect to server")

            self._refresh_queue.put(apply_connection_result)

        threading.Thread(target=connect_worker, daemon=True).start()
    def reload_window(self):
        """Р РµРёРЅРёС†РёР°Р»РёР·Р°С†РёСЏ РѕРєРЅР° РЅР° Р»РµС‚Сѓ"""
        try:
            logger.info("Reloading window...")

            # РЎРѕС…СЂР°РЅСЏРµРј С‚РµРєСѓС‰РµРµ СЃРѕСЃС‚РѕСЏРЅРёРµ
            current_client = None
            if self.client_manager.current_client_id and self.client_manager.clients_data:
                for client in self.client_manager.clients_data:
                    if str(client.get('id')) == str(self.client_manager.current_client_id):
                        current_client = client
                        break

            saved_state = {
                'server_url': dpg.get_value("server_url_input") if dpg.does_item_exist(
                    "server_url_input") else "https://127.0.0.1:8080",
                'connected': self.connected,
                'current_client_id': self.client_manager.current_client_id,
                'current_client': current_client
            }

            if self.refresh_thread and self.refresh_thread.is_alive():
                self.running = False
                self.refresh_thread.join(timeout=1.0)

            # РЈРґР°Р»СЏРµРј РІСЃРµ РґРѕС‡РµСЂРЅРёРµ СЌР»РµРјРµРЅС‚С‹ РѕРєРЅР°
            try:
                children = dpg.get_item_children("main_window", slot=1)
                for child in children:
                    dpg.delete_item(child)
            except Exception as e:
                logger.warning(f"Could not delete window children: {e}")

            # РџРµСЂРµСЃРѕР·РґР°РµРј СЃРѕРґРµСЂР¶РёРјРѕРµ РѕРєРЅР°
            # Р’РµСЂС…РЅСЏСЏ РїР°РЅРµР»СЊ
            with dpg.group(horizontal=True, parent="main_window"):
                dpg.add_text("Server URL:")
                with dpg.group(horizontal=True):
                    dpg.add_input_text(
                        default_value=saved_state['server_url'],
                        tag="server_url_input",
                        width=300,
                        callback=on_server_url_changed
                    )
                    dpg.add_button(
                        label="...",
                        callback=self.show_server_url_dialog,
                        width=30
                    )
                dpg.add_button(label="Connect", callback=self.on_connect)
                status_text = "Status: Connected" if saved_state['connected'] else "Status: Disconnected"
                dpg.add_text(status_text, tag="status_text")

            dpg.add_separator(parent="main_window")

            # РћСЃРЅРѕРІРЅР°СЏ РѕР±Р»Р°СЃС‚СЊ СЃ РІРєР»Р°РґРєР°РјРё
            with dpg.tab_bar(parent="main_window"):
                # Р’РєР»Р°РґРєР° РєР»РёРµРЅС‚РѕРІ
                with dpg.tab(label="Clients"):
                    self.client_manager.create_tab()

                # Р’РєР»Р°РґРєР° РїСЂР°РІРёР»
                with dpg.tab(label="Rules"):
                    self.rules_manager.create_tab()

                # Р’РєР»Р°РґРєР° Р°РЅР°Р»РёС‚РёРєРё
                with dpg.tab(label="Analytics"):
                    self.analytics_manager.create_tab()

                # Р’РєР»Р°РґРєР° Р·Р°РїСЂРѕСЃРѕРІ РЅР° РёР·РјРµРЅРµРЅРёРµ
                with dpg.tab(label="Change Requests"):
                    self.change_requests_manager.create_tab()

                # Р’РєР»Р°РґРєР° РјРѕРЅРёС‚РѕСЂРёРЅРіР°
                with dpg.tab(label="Monitoring"):
                    self.monitoring_manager.create_tab()

                # Р’РєР»Р°РґРєР° РЅР°СЃС‚СЂРѕРµРє
                with dpg.tab(label="Settings"):
                    self.settings_manager.create_tab()

            # Р’РѕСЃСЃС‚Р°РЅР°РІР»РёРІР°РµРј СЃРѕСЃС‚РѕСЏРЅРёРµ
            if saved_state['connected'] and self.api_client:
                # РћР±РЅРѕРІР»СЏРµРј СЃРїРёСЃРѕРє РєР»РёРµРЅС‚РѕРІ
                self.client_manager.refresh_clients()

                # Р’РѕСЃСЃС‚Р°РЅР°РІР»РёРІР°РµРј РІС‹Р±СЂР°РЅРЅРѕРіРѕ РєР»РёРµРЅС‚Р°, РµСЃР»Рё РѕРЅ Р±С‹Р»
                if saved_state['current_client_id']:
                    self.client_manager.current_client_id = saved_state['current_client_id']
                    if saved_state['current_client']:
                        for client in self.client_manager.clients_data:
                            if str(client.get('id')) == str(saved_state['current_client_id']):
                                self.client_manager._show_client_details(client)
                                break
                self._apply_runtime_settings()

            logger.info("Window reloaded successfully")
        except Exception as e:
            logger.error(f"Failed to reload window: {e}", exc_info=True)

    def _process_refresh_queue(self):
        """РћР±СЂР°Р±РѕС‚РєР° РѕС‡РµСЂРµРґРё РѕР±РЅРѕРІР»РµРЅРёР№ РІ РіР»Р°РІРЅРѕРј РїРѕС‚РѕРєРµ (РІС‹Р·С‹РІР°РµС‚СЃСЏ РёР· РіР»Р°РІРЅРѕРіРѕ С†РёРєР»Р°)"""
        try:
            while True:
                callback = self._refresh_queue.get_nowait()
                try:
                    callback()
                except Exception as e:
                    logger.error(f"Error in refresh callback: {e}", exc_info=True)
        except queue.Empty:
            pass

    def start_auto_refresh(self):
        """Starts the automatic refresh loop using configured intervals."""
        if self.refresh_thread and self.refresh_thread.is_alive():
            logger.debug("Auto refresh thread is already running")
            self.running = True
            return

        self.running = True

        def refresh_loop():
            next_clients = 0.0
            next_monitoring = 0.0
            next_analytics = 0.0
            next_requests = 0.0
            while self.running:
                refresh_settings = self._get_refresh_settings()
                if not refresh_settings.get("auto_refresh", True):
                    time.sleep(1.0)
                    continue

                now = time.monotonic()
                client_interval = max(5, int(refresh_settings.get("refresh_interval", 30)))
                monitoring_interval = max(5, int(refresh_settings.get("monitoring_interval", 30)))
                analytics_interval = max(5, int(refresh_settings.get("analytics_interval", 60)))

                if now >= next_clients:
                    self._refresh_queue.put(self.client_manager.refresh_clients)
                    if self.client_manager.current_client_id:
                        self._refresh_queue.put(self.rules_manager.refresh_rules)
                    next_clients = now + client_interval

                if now >= next_monitoring:
                    self._refresh_queue.put(self.monitoring_manager.refresh_monitoring)
                    next_monitoring = now + monitoring_interval

                if now >= next_analytics:
                    self._refresh_queue.put(self.analytics_manager.refresh_analytics)
                    next_analytics = now + analytics_interval

                if now >= next_requests:
                    self._refresh_queue.put(self.change_requests_manager.refresh_change_requests)
                    next_requests = now + client_interval

                time.sleep(1.0)

        self.refresh_thread = threading.Thread(target=refresh_loop, daemon=True)
        self.refresh_thread.start()
    def stop_auto_refresh(self):
        """РћСЃС‚Р°РЅРѕРІРєР° Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРѕРіРѕ РѕР±РЅРѕРІР»РµРЅРёСЏ"""
        self.running = False
        self.monitoring_running = False

    def run(self):
        """Р—Р°РїСѓСЃРє GUI РїСЂРёР»РѕР¶РµРЅРёСЏ"""
        self.create_window()
        try:
            while dpg.is_dearpygui_running():
                self._process_refresh_queue()
                dpg.render_dearpygui_frame()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop_auto_refresh()
            dpg.destroy_context()


def main():
    """РўРѕС‡РєР° РІС…РѕРґР° GUI РїСЂРёР»РѕР¶РµРЅРёСЏ"""
    import sys

    if len(sys.argv) > 1:
        server_url = sys.argv[1]
    else:
        server_url = "https://127.0.0.1:8080"

    app = FlamixGUI(server_url)
    app.run()


if __name__ == "__main__":
    main()








