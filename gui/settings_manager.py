"""Settings tab helpers for Flamix GUI."""

import json
import logging
import sys
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable

import dearpygui.dearpygui as dpg

logger = logging.getLogger(__name__)


def restart_application():
    """Restart the application."""
    try:
        script_path = Path(__file__).parent.parent / "run.py"
        dpg.stop_dearpygui()
        python_exe = sys.executable
        subprocess.Popen([python_exe, str(script_path)])
        sys.exit(0)
    except Exception as e:
        logger.error(f"Failed to restart application: {e}", exc_info=True)
        if dpg.does_item_exist("font_restart_dialog"):
            dpg.delete_item("font_restart_dialog")


def on_server_url_changed(app_data):
    """Auto-expands the top bar URL field as the text grows."""
    url = app_data
    if len(url) > 50 and dpg.does_item_exist("server_url_input"):
        current_width = dpg.get_item_configuration("server_url_input")["width"]
        new_width = min(300 + (len(url) - 50) * 5, 600)
        if new_width > current_width:
            dpg.configure_item("server_url_input", width=new_width)


class SettingsManager:
    """Renders and manages the settings tab."""

    def __init__(
        self,
        settings_file: Path,
        fonts_dir: Path,
        get_current_font_callback,
        set_current_font_callback,
        get_font_size_callback,
        set_font_size_callback,
        get_selected_font_name_callback,
        set_selected_font_name_callback,
        get_available_fonts_callback,
        apply_font_callback,
        save_settings_callback,
        reload_window_callback,
        show_server_url_dialog_callback,
        on_connect_callback,
        get_settings_callback: Optional[Callable[[], Dict[str, Any]]] = None,
        apply_settings_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
        test_connection_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
        connect_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
        export_settings_callback: Optional[Callable[[str], Any]] = None,
        import_settings_callback: Optional[Callable[[str], Any]] = None,
        reset_settings_callback: Optional[Callable[[], Any]] = None,
        get_server_runtime_callback: Optional[Callable[[], Dict[str, Any]]] = None,
        refresh_server_runtime_callback: Optional[Callable[..., Any]] = None,
        apply_server_runtime_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ):
        self.settings_file = settings_file
        self.fonts_dir = fonts_dir
        self.get_current_font = get_current_font_callback
        self.set_current_font = set_current_font_callback
        self.get_font_size = get_font_size_callback
        self.set_font_size = set_font_size_callback
        self.get_selected_font_name = get_selected_font_name_callback
        self.set_selected_font_name = set_selected_font_name_callback
        self.get_available_fonts = get_available_fonts_callback
        self.apply_font = apply_font_callback
        self.save_settings = save_settings_callback
        self.reload_window = reload_window_callback
        self.show_server_url_dialog = show_server_url_dialog_callback
        self.on_connect = on_connect_callback
        self.get_settings = get_settings_callback or (lambda: {})
        self.apply_settings = apply_settings_callback or save_settings_callback
        self.test_connection = test_connection_callback
        self.connect_with_settings = connect_callback
        self.export_settings = export_settings_callback
        self.import_settings = import_settings_callback
        self.reset_settings = reset_settings_callback
        self.get_server_runtime = get_server_runtime_callback or (lambda: {})
        self.refresh_server_runtime = refresh_server_runtime_callback
        self.apply_server_runtime = apply_server_runtime_callback
        self._preview_cache: Dict[str, Any] = {}

    def _get_snapshot(self) -> Dict[str, Any]:
        snapshot = self.get_settings() or {}
        if isinstance(snapshot, dict):
            self._preview_cache = snapshot
            return snapshot
        return {}

    def _set_if_exists(self, tag: str, value: Any):
        if dpg.does_item_exist(tag):
            dpg.set_value(tag, value)

    def _update_preview(self, snapshot: Optional[Dict[str, Any]] = None):
        data = snapshot if snapshot is not None else self._get_snapshot()
        self._set_if_exists("settings_preview", json.dumps(data, indent=2, ensure_ascii=False, default=str))

    def _update_server_runtime_preview(self, snapshot: Optional[Dict[str, Any]] = None):
        data = snapshot if snapshot is not None else (self.get_server_runtime() or {})
        self._set_if_exists("settings_server_runtime_preview", json.dumps(data, indent=2, ensure_ascii=False, default=str))

    def _set_status(self, message: str, color=(150, 200, 255)):
        if dpg.does_item_exist("settings_status_text"):
            dpg.set_value("settings_status_text", message)

    def _sync_controls_from_snapshot(self, snapshot: Dict[str, Any]):
        connection = snapshot.get("connection", {})
        refresh = snapshot.get("refresh", {})
        analytics = snapshot.get("analytics", {})
        logging_cfg = snapshot.get("logging", {})
        downloads = snapshot.get("downloads", {})
        ui = snapshot.get("ui", {})

        # Connection
        self._set_if_exists("settings_server_url_input", connection.get("server_url", "https://127.0.0.1:8080"))
        self._set_if_exists("settings_verify_ssl_checkbox", bool(connection.get("verify_ssl", False)))
        self._set_if_exists("settings_trust_store_mode_combo", connection.get("trust_store_mode", "system"))
        self._set_if_exists("settings_ca_cert_path_input", str(connection.get("ca_cert_path", "") or ""))
        self._set_if_exists("settings_connect_timeout_input", float(connection.get("timeout_connect", 3.05)))
        self._set_if_exists("settings_read_timeout_input", float(connection.get("timeout_read", 10.0)))
        self._set_if_exists("settings_auto_connect_checkbox", bool(connection.get("auto_connect", False)))

        # Refresh / monitoring
        self._set_if_exists("settings_auto_refresh_checkbox", bool(refresh.get("auto_refresh", True)))
        self._set_if_exists("settings_refresh_interval_input", int(refresh.get("refresh_interval", 30)))
        self._set_if_exists("settings_monitoring_interval_input", int(refresh.get("monitoring_interval", 30)))
        self._set_if_exists("settings_analytics_interval_input", int(refresh.get("analytics_interval", 60)))
        self._set_if_exists("settings_monitoring_status_limit_input", int(refresh.get("monitoring_status_limit", 1000)))
        self._set_if_exists("settings_monitoring_logs_limit_input", int(refresh.get("monitoring_logs_limit", 500)))
        self._set_if_exists("settings_monitoring_logs_level_combo", refresh.get("monitoring_logs_level", "all"))
        self._set_if_exists("settings_monitoring_scope_combo", refresh.get("monitoring_client_scope", "all"))

        # Analytics / logging
        self._set_if_exists("settings_analytics_limit_input", int(analytics.get("limit", 1000)))
        self._set_if_exists("settings_analytics_table_limit_input", int(analytics.get("table_limit", 250)))
        self._set_if_exists("settings_analytics_default_client_combo", analytics.get("default_client", "all"))
        self._set_if_exists("settings_log_level_combo", logging_cfg.get("level", "INFO"))
        self._set_if_exists("settings_log_entry_limit_input", int(logging_cfg.get("max_entries", 1000)))

        # Downloads
        self._set_if_exists("settings_download_dir_input", str(downloads.get("directory", str(Path.home() / "Downloads"))))
        self._set_if_exists("settings_package_prefix_input", downloads.get("package_prefix", "flamix-client"))
        self._set_if_exists("settings_open_folder_checkbox", bool(downloads.get("open_folder_after_download", False)))
        self._set_if_exists("settings_overwrite_checkbox", bool(downloads.get("overwrite_existing", False)))

        # UI
        available_fonts = self.get_available_fonts()
        font_names = [f.name for f in available_fonts]
        if dpg.does_item_exist("settings_font_selector"):
            dpg.configure_item("settings_font_selector", items=font_names or ["Default"])
            current_font = ui.get("font_name")
            if current_font in font_names:
                dpg.set_value("settings_font_selector", current_font)
            elif font_names:
                dpg.set_value("settings_font_selector", font_names[0])
        self._set_if_exists("settings_font_size_input", int(ui.get("font_size", 13)))
        self._set_if_exists("settings_compact_mode_checkbox", bool(ui.get("compact_mode", False)))
        self._set_if_exists("settings_theme_combo", ui.get("theme", "system"))
        self._set_if_exists("settings_table_row_limit_input", int(ui.get("table_row_limit", 200)))

        self._set_if_exists("settings_export_path_input", str(snapshot.get("diagnostics", {}).get("last_export_path") or self.settings_file.with_suffix(".export.json")))
        self._set_if_exists("settings_import_path_input", str(snapshot.get("diagnostics", {}).get("last_import_path") or self.settings_file.with_suffix(".import.json")))

        self._update_preview(snapshot)

    def _sync_server_runtime_controls(self, snapshot: Optional[Dict[str, Any]] = None):
        runtime_snapshot = snapshot if isinstance(snapshot, dict) else (self.get_server_runtime() or {})
        runtime_config = runtime_snapshot.get("config", {}) if isinstance(runtime_snapshot, dict) else {}
        server_cfg = runtime_config.get("server", {})
        web_cfg = runtime_config.get("web", {})
        paths_cfg = runtime_config.get("paths", {})
        runtime_cfg = runtime_config.get("runtime", {})
        retention_cfg = runtime_config.get("retention", {})
        features_cfg = runtime_config.get("features", {})
        logging_cfg = runtime_config.get("logging", {})

        self._set_if_exists("settings_runtime_server_host_input", runtime_config.get("server_host", server_cfg.get("host", "")))
        self._set_if_exists("settings_runtime_server_port_input", int(runtime_config.get("server_port", server_cfg.get("port", 8443) or 8443)))
        self._set_if_exists("settings_runtime_web_enabled_checkbox", bool(runtime_config.get("web_enabled", web_cfg.get("enabled", True))))
        self._set_if_exists("settings_runtime_web_host_input", runtime_config.get("web_host", web_cfg.get("host", "")))
        self._set_if_exists("settings_runtime_web_port_input", int(runtime_config.get("web_port", web_cfg.get("port", 8080) or 8080)))
        self._set_if_exists("settings_runtime_db_path_input", runtime_config.get("db_path", paths_cfg.get("db_path", "")))
        self._set_if_exists("settings_runtime_cert_dir_input", runtime_config.get("cert_dir", paths_cfg.get("cert_dir", "")))
        self._set_if_exists("settings_runtime_log_dir_input", runtime_config.get("log_dir", paths_cfg.get("log_dir", "")))
        self._set_if_exists("settings_runtime_periodic_input", int(runtime_config.get("periodic_task_interval_seconds", runtime_cfg.get("periodic_task_interval_seconds", 60) or 60)))
        self._set_if_exists("settings_runtime_session_timeout_input", int(runtime_config.get("session_timeout_seconds", runtime_cfg.get("session_timeout_seconds", 3600) or 3600)))
        self._set_if_exists("settings_runtime_client_logs_retention_input", int(runtime_config.get("client_log_retention_days") or retention_cfg.get("client_log_retention_days") or 0))
        self._set_if_exists("settings_runtime_analytics_retention_input", int(runtime_config.get("analytics_retention_days") or retention_cfg.get("analytics_retention_days") or 0))
        self._set_if_exists("settings_runtime_traffic_retention_input", int(runtime_config.get("traffic_stats_retention_days") or retention_cfg.get("traffic_stats_retention_days") or 0))
        self._set_if_exists("settings_runtime_status_retention_input", int(runtime_config.get("system_status_retention_days") or retention_cfg.get("system_status_retention_days") or 0))
        self._set_if_exists("settings_runtime_require_client_cert_checkbox", bool(runtime_config.get("require_client_cert", features_cfg.get("require_client_cert", True))))
        self._set_if_exists("settings_runtime_persist_checkbox", bool(runtime_config.get("persist_runtime_config", features_cfg.get("persist_runtime_config", True))))
        self._set_if_exists("settings_runtime_log_level_combo", runtime_config.get("log_level", logging_cfg.get("level", "INFO")))
        self._set_if_exists("settings_runtime_status_text", "Server runtime loaded" if runtime_config else "Server runtime not loaded")
        self._update_server_runtime_preview(runtime_snapshot)

    def _collect_server_runtime_patch(self) -> Dict[str, Any]:
        def value(tag, default=None):
            return dpg.get_value(tag) if dpg.does_item_exist(tag) else default

        def retention(tag):
            raw = value(tag, 0)
            try:
                parsed = int(raw)
            except Exception:
                parsed = 0
            return parsed if parsed > 0 else None

        return {
            "server": {
                "host": str(value("settings_runtime_server_host_input", "0.0.0.0")).strip() or "0.0.0.0",
                "port": int(value("settings_runtime_server_port_input", 8443)),
            },
            "web": {
                "enabled": bool(value("settings_runtime_web_enabled_checkbox", True)),
                "host": str(value("settings_runtime_web_host_input", "127.0.0.1")).strip() or "127.0.0.1",
                "port": int(value("settings_runtime_web_port_input", 8080)),
            },
            "paths": {
                "db_path": str(value("settings_runtime_db_path_input", "")).strip(),
                "cert_dir": str(value("settings_runtime_cert_dir_input", "")).strip(),
                "log_dir": str(value("settings_runtime_log_dir_input", "")).strip(),
            },
            "runtime": {
                "periodic_task_interval_seconds": int(value("settings_runtime_periodic_input", 60)),
                "session_timeout_seconds": int(value("settings_runtime_session_timeout_input", 3600)),
            },
            "retention": {
                "client_log_retention_days": retention("settings_runtime_client_logs_retention_input"),
                "analytics_retention_days": retention("settings_runtime_analytics_retention_input"),
                "traffic_stats_retention_days": retention("settings_runtime_traffic_retention_input"),
                "system_status_retention_days": retention("settings_runtime_status_retention_input"),
            },
            "features": {
                "require_client_cert": bool(value("settings_runtime_require_client_cert_checkbox", True)),
                "persist_runtime_config": bool(value("settings_runtime_persist_checkbox", True)),
            },
            "logging": {
                "level": value("settings_runtime_log_level_combo", "INFO"),
            },
        }

    def _collect_controls(self) -> Dict[str, Any]:
        def value(tag, default=None):
            return dpg.get_value(tag) if dpg.does_item_exist(tag) else default

        return {
            "connection": {
                "server_url": str(value("settings_server_url_input", "https://127.0.0.1:8080")).strip() or "https://127.0.0.1:8080",
                "verify_ssl": bool(value("settings_verify_ssl_checkbox", False)),
                "trust_store_mode": str(value("settings_trust_store_mode_combo", "system")).strip().lower() or "system",
                "ca_cert_path": str(value("settings_ca_cert_path_input", "")).strip(),
                "timeout_connect": value("settings_connect_timeout_input", 3.05),
                "timeout_read": value("settings_read_timeout_input", 10.0),
                "auto_connect": bool(value("settings_auto_connect_checkbox", False)),
            },
            "refresh": {
                "auto_refresh": bool(value("settings_auto_refresh_checkbox", True)),
                "refresh_interval": value("settings_refresh_interval_input", 30),
                "monitoring_interval": value("settings_monitoring_interval_input", 30),
                "analytics_interval": value("settings_analytics_interval_input", 60),
                "monitoring_status_limit": value("settings_monitoring_status_limit_input", 1000),
                "monitoring_logs_limit": value("settings_monitoring_logs_limit_input", 500),
                "monitoring_logs_level": value("settings_monitoring_logs_level_combo", "all"),
                "monitoring_client_scope": value("settings_monitoring_scope_combo", "all"),
            },
            "analytics": {
                "limit": value("settings_analytics_limit_input", 1000),
                "table_limit": value("settings_analytics_table_limit_input", 250),
                "default_client": value("settings_analytics_default_client_combo", "all"),
            },
            "logging": {
                "level": value("settings_log_level_combo", "INFO"),
                "max_entries": value("settings_log_entry_limit_input", 1000),
            },
            "downloads": {
                "directory": str(value("settings_download_dir_input", str(Path.home() / "Downloads"))).strip(),
                "package_prefix": str(value("settings_package_prefix_input", "flamix-client")).strip() or "flamix-client",
                "open_folder_after_download": bool(value("settings_open_folder_checkbox", False)),
                "overwrite_existing": bool(value("settings_overwrite_checkbox", False)),
            },
            "ui": {
                "font_name": value("settings_font_selector", None),
                "font_size": value("settings_font_size_input", 13),
                "compact_mode": bool(value("settings_compact_mode_checkbox", False)),
                "theme": value("settings_theme_combo", "system"),
                "table_row_limit": value("settings_table_row_limit_input", 200),
            },
            "diagnostics": {
                "last_export_path": str(value("settings_export_path_input", "")),
                "last_import_path": str(value("settings_import_path_input", "")),
            },
        }

    def create_tab(self):
        """Creates the settings page."""
        snapshot = self._get_snapshot()

        dpg.add_text("Application Settings", color=(100, 150, 255))
        dpg.add_separator()

        with dpg.group(horizontal=True):
            with dpg.child_window(width=420, height=-1):
                dpg.add_text("Connection", color=(150, 150, 255))
                dpg.add_separator()
                dpg.add_text("Server URL:")
                dpg.add_input_text(tag="settings_server_url_input", width=-1, callback=on_server_url_changed)
                dpg.add_checkbox(tag="settings_verify_ssl_checkbox", label="Verify SSL")
                dpg.add_text("Trust store mode:")
                dpg.add_combo(tag="settings_trust_store_mode_combo", items=["system", "custom"], width=-1)
                dpg.add_text("CA certificate path (used when trust store mode = custom):")
                dpg.add_input_text(tag="settings_ca_cert_path_input", width=-1)
                dpg.add_text("Connect timeout (seconds):")
                dpg.add_input_float(tag="settings_connect_timeout_input", min_value=0.1, max_value=60.0, width=120)
                dpg.add_text("Read timeout (seconds):")
                dpg.add_input_float(tag="settings_read_timeout_input", min_value=0.1, max_value=300.0, width=120)
                dpg.add_checkbox(tag="settings_auto_connect_checkbox", label="Auto-connect on startup")
                with dpg.group(horizontal=True):
                    dpg.add_button(label="Save Connection", callback=self.save_connection_from_ui, width=140)
                    dpg.add_button(label="Test Connection", callback=self.test_connection_from_ui, width=150)
                    dpg.add_button(label="Connect Now", callback=self.connect_from_ui, width=150)
                dpg.add_text("Connection changes take effect after Save Connection.", color=(170, 170, 170), wrap=390)
                dpg.add_button(label="Open Main URL Editor", callback=self.show_server_url_dialog, width=-1)

                dpg.add_separator()
                dpg.add_text("Refresh / Monitoring", color=(150, 150, 255))
                dpg.add_separator()
                dpg.add_checkbox(tag="settings_auto_refresh_checkbox", label="Enable auto refresh")
                dpg.add_text("Global refresh interval (seconds):")
                dpg.add_input_int(tag="settings_refresh_interval_input", min_value=5, max_value=3600, width=120)
                dpg.add_text("Monitoring refresh interval (seconds):")
                dpg.add_input_int(tag="settings_monitoring_interval_input", min_value=5, max_value=3600, width=120)
                dpg.add_text("Analytics refresh interval (seconds):")
                dpg.add_input_int(tag="settings_analytics_interval_input", min_value=5, max_value=3600, width=120)
                dpg.add_text("Monitoring default scope:")
                dpg.add_combo(
                    tag="settings_monitoring_scope_combo",
                    items=["all", "default"],
                    width=-1
                )
                dpg.add_text("Monitoring status history limit:")
                dpg.add_input_int(tag="settings_monitoring_status_limit_input", min_value=10, max_value=10000, width=140)
                dpg.add_text("Monitoring logs limit:")
                dpg.add_input_int(tag="settings_monitoring_logs_limit_input", min_value=10, max_value=10000, width=140)
                dpg.add_text("Monitoring logs level:")
                dpg.add_combo(
                    tag="settings_monitoring_logs_level_combo",
                    items=["all", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                    width=-1
                )

            with dpg.child_window(width=420, height=-1):
                dpg.add_text("Analytics / Logging", color=(150, 150, 255))
                dpg.add_separator()
                dpg.add_text("Analytics API limit:")
                dpg.add_input_int(tag="settings_analytics_limit_input", min_value=10, max_value=50000, width=140)
                dpg.add_text("Analytics table row limit:")
                dpg.add_input_int(tag="settings_analytics_table_limit_input", min_value=10, max_value=5000, width=140)
                dpg.add_text("Analytics default client:")
                dpg.add_combo(tag="settings_analytics_default_client_combo", items=["all", "selected"], width=-1)
                dpg.add_separator()
                dpg.add_text("UI log level:")
                dpg.add_combo(
                    tag="settings_log_level_combo",
                    items=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                    width=-1
                )
                dpg.add_text("Maximum log entries to keep in tables:")
                dpg.add_input_int(tag="settings_log_entry_limit_input", min_value=100, max_value=50000, width=140)

                dpg.add_separator()
                dpg.add_text("Downloads / Packaging", color=(150, 150, 255))
                dpg.add_separator()
                dpg.add_text("Download directory:")
                dpg.add_input_text(tag="settings_download_dir_input", width=-1)
                dpg.add_text("Package filename prefix:")
                dpg.add_input_text(tag="settings_package_prefix_input", width=-1)
                dpg.add_checkbox(tag="settings_open_folder_checkbox", label="Open folder after download")
                dpg.add_checkbox(tag="settings_overwrite_checkbox", label="Allow overwriting existing files")

                dpg.add_separator()
                dpg.add_text("UI Preferences", color=(150, 150, 255))
                dpg.add_separator()
                available_fonts = self.get_available_fonts()
                font_names = [f.name for f in available_fonts] or ["Default"]
                dpg.add_text("Font:")
                dpg.add_combo(tag="settings_font_selector", items=font_names, width=-1)
                dpg.add_text("Font size:")
                dpg.add_input_int(tag="settings_font_size_input", min_value=8, max_value=36, width=120)
                dpg.add_checkbox(tag="settings_compact_mode_checkbox", label="Compact mode")
                dpg.add_text("Theme:")
                dpg.add_combo(tag="settings_theme_combo", items=["system", "light", "dark"], width=-1)
                dpg.add_text("Table row limit:")
                dpg.add_input_int(tag="settings_table_row_limit_input", min_value=10, max_value=5000, width=140)
                dpg.add_button(label="Apply Font", callback=self.apply_selected_font, width=-1)

            with dpg.child_window(width=-1, height=-1):
                dpg.add_text("Diagnostics / About", color=(150, 150, 255))
                dpg.add_separator()
                dpg.add_text(f"Settings file: {self.settings_file}")
                dpg.add_text(f"Settings directory: {self.settings_file.parent}")
                dpg.add_separator()
                dpg.add_text("Export path:")
                dpg.add_input_text(tag="settings_export_path_input", width=-1)
                dpg.add_text("Import path:")
                dpg.add_input_text(tag="settings_import_path_input", width=-1)
                with dpg.group(horizontal=True):
                    dpg.add_button(label="Apply / Save", callback=self.apply_from_ui, width=120)
                    dpg.add_button(label="Export", callback=self.export_from_ui, width=90)
                    dpg.add_button(label="Import", callback=self.import_from_ui, width=90)
                    dpg.add_button(label="Reset Defaults", callback=self.reset_defaults_from_ui, width=130)
                dpg.add_text("", tag="settings_status_text")
                dpg.add_separator()
                dpg.add_text("Current settings snapshot:")
                dpg.add_input_text(tag="settings_preview", multiline=True, readonly=True, width=-1, height=420)
                dpg.add_separator()
                dpg.add_text("Server Runtime / Deployment", color=(150, 150, 255))
                dpg.add_separator()
                with dpg.group(horizontal=True):
                    dpg.add_button(label="Load Server Runtime", callback=self.refresh_server_runtime_from_ui, width=160)
                    dpg.add_button(label="Apply to Server", callback=self.apply_server_runtime_from_ui, width=140)
                dpg.add_text("", tag="settings_runtime_status_text")
                dpg.add_text("Server host:")
                dpg.add_input_text(tag="settings_runtime_server_host_input", width=-1)
                dpg.add_text("Server port:")
                dpg.add_input_int(tag="settings_runtime_server_port_input", min_value=1, max_value=65535, width=140)
                dpg.add_checkbox(tag="settings_runtime_web_enabled_checkbox", label="Enable web/admin UI")
                dpg.add_text("Web host:")
                dpg.add_input_text(tag="settings_runtime_web_host_input", width=-1)
                dpg.add_text("Web port:")
                dpg.add_input_int(tag="settings_runtime_web_port_input", min_value=1, max_value=65535, width=140)
                dpg.add_text("Database path:")
                dpg.add_input_text(tag="settings_runtime_db_path_input", width=-1)
                dpg.add_text("Certificates directory:")
                dpg.add_input_text(tag="settings_runtime_cert_dir_input", width=-1)
                dpg.add_text("Logs directory:")
                dpg.add_input_text(tag="settings_runtime_log_dir_input", width=-1)
                dpg.add_text("Periodic task interval (seconds):")
                dpg.add_input_int(tag="settings_runtime_periodic_input", min_value=5, max_value=3600, width=140)
                dpg.add_text("Session timeout (seconds):")
                dpg.add_input_int(tag="settings_runtime_session_timeout_input", min_value=60, max_value=86400, width=140)
                dpg.add_text("Client logs retention days (0 = unlimited):")
                dpg.add_input_int(tag="settings_runtime_client_logs_retention_input", min_value=0, max_value=3650, width=140)
                dpg.add_text("Analytics retention days (0 = unlimited):")
                dpg.add_input_int(tag="settings_runtime_analytics_retention_input", min_value=0, max_value=3650, width=140)
                dpg.add_text("Traffic stats retention days (0 = unlimited):")
                dpg.add_input_int(tag="settings_runtime_traffic_retention_input", min_value=0, max_value=3650, width=140)
                dpg.add_text("System status retention days (0 = unlimited):")
                dpg.add_input_int(tag="settings_runtime_status_retention_input", min_value=0, max_value=3650, width=140)
                dpg.add_checkbox(tag="settings_runtime_require_client_cert_checkbox", label="Require client certificates")
                dpg.add_checkbox(tag="settings_runtime_persist_checkbox", label="Persist runtime config on server")
                dpg.add_text("Server log level:")
                dpg.add_combo(tag="settings_runtime_log_level_combo", items=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], width=-1)
                dpg.add_text("Server runtime snapshot:")
                dpg.add_input_text(tag="settings_server_runtime_preview", multiline=True, readonly=True, width=-1, height=260)

        self._sync_controls_from_snapshot(snapshot)
        self._sync_server_runtime_controls(self.get_server_runtime() or {})

    def apply_from_ui(self):
        """Validates and persists values from the settings form."""
        snapshot = self._collect_controls()
        if self.apply_settings:
            result = self.apply_settings(snapshot)
            if isinstance(result, tuple) and len(result) >= 2:
                success, message = bool(result[0]), str(result[1])
            else:
                success, message = True, "Settings applied"
        else:
            success, message = False, "Save callback is unavailable"

        if success:
            self._set_status(message, color=(120, 220, 120))
            self._sync_controls_from_snapshot(self._get_snapshot() or snapshot)
        else:
            self._set_status(message, color=(220, 120, 120))

    def test_connection_from_ui(self):
        """Tests the currently entered connection settings."""
        if not self.test_connection:
            self._set_status("Test connection callback is unavailable", color=(220, 120, 120))
            return

        snapshot = self._collect_controls()
        result = self.test_connection(snapshot)
        if isinstance(result, tuple) and len(result) >= 2:
            success, message = bool(result[0]), str(result[1])
        else:
            success = bool(result)
            message = "Connection succeeded" if success else "Connection failed"

        self._set_status(message, color=(120, 220, 120) if success else (220, 120, 120))

    def connect_from_ui(self):
        """Applies settings and connects using the current snapshot."""
        snapshot = self._collect_controls()
        if self.connect_with_settings:
            result = self.connect_with_settings(snapshot)
            if isinstance(result, tuple) and len(result) >= 2:
                success, message = bool(result[0]), str(result[1])
            else:
                success = bool(result)
                message = "Connection started" if success else "Connection failed"
            self._set_status(message, color=(120, 220, 120) if success else (220, 120, 120))
            return

        self._set_status("Connect callback is unavailable", color=(220, 120, 120))

    def save_connection_from_ui(self):
        """Saves and applies only the connection-related settings."""
        if not self.apply_settings:
            self._set_status("Save callback is unavailable", color=(220, 120, 120))
            return

        collected = self._collect_controls()
        snapshot = self._get_snapshot()
        snapshot["connection"] = dict(collected.get("connection", {}))

        result = self.apply_settings(snapshot)
        if isinstance(result, tuple) and len(result) >= 2:
            success, message = bool(result[0]), str(result[1])
            updated_snapshot = result[2] if len(result) > 2 and isinstance(result[2], dict) else None
        elif isinstance(result, dict):
            success, message, updated_snapshot = True, "Connection settings saved", result
        else:
            success = bool(result)
            message = "Connection settings saved" if success else "Failed to save connection settings"
            updated_snapshot = None

        if success:
            final_snapshot = updated_snapshot or self._get_snapshot()
            self._sync_controls_from_snapshot(final_snapshot)
            self._set_status(message, color=(120, 220, 120))
        else:
            self._set_status(message, color=(220, 120, 120))

    def export_from_ui(self):
        """Exports settings to the requested path."""
        path = str(dpg.get_value("settings_export_path_input")).strip()
        if not path:
            self._set_status("Export path is empty", color=(220, 120, 120))
            return

        if not self.export_settings:
            self._set_status("Export callback is unavailable", color=(220, 120, 120))
            return

        result = self.export_settings(path)
        if isinstance(result, tuple) and len(result) >= 2:
            success, message = bool(result[0]), str(result[1])
        else:
            success = bool(result)
            message = f"Exported to {path}" if success else "Export failed"

        self._set_status(message, color=(120, 220, 120) if success else (220, 120, 120))
        if success:
            self._update_preview()

    def import_from_ui(self):
        """Imports settings from the requested path."""
        path = str(dpg.get_value("settings_import_path_input")).strip()
        if not path:
            self._set_status("Import path is empty", color=(220, 120, 120))
            return

        if not self.import_settings:
            self._set_status("Import callback is unavailable", color=(220, 120, 120))
            return

        result = self.import_settings(path)
        if isinstance(result, tuple) and len(result) >= 2:
            success, message = bool(result[0]), str(result[1])
            snapshot = result[2] if len(result) > 2 and isinstance(result[2], dict) else None
        elif isinstance(result, dict):
            success, message, snapshot = True, f"Imported from {path}", result
        else:
            success, message, snapshot = bool(result), (f"Imported from {path}" if result else "Import failed"), None

        if success:
            self._set_status(message, color=(120, 220, 120))
            self._sync_controls_from_snapshot(snapshot or self._get_snapshot())
        else:
            self._set_status(message, color=(220, 120, 120))

    def reset_defaults_from_ui(self):
        """Resets settings to safe defaults."""
        if not self.reset_settings:
            self._set_status("Reset callback is unavailable", color=(220, 120, 120))
            return

        result = self.reset_settings()
        if isinstance(result, tuple) and len(result) >= 2:
            success, message = bool(result[0]), str(result[1])
            snapshot = result[2] if len(result) > 2 and isinstance(result[2], dict) else None
        elif isinstance(result, dict):
            success, message, snapshot = True, "Defaults restored", result
        else:
            success, message, snapshot = bool(result), ("Defaults restored" if result else "Reset failed"), None

        if success:
            self._set_status(message, color=(120, 220, 120))
            self._sync_controls_from_snapshot(snapshot or self._get_snapshot())
        else:
            self._set_status(message, color=(220, 120, 120))

    def refresh_server_runtime_from_ui(self):
        """Loads the latest effective server runtime configuration into the form."""
        if not self.refresh_server_runtime:
            self._set_status("Server runtime refresh is unavailable", color=(220, 120, 120))
            return

        result = self.refresh_server_runtime(silent=False)
        if isinstance(result, tuple) and len(result) >= 2:
            success, message = bool(result[0]), str(result[1])
            snapshot = result[2] if len(result) > 2 and isinstance(result[2], dict) else None
        elif isinstance(result, dict):
            success, message, snapshot = True, "Server runtime loaded", result
        else:
            success, message, snapshot = bool(result), ("Server runtime loaded" if result else "Failed to load server runtime"), None

        if success:
            runtime_snapshot = snapshot or self.get_server_runtime() or {}
            self._sync_server_runtime_controls(runtime_snapshot)
            self._set_status(message, color=(120, 220, 120))
        else:
            self._set_status(message, color=(220, 120, 120))

    def apply_server_runtime_from_ui(self):
        """Sends the runtime settings patch to the connected server."""
        if not self.apply_server_runtime:
            self._set_status("Server runtime apply is unavailable", color=(220, 120, 120))
            return

        patch = self._collect_server_runtime_patch()
        result = self.apply_server_runtime(patch)
        if isinstance(result, tuple) and len(result) >= 2:
            success, message = bool(result[0]), str(result[1])
            snapshot = result[2] if len(result) > 2 and isinstance(result[2], dict) else None
        elif isinstance(result, dict):
            success, message, snapshot = True, "Server runtime updated", result
        else:
            success, message, snapshot = bool(result), ("Server runtime updated" if result else "Failed to update server runtime"), None

        if success:
            runtime_snapshot = snapshot or self.get_server_runtime() or {}
            self._sync_server_runtime_controls(runtime_snapshot)
            self._set_status(message, color=(120, 220, 120))
        else:
            self._set_status(message, color=(220, 120, 120))

    def on_font_changed(self, app_data):
        """Stores the selected font name."""
        selected_font_name = app_data
        self.set_selected_font_name(selected_font_name)
        logger.info(f"Font selected: {selected_font_name}")

    def on_font_size_changed(self, app_data):
        """Stores the selected font size."""
        new_size = app_data
        if 8 <= new_size <= 36:
            self.set_font_size(new_size)
            logger.info(f"Font size changed to: {new_size}")

    def apply_selected_font(self):
        """Applies the selected font immediately."""
        try:
            selected_font_name = dpg.get_value("settings_font_selector")
            new_size = dpg.get_value("settings_font_size_input")

            available_fonts = self.get_available_fonts()
            if not selected_font_name or not available_fonts:
                logger.warning("No font selected")
                return

            font_path = None
            for candidate in available_fonts:
                if candidate.name == selected_font_name:
                    font_path = candidate
                    break

            if not font_path:
                logger.error(f"Font not found: {selected_font_name}")
                return

            current_font = self.get_current_font()
            if current_font is not None:
                try:
                    dpg.delete_item(current_font)
                except Exception as e:
                    logger.debug(f"Could not delete old font: {e}")

            with dpg.font_registry():
                new_font = dpg.add_font(str(font_path), new_size)
                self.set_current_font(new_font)
                self.set_font_size(new_size)
                self.set_selected_font_name(selected_font_name)

            self.apply_font(new_font)
            self.apply_from_ui()
            logger.info(f"Applied font: {selected_font_name} (size: {new_size})")
        except Exception as e:
            logger.error(f"Failed to apply font: {e}", exc_info=True)

    def show_font_restart_dialog(self, font_name: str, font_size: int):
        """Shows a restart prompt when font size changes."""
        if dpg.does_item_exist("font_restart_dialog"):
            dpg.delete_item("font_restart_dialog")

        self.set_selected_font_name(font_name)
        self.set_font_size(font_size)
        self.apply_from_ui()

        with dpg.window(
            label="Font Size Changed",
            modal=True,
            tag="font_restart_dialog",
            width=400,
            height=200
        ):
            dpg.add_text(f"Font size changed to {font_size}.")
            dpg.add_text("Application restart is required for the new font size to take effect.")
            dpg.add_separator()
            with dpg.group(horizontal=True):
                dpg.add_button(label="Restart Now", callback=restart_application, width=150)
                dpg.add_button(label="Keep Running", callback=lambda: dpg.delete_item("font_restart_dialog"), width=150)
