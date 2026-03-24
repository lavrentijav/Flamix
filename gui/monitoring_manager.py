"""Модуль мониторинга - статус, плагины, логи"""

import json
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any

import dearpygui.dearpygui as dpg

logger = logging.getLogger(__name__)
ALL_CLIENTS_OPTION = "all"


def _clear_table_rows(table_tag: str):
    """Удаляет только строки таблицы, сохраняя колонки."""
    if not dpg.does_item_exist(table_tag):
        return

    for slot in range(4):
        try:
            children = dpg.get_item_children(table_tag, slot=slot) or []
        except Exception:
            continue

        for child in list(children):
            item_type = dpg.get_item_info(child).get("type", "")
            if item_type.endswith("mvTableRow"):
                dpg.delete_item(child)


def _parse_plot_timestamp(raw_timestamp: Any) -> Optional[float]:
    """Приводит unix/ISO timestamp к float для графиков и сортировки."""
    if raw_timestamp is None:
        return None

    if isinstance(raw_timestamp, (int, float)):
        return float(raw_timestamp)

    timestamp_str = str(raw_timestamp).strip()
    if not timestamp_str:
        return None

    try:
        return float(timestamp_str)
    except ValueError:
        pass

    try:
        return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).timestamp()
    except ValueError:
        logger.debug("Unsupported timestamp format: %s", timestamp_str)
        return None


def _create_monitoring_status_view():
    """Создание вида системного статуса"""
    # Темы создаются вне любого контейнера (plot/window), иначе краш
    with dpg.theme() as cpu_theme:
        with dpg.theme_component(dpg.mvShadeSeries):
            dpg.add_theme_color(dpg.mvPlotCol_Line, (255, 140, 0, 255), category=dpg.mvThemeCat_Plots)   # Оранжевый
            dpg.add_theme_color(dpg.mvPlotCol_Fill, (255, 140, 0, 80), category=dpg.mvThemeCat_Plots)

    with dpg.theme() as memory_theme:
        with dpg.theme_component(dpg.mvShadeSeries):
            dpg.add_theme_color(dpg.mvPlotCol_Line, (50, 150, 255, 255), category=dpg.mvThemeCat_Plots)  # Синий
            dpg.add_theme_color(dpg.mvPlotCol_Fill, (50, 150, 255, 25), category=dpg.mvThemeCat_Plots)

    with dpg.theme() as disk_theme:
        with dpg.theme_component(dpg.mvLineSeries):
            dpg.add_theme_color(dpg.mvPlotCol_Line, (0, 210, 100, 255), category=dpg.mvThemeCat_Plots)   # Зелёный

    with dpg.group(parent="monitoring_content"):
        dpg.add_text("System Status Overview", color=(100, 150, 255))
        dpg.add_separator()

        # График системных метрик
        with dpg.plot(label="System Metrics", height=300, width=-1,
                      use_local_time=True,
                      use_24hour_clock=True,
                      use_ISO8601=False,
                      ):
            dpg.add_plot_legend()
            dpg.add_plot_axis(dpg.mvXAxis, label="Time", tag="TimeAxis", scale=dpg.mvPlotScale_Time)
            dpg.add_plot_axis(dpg.mvYAxis, label="Percentage (%)", tag="status_metrics")

            dpg.set_axis_limits("status_metrics", 0, 100)

            # CPU и Memory — shade_series (заливка под линией), Disk — line_series
            dpg.add_shade_series([], [], y2=[], label="CPU %", tag="status_cpu_series", parent="status_metrics")
            dpg.add_shade_series([], [], y2=[], label="Memory %", tag="status_memory_series", parent="status_metrics")
            dpg.add_line_series([], [], label="Disk %", tag="status_disk_series", parent="status_metrics")

        # Привязываем темы после выхода из контекста plot
        dpg.bind_item_theme("status_cpu_series", cpu_theme)
        dpg.bind_item_theme("status_memory_series", memory_theme)
        dpg.bind_item_theme("status_disk_series", disk_theme)

        dpg.add_separator()

        with dpg.table(
                tag="monitoring_status_table",
                header_row=True,
                resizable=True,
                policy=dpg.mvTable_SizingStretchProp,
                borders_innerH=True,
                borders_outerH=True,
                borders_innerV=True,
                borders_outerV=True
        ):
            dpg.add_table_column(label="Client ID", width_fixed=True, init_width_or_weight=100)
            dpg.add_table_column(label="Name", width_fixed=True, init_width_or_weight=150)
            dpg.add_table_column(label="CPU %", width_fixed=True, init_width_or_weight=80)
            dpg.add_table_column(label="Memory %", width_fixed=True, init_width_or_weight=100)
            dpg.add_table_column(label="Disk %", width_fixed=True, init_width_or_weight=80)
            dpg.add_table_column(label="Status", width_fixed=True, init_width_or_weight=100)
            dpg.add_table_column(label="Last Seen", width_fixed=True, init_width_or_weight=150)
            dpg.add_table_column(label="Actions", width_fixed=True, init_width_or_weight=150)


class MonitoringManager:
    """Класс для управления мониторингом - статус, плагины, логи"""

    def __init__(
        self,
        api_client,
        get_clients_data_callback,
        get_monitoring_client_id_callback,
        set_monitoring_client_id_callback,
        show_client_status_details_callback,
        get_monitoring_settings_callback=None,
        get_ui_settings_callback=None
    ):
        """
        Инициализация менеджера мониторинга
        
        Args:
            api_client: API клиент для работы с сервером
            get_clients_data_callback: Callback для получения списка клиентов
            get_monitoring_client_id_callback: Callback для получения текущего ID клиента мониторинга
            set_monitoring_client_id_callback: Callback для установки ID клиента мониторинга
            show_client_status_details_callback: Callback для показа деталей статуса клиента
        """
        self.api_client = api_client
        self.get_clients_data = get_clients_data_callback
        self.get_monitoring_client_id = get_monitoring_client_id_callback
        self.set_monitoring_client_id = set_monitoring_client_id_callback
        self.show_client_status_details = show_client_status_details_callback
        self.get_monitoring_settings = get_monitoring_settings_callback or (lambda: {})
        self.get_ui_settings = get_ui_settings_callback or (lambda: {})
        self.status_graph_initialized = False

    def _get_selected_client_id(self) -> str:
        """Возвращает текущий выбор клиента из GUI и синхронизирует внутреннее состояние."""
        selected_client_id = self.get_monitoring_client_id() or ALL_CLIENTS_OPTION

        if dpg.does_item_exist("monitoring_global_client_combo"):
            combo_value = dpg.get_value("monitoring_global_client_combo")
            if combo_value:
                selected_client_id = combo_value

        if selected_client_id != self.get_monitoring_client_id():
            self.set_monitoring_client_id(selected_client_id)

        return selected_client_id

    def create_tab(self):
        """Создание вкладки мониторинга"""
        with dpg.group(horizontal=True):
            with dpg.child_window(width=300, height=600):
                dpg.add_text("Monitoring", color=(100, 150, 255))
                dpg.add_separator()
                # Глобальный выбор клиента для мониторинга
                dpg.add_text("Client:", color=(150, 150, 255))
                clients_data = self.get_clients_data()
                client_ids = [str(c.get('id')) for c in clients_data if c.get('id') is not None]
                client_options = [ALL_CLIENTS_OPTION] + client_ids
                monitoring_client_id = self.get_monitoring_client_id()
                if monitoring_client_id not in client_options:
                    monitoring_client_id = ALL_CLIENTS_OPTION
                    self.set_monitoring_client_id(monitoring_client_id)
                default_value = monitoring_client_id or ALL_CLIENTS_OPTION
                dpg.add_combo(
                    tag="monitoring_global_client_combo",
                    items=client_options,
                    default_value=default_value,
                    width=-1,
                    callback=self._on_monitoring_client_changed
                )
                dpg.add_separator()
                dpg.add_text("Sections:", color=(150, 150, 255))
                dpg.add_button(
                    label="System Status",
                    width=-1,
                    callback=lambda: self._show_monitoring_section("status")
                )
                dpg.add_button(
                    label="Plugins",
                    width=-1,
                    callback=lambda: self._show_monitoring_section("plugins")
                )
                dpg.add_button(
                    label="Logs",
                    width=-1,
                    callback=lambda: self._show_monitoring_section("logs")
                )
                dpg.add_separator()
                dpg.add_button(label="Refresh All", callback=self.refresh_monitoring, width=-1)

            with dpg.child_window(width=-1, height=600, tag="monitoring_content"):
                dpg.add_text("Select a section to view", tag="monitoring_placeholder")

    def _show_monitoring_section(self, section: str):
        """Показ секции мониторинга"""
        # Clear content
        if dpg.does_item_exist("monitoring_content"):
            dpg.delete_item("monitoring_content", children_only=True)

        if section == "status":
            _create_monitoring_status_view()
            self.status_graph_initialized = False
            self.refresh_monitoring_status()
        elif section == "plugins":
            self._create_monitoring_plugins_view()
            monitoring_client_id = self._get_selected_client_id()
            if monitoring_client_id:
                self.refresh_monitoring_plugins()
        elif section == "logs":
            self._create_monitoring_logs_view()
            monitoring_client_id = self._get_selected_client_id()
            if monitoring_client_id:
                self.refresh_monitoring_logs()

    def _on_monitoring_client_changed(self):
        """Обработка изменения глобального выбора клиента для мониторинга"""
        if dpg.does_item_exist("monitoring_global_client_combo"):
            client_id = dpg.get_value("monitoring_global_client_combo")
            self.set_monitoring_client_id(client_id if client_id else ALL_CLIENTS_OPTION)
            # Обновляем все секции мониторинга
            if dpg.does_item_exist("monitoring_status_table"):
                self.refresh_monitoring_status()
            if dpg.does_item_exist("monitoring_plugins_table"):
                self.refresh_monitoring_plugins()
            if dpg.does_item_exist("monitoring_logs_table"):
                self.refresh_monitoring_logs()

    def _create_monitoring_plugins_view(self):
        """Создание вида плагинов"""
        with dpg.group(parent="monitoring_content"):
            dpg.add_text("Client Plugins", color=(100, 150, 255))
            dpg.add_separator()
            dpg.add_text("Using global client selection from sidebar", color=(150, 150, 150))
            dpg.add_separator()
            with dpg.table(
                    tag="monitoring_plugins_table",
                    header_row=True,
                    resizable=True,
                    policy=dpg.mvTable_SizingStretchProp,
                    borders_innerH=True,
                    borders_outerH=True,
                    borders_innerV=True,
                    borders_outerV=True
            ):
                dpg.add_table_column(label="Plugin ID", width_fixed=True, init_width_or_weight=150)
                dpg.add_table_column(label="Enabled", width_fixed=True, init_width_or_weight=80)
                dpg.add_table_column(label="Available", width_fixed=True, init_width_or_weight=80)
                dpg.add_table_column(label="Health Status", width_fixed=True, init_width_or_weight=150)
                dpg.add_table_column(label="Details", width_fixed=True, init_width_or_weight=300)

    def _create_monitoring_logs_view(self):
        """Создание вида логов"""
        with dpg.group(parent="monitoring_content"):
            dpg.add_text("Client Logs", color=(100, 150, 255))
            dpg.add_separator()
            with dpg.group(horizontal=True):
                dpg.add_text("Using global client selection from sidebar", color=(150, 150, 150))
                dpg.add_text("Level:")
                monitoring_settings = self.get_monitoring_settings() or {}
                default_log_level = monitoring_settings.get("logs_level_default", "all")
                dpg.add_combo(
                    tag="monitoring_logs_level_combo",
                    items=["all", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                    default_value=default_log_level if default_log_level in {"all", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"} else "all",
                    width=150,
                    callback=self.refresh_monitoring_logs
                )
                dpg.add_button(label="Refresh", callback=self.refresh_monitoring_logs)
            dpg.add_separator()
            with dpg.table(
                    tag="monitoring_logs_table",
                    header_row=True,
                    resizable=True,
                    policy=dpg.mvTable_SizingStretchProp,
                    borders_innerH=True,
                    borders_outerH=True,
                    borders_innerV=True,
                    borders_outerV=True
            ):
                dpg.add_table_column(label="Client ID", width_fixed=True, init_width_or_weight=100)
                dpg.add_table_column(label="Timestamp", width_fixed=True, init_width_or_weight=150)
                dpg.add_table_column(label="Level", width_fixed=True, init_width_or_weight=80)
                dpg.add_table_column(label="Logger", width_fixed=True, init_width_or_weight=150)
                dpg.add_table_column(label="Message", width_fixed=True, init_width_or_weight=600)

    def refresh_monitoring(self):
        """Обновление всех данных мониторинга"""
        self.refresh_monitoring_status()
        self.refresh_monitoring_plugins()
        self.refresh_monitoring_logs()

    def refresh_monitoring_status(self):
        """Обновление системного статуса"""
        if not dpg.does_item_exist("monitoring_status_table"):
            logger.debug("refresh_monitoring_status: monitoring_status_table does not exist, skipping")
            return

        try:
            logger.debug("refresh_monitoring_status: fetching monitoring overview")
            overview = self.api_client.get_monitoring_overview()
            if not overview:
                logger.warning("refresh_monitoring_status: got empty overview")
                return

            clients = overview.get('clients', [])
            logger.info(f"refresh_monitoring_status: loaded {len(clients)} clients")
        except Exception as e:
            logger.error(f"Error getting monitoring overview: {e}", exc_info=True)
            return

        # Update graphs if they exist
        if dpg.does_item_exist("status_cpu_series") and clients:
            monitoring_client_id = self._get_selected_client_id()
            client_id = None
            if monitoring_client_id and monitoring_client_id != ALL_CLIENTS_OPTION:
                for client in clients:
                    if str(client.get('client_id')) == str(monitoring_client_id):
                        client_id = client.get('client_id')
                        break

            if not client_id and clients:
                client_id = clients[0].get('client_id')

            if client_id:
                try:
                    monitoring_settings = self.get_monitoring_settings() or {}
                    status_limit = int(monitoring_settings.get("status_limit", 1000) or 1000)
                    statuses = self.api_client.get_client_status(client_id, limit=status_limit)
                    if statuses:
                        timestamps = []
                        cpu_data = []
                        memory_data = []
                        disk_data = []

                        for status in reversed(statuses):
                            try:
                                raw_ts = _parse_plot_timestamp(status.get('timestamp'))
                                if raw_ts is None:
                                    continue
                                timestamps.append(raw_ts)
                                cpu_data.append(status.get('cpu_percent', 0) or 0)
                                memory_data.append(status.get('memory_percent', 0) or 0)

                                disk_percent = 0
                                disk_usage_raw = status.get('disk_usage')
                                if disk_usage_raw:
                                    try:
                                        disk_info = json.loads(disk_usage_raw)
                                        if disk_info.get('partitions'):
                                            first_part = list(disk_info['partitions'].values())[0]
                                            disk_percent = first_part.get('percent', 0)
                                    except (json.JSONDecodeError, TypeError):
                                        disk_percent = 0

                                disk_data.append(disk_percent)
                            except Exception as e:
                                logger.warning(f"Error parsing status: {e}")
                                continue

                        if timestamps:
                            try:
                                zeros = [0.0] * len(timestamps)
                                if cpu_data:
                                    dpg.set_value("status_cpu_series", [timestamps, cpu_data, zeros])
                                if memory_data:
                                    dpg.set_value("status_memory_series", [timestamps, memory_data, zeros])
                                if disk_data:
                                    dpg.set_value("status_disk_series", [timestamps, disk_data])

                                if not self.status_graph_initialized:
                                    dpg.fit_axis_data("TimeAxis")
                                    self.status_graph_initialized = True
                            except Exception as e:
                                logger.error(f"Error updating status graphs: {e}")
                except Exception as e:
                    logger.error(f"Error getting client status: {e}", exc_info=True)

        # Fill table
        _clear_table_rows("monitoring_status_table")
        if not clients:
            with dpg.table_row(parent="monitoring_status_table"):
                dpg.add_text("No clients found", color=(150, 150, 150))
        else:
            for client in clients:
                with dpg.table_row(parent="monitoring_status_table"):
                    dpg.add_text(str(client.get('client_id', 'N/A')))
                    dpg.add_text(client.get('client_name', 'N/A'))
                    cpu = client.get('cpu_percent')
                    dpg.add_text(f"{cpu:.1f}%" if cpu is not None else "N/A")
                    mem = client.get('memory_percent')
                    dpg.add_text(f"{mem:.1f}%" if mem is not None else "N/A")
                    disk = client.get('disk_percent')
                    dpg.add_text(f"{disk:.1f}%" if disk is not None else "N/A")
                    status_text = "Online" if client.get('is_online') else "Offline"
                    status_color = (0, 200, 0) if client.get('is_online') else (200, 0, 0)
                    dpg.add_text(status_text, color=status_color)
                    last_seen = client.get('last_seen', 'N/A')
                    if last_seen and last_seen != 'N/A':
                        dpg.add_text(last_seen[:19])
                    else:
                        dpg.add_text('N/A')
                    with dpg.group(horizontal=True):
                        client_id = client.get('client_id')
                        dpg.add_button(
                            label="Details",
                            callback=lambda s, a, cid=client_id: self.show_client_status_details(cid)
                        )

    def refresh_monitoring_plugins(self):
        """Обновление статуса плагинов"""
        if not dpg.does_item_exist("monitoring_plugins_table"):
            logger.debug("refresh_monitoring_plugins: monitoring_plugins_table does not exist, skipping")
            return

        monitoring_client_id = self._get_selected_client_id()
        logger.info(f"refresh_monitoring_plugins: loading plugins for client_id={monitoring_client_id}")

        _clear_table_rows("monitoring_plugins_table")

        if not monitoring_client_id:
            with dpg.table_row(parent="monitoring_plugins_table"):
                dpg.add_text("No client selected", color=(200, 200, 0))
            return

        if monitoring_client_id == ALL_CLIENTS_OPTION:
            with dpg.table_row(parent="monitoring_plugins_table"):
                dpg.add_text("Select a specific client to view plugins", color=(200, 200, 0))
            return

        try:
            plugins = self.api_client.get_client_plugins(monitoring_client_id)
            logger.info(f"refresh_monitoring_plugins: loaded {len(plugins)} plugins for client {monitoring_client_id}")
        except Exception as e:
            logger.error(f"Error getting plugins: {e}", exc_info=True)
            with dpg.table_row(parent="monitoring_plugins_table"):
                dpg.add_text(f"Error loading plugins: {e}", color=(200, 0, 0))
            return

        if not plugins:
            with dpg.table_row(parent="monitoring_plugins_table"):
                dpg.add_text("No plugins found", color=(150, 150, 150))
            return

        for plugin in plugins:
            with dpg.table_row(parent="monitoring_plugins_table"):
                dpg.add_text(plugin.get('id', 'N/A'))
                dpg.add_text("Yes" if plugin.get('enabled') else "No")
                dpg.add_text("Yes" if plugin.get('available') else "No")
                health = plugin.get('health', {})
                health_status = health.get('status', 'unknown')
                status_color = (0, 200, 0) if health_status == 'ok' else (200, 200, 0) if health_status == 'warning' else (200, 0, 0)
                dpg.add_text(health_status.upper(), color=status_color)
                health_details = json.dumps(health, indent=2) if health else "N/A"
                dpg.add_text(health_details[:100] + "..." if len(health_details) > 100 else health_details)

    def refresh_monitoring_logs(self):
        """Обновление логов"""
        if not dpg.does_item_exist("monitoring_logs_table"):
            return

        monitoring_client_id = self._get_selected_client_id()
        client_id = monitoring_client_id if monitoring_client_id else ALL_CLIENTS_OPTION
        level = dpg.get_value("monitoring_logs_level_combo") if dpg.does_item_exist(
            "monitoring_logs_level_combo") else ALL_CLIENTS_OPTION

        logger.info(f"refresh_monitoring_logs: loading logs for client_id={client_id}, level={level}")

        _clear_table_rows("monitoring_logs_table")

        all_logs = []
        if client_id == ALL_CLIENTS_OPTION or not client_id:
            clients_data = self.get_clients_data()
            for client in clients_data:
                cid = str(client.get('id')) if client.get('id') is not None else None
                if cid:
                    try:
                        monitoring_settings = self.get_monitoring_settings() or {}
                        logs_limit = int(monitoring_settings.get("logs_limit", 500) or 500)
                        client_logs = self.api_client.get_client_logs(
                            cid,
                            level=None if level == "all" else level,
                            limit=logs_limit
                        )
                        for log in client_logs:
                            log['_client_id'] = cid
                        all_logs.extend(client_logs)
                    except Exception as e:
                        logger.error(f"Error getting logs for client {cid}: {e}", exc_info=True)
                        continue
            all_logs.sort(key=lambda x: _parse_plot_timestamp(x.get('timestamp')) or 0.0, reverse=True)
            logger.info(f"refresh_monitoring_logs: loaded {len(all_logs)} total logs from all clients")
        else:
            try:
                monitoring_settings = self.get_monitoring_settings() or {}
                logs_limit = int(monitoring_settings.get("logs_limit", 500) or 500)
                all_logs = self.api_client.get_client_logs(
                    client_id,
                    level=None if level == "all" else level,
                    limit=logs_limit
                )
                logger.info(f"refresh_monitoring_logs: loaded {len(all_logs)} logs for client {client_id}")
            except Exception as e:
                logger.error(f"Error getting logs for client {client_id}: {e}", exc_info=True)
                all_logs = []

        ui_settings = self.get_ui_settings() or {}
        table_row_limit = max(1, int(ui_settings.get("table_row_limit", 1000) or 1000))
        if len(all_logs) > table_row_limit:
            all_logs = all_logs[:table_row_limit]

        if not all_logs:
            with dpg.table_row(parent="monitoring_logs_table"):
                dpg.add_text("No logs found", color=(150, 150, 150))
        else:
            for log in all_logs:
                row_id = dpg.add_table_row(parent="monitoring_logs_table")
                timestamp = log.get('timestamp', 'N/A')
                log_level = log.get('level', 'INFO')
                level_color = {
                    'DEBUG': (150, 150, 150),
                    'INFO': (200, 200, 200),
                    'WARNING': (200, 200, 0),
                    'ERROR': (200, 0, 0),
                    'CRITICAL': (255, 0, 0)
                }.get(log_level, (200, 200, 200))

                dpg.add_text(str(log.get('_client_id', client_id or 'N/A')), parent=row_id)
                dpg.add_text(timestamp[:19] if timestamp != 'N/A' else 'N/A', parent=row_id)
                dpg.add_text(log_level, color=level_color, parent=row_id)
                dpg.add_text(log.get('logger_name', 'N/A')[:30], parent=row_id)
                dpg.add_text(log.get('message', 'N/A')[:200], parent=row_id)
