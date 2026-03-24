"""Модуль аналитики - графики и таблицы аналитики"""

import logging
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Optional

import dearpygui.dearpygui as dpg

logger = logging.getLogger(__name__)


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


class AnalyticsManager:
    """Класс для управления аналитикой - графики и таблицы"""

    def __init__(
        self,
        api_client,
        get_clients_data_callback,
        get_analytics_settings_callback=None,
        get_ui_settings_callback=None
    ):
        """
        Инициализация менеджера аналитики
        
        Args:
            api_client: API клиент для работы с сервером
            get_clients_data_callback: Callback для получения списка клиентов
        """
        self.api_client = api_client
        self.get_clients_data = get_clients_data_callback
        self.get_analytics_settings = get_analytics_settings_callback or (lambda: {})
        self.get_ui_settings = get_ui_settings_callback or (lambda: {})

    def create_tab(self):
        """Создание вкладки аналитики"""
        with dpg.group(horizontal=True):
            # Левая панель с фильтрами
            with dpg.child_window(width=300, height=-1):
                dpg.add_text("Filters", color=(100, 150, 255))
                dpg.add_separator()
                dpg.add_text("Client:")
                dpg.add_combo(
                    tag="analytics_client_combo",
                    items=["all"],
                    default_value="all",
                    width=-1,
                    callback=self.refresh_analytics
                )
                dpg.add_separator()
                dpg.add_button(label="Refresh", callback=self.refresh_analytics, width=-1)

            # Правая панель с графиками и таблицей
            with dpg.child_window(width=-1, height=-1):
                dpg.add_text("Analytics", color=(100, 150, 255))
                dpg.add_separator()

                # График событий по времени
                with dpg.group():
                    dpg.add_text("Events Over Time", color=(150, 200, 255))
                    with dpg.plot(
                            label="Events Over Time",
                            height=300,
                            width=-1,
                            tag="analytics_events_plot"
                    ):
                        dpg.add_plot_legend()
                        dpg.add_plot_axis(dpg.mvXAxis, label="Time", tag="analytics_events_x")
                        with dpg.plot_axis(dpg.mvYAxis, label="Count", tag="analytics_events_y"):
                            dpg.add_line_series(
                                [],
                                [],
                                label="Events",
                                tag="analytics_events_series",
                                parent="analytics_events_y"
                            )

                dpg.add_separator()

                # График событий по типу
                with dpg.group():
                    dpg.add_text("Events by Type", color=(150, 200, 255))
                    with dpg.plot(
                            label="Events by Type",
                            height=300,
                            width=-1,
                            tag="analytics_type_plot"
                    ):
                        dpg.add_plot_legend()
                        dpg.add_plot_axis(dpg.mvXAxis, label="Event Type", tag="analytics_type_x")
                        with dpg.plot_axis(dpg.mvYAxis, label="Count", tag="analytics_type_y"):
                            dpg.add_bar_series(
                                [],
                                [],
                                label="Count",
                                tag="analytics_type_series",
                                parent="analytics_type_y"
                            )

                dpg.add_separator()

                # Таблица аналитики
                dpg.add_text("Analytics Table", color=(150, 200, 255))
                with dpg.table(
                        tag="analytics_table",
                        header_row=True,
                        resizable=True,
                        policy=dpg.mvTable_SizingStretchProp,
                        borders_innerH=True,
                        borders_outerH=True,
                        borders_innerV=True,
                        borders_outerV=True,
                        height=300
                ):
                    dpg.add_table_column(label="Timestamp", width_fixed=True, init_width_or_weight=150)
                    dpg.add_table_column(label="Event Type", width_fixed=True, init_width_or_weight=100)
                    dpg.add_table_column(label="Target IP", width_fixed=True, init_width_or_weight=120)
                    dpg.add_table_column(label="Target Domain", width_fixed=True, init_width_or_weight=200)
                    dpg.add_table_column(label="Port", width_fixed=True, init_width_or_weight=80)
                    dpg.add_table_column(label="Protocol", width_fixed=True, init_width_or_weight=80)
                    dpg.add_table_column(label="Action", width_fixed=True, init_width_or_weight=80)

    def refresh_analytics(self):
        """Обновление аналитики"""
        if not dpg.does_item_exist("analytics_table"):
            logger.warning("refresh_analytics: analytics_table does not exist, skipping")
            return

        try:
            clients_data = self.get_clients_data()
            if dpg.does_item_exist("analytics_client_combo"):
                client_ids = ["all"] + [str(c.get('id')) for c in clients_data if c.get('id') is not None]
                current_value = dpg.get_value("analytics_client_combo")
                dpg.configure_item("analytics_client_combo", items=client_ids)
                if current_value in client_ids:
                    dpg.set_value("analytics_client_combo", current_value)
                elif client_ids:
                    dpg.set_value("analytics_client_combo", client_ids[0])

            client_id = dpg.get_value("analytics_client_combo") if dpg.does_item_exist(
                "analytics_client_combo") else "all"
            if client_id == "all":
                client_id = None

            logger.info(f"refresh_analytics: fetching analytics for client_id={client_id}")
            analytics_settings = self.get_analytics_settings() or {}
            analytics_limit = int(analytics_settings.get("limit", 1000) or 1000)
            analytics = self.api_client.get_analytics(client_id=client_id, limit=analytics_limit)
            logger.info(f"refresh_analytics: loaded {len(analytics)} analytics entries")
            ui_settings = self.get_ui_settings() or {}
            table_row_limit = int(ui_settings.get("table_row_limit", 1000) or 1000)
            analytics_table_limit = int(analytics_settings.get("table_limit", 250) or 250)
            display_limit = max(1, min(len(analytics), table_row_limit, analytics_table_limit))

            # Update graphs if they exist
            if dpg.does_item_exist("analytics_events_series"):
                logger.debug(f"refresh_analytics: updating graphs with {len(analytics)} analytics entries")

                if analytics:
                    # Prepare data for time series graph
                    time_buckets = defaultdict(int)
                    type_counts = defaultdict(int)

                    parsed_count = 0
                    for item in analytics:
                        try:
                            # Group by 5-minute intervals for better visualization
                            ts_str = item.get('timestamp', '')
                            if not ts_str:
                                continue
                            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                            # Group by 5-minute intervals
                            minute_key = ts.replace(second=0, microsecond=0)
                            minute_key = minute_key.replace(minute=(minute_key.minute // 5) * 5)
                            time_key = minute_key.timestamp()
                            time_buckets[time_key] += 1

                            # Count by type
                            event_type = item.get('event_type', 'unknown')
                            type_counts[event_type] += 1
                            parsed_count += 1
                        except Exception as e:
                            logger.debug(f"Error parsing analytics item: {e}, item: {item}")
                            continue

                    logger.debug(
                        f"refresh_analytics: parsed {parsed_count} items, {len(time_buckets)} time buckets, {len(type_counts)} event types")

                    # Update Events Over Time graph
                    if time_buckets:
                        sorted_times = sorted(time_buckets.keys())
                        counts = [time_buckets[t] for t in sorted_times]

                        if sorted_times and counts and len(sorted_times) == len(counts):
                            try:
                                logger.info(
                                    f"refresh_analytics: updating Events Over Time graph with {len(sorted_times)} data points")
                                # Ensure data is in correct format for dearpygui
                                x_data = [float(t) for t in sorted_times]
                                y_data = [float(c) for c in counts]
                                dpg.set_value("analytics_events_series", [x_data, y_data])

                                # Configure axis limits for better visualization
                                if x_data:
                                    dpg.set_axis_limits("analytics_events_x", min(x_data) - 100, max(x_data) + 100)
                                if y_data:
                                    dpg.set_axis_limits("analytics_events_y", 0, max(y_data) * 1.1)
                            except Exception as e:
                                logger.error(f"Error updating analytics_events_series: {e}", exc_info=True)
                        else:
                            logger.warning(
                                f"refresh_analytics: invalid data for graph - times: {len(sorted_times)}, counts: {len(counts)}")
                    else:
                        logger.debug("refresh_analytics: no time buckets, clearing Events Over Time graph")
                        try:
                            dpg.set_value("analytics_events_series", [[], []])
                        except Exception as e:
                            logger.debug(f"Error clearing analytics_events_series: {e}")

                    # Update Events by Type graph
                    if type_counts:
                        types = list(type_counts.keys())
                        type_values = [type_counts[t] for t in types]
                        type_indices = list(range(len(types)))

                        if type_indices and type_values and len(type_indices) == len(type_values):
                            try:
                                logger.info(f"refresh_analytics: updating Events by Type graph with {len(types)} types")
                                # Ensure data is in correct format
                                x_data = [float(i) for i in type_indices]
                                y_data = [float(v) for v in type_values]
                                dpg.set_value("analytics_type_series", [x_data, y_data])

                                # Configure axis limits
                                if x_data:
                                    dpg.set_axis_limits("analytics_type_x", -0.5, max(x_data) + 0.5)
                                if y_data:
                                    dpg.set_axis_limits("analytics_type_y", 0, max(y_data) * 1.1)
                            except Exception as e:
                                logger.error(f"Error updating analytics_type_series: {e}", exc_info=True)
                    else:
                        logger.debug("refresh_analytics: no type counts, clearing Events by Type graph")
                        try:
                            dpg.set_value("analytics_type_series", [[], []])
                        except Exception as e:
                            logger.debug(f"Error clearing analytics_type_series: {e}")
                else:
                    # Clear graphs if no analytics data
                    logger.debug("refresh_analytics: no analytics data, clearing graphs")
                    try:
                        dpg.set_value("analytics_events_series", [[], []])
                        dpg.set_value("analytics_type_series", [[], []])
                    except Exception as e:
                        logger.debug(f"Error clearing graphs: {e}")
            else:
                logger.debug("refresh_analytics: analytics_events_series does not exist")

            # Очищаем только строки, не затрагивая колонки
            _clear_table_rows("analytics_table")

            if analytics:
                for item in analytics[:display_limit]:
                    with dpg.table_row(parent="analytics_table"):
                        dpg.add_text(item.get('timestamp', 'N/A')[:19] if item.get('timestamp') else 'N/A')
                        dpg.add_text(item.get('event_type', 'N/A'))
                        dpg.add_text(item.get('target_ip', 'N/A') or 'N/A')
                        dpg.add_text(item.get('target_domain', 'N/A') or 'N/A')
                        dpg.add_text(
                            str(item.get('target_port', 'N/A')) if item.get('target_port') is not None else 'N/A')
                        dpg.add_text(item.get('protocol', 'N/A') or 'N/A')
                        dpg.add_text(item.get('action', 'N/A') or 'N/A')
                logger.debug(f"refresh_analytics: added {display_limit} rows to table")
            else:
                # Show message if no data
                with dpg.table_row(parent="analytics_table"):
                    dpg.add_text("No analytics data found", color=(150, 150, 150))
        except Exception as e:
            logger.error(f"Error refreshing analytics: {e}", exc_info=True)
