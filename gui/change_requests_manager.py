"""Модуль запросов на изменение - одобрение и отклонение запросов"""

import logging
from typing import Dict, Any

import dearpygui.dearpygui as dpg

logger = logging.getLogger(__name__)


class ChangeRequestsManager:
    """Класс для управления запросами на изменение"""

    def __init__(self, api_client):
        """
        Инициализация менеджера запросов на изменение
        
        Args:
            api_client: API клиент для работы с сервером
        """
        self.api_client = api_client

    def create_tab(self):
        """Создание вкладки запросов на изменение"""
        with dpg.group(horizontal=True):
            with dpg.child_window(width=300, height=600):
                dpg.add_text("Filters", color=(100, 150, 255))
                dpg.add_separator()
                dpg.add_text("Status:")
                dpg.add_combo(
                    tag="requests_status_combo",
                    items=["all", "pending", "approved", "rejected"],
                    default_value="pending",
                    width=-1,
                    callback=self.refresh_change_requests
                )
                dpg.add_separator()
                dpg.add_button(label="Refresh", callback=self.refresh_change_requests)

            with dpg.child_window(width=-1, height=600):
                dpg.add_text("Change Requests", color=(100, 150, 255))
                dpg.add_separator()
                with dpg.table(
                        tag="requests_table",
                        header_row=True,
                        resizable=True,
                        policy=dpg.mvTable_SizingStretchProp,
                        borders_innerH=True,
                        borders_outerH=True,
                        borders_innerV=True,
                        borders_outerV=True
                ):
                    dpg.add_table_column(label="ID", width_fixed=True, init_width_or_weight=100)
                    dpg.add_table_column(label="Client ID", width_fixed=True, init_width_or_weight=150)
                    dpg.add_table_column(label="Rule ID", width_fixed=True, init_width_or_weight=100)
                    dpg.add_table_column(label="Status", width_fixed=True, init_width_or_weight=100)
                    dpg.add_table_column(label="Requested At", width_fixed=True, init_width_or_weight=150)
                    dpg.add_table_column(label="Actions", width_fixed=True, init_width_or_weight=200)

    def refresh_change_requests(self):
        """Обновление запросов на изменение"""
        if not dpg.does_item_exist("requests_table"):
            logger.warning("refresh_change_requests: requests_table does not exist, skipping")
            return

        try:
            status = dpg.get_value("requests_status_combo") if dpg.does_item_exist("requests_status_combo") else None
            if status == "all":
                status = None

            requests = self.api_client.get_change_requests(status=status)
            logger.info(f"refresh_change_requests: loaded {len(requests)} change requests")

            # Очищаем таблицу
            dpg.delete_item("requests_table", children_only=True)

            # Заполняем таблицу
            for req in requests:
                with dpg.table_row(parent="requests_table"):
                    dpg.add_text(req.get('id', 'N/A')[:20])
                    dpg.add_text(req.get('client_id', 'N/A'))
                    dpg.add_text(req.get('rule_id', 'N/A') or 'N/A')
                    dpg.add_text(req.get('status', 'N/A'))
                    dpg.add_text(req.get('requested_at', 'N/A')[:19] if req.get('requested_at') else 'N/A')
                    with dpg.group(horizontal=True):
                        if req.get('status') == 'pending':
                            dpg.add_button(
                                label="Approve",
                                callback=lambda s, a, r=req: self.approve_request(r.get('id'))
                            )
                            dpg.add_button(
                                label="Reject",
                                callback=lambda s, a, r=req: self.show_reject_dialog(r.get('id'))
                            )
            logger.debug(f"refresh_change_requests: added {len(requests)} rows to table")
        except Exception as e:
            logger.error(f"Error refreshing change requests: {e}", exc_info=True)

    def approve_request(self, request_id: str):
        """Одобрение запроса"""
        result = self.api_client.approve_request(request_id)
        if result:
            logger.info("Request approved")
            self.refresh_change_requests()
        else:
            logger.error("Failed to approve request")

    def show_reject_dialog(self, request_id: str):
        """Показ диалога отклонения запроса"""
        # Удаляем существующее окно, если оно есть
        if dpg.does_item_exist("reject_window"):
            dpg.delete_item("reject_window")

        with dpg.window(label="Reject Request", modal=True, tag="reject_window", width=400, height=200):
            dpg.add_text("Reason:")
            dpg.add_input_text(tag="reject_reason_input", width=-1, multiline=True, height=100)
            with dpg.group(horizontal=True):
                dpg.add_button(
                    label="Reject",
                    callback=lambda: self.reject_request(request_id)
                )
                dpg.add_button(label="Cancel", callback=lambda: dpg.delete_item("reject_window"))

    def reject_request(self, request_id: str):
        """Отклонение запроса"""
        reason = dpg.get_value("reject_reason_input")
        result = self.api_client.reject_request(request_id, reason)
        if result:
            logger.info("Request rejected")
            dpg.delete_item("reject_window")
            self.refresh_change_requests()
        else:
            logger.error("Failed to reject request")
