"""GUI приложение на dearpygui для управления Flamix Server"""

import dearpygui.dearpygui as dpg
import logging
import threading
import time
from typing import Optional, Dict, Any, List

from app.api_client import FlamixAPIClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


class FlamixGUI:
    """GUI приложение Flamix"""

    def __init__(self, server_url: str = "http://127.0.0.1:8080"):
        """
        Инициализация GUI

        Args:
            server_url: URL сервера
        """
        self.api_client = FlamixAPIClient(server_url)
        self.current_client_id: Optional[str] = None
        self.rules_data: List[Dict[str, Any]] = []
        self.clients_data: List[Dict[str, Any]] = []
        self.refresh_thread: Optional[threading.Thread] = None
        self.running = False

    def create_window(self):
        """Создание главного окна"""
        dpg.create_context()
        dpg.create_viewport(title="Flamix Management", width=1400, height=900)
        
        # Настройка темы
        with dpg.theme() as global_theme:
            with dpg.theme_component(dpg.mvAll):
                dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 5, category=dpg.mvThemeCat_Core)
                dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 5, category=dpg.mvThemeCat_Core)
        
        dpg.bind_theme(global_theme)

        with dpg.window(label="Flamix Server Management", tag="main_window"):
            # Верхняя панель
            with dpg.group(horizontal=True):
                dpg.add_text("Server URL:")
                dpg.add_input_text(
                    default_value="http://127.0.0.1:8080",
                    tag="server_url_input",
                    width=200
                )
                dpg.add_button(label="Connect", callback=self.on_connect)
                dpg.add_text("Status: Disconnected", tag="status_text")

            dpg.add_separator()

            # Основная область с вкладками
            with dpg.tab_bar():
                # Вкладка клиентов
                with dpg.tab(label="Clients"):
                    self._create_clients_tab()

                # Вкладка правил
                with dpg.tab(label="Rules"):
                    self._create_rules_tab()

                # Вкладка аналитики
                with dpg.tab(label="Analytics"):
                    self._create_analytics_tab()

                # Вкладка запросов на изменение
                with dpg.tab(label="Change Requests"):
                    self._create_change_requests_tab()

        dpg.setup_dearpygui()
        dpg.show_viewport()
        dpg.set_primary_window("main_window", True)
        
        # Иконка (опционально)
        # dpg.set_viewport_icon("icon.ico")

    def _create_clients_tab(self):
        """Создание вкладки клиентов"""
        with dpg.group(horizontal=True):
            with dpg.child_window(width=400, height=600):
                dpg.add_text("Clients", color=(100, 150, 255))
                dpg.add_separator()
                dpg.add_button(label="Refresh", callback=self.refresh_clients)
                dpg.add_listbox(
                    tag="clients_list",
                    width=-1,
                    num_items=20,
                    callback=self.on_client_selected
                )

            with dpg.child_window(width=-1, height=600):
                dpg.add_text("Client Details", tag="client_details_title", color=(100, 150, 255))
                dpg.add_separator()
                with dpg.group(tag="client_details"):
                    dpg.add_text("Select a client to view details")

    def _create_rules_tab(self):
        """Создание вкладки правил"""
        with dpg.group(horizontal=True):
            with dpg.child_window(width=300, height=600):
                dpg.add_text("Client:", color=(100, 150, 255))
                dpg.add_combo(
                    tag="rules_client_combo",
                    width=-1,
                    callback=self.on_rules_client_changed
                )
                dpg.add_separator()
                dpg.add_button(label="Refresh Rules", callback=self.refresh_rules)
                dpg.add_button(label="Add Rule", callback=self.show_add_rule_dialog)

            with dpg.child_window(width=-1, height=600):
                dpg.add_text("Rules", color=(100, 150, 255))
                dpg.add_separator()
                with dpg.table(
                    tag="rules_table",
                    header_row=True,
                    resizable=True,
                    policy=dpg.mvTable_SizingStretchProp,
                    borders_innerH=True,
                    borders_outerH=True,
                    borders_innerV=True,
                    borders_outerV=True
                ):
                    dpg.add_table_column(label="ID", width_fixed=True, init_width_or_weight=100)
                    dpg.add_table_column(label="Name", width_fixed=True, init_width_or_weight=200)
                    dpg.add_table_column(label="Action", width_fixed=True, init_width_or_weight=80)
                    dpg.add_table_column(label="Direction", width_fixed=True, init_width_or_weight=100)
                    dpg.add_table_column(label="Protocol", width_fixed=True, init_width_or_weight=80)
                    dpg.add_table_column(label="Enabled", width_fixed=True, init_width_or_weight=80)
                    dpg.add_table_column(label="Actions", width_fixed=True, init_width_or_weight=150)

    def _create_analytics_tab(self):
        """Создание вкладки аналитики"""
        with dpg.group(horizontal=True):
            with dpg.child_window(width=300, height=600):
                dpg.add_text("Filters", color=(100, 150, 255))
                dpg.add_separator()
                dpg.add_text("Client:")
                dpg.add_combo(tag="analytics_client_combo", width=-1)
                dpg.add_separator()
                dpg.add_button(label="Refresh", callback=self.refresh_analytics)

            with dpg.child_window(width=-1, height=600):
                dpg.add_text("Analytics", color=(100, 150, 255))
                dpg.add_separator()
                with dpg.table(
                    tag="analytics_table",
                    header_row=True,
                    resizable=True,
                    policy=dpg.mvTable_SizingStretchProp,
                    borders_innerH=True,
                    borders_outerH=True,
                    borders_innerV=True,
                    borders_outerV=True
                ):
                    dpg.add_table_column(label="Timestamp", width_fixed=True, init_width_or_weight=150)
                    dpg.add_table_column(label="Event Type", width_fixed=True, init_width_or_weight=100)
                    dpg.add_table_column(label="Target IP", width_fixed=True, init_width_or_weight=120)
                    dpg.add_table_column(label="Target Domain", width_fixed=True, init_width_or_weight=200)
                    dpg.add_table_column(label="Port", width_fixed=True, init_width_or_weight=80)
                    dpg.add_table_column(label="Protocol", width_fixed=True, init_width_or_weight=80)
                    dpg.add_table_column(label="Action", width_fixed=True, init_width_or_weight=80)

    def _create_change_requests_tab(self):
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

    def on_connect(self):
        """Обработка подключения к серверу"""
        server_url = dpg.get_value("server_url_input")
        self.api_client = FlamixAPIClient(server_url)

        if self.api_client.test_connection():
            dpg.set_value("status_text", f"Status: Connected to {server_url}")
            logger.info(f"Connected to server: {server_url}")
            self.refresh_clients()
            self.start_auto_refresh()
        else:
            dpg.set_value("status_text", f"Status: Connection failed")
            logger.error("Failed to connect to server")

    def refresh_clients(self):
        """Обновление списка клиентов"""
        clients = self.api_client.get_clients()
        self.clients_data = clients

        client_names = [f"{c.get('id', 'Unknown')} - {c.get('name', 'N/A')}" for c in clients]
        dpg.configure_item("clients_list", items=client_names)

        # Обновляем комбобоксы
        client_ids = [c.get('id', '') for c in clients]
        dpg.configure_item("rules_client_combo", items=client_ids)
        dpg.configure_item("analytics_client_combo", items=["all"] + client_ids)

    def on_client_selected(self, sender, app_data):
        """Обработка выбора клиента"""
        selected_idx = app_data
        if 0 <= selected_idx < len(self.clients_data):
            client = self.clients_data[selected_idx]
            self.current_client_id = client.get('id')
            self._show_client_details(client)

    def _show_client_details(self, client: Dict[str, Any]):
        """Отображение деталей клиента"""
        dpg.delete_item("client_details", children_only=True)

        with dpg.group(parent="client_details"):
            dpg.add_text(f"ID: {client.get('id', 'N/A')}")
            dpg.add_text(f"Name: {client.get('name', 'N/A')}")
            dpg.add_text(f"Hostname: {client.get('hostname', 'N/A')}")
            dpg.add_text(f"IP Address: {client.get('ip_address', 'N/A')}")
            dpg.add_text(f"Last Seen: {client.get('last_seen', 'N/A')}")
            dpg.add_text(f"Enabled: {'Yes' if client.get('enabled') else 'No'}")

    def on_rules_client_changed(self):
        """Обработка изменения выбранного клиента для правил"""
        client_id = dpg.get_value("rules_client_combo")
        if client_id:
            self.current_client_id = client_id
            self.refresh_rules()

    def refresh_rules(self):
        """Обновление списка правил"""
        if not self.current_client_id:
            return

        rules = self.api_client.get_client_rules(self.current_client_id)
        self.rules_data = rules

        # Очищаем таблицу
        dpg.delete_item("rules_table", children_only=True)

        # Заполняем таблицу
        for rule in rules:
            with dpg.table_row(parent="rules_table"):
                dpg.add_text(rule.get('id', 'N/A')[:20])
                dpg.add_text(rule.get('name', 'N/A'))
                dpg.add_text(rule.get('action', 'N/A'))
                dpg.add_text(rule.get('direction', 'N/A'))
                dpg.add_text(rule.get('protocol', 'N/A'))
                dpg.add_text("Yes" if rule.get('enabled', False) else "No")
                with dpg.group(horizontal=True):
                    dpg.add_button(
                        label="Edit",
                        callback=lambda s, a, r=rule: self.show_edit_rule_dialog(r)
                    )
                    dpg.add_button(
                        label="Delete",
                        callback=lambda s, a, r=rule: self.delete_rule(r)
                    )

    def show_add_rule_dialog(self):
        """Показ диалога добавления правила"""
        with dpg.window(label="Add Rule", modal=True, tag="add_rule_window", width=500, height=400):
            dpg.add_text("Rule Name:")
            dpg.add_input_text(tag="rule_name_input", width=-1)
            dpg.add_text("Action:")
            dpg.add_combo(items=["allow", "block"], default_value="block", tag="rule_action_combo", width=-1)
            dpg.add_text("Direction:")
            dpg.add_combo(items=["inbound", "outbound"], default_value="inbound", tag="rule_direction_combo", width=-1)
            dpg.add_text("Protocol:")
            dpg.add_combo(items=["TCP", "UDP", "ICMP", "ANY"], default_value="TCP", tag="rule_protocol_combo", width=-1)
            dpg.add_text("IP Addresses (comma-separated):")
            dpg.add_input_text(tag="rule_ips_input", width=-1)
            dpg.add_text("Domains (comma-separated):")
            dpg.add_input_text(tag="rule_domains_input", width=-1)
            dpg.add_text("Ports (comma-separated or range):")
            dpg.add_input_text(tag="rule_ports_input", width=-1)
            dpg.add_checkbox(label="Enabled", default_value=True, tag="rule_enabled_checkbox")
            with dpg.group(horizontal=True):
                dpg.add_button(label="Create", callback=self.create_rule)
                dpg.add_button(label="Cancel", callback=lambda: dpg.delete_item("add_rule_window"))

    def show_edit_rule_dialog(self, rule: Dict[str, Any]):
        """Показ диалога редактирования правила"""
        with dpg.window(label="Edit Rule", modal=True, tag="edit_rule_window", width=500, height=400):
            dpg.add_text("Rule Name:")
            dpg.add_input_text(default_value=rule.get('name', ''), tag="edit_rule_name_input", width=-1)
            dpg.add_text("Action:")
            dpg.add_combo(
                items=["allow", "block"],
                default_value=rule.get('action', 'block'),
                tag="edit_rule_action_combo",
                width=-1
            )
            dpg.add_text("Direction:")
            dpg.add_combo(
                items=["inbound", "outbound"],
                default_value=rule.get('direction', 'inbound'),
                tag="edit_rule_direction_combo",
                width=-1
            )
            dpg.add_text("Protocol:")
            dpg.add_combo(
                items=["TCP", "UDP", "ICMP", "ANY"],
                default_value=rule.get('protocol', 'TCP'),
                tag="edit_rule_protocol_combo",
                width=-1
            )
            targets = rule.get('targets', {})
            dpg.add_text("IP Addresses (comma-separated):")
            dpg.add_input_text(
                default_value=','.join(targets.get('ips', [])),
                tag="edit_rule_ips_input",
                width=-1
            )
            dpg.add_text("Domains (comma-separated):")
            dpg.add_input_text(
                default_value=','.join(targets.get('domains', [])),
                tag="edit_rule_domains_input",
                width=-1
            )
            dpg.add_text("Ports (comma-separated or range):")
            dpg.add_input_text(
                default_value=','.join(targets.get('ports', [])),
                tag="edit_rule_ports_input",
                width=-1
            )
            dpg.add_checkbox(
                label="Enabled",
                default_value=rule.get('enabled', True),
                tag="edit_rule_enabled_checkbox"
            )
            with dpg.group(horizontal=True):
                dpg.add_button(
                    label="Save",
                    callback=lambda: self.update_rule(rule.get('id'))
                )
                dpg.add_button(label="Cancel", callback=lambda: dpg.delete_item("edit_rule_window"))

    def create_rule(self):
        """Создание нового правила"""
        if not self.current_client_id:
            logger.warning("No client selected")
            return

        rule_data = {
            'client_id': self.current_client_id,
            'name': dpg.get_value("rule_name_input"),
            'action': dpg.get_value("rule_action_combo"),
            'direction': dpg.get_value("rule_direction_combo"),
            'protocol': dpg.get_value("rule_protocol_combo"),
            'targets': {
                'ips': [ip.strip() for ip in dpg.get_value("rule_ips_input").split(',') if ip.strip()],
                'domains': [d.strip() for d in dpg.get_value("rule_domains_input").split(',') if d.strip()],
                'ports': [p.strip() for p in dpg.get_value("rule_ports_input").split(',') if p.strip()]
            },
            'enabled': dpg.get_value("rule_enabled_checkbox")
        }

        result = self.api_client.create_rule(rule_data)
        if result:
            logger.info("Rule created successfully")
            dpg.delete_item("add_rule_window")
            self.refresh_rules()
        else:
            logger.error("Failed to create rule")

    def update_rule(self, rule_id: str):
        """Обновление правила"""
        if not self.current_client_id:
            return

        rule_data = {
            'client_id': self.current_client_id,
            'name': dpg.get_value("edit_rule_name_input"),
            'action': dpg.get_value("edit_rule_action_combo"),
            'direction': dpg.get_value("edit_rule_direction_combo"),
            'protocol': dpg.get_value("edit_rule_protocol_combo"),
            'targets': {
                'ips': [ip.strip() for ip in dpg.get_value("edit_rule_ips_input").split(',') if ip.strip()],
                'domains': [d.strip() for d in dpg.get_value("edit_rule_domains_input").split(',') if d.strip()],
                'ports': [p.strip() for p in dpg.get_value("edit_rule_ports_input").split(',') if p.strip()]
            },
            'enabled': dpg.get_value("edit_rule_enabled_checkbox")
        }

        result = self.api_client.update_rule(rule_id, rule_data)
        if result:
            logger.info("Rule updated successfully")
            dpg.delete_item("edit_rule_window")
            self.refresh_rules()
        else:
            logger.error("Failed to update rule")

    def delete_rule(self, rule: Dict[str, Any]):
        """Удаление правила"""
        if not self.current_client_id:
            return

        result = self.api_client.delete_rule(rule.get('id'), self.current_client_id)
        if result:
            logger.info("Rule deleted successfully")
            self.refresh_rules()
        else:
            logger.error("Failed to delete rule")

    def refresh_analytics(self):
        """Обновление аналитики"""
        client_id = dpg.get_value("analytics_client_combo")
        if client_id == "all":
            client_id = None

        analytics = self.api_client.get_analytics(client_id=client_id, limit=1000)

        # Очищаем таблицу
        dpg.delete_item("analytics_table", children_only=True)

        # Заполняем таблицу
        for item in analytics[:100]:  # Показываем первые 100 записей
            with dpg.table_row(parent="analytics_table"):
                dpg.add_text(item.get('timestamp', 'N/A')[:19])
                dpg.add_text(item.get('event_type', 'N/A'))
                dpg.add_text(item.get('target_ip', 'N/A'))
                dpg.add_text(item.get('target_domain', 'N/A'))
                dpg.add_text(str(item.get('target_port', 'N/A')))
                dpg.add_text(item.get('protocol', 'N/A'))
                dpg.add_text(item.get('action', 'N/A'))

    def refresh_change_requests(self):
        """Обновление запросов на изменение"""
        status = dpg.get_value("requests_status_combo")
        if status == "all":
            status = None

        requests = self.api_client.get_change_requests(status=status)

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

    def start_auto_refresh(self):
        """Запуск автоматического обновления"""
        self.running = True

        def refresh_loop():
            while self.running:
                time.sleep(30)  # Обновление каждые 30 секунд
                if self.running:
                    try:
                        self.refresh_clients()
                        if self.current_client_id:
                            self.refresh_rules()
                    except Exception as e:
                        logger.error(f"Error in auto-refresh: {e}")

        self.refresh_thread = threading.Thread(target=refresh_loop, daemon=True)
        self.refresh_thread.start()

    def stop_auto_refresh(self):
        """Остановка автоматического обновления"""
        self.running = False

    def run(self):
        """Запуск GUI приложения"""
        self.create_window()
        try:
            dpg.start_dearpygui()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop_auto_refresh()
            dpg.destroy_context()


def main():
    """Точка входа GUI приложения"""
    import sys

    if len(sys.argv) > 1:
        server_url = sys.argv[1]
    else:
        server_url = "http://127.0.0.1:8080"

    app = FlamixGUI(server_url)
    app.run()


if __name__ == "__main__":
    main()
