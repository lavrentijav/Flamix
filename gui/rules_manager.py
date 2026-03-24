"""Модуль управления правилами - CRUD операции с правилами"""

import logging
from typing import Optional, Dict, Any, List

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


class RulesManager:
    """Класс для управления правилами - все функции работы с правилами"""

    def __init__(self, api_client, get_current_client_id_callback):
        """
        Инициализация менеджера правил
        
        Args:
            api_client: API клиент для работы с сервером
            get_current_client_id_callback: Callback для получения текущего ID клиента
        """
        self.api_client = api_client
        self.get_current_client_id = get_current_client_id_callback
        self.rules_data: List[Dict[str, Any]] = []

    def create_tab(self):
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

    def on_rules_client_changed(self):
        """Обработка изменения выбранного клиента для правил"""
        client_id = dpg.get_value("rules_client_combo")
        if client_id:
            self.refresh_rules()

    def refresh_rules(self):
        """Обновление списка правил"""
        current_client_id = self.get_current_client_id()
        if not current_client_id:
            # Пытаемся получить из комбобокса
            if dpg.does_item_exist("rules_client_combo"):
                current_client_id = dpg.get_value("rules_client_combo")
            if not current_client_id:
                logger.debug("refresh_rules: no current_client_id, skipping")
                return

        if not dpg.does_item_exist("rules_table"):
            logger.warning("refresh_rules: rules_table does not exist, skipping")
            return

        try:
            rules = self.api_client.get_client_rules(current_client_id)
            logger.info(f"refresh_rules: loaded {len(rules)} rules for client {current_client_id}")
            self.rules_data = rules

            # Очищаем только строки, не затрагивая колонки
            _clear_table_rows("rules_table")

            # Заполняем таблицу
            for rule in rules:
                with dpg.table_row(parent="rules_table"):
                    dpg.add_text(rule.get('id', 'N/A'))
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
            logger.debug(f"refresh_rules: added {len(rules)} rows to table")
        except Exception as e:
            logger.error(f"Error refreshing rules: {e}", exc_info=True)

    def show_add_rule_dialog(self):
        """Показ диалога добавления правила"""
        # Удаляем существующее окно, если оно есть
        if dpg.does_item_exist("add_rule_window"):
            dpg.delete_item("add_rule_window")

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
        # Удаляем существующее окно, если оно есть
        if dpg.does_item_exist("edit_rule_window"):
            dpg.delete_item("edit_rule_window")

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
        current_client_id = self.get_current_client_id()
        if not current_client_id:
            # Пытаемся получить из комбобокса
            if dpg.does_item_exist("rules_client_combo"):
                current_client_id = dpg.get_value("rules_client_combo")
            if not current_client_id:
                logger.warning("No client selected")
                return

        rule_data = {
            'client_id': current_client_id,
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
        current_client_id = self.get_current_client_id()
        if not current_client_id:
            # Пытаемся получить из комбобокса
            if dpg.does_item_exist("rules_client_combo"):
                current_client_id = dpg.get_value("rules_client_combo")
            if not current_client_id:
                return

        rule_data = {
            'client_id': current_client_id,
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
        current_client_id = self.get_current_client_id()
        if not current_client_id:
            # Пытаемся получить из комбобокса
            if dpg.does_item_exist("rules_client_combo"):
                current_client_id = dpg.get_value("rules_client_combo")
            if not current_client_id:
                return

        result = self.api_client.delete_rule(rule.get('id'), current_client_id)
        if result:
            logger.info("Rule deleted successfully")
            self.refresh_rules()
        else:
            logger.error("Failed to delete rule")
