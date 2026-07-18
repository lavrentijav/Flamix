"""Виджет формы для создания/редактирования правил файрвола"""

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QComboBox,
    QPushButton,
    QFormLayout,
)
from PySide6.QtCore import Qt
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class RuleFormWidget(QWidget):
    """Форма для создания и редактирования правил файрвола"""

    def __init__(self, schema: Optional[Dict[str, Any]] = None, parent=None):
        super().__init__(parent)
        self.schema = schema
        self.init_ui()

    def init_ui(self):
        """Инициализация UI формы"""
        layout = QFormLayout()
        
        # Имя правила
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Введите имя правила")
        layout.addRow("Имя правила:", self.name_input)
        
        # Направление
        self.direction_combo = QComboBox()
        self.direction_combo.addItems(["in", "out"])
        layout.addRow("Направление:", self.direction_combo)
        
        # Действие
        self.action_combo = QComboBox()
        self.action_combo.addItems(["block", "allow"])
        layout.addRow("Действие:", self.action_combo)
        
        # Протокол
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["", "TCP", "UDP", "ICMP", "Any"])
        layout.addRow("Протокол:", self.protocol_combo)
        
        # Порт (локальный)
        self.local_port_input = QLineEdit()
        self.local_port_input.setPlaceholderText("например: 80, 8000-9000")
        layout.addRow("Локальный порт:", self.local_port_input)
        
        # Порт (удаленный)
        self.remote_port_input = QLineEdit()
        self.remote_port_input.setPlaceholderText("например: 80, 8000-9000")
        layout.addRow("Удаленный порт:", self.remote_port_input)
        
        # IP (локальный)
        self.local_ip_input = QLineEdit()
        self.local_ip_input.setPlaceholderText("Any, LocalSubnet, или IP адрес")
        self.local_ip_input.setText("Any")
        layout.addRow("Локальный IP:", self.local_ip_input)
        
        # IP (удаленный)
        self.remote_ip_input = QLineEdit()
        self.remote_ip_input.setPlaceholderText("Any, LocalSubnet, или IP адрес")
        self.remote_ip_input.setText("Any")
        layout.addRow("Удаленный IP:", self.remote_ip_input)
        
        # Профиль
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(["", "domain", "private", "public"])
        layout.addRow("Профиль:", self.profile_combo)
        
        # Кнопки
        button_layout = QHBoxLayout()
        self.apply_btn = QPushButton("Применить")
        self.cancel_btn = QPushButton("Отмена")
        button_layout.addWidget(self.apply_btn)
        button_layout.addWidget(self.cancel_btn)
        layout.addRow("", button_layout)
        
        self.setLayout(layout)

    def get_rule_data(self) -> Dict[str, Any]:
        """
        Получение данных правила из формы
        
        Returns:
            Словарь с данными правила
        """
        rule_data = {
            "name": self.name_input.text().strip(),
            "direction": self.direction_combo.currentText(),
            "action": self.action_combo.currentText(),
        }
        
        # Протокол (только если выбран)
        protocol = self.protocol_combo.currentText()
        if protocol and protocol != "":
            rule_data["protocol"] = protocol if protocol != "Any" else None
        
        # Порты
        local_port = self.local_port_input.text().strip()
        if local_port:
            rule_data["port"] = local_port  # Для совместимости с GUI
            rule_data["local_port"] = local_port
        
        remote_port = self.remote_port_input.text().strip()
        if remote_port:
            rule_data["remote_port"] = remote_port
        
        # IP адреса
        local_ip = self.local_ip_input.text().strip()
        if local_ip and local_ip != "Any":
            rule_data["local_ip"] = local_ip
        
        remote_ip = self.remote_ip_input.text().strip()
        if remote_ip and remote_ip != "Any":
            rule_data["ip"] = remote_ip  # Для совместимости с GUI
            rule_data["remote_ip"] = remote_ip
        
        # Профиль
        profile = self.profile_combo.currentText()
        if profile and profile != "":
            rule_data["profile"] = profile
        
        return rule_data

    def set_rule_data(self, rule_data: Dict[str, Any]):
        """
        Заполнение формы данными правила
        
        Args:
            rule_data: Словарь с данными правила
        """
        self.name_input.setText(rule_data.get("name", ""))
        
        if "direction" in rule_data:
            index = self.direction_combo.findText(rule_data["direction"])
            if index >= 0:
                self.direction_combo.setCurrentIndex(index)
        
        if "action" in rule_data:
            index = self.action_combo.findText(rule_data["action"])
            if index >= 0:
                self.action_combo.setCurrentIndex(index)
        
        if "protocol" in rule_data:
            protocol = rule_data["protocol"]
            index = self.protocol_combo.findText(protocol if protocol else "Any")
            if index >= 0:
                self.protocol_combo.setCurrentIndex(index)
        
        self.local_port_input.setText(str(rule_data.get("local_port", rule_data.get("port", ""))))
        self.remote_port_input.setText(str(rule_data.get("remote_port", "")))
        self.local_ip_input.setText(str(rule_data.get("local_ip", "Any")))
        self.remote_ip_input.setText(str(rule_data.get("remote_ip", rule_data.get("ip", "Any"))))
        
        if "profile" in rule_data:
            profile = rule_data["profile"]
            index = self.profile_combo.findText(profile if profile else "")
            if index >= 0:
                self.profile_combo.setCurrentIndex(index)

    def clear(self):
        """Очистка формы"""
        self.name_input.clear()
        self.direction_combo.setCurrentIndex(0)
        self.action_combo.setCurrentIndex(0)
        self.protocol_combo.setCurrentIndex(0)
        self.local_port_input.clear()
        self.remote_port_input.clear()
        self.local_ip_input.setText("Any")
        self.remote_ip_input.setText("Any")
        self.profile_combo.setCurrentIndex(0)
