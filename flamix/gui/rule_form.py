"""Виджет формы для создания правил на основе схемы"""

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QSpinBox,
    QComboBox,
    QRadioButton,
    QButtonGroup,
    QPushButton,
    QFormLayout,
    QGroupBox,
)
from PySide6.QtCore import Qt
from typing import Dict, Any, List, Optional


class RuleFormWidget(QWidget):
    """Виджет формы для создания правила на основе схемы из манифеста"""

    def __init__(self, schema: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.schema = schema
        self.fields: Dict[str, Any] = {}
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Заголовок
        title = QLabel("Create New Rule")
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(title)

        # Форма
        form_layout = QFormLayout()

        fields = self.schema.get("fields", [])
        for field_def in fields:
            field_name = field_def["name"]
            field_type = field_def.get("type", "text")
            label = field_def.get("label", field_name)
            required = field_def.get("required", False)
            default = field_def.get("default")

            widget = self._create_field_widget(field_def)
            self.fields[field_name] = widget

            label_text = label + (" *" if required else "")
            form_layout.addRow(label_text, widget)

        layout.addLayout(form_layout)

        # Кнопки
        btn_layout = QHBoxLayout()
        self.apply_btn = QPushButton("Apply Rule")
        self.cancel_btn = QPushButton("Cancel")
        btn_layout.addWidget(self.apply_btn)
        btn_layout.addWidget(self.cancel_btn)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

    def _create_field_widget(self, field_def: Dict[str, Any]):
        """Создание виджета для поля на основе схемы"""
        field_type = field_def.get("type", "text")
        default = field_def.get("default")

        if field_type == "text":
            widget = QLineEdit()
            if default:
                widget.setText(str(default))
            return widget

        elif field_type == "number":
            widget = QSpinBox()
            widget.setMinimum(field_def.get("min", 0))
            widget.setMaximum(field_def.get("max", 65535))
            if default is not None:
                widget.setValue(int(default))
            else:
                widget.setSpecialValueText("Not set")
            return widget

        elif field_type == "select":
            widget = QComboBox()
            options = field_def.get("options", [])
            for option in options:
                if isinstance(option, dict):
                    widget.addItem(option.get("label", option.get("value")), option.get("value"))
                else:
                    widget.addItem(str(option), option)
            if default:
                index = widget.findData(default)
                if index >= 0:
                    widget.setCurrentIndex(index)
            return widget

        elif field_type == "radio":
            group = QButtonGroup()
            container = QWidget()
            layout = QHBoxLayout()
            container.setLayout(layout)

            options = field_def.get("options", [])
            for option in options:
                if isinstance(option, dict):
                    value = option.get("value")
                    label = option.get("label", value)
                else:
                    value = option
                    label = str(option)

                radio = QRadioButton(label)
                radio.setProperty("value", value)
                group.addButton(radio)
                layout.addWidget(radio)

                if default == value:
                    radio.setChecked(True)

            # Сохраняем группу в виджете
            container.setProperty("button_group", group)
            return container

        else:
            # По умолчанию текстовое поле
            widget = QLineEdit()
            if default:
                widget.setText(str(default))
            return widget

    def get_rule_data(self) -> Dict[str, Any]:
        """Получение данных правила из формы"""
        rule = {}

        for field_name, widget in self.fields.items():
            # Получаем значение в зависимости от типа виджета
            if isinstance(widget, QLineEdit):
                value = widget.text().strip()
                if value:
                    rule[field_name] = value

            elif isinstance(widget, QSpinBox):
                if widget.value() > 0 or not widget.specialValueText():
                    rule[field_name] = widget.value()

            elif isinstance(widget, QComboBox):
                rule[field_name] = widget.currentData()

            elif isinstance(widget, QWidget):
                # Radio buttons
                button_group = widget.property("button_group")
                if button_group:
                    checked_button = button_group.checkedButton()
                    if checked_button:
                        rule[field_name] = checked_button.property("value")

        return rule

    def set_rule_data(self, rule: Dict[str, Any]):
        """Установка данных правила в форму"""
        for field_name, value in rule.items():
            if field_name in self.fields:
                widget = self.fields[field_name]

                if isinstance(widget, QLineEdit):
                    widget.setText(str(value))

                elif isinstance(widget, QSpinBox):
                    widget.setValue(int(value))

                elif isinstance(widget, QComboBox):
                    index = widget.findData(value)
                    if index >= 0:
                        widget.setCurrentIndex(index)

                elif isinstance(widget, QWidget):
                    button_group = widget.property("button_group")
                    if button_group:
                        for button in button_group.buttons():
                            if button.property("value") == value:
                                button.setChecked(True)
                                break

    def clear(self):
        """Очистка формы"""
        for field_name, widget in self.fields.items():
            if isinstance(widget, QLineEdit):
                widget.clear()
            elif isinstance(widget, QSpinBox):
                widget.setValue(0)
            elif isinstance(widget, QComboBox):
                widget.setCurrentIndex(0)
            elif isinstance(widget, QWidget):
                button_group = widget.property("button_group")
                if button_group:
                    for button in button_group.buttons():
                        button.setChecked(False)

