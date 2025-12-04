"""Главное окно GUI"""

import sys
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTabWidget,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QFileDialog,
    QMessageBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QSplitter,
)
from PySide6.QtCore import Qt, QTimer, QThread, Signal, QObject
import logging

from flamix.gui.rule_form import RuleFormWidget

logger = logging.getLogger(__name__)


class SyncWorker(QObject):
    """Рабочий поток для синхронных операций"""
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def run(self):
        """Запуск синхронной функции"""
        try:
            result = self.func(*self.args, **self.kwargs)
            self.finished.emit(result)
        except Exception as e:
            logger.error(f"Error in SyncWorker: {e}", exc_info=True)
            self.error.emit(str(e))


class PluginSelectorDialog(QDialog):
    """Диалог выбора плагина при входе"""

    def __init__(self, plugins: List[Dict[str, Any]], parent=None):
        super().__init__(parent)
        self.selected_plugin = None
        self.plugins = plugins
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Select Plugin")
        self.setModal(True)
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Select a plugin to manage rules:"))

        self.combo = QComboBox()
        for plugin in self.plugins:
            if plugin.get("enabled"):
                self.combo.addItem(
                    f"{plugin['name']} ({plugin['id']})",
                    plugin["id"]
                )
        layout.addWidget(self.combo)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def get_selected_plugin_id(self) -> Optional[str]:
        """Получение выбранного ID плагина"""
        if self.exec() == QDialog.Accepted:
            return self.combo.currentData()
        return None


class DashboardWidget(QWidget):
    """Dashboard экран"""

    def __init__(self, plugin_manager, db, traffic_monitor):
        super().__init__()
        self.plugin_manager = plugin_manager
        self.db = db
        self.traffic_monitor = traffic_monitor
        self.init_ui()
        # Отложенный запуск refresh через QTimer, чтобы Qt и БД были полностью инициализированы
        QTimer.singleShot(500, self._delayed_init)
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh)
        self.refresh_timer.start(5000)  # Обновление каждые 5 секунд
    
    def _delayed_init(self):
        """Отложенная инициализация после полной загрузки Qt"""
        try:
            self.refresh()
        except Exception as e:
            logger.error(f"Error in delayed init: {e}", exc_info=True)

    def init_ui(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Flamix Dashboard"))
        
        self.status_label = QLabel("Status: Initializing...")
        layout.addWidget(self.status_label)
        
        self.plugins_label = QLabel("Active Plugins: 0")
        layout.addWidget(self.plugins_label)
        
        self.traffic_label = QLabel("Avg Speed: -")
        layout.addWidget(self.traffic_label)
        
        layout.addStretch()
        self.setLayout(layout)

    def refresh(self):
        """Обновление данных"""
        if not hasattr(self, 'status_label'):
            return
            
        def _refresh():
            try:
                plugins = self.plugin_manager.list_plugins()
                enabled_count = sum(1 for p in plugins if p.get("enabled"))
                if hasattr(self, 'plugins_label'):
                    self.plugins_label.setText(f"Active Plugins: {enabled_count}")
                if hasattr(self, 'status_label'):
                    self.status_label.setText("Status: Running")
                
                # Получение статистики трафика за последний час
                try:
                    # Ожидание готовности traffic_monitor
                    if not self.traffic_monitor.is_ready():
                        import time
                        for _ in range(300):  # 30 секунд максимум
                            if self.traffic_monitor.is_ready():
                                break
                            time.sleep(0.1)
                    
                    from datetime import datetime, timedelta
                    end_time = datetime.now()
                    start_time = end_time - timedelta(hours=1)
                    stats = self.traffic_monitor.get_traffic_stats(start_time, end_time)
                    
                    if stats and hasattr(self, 'traffic_label'):
                        total_sent = sum(s.get("sent_speed", 0) for s in stats)
                        total_recv = sum(s.get("recv_speed", 0) for s in stats)
                        avg_sent = total_sent / len(stats) if stats else 0
                        avg_recv = total_recv / len(stats) if stats else 0
                        self.traffic_label.setText(
                            f"Avg Speed: ↑ {avg_sent/1024:.1f} KB/s ↓ {avg_recv/1024:.1f} KB/s"
                        )
                except Exception as e:
                    logger.debug(f"Error getting traffic stats: {e}")
            except Exception as e:
                logger.error(f"Error in refresh: {e}")
                if hasattr(self, 'status_label'):
                    self.status_label.setText(f"Status: Error - {e}")

        # Запускаем синхронную функцию в потоке
        self._run_sync(_refresh)

    def _run_sync(self, func, *args, **kwargs):
        """Запуск синхронной операции в потоке"""
        try:
            # Убеждаемся, что QApplication существует
            app = QApplication.instance()
            if app is None:
                logger.error("QApplication instance not found, cannot start sync operation")
                return
            
            worker = SyncWorker(func, *args, **kwargs)
            thread = QThread()
            worker.moveToThread(thread)
            thread.started.connect(worker.run)
            worker.finished.connect(thread.quit)
            worker.finished.connect(thread.deleteLater)
            # Безопасная обработка ошибок - логируем, но не показываем QMessageBox из потока
            worker.error.connect(lambda e: logger.error(f"Sync operation error: {e}"))
            thread.finished.connect(thread.deleteLater)
            thread.start()
        except Exception as e:
            logger.error(f"Error starting sync operation: {e}", exc_info=True)


class PluginsWidget(QWidget):
    """Экран управления плагинами"""

    def __init__(self, plugin_manager, db):
        super().__init__()
        self.plugin_manager = plugin_manager
        self.db = db
        self.init_ui()
        # Отложенный запуск refresh через QTimer, чтобы Qt был полностью инициализирован
        QTimer.singleShot(100, self._delayed_init)
    
    def _delayed_init(self):
        """Отложенная инициализация после полной загрузки Qt"""
        try:
            self.refresh()
        except Exception as e:
            logger.error(f"Error in delayed init: {e}", exc_info=True)

    def init_ui(self):
        layout = QVBoxLayout()

        # Кнопка установки плагина
        install_btn = QPushButton("Install Plugin")
        install_btn.clicked.connect(self.install_plugin)
        layout.addWidget(install_btn)

        # Таблица плагинов
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["ID", "Name", "Version", "Status", "Actions"]
        )
        layout.addWidget(self.table)

        self.setLayout(layout)

    def install_plugin(self):
        """Установка плагина из ZIP"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Plugin ZIP",
            "",
            "ZIP Files (*.zip)"
        )
        if file_path:
            def _install():
                try:
                    from pathlib import Path
                    plugin_id = self.plugin_manager.install_plugin(Path(file_path))
                    manifest = self.plugin_manager.plugins[plugin_id]["manifest"]
                    self.db.add_plugin(plugin_id, manifest.permissions)
                    # Используем QTimer для безопасного вызова QMessageBox из главного потока
                    QTimer.singleShot(0, lambda: QMessageBox.information(
                        self,
                        "Success",
                        f"Plugin installed: {plugin_id}"
                    ))
                    self.refresh()
                except Exception as e:
                    logger.error(f"Error installing plugin: {e}", exc_info=True)
                    error_msg = str(e)
                    # Используем QTimer для безопасного вызова QMessageBox из главного потока
                    QTimer.singleShot(0, lambda: QMessageBox.critical(
                        self, 
                        "Error", 
                        f"Failed to install plugin:\n{error_msg}"
                    ))

            self._run_sync(_install)

    def refresh(self):
        """Обновление списка плагинов"""
        def _refresh():
            try:
                plugins = self.plugin_manager.list_plugins()
                self.table.setRowCount(len(plugins))
                for i, plugin in enumerate(plugins):
                    self.table.setItem(i, 0, QTableWidgetItem(plugin["id"]))
                    self.table.setItem(i, 1, QTableWidgetItem(plugin["name"]))
                    self.table.setItem(i, 2, QTableWidgetItem(plugin["version"]))
                    status = "Enabled" if plugin.get("enabled") else "Disabled"
                    self.table.setItem(i, 3, QTableWidgetItem(status))
                    
                    # Кнопка enable/disable
                    btn = QPushButton("Enable" if not plugin.get("enabled") else "Disable")
                    btn.clicked.connect(
                        lambda checked, pid=plugin["id"], enabled=plugin.get("enabled"): 
                        self.toggle_plugin(pid, enabled)
                    )
                    self.table.setCellWidget(i, 4, btn)
            except Exception as e:
                logger.error(f"Error refreshing plugins: {e}", exc_info=True)
                error_msg = str(e)
                # Используем QTimer для безопасного вызова QMessageBox из главного потока
                QTimer.singleShot(0, lambda: QMessageBox.critical(
                    self, 
                    "Error", 
                    f"Failed to load plugins:\n{error_msg}"
                ))

        self._run_sync(_refresh)

    def toggle_plugin(self, plugin_id: str, currently_enabled: bool):
        """Включение/отключение плагина"""
        def _toggle():
            try:
                if currently_enabled:
                    self.plugin_manager.disable_plugin(plugin_id)
                else:
                    self.plugin_manager.enable_plugin(plugin_id)
                self.refresh()
            except Exception as e:
                logger.error(f"Error toggling plugin {plugin_id}: {e}", exc_info=True)
                # Используем QTimer для безопасного вызова QMessageBox из главного потока
                error_msg = str(e)
                QTimer.singleShot(0, lambda: QMessageBox.critical(
                    self, 
                    "Error", 
                    f"Failed to toggle plugin:\n{error_msg}\n\nPlugin may require firewall to be configured first."
                ))

        self._run_sync(_toggle)

    def _run_sync(self, func, *args, **kwargs):
        """Запуск синхронной операции в потоке"""
        try:
            # Убеждаемся, что QApplication существует
            app = QApplication.instance()
            if app is None:
                logger.error("QApplication instance not found, cannot start sync operation")
                return
            
            worker = SyncWorker(func, *args, **kwargs)
            thread = QThread()
            worker.moveToThread(thread)
            thread.started.connect(worker.run)
            worker.finished.connect(thread.quit)
            worker.finished.connect(thread.deleteLater)
            # Безопасная обработка ошибок - логируем, но не показываем QMessageBox из потока
            worker.error.connect(lambda e: logger.error(f"Sync operation error: {e}"))
            thread.finished.connect(thread.deleteLater)
            thread.start()
        except Exception as e:
            logger.error(f"Error starting sync operation: {e}", exc_info=True)


class RulesWidget(QWidget):
    """Экран управления правилами"""

    def __init__(self, plugin_manager, db):
        super().__init__()
        self.plugin_manager = plugin_manager
        self.db = db
        self.current_plugin_id: Optional[str] = None
        self.rule_schema: Optional[Dict[str, Any]] = None
        try:
            self.init_ui()
            # Отложенный запуск select_plugin через QTimer, чтобы БД успела инициализироваться
            QTimer.singleShot(500, self.select_plugin)
        except Exception as e:
            logger.error(f"Error initializing RulesWidget: {e}", exc_info=True)
            layout = QVBoxLayout()
            layout.addWidget(QLabel(f"Error: {e}"))
            self.setLayout(layout)

    def init_ui(self):
        layout = QVBoxLayout()

        # Выбор плагина
        plugin_layout = QHBoxLayout()
        plugin_layout.addWidget(QLabel("Plugin:"))
        self.plugin_combo = QComboBox()
        self.plugin_combo.currentTextChanged.connect(self.on_plugin_changed)
        plugin_layout.addWidget(self.plugin_combo)
        select_btn = QPushButton("Select Plugin")
        select_btn.clicked.connect(self.select_plugin)
        plugin_layout.addWidget(select_btn)
        layout.addLayout(plugin_layout)

        # Splitter для формы и таблицы
        splitter = QSplitter(Qt.Horizontal)

        # Форма для добавления правил
        form_container = QWidget()
        form_layout = QVBoxLayout()
        form_label = QLabel("Add New Rule")
        form_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        form_layout.addWidget(form_label)
        
        self.rule_form = None
        self.form_container = QWidget()
        form_layout.addWidget(self.form_container)
        form_layout.addStretch()
        
        form_container.setLayout(form_layout)
        splitter.addWidget(form_container)

        # Таблица правил
        rules_container = QWidget()
        rules_layout = QVBoxLayout()
        rules_label = QLabel("Existing Rules")
        rules_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        rules_layout.addWidget(rules_label)
        
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["ID", "Name", "Details", "Created", "Actions"]
        )
        rules_layout.addWidget(self.table)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_rules)
        rules_layout.addWidget(refresh_btn)
        
        rules_container.setLayout(rules_layout)
        splitter.addWidget(rules_container)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter)
        self.setLayout(layout)

    def select_plugin(self):
        """Выбор плагина"""
        def _select():
            try:
                plugins = self.plugin_manager.list_plugins()
                enabled_plugins = [p for p in plugins if p.get("enabled")]
                
                if not enabled_plugins:
                    QTimer.singleShot(0, lambda: QMessageBox.warning(
                        self,
                        "No Plugins",
                        "No enabled plugins found. Please enable a plugin first."
                    ))
                    return

                dialog = PluginSelectorDialog(enabled_plugins, self)
                plugin_id = dialog.get_selected_plugin_id()
                
                if plugin_id:
                    self.current_plugin_id = plugin_id
                    self.load_plugin_schema(plugin_id)
                    self.refresh_rules()
            except Exception as e:
                logger.error(f"Error selecting plugin: {e}", exc_info=True)
                error_msg = str(e)
                QTimer.singleShot(0, lambda: QMessageBox.critical(
                    self, 
                    "Error", 
                    f"Failed to select plugin:\n{error_msg}"
                ))

        self._run_sync(_select)

    def load_plugin_schema(self, plugin_id: str):
        """Загрузка схемы правил из манифеста плагина (синхронный метод)"""
        try:
            if plugin_id not in self.plugin_manager.plugins:
                raise ValueError(f"Plugin {plugin_id} not found")
            
            plugin_info = self.plugin_manager.plugins[plugin_id]
            manifest = plugin_info["manifest"]
            self.rule_schema = manifest.dict().get("rule_schema")
            
            # Обновление формы
            if self.rule_form:
                self.form_container.layout().removeWidget(self.rule_form)
                self.rule_form.deleteLater()

            if self.rule_schema:
                self.rule_form = RuleFormWidget(self.rule_schema)
                self.rule_form.apply_btn.clicked.connect(self.apply_rule)
                self.rule_form.cancel_btn.clicked.connect(self.rule_form.clear)
                self.form_container.layout().insertWidget(1, self.rule_form)
        except Exception as e:
            logger.error(f"Failed to load schema: {e}")

    def on_plugin_changed(self, text: str):
        """Обработка изменения выбранного плагина"""
        # Можно добавить логику если нужно
        pass

    def apply_rule(self):
        """Применение правила"""
        if not self.current_plugin_id or not self.rule_form:
            QMessageBox.warning(self, "Error", "No plugin selected or form not loaded")
            return

        rule_data = self.rule_form.get_rule_data()
        if not rule_data:
            QMessageBox.warning(self, "Error", "Please fill in at least one field")
            return

        def _apply():
            try:
                import asyncio
                
                if self.current_plugin_id not in self.plugin_manager.plugins:
                    raise ValueError(f"Plugin {self.current_plugin_id} not found")

                plugin_info = self.plugin_manager.plugins[self.current_plugin_id]
                if not plugin_info["enabled"]:
                    raise ValueError(f"Plugin {self.current_plugin_id} is not enabled")

                instance = plugin_info["instance"]
                # Вызываем async метод плагина через asyncio.run
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                loop.run_until_complete(instance.apply_rule(rule_data))

                # Сохранение в БД
                import json
                rule_id = self.db.add_rule(self.current_plugin_id, json.dumps(rule_data))
                self.db.log_audit(
                    self.current_plugin_id,
                    "apply_rule",
                    "firewall",
                    "success",
                    {"rule_id": rule_id, "rule": rule_data}
                )

                QTimer.singleShot(0, lambda: QMessageBox.information(
                    self,
                    "Success",
                    f"Rule applied successfully! Rule ID: {rule_id}"
                ))
                self.rule_form.clear()
                self.refresh_rules()
            except Exception as e:
                logger.error(f"Error applying rule: {e}", exc_info=True)
                error_msg = str(e)
                QTimer.singleShot(0, lambda: QMessageBox.critical(
                    self, 
                    "Error", 
                    f"Failed to apply rule:\n{error_msg}"
                ))

        self._run_sync(_apply)

    def refresh_rules(self):
        """Обновление списка правил"""
        if not self.current_plugin_id:
            return

        def _refresh():
            try:
                rules = self.db.get_rules(self.current_plugin_id, limit=100)
                self.table.setRowCount(len(rules))
                for i, rule in enumerate(rules):
                    rule_id = rule.get("id", "")
                    content = rule.get("content", "{}")
                    try:
                        content_dict = json.loads(content)
                        rule_name = content_dict.get("name", "Unknown")
                        details = f"{content_dict.get('protocol', '')} {content_dict.get('port', '')}"
                    except:
                        rule_name = "Unknown"
                        details = content[:50]

                    self.table.setItem(i, 0, QTableWidgetItem(str(rule_id)))
                    self.table.setItem(i, 1, QTableWidgetItem(rule_name))
                    self.table.setItem(i, 2, QTableWidgetItem(details))
                    self.table.setItem(i, 3, QTableWidgetItem(rule.get("created_at", "")))
                    
                    # Кнопка удаления
                    delete_btn = QPushButton("Delete")
                    delete_btn.clicked.connect(
                        lambda checked, rid=rule_id: self.delete_rule(rid)
                    )
                    self.table.setCellWidget(i, 4, delete_btn)
            except Exception as e:
                logger.error(f"Error loading rules: {e}", exc_info=True)
                error_msg = str(e)
                QTimer.singleShot(0, lambda: QMessageBox.critical(
                    self, 
                    "Error", 
                    f"Failed to load rules:\n{error_msg}"
                ))

        self._run_sync(_refresh)

    def delete_rule(self, rule_id: int):
        """Удаление правила"""
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete rule {rule_id}?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            # TODO: Реализовать удаление через API
            QMessageBox.information(
                self,
                "Info",
                "Rule deletion will be implemented in the API"
            )
            self.refresh_rules()

    def _run_sync(self, func, *args, **kwargs):
        """Запуск синхронной операции в потоке"""
        try:
            # Убеждаемся, что QApplication существует
            app = QApplication.instance()
            if app is None:
                logger.error("QApplication instance not found, cannot start sync operation")
                return
            
            worker = SyncWorker(func, *args, **kwargs)
            thread = QThread()
            worker.moveToThread(thread)
            thread.started.connect(worker.run)
            worker.finished.connect(thread.quit)
            worker.finished.connect(thread.deleteLater)
            # Безопасная обработка ошибок - логируем, но не показываем QMessageBox из потока
            worker.error.connect(lambda e: logger.error(f"Sync operation error: {e}"))
            thread.finished.connect(thread.deleteLater)
            thread.start()
        except Exception as e:
            logger.error(f"Error starting sync operation: {e}", exc_info=True)


class LogsWidget(QWidget):
    """Экран просмотра логов"""

    def __init__(self, db, traffic_monitor):
        super().__init__()
        self.db = db
        self.traffic_monitor = traffic_monitor
        self.init_ui()
        # Отложенный запуск refresh через QTimer, чтобы Qt и БД были полностью инициализированы
        QTimer.singleShot(500, self._delayed_init)
    
    def _delayed_init(self):
        """Отложенная инициализация после полной загрузки Qt"""
        try:
            self.refresh()
        except Exception as e:
            logger.error(f"Error in delayed init: {e}", exc_info=True)

    def init_ui(self):
        layout = QVBoxLayout()

        # Таблица логов
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["Time", "Plugin", "Action", "Target", "Result"]
        )
        layout.addWidget(self.table)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        layout.addWidget(refresh_btn)

        self.setLayout(layout)

    def refresh(self):
        """Обновление логов"""
        def _refresh():
            try:
                logs = self.db.get_audit_log(limit=100)
                self.table.setRowCount(len(logs))
                for i, log in enumerate(logs):
                    self.table.setItem(i, 0, QTableWidgetItem(log.get("event_time", "")))
                    self.table.setItem(i, 1, QTableWidgetItem(log.get("plugin_id", "")))
                    self.table.setItem(i, 2, QTableWidgetItem(log.get("action", "")))
                    self.table.setItem(i, 3, QTableWidgetItem(log.get("target", "")))
                    self.table.setItem(i, 4, QTableWidgetItem(log.get("result", "")))
            except Exception as e:
                logger.error(f"Failed to load logs: {e}")

        self._run_sync(_refresh)

    def _run_sync(self, func, *args, **kwargs):
        """Запуск синхронной операции в потоке"""
        try:
            # Убеждаемся, что QApplication существует
            app = QApplication.instance()
            if app is None:
                logger.error("QApplication instance not found, cannot start sync operation")
                return
            
            worker = SyncWorker(func, *args, **kwargs)
            thread = QThread()
            worker.moveToThread(thread)
            thread.started.connect(worker.run)
            worker.finished.connect(thread.quit)
            worker.finished.connect(thread.deleteLater)
            # Безопасная обработка ошибок - логируем, но не показываем QMessageBox из потока
            worker.error.connect(lambda e: logger.error(f"Sync operation error: {e}"))
            thread.finished.connect(thread.deleteLater)
            thread.start()
        except Exception as e:
            logger.error(f"Error starting sync operation: {e}", exc_info=True)


class MainWindow(QMainWindow):
    """Главное окно приложения"""

    def __init__(self, flamix_app=None):
        super().__init__()
        try:
            # Получаем приложение напрямую (без IPC)
            if flamix_app is None:
                from flamix.app import get_app
                flamix_app = get_app()
            
            self.flamix_app = flamix_app
            self.plugin_manager = flamix_app.get_plugin_manager()
            self.db = flamix_app.get_db()
            self.traffic_monitor = flamix_app.get_traffic_monitor()
            
            logger.info("Initializing UI...")
            # Убеждаемся, что QApplication существует
            app = QApplication.instance()
            if app is None:
                raise RuntimeError("QApplication must be created before MainWindow")
            
            self.init_ui()
            logger.info("UI initialized successfully")
        except Exception as e:
            logger.critical(f"Critical error in MainWindow.__init__: {e}", exc_info=True)
            import traceback
            traceback.print_exc()
            # Создаем минимальное окно с ошибкой
            self.setWindowTitle("Flamix - Error")
            error_widget = QWidget()
            layout = QVBoxLayout()
            layout.addWidget(QLabel("Critical Error"))
            layout.addWidget(QLabel(str(e)))
            error_widget.setLayout(layout)
            self.setCentralWidget(error_widget)

    def init_ui(self):
        try:
            logger.info("Setting window title and geometry...")
            self.setWindowTitle("Flamix - Firewall Manager")
            self.setGeometry(100, 100, 1200, 800)

            logger.info("Creating tab widget...")
            # Центральный виджет с вкладками
            tabs = QTabWidget()
            
            # Dashboard
            try:
                logger.info("Creating Dashboard widget...")
                tabs.addTab(
                    DashboardWidget(
                        self.plugin_manager,
                        self.db,
                        self.traffic_monitor
                    ),
                    "Dashboard"
                )
                logger.info("Dashboard widget created")
            except Exception as e:
                logger.error(f"Failed to create Dashboard: {e}", exc_info=True)
                error_widget = QWidget()
                layout = QVBoxLayout()
                layout.addWidget(QLabel(f"Dashboard error: {e}"))
                error_widget.setLayout(layout)
                tabs.addTab(error_widget, "Dashboard")
            
            # Plugins
            try:
                logger.info("Creating Plugins widget...")
                tabs.addTab(
                    PluginsWidget(self.plugin_manager, self.db),
                    "Plugins"
                )
                logger.info("Plugins widget created")
            except Exception as e:
                logger.error(f"Failed to create PluginsWidget: {e}", exc_info=True)
                error_widget = QWidget()
                layout = QVBoxLayout()
                layout.addWidget(QLabel(f"Plugins error: {e}"))
                error_widget.setLayout(layout)
                tabs.addTab(error_widget, "Plugins")
            
            # Rules
            try:
                logger.info("Creating Rules widget...")
                tabs.addTab(
                    RulesWidget(self.plugin_manager, self.db),
                    "Rules"
                )
                logger.info("Rules widget created")
            except Exception as e:
                logger.error(f"Failed to create RulesWidget: {e}", exc_info=True)
                error_widget = QWidget()
                layout = QVBoxLayout()
                layout.addWidget(QLabel(f"Rules error: {e}"))
                error_widget.setLayout(layout)
                tabs.addTab(error_widget, "Rules")
            
            # Logs
            try:
                logger.info("Creating Logs widget...")
                tabs.addTab(
                    LogsWidget(self.db, self.traffic_monitor),
                    "Logs"
                )
                logger.info("Logs widget created")
            except Exception as e:
                logger.error(f"Failed to create LogsWidget: {e}", exc_info=True)
                error_widget = QWidget()
                layout = QVBoxLayout()
                layout.addWidget(QLabel(f"Logs error: {e}"))
                error_widget.setLayout(layout)
                tabs.addTab(error_widget, "Logs")
            
            # Traffic
            try:
                logger.info("Creating Traffic widget...")
                from flamix.gui.traffic_widget import TrafficWidget
                tabs.addTab(
                    TrafficWidget(self.traffic_monitor, self.db),
                    "Traffic"
                )
                logger.info("Traffic widget created")
            except Exception as e:
                logger.error(f"Failed to create TrafficWidget: {e}", exc_info=True)
                error_widget = QWidget()
                layout = QVBoxLayout()
                layout.addWidget(QLabel(f"Traffic monitoring unavailable:\n{e}"))
                error_widget.setLayout(layout)
                tabs.addTab(error_widget, "Traffic")

            logger.info("Setting central widget...")
            self.setCentralWidget(tabs)
            logger.info("Central widget set")
        except Exception as e:
            logger.critical(f"Critical error in init_ui: {e}", exc_info=True)
            # Создаем минимальное окно с ошибкой
            error_widget = QWidget()
            layout = QVBoxLayout()
            layout.addWidget(QLabel("Critical Error"))
            layout.addWidget(QLabel(str(e)))
            error_widget.setLayout(layout)
            self.setCentralWidget(error_widget)


def main():
    """Точка входа GUI (старая версия, используйте flamix.app.main)"""
    from flamix.app import main as app_main
    app_main()


if __name__ == "__main__":
    main()
