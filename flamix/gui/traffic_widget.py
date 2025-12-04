"""Виджет для отображения мониторинга трафика"""

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QComboBox,
    QDateEdit,
)
from PySide6.QtCore import Qt, QDate
from datetime import datetime, timedelta
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class TrafficWidget(QWidget):
    """Виджет для отображения статистики трафика и соединений"""

    def __init__(self, traffic_monitor, db):
        super().__init__()
        self.traffic_monitor = traffic_monitor
        self.db = db
        try:
            self.init_ui()
            # Отложенный запуск refresh через QTimer, чтобы Qt и БД были полностью инициализированы
            from PySide6.QtCore import QTimer
            QTimer.singleShot(500, self._delayed_init)
        except Exception as e:
            logger.error(f"Error initializing TrafficWidget: {e}", exc_info=True)
            layout = QVBoxLayout()
            layout.addWidget(QLabel(f"Error: {e}"))
            self.setLayout(layout)
    
    def _delayed_init(self):
        """Отложенная инициализация после полной загрузки Qt"""
        try:
            self.refresh()
        except Exception as e:
            logger.error(f"Error in delayed init: {e}", exc_info=True)

    def init_ui(self):
        layout = QVBoxLayout()

        # Фильтры
        filter_layout = QHBoxLayout()
        
        filter_layout.addWidget(QLabel("From:"))
        self.start_date = QDateEdit()
        self.start_date.setDate(QDate.currentDate().addDays(-7))
        self.start_date.setCalendarPopup(True)
        filter_layout.addWidget(self.start_date)
        
        filter_layout.addWidget(QLabel("To:"))
        self.end_date = QDateEdit()
        self.end_date.setDate(QDate.currentDate())
        self.end_date.setCalendarPopup(True)
        filter_layout.addWidget(self.end_date)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        filter_layout.addWidget(refresh_btn)
        
        filter_layout.addStretch()
        layout.addLayout(filter_layout)

        # Таблица соединений
        connections_label = QLabel("Network Connections")
        connections_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        layout.addWidget(connections_label)

        self.connections_table = QTableWidget()
        self.connections_table.setColumnCount(7)
        self.connections_table.setHorizontalHeaderLabels(
            ["Time", "Process", "PID", "Remote Address", "Port", "Domain", "Protocol"]
        )
        layout.addWidget(self.connections_table)

        # Таблица статистики трафика
        stats_label = QLabel("Traffic Statistics")
        stats_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        layout.addWidget(stats_label)

        self.stats_table = QTableWidget()
        self.stats_table.setColumnCount(6)
        self.stats_table.setHorizontalHeaderLabels(
            ["Time", "Interface", "Sent Speed", "Recv Speed", "Total Sent", "Total Recv"]
        )
        layout.addWidget(self.stats_table)

        self.setLayout(layout)

    def refresh(self):
        """Обновление данных"""
        def _refresh():
            try:
                # Ожидание готовности traffic_monitor (синхронно)
                if not self.traffic_monitor.is_ready():
                    import time
                    for _ in range(300):  # 30 секунд максимум
                        if self.traffic_monitor.is_ready():
                            break
                        time.sleep(0.1)
                
                # Получение дат
                start_date = self.start_date.date().toPython()
                end_date = self.end_date.date().toPython()
                start_time = datetime.combine(start_date, datetime.min.time())
                end_time = datetime.combine(end_date, datetime.max.time())

                # Загрузка соединений
                connections = self.traffic_monitor.get_connections(
                    start_time, end_time
                )
                self.connections_table.setRowCount(len(connections))
                for i, conn in enumerate(connections):
                    self.connections_table.setItem(
                        i, 0, QTableWidgetItem(conn.get("timestamp", "")[:19])
                    )
                    self.connections_table.setItem(
                        i, 1, QTableWidgetItem(conn.get("process_name", "unknown"))
                    )
                    self.connections_table.setItem(
                        i, 2, QTableWidgetItem(str(conn.get("process_pid", 0)))
                    )
                    self.connections_table.setItem(
                        i, 3, QTableWidgetItem(conn.get("remote_addr", ""))
                    )
                    self.connections_table.setItem(
                        i, 4, QTableWidgetItem(str(conn.get("remote_port", "")))
                    )
                    self.connections_table.setItem(
                        i, 5, QTableWidgetItem(conn.get("domain", "") or "-")
                    )
                    self.connections_table.setItem(
                        i, 6, QTableWidgetItem(conn.get("protocol", ""))
                    )

                # Загрузка статистики
                stats = self.traffic_monitor.get_traffic_stats(
                    start_time, end_time
                )
                self.stats_table.setRowCount(len(stats))
                for i, stat in enumerate(stats):
                    self.stats_table.setItem(
                        i, 0, QTableWidgetItem(stat.get("timestamp", "")[:19])
                    )
                    self.stats_table.setItem(
                        i, 1, QTableWidgetItem(stat.get("interface", ""))
                    )
                    sent_speed = stat.get("sent_speed", 0) / 1024  # KB/s
                    recv_speed = stat.get("recv_speed", 0) / 1024  # KB/s
                    self.stats_table.setItem(
                        i, 2, QTableWidgetItem(f"{sent_speed:.2f} KB/s")
                    )
                    self.stats_table.setItem(
                        i, 3, QTableWidgetItem(f"{recv_speed:.2f} KB/s")
                    )
                    bytes_sent = stat.get("bytes_sent", 0) / (1024 * 1024)  # MB
                    bytes_recv = stat.get("bytes_recv", 0) / (1024 * 1024)  # MB
                    self.stats_table.setItem(
                        i, 4, QTableWidgetItem(f"{bytes_sent:.2f} MB")
                    )
                    self.stats_table.setItem(
                        i, 5, QTableWidgetItem(f"{bytes_recv:.2f} MB")
                    )
            except Exception as e:
                logger.error(f"Failed to refresh traffic data: {e}")

        self._run_sync(_refresh)

    def _run_sync(self, func, *args, **kwargs):
        """Запуск синхронной операции в потоке"""
        try:
            from flamix.gui.main import SyncWorker
            from PySide6.QtCore import QThread
            from PySide6.QtWidgets import QApplication
            
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
            worker.error.connect(lambda e: logger.error(f"Error: {e}"))
            thread.finished.connect(thread.deleteLater)
            thread.start()
        except Exception as e:
            logger.error(f"Error starting sync operation: {e}", exc_info=True)

