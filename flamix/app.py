"""Главное приложение Flamix (GUI + Agent в одном процессе)"""

import sys
import logging
from pathlib import Path

from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtCore import QTimer, QThread, QObject, Signal

from flamix.config import ensure_directories
from flamix.security import PermissionManager
from flamix.plugins.manager import PluginManager
from flamix.database.rules_db import RulesDB
from flamix.services.traffic_monitor import TrafficMonitor
from flamix.gui.main import MainWindow

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


class InitWorker(QObject):
    """Рабочий поток для инициализации приложения"""
    finished = Signal()
    error = Signal(str)
    
    def __init__(self, flamix_app):
        super().__init__()
        self.flamix_app = flamix_app
    
    def run(self):
        """Запуск инициализации в отдельном потоке"""
        try:
            logger.info("Starting initialization in background thread...")
            self.flamix_app.initialize()
            logger.info("Initialization completed")
            self.finished.emit()
        except Exception as e:
            logger.error(f"Initialization error: {e}", exc_info=True)
            self.error.emit(str(e))


class FlamixApp:
    """Главное приложение Flamix"""

    def __init__(self):
        ensure_directories()

        # Инициализация компонентов
        self.permission_manager = PermissionManager()
        self.plugin_manager = PluginManager(self.permission_manager)
        self.db = RulesDB()
        self.traffic_monitor = TrafficMonitor(self.db)
        
        # GUI будет создан позже
        self.main_window = None

    def initialize(self):
        """Синхронная инициализация (вызывается из отдельного потока)"""
        # Инициализация БД (может быть долгой операцией)
        logger.info("Initializing database...")
        self.db.initialize()
        logger.info("Database initialized")
        
        # Запуск мониторинга трафика (в отдельном потоке)
        try:
            logger.info("Starting traffic monitor...")
            self.traffic_monitor.start()
            logger.info("Traffic monitor started")
        except Exception as e:
            logger.warning(f"Failed to start traffic monitor: {e}")
            # Продолжаем работу даже если мониторинг не запустился
        
        logger.info("Flamix application initialized")

    def shutdown(self):
        """Остановка приложения"""
        try:
            self.traffic_monitor.stop()
        except Exception as e:
            logger.error(f"Error stopping traffic monitor: {e}")
        logger.info("Flamix application shutdown")

    def get_plugin_manager(self):
        """Получение менеджера плагинов"""
        return self.plugin_manager

    def get_db(self):
        """Получение БД"""
        return self.db

    def get_traffic_monitor(self):
        """Получение мониторинга трафика"""
        return self.traffic_monitor


# Глобальный экземпляр приложения
_app_instance: FlamixApp = None


def get_app() -> FlamixApp:
    """Получение глобального экземпляра приложения"""
    global _app_instance
    if _app_instance is None:
        _app_instance = FlamixApp()
    return _app_instance


def main():
    """Точка входа приложения"""
    try:
        app = QApplication(sys.argv)
        
        # Создание приложения
        flamix_app = get_app()
        
        # Создаем GUI сразу, не ждем инициализации
        # Инициализация будет продолжаться в фоне
        try:
            logger.info("Creating main window...")
            
            # Создаем окно в отдельном потоке не нужно - это должно быть в главном потоке Qt
            # Но убеждаемся, что все тяжелые операции отложены
            main_window = MainWindow(flamix_app)
            flamix_app.main_window = main_window
            logger.info("Main window created, showing...")
            main_window.show()
            logger.info("Main window shown")
            
            # Инициализация в отдельном потоке, чтобы не блокировать GUI
            init_worker = InitWorker(flamix_app)
            init_thread = QThread()
            init_worker.moveToThread(init_thread)
            init_thread.started.connect(init_worker.run)
            init_thread.finished.connect(init_thread.deleteLater)
            
            # Обработка завершения инициализации в фоне
            def on_init_complete():
                logger.info("Background initialization completed successfully")
            
            def on_init_failed(error_msg):
                logger.error(f"Background initialization failed: {error_msg}")
                # Показываем ошибку через QTimer, чтобы быть в главном потоке
                QTimer.singleShot(0, lambda: QMessageBox.warning(
                    main_window,
                    "Initialization Warning",
                    f"Some components failed to initialize:\n{error_msg}\n\nApplication may work with limited functionality."
                ))
            
            init_worker.finished.connect(on_init_complete)
            init_worker.error.connect(on_init_failed)
            
            # Запускаем инициализацию в фоне ПОСЛЕ создания GUI
            logger.info("Starting initialization thread...")
            init_thread.start()
            
        except Exception as e:
            logger.error(f"Failed to create main window: {e}", exc_info=True)
            import traceback
            traceback.print_exc()
            try:
                QMessageBox.critical(
                    None,
                    "Window Error",
                    f"Failed to create main window:\n{e}\n\nSee console for details."
                )
            except:
                pass
            return 1
        
        # Обработка закрытия приложения
        def on_quit():
            try:
                flamix_app.shutdown()
            except Exception as e:
                logger.error(f"Error during shutdown: {e}")
        
        app.aboutToQuit.connect(on_quit)
        
        return app.exec()
        
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        try:
            QMessageBox.critical(
                None,
                "Fatal Error",
                f"Fatal error occurred:\n{e}\n\nCheck logs for details."
            )
        except:
            pass
        return 1


if __name__ == "__main__":
    main()
