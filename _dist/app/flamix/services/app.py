"""Главное приложение Flamix (GUI + Agent в одном процессе)"""

import sys
import logging
import threading
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
            logger.info("[InitWorker] Starting initialization in background thread...")
            logger.info(f"[InitWorker] Thread ID: {threading.current_thread().ident}")
            logger.info(f"[InitWorker] Thread name: {threading.current_thread().name}")
            
            logger.info("[InitWorker] Calling flamix_app.initialize()...")
            self.flamix_app.initialize()
            logger.info("[InitWorker] flamix_app.initialize() completed successfully")
            
            logger.info("[InitWorker] Emitting finished signal...")
            self.finished.emit()
            logger.info("[InitWorker] Finished signal emitted")
        except Exception as e:
            logger.error(f"[InitWorker] Initialization error: {e}", exc_info=True)
            logger.error(f"[InitWorker] Error type: {type(e).__name__}")
            logger.error(f"[InitWorker] Emitting error signal...")
            self.error.emit(str(e))
            logger.error(f"[InitWorker] Error signal emitted")


class FlamixApp:
    """Главное приложение Flamix"""

    def __init__(self):
        logger.info("[FlamixApp] __init__ started")
        logger.info("[FlamixApp] Ensuring directories...")
        ensure_directories()
        logger.info("[FlamixApp] Directories ensured")

        logger.info("[FlamixApp] Creating PermissionManager...")
        # Инициализация компонентов
        self.permission_manager = PermissionManager()
        logger.info("[FlamixApp] PermissionManager created")
        
        logger.info("[FlamixApp] Creating PluginManager...")
        self.plugin_manager = PluginManager(self.permission_manager)
        logger.info("[FlamixApp] PluginManager created")
        
        logger.info("[FlamixApp] Creating RulesDB...")
        self.db = RulesDB()
        logger.info("[FlamixApp] RulesDB created")
        
        logger.info("[FlamixApp] Creating TrafficMonitor...")
        self.traffic_monitor = TrafficMonitor(self.db)
        logger.info("[FlamixApp] TrafficMonitor created")
        
        # GUI будет создан позже
        self.main_window = None
        logger.info("[FlamixApp] __init__ completed")

    def initialize(self):
        """Синхронная инициализация (вызывается из отдельного потока)"""
        logger.info("[FlamixApp.initialize] Starting initialization...")
        logger.info(f"[FlamixApp.initialize] Thread ID: {threading.current_thread().ident}")
        logger.info(f"[FlamixApp.initialize] Thread name: {threading.current_thread().name}")
        
        # Инициализация БД (может быть долгой операцией)
        logger.info("[FlamixApp.initialize] Calling self.db.initialize()...")
        try:
            self.db.initialize()
            logger.info("[FlamixApp.initialize] Database initialized successfully")
        except Exception as e:
            logger.error(f"[FlamixApp.initialize] Database initialization failed: {e}", exc_info=True)
            raise
        
        # Запуск мониторинга трафика (в отдельном потоке)
        logger.info("[FlamixApp.initialize] Starting traffic monitor...")
        try:
            self.traffic_monitor.start()
            logger.info("[FlamixApp.initialize] Traffic monitor started successfully")
        except Exception as e:
            logger.warning(f"[FlamixApp.initialize] Failed to start traffic monitor: {e}", exc_info=True)
            # Продолжаем работу даже если мониторинг не запустился
        
        logger.info("[FlamixApp.initialize] Initialization completed successfully")

    def shutdown(self):
        """Остановка приложения"""
        try:
            # Ожидаем завершения потока инициализации, если он еще работает
            if hasattr(self, '_init_thread') and self._init_thread:
                if self._init_thread.isRunning():
                    logger.info("Waiting for initialization thread to finish...")
                    self._init_thread.quit()
                    if not self._init_thread.wait(5000):  # Ждем до 5 секунд
                        logger.warning("Initialization thread did not finish in time")
                # Очищаем ссылки
                self._init_thread = None
                self._init_worker = None
        except Exception as e:
            logger.error(f"Error stopping init thread: {e}")
        
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
    logger.info("=" * 60)
    logger.info("[main] Application entry point - START")
    logger.info(f"[main] Main thread ID: {threading.current_thread().ident}")
    logger.info(f"[main] Main thread name: {threading.current_thread().name}")
    logger.info("=" * 60)
    
    try:
        logger.info("[main] Creating QApplication...")
        app = QApplication(sys.argv)
        logger.info("[main] QApplication created successfully")
        
        logger.info("[main] Getting FlamixApp instance...")
        # Создание приложения
        flamix_app = get_app()
        logger.info("[main] FlamixApp instance obtained")
        
        # Создаем GUI сразу, не ждем инициализации
        # Инициализация будет продолжаться в фоне
        try:
            logger.info("[main] ===== Creating main window =====...")
            
            # Создаем окно в отдельном потоке не нужно - это должно быть в главном потоке Qt
            # Но убеждаемся, что все тяжелые операции отложены
            logger.info("[main] Calling MainWindow(flamix_app)...")
            main_window = MainWindow(flamix_app)
            logger.info("[main] MainWindow constructor completed")
            
            flamix_app.main_window = main_window
            logger.info("[main] Main window reference stored in flamix_app")
            
            logger.info("[main] Calling main_window.show()...")
            main_window.show()
            logger.info("[main] main_window.show() completed - window should be visible now")
            
            logger.info("[main] ===== Setting up initialization thread =====...")
            
            # Инициализация в отдельном потоке, чтобы не блокировать GUI
            logger.info("[main] Creating InitWorker...")
            init_worker = InitWorker(flamix_app)
            logger.info("[main] InitWorker created")
            
            logger.info("[main] Creating QThread for initialization...")
            init_thread = QThread()
            logger.info("[main] QThread created")
            
            logger.info("[main] Moving InitWorker to QThread...")
            init_worker.moveToThread(init_thread)
            logger.info("[main] InitWorker moved to QThread")
            
            # Сохраняем ссылку на поток для корректного завершения
            flamix_app._init_thread = init_thread
            flamix_app._init_worker = init_worker
            logger.info("[main] Thread references stored in flamix_app")
            
            # Обработка завершения инициализации в фоне
            def on_init_complete():
                logger.info("[main] ===== Background initialization completed successfully =====...")
                logger.info("[main] Calling init_thread.quit()...")
                init_thread.quit()
                logger.info("[main] init_thread.quit() called")
            
            def on_init_failed(error_msg):
                logger.error(f"[main] ===== Background initialization failed: {error_msg} =====...")
                # Показываем ошибку через QTimer, чтобы быть в главном потоке
                logger.info("[main] Scheduling error message display via QTimer...")
                QTimer.singleShot(0, lambda: QMessageBox.warning(
                    main_window,
                    "Initialization Warning",
                    f"Some components failed to initialize:\n{error_msg}\n\nApplication may work with limited functionality."
                ))
                logger.info("[main] Calling init_thread.quit() after error...")
                init_thread.quit()
                logger.info("[main] init_thread.quit() called after error")
            
            logger.info("[main] Connecting signals...")
            init_worker.finished.connect(on_init_complete)
            init_worker.error.connect(on_init_failed)
            logger.info("[main] Signals connected")
            
            # Очистка при завершении потока (отложенная, чтобы избежать предупреждений)
            def cleanup_thread():
                logger.info("[main] cleanup_thread called")
                if init_thread.isFinished():
                    logger.info("[main] Thread is finished, calling deleteLater()...")
                    init_thread.deleteLater()
                    logger.info("[main] deleteLater() called")
                else:
                    logger.warning("[main] Thread is not finished yet, skipping deleteLater()")
            
            init_thread.finished.connect(cleanup_thread)
            
            # Подключаем запуск после старта потока
            logger.info("[main] Connecting thread.started to worker.run...")
            init_thread.started.connect(init_worker.run)
            logger.info("[main] thread.started signal connected")
            
            # Запускаем инициализацию в фоне ПОСЛЕ создания GUI
            logger.info("[main] ===== Starting initialization thread =====...")
            init_thread.start()
            logger.info(f"[main] init_thread.start() called, thread running: {init_thread.isRunning()}")
            
            # Не используем deleteLater сразу - поток должен завершиться естественным образом
            logger.info("[main] ===== Main window and initialization setup completed =====...")
            
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
            import traceback
            logger.info("[main] ===== Application is quitting =====...")
            logger.info("[main] aboutToQuit signal received!")
            logger.info("[main] Checking why application is quitting...")
            logger.info(f"[main] Main window visible: {main_window.isVisible() if main_window else 'N/A'}")
            logger.info(f"[main] Main window exists: {main_window is not None}")
            
            # Логируем стек вызовов
            logger.info("[main] aboutToQuit call stack:")
            for line in traceback.format_stack():
                logger.info(f"[main]   {line.strip()}")
            
            try:
                logger.info("[main] Calling flamix_app.shutdown()...")
                flamix_app.shutdown()
                logger.info("[main] flamix_app.shutdown() completed")
            except Exception as e:
                logger.error(f"[main] Error during shutdown: {e}", exc_info=True)
            logger.info("[main] ===== on_quit handler completed =====...")
        
        logger.info("[main] Connecting app.aboutToQuit signal...")
        app.aboutToQuit.connect(on_quit)
        logger.info("[main] aboutToQuit signal connected")
        
        # Убеждаемся, что приложение НЕ закроется автоматически при закрытии последнего окна
        # Пользователь может закрыть приложение вручную
        logger.info("[main] Setting quitOnLastWindowClosed to False...")
        app.setQuitOnLastWindowClosed(False)  # Не закрывать приложение автоматически
        logger.info("[main] quitOnLastWindowClosed set to False")
        
        logger.info("[main] ===== Starting Qt event loop (app.exec()) =====...")
        logger.info("[main] Application will now process events...")
        logger.info("[main] Main window should be visible and application should be running...")
        
        # Проверяем, что окно действительно открыто
        logger.info("[main] Checking main window state...")
        logger.info(f"[main] Main window visible: {main_window.isVisible()}")
        logger.info(f"[main] Main window isActiveWindow: {main_window.isActiveWindow()}")
        logger.info(f"[main] Main window isEnabled: {main_window.isEnabled()}")
        
        if main_window.isVisible():
            logger.info("[main] Main window is visible - good!")
        else:
            logger.warning("[main] Main window is not visible - forcing show()...")
            main_window.show()
            logger.info(f"[main] After show(), window visible: {main_window.isVisible()}")
        
        # Принудительно активируем окно
        logger.info("[main] Activating main window...")
        main_window.activateWindow()
        main_window.raise_()
        logger.info("[main] Main window activated")
        
        # Не вызываем app.processEvents() здесь - это может вызывать проблемы
        # app.exec() сам начнет обработку событий
        logger.info("[main] Skipping explicit processEvents() before exec()")
        logger.info(f"[main] Window visible before exec(): {main_window.isVisible()}")
        
        logger.info("[main] About to call app.exec()...")
        logger.info(f"[main] QApplication instance: {app}")
        logger.info(f"[main] Main window exists: {main_window is not None}")
        logger.info(f"[main] Main window visible: {main_window.isVisible() if main_window else False}")
        logger.info("[main] Entering app.exec() - this will block until application closes...")
        logger.info("[main] If you see this, application is starting event loop...")
        
        # Флушим логи перед блокирующим вызовом
        sys.stdout.flush()
        sys.stderr.flush()
        logger.info("[main] Flushed stdout/stderr, now calling app.exec()...")
        
        try:
            logger.info("[main] CALLING app.exec() NOW...")
            exit_code = app.exec()
            logger.info(f"[main] app.exec() RETURNED with exit code: {exit_code}")
            logger.info(f"[main] app.exec() returned with exit code: {exit_code}")
        except Exception as e:
            logger.error(f"[main] Exception in app.exec(): {e}", exc_info=True)
            exit_code = 1
        logger.info(f"[main] ===== Qt event loop finished, exit code: {exit_code} =====...")
        logger.info("=" * 60)
        logger.info("[main] Application entry point - END")
        logger.info("=" * 60)
        
        return exit_code
        
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
