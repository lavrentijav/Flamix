"""Мониторинг сетевого трафика"""

import threading
import time
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class TrafficMonitor:
    """Мониторинг сетевого трафика и соединений"""

    def __init__(self, db):
        self.db = db
        self.running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self.last_stats = {}
        self._initialized = False
        self._thread_lock = threading.Lock()

    def start(self):
        """Запуск мониторинга"""
        logger.info("[TrafficMonitor.start] Starting traffic monitor...")
        logger.info(f"[TrafficMonitor.start] Thread ID: {threading.current_thread().ident}")
        
        with self._thread_lock:
            logger.info("[TrafficMonitor.start] Lock acquired")
            if self.running:
                logger.warning("[TrafficMonitor.start] Monitor already running, returning")
                return
            
            logger.info("[TrafficMonitor.start] Setting running = True, _initialized = False...")
            self.running = True
            self._initialized = False
            
            logger.info("[TrafficMonitor.start] Creating monitor thread...")
            self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            logger.info("[TrafficMonitor.start] Monitor thread created")
            
            logger.info("[TrafficMonitor.start] Starting monitor thread...")
            self._monitor_thread.start()
            logger.info(f"[TrafficMonitor.start] Monitor thread started, thread ID: {self._monitor_thread.ident}")
            
            # Ждем инициализации
            logger.info("[TrafficMonitor.start] Waiting for monitor initialization...")
            start_time = time.time()
            wait_count = 0
            while not self._initialized:
                wait_count += 1
                if time.time() - start_time > 10.0:
                    logger.warning("[TrafficMonitor.start] Monitor did not initialize in time (10s timeout)")
                    break
                if wait_count % 10 == 0:  # Логируем каждую секунду
                    logger.info(f"[TrafficMonitor.start] Still waiting for initialization... ({wait_count * 0.1:.1f}s)")
                time.sleep(0.1)
            
            logger.info("[TrafficMonitor.start] Lock released")
            logger.info("[TrafficMonitor.start] Traffic monitor started successfully")

    def stop(self):
        """Остановка мониторинга"""
        with self._thread_lock:
            self.running = False
            self._initialized = False
            if self._monitor_thread and self._monitor_thread.is_alive():
                self._monitor_thread.join(timeout=5)
                if self._monitor_thread.is_alive():
                    logger.warning("Traffic monitor thread did not terminate gracefully.")
            logger.info("Traffic monitor stopped")

    def is_ready(self) -> bool:
        """Проверка готовности монитора"""
        with self._thread_lock:
            return self._initialized and self.running

    def _monitor_loop(self):
        """Основной цикл мониторинга"""
        logger.info("[TrafficMonitor._monitor_loop] Monitor loop started")
        logger.info(f"[TrafficMonitor._monitor_loop] Thread ID: {threading.current_thread().ident}")
        logger.info("[TrafficMonitor._monitor_loop] Setting _initialized = True...")
        self._initialized = True
        logger.info("[TrafficMonitor._monitor_loop] _initialized set to True")
        
        logger.info("[TrafficMonitor._monitor_loop] Entering main loop...")
        while self.running:
            try:
                # Здесь можно добавить логику мониторинга
                time.sleep(5)
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}", exc_info=True)
                time.sleep(5)
        
        logger.info("Traffic monitor background loop stopped.")

    def get_traffic_stats(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        interface: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Получение статистики трафика"""
        return self.db.get_traffic_stats(start_time, end_time, interface) if self.db else []

    def get_connections(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        process_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Получение списка соединений"""
        return self.db.get_connections(start_time, end_time, process_name) if self.db else []
