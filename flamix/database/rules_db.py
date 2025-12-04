"""SQLite база данных для правил и аудита"""

import sqlite3
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import logging

from flamix.config import DB_PATH

logger = logging.getLogger(__name__)


class RulesDB:
    """База данных правил и аудита"""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._initialized = False

    def _get_connection(self):
        """Получение соединения с БД (thread-safe)"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self):
        """Инициализация схемы БД"""
        with self._lock:
            with self._get_connection() as db:
                # Таблица плагинов
                db.execute("""
                    CREATE TABLE IF NOT EXISTS plugins (
                        id TEXT PRIMARY KEY,
                        enabled INTEGER DEFAULT 0,
                        permissions TEXT,
                        installed_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # Таблица правил
                db.execute("""
                    CREATE TABLE IF NOT EXISTS rules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        plugin_id TEXT NOT NULL,
                        content TEXT NOT NULL,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (plugin_id) REFERENCES plugins(id)
                    )
                """)

                # Таблица аудита
                db.execute("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_time TEXT DEFAULT CURRENT_TIMESTAMP,
                        plugin_id TEXT,
                        action TEXT NOT NULL,
                        target TEXT,
                        result TEXT,
                        details TEXT
                    )
                """)

                # Таблица статистики трафика
                db.execute("""
                    CREATE TABLE IF NOT EXISTS traffic_stats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        interface TEXT NOT NULL,
                        bytes_sent INTEGER DEFAULT 0,
                        bytes_recv INTEGER DEFAULT 0,
                        sent_speed REAL DEFAULT 0,
                        recv_speed REAL DEFAULT 0,
                        packets_sent INTEGER DEFAULT 0,
                        packets_recv INTEGER DEFAULT 0
                    )
                """)

                # Таблица сетевых соединений
                db.execute("""
                    CREATE TABLE IF NOT EXISTS network_connections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        process_name TEXT,
                        process_pid INTEGER,
                        local_addr TEXT,
                        local_port INTEGER,
                        remote_addr TEXT NOT NULL,
                        remote_port INTEGER,
                        domain TEXT,
                        protocol TEXT
                    )
                """)

                # Индексы для быстрого поиска
                db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_traffic_timestamp 
                    ON traffic_stats(timestamp)
                """)
                
                db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_connections_timestamp 
                    ON network_connections(timestamp)
                """)
                
                db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_connections_process 
                    ON network_connections(process_name)
                """)

                db.commit()
                logger.info(f"Database initialized at {self.db_path}")
            
            # Очистка старых данных (старше 30 дней)
            self._cleanup_old_data()
            
            self._initialized = True

    def add_plugin(self, plugin_id: str, permissions: List[str]):
        """Добавление плагина в БД"""
        if not self._initialized:
            logger.warning("Database not initialized yet, skipping add_plugin")
            return
        with self._lock:
            with self._get_connection() as db:
                db.execute(
                    "INSERT OR REPLACE INTO plugins (id, permissions) VALUES (?, ?)",
                    (plugin_id, ",".join(permissions))
                )
                db.commit()

    def add_rule(self, plugin_id: str, content: str) -> int:
        """Добавление правила"""
        with self._lock:
            with self._get_connection() as db:
                cursor = db.execute(
                    "INSERT INTO rules (plugin_id, content) VALUES (?, ?)",
                    (plugin_id, content)
                )
                db.commit()
                return cursor.lastrowid

    def log_audit(
        self,
        plugin_id: Optional[str],
        action: str,
        target: Optional[str],
        result: str,
        details: Optional[Dict[str, Any]] = None
    ):
        """Логирование аудита"""
        import json
        with self._lock:
            with self._get_connection() as db:
                db.execute(
                    """INSERT INTO audit_log 
                       (plugin_id, action, target, result, details) 
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        plugin_id,
                        action,
                        target,
                        result,
                        json.dumps(details) if details else None
                    )
                )
                db.commit()

    def get_rules(
        self,
        plugin_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Получение правил"""
        if not self._initialized:
            logger.warning("Database not initialized yet, returning empty list")
            return []
        with self._lock:
            with self._get_connection() as db:
                if plugin_id:
                    cursor = db.execute(
                        "SELECT * FROM rules WHERE plugin_id = ? ORDER BY created_at DESC LIMIT ?",
                        (plugin_id, limit)
                    )
                else:
                    cursor = db.execute(
                        "SELECT * FROM rules ORDER BY created_at DESC LIMIT ?",
                        (limit,)
                    )
                rows = cursor.fetchall()
                return [dict(row) for row in rows]

    def get_audit_log(
        self,
        plugin_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Получение логов аудита"""
        if not self._initialized:
            logger.warning("Database not initialized yet, returning empty list")
            return []
        with self._lock:
            with self._get_connection() as db:
                if plugin_id:
                    cursor = db.execute(
                        """SELECT * FROM audit_log 
                           WHERE plugin_id = ? 
                           ORDER BY event_time DESC LIMIT ?""",
                        (plugin_id, limit)
                    )
                else:
                    cursor = db.execute(
                        "SELECT * FROM audit_log ORDER BY event_time DESC LIMIT ?",
                        (limit,)
                    )
                rows = cursor.fetchall()
                return [dict(row) for row in rows]

    def save_traffic_stats(
        self,
        timestamp: datetime,
        interface: str,
        bytes_sent: int,
        bytes_recv: int,
        sent_speed: float,
        recv_speed: float,
        packets_sent: int,
        packets_recv: int
    ):
        """Сохранение статистики трафика"""
        with self._lock:
            with self._get_connection() as db:
                db.execute(
                    """INSERT INTO traffic_stats 
                       (timestamp, interface, bytes_sent, bytes_recv, 
                        sent_speed, recv_speed, packets_sent, packets_recv) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        timestamp.isoformat(),
                        interface,
                        bytes_sent,
                        bytes_recv,
                        sent_speed,
                        recv_speed,
                        packets_sent,
                        packets_recv
                    )
                )
                db.commit()

    def save_connection(
        self,
        timestamp: datetime,
        process_name: str,
        process_pid: int,
        local_addr: Optional[str],
        local_port: Optional[int],
        remote_addr: str,
        remote_port: Optional[int],
        domain: Optional[str],
        protocol: str
    ):
        """Сохранение информации о соединении"""
        with self._lock:
            with self._get_connection() as db:
                db.execute(
                    """INSERT INTO network_connections 
                       (timestamp, process_name, process_pid, local_addr, local_port,
                        remote_addr, remote_port, domain, protocol) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        timestamp.isoformat(),
                        process_name,
                        process_pid,
                        local_addr,
                        local_port,
                        remote_addr,
                        remote_port,
                        domain,
                        protocol
                    )
                )
                db.commit()

    def get_traffic_stats(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        interface: Optional[str] = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Получение статистики трафика"""
        with self._lock:
            with self._get_connection() as db:
                query = "SELECT * FROM traffic_stats WHERE 1=1"
                params = []
                
                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time.isoformat())
                
                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time.isoformat())
                
                if interface:
                    query += " AND interface = ?"
                    params.append(interface)
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                cursor = db.execute(query, params)
                rows = cursor.fetchall()
                return [dict(row) for row in rows]

    def get_connections(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        process_name: Optional[str] = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Получение соединений"""
        with self._lock:
            with self._get_connection() as db:
                query = "SELECT * FROM network_connections WHERE 1=1"
                params = []
                
                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time.isoformat())
                
                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time.isoformat())
                
                if process_name:
                    query += " AND process_name = ?"
                    params.append(process_name)
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                cursor = db.execute(query, params)
                rows = cursor.fetchall()
                return [dict(row) for row in rows]

    def _cleanup_old_data(self):
        """Очистка данных старше 30 дней"""
        cutoff_date = datetime.now() - timedelta(days=30)
        
        with self._lock:
            with self._get_connection() as db:
                # Удаление старых записей статистики трафика
                db.execute(
                    "DELETE FROM traffic_stats WHERE timestamp < ?",
                    (cutoff_date.isoformat(),)
                )
                
                # Удаление старых записей соединений
                db.execute(
                    "DELETE FROM network_connections WHERE timestamp < ?",
                    (cutoff_date.isoformat(),)
                )
                
                db.commit()
                logger.info(f"Cleaned up data older than 30 days")
