"""SQLite база данных для правил и аудита"""

import sqlite3
import threading
import os
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
        # Ensure path is converted to string and resolve any relative paths
        db_path_str = str(self.db_path.resolve())
        
        # Ensure parent directory exists and is writable
        parent_dir = self.db_path.parent
        if not parent_dir.exists():
            logger.info(f"[RulesDB._get_connection] Creating parent directory: {parent_dir}")
            parent_dir.mkdir(parents=True, exist_ok=True)
        
        if not os.access(str(parent_dir), os.W_OK):
            raise PermissionError(f"Cannot write to database directory: {parent_dir}. Please check directory permissions.")
        
        # Check if database file exists and ensure it's writable
        if self.db_path.exists():
            import stat
            try:
                # Always ensure file is writable on Windows (remove read-only attribute)
                if os.name == 'nt':  # Windows
                    try:
                        # Try using st_file_attributes if available (Python 3.8+)
                        file_stat = os.stat(db_path_str)
                        if hasattr(file_stat, 'st_file_attributes'):
                            if file_stat.st_file_attributes & 0x1:  # FILE_ATTRIBUTE_READONLY
                                logger.warning(f"[RulesDB._get_connection] Database file has read-only attribute, removing it: {db_path_str}")
                                # Remove read-only attribute using win32 API-style chmod
                                os.chmod(db_path_str, stat.S_IWRITE | stat.S_IREAD)
                        else:
                            # Fallback: use st_mode for older Python versions
                            current_mode = file_stat.st_mode
                            # Ensure write permission is set
                            os.chmod(db_path_str, current_mode | stat.S_IWRITE)
                    except Exception as e:
                        logger.warning(f"[RulesDB._get_connection] Could not check/fix Windows file attributes: {e}")
                else:  # Unix/Linux
                    # Check if file is writable
                    if not os.access(db_path_str, os.W_OK):
                        logger.warning(f"[RulesDB._get_connection] Database file is not writable, fixing permissions: {db_path_str}")
                        os.chmod(db_path_str, 0o666)
            except Exception as e:
                logger.warning(f"[RulesDB._get_connection] Error ensuring file is writable: {e}")
                # Don't fail here - let SQLite try to open and report its own error
        
        # Открываем соединение с явным указанием режима записи
        # Используем URI mode для более надежной работы с путями
        try:
            conn = sqlite3.connect(db_path_str, uri=False)
            conn.row_factory = sqlite3.Row
            # Проверяем, что база данных доступна для записи
            try:
                conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging для лучшей производительности
            except sqlite3.OperationalError:
                # Если WAL не поддерживается, продолжаем с обычным режимом
                pass
            return conn
        except sqlite3.OperationalError as e:
            if "readonly" in str(e).lower() or "read-only" in str(e).lower():
                error_msg = (
                    f"Cannot open database for writing: {db_path_str}\n"
                    f"Error: {e}\n"
                    f"Please check:\n"
                    f"1. File permissions (file should be writable)\n"
                    f"2. Directory permissions (directory should be writable)\n"
                    f"3. Disk space availability\n"
                    f"4. File is not locked by another process"
                )
                logger.error(f"[RulesDB._get_connection] {error_msg}")
                raise PermissionError(error_msg) from e
            raise

    def initialize(self):
        """Инициализация схемы БД"""
        logger.info("[RulesDB.initialize] Starting database initialization...")
        logger.info(f"[RulesDB.initialize] Database path: {self.db_path}")
        with self._lock:
            logger.info("[RulesDB.initialize] Lock acquired")
            logger.info("[RulesDB.initialize] Opening database connection...")
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

                logger.info("[RulesDB.initialize] Committing database changes...")
                db.commit()
                logger.info("[RulesDB.initialize] Database commit successful")
                logger.info(f"[RulesDB.initialize] Database initialized at {self.db_path}")
            
            logger.info("[RulesDB.initialize] Database connection closed (exiting inner with block)")
            logger.info("[RulesDB.initialize] Lock released (exiting with self._lock block)")
        
        # Очистка старых данных (старше 30 дней) - вызываем ВНЕ блока с блокировкой
        # чтобы избежать deadlock (так как _cleanup_old_data тоже использует self._lock)
        logger.info("[RulesDB.initialize] Calling _cleanup_old_data() (outside lock)...")
        try:
            self._cleanup_old_data()
            logger.info("[RulesDB.initialize] _cleanup_old_data() completed")
        except Exception as e:
            logger.warning(f"[RulesDB.initialize] Error in _cleanup_old_data(): {e}. Continuing initialization...")
            # Не прерываем инициализацию из-за ошибки cleanup - это не критично
        
        logger.info("[RulesDB.initialize] Setting _initialized = True...")
        self._initialized = True
        logger.info("[RulesDB.initialize] Database initialization completed successfully")

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
    
    def delete_rule(self, rule_id: int) -> bool:
        """Удаление правила по ID"""
        if not self._initialized:
            logger.warning("Database not initialized yet, skipping delete_rule")
            return False
        with self._lock:
            with self._get_connection() as db:
                cursor = db.execute(
                    "DELETE FROM rules WHERE id = ?",
                    (rule_id,)
                )
                db.commit()
                return cursor.rowcount > 0
    
    def delete_rules_by_ip(self, plugin_id: str, ip: str) -> int:
        """Удаление всех правил для указанного IP адреса"""
        if not self._initialized:
            logger.warning("Database not initialized yet, skipping delete_rules_by_ip")
            return 0
        deleted_count = 0
        with self._lock:
            with self._get_connection() as db:
                rules = db.execute(
                    "SELECT id, content FROM rules WHERE plugin_id = ?",
                    (plugin_id,)
                ).fetchall()
                
                for rule in rules:
                    try:
                        import json
                        content = json.loads(rule[1])
                        rule_ip = content.get("remote_ip") or content.get("ip")
                        if rule_ip == ip:
                            db.execute("DELETE FROM rules WHERE id = ?", (rule[0],))
                            deleted_count += 1
                    except Exception as e:
                        logger.warning(f"Ошибка при проверке правила {rule[0]}: {e}")
                
                db.commit()
        return deleted_count

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
        logger.info("[RulesDB._cleanup_old_data] Starting cleanup of old data...")
        cutoff_date = datetime.now() - timedelta(days=30)
        logger.info(f"[RulesDB._cleanup_old_data] Cutoff date: {cutoff_date}")
        
        try:
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
                    
                    logger.info("[RulesDB._cleanup_old_data] Committing cleanup changes...")
                    db.commit()
                    logger.info("[RulesDB._cleanup_old_data] Cleanup commit successful")
                    logger.info(f"[RulesDB._cleanup_old_data] Cleaned up data older than 30 days")
                logger.info("[RulesDB._cleanup_old_data] Database connection closed (exiting with block)")
        except sqlite3.OperationalError as e:
            if "readonly" in str(e).lower() or "read-only" in str(e).lower():
                # Database is read-only - log warning and skip cleanup (not critical)
                logger.warning(f"[RulesDB._cleanup_old_data] Database is read-only, skipping cleanup: {e}")
                logger.warning(f"[RulesDB._cleanup_old_data] This is not critical - application will continue normally")
                # Don't raise - cleanup is not critical for application operation
                return
            else:
                # Re-raise if it's a different operational error
                raise
        logger.info("[RulesDB._cleanup_old_data] Lock released (exiting with block)")
        logger.info("[RulesDB._cleanup_old_data] Cleanup completed successfully")
