"""SQLCipher обертка для шифрования базы данных"""

import sqlite3
import threading
import os
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
import keyring

logger = logging.getLogger(__name__)

# Переменная окружения для отключения шифрования в тестах
DISABLE_ENCRYPTION_ENV = 'FLAMIX_DISABLE_ENCRYPTION'

try:
    from pysqlcipher3 import dbapi2 as sqlcipher
    SQLCIPHER_AVAILABLE = True
except ImportError:
    logger.warning("pysqlcipher3 not available, falling back to sqlite3")
    import sqlite3 as sqlcipher
    SQLCIPHER_AVAILABLE = False


class EncryptedDB:
    """Зашифрованная база данных на основе SQLCipher"""

    SERVICE_NAME = "flamix"
    KEY_NAME = "db_encryption_key"

    def __init__(self, db_path: Path, key_rotation_hours: int = 24, use_encryption: Optional[bool] = None):
        """
        Инициализация зашифрованной БД

        Args:
            db_path: Путь к файлу БД
            key_rotation_hours: Часы до ротации ключа
            use_encryption: Использовать ли шифрование (None = автоопределение из env, False для тестов)
        """
        self.db_path = db_path
        self.key_rotation_hours = key_rotation_hours
        
        # Автоопределение из переменной окружения если не указано явно
        if use_encryption is None:
            use_encryption = os.getenv(DISABLE_ENCRYPTION_ENV, '').lower() not in ('1', 'true', 'yes')
        
        self.use_encryption = use_encryption
        self._lock = threading.Lock()
        self._initialized = False
        self._current_key_id: Optional[str] = None
        
        if not self.use_encryption:
            logger.info("Database encryption is DISABLED (for testing)")

    def _get_encryption_key(self) -> str:
        """
        Получение ключа шифрования из защищенного хранилища

        Returns:
            Ключ шифрования
        """
        key = keyring.get_password(self.SERVICE_NAME, self.KEY_NAME)
        if not key:
            # Генерируем новый ключ
            import secrets
            key = secrets.token_hex(32)  # 256 бит в hex
            keyring.set_password(self.SERVICE_NAME, self.KEY_NAME, key)
            logger.info("Generated new encryption key")
        return key

    def _get_connection(self, key: Optional[str] = None):
        """
        Получение соединения с зашифрованной БД

        Args:
            key: Ключ шифрования (если None, берется из хранилища)

        Returns:
            Соединение с БД
        """
        db_path_str = str(self.db_path.resolve())
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Если шифрование отключено (для тестов)
        if not self.use_encryption:
            logger.debug("Using unencrypted SQLite (encryption disabled for tests)")
            conn = sqlite3.connect(db_path_str)
        elif SQLCIPHER_AVAILABLE:
            if key is None:
                key = self._get_encryption_key()
            conn = sqlcipher.connect(db_path_str)
            conn.execute(f"PRAGMA key='{key}'")
            conn.execute("PRAGMA cipher_page_size=4096")
            conn.execute("PRAGMA kdf_iter=64000")
            conn.execute("PRAGMA cipher_hmac_algorithm=HMAC_SHA1")
            conn.execute("PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_SHA1")
        else:
            # Fallback к обычному SQLite (не рекомендуется для продакшена)
            logger.warning("Using unencrypted SQLite (SQLCipher not available)")
            conn = sqlite3.connect(db_path_str)

        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")

        return conn

    def initialize(self):
        """Инициализация схемы БД"""
        logger.info(f"Initializing encrypted database at {self.db_path}")

        with self._lock:
            with self._get_connection() as db:
                # Таблица клиентов
                db.execute("""
                    CREATE TABLE IF NOT EXISTS clients (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        hostname TEXT,
                        ip_address TEXT,
                        last_seen TEXT,
                        registered_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        enabled INTEGER DEFAULT 1,
                        metadata TEXT
                    )
                """)

                # Таблица правил клиентов
                db.execute("""
                    CREATE TABLE IF NOT EXISTS client_rules (
                        id TEXT PRIMARY KEY,
                        client_id TEXT NOT NULL,
                        rule_id TEXT NOT NULL,
                        rule_data TEXT NOT NULL,
                        version INTEGER DEFAULT 1,
                        checksum TEXT NOT NULL,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        enabled INTEGER DEFAULT 1,
                        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
                        UNIQUE(client_id, rule_id)
                    )
                """)

                # Таблица истории изменений правил
                db.execute("""
                    CREATE TABLE IF NOT EXISTS rule_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rule_id TEXT NOT NULL,
                        client_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        old_data TEXT,
                        new_data TEXT,
                        changed_by TEXT,
                        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
                    )
                """)

                # Таблица запросов на изменение правил
                db.execute("""
                    CREATE TABLE IF NOT EXISTS rule_change_requests (
                        id TEXT PRIMARY KEY,
                        client_id TEXT NOT NULL,
                        rule_id TEXT,
                        old_rule TEXT,
                        new_rule TEXT,
                        change_source TEXT NOT NULL,
                        status TEXT DEFAULT 'pending',
                        requested_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        reviewed_at TEXT,
                        reviewed_by TEXT,
                        reason TEXT,
                        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
                    )
                """)

                # Таблица аналитики
                db.execute("""
                    CREATE TABLE IF NOT EXISTS analytics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        client_id TEXT,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        target_ip TEXT,
                        target_domain TEXT,
                        target_port INTEGER,
                        protocol TEXT,
                        action TEXT,
                        details TEXT,
                        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL
                    )
                """)

                # Таблица сессий клиентов
                db.execute("""
                    CREATE TABLE IF NOT EXISTS client_sessions (
                        id TEXT PRIMARY KEY,
                        client_id TEXT NOT NULL,
                        session_key TEXT,
                        dh_public_key TEXT,
                        dh_params TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        expires_at TEXT,
                        last_activity TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
                    )
                """)

                # Таблица ключей шифрования
                db.execute("""
                    CREATE TABLE IF NOT EXISTS encryption_keys (
                        id TEXT PRIMARY KEY,
                        key_data TEXT NOT NULL,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        expires_at TEXT,
                        active INTEGER DEFAULT 1
                    )
                """)

                # Таблица контрольных сумм правил
                db.execute("""
                    CREATE TABLE IF NOT EXISTS rule_checksums (
                        client_id TEXT NOT NULL,
                        rule_id TEXT NOT NULL,
                        checksum TEXT NOT NULL,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (client_id, rule_id),
                        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
                    )
                """)

                # Индексы
                db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_client_rules_client 
                    ON client_rules(client_id)
                """)
                db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_rule_history_rule 
                    ON rule_history(rule_id)
                """)
                db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_analytics_timestamp 
                    ON analytics(timestamp)
                """)
                db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_sessions_client 
                    ON client_sessions(client_id)
                """)
                db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_change_requests_status 
                    ON rule_change_requests(status)
                """)

                db.commit()
                logger.info("Database schema initialized")

        self._initialized = True

    def execute(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """
        Выполнение запроса

        Args:
            query: SQL запрос
            params: Параметры запроса

        Returns:
            Список результатов
        """
        with self._lock:
            with self._get_connection() as db:
                cursor = db.execute(query, params)
                db.commit()
                rows = cursor.fetchall()
                return [dict(row) for row in rows]

    def execute_one(self, query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
        """
        Выполнение запроса с возвратом одного результата

        Args:
            query: SQL запрос
            params: Параметры запроса

        Returns:
            Один результат или None
        """
        results = self.execute(query, params)
        return results[0] if results else None

    def execute_write(self, query: str, params: tuple = ()) -> int:
        """
        Выполнение запроса на запись

        Args:
            query: SQL запрос
            params: Параметры запроса

        Returns:
            ID последней вставленной строки
        """
        with self._lock:
            with self._get_connection() as db:
                cursor = db.execute(query, params)
                db.commit()
                return cursor.lastrowid

    def close(self):
        """Закрытие соединений"""
        # SQLite автоматически закрывает соединения при выходе из контекста
        pass
