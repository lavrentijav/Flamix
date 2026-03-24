"""База данных с опциональным шифрованием"""

import sqlite3
import threading
import os
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
import keyring
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

# Переменная окружения для отключения шифрования в тестах
DISABLE_ENCRYPTION_ENV = 'FLAMIX_DISABLE_ENCRYPTION'

# Используем обычный sqlite3 (SQLCipher больше не требуется)
sqlcipher = sqlite3
SQLCIPHER_AVAILABLE = False  # Отключено, используем шифрование на уровне приложения


class EncryptedDB:
    """База данных с опциональным шифрованием на уровне приложения"""

    SERVICE_NAME = "flamix"
    KEY_NAME = "db_encryption_key"
    SECRET_PROTECTION_KEY_NAME = "db_secret_protection_key"
    SECRET_PREFIX = "enc:v1:"

    def __init__(self, db_path: Path, key_rotation_hours: int = 24, use_encryption: Optional[bool] = None):
        """
        Инициализация БД

        Args:
            db_path: Путь к файлу БД
            key_rotation_hours: Часы до ротации ключа (зарезервировано для будущего использования)
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
        else:
            logger.info("Using SQLite with application-level protection for selected secrets")

    def _get_encryption_key(self) -> str:
        """
        Получение ключа шифрования из защищенного хранилища
        (зарезервировано для будущего использования)

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

    def _get_secret_protection_key(self) -> bytes:
        """Return the Fernet key used to wrap selected secrets stored in SQLite."""
        key = keyring.get_password(self.SERVICE_NAME, self.SECRET_PROTECTION_KEY_NAME)
        if not key:
            key = Fernet.generate_key().decode("ascii")
            keyring.set_password(self.SERVICE_NAME, self.SECRET_PROTECTION_KEY_NAME, key)
            logger.info("Generated database secret protection key")
        return key.encode("ascii")

    def is_secret_protected(self, value: Optional[str]) -> bool:
        """Return True if the value uses the current secret wrapper format."""
        return bool(value) and value.startswith(self.SECRET_PREFIX)

    def protect_secret(self, value: Optional[str]) -> Optional[str]:
        """
        Protect a sensitive value before writing it to SQLite.

        This is intentionally limited to selected fields. It does not encrypt the
        entire database file.
        """
        if value is None:
            return None
        if not self.use_encryption or self.is_secret_protected(value):
            return value

        token = Fernet(self._get_secret_protection_key()).encrypt(value.encode("utf-8"))
        return f"{self.SECRET_PREFIX}{token.decode('ascii')}"

    def unprotect_secret(self, value: Optional[str]) -> Optional[str]:
        """Return the plaintext value for a protected secret."""
        if value is None or not self.is_secret_protected(value):
            return value

        token = value[len(self.SECRET_PREFIX):].encode("ascii")
        plaintext = Fernet(self._get_secret_protection_key()).decrypt(token)
        return plaintext.decode("utf-8")

    def _get_connection(self, key: Optional[str] = None):
        """
        Получение соединения с БД

        Args:
            key: Ключ шифрования (игнорируется, используется для совместимости)

        Returns:
            Соединение с БД (контекстный менеджер)
        """
        db_path_str = str(self.db_path.resolve())
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Используем обычный SQLite
        # Шифрование чувствительных данных может быть добавлено на уровне приложения при необходимости
        # Логирование убрано для уменьшения шума в логах (соединения создаются очень часто)
        
        conn = sqlite3.connect(db_path_str, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=NORMAL")  # Улучшает производительность

        return conn
    
    def _encrypt_value(self, value: str) -> str:
        """
        Шифрование значения для хранения в БД (зарезервировано для будущего использования)
        
        Note: В текущей реализации используется обычный SQLite без шифрования на уровне БД.
        Критичные данные (ключи, пароли) хранятся в keyring.
        """
        # Зарезервировано для будущей реализации шифрования чувствительных полей
        return value
    
    def _decrypt_value(self, encrypted_value: str) -> str:
        """
        Расшифровка значения из БД (зарезервировано для будущего использования)
        """
        # Зарезервировано для будущей реализации шифрования чувствительных полей
        return encrypted_value

    def _migrate_sensitive_storage(self, db: sqlite3.Connection):
        """
        Remove or protect legacy plaintext secrets stored in SQLite.

        Active session keys are no longer persisted at all. Rotation keys remain
        available for compatibility, but are wrapped before staying in SQLite.
        """
        try:
            scrubbed_sessions = db.execute(
                """
                UPDATE client_sessions
                SET session_key = NULL
                WHERE session_key IS NOT NULL AND session_key != ''
                """
            ).rowcount
            if scrubbed_sessions:
                logger.info("Scrubbed %s persisted session keys from SQLite", scrubbed_sessions)
        except sqlite3.OperationalError:
            logger.debug("Skipping session-key scrub because client_sessions is unavailable")

        if not self.use_encryption:
            return

        try:
            legacy_keys = db.execute(
                "SELECT id, key_data FROM encryption_keys WHERE key_data IS NOT NULL"
            ).fetchall()
        except sqlite3.OperationalError:
            logger.debug("Skipping key migration because encryption_keys is unavailable")
            return

        migrated_keys = 0
        for row in legacy_keys:
            key_data = row["key_data"]
            if self.is_secret_protected(key_data):
                continue
            db.execute(
                "UPDATE encryption_keys SET key_data = ? WHERE id = ?",
                (self.protect_secret(key_data), row["id"])
            )
            migrated_keys += 1

        if migrated_keys:
            logger.info("Protected %s legacy encryption keys stored in SQLite", migrated_keys)

    def initialize(self):
        """Инициализация схемы БД"""
        logger.info(f"Initializing database at {self.db_path}")
        
        # Убеждаемся, что директория существует
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"Database directory: {self.db_path.parent}")

        with self._lock:
            db = self._get_connection()
            try:
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

                db.execute("""
                    CREATE TABLE IF NOT EXISTS client_bootstrap_tokens (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        client_id TEXT NOT NULL,
                        token_hash TEXT NOT NULL UNIQUE,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        expires_at TEXT NOT NULL,
                        used_at TEXT,
                        metadata TEXT,
                        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
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

                # Таблица конфигураций клиентов
                db.execute("""
                    CREATE TABLE IF NOT EXISTS client_configs (
                        client_id TEXT PRIMARY KEY,
                        config_data TEXT NOT NULL,
                        version INTEGER DEFAULT 1,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
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

                # Таблица статистики трафика
                db.execute("""
                    CREATE TABLE IF NOT EXISTS traffic_stats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        client_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        src_ip TEXT,
                        dst_ip TEXT,
                        src_port INTEGER,
                        dst_port INTEGER,
                        protocol TEXT,
                        action TEXT,
                        bytes_in INTEGER DEFAULT 0,
                        bytes_out INTEGER DEFAULT 0,
                        connections INTEGER DEFAULT 0,
                        bandwidth_bps REAL,
                        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
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

                # Таблица системного статуса клиентов
                db.execute("""
                    CREATE TABLE IF NOT EXISTS client_system_status (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        client_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        cpu_percent REAL,
                        cpu_per_core TEXT,
                        memory_total INTEGER,
                        memory_used INTEGER,
                        memory_percent REAL,
                        disk_usage TEXT,
                        os_info TEXT,
                        plugins_status TEXT,
                        extra TEXT,
                        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
                    )
                """)

                # Таблица логов клиентов
                db.execute("""
                    CREATE TABLE IF NOT EXISTS client_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        client_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        level TEXT NOT NULL,
                        logger_name TEXT,
                        message TEXT NOT NULL,
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
                db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_traffic_stats_client_timestamp 
                    ON traffic_stats(client_id, timestamp)
                """)
                db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_traffic_stats_src_ip 
                    ON traffic_stats(src_ip)
                """)
                db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_traffic_stats_dst_ip 
                    ON traffic_stats(dst_ip)
                """)
                db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_client_system_status_client_timestamp 
                    ON client_system_status(client_id, timestamp)
                """)
                db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_client_logs_client_timestamp 
                    ON client_logs(client_id, timestamp)
                """)
                db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_client_logs_level 
                    ON client_logs(level)
                """)

                self._migrate_sensitive_storage(db)
                db.commit()
                logger.info("Database schema initialized successfully")
            except Exception as e:
                logger.error(f"Error initializing database: {e}", exc_info=True)
                db.rollback()
                raise
            finally:
                db.close()

        self._initialized = True
        logger.info(f"Database initialized: {self.db_path}")
        logger.info(f"Database initialized: {self.db_path}")

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
            db = self._get_connection()
            try:
                cursor = db.execute(query, params)
                db.commit()
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            except Exception as e:
                logger.error(f"Error executing query: {e}", exc_info=True)
                logger.error(f"Query: {query}")
                logger.error(f"Params: {params}")
                db.rollback()
                raise
            finally:
                db.close()

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
            db = self._get_connection()
            try:
                cursor = db.execute(query, params)
                db.commit()
                lastrowid = cursor.lastrowid
                logger.debug(f"Write query executed successfully, lastrowid: {lastrowid}")
                return lastrowid
            except Exception as e:
                logger.error(f"Error executing write query: {e}", exc_info=True)
                logger.error(f"Query: {query}")
                logger.error(f"Params: {params}")
                db.rollback()
                raise
            finally:
                db.close()

    def execute_delete(self, query: str, params: tuple = ()) -> int:
        """
        Выполнение DELETE запроса

        Args:
            query: SQL запрос DELETE
            params: Параметры запроса

        Returns:
            Количество удаленных строк
        """
        with self._lock:
            db = self._get_connection()
            try:
                cursor = db.execute(query, params)
                db.commit()
                rowcount = cursor.rowcount
                logger.debug(f"Delete query executed successfully, rows deleted: {rowcount}")
                return rowcount
            except Exception as e:
                logger.error(f"Error executing delete query: {e}", exc_info=True)
                logger.error(f"Query: {query}")
                logger.error(f"Params: {params}")
                db.rollback()
                raise
            finally:
                db.close()

    def close(self):
        """Закрытие соединений"""
        # SQLite автоматически закрывает соединения при выходе из контекста
        pass
