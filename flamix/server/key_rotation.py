"""Ротация ключей шифрования"""

import asyncio
import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional

from flamix.database.encrypted_db import EncryptedDB
import keyring

logger = logging.getLogger(__name__)


class KeyRotation:
    """Ротация ключей шифрования"""

    SERVICE_NAME = "flamix"
    KEY_NAME = "db_encryption_key"
    ROTATION_KEY_NAME = "db_encryption_key_rotation"

    def __init__(self, db: EncryptedDB, rotation_hours: int = 24):
        """
        Инициализация ротации ключей

        Args:
            db: База данных
            rotation_hours: Часы до ротации
        """
        self.db = db
        self.rotation_hours = rotation_hours
        self.running = False
        self.last_rotation: Optional[datetime] = None

    async def start(self):
        """Запуск ротации ключей"""
        self.running = True
        asyncio.create_task(self._rotation_loop())

    async def stop(self):
        """Остановка ротации ключей"""
        self.running = False

    async def _rotation_loop(self):
        """Цикл ротации ключей"""
        while self.running:
            try:
                await asyncio.sleep(3600)  # Проверяем каждый час
                if self._should_rotate():
                    await self.rotate_key()
            except Exception as e:
                logger.error(f"Error in key rotation loop: {e}", exc_info=True)

    def _should_rotate(self) -> bool:
        """
        Проверка необходимости ротации

        Returns:
            True если нужна ротация
        """
        last_rotation_str = keyring.get_password(self.SERVICE_NAME, self.ROTATION_KEY_NAME)
        if not last_rotation_str:
            return True

        try:
            last_rotation = datetime.fromisoformat(last_rotation_str)
            hours_since_rotation = (datetime.utcnow() - last_rotation).total_seconds() / 3600
            return hours_since_rotation >= self.rotation_hours
        except Exception as e:
            logger.error(f"Error parsing last rotation time: {e}")
            return True

    async def rotate_key(self) -> bool:
        """
        Ротация ключа шифрования

        Returns:
            True если успешно
        """
        try:
            logger.info("Starting key rotation...")

            # Генерируем новый ключ
            new_key = secrets.token_hex(32)  # 256 бит в hex

            # Сохраняем старый ключ для миграции данных
            old_key = keyring.get_password(self.SERVICE_NAME, self.KEY_NAME)
            if old_key:
                # Сохраняем старый ключ в БД для возможности расшифровки истории
                key_id = str(secrets.token_hex(16))
                self.db.execute_write(
                    """
                    INSERT INTO encryption_keys (id, key_data, created_at, expires_at, active)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        key_id,
                        old_key,
                        datetime.utcnow().isoformat() + "Z",
                        (datetime.utcnow() + timedelta(days=30)).isoformat() + "Z",  # Храним 30 дней
                        0  # Не активный
                    )
                )

            # Устанавливаем новый ключ
            keyring.set_password(self.SERVICE_NAME, self.KEY_NAME, new_key)

            # Обновляем время последней ротации
            keyring.set_password(
                self.SERVICE_NAME,
                self.ROTATION_KEY_NAME,
                datetime.utcnow().isoformat()
            )

            self.last_rotation = datetime.utcnow()

            logger.info("Key rotation completed successfully")
            return True

        except Exception as e:
            logger.error(f"Error rotating key: {e}", exc_info=True)
            return False

    def get_active_key(self) -> Optional[str]:
        """
        Получение активного ключа

        Returns:
            Активный ключ или None
        """
        return keyring.get_password(self.SERVICE_NAME, self.KEY_NAME)

    def get_old_key(self, key_id: str) -> Optional[str]:
        """
        Получение старого ключа по ID

        Args:
            key_id: ID ключа

        Returns:
            Ключ или None
        """
        result = self.db.execute_one(
            "SELECT key_data FROM encryption_keys WHERE id = ?",
            (key_id,)
        )
        return result['key_data'] if result else None

    def cleanup_expired_keys(self, retention_days: int = 30):
        """
        Очистка истекших ключей

        Args:
            retention_days: Количество дней для хранения
        """
        cutoff_date = (datetime.utcnow() - timedelta(days=retention_days)).isoformat() + "Z"
        self.db.execute_write(
            "DELETE FROM encryption_keys WHERE expires_at < ?",
            (cutoff_date,)
        )
        logger.info(f"Cleaned up encryption keys older than {retention_days} days")
