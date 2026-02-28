"""Управление подключенными клиентами"""

import asyncio
import logging
import uuid
from typing import Dict, Optional
from datetime import datetime, timedelta

from flamix.common.diffie_hellman import DiffieHellman
from flamix.common.crypto import derive_key
from flamix.database.encrypted_db import EncryptedDB

logger = logging.getLogger(__name__)


class ClientSession:
    """Сессия клиента"""

    def __init__(self, client_id: str, session_id: str, session_key: bytes):
        """
        Инициализация сессии

        Args:
            client_id: ID клиента
            session_id: ID сессии
            session_key: Сессионный ключ
        """
        self.client_id = client_id
        self.session_id = session_id
        self.session_key = session_key
        self.created_at = datetime.utcnow()
        self.last_activity = datetime.utcnow()
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.dh: Optional[DiffieHellman] = None

    def update_activity(self):
        """Обновление времени последней активности"""
        self.last_activity = datetime.utcnow()

    def is_expired(self, timeout_seconds: int = 3600) -> bool:
        """
        Проверка истечения сессии

        Args:
            timeout_seconds: Таймаут в секундах

        Returns:
            True если сессия истекла
        """
        return (datetime.utcnow() - self.last_activity).total_seconds() > timeout_seconds


class ClientManager:
    """Менеджер подключенных клиентов"""

    def __init__(self, db: EncryptedDB):
        """
        Инициализация менеджера клиентов

        Args:
            db: База данных
        """
        self.db = db
        self.sessions: Dict[str, ClientSession] = {}  # session_id -> ClientSession
        self.client_sessions: Dict[str, str] = {}  # client_id -> session_id

    async def create_session(
        self,
        client_id: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> ClientSession:
        """
        Создание новой сессии клиента

        Args:
            client_id: ID клиента
            reader: Поток для чтения
            writer: Поток для записи

        Returns:
            Созданная сессия
        """
        # Закрываем старую сессию если есть
        if client_id in self.client_sessions:
            old_session_id = self.client_sessions[client_id]
            await self.close_session(old_session_id)

        # Создаем новую сессию
        session_id = str(uuid.uuid4())
        dh = DiffieHellman()

        # Пока что создаем временный ключ, реальный будет после DH обмена
        temp_key = b'\x00' * 32
        session = ClientSession(client_id, session_id, temp_key)
        session.reader = reader
        session.writer = writer
        session.dh = dh

        self.sessions[session_id] = session
        self.client_sessions[client_id] = session_id

        # Сохраняем в БД
        self._save_session_to_db(session)

        logger.info(f"Created session {session_id} for client {client_id}")
        return session

    def get_session(self, session_id: str) -> Optional[ClientSession]:
        """
        Получение сессии по ID

        Args:
            session_id: ID сессии

        Returns:
            Сессия или None
        """
        return self.sessions.get(session_id)

    def get_session_by_client(self, client_id: str) -> Optional[ClientSession]:
        """
        Получение сессии по ID клиента

        Args:
            client_id: ID клиента

        Returns:
            Сессия или None
        """
        session_id = self.client_sessions.get(client_id)
        if session_id:
            return self.sessions.get(session_id)
        return None

    async def complete_dh_exchange(self, session_id: str, peer_public_key: bytes) -> bytes:
        """
        Завершение обмена ключами Диффи-Хеллмана

        Args:
            session_id: ID сессии
            peer_public_key: Публичный ключ клиента

        Returns:
            Сессионный ключ
        """
        session = self.sessions.get(session_id)
        if not session or not session.dh:
            raise ValueError(f"Session {session_id} not found or DH not initialized")

        # Вычисляем общий секрет
        shared_secret = session.dh.compute_shared_secret(peer_public_key)

        # Генерируем сессионный ключ
        session_key = DiffieHellman.generate_session_key(shared_secret)

        # Обновляем сессию
        session.session_key = session_key
        session.update_activity()

        # Обновляем в БД
        self._save_session_to_db(session)

        logger.info(f"DH exchange completed for session {session_id}")
        return session_key

    async def close_session(self, session_id: str):
        """
        Закрытие сессии

        Args:
            session_id: ID сессии
        """
        session = self.sessions.get(session_id)
        if not session:
            return

        # Закрываем соединение
        if session.writer:
            try:
                session.writer.close()
                await session.writer.wait_closed()
            except Exception as e:
                logger.error(f"Error closing writer for session {session_id}: {e}")

        # Удаляем из словарей
        if session.client_id in self.client_sessions:
            del self.client_sessions[session.client_id]
        del self.sessions[session_id]

        logger.info(f"Closed session {session_id}")

    def update_activity(self, session_id: str):
        """
        Обновление активности сессии

        Args:
            session_id: ID сессии
        """
        session = self.sessions.get(session_id)
        if session:
            session.update_activity()
            self._save_session_to_db(session)

    def cleanup_expired_sessions(self, timeout_seconds: int = 3600):
        """
        Очистка истекших сессий

        Args:
            timeout_seconds: Таймаут в секундах
        """
        expired_sessions = [
            session_id for session_id, session in self.sessions.items()
            if session.is_expired(timeout_seconds)
        ]

        for session_id in expired_sessions:
            asyncio.create_task(self.close_session(session_id))

    def _save_session_to_db(self, session: ClientSession):
        """Сохранение сессии в БД"""
        try:
            import json
            dh_params = None
            if session.dh:
                dh_params = json.dumps({
                    'public_key': session.dh.get_public_key_bytes().decode('utf-8')
                })

            expires_at = (datetime.utcnow() + timedelta(hours=24)).isoformat() + "Z"

            self.db.execute_write(
                """
                INSERT OR REPLACE INTO client_sessions 
                (id, client_id, session_key, dh_public_key, dh_params, expires_at, last_activity)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    session.client_id,
                    session.session_key.hex(),
                    session.dh.get_public_key_bytes().hex() if session.dh else None,
                    dh_params,
                    expires_at,
                    session.last_activity.isoformat() + "Z"
                )
            )
        except Exception as e:
            logger.error(f"Error saving session to DB: {e}")
