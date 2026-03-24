"""Синхронизация конфигурации с сервером"""

import asyncio
import logging
from typing import Optional, Dict, Any
from pathlib import Path

from flamix.client.client import FlamixClient

logger = logging.getLogger(__name__)


class ConfigSync:
    """Синхронизация конфигурации между клиентом и сервером"""

    def __init__(
        self,
        client: FlamixClient,
        config_path: Path,
        sync_interval: int = 300  # 5 минут по умолчанию
    ):
        """
        Инициализация синхронизации конфигурации

        Args:
            client: Клиент для связи с сервером
            config_path: Путь к файлу config.json
            sync_interval: Интервал синхронизации в секундах
        """
        self.client = client
        self.config_path = config_path
        self.sync_interval = sync_interval
        self.running = False
        self.last_config_version: Optional[int] = None

    async def start(self):
        """Запуск синхронизации конфигурации"""
        self.running = True
        asyncio.create_task(self._sync_loop())

    async def stop(self):
        """Остановка синхронизации"""
        self.running = False

    async def _sync_loop(self):
        """Цикл синхронизации конфигурации"""
        while self.running:
            try:
                await asyncio.sleep(self.sync_interval)
                if self.client.connected:
                    await self.sync_config()
            except Exception as e:
                logger.error(f"Error in config sync loop: {e}", exc_info=True)

    async def sync_config(self) -> bool:
        """
        Синхронизация конфигурации с сервером

        Returns:
            True если конфиг обновлен
        """
        if not self.client.connected:
            logger.warning("Client not connected, cannot sync config")
            return False

        try:
            # Запрашиваем конфиг с сервера
            config = await self.client.request_config()
            if config:
                # Применяем новый конфиг
                await self.client._apply_config(config)
                logger.info("Configuration synced from server")
                return True
            else:
                logger.debug("No config update from server")
                return False
        except Exception as e:
            logger.error(f"Error syncing config: {e}", exc_info=True)
            return False
