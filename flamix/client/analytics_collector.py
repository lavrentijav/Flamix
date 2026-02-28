"""Сборщик аналитики на клиенте"""

import asyncio
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

from flamix.client.client import FlamixClient

logger = logging.getLogger(__name__)


class AnalyticsCollector:
    """Сборщик аналитики блокировок"""

    def __init__(
        self,
        client: FlamixClient,
        enabled: bool = False,
        report_interval: int = 60
    ):
        """
        Инициализация сборщика аналитики

        Args:
            client: Клиент для отправки данных
            enabled: Включен ли сбор аналитики
            report_interval: Интервал отправки в секундах
        """
        self.client = client
        self.enabled = enabled
        self.report_interval = report_interval
        self.running = False
        self.events: List[Dict[str, Any]] = []

    async def start(self):
        """Запуск сборщика"""
        if not self.enabled:
            return

        self.running = True
        asyncio.create_task(self._report_loop())

    async def stop(self):
        """Остановка сборщика"""
        self.running = False
        # Отправляем оставшиеся события
        if self.events:
            await self._send_events()

    def record_block(
        self,
        target_ip: Optional[str] = None,
        target_domain: Optional[str] = None,
        target_port: Optional[int] = None,
        protocol: Optional[str] = None
    ):
        """
        Запись события блокировки

        Args:
            target_ip: Целевой IP
            target_domain: Целевой домен
            target_port: Целевой порт
            protocol: Протокол
        """
        if not self.enabled:
            return

        event = {
            'event_type': 'block',
            'target_ip': target_ip,
            'target_domain': target_domain,
            'target_port': target_port,
            'protocol': protocol,
            'action': 'block',
            'timestamp': datetime.utcnow().isoformat() + "Z"
        }

        self.events.append(event)

    def record_allow(
        self,
        target_ip: Optional[str] = None,
        target_domain: Optional[str] = None,
        target_port: Optional[int] = None,
        protocol: Optional[str] = None
    ):
        """
        Запись события разрешения

        Args:
            target_ip: Целевой IP
            target_domain: Целевой домен
            target_port: Целевой порт
            protocol: Протокол
        """
        if not self.enabled:
            return

        event = {
            'event_type': 'allow',
            'target_ip': target_ip,
            'target_domain': target_domain,
            'target_port': target_port,
            'protocol': protocol,
            'action': 'allow',
            'timestamp': datetime.utcnow().isoformat() + "Z"
        }

        self.events.append(event)

    async def _report_loop(self):
        """Цикл отправки аналитики"""
        while self.running:
            try:
                await asyncio.sleep(self.report_interval)
                if self.events and self.client.connected:
                    await self._send_events()
            except Exception as e:
                logger.error(f"Error in analytics report loop: {e}", exc_info=True)

    async def _send_events(self):
        """Отправка событий на сервер"""
        if not self.events:
            return

        try:
            # Отправляем события батчами
            batch_size = 100
            for i in range(0, len(self.events), batch_size):
                batch = self.events[i:i + batch_size]
                await self.client.send_analytics({
                    'events': batch,
                    'client_id': self.client.client_id
                })

            # Очищаем отправленные события
            self.events = []
            logger.debug(f"Sent {len(batch)} analytics events to server")

        except Exception as e:
            logger.error(f"Error sending analytics events: {e}", exc_info=True)
