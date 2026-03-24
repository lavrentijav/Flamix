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

    async def record_traffic_stats(self, traffic_snapshot: Dict[str, Any]):
        """
        Запись и немедленная отправка статистики трафика для реального времени

        Args:
            traffic_snapshot: Снимок статистики трафика от TrafficCollector
        """
        if not self.enabled:
            return

        # Создаем событие статистики трафика
        event = {
            'event_type': 'traffic_stats',
            'timestamp': traffic_snapshot.get('timestamp', datetime.utcnow().isoformat() + "Z"),
            'connections': traffic_snapshot.get('connections', []),
            'network_io': traffic_snapshot.get('network_io', {}),
            'aggregated': traffic_snapshot.get('aggregated', {}),
            'firewall_events': traffic_snapshot.get('firewall_events', [])
        }

        # Для статистики трафика отправляем сразу для реального времени
        # Обычные события (block/allow) накапливаются в батчах
        if self.client.connected:
            try:
                await self._send_traffic_stats_immediately(event)
            except Exception as e:
                logger.error(f"Error sending traffic stats immediately: {e}", exc_info=True)
                # Если не удалось отправить, добавляем в очередь для повторной попытки
                self.events.append(event)
        else:
            # Если не подключен, добавляем в очередь
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

    async def _send_traffic_stats_immediately(self, event: Dict[str, Any]):
        """Немедленная отправка статистики трафика для реального времени"""
        try:
            await self.client.send_analytics({
                'events': [event],
                'client_id': self.client.client_id
            })
            # Удаляем отправленное событие из очереди
            if event in self.events:
                self.events.remove(event)
            logger.debug("Sent traffic stats immediately to server")
        except Exception as e:
            logger.error(f"Error sending traffic stats immediately: {e}", exc_info=True)

    async def _send_events(self):
        """Отправка событий на сервер (батчами для обычных событий)"""
        if not self.events:
            return

        try:
            # Фильтруем только обычные события (не traffic_stats, они уже отправлены)
            regular_events = [e for e in self.events if e.get('event_type') != 'traffic_stats']
            
            if not regular_events:
                # Если остались только traffic_stats (не должны быть, но на всякий случай)
                self.events = []
                return

            # Отправляем обычные события батчами
            batch_size = 100
            for i in range(0, len(regular_events), batch_size):
                batch = regular_events[i:i + batch_size]
                await self.client.send_analytics({
                    'events': batch,
                    'client_id': self.client.client_id
                })

            # Очищаем отправленные события
            self.events = [e for e in self.events if e.get('event_type') == 'traffic_stats']
            logger.debug(f"Sent {len(batch)} analytics events to server")

        except Exception as e:
            logger.error(f"Error sending analytics events: {e}", exc_info=True)
