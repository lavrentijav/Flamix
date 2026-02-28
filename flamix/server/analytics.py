"""Аналитика блокировок"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from flamix.database.encrypted_db import EncryptedDB

logger = logging.getLogger(__name__)


class Analytics:
    """Сбор и агрегация аналитики"""

    def __init__(self, db: EncryptedDB):
        """
        Инициализация аналитики

        Args:
            db: База данных
        """
        self.db = db

    def save_event(
        self,
        client_id: Optional[str],
        event_type: str,
        target_ip: Optional[str] = None,
        target_domain: Optional[str] = None,
        target_port: Optional[int] = None,
        protocol: Optional[str] = None,
        action: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Сохранение события

        Args:
            client_id: ID клиента
            event_type: Тип события
            target_ip: Целевой IP
            target_domain: Целевой домен
            target_port: Целевой порт
            protocol: Протокол
            action: Действие
            details: Дополнительные детали
        """
        import json
        self.db.execute_write(
            """
            INSERT INTO analytics
            (client_id, timestamp, event_type, target_ip, target_domain, target_port, protocol, action, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client_id,
                datetime.utcnow().isoformat() + "Z",
                event_type,
                target_ip,
                target_domain,
                target_port,
                protocol,
                action,
                json.dumps(details) if details else None
            )
        )

    def get_statistics(
        self,
        client_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Получение статистики

        Args:
            client_id: ID клиента (опционально)
            start_time: Начальное время
            end_time: Конечное время

        Returns:
            Словарь со статистикой
        """
        query = "SELECT * FROM analytics WHERE 1=1"
        params = []

        if client_id:
            query += " AND client_id = ?"
            params.append(client_id)

        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat() + "Z")

        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat() + "Z")

        events = self.db.execute(query, tuple(params))

        # Агрегация
        stats = {
            'total_events': len(events),
            'by_type': {},
            'by_action': {},
            'by_protocol': {},
            'top_ips': {},
            'top_domains': {},
            'top_ports': {}
        }

        for event in events:
            # По типу
            event_type = event.get('event_type', 'unknown')
            stats['by_type'][event_type] = stats['by_type'].get(event_type, 0) + 1

            # По действию
            action = event.get('action')
            if action:
                stats['by_action'][action] = stats['by_action'].get(action, 0) + 1

            # По протоколу
            protocol = event.get('protocol')
            if protocol:
                stats['by_protocol'][protocol] = stats['by_protocol'].get(protocol, 0) + 1

            # Топ IP
            target_ip = event.get('target_ip')
            if target_ip:
                stats['top_ips'][target_ip] = stats['top_ips'].get(target_ip, 0) + 1

            # Топ домены
            target_domain = event.get('target_domain')
            if target_domain:
                stats['top_domains'][target_domain] = stats['top_domains'].get(target_domain, 0) + 1

            # Топ порты
            target_port = event.get('target_port')
            if target_port:
                stats['top_ports'][target_port] = stats['top_ports'].get(target_port, 0) + 1

        # Сортируем топы
        stats['top_ips'] = dict(sorted(stats['top_ips'].items(), key=lambda x: x[1], reverse=True)[:10])
        stats['top_domains'] = dict(sorted(stats['top_domains'].items(), key=lambda x: x[1], reverse=True)[:10])
        stats['top_ports'] = dict(sorted(stats['top_ports'].items(), key=lambda x: x[1], reverse=True)[:10])

        return stats

    def cleanup_old_data(self, retention_days: int = 30):
        """
        Очистка старых данных

        Args:
            retention_days: Количество дней для хранения
        """
        cutoff_date = (datetime.utcnow() - timedelta(days=retention_days)).isoformat() + "Z"
        self.db.execute_write(
            "DELETE FROM analytics WHERE timestamp < ?",
            (cutoff_date,)
        )
        logger.info(f"Cleaned up analytics data older than {retention_days} days")
