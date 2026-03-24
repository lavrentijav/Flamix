"""Traffic analytics with numpy/scipy aggregation

ВАЖНО: Этот модуль НЕ читает трафик напрямую!
Он только агрегирует данные, которые были собраны КЛИЕНТОМ
и отправлены на сервер через ANALYTICS_REPORT.
Клиент собирает трафик через psutil и плагины файрвола.
"""

import logging
import numpy as np
from scipy import stats
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from flamix.database.encrypted_db import EncryptedDB

logger = logging.getLogger(__name__)


class TrafficAnalytics:
    """
    Traffic analytics with statistical analysis.
    
    Агрегирует данные трафика, собранные клиентами.
    Данные поступают от клиентов через ANALYTICS_REPORT сообщения
    и сохраняются в таблицу traffic_stats.
    """

    def __init__(self, db: EncryptedDB):
        """
        Initialize traffic analytics

        Args:
            db: Database instance (содержит данные, собранные клиентами)
        """
        self.db = db

    def get_traffic_summary(
        self,
        client_id: Optional[str] = None,
        period: str = "24h"
    ) -> Dict[str, Any]:
        """
        Get aggregated traffic summary

        Args:
            client_id: Client ID (optional, None for all clients)
            period: Time period (e.g., "1h", "24h", "7d")

        Returns:
            Dictionary with summary statistics
        """
        start_time = self._parse_period(period)
        start_iso = start_time.isoformat() + "Z"

        query = "SELECT * FROM traffic_stats WHERE timestamp >= ?"
        params = [start_iso]

        if client_id:
            query += " AND client_id = ?"
            params.append(client_id)

        query += " ORDER BY timestamp DESC"

        rows = self.db.execute(query, tuple(params))

        if not rows:
            return {
                "total_bytes_in": 0,
                "total_bytes_out": 0,
                "total_connections": 0,
                "top_source_ips": {},
                "top_destination_ips": {},
                "top_ports": {},
                "by_protocol": {},
                "by_action": {}
            }

        # Convert to numpy arrays for fast aggregation
        bytes_in = np.array([r.get('bytes_in', 0) or 0 for r in rows], dtype=np.int64)
        bytes_out = np.array([r.get('bytes_out', 0) or 0 for r in rows], dtype=np.int64)
        connections = np.array([r.get('connections', 0) or 0 for r in rows], dtype=np.int64)

        # Aggregate by IP
        src_ips = {}
        dst_ips = {}
        ports = {}
        protocols = {}
        actions = {}

        for row in rows:
            src_ip = row.get('src_ip')
            if src_ip:
                if src_ip not in src_ips:
                    src_ips[src_ip] = {'bytes': 0, 'connections': 0}
                src_ips[src_ip]['bytes'] += row.get('bytes_in', 0) or 0
                src_ips[src_ip]['connections'] += row.get('connections', 0) or 0

            dst_ip = row.get('dst_ip')
            if dst_ip:
                if dst_ip not in dst_ips:
                    dst_ips[dst_ip] = {'bytes': 0, 'connections': 0}
                dst_ips[dst_ip]['bytes'] += row.get('bytes_out', 0) or 0
                dst_ips[dst_ip]['connections'] += row.get('connections', 0) or 0

            dst_port = row.get('dst_port')
            if dst_port:
                ports[dst_port] = ports.get(dst_port, 0) + 1

            protocol = row.get('protocol')
            if protocol:
                protocols[protocol] = protocols.get(protocol, 0) + 1

            action = row.get('action')
            if action:
                actions[action] = actions.get(action, 0) + 1

        # Sort and limit top items
        top_src_ips = dict(sorted(
            src_ips.items(),
            key=lambda x: x[1]['bytes'],
            reverse=True
        )[:20])

        top_dst_ips = dict(sorted(
            dst_ips.items(),
            key=lambda x: x[1]['bytes'],
            reverse=True
        )[:20])

        top_ports = dict(sorted(
            ports.items(),
            key=lambda x: x[1],
            reverse=True
        )[:20])

        return {
            "total_bytes_in": int(np.sum(bytes_in)),
            "total_bytes_out": int(np.sum(bytes_out)),
            "total_connections": int(np.sum(connections)),
            "avg_bytes_in": float(np.mean(bytes_in)) if len(bytes_in) > 0 else 0.0,
            "avg_bytes_out": float(np.mean(bytes_out)) if len(bytes_out) > 0 else 0.0,
            "top_source_ips": top_src_ips,
            "top_destination_ips": top_dst_ips,
            "top_ports": top_ports,
            "by_protocol": protocols,
            "by_action": actions,
            "period": period,
            "record_count": len(rows)
        }

    def get_time_series(
        self,
        client_id: Optional[str],
        interval: str = "1m",
        period: str = "1h"
    ) -> Dict[str, Any]:
        """
        Get time series data for traffic

        Args:
            client_id: Client ID (optional)
            interval: Time bucket interval (e.g., "1m", "5m", "1h")
            period: Time period to analyze

        Returns:
            Dictionary with time series data
        """
        start_time = self._parse_period(period)
        start_iso = start_time.isoformat() + "Z"
        interval_seconds = self._parse_interval(interval)

        query = "SELECT * FROM traffic_stats WHERE timestamp >= ?"
        params = [start_iso]

        if client_id:
            query += " AND client_id = ?"
            params.append(client_id)

        query += " ORDER BY timestamp ASC"

        rows = self.db.execute(query, tuple(params))

        if not rows:
            return {
                "timestamps": [],
                "bytes_in": [],
                "bytes_out": [],
                "connections": [],
                "bandwidth": []
            }

        # Group by time buckets
        buckets = {}
        for row in rows:
            timestamp_str = row.get('timestamp', '')
            try:
                ts = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                # Round to interval
                bucket_key = int(ts.timestamp() // interval_seconds) * interval_seconds
                if bucket_key not in buckets:
                    buckets[bucket_key] = {
                        'bytes_in': 0,
                        'bytes_out': 0,
                        'connections': 0,
                        'count': 0
                    }
                buckets[bucket_key]['bytes_in'] += row.get('bytes_in', 0) or 0
                buckets[bucket_key]['bytes_out'] += row.get('bytes_out', 0) or 0
                buckets[bucket_key]['connections'] += row.get('connections', 0) or 0
                buckets[bucket_key]['count'] += 1
            except Exception as e:
                logger.debug(f"Error parsing timestamp {timestamp_str}: {e}")
                continue

        # Convert to sorted lists
        sorted_buckets = sorted(buckets.items())
        timestamps = [datetime.fromtimestamp(k).isoformat() + "Z" for k, _ in sorted_buckets]
        bytes_in = [b['bytes_in'] for _, b in sorted_buckets]
        bytes_out = [b['bytes_out'] for _, b in sorted_buckets]
        connections = [b['connections'] for _, b in sorted_buckets]

        # Calculate bandwidth (bytes per second)
        bandwidth = []
        for i, (bucket_key, bucket_data) in enumerate(sorted_buckets):
            if i > 0:
                prev_key = sorted_buckets[i-1][0]
                time_diff = bucket_key - prev_key
                if time_diff > 0:
                    total_bytes = bucket_data['bytes_in'] + bucket_data['bytes_out']
                    bps = total_bytes / time_diff
                    bandwidth.append(bps)
                else:
                    bandwidth.append(0)
            else:
                bandwidth.append(0)

        return {
            "timestamps": timestamps,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "connections": connections,
            "bandwidth": bandwidth,
            "interval": interval
        }

    def get_bandwidth_stats(
        self,
        client_id: Optional[str] = None,
        period: str = "1h"
    ) -> Dict[str, Any]:
        """
        Get bandwidth statistics using scipy

        Args:
            client_id: Client ID (optional)
            period: Time period

        Returns:
            Dictionary with bandwidth statistics
        """
        time_series = self.get_time_series(client_id, interval="1m", period=period)

        if not time_series['bandwidth'] or len(time_series['bandwidth']) == 0:
            return {
                "current_bps": 0,
                "avg_bps": 0,
                "peak_bps": 0,
                "min_bps": 0
            }

        bandwidth_array = np.array(time_series['bandwidth'])

        # Calculate moving average using scipy
        if len(bandwidth_array) > 5:
            window_size = min(5, len(bandwidth_array) // 2)
            moving_avg = stats.uniform_filter1d(bandwidth_array, size=window_size, mode='nearest')
            current_bps = float(moving_avg[-1]) if len(moving_avg) > 0 else 0.0
        else:
            current_bps = float(bandwidth_array[-1]) if len(bandwidth_array) > 0 else 0.0

        return {
            "current_bps": current_bps,
            "avg_bps": float(np.mean(bandwidth_array)),
            "peak_bps": float(np.max(bandwidth_array)),
            "min_bps": float(np.min(bandwidth_array)),
            "std_bps": float(np.std(bandwidth_array))
        }

    def detect_anomalies(
        self,
        client_id: Optional[str] = None,
        period: str = "24h"
    ) -> List[Dict[str, Any]]:
        """
        Detect traffic anomalies using scipy z-score

        Args:
            client_id: Client ID (optional)
            period: Time period

        Returns:
            List of detected anomalies
        """
        time_series = self.get_time_series(client_id, interval="5m", period=period)

        if not time_series['bandwidth'] or len(time_series['bandwidth']) < 10:
            return []

        bandwidth_array = np.array(time_series['bandwidth'])

        # Calculate z-scores
        z_scores = np.abs(stats.zscore(bandwidth_array))

        # Find anomalies (z-score > 2)
        threshold = 2.0
        anomalies = []

        for i, (z_score, timestamp) in enumerate(zip(z_scores, time_series['timestamps'])):
            if z_score > threshold:
                anomalies.append({
                    "timestamp": timestamp,
                    "bandwidth_bps": float(bandwidth_array[i]),
                    "z_score": float(z_score),
                    "severity": "high" if z_score > 3 else "medium"
                })

        return anomalies

    def get_ip_details(
        self,
        client_id: Optional[str],
        ip: str,
        period: str = "24h"
    ) -> Dict[str, Any]:
        """
        Get detailed statistics for a specific IP

        Args:
            client_id: Client ID (optional)
            ip: IP address to analyze
            period: Time period

        Returns:
            Dictionary with IP details
        """
        start_time = self._parse_period(period)
        start_iso = start_time.isoformat() + "Z"

        query = """
            SELECT * FROM traffic_stats 
            WHERE timestamp >= ? AND (src_ip = ? OR dst_ip = ?)
        """
        params = [start_iso, ip, ip]

        if client_id:
            query += " AND client_id = ?"
            params.append(client_id)

        query += " ORDER BY timestamp DESC"

        rows = self.db.execute(query, tuple(params))

        if not rows:
            return {
                "ip": ip,
                "total_bytes_in": 0,
                "total_bytes_out": 0,
                "total_connections": 0,
                "ports": {},
                "protocols": {},
                "timeline": []
            }

        bytes_in = np.array([r.get('bytes_in', 0) or 0 for r in rows], dtype=np.int64)
        bytes_out = np.array([r.get('bytes_out', 0) or 0 for r in rows], dtype=np.int64)
        connections = np.array([r.get('connections', 0) or 0 for r in rows], dtype=np.int64)

        ports = {}
        protocols = {}

        for row in rows:
            port = row.get('dst_port') or row.get('src_port')
            if port:
                ports[port] = ports.get(port, 0) + 1

            protocol = row.get('protocol')
            if protocol:
                protocols[protocol] = protocols.get(protocol, 0) + 1

        return {
            "ip": ip,
            "total_bytes_in": int(np.sum(bytes_in)),
            "total_bytes_out": int(np.sum(bytes_out)),
            "total_connections": int(np.sum(connections)),
            "avg_bytes_in": float(np.mean(bytes_in)) if len(bytes_in) > 0 else 0.0,
            "avg_bytes_out": float(np.mean(bytes_out)) if len(bytes_out) > 0 else 0.0,
            "ports": dict(sorted(ports.items(), key=lambda x: x[1], reverse=True)[:20]),
            "protocols": protocols,
            "record_count": len(rows)
        }

    def _parse_period(self, period: str) -> datetime:
        """Parse time period string to datetime"""
        now = datetime.utcnow()
        period_lower = period.lower()

        if period_lower.endswith('h'):
            hours = int(period_lower[:-1])
            return now - timedelta(hours=hours)
        elif period_lower.endswith('d'):
            days = int(period_lower[:-1])
            return now - timedelta(days=days)
        elif period_lower.endswith('m'):
            minutes = int(period_lower[:-1])
            return now - timedelta(minutes=minutes)
        else:
            # Default to 24 hours
            return now - timedelta(hours=24)

    def _parse_interval(self, interval: str) -> int:
        """Parse interval string to seconds"""
        interval_lower = interval.lower()

        if interval_lower.endswith('m'):
            minutes = int(interval_lower[:-1])
            return minutes * 60
        elif interval_lower.endswith('h'):
            hours = int(interval_lower[:-1])
            return hours * 3600
        elif interval_lower.endswith('s'):
            seconds = int(interval_lower[:-1])
            return seconds
        else:
            # Default to 1 minute
            return 60
