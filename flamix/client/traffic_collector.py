"""Traffic statistics collector

Этот модуль собирает статистику трафика на КЛИЕНТЕ:
- psutil: активные соединения, сетевой I/O, счетчики интерфейсов
- плагины файрвола: логи iptables/Windows Firewall

Собранные данные отправляются на сервер через AnalyticsCollector.
"""

import asyncio
import logging
import psutil
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from flamix.client.plugins.base import FirewallPlugin

logger = logging.getLogger(__name__)


class TrafficCollector:
    """
    Collects traffic statistics from psutil and firewall logs.
    
    Работает на КЛИЕНТЕ, собирает данные локально и отправляет на сервер.
    """

    def __init__(
        self,
        plugin: Optional[FirewallPlugin] = None,
        collection_interval: int = 10
    ):
        """
        Initialize traffic collector

        Args:
            plugin: Active firewall plugin for log parsing
            collection_interval: Interval between collections in seconds
        """
        self.plugin = plugin
        self.collection_interval = collection_interval
        self.running = False
        self.last_collection_time = None
        self.last_net_io = None

    async def start(self):
        """Start the traffic collector"""
        self.running = True
        self.last_collection_time = datetime.utcnow()
        self.last_net_io = psutil.net_io_counters()

    async def stop(self):
        """Stop the traffic collector"""
        self.running = False

    async def collect_snapshot(self) -> Dict[str, Any]:
        """
        Collect a snapshot of current traffic statistics

        Returns:
            Dictionary with traffic statistics
        """
        snapshot = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "connections": [],
            "network_io": {},
            "firewall_events": [],
            "aggregated": {}
        }

        # Collect from psutil
        try:
            # Active connections
            connections = psutil.net_connections(kind='inet')
            connection_stats = defaultdict(lambda: {
                "count": 0,
                "bytes_sent": 0,
                "bytes_recv": 0
            })

            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    src_ip = conn.laddr.ip if conn.laddr else None
                    dst_ip = conn.raddr.ip if conn.raddr else None
                    src_port = conn.laddr.port if conn.laddr else None
                    dst_port = conn.raddr.port if conn.raddr else None

                    if src_ip and dst_ip:
                        key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                        connection_stats[key]["count"] += 1

                        snapshot["connections"].append({
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "status": conn.status,
                            "pid": conn.pid
                        })

            # Network I/O counters
            current_net_io = psutil.net_io_counters()
            if self.last_net_io:
                time_delta = (datetime.utcnow() - self.last_collection_time).total_seconds()
                if time_delta > 0:
                    bytes_sent_diff = current_net_io.bytes_sent - self.last_net_io.bytes_sent
                    bytes_recv_diff = current_net_io.bytes_recv - self.last_net_io.bytes_recv
                    packets_sent_diff = current_net_io.packets_sent - self.last_net_io.packets_sent
                    packets_recv_diff = current_net_io.packets_recv - self.last_net_io.packets_recv

                    snapshot["network_io"] = {
                        "bytes_sent": bytes_sent_diff,
                        "bytes_recv": bytes_recv_diff,
                        "packets_sent": packets_sent_diff,
                        "packets_recv": packets_recv_diff,
                        "bytes_sent_per_sec": bytes_sent_diff / time_delta,
                        "bytes_recv_per_sec": bytes_recv_diff / time_delta,
                        "bandwidth_bps": (bytes_sent_diff + bytes_recv_diff) / time_delta
                    }
                else:
                    snapshot["network_io"] = {
                        "bytes_sent": 0,
                        "bytes_recv": 0,
                        "packets_sent": 0,
                        "packets_recv": 0,
                        "bytes_sent_per_sec": 0,
                        "bytes_recv_per_sec": 0,
                        "bandwidth_bps": 0
                    }

            self.last_net_io = current_net_io
            self.last_collection_time = datetime.utcnow()

            # Per-interface stats
            per_nic = psutil.net_io_counters(pernic=True)
            snapshot["network_io"]["per_interface"] = {}
            for interface, stats in per_nic.items():
                snapshot["network_io"]["per_interface"][interface] = {
                    "bytes_sent": stats.bytes_sent,
                    "bytes_recv": stats.bytes_recv,
                    "packets_sent": stats.packets_sent,
                    "packets_recv": stats.packets_recv
                }

        except Exception as e:
            logger.error(f"Error collecting psutil stats: {e}", exc_info=True)

        # Collect from firewall plugin logs
        if self.plugin:
            try:
                firewall_events = await self.plugin.get_traffic_stats(limit=50)
                snapshot["firewall_events"] = firewall_events
            except Exception as e:
                logger.debug(f"Error collecting firewall stats: {e}")

        # Aggregate statistics
        snapshot["aggregated"] = self._aggregate_stats(snapshot)

        return snapshot

    def _aggregate_stats(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate statistics from collected data"""
        aggregated = {
            "total_connections": len(snapshot.get("connections", [])),
            "top_source_ips": {},
            "top_destination_ips": {},
            "top_ports": {},
            "total_bytes_sent": snapshot.get("network_io", {}).get("bytes_sent", 0),
            "total_bytes_recv": snapshot.get("network_io", {}).get("bytes_recv", 0),
            "bandwidth_bps": snapshot.get("network_io", {}).get("bandwidth_bps", 0)
        }

        # Count connections by source IP
        for conn in snapshot.get("connections", []):
            src_ip = conn.get("src_ip")
            if src_ip:
                aggregated["top_source_ips"][src_ip] = aggregated["top_source_ips"].get(src_ip, 0) + 1

        # Count connections by destination IP
        for conn in snapshot.get("connections", []):
            dst_ip = conn.get("dst_ip")
            if dst_ip:
                aggregated["top_destination_ips"][dst_ip] = aggregated["top_destination_ips"].get(dst_ip, 0) + 1

        # Count connections by port
        for conn in snapshot.get("connections", []):
            dst_port = conn.get("dst_port")
            if dst_port:
                aggregated["top_ports"][dst_port] = aggregated["top_ports"].get(dst_port, 0) + 1

        # Sort and limit top items
        aggregated["top_source_ips"] = dict(
            sorted(aggregated["top_source_ips"].items(), key=lambda x: x[1], reverse=True)[:10]
        )
        aggregated["top_destination_ips"] = dict(
            sorted(aggregated["top_destination_ips"].items(), key=lambda x: x[1], reverse=True)[:10]
        )
        aggregated["top_ports"] = dict(
            sorted(aggregated["top_ports"].items(), key=lambda x: x[1], reverse=True)[:10]
        )

        # Aggregate firewall events
        firewall_bytes_in = 0
        firewall_bytes_out = 0
        firewall_blocks = 0
        firewall_allows = 0

        for event in snapshot.get("firewall_events", []):
            firewall_bytes_in += event.get("bytes_in", 0)
            firewall_bytes_out += event.get("bytes_out", 0)
            if event.get("action") == "block":
                firewall_blocks += 1
            elif event.get("action") == "allow":
                firewall_allows += 1

        aggregated["firewall_bytes_in"] = firewall_bytes_in
        aggregated["firewall_bytes_out"] = firewall_bytes_out
        aggregated["firewall_blocks"] = firewall_blocks
        aggregated["firewall_allows"] = firewall_allows

        return aggregated

    async def collect_loop(self, callback):
        """
        Continuous collection loop

        Args:
            callback: Async function to call with each snapshot
        """
        await self.start()
        while self.running:
            try:
                snapshot = await self.collect_snapshot()
                if callback:
                    await callback(snapshot)
                await asyncio.sleep(self.collection_interval)
            except Exception as e:
                logger.error(f"Error in traffic collection loop: {e}", exc_info=True)
                await asyncio.sleep(self.collection_interval)
