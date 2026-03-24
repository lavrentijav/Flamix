"""System monitoring module for collecting CPU, memory, disk, and OS information"""

import logging
import psutil
import platform
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class SystemMonitor:
    """Collects system metrics using psutil"""

    def __init__(self):
        """Initialize the system monitor"""
        self.boot_time = datetime.fromtimestamp(psutil.boot_time())

    def collect_system_status(self, plugins_status: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Collect comprehensive system status

        Args:
            plugins_status: Optional list of plugin status dictionaries

        Returns:
            Dictionary with system metrics
        """
        status = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "cpu": self._collect_cpu_info(),
            "memory": self._collect_memory_info(),
            "disk": self._collect_disk_info(),
            "network": self._collect_network_info(),
            "os": self._collect_os_info(),
            "plugins": plugins_status or []
        }
        return status

    def _collect_cpu_info(self) -> Dict[str, Any]:
        """Collect CPU information"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_per_core = psutil.cpu_percent(interval=0.1, percpu=True)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            
            cpu_info = {
                "percent": cpu_percent,
                "per_core": cpu_per_core,
                "count": cpu_count,
                "frequency_mhz": cpu_freq.current if cpu_freq else None
            }
            
            if cpu_freq:
                cpu_info["frequency_min_mhz"] = cpu_freq.min
                cpu_info["frequency_max_mhz"] = cpu_freq.max
                
            return cpu_info
        except Exception as e:
            logger.error(f"Error collecting CPU info: {e}", exc_info=True)
            return {"percent": 0, "per_core": [], "count": 0}

    def _collect_memory_info(self) -> Dict[str, Any]:
        """Collect memory information"""
        try:
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            return {
                "total": mem.total,
                "available": mem.available,
                "used": mem.used,
                "free": mem.free,
                "percent": mem.percent,
                "swap_total": swap.total,
                "swap_used": swap.used,
                "swap_free": swap.free,
                "swap_percent": swap.percent
            }
        except Exception as e:
            logger.error(f"Error collecting memory info: {e}", exc_info=True)
            return {"total": 0, "used": 0, "available": 0, "percent": 0}

    def _collect_disk_info(self) -> Dict[str, Any]:
        """Collect disk information"""
        try:
            disk_usage = {}
            disk_io = psutil.disk_io_counters()
            
            # Get all disk partitions
            partitions = psutil.disk_partitions()
            for partition in partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_usage[partition.mountpoint] = {
                        "device": partition.device,
                        "fstype": partition.fstype,
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": usage.percent
                    }
                except PermissionError:
                    # Skip partitions we can't access
                    continue
                except Exception as e:
                    logger.debug(f"Error reading partition {partition.mountpoint}: {e}")
                    continue
            
            disk_info = {
                "partitions": disk_usage
            }
            
            if disk_io:
                disk_info["io"] = {
                    "read_count": disk_io.read_count,
                    "write_count": disk_io.write_count,
                    "read_bytes": disk_io.read_bytes,
                    "write_bytes": disk_io.write_bytes,
                    "read_time": disk_io.read_time,
                    "write_time": disk_io.write_time
                }
            
            return disk_info
        except Exception as e:
            logger.error(f"Error collecting disk info: {e}", exc_info=True)
            return {"partitions": {}}

    def _collect_network_info(self) -> Dict[str, Any]:
        """Collect network interface information"""
        try:
            net_io = psutil.net_io_counters()
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
            
            interfaces = {}
            for interface_name, addrs in net_if_addrs.items():
                interface_info = {
                    "addresses": [],
                    "isup": net_if_stats[interface_name].isup if interface_name in net_if_stats else False,
                    "speed": net_if_stats[interface_name].speed if interface_name in net_if_stats else 0
                }
                
                for addr in addrs:
                    interface_info["addresses"].append({
                        "family": str(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask if addr.netmask else None,
                        "broadcast": addr.broadcast if addr.broadcast else None
                    })
                
                interfaces[interface_name] = interface_info
            
            network_info = {
                "interfaces": interfaces
            }
            
            if net_io:
                network_info["total"] = {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv,
                    "errin": net_io.errin,
                    "errout": net_io.errout,
                    "dropin": net_io.dropin,
                    "dropout": net_io.dropout
                }
            
            return network_info
        except Exception as e:
            logger.error(f"Error collecting network info: {e}", exc_info=True)
            return {"interfaces": {}}

    def _collect_os_info(self) -> Dict[str, Any]:
        """Collect OS information"""
        try:
            uptime_seconds = (datetime.now() - self.boot_time).total_seconds()
            
            return {
                "platform": platform.system(),
                "platform_release": platform.release(),
                "platform_version": platform.version(),
                "architecture": platform.machine(),
                "hostname": platform.node(),
                "processor": platform.processor(),
                "uptime_seconds": int(uptime_seconds),
                "boot_time": self.boot_time.isoformat() + "Z"
            }
        except Exception as e:
            logger.error(f"Error collecting OS info: {e}", exc_info=True)
            return {
                "platform": "unknown",
                "hostname": "unknown",
                "uptime_seconds": 0
            }
