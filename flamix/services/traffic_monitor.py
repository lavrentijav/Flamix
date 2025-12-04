"""Сервис мониторинга сетевого трафика"""

import threading
import socket
import psutil
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging
import ipaddress

logger = logging.getLogger(__name__)


class TrafficMonitor:
    """Мониторинг сетевого трафика и соединений"""

    def __init__(self, db):
        self.db = db
        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.last_stats = {}
        self.cache_domains: Dict[str, Optional[str]] = {}
        self._initialized = False
        self._lock = threading.Lock()

    def start(self):
        """Запуск мониторинга (синхронный метод)"""
        if self.running:
            return

        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        # Даем время на инициализацию
        time.sleep(0.1)
        self._initialized = True
        
        logger.info("Traffic monitor started")

    def stop(self):
        """Остановка мониторинга (синхронный метод)"""
        self.running = False
        self._initialized = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2.0)
        logger.info("Traffic monitor stopped")
    
    def is_ready(self) -> bool:
        """Проверка готовности монитора"""
        return self._initialized and self.running

    def _monitor_loop(self):
        """Основной цикл мониторинга (синхронный метод)"""
        while self.running:
            try:
                self._collect_stats()
                time.sleep(5)  # Сбор данных каждые 5 секунд
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}", exc_info=True)
                # Продолжаем работу даже при ошибках
                time.sleep(5)

    def _collect_stats(self):
        """Сбор статистики трафика"""
        try:
            # Получение сетевых соединений (может требовать прав администратора)
            try:
                connections = psutil.net_connections(kind='inet')
            except (psutil.AccessDenied, PermissionError) as e:
                logger.debug(f"Access denied for net_connections: {e}")
                connections = []
            except Exception as e:
                logger.warning(f"Error getting connections: {e}")
                connections = []
            
            # Получение статистики по интерфейсам
            try:
                net_io = psutil.net_io_counters(pernic=True)
            except Exception as e:
                logger.warning(f"Error getting net_io_counters: {e}")
                net_io = {}
            
            # Обработка соединений
            for conn in connections:
                try:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        self._process_connection(conn)
                except Exception as e:
                    logger.debug(f"Error processing connection: {e}")
            
            # Обработка статистики интерфейсов
            for interface, stats in net_io.items():
                try:
                    self._process_interface_stats(interface, stats)
                except Exception as e:
                    logger.debug(f"Error processing interface {interface}: {e}")
                
        except Exception as e:
            logger.error(f"Error collecting stats: {e}", exc_info=True)

    def _process_connection(self, conn):
        """Обработка одного соединения (синхронный метод)"""
        try:
            # Получение процесса
            process = None
            process_name = "unknown"
            if conn.pid:
                try:
                    process = psutil.Process(conn.pid)
                    process_name = process.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                except Exception as e:
                    logger.debug(f"Error getting process {conn.pid}: {e}")

            # Получение адреса
            remote_addr = conn.raddr[0] if conn.raddr else None
            remote_port = conn.raddr[1] if conn.raddr else None
            
            if not remote_addr:
                return

            # Разрешение домена (синхронно, но быстро)
            domain = None
            try:
                domain = self._resolve_domain(remote_addr)
            except Exception as e:
                logger.debug(f"Error resolving domain for {remote_addr}: {e}")

            # Сохранение в БД
            self.db.save_connection(
                timestamp=datetime.now(),
                process_name=process_name,
                process_pid=conn.pid or 0,
                local_addr=conn.laddr[0] if conn.laddr else None,
                local_port=conn.laddr[1] if conn.laddr else None,
                remote_addr=remote_addr,
                remote_port=remote_port,
                domain=domain,
                protocol=conn.type.name if conn.type else "unknown"
            )

        except Exception as e:
            logger.debug(f"Error processing connection: {e}")

    def _process_interface_stats(self, interface: str, stats):
        """Обработка статистики интерфейса (синхронный метод)"""
        try:
            # Вычисление скорости (байт/сек)
            key = f"{interface}_bytes_sent"
            bytes_sent = stats.bytes_sent
            bytes_recv = stats.bytes_recv
            
            if key in self.last_stats:
                last_sent = self.last_stats[key]
                last_recv = self.last_stats.get(f"{interface}_bytes_recv", 0)
                
                # Скорость за последние 5 секунд
                sent_speed = (bytes_sent - last_sent) / 5.0
                recv_speed = (bytes_recv - last_recv) / 5.0
                
                self.db.save_traffic_stats(
                    timestamp=datetime.now(),
                    interface=interface,
                    bytes_sent=bytes_sent,
                    bytes_recv=bytes_recv,
                    sent_speed=sent_speed,
                    recv_speed=recv_speed,
                    packets_sent=stats.packets_sent,
                    packets_recv=stats.packets_recv
                )
            
            self.last_stats[key] = bytes_sent
            self.last_stats[f"{interface}_bytes_recv"] = bytes_recv

        except Exception as e:
            logger.error(f"Error processing interface stats: {e}", exc_info=True)

    def _resolve_domain(self, ip: str) -> Optional[str]:
        """Разрешение домена по IP адресу (синхронный метод)"""
        # Проверка кеша
        if ip in self.cache_domains:
            return self.cache_domains[ip]

        # Пропускаем локальные адреса
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                self.cache_domains[ip] = None
                return None
        except ValueError:
            return None

        # Синхронное разрешение домена
        try:
            hostname = socket.gethostbyaddr(ip)
            domain = hostname[0] if hostname else None
            self.cache_domains[ip] = domain
            return domain
        except (socket.herror, socket.gaierror):
            self.cache_domains[ip] = None
            return None
        except Exception as e:
            logger.debug(f"Failed to resolve domain for {ip}: {e}")
            self.cache_domains[ip] = None
            return None

    def get_traffic_stats(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        interface: Optional[str] = None
    ) -> List[Dict]:
        """Получение статистики трафика (синхронный метод)"""
        return self.db.get_traffic_stats(start_time, end_time, interface)

    def get_connections(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        process_name: Optional[str] = None
    ) -> List[Dict]:
        """Получение соединений (синхронный метод)"""
        return self.db.get_connections(start_time, end_time, process_name)

