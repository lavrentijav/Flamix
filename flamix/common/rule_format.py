"""Унифицированный формат правил"""

from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from pydantic import BaseModel, Field, validator
import uuid


class RuleTargets(BaseModel):
    """Целевые объекты правила"""

    ips: List[str] = Field(default_factory=list, description="IP адреса и подсети")
    domains: List[str] = Field(default_factory=list, description="Домены и поддомены")
    ports: List[str] = Field(default_factory=list, description="Порты (например, '80,443' или '8080-8090')")

    @validator('ips')
    def validate_ips(cls, v):
        """Валидация IP адресов"""
        from netaddr import IPAddress, IPNetwork
        validated = []
        for ip in v:
            try:
                if '/' in ip:
                    IPNetwork(ip)
                else:
                    IPAddress(ip)
                validated.append(ip)
            except Exception:
                raise ValueError(f"Invalid IP address or network: {ip}")
        return validated

    @validator('domains')
    def validate_domains(cls, v):
        """Валидация доменов"""
        import re
        domain_pattern = re.compile(
            r'^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        validated = []
        for domain in v:
            if domain_pattern.match(domain) or domain == '*':
                validated.append(domain)
            else:
                raise ValueError(f"Invalid domain: {domain}")
        return validated

    @validator('ports')
    def validate_ports(cls, v):
        """Валидация портов"""
        import re
        port_pattern = re.compile(r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$|^any$')
        validated = []
        for port in v:
            port_lower = port.lower()
            if port_pattern.match(port) or port_lower == 'any':
                validated.append(port)
            else:
                raise ValueError(f"Invalid port specification: {port}")
        return validated


class FirewallRule(BaseModel):
    """Унифицированный формат правила фаервола"""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Уникальный ID правила")
    name: str = Field(..., description="Имя правила")
    action: str = Field(..., description="Действие: allow или block")
    direction: str = Field(..., description="Направление: inbound или outbound")
    targets: RuleTargets = Field(default_factory=RuleTargets, description="Целевые объекты")
    protocol: str = Field(default="TCP", description="Протокол: TCP, UDP, ICMP, ANY")
    enabled: bool = Field(default=True, description="Включено ли правило")
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    updated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    version: int = Field(default=1, description="Версия правила")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Дополнительные метаданные")

    @validator('action')
    def validate_action(cls, v):
        """Валидация действия"""
        if v.lower() not in ['allow', 'block']:
            raise ValueError("Action must be 'allow' or 'block'")
        return v.lower()

    @validator('direction')
    def validate_direction(cls, v):
        """Валидация направления"""
        if v.lower() not in ['inbound', 'outbound']:
            raise ValueError("Direction must be 'inbound' or 'outbound'")
        return v.lower()

    @validator('protocol')
    def validate_protocol(cls, v):
        """Валидация протокола"""
        if v.upper() not in ['TCP', 'UDP', 'ICMP', 'ANY']:
            raise ValueError("Protocol must be 'TCP', 'UDP', 'ICMP', or 'ANY'")
        return v.upper()

    def to_dict(self) -> Dict[str, Any]:
        """Преобразование в словарь"""
        return self.dict()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FirewallRule':
        """Создание из словаря"""
        return cls(**data)

    def calculate_checksum(self) -> str:
        """Вычисление контрольной суммы правила"""
        import hashlib
        import json
        # Сортируем ключи для консистентности
        rule_dict = self.dict()
        rule_dict.pop('updated_at', None)  # Исключаем updated_at из checksum
        rule_json = json.dumps(rule_dict, sort_keys=True)
        return hashlib.sha256(rule_json.encode()).hexdigest()

    def matches_domain(self, domain: str) -> bool:
        """
        Проверка, соответствует ли правило домену

        Args:
            domain: Домен для проверки

        Returns:
            True если соответствует
        """
        for rule_domain in self.targets.domains:
            if rule_domain == '*':
                return True
            if rule_domain.startswith('*.'):
                # Поддомены
                base_domain = rule_domain[2:]
                if domain == base_domain or domain.endswith('.' + base_domain):
                    return True
            elif rule_domain == domain:
                return True
        return False

    def matches_ip(self, ip: str) -> bool:
        """
        Проверка, соответствует ли правило IP адресу

        Args:
            ip: IP адрес для проверки

        Returns:
            True если соответствует
        """
        from netaddr import IPAddress, IPNetwork
        try:
            ip_obj = IPAddress(ip)
            for rule_ip in self.targets.ips:
                if '/' in rule_ip:
                    network = IPNetwork(rule_ip)
                    if ip_obj in network:
                        return True
                else:
                    if str(ip_obj) == rule_ip:
                        return True
        except Exception:
            return False
        return False

    def matches_port(self, port: int) -> bool:
        """
        Проверка, соответствует ли правило порту

        Args:
            port: Порт для проверки

        Returns:
            True если соответствует
        """
        for port_spec in self.targets.ports:
            if port_spec.lower() == 'any':
                return True
            # Обработка диапазонов и списков
            for part in port_spec.split(','):
                part = part.strip()
                if '-' in part:
                    # Диапазон
                    start, end = map(int, part.split('-'))
                    if start <= port <= end:
                        return True
                else:
                    # Один порт
                    if int(part) == port:
                        return True
        return False
