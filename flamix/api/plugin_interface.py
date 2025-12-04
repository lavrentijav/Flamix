"""Интерфейс для плагинов"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class PluginInterface(ABC):
    """Базовый интерфейс для всех плагинов Flamix"""

    def __init__(self):
        self.plugin_id: Optional[str] = None
        self.core_api: Optional[Any] = None  # CoreAPI instance

    @abstractmethod
    async def on_install(self):
        """Вызывается при установке плагина"""
        pass

    @abstractmethod
    async def on_enable(self):
        """Вызывается при включении плагина"""
        pass

    @abstractmethod
    async def on_init(self, core_api):
        """
        Вызывается при инициализации плагина
        
        Args:
            core_api: Экземпляр CoreAPI для взаимодействия с ядром
        """
        pass

    @abstractmethod
    async def on_disable(self):
        """Вызывается при отключении плагина"""
        pass

    @abstractmethod
    async def on_uninstall(self):
        """Вызывается при удалении плагина"""
        pass

    @abstractmethod
    async def get_health(self) -> Dict[str, Any]:
        """
        Проверка здоровья плагина
        
        Returns:
            dict с ключом "status": "ok" | "degraded" | "critical"
        """
        pass

    @abstractmethod
    async def apply_rule(self, rule: Dict[str, Any]):
        """
        Применение правила firewall
        
        Args:
            rule: Словарь с параметрами правила
        """
        pass

