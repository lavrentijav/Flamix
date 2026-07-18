"""Базовый интерфейс для плагинов Flamix"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class PluginInterface(ABC):
    """Базовый интерфейс для всех плагинов Flamix"""
    
    plugin_id: Optional[str] = None
    core_api: Optional[Any] = None
    
    async def on_install(self):
        """Вызывается при установке плагина"""
        pass
    
    async def on_enable(self):
        """Вызывается при включении плагина"""
        pass
    
    async def on_init(self, core_api):
        """Вызывается при инициализации плагина"""
        self.core_api = core_api
    
    async def on_disable(self):
        """Вызывается при отключении плагина"""
        pass
    
    async def on_uninstall(self):
        """Вызывается при удалении плагина"""
        pass
    
    async def get_health(self) -> Dict[str, Any]:
        """
        Проверка состояния плагина
        
        Returns:
            dict с информацией о состоянии плагина
        """
        return {"status": "ok"}
    
    @abstractmethod
    async def apply_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """
        Применение правила файрвола
        
        Args:
            rule: Словарь с параметрами правила (name, direction, action, protocol, port, ip и т.д.)
            
        Returns:
            dict с результатом применения правила (success, rule_id, message)
        """
        pass
