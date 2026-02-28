"""Синхронизация правил с сервером"""

import asyncio
import logging
from typing import Dict, List, Optional
from datetime import datetime

from flamix.client.client import FlamixClient
from flamix.client.rule_converter import RuleConverter
from flamix.common.rule_format import FirewallRule

logger = logging.getLogger(__name__)


class RuleSync:
    """Синхронизация правил между клиентом и сервером"""

    def __init__(
        self,
        client: FlamixClient,
        rule_converter: RuleConverter,
        sync_interval: int = 30
    ):
        """
        Инициализация синхронизации

        Args:
            client: Клиент для связи с сервером
            rule_converter: Конвертер правил
            sync_interval: Интервал синхронизации в секундах
        """
        self.client = client
        self.rule_converter = rule_converter
        self.sync_interval = sync_interval
        self.running = False
        self.synced_rules: Dict[str, FirewallRule] = {}  # rule_id -> rule
        self.applied_rules: Dict[str, str] = {}  # rule_id -> plugin_id

    async def start(self):
        """Запуск синхронизации"""
        self.running = True
        asyncio.create_task(self._sync_loop())

    async def stop(self):
        """Остановка синхронизации"""
        self.running = False

    async def sync(self) -> List[FirewallRule]:
        """
        Синхронизация правил с сервером

        Returns:
            Список синхронизированных правил
        """
        if not self.client.connected:
            logger.warning("Client not connected, cannot sync")
            return []

        try:
            # Получаем правила с сервера
            rules = await self.client.sync_rules()

            # Применяем новые/измененные правила
            for rule in rules:
                await self._apply_rule_if_needed(rule)

            # Удаляем правила, которых больше нет на сервере
            server_rule_ids = {rule.id for rule in rules}
            local_rule_ids = set(self.synced_rules.keys())
            deleted_rule_ids = local_rule_ids - server_rule_ids

            for rule_id in deleted_rule_ids:
                await self._remove_rule(rule_id)

            self.synced_rules = {rule.id: rule for rule in rules}
            logger.info(f"Synced {len(rules)} rules")

            return rules

        except Exception as e:
            logger.error(f"Error syncing rules: {e}", exc_info=True)
            return []

    async def _apply_rule_if_needed(self, rule: FirewallRule):
        """
        Применение правила если оно изменилось

        Args:
            rule: Правило для применения
        """
        existing_rule = self.synced_rules.get(rule.id)

        # Проверяем, изменилось ли правило
        if existing_rule:
            existing_checksum = existing_rule.calculate_checksum()
            new_checksum = rule.calculate_checksum()
            if existing_checksum == new_checksum:
                # Правило не изменилось
                return

        # Определяем плагин для применения
        # Пока что используем первый доступный плагин
        # В реальной версии это должно быть настраиваемо
        plugin_id = self._get_plugin_for_rule(rule)
        if not plugin_id:
            logger.warning(f"No plugin available for rule {rule.id}")
            return

        # Применяем правило
        result = await self.rule_converter.apply_rule(rule, plugin_id)
        if result.get('success', False):
            self.applied_rules[rule.id] = plugin_id
            logger.info(f"Applied rule {rule.id} via plugin {plugin_id}")
        else:
            logger.error(f"Failed to apply rule {rule.id}: {result.get('error', 'Unknown error')}")

    async def _remove_rule(self, rule_id: str):
        """
        Удаление правила

        Args:
            rule_id: ID правила
        """
        if rule_id in self.synced_rules:
            del self.synced_rules[rule_id]

        if rule_id in self.applied_rules:
            # Здесь должна быть логика удаления правила через плагин
            # Пока что просто удаляем из словаря
            del self.applied_rules[rule_id]
            logger.info(f"Removed rule {rule_id}")

    def _get_plugin_for_rule(self, rule: FirewallRule) -> Optional[str]:
        """
        Определение плагина для правила

        Args:
            rule: Правило

        Returns:
            ID плагина или None
        """
        # Упрощенная логика: используем первый доступный плагин
        # В реальной версии это должно быть настраиваемо
        if self.rule_converter.plugin_manager:
            plugins = self.rule_converter.plugin_manager.list_plugins()
            for plugin in plugins:
                if plugin.get('enabled'):
                    return plugin.get('id')
        return None

    async def _sync_loop(self):
        """Цикл синхронизации"""
        while self.running:
            try:
                await asyncio.sleep(self.sync_interval)
                if self.client.connected:
                    await self.sync()
            except Exception as e:
                logger.error(f"Error in sync loop: {e}", exc_info=True)
