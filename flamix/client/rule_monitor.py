"""Мониторинг изменений правил на клиенте"""

import asyncio
import logging
from typing import Dict, Optional, List
from datetime import datetime

from flamix.client.client import FlamixClient
from flamix.client.rule_converter import RuleConverter
from flamix.common.rule_format import FirewallRule

logger = logging.getLogger(__name__)


class RuleMonitor:
    """Мониторинг изменений правил на клиенте"""

    def __init__(
        self,
        client: FlamixClient,
        rule_converter: RuleConverter,
        check_interval: int = 10
    ):
        """
        Инициализация монитора

        Args:
            client: Клиент для связи с сервером
            rule_converter: Конвертер правил
            check_interval: Интервал проверки в секундах
        """
        self.client = client
        self.rule_converter = rule_converter
        self.check_interval = check_interval
        self.running = False
        self.known_checksums: Dict[str, str] = {}  # rule_id -> checksum
        self.pending_changes: Dict[str, FirewallRule] = {}  # rule_id -> rule

    async def start(self):
        """Запуск мониторинга"""
        self.running = True
        asyncio.create_task(self._monitor_loop())

    async def stop(self):
        """Остановка мониторинга"""
        self.running = False

    async def _monitor_loop(self):
        """Цикл мониторинга"""
        while self.running:
            try:
                await asyncio.sleep(self.check_interval)
                if self.client.connected:
                    await self._check_rules()
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}", exc_info=True)

    async def _check_rules(self):
        """Проверка правил на изменения"""
        # Получаем текущие правила с фаервола через плагины
        current_rules = await self._get_current_firewall_rules()

        # Сравниваем с известными правилами
        for rule in current_rules:
            rule_id = rule.id
            current_checksum = rule.calculate_checksum()
            known_checksum = self.known_checksums.get(rule_id)

            if known_checksum and current_checksum != known_checksum:
                # Правило изменилось!
                logger.warning(f"Rule {rule_id} changed manually!")
                await self._handle_rule_change(rule, known_checksum)

            # Обновляем известную checksum
            self.known_checksums[rule_id] = current_checksum

    async def _get_current_firewall_rules(self) -> List[FirewallRule]:
        """
        Получение текущих правил с фаервола

        Returns:
            Список правил
        """
        rules = []

        if not self.rule_converter.plugin_manager:
            return rules

        # Получаем все плагины
        plugins = self.rule_converter.plugin_manager.list_plugins()
        for plugin in plugins:
            if not plugin.get('enabled'):
                continue

            plugin_id = plugin.get('id')
            plugin_instance = self.rule_converter.plugin_manager.plugins.get(plugin_id, {}).get('instance')

            if not plugin_instance:
                continue

            # Пытаемся получить правила из плагина
            # Это зависит от реализации плагина
            # Пока что используем правила из клиента
            for rule_id, rule in self.client.rules.items():
                rules.append(rule)

        return rules

    async def _handle_rule_change(self, changed_rule: FirewallRule, old_checksum: str):
        """
        Обработка изменения правила

        Args:
            changed_rule: Измененное правило
            old_checksum: Старая контрольная сумма
        """
        # Получаем оригинальное правило с сервера
        original_rule = self.client.rules.get(changed_rule.id)
        if not original_rule:
            logger.warning(f"Original rule {changed_rule.id} not found")
            return

        # Откатываем изменение - восстанавливаем оригинальное правило
        logger.info(f"Rolling back manual change to rule {changed_rule.id}")
        await self._rollback_rule(changed_rule.id, original_rule)

        # Отправляем запрос на авторизацию изменения
        logger.info(f"Requesting authorization for rule {changed_rule.id} change")
        approved = await self.client.request_rule_update(changed_rule)

        if approved:
            logger.info(f"Rule {changed_rule.id} change approved by server")
            # Обновляем известную checksum
            self.known_checksums[changed_rule.id] = changed_rule.calculate_checksum()
        else:
            logger.warning(f"Rule {changed_rule.id} change rejected by server")
            # Правило уже откачено, ничего не делаем

    async def _rollback_rule(self, rule_id: str, original_rule: FirewallRule):
        """
        Откат правила к оригинальному состоянию

        Args:
            rule_id: ID правила
            original_rule: Оригинальное правило
        """
        # Определяем плагин
        plugin_id = self._get_plugin_for_rule(original_rule)
        if not plugin_id:
            logger.warning(f"No plugin available for rollback of rule {rule_id}")
            return

        # Применяем оригинальное правило
        result = await self.rule_converter.apply_rule(original_rule, plugin_id)
        if result.get('success', False):
            logger.info(f"Rolled back rule {rule_id} to original state")
        else:
            logger.error(f"Failed to rollback rule {rule_id}: {result.get('error', 'Unknown error')}")

    def _get_plugin_for_rule(self, rule: FirewallRule) -> Optional[str]:
        """
        Определение плагина для правила

        Args:
            rule: Правило

        Returns:
            ID плагина или None
        """
        if self.rule_converter.plugin_manager:
            plugins = self.rule_converter.plugin_manager.list_plugins()
            for plugin in plugins:
                if plugin.get('enabled'):
                    return plugin.get('id')
        return None

    def update_known_checksum(self, rule_id: str, checksum: str):
        """
        Обновление известной контрольной суммы правила

        Args:
            rule_id: ID правила
            checksum: Контрольная сумма
        """
        self.known_checksums[rule_id] = checksum

    def initialize_checksums(self, rules: List[FirewallRule]):
        """
        Инициализация контрольных сумм для правил

        Args:
            rules: Список правил
        """
        for rule in rules:
            self.known_checksums[rule.id] = rule.calculate_checksum()
