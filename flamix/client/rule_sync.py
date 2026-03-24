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
        logger.info("=" * 60)
        logger.info("RuleSync.sync() called")
        logger.info(f"Client connected: {self.client.connected}")
        logger.info(f"Current synced rules count: {len(self.synced_rules)}")
        logger.info(f"Current applied rules count: {len(self.applied_rules)}")
        logger.info("=" * 60)
        
        if not self.client.connected:
            logger.warning("Client not connected, cannot sync")
            logger.warning(f"Connection status: connected={self.client.connected}")
            return []

        try:
            # Получаем правила с сервера
            logger.info("Calling client.sync_rules()...")
            rules = await self.client.sync_rules()
            logger.info(f"client.sync_rules() returned {len(rules)} rules")

            if not rules:
                logger.warning("No rules received from server!")
                logger.warning("This could mean:")
                logger.warning("  - Server has no rules configured for this client")
                logger.warning("  - Server returned empty rules list")
                logger.warning("  - Error occurred during rule retrieval")
                return []

            logger.info(f"Processing {len(rules)} rules...")
            
            # Применяем новые/измененные правила
            applied_count = 0
            skipped_count = 0
            for idx, rule in enumerate(rules):
                logger.debug(f"Processing rule {idx + 1}/{len(rules)}: id={rule.id}, name={rule.name}")
                try:
                    result = await self._apply_rule_if_needed(rule)
                    if result:
                        applied_count += 1
                    else:
                        skipped_count += 1
                except Exception as e:
                    logger.error(f"Error applying rule {rule.id}: {e}", exc_info=True)
                    skipped_count += 1

            logger.info(f"Rule application summary: applied={applied_count}, skipped={skipped_count}")

            # Удаляем правила, которых больше нет на сервере
            server_rule_ids = {rule.id for rule in rules}
            local_rule_ids = set(self.synced_rules.keys())
            deleted_rule_ids = local_rule_ids - server_rule_ids

            logger.info(f"Rule deletion check: server={len(server_rule_ids)}, local={len(local_rule_ids)}, to_delete={len(deleted_rule_ids)}")
            
            if deleted_rule_ids:
                logger.info(f"Removing {len(deleted_rule_ids)} deleted rules: {list(deleted_rule_ids)}")
                for rule_id in deleted_rule_ids:
                    await self._remove_rule(rule_id)
            else:
                logger.debug("No rules to delete")

            self.synced_rules = {rule.id: rule for rule in rules}
            logger.info("=" * 60)
            logger.info(f"Sync completed successfully:")
            logger.info(f"  - Total rules synced: {len(rules)}")
            logger.info(f"  - Rules applied: {applied_count}")
            logger.info(f"  - Rules skipped: {skipped_count}")
            logger.info(f"  - Rules deleted: {len(deleted_rule_ids)}")
            logger.info(f"  - Final synced rules count: {len(self.synced_rules)}")
            logger.info("=" * 60)

            return rules

        except Exception as e:
            logger.error("=" * 60)
            logger.error(f"ERROR in RuleSync.sync(): {e}", exc_info=True)
            logger.error("=" * 60)
            return []

    async def _apply_rule_if_needed(self, rule: FirewallRule):
        """
        Применение правила если оно изменилось

        Args:
            rule: Правило для применения
        """
        logger.debug(f"_apply_rule_if_needed called for rule: id={rule.id}, name={rule.name}")
        
        existing_rule = self.synced_rules.get(rule.id)

        # Проверяем, изменилось ли правило
        if existing_rule:
            logger.debug(f"Existing rule found: id={existing_rule.id}")
            existing_checksum = existing_rule.calculate_checksum()
            new_checksum = rule.calculate_checksum()
            logger.debug(f"Checksums: existing={existing_checksum}, new={new_checksum}")
            
            if existing_checksum == new_checksum:
                # Правило не изменилось
                logger.debug(f"Rule {rule.id} unchanged (checksums match), skipping application")
                return False
            else:
                logger.info(f"Rule {rule.id} changed (checksums differ), will apply")
        else:
            logger.info(f"New rule {rule.id} (not in synced_rules), will apply")

        # Определяем плагин для применения
        # Пока что используем первый доступный плагин
        # В реальной версии это должно быть настраиваемо
        logger.debug("Determining plugin for rule...")
        plugin_id = self._get_plugin_for_rule(rule)
        if not plugin_id:
            logger.warning(f"No plugin available for rule {rule.id}")
            logger.warning(f"Rule details: name={rule.name}, action={rule.action}, direction={rule.direction}")
            return False
        
        logger.info(f"Using plugin {plugin_id} for rule {rule.id}")

        # Применяем правило
        logger.debug(f"Calling rule_converter.apply_rule(rule_id={rule.id}, plugin_id={plugin_id})...")
        try:
            result = await self.rule_converter.apply_rule(rule, plugin_id)
            logger.debug(f"apply_rule result: {result}")
            
            if result.get('success', False):
                self.applied_rules[rule.id] = plugin_id
                logger.info(f"✓ Successfully applied rule {rule.id} via plugin {plugin_id}")
                return True
            else:
                error_msg = result.get('error', 'Unknown error')
                logger.error(f"✗ Failed to apply rule {rule.id}: {error_msg}")
                logger.error(f"  Plugin: {plugin_id}")
                logger.error(f"  Rule details: name={rule.name}, action={rule.action}")
                return False
        except Exception as e:
            logger.error(f"Exception while applying rule {rule.id}: {e}", exc_info=True)
            return False

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
        return self.rule_converter.get_preferred_plugin_id()

    async def _sync_loop(self):
        """Цикл синхронизации"""
        while self.running:
            try:
                await asyncio.sleep(self.sync_interval)
                if self.client.connected:
                    await self.sync()
            except Exception as e:
                logger.error(f"Error in sync loop: {e}", exc_info=True)
