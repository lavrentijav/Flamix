"""Авторизация изменений правил на сервере"""

import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

from flamix.database.encrypted_db import EncryptedDB
from flamix.server.rule_manager import RuleManager
from flamix.common.rule_format import FirewallRule

logger = logging.getLogger(__name__)


class AuthorizationPolicy:
    """Политика авторизации"""

    def __init__(
        self,
        allow_manual_changes: bool = False,
        require_approval: bool = True,
        auto_approve_whitelist: list = None,
        max_changes_per_hour: int = 10,
        validation_rules: list = None
    ):
        """
        Инициализация политики

        Args:
            allow_manual_changes: Разрешены ли ручные изменения
            require_approval: Требуется ли одобрение
            auto_approve_whitelist: Список правил для автоматического одобрения
            max_changes_per_hour: Максимум изменений в час
            validation_rules: Правила валидации
        """
        self.allow_manual_changes = allow_manual_changes
        self.require_approval = require_approval
        self.auto_approve_whitelist = auto_approve_whitelist or []
        self.max_changes_per_hour = max_changes_per_hour
        self.validation_rules = validation_rules or []


class RuleAuthorization:
    """Система авторизации изменений правил"""

    def __init__(self, db: EncryptedDB, rule_manager: RuleManager):
        """
        Инициализация системы авторизации

        Args:
            db: База данных
            rule_manager: Менеджер правил
        """
        self.db = db
        self.rule_manager = rule_manager
        self.policies: Dict[str, AuthorizationPolicy] = {}  # client_id -> policy

    def set_policy(self, client_id: str, policy: AuthorizationPolicy):
        """
        Установка политики для клиента

        Args:
            client_id: ID клиента
            policy: Политика авторизации
        """
        self.policies[client_id] = policy

    def get_policy(self, client_id: str) -> AuthorizationPolicy:
        """
        Получение политики для клиента

        Args:
            client_id: ID клиента

        Returns:
            Политика авторизации (по умолчанию строгая)
        """
        return self.policies.get(
            client_id,
            AuthorizationPolicy()  # Строгая политика по умолчанию
        )

    async def authorize_rule_change(
        self,
        client_id: str,
        rule_id: str,
        old_rule: Optional[FirewallRule],
        new_rule: FirewallRule,
        change_source: str = "manual"
    ) -> Tuple[bool, Optional[str]]:
        """
        Авторизация изменения правила

        Args:
            client_id: ID клиента
            rule_id: ID правила
            old_rule: Старое правило
            new_rule: Новое правило
            change_source: Источник изменения

        Returns:
            Кортеж (одобрено, причина отклонения)
        """
        policy = self.get_policy(client_id)

        # Проверка разрешения ручных изменений
        if change_source == "manual" and not policy.allow_manual_changes:
            return False, "Manual changes are not allowed for this client"

        # Проверка лимита изменений
        if not self._check_change_limit(client_id):
            return False, f"Change limit exceeded (max {policy.max_changes_per_hour} per hour)"

        # Валидация правила
        validation_result = self._validate_rule(new_rule, policy)
        if not validation_result[0]:
            return False, validation_result[1]

        # Проверка конфликтов
        conflict_result = self._check_conflicts(client_id, new_rule)
        if conflict_result[0]:
            return False, f"Rule conflicts with existing rules: {conflict_result[1]}"

        # Проверка на автоматическое одобрение
        if rule_id in policy.auto_approve_whitelist:
            return True, None

        # Если требуется одобрение, сохраняем запрос
        if policy.require_approval:
            self._save_change_request(client_id, rule_id, old_rule, new_rule, change_source)
            return False, "Approval required (pending)"

        # Автоматическое одобрение
        return True, None

    def _check_change_limit(self, client_id: str) -> bool:
        """
        Проверка лимита изменений

        Args:
            client_id: ID клиента

        Returns:
            True если лимит не превышен
        """
        policy = self.get_policy(client_id)
        from datetime import timedelta

        cutoff_time = (datetime.utcnow() - timedelta(hours=1)).isoformat() + "Z"

        result = self.db.execute_one(
            """
            SELECT COUNT(*) as count FROM rule_change_requests
            WHERE client_id = ? AND requested_at > ? AND status = 'approved'
            """,
            (client_id, cutoff_time)
        )

        count = result['count'] if result else 0
        return count < policy.max_changes_per_hour

    def _validate_rule(self, rule: FirewallRule, policy: AuthorizationPolicy) -> Tuple[bool, Optional[str]]:
        """
        Валидация правила

        Args:
            rule: Правило для валидации
            policy: Политика

        Returns:
            Кортеж (валидно, причина отклонения)
        """
        # Проверка правил валидации из политики
        for validation_rule in policy.validation_rules:
            if validation_rule.get('type') == 'block_critical_ips':
                critical_ips = validation_rule.get('ips', [])
                for rule_ip in rule.targets.ips:
                    if rule_ip in critical_ips and rule.action == 'block':
                        return False, f"Cannot block critical IP: {rule_ip}"

        # Базовая валидация
        if not rule.name:
            return False, "Rule name is required"

        if not rule.targets.ips and not rule.targets.domains and not rule.targets.ports:
            return False, "Rule must have at least one target"

        return True, None

    def _check_conflicts(self, client_id: str, rule: FirewallRule) -> Tuple[bool, Optional[str]]:
        """
        Проверка конфликтов с существующими правилами

        Args:
            client_id: ID клиента
            rule: Правило для проверки

        Returns:
            Кортеж (есть конфликт, описание конфликта)
        """
        existing_rules = self.rule_manager.get_all_rules(client_id)

        for existing_rule in existing_rules:
            if existing_rule.id == rule.id:
                continue

            # Проверка на противоположные действия для одних и тех же целей
            if rule.action != existing_rule.action:
                # Проверяем пересечение целей
                if self._targets_overlap(rule, existing_rule):
                    return True, f"Conflicts with rule {existing_rule.id}"

        return False, None

    def _targets_overlap(self, rule1: FirewallRule, rule2: FirewallRule) -> bool:
        """
        Проверка пересечения целей правил

        Args:
            rule1: Первое правило
            rule2: Второе правило

        Returns:
            True если есть пересечение
        """
        # Проверка IP
        for ip1 in rule1.targets.ips:
            for ip2 in rule2.targets.ips:
                if ip1 == ip2:
                    return True

        # Проверка доменов
        for domain1 in rule1.targets.domains:
            for domain2 in rule2.targets.domains:
                if domain1 == domain2 or domain1.startswith('*.') and domain2.endswith(domain1[2:]):
                    return True

        # Проверка портов
        for port1 in rule1.targets.ports:
            for port2 in rule2.targets.ports:
                if port1 == port2 or port1 == 'any' or port2 == 'any':
                    return True

        return False

    def _save_change_request(
        self,
        client_id: str,
        rule_id: str,
        old_rule: Optional[FirewallRule],
        new_rule: FirewallRule,
        change_source: str
    ):
        """Сохранение запроса на изменение"""
        import json
        import uuid

        old_rule_data = json.dumps(old_rule.to_dict()) if old_rule else None
        new_rule_data = json.dumps(new_rule.to_dict())

        self.db.execute_write(
            """
            INSERT INTO rule_change_requests
            (id, client_id, rule_id, old_rule, new_rule, change_source, status, requested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                client_id,
                rule_id,
                old_rule_data,
                new_rule_data,
                change_source,
                'pending',
                datetime.utcnow().isoformat() + "Z"
            )
        )

    def approve_request(self, request_id: str, reviewer: str) -> bool:
        """
        Одобрение запроса на изменение

        Args:
            request_id: ID запроса
            reviewer: Имя одобряющего

        Returns:
            True если успешно
        """
        request = self.db.execute_one(
            "SELECT * FROM rule_change_requests WHERE id = ? AND status = 'pending'",
            (request_id,)
        )

        if not request:
            return False

        import json
        new_rule_data = json.loads(request['new_rule'])
        new_rule = FirewallRule.from_dict(new_rule_data)

        # Применяем правило
        self.rule_manager.update_rule(request['client_id'], new_rule)

        # Обновляем статус запроса
        self.db.execute_write(
            """
            UPDATE rule_change_requests
            SET status = 'approved', reviewed_at = ?, reviewed_by = ?
            WHERE id = ?
            """,
            (
                datetime.utcnow().isoformat() + "Z",
                reviewer,
                request_id
            )
        )

        return True

    def reject_request(self, request_id: str, reviewer: str, reason: str) -> bool:
        """
        Отклонение запроса на изменение

        Args:
            request_id: ID запроса
            reviewer: Имя отклоняющего
            reason: Причина отклонения

        Returns:
            True если успешно
        """
        self.db.execute_write(
            """
            UPDATE rule_change_requests
            SET status = 'rejected', reviewed_at = ?, reviewed_by = ?, reason = ?
            WHERE id = ?
            """,
            (
                datetime.utcnow().isoformat() + "Z",
                reviewer,
                reason,
                request_id
            )
        )

        return True
