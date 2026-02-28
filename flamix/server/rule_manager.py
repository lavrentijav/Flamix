"""Менеджер правил на сервере"""

import logging
import json
import uuid
from typing import List, Optional, Dict, Any
from datetime import datetime

from flamix.database.encrypted_db import EncryptedDB
from flamix.common.rule_format import FirewallRule

logger = logging.getLogger(__name__)


class RuleManager:
    """Управление правилами на сервере"""

    def __init__(self, db: EncryptedDB):
        """
        Инициализация менеджера правил

        Args:
            db: База данных
        """
        self.db = db

    def add_rule(self, client_id: str, rule: FirewallRule) -> str:
        """
        Добавление правила для клиента

        Args:
            client_id: ID клиента
            rule: Правило

        Returns:
            ID правила
        """
        checksum = rule.calculate_checksum()
        rule_data = json.dumps(rule.to_dict())

        self.db.execute_write(
            """
            INSERT OR REPLACE INTO client_rules 
            (id, client_id, rule_id, rule_data, version, checksum, updated_at, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                client_id,
                rule.id,
                rule_data,
                rule.version,
                checksum,
                datetime.utcnow().isoformat() + "Z",
                1 if rule.enabled else 0
            )
        )

        # Сохраняем в историю
        self._add_to_history(client_id, rule.id, "create", None, rule_data)

        # Обновляем checksum
        self._update_checksum(client_id, rule.id, checksum)

        logger.info(f"Added rule {rule.id} for client {client_id}")
        return rule.id

    def update_rule(self, client_id: str, rule: FirewallRule) -> bool:
        """
        Обновление правила

        Args:
            client_id: ID клиента
            rule: Обновленное правило

        Returns:
            True если успешно
        """
        # Получаем старое правило
        old_rule_data = self.get_rule(client_id, rule.id)
        if not old_rule_data:
            return False

        old_data = json.dumps(old_rule_data.to_dict()) if isinstance(old_rule_data, FirewallRule) else old_rule_data

        # Обновляем версию
        rule.version += 1
        rule.updated_at = datetime.utcnow().isoformat() + "Z"

        checksum = rule.calculate_checksum()
        rule_data = json.dumps(rule.to_dict())

        self.db.execute_write(
            """
            UPDATE client_rules 
            SET rule_data = ?, version = ?, checksum = ?, updated_at = ?, enabled = ?
            WHERE client_id = ? AND rule_id = ?
            """,
            (
                rule_data,
                rule.version,
                checksum,
                rule.updated_at,
                1 if rule.enabled else 0,
                client_id,
                rule.id
            )
        )

        # Сохраняем в историю
        self._add_to_history(client_id, rule.id, "update", old_data, rule_data)

        # Обновляем checksum
        self._update_checksum(client_id, rule.id, checksum)

        logger.info(f"Updated rule {rule.id} for client {client_id}")
        return True

    def delete_rule(self, client_id: str, rule_id: str) -> bool:
        """
        Удаление правила

        Args:
            client_id: ID клиента
            rule_id: ID правила

        Returns:
            True если успешно
        """
        # Получаем старое правило для истории
        old_rule = self.get_rule(client_id, rule_id)
        old_data = json.dumps(old_rule.to_dict()) if old_rule else None

        result = self.db.execute_write(
            "DELETE FROM client_rules WHERE client_id = ? AND rule_id = ?",
            (client_id, rule_id)
        )

        if old_rule:
            # Сохраняем в историю
            self._add_to_history(client_id, rule_id, "delete", old_data, None)

            # Удаляем checksum
            self.db.execute_write(
                "DELETE FROM rule_checksums WHERE client_id = ? AND rule_id = ?",
                (client_id, rule_id)
            )

        logger.info(f"Deleted rule {rule_id} for client {client_id}")
        return result > 0

    def get_rule(self, client_id: str, rule_id: str) -> Optional[FirewallRule]:
        """
        Получение правила

        Args:
            client_id: ID клиента
            rule_id: ID правила

        Returns:
            Правило или None
        """
        result = self.db.execute_one(
            """
            SELECT rule_data FROM client_rules 
            WHERE client_id = ? AND rule_id = ? AND enabled = 1
            """,
            (client_id, rule_id)
        )

        if not result:
            return None

        try:
            rule_dict = json.loads(result['rule_data'])
            return FirewallRule.from_dict(rule_dict)
        except Exception as e:
            logger.error(f"Error parsing rule: {e}")
            return None

    def get_all_rules(self, client_id: str) -> List[FirewallRule]:
        """
        Получение всех правил клиента

        Args:
            client_id: ID клиента

        Returns:
            Список правил
        """
        results = self.db.execute(
            """
            SELECT rule_data FROM client_rules 
            WHERE client_id = ? AND enabled = 1
            ORDER BY created_at
            """,
            (client_id,)
        )

        rules = []
        for result in results:
            try:
                rule_dict = json.loads(result['rule_data'])
                rules.append(FirewallRule.from_dict(rule_dict))
            except Exception as e:
                logger.error(f"Error parsing rule: {e}")
                continue

        return rules

    def get_rule_checksum(self, client_id: str, rule_id: str) -> Optional[str]:
        """
        Получение контрольной суммы правила

        Args:
            client_id: ID клиента
            rule_id: ID правила

        Returns:
            Контрольная сумма или None
        """
        result = self.db.execute_one(
            "SELECT checksum FROM rule_checksums WHERE client_id = ? AND rule_id = ?",
            (client_id, rule_id)
        )

        return result['checksum'] if result else None

    def compare_rules(self, client_id1: str, client_id2: str) -> Dict[str, Any]:
        """
        Сравнение правил между клиентами

        Args:
            client_id1: ID первого клиента
            client_id2: ID второго клиента

        Returns:
            Словарь с различиями
        """
        rules1 = {rule.id: rule for rule in self.get_all_rules(client_id1)}
        rules2 = {rule.id: rule for rule in self.get_all_rules(client_id2)}

        only_in_1 = list(rules1.keys() - rules2.keys())
        only_in_2 = list(rules2.keys() - rules1.keys())
        common = list(rules1.keys() & rules2.keys())

        different = []
        for rule_id in common:
            rule1 = rules1[rule_id]
            rule2 = rules2[rule_id]
            if rule1.calculate_checksum() != rule2.calculate_checksum():
                different.append({
                    'rule_id': rule_id,
                    'client1': rule1.to_dict(),
                    'client2': rule2.to_dict()
                })

        return {
            'only_in_client1': only_in_1,
            'only_in_client2': only_in_2,
            'different': different,
            'common_count': len(common) - len(different)
        }

    def _add_to_history(
        self,
        client_id: str,
        rule_id: str,
        action: str,
        old_data: Optional[str],
        new_data: Optional[str]
    ):
        """Добавление записи в историю"""
        self.db.execute_write(
            """
            INSERT INTO rule_history 
            (rule_id, client_id, action, old_data, new_data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                rule_id,
                client_id,
                action,
                old_data,
                new_data,
                datetime.utcnow().isoformat() + "Z"
            )
        )

    def _update_checksum(self, client_id: str, rule_id: str, checksum: str):
        """Обновление контрольной суммы"""
        self.db.execute_write(
            """
            INSERT OR REPLACE INTO rule_checksums 
            (client_id, rule_id, checksum, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                client_id,
                rule_id,
                checksum,
                datetime.utcnow().isoformat() + "Z"
            )
        )
