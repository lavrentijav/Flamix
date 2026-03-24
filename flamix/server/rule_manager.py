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
        # Нормализуем client_id как строку
        client_id_str = str(client_id)
        logger.info(f"add_rule called: client_id='{client_id_str}' (type: {type(client_id_str).__name__}), rule_id='{rule.id}', enabled={rule.enabled}")
        
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
                client_id_str,
                rule.id,
                rule_data,
                rule.version,
                checksum,
                datetime.utcnow().isoformat() + "Z",
                1 if rule.enabled else 0
            )
        )

        # Сохраняем в историю
        self._add_to_history(client_id_str, rule.id, "create", None, rule_data)

        # Обновляем checksum
        self._update_checksum(client_id_str, rule.id, checksum)

        logger.info(f"Successfully added rule {rule.id} for client {client_id_str} (enabled={rule.enabled})")
        
        # Проверим, что правило действительно сохранено
        saved_rule = self.get_rule(client_id_str, rule.id)
        if saved_rule:
            logger.info(f"Verified: rule {rule.id} exists in database for client {client_id_str}")
        else:
            logger.error(f"ERROR: rule {rule.id} was not found in database after saving for client {client_id_str}")
        
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
        logger.info(f"get_all_rules called for client_id={client_id} (type: {type(client_id).__name__})")
        
        # Убеждаемся, что client_id - строка
        client_id_str = str(client_id) if client_id is not None else None
        if client_id_str is None:
            logger.error("client_id is None in get_all_rules!")
            return []
        
        logger.debug(f"Querying database for client_id='{client_id_str}'")
        results = self.db.execute(
            """
            SELECT rule_data FROM client_rules 
            WHERE client_id = ? AND enabled = 1
            ORDER BY created_at, rule_id
            """,
            (client_id_str,)
        )

        # Преобразуем результаты в список для подсчета
        results_list = list(results)
        logger.info(f"Database query returned {len(results_list)} rows for client_id='{client_id_str}'")
        
        # Если результатов нет, проверим, есть ли вообще правила для этого клиента (включая отключенные)
        if len(results_list) == 0:
            all_results = self.db.execute(
                """
                SELECT COUNT(*) as count FROM client_rules 
                WHERE client_id = ?
                """,
                (client_id_str,)
            )
            all_count = list(all_results)
            if all_count and all_count[0].get('count', 0) > 0:
                logger.warning(f"Found {all_count[0].get('count', 0)} rules for client_id='{client_id_str}', but all are disabled (enabled=0)")
            else:
                logger.warning(f"No rules found in database for client_id='{client_id_str}'")
                
                # Дополнительная диагностика: проверим все client_id в базе
                all_clients = self.db.execute(
                    """
                    SELECT DISTINCT client_id FROM client_rules
                    """
                )
                client_list = [row['client_id'] for row in all_clients]
                if client_list:
                    logger.info(f"Available client_ids in database: {client_list}")
                    logger.info(f"Requested client_id='{client_id_str}' (type: {type(client_id_str).__name__})")
                    # Проверим, есть ли совпадение при сравнении строк
                    for db_client_id in client_list:
                        if str(db_client_id) == str(client_id_str):
                            logger.warning(f"Found matching client_id in database: '{db_client_id}' (type: {type(db_client_id).__name__})")
                else:
                    logger.warning("No rules found in database for any client")

        rules = []
        for idx, result in enumerate(results_list):
            try:
                rule_dict = json.loads(result['rule_data'])
                rule = FirewallRule.from_dict(rule_dict)
                rules.append(rule)
                logger.debug(f"Successfully parsed rule {idx + 1}/{len(results_list)}: id={rule.id}, name={rule.name}")
            except Exception as e:
                logger.error(f"Error parsing rule {idx + 1}: {e}", exc_info=True)
                continue

        logger.info(f"get_all_rules returning {len(rules)} rules for client_id='{client_id_str}'")
        return rules

    def restore_rule(self, client_id: str, rule: FirewallRule) -> bool:
        """
        Restore a rule snapshot without changing its stored version.

        This is used by authorization rollback paths where we need an exact
        recovery of the previous server-side rule record.
        """
        client_id_str = str(client_id)
        old_rule = self.get_rule(client_id_str, rule.id)
        old_data = json.dumps(old_rule.to_dict()) if old_rule else None
        rule_data = json.dumps(rule.to_dict())
        checksum = rule.calculate_checksum()

        existing = self.db.execute_one(
            "SELECT id FROM client_rules WHERE client_id = ? AND rule_id = ?",
            (client_id_str, rule.id)
        )

        if existing:
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
                    client_id_str,
                    rule.id,
                )
            )
        else:
            self.db.execute_write(
                """
                INSERT INTO client_rules
                (id, client_id, rule_id, rule_data, version, checksum, created_at, updated_at, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    client_id_str,
                    rule.id,
                    rule_data,
                    rule.version,
                    checksum,
                    rule.created_at,
                    rule.updated_at,
                    1 if rule.enabled else 0,
                )
            )

        self._add_to_history(client_id_str, rule.id, "restore", old_data, rule_data)
        self._update_checksum(client_id_str, rule.id, checksum)

        logger.info(f"Restored rule {rule.id} for client {client_id_str}")
        return True

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
