"""Система бэкапов и восстановления"""

import json
import logging
import hashlib
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

from flamix.database.encrypted_db import EncryptedDB
from flamix.server.rule_manager import RuleManager
from flamix.common.rule_format import FirewallRule

logger = logging.getLogger(__name__)


class BackupManager:
    """Менеджер бэкапов"""

    def __init__(self, db: EncryptedDB, rule_manager: RuleManager):
        """
        Инициализация менеджера бэкапов

        Args:
            db: База данных
            rule_manager: Менеджер правил
        """
        self.db = db
        self.rule_manager = rule_manager

    def create_backup(self, output_path: Path) -> Dict[str, Any]:
        """
        Создание бэкапа

        Args:
            output_path: Путь для сохранения бэкапа

        Returns:
            Метаданные бэкапа
        """
        logger.info(f"Creating backup to {output_path}")

        # Получаем всех клиентов
        clients = self.db.execute("SELECT * FROM clients")

        backup_data = {
            'version': '1.0',
            'created_at': datetime.utcnow().isoformat() + "Z",
            'clients': [],
            'metadata': {}
        }

        # Сохраняем правила для каждого клиента
        for client in clients:
            client_id = client['id']
            rules = self.rule_manager.get_all_rules(client_id)

            client_data = {
                'id': client_id,
                'name': client.get('name'),
                'rules': [rule.to_dict() for rule in rules]
            }

            backup_data['clients'].append(client_data)

        # Сохраняем в файл
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(backup_data, f, indent=2, ensure_ascii=False)

        # Вычисляем checksum
        with open(output_path, 'rb') as f:
            checksum = hashlib.sha256(f.read()).hexdigest()

        backup_data['metadata']['checksum'] = checksum
        backup_data['metadata']['file_size'] = output_path.stat().st_size

        # Сохраняем метаданные обратно в файл
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(backup_data, f, indent=2, ensure_ascii=False)

        logger.info(f"Backup created: {len(backup_data['clients'])} clients, checksum: {checksum}")
        return backup_data['metadata']

    def restore_backup(self, backup_path: Path) -> Dict[str, Any]:
        """
        Восстановление из бэкапа

        Args:
            backup_path: Путь к файлу бэкапа

        Returns:
            Результат восстановления
        """
        logger.info(f"Restoring backup from {backup_path}")

        # Читаем бэкап
        with open(backup_path, 'r', encoding='utf-8') as f:
            backup_data = json.load(f)

        # Проверка версии
        if backup_data.get('version') != '1.0':
            raise ValueError(f"Unsupported backup version: {backup_data.get('version')}")

        # Проверка checksum
        with open(backup_path, 'rb') as f:
            current_checksum = hashlib.sha256(f.read()).hexdigest()
        expected_checksum = backup_data.get('metadata', {}).get('checksum')
        if expected_checksum and current_checksum != expected_checksum:
            raise ValueError("Backup file checksum mismatch")

        restored_count = 0
        error_count = 0

        # Восстанавливаем правила
        for client_data in backup_data.get('clients', []):
            client_id = client_data['id']

            # Регистрируем клиента если нужно
            self.db.execute_write(
                """
                INSERT OR REPLACE INTO clients (id, name, enabled)
                VALUES (?, ?, ?)
                """,
                (client_id, client_data.get('name', client_id), 1)
            )

            # Восстанавливаем правила
            for rule_dict in client_data.get('rules', []):
                try:
                    rule = FirewallRule.from_dict(rule_dict)
                    self.rule_manager.add_rule(client_id, rule)
                    restored_count += 1
                except Exception as e:
                    logger.error(f"Error restoring rule: {e}")
                    error_count += 1

        logger.info(f"Restore completed: {restored_count} rules restored, {error_count} errors")
        return {
            'restored_count': restored_count,
            'error_count': error_count,
            'clients_count': len(backup_data.get('clients', []))
        }
