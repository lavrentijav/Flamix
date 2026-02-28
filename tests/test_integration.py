"""Интеграционные тесты"""

import pytest
import asyncio
from pathlib import Path
import tempfile
import shutil

from flamix.database.encrypted_db import EncryptedDB
from flamix.server.rule_manager import RuleManager
from flamix.common.rule_format import FirewallRule


@pytest.fixture
def temp_db():
    """Временная база данных для тестов"""
    temp_dir = tempfile.mkdtemp()
    db_path = Path(temp_dir) / "test.db"
    # Отключаем шифрование для тестов
    db = EncryptedDB(db_path, use_encryption=False)
    db.initialize()
    yield db
    shutil.rmtree(temp_dir)


@pytest.mark.asyncio
async def test_rule_manager_add_get(temp_db):
    """Тест добавления и получения правил"""
    rule_manager = RuleManager(temp_db)
    client_id = "test-client"

    rule = FirewallRule(
        name="Test Rule",
        action="block",
        direction="inbound",
        protocol="TCP"
    )

    rule_id = rule_manager.add_rule(client_id, rule)
    assert rule_id == rule.id

    retrieved_rule = rule_manager.get_rule(client_id, rule_id)
    assert retrieved_rule is not None
    assert retrieved_rule.name == "Test Rule"


@pytest.mark.asyncio
async def test_rule_manager_update(temp_db):
    """Тест обновления правил"""
    rule_manager = RuleManager(temp_db)
    client_id = "test-client"

    rule = FirewallRule(
        name="Test Rule",
        action="block",
        direction="inbound",
        protocol="TCP"
    )

    rule_manager.add_rule(client_id, rule)

    # Обновляем правило
    rule.name = "Updated Rule"
    success = rule_manager.update_rule(client_id, rule)
    assert success

    retrieved_rule = rule_manager.get_rule(client_id, rule.id)
    assert retrieved_rule.name == "Updated Rule"
    assert retrieved_rule.version == 2  # Версия должна увеличиться


@pytest.mark.asyncio
async def test_rule_manager_delete(temp_db):
    """Тест удаления правил"""
    rule_manager = RuleManager(temp_db)
    client_id = "test-client"

    rule = FirewallRule(
        name="Test Rule",
        action="block",
        direction="inbound",
        protocol="TCP"
    )

    rule_manager.add_rule(client_id, rule)
    success = rule_manager.delete_rule(client_id, rule.id)
    assert success

    retrieved_rule = rule_manager.get_rule(client_id, rule.id)
    assert retrieved_rule is None
