"""Интеграционные тесты"""

import pytest
import asyncio
from pathlib import Path
import shutil
import uuid
from datetime import datetime

from flamix.database.encrypted_db import EncryptedDB
from flamix.server.server import FlamixServer
from flamix.server.rule_manager import RuleManager
from flamix.common.rule_format import FirewallRule


@pytest.fixture
def temp_db():
    """Временная база данных для тестов"""
    temp_root = Path("temp") / "pytest-db"
    temp_root.mkdir(parents=True, exist_ok=True)
    temp_dir = temp_root / str(uuid.uuid4())
    temp_dir.mkdir()
    db_path = temp_dir / "test.db"
    # Отключаем шифрование для тестов
    db = EncryptedDB(db_path, use_encryption=False)
    db.initialize()
    db.execute_write(
        """
        INSERT INTO clients (id, name, ip_address, last_seen, enabled)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "test-client",
            "test-client",
            "127.0.0.1",
            datetime.utcnow().isoformat() + "Z",
            1,
        ),
    )
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


def test_server_saves_client_logs(temp_db):
    """РўРµСЃС‚ СЃРѕС…СЂР°РЅРµРЅРёСЏ Р»РѕРіРѕРІ РєР»РёРµРЅС‚Р°"""
    server = FlamixServer(web_enabled=False)
    server.db = temp_db

    server._save_client_logs(
        "test-client",
        {
            "logs": [
                {
                    "timestamp": "2026-03-25T12:00:00Z",
                    "level": "INFO",
                    "logger_name": "tests.log_delivery",
                    "message": "log payload",
                }
            ]
        },
    )

    saved_log = temp_db.execute_one(
        """
        SELECT client_id, timestamp, level, logger_name, message
        FROM client_logs
        WHERE client_id = ?
        """,
        ("test-client",),
    )

    assert saved_log is not None
    assert saved_log["client_id"] == "test-client"
    assert saved_log["timestamp"] == "2026-03-25T12:00:00Z"
    assert saved_log["level"] == "INFO"
    assert saved_log["logger_name"] == "tests.log_delivery"
    assert saved_log["message"] == "log payload"
