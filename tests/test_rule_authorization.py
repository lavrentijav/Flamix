"""Tests for rule conflict, shadowing, and rollback handling."""

from __future__ import annotations

import uuid
import tempfile
import shutil
from datetime import datetime
from pathlib import Path

import pytest

from flamix.common.rule_format import FirewallRule, RuleTargets
from flamix.database.encrypted_db import EncryptedDB
from flamix.server.rule_authorization import AuthorizationPolicy, RuleAuthorization
from flamix.server.rule_manager import RuleManager


@pytest.fixture
def temp_db():
    temp_root = Path("temp") / "pytest-rule-auth"
    temp_root.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(dir=temp_root))
    db_path = temp_dir / "rule-auth.db"
    db = EncryptedDB(db_path, use_encryption=False)
    db.initialize()
    db.execute_write(
        """
        INSERT INTO clients (id, name, ip_address, last_seen, enabled)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "client-a",
            "client-a",
            "127.0.0.1",
            datetime.utcnow().isoformat() + "Z",
            1,
        ),
    )
    try:
        yield db
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _rule(
    *,
    name: str,
    action: str,
    direction: str = "inbound",
    protocol: str = "TCP",
    ips: list[str] | None = None,
    domains: list[str] | None = None,
    ports: list[str] | None = None,
    rule_id: str | None = None,
) -> FirewallRule:
    return FirewallRule(
        id=rule_id or str(uuid.uuid4()),
        name=name,
        action=action,
        direction=direction,
        protocol=protocol,
        targets=RuleTargets(
            ips=ips or [],
            domains=domains or [],
            ports=ports or [],
        ),
    )


@pytest.mark.asyncio
async def test_rule_review_rejects_shadowed_rule(temp_db):
    rule_manager = RuleManager(temp_db)
    auth = RuleAuthorization(temp_db, rule_manager)
    auth.set_policy("client-a", AuthorizationPolicy(allow_manual_changes=True, require_approval=False))

    existing = _rule(
        name="Allow web",
        action="allow",
        ips=["10.0.0.0/24"],
        ports=["80"],
    )
    rule_manager.add_rule("client-a", existing)

    candidate = _rule(
        name="Block host",
        action="block",
        ips=["10.0.0.5"],
        ports=["80"],
    )

    review = auth.review_rule_change(
        "client-a",
        candidate.id,
        None,
        candidate,
        change_source="api",
    )

    assert not review.allowed
    assert review.status == "rejected"
    assert "shadowed" in review.reason.lower()
    assert existing.id in review.reason


@pytest.mark.asyncio
async def test_rule_review_rejects_conflicting_rule(temp_db):
    rule_manager = RuleManager(temp_db)
    auth = RuleAuthorization(temp_db, rule_manager)
    auth.set_policy("client-a", AuthorizationPolicy(allow_manual_changes=True, require_approval=False))

    existing = _rule(
        name="Block subnet",
        action="block",
        ips=["10.0.0.0/24"],
        ports=["443"],
    )
    rule_manager.add_rule("client-a", existing)

    candidate = _rule(
        name="Allow subnet",
        action="allow",
        ips=["10.0.0.0/24"],
        ports=["443,8443"],
    )

    review = auth.review_rule_change(
        "client-a",
        candidate.id,
        None,
        candidate,
        change_source="api",
    )

    assert not review.allowed
    assert review.status == "rejected"
    assert "conflict" in review.reason.lower()
    assert existing.id in review.reason


@pytest.mark.asyncio
async def test_pending_rule_can_be_approved_and_persisted(temp_db):
    rule_manager = RuleManager(temp_db)
    auth = RuleAuthorization(temp_db, rule_manager)
    auth.set_policy("client-a", AuthorizationPolicy(allow_manual_changes=True, require_approval=True))

    candidate = _rule(
        name="Allow ssh",
        action="allow",
        ips=["10.0.0.10"],
        ports=["22"],
    )

    review = auth.review_rule_change(
        "client-a",
        candidate.id,
        None,
        candidate,
        change_source="api",
    )

    assert not review.allowed
    assert review.status == "pending"
    assert review.request_id is not None
    assert review.reason == "Approval required (pending)"

    success, reason = auth.approve_request(review.request_id, "reviewer-1")
    assert success
    assert reason is None

    stored_rule = rule_manager.get_rule("client-a", candidate.id)
    assert stored_rule is not None
    assert stored_rule.name == "Allow ssh"
    assert stored_rule.targets.ips == ["10.0.0.10"]

    request_row = temp_db.execute_one(
        "SELECT status, reviewed_by FROM rule_change_requests WHERE id = ?",
        (review.request_id,),
    )
    assert request_row["status"] == "approved"
    assert request_row["reviewed_by"] == "reviewer-1"


@pytest.mark.asyncio
async def test_approval_rolls_back_snapshot_when_apply_fails(temp_db, monkeypatch):
    rule_manager = RuleManager(temp_db)
    auth = RuleAuthorization(temp_db, rule_manager)
    auth.set_policy("client-a", AuthorizationPolicy(allow_manual_changes=True, require_approval=True))

    original = _rule(
        name="Allow dashboard",
        action="allow",
        ips=["10.0.0.20"],
        ports=["443"],
    )
    rule_manager.add_rule("client-a", original)

    updated = _rule(
        name="Allow dashboard v2",
        action="allow",
        ips=["10.0.0.20"],
        ports=["8443"],
        rule_id=original.id,
    )

    review = auth.review_rule_change(
        "client-a",
        original.id,
        original,
        updated,
        change_source="api",
    )

    assert not review.allowed
    assert review.status == "pending"

    original_update_rule = rule_manager.update_rule

    def failing_update(client_id: str, rule: FirewallRule):
        result = original_update_rule(client_id, rule)
        raise RuntimeError("simulated post-apply failure")

    monkeypatch.setattr(rule_manager, "update_rule", failing_update)

    success, reason = auth.approve_request(review.request_id, "reviewer-2")
    assert not success
    assert "failed to apply approved change" in reason.lower()

    stored_rule = rule_manager.get_rule("client-a", original.id)
    assert stored_rule is not None
    assert stored_rule.name == original.name
    assert stored_rule.targets.ports == original.targets.ports

    history_rows = temp_db.execute(
        """
        SELECT action, new_data
        FROM rule_history
        WHERE client_id = ? AND rule_id = ?
        ORDER BY id ASC
        """,
        ("client-a", original.id),
    )
    actions = [row["action"] for row in history_rows]
    assert "restore" in actions

    request_row = temp_db.execute_one(
        "SELECT status, reason FROM rule_change_requests WHERE id = ?",
        (review.request_id,),
    )
    assert request_row["status"] == "rejected"
    assert "failed to apply approved change" in request_row["reason"].lower()
