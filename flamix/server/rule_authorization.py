"""Rule authorization and review logic for server-side rule changes."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from flamix.common.rule_format import FirewallRule
from flamix.database.encrypted_db import EncryptedDB
from flamix.server.rule_analysis import LIMITATION_NOTE, RuleAnalyzer, RuleChangeReview
from flamix.server.rule_manager import RuleManager

logger = logging.getLogger(__name__)


class AuthorizationPolicy:
    """Authorization policy for a client."""

    def __init__(
        self,
        allow_manual_changes: bool = False,
        require_approval: bool = True,
        auto_approve_whitelist: list = None,
        max_changes_per_hour: int = 10,
        validation_rules: list = None,
    ):
        self.allow_manual_changes = allow_manual_changes
        self.require_approval = require_approval
        self.auto_approve_whitelist = auto_approve_whitelist or []
        self.max_changes_per_hour = max_changes_per_hour
        self.validation_rules = validation_rules or []


class RuleAuthorization:
    """Server-side authorization for firewall rule changes."""

    def __init__(self, db: EncryptedDB, rule_manager: RuleManager):
        self.db = db
        self.rule_manager = rule_manager
        self.analyzer = RuleAnalyzer()
        self.policies: Dict[str, AuthorizationPolicy] = {}

    def set_policy(self, client_id: str, policy: AuthorizationPolicy):
        self.policies[client_id] = policy

    def get_policy(self, client_id: str) -> AuthorizationPolicy:
        return self.policies.get(client_id, AuthorizationPolicy())

    def review_rule_change(
        self,
        client_id: str,
        rule_id: str,
        old_rule: Optional[FirewallRule],
        new_rule: FirewallRule,
        change_source: str = "manual",
        require_approval: bool = True,
    ) -> RuleChangeReview:
        """
        Review a rule change without mutating firewall state.

        The review can either approve immediately, queue the request for approval,
        or reject it with a detailed reason.
        """

        policy = self.get_policy(client_id)
        limitations = [LIMITATION_NOTE]

        if change_source == "manual" and not policy.allow_manual_changes:
            return RuleChangeReview(
                allowed=False,
                status="rejected",
                reason="Manual changes are not allowed for this client",
                limitations=limitations,
                snapshot=self._build_snapshot(client_id, rule_id, old_rule, new_rule, change_source),
            )

        if not self._check_change_limit(client_id):
            return RuleChangeReview(
                allowed=False,
                status="rejected",
                reason=f"Change limit exceeded (max {policy.max_changes_per_hour} per hour)",
                limitations=limitations,
                snapshot=self._build_snapshot(client_id, rule_id, old_rule, new_rule, change_source),
            )

        validation_result = self._validate_rule(new_rule, policy)
        if not validation_result[0]:
            return RuleChangeReview(
                allowed=False,
                status="rejected",
                reason=validation_result[1],
                limitations=limitations,
                snapshot=self._build_snapshot(client_id, rule_id, old_rule, new_rule, change_source),
            )

        existing_rules = self.rule_manager.get_all_rules(client_id)
        review = self.analyzer.analyze(
            existing_rules=existing_rules,
            candidate_rule=new_rule,
            candidate_rule_id=rule_id,
        )
        review.limitations = list(dict.fromkeys(review.limitations + limitations))
        review.snapshot = self._build_snapshot(client_id, rule_id, old_rule, new_rule, change_source)

        if not review.allowed:
            return review

        if rule_id in policy.auto_approve_whitelist or not policy.require_approval or not require_approval:
            review.status = "approved"
            review.reason = None
            return review

        request_id = self._save_change_request(client_id, rule_id, old_rule, new_rule, change_source)
        review.allowed = False
        review.status = "pending"
        review.reason = "Approval required (pending)"
        review.request_id = request_id
        review.snapshot["request_id"] = request_id
        return review

    async def authorize_rule_change(
        self,
        client_id: str,
        rule_id: str,
        old_rule: Optional[FirewallRule],
        new_rule: FirewallRule,
        change_source: str = "manual",
    ) -> Tuple[bool, Optional[str]]:
        review = self.review_rule_change(client_id, rule_id, old_rule, new_rule, change_source)
        return review.allowed, review.reason

    def _check_change_limit(self, client_id: str) -> bool:
        policy = self.get_policy(client_id)
        cutoff_time = (datetime.utcnow() - timedelta(hours=1)).isoformat() + "Z"

        result = self.db.execute_one(
            """
            SELECT COUNT(*) as count FROM rule_change_requests
            WHERE client_id = ? AND requested_at > ? AND status = 'approved'
            """,
            (client_id, cutoff_time),
        )

        count = result["count"] if result else 0
        return count < policy.max_changes_per_hour

    def _validate_rule(self, rule: FirewallRule, policy: AuthorizationPolicy) -> Tuple[bool, Optional[str]]:
        for validation_rule in policy.validation_rules:
            if validation_rule.get("type") == "block_critical_ips":
                critical_ips = validation_rule.get("ips", [])
                for rule_ip in rule.targets.ips:
                    if rule_ip in critical_ips and rule.action == "block":
                        return False, f"Cannot block critical IP: {rule_ip}"

        if not rule.name:
            return False, "Rule name is required"

        if not rule.targets.ips and not rule.targets.domains and not rule.targets.ports:
            return False, "Rule must have at least one target"

        return True, None

    def _build_snapshot(
        self,
        client_id: str,
        rule_id: str,
        old_rule: Optional[FirewallRule],
        new_rule: FirewallRule,
        change_source: str,
    ) -> Dict[str, Any]:
        return {
            "client_id": client_id,
            "rule_id": rule_id,
            "change_source": change_source,
            "captured_at": datetime.utcnow().isoformat() + "Z",
            "old_rule": old_rule.to_dict() if old_rule else None,
            "new_rule": new_rule.to_dict(),
        }

    def _save_change_request(
        self,
        client_id: str,
        rule_id: str,
        old_rule: Optional[FirewallRule],
        new_rule: FirewallRule,
        change_source: str,
    ) -> str:
        old_rule_data = json.dumps(old_rule.to_dict()) if old_rule else None
        new_rule_data = json.dumps(new_rule.to_dict())
        request_id = str(uuid.uuid4())

        self.db.execute_write(
            """
            INSERT INTO rule_change_requests
            (id, client_id, rule_id, old_rule, new_rule, change_source, status, requested_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                client_id,
                rule_id,
                old_rule_data,
                new_rule_data,
                change_source,
                "pending",
                datetime.utcnow().isoformat() + "Z",
            ),
        )

        return request_id

    def _set_request_state(
        self,
        request_id: str,
        status: str,
        reviewer: str,
        reason: Optional[str] = None,
    ) -> None:
        self.db.execute_write(
            """
            UPDATE rule_change_requests
            SET status = ?, reviewed_at = ?, reviewed_by = ?, reason = ?
            WHERE id = ?
            """,
            (
                status,
                datetime.utcnow().isoformat() + "Z",
                reviewer,
                reason,
                request_id,
            ),
        )

    def _restore_snapshot(self, client_id: str, snapshot_rule: Optional[FirewallRule], rule_id: str) -> bool:
        if snapshot_rule is None:
            return self.rule_manager.delete_rule(client_id, rule_id)
        return self.rule_manager.restore_rule(client_id, snapshot_rule)

    def approve_request(self, request_id: str, reviewer: str) -> Tuple[bool, Optional[str]]:
        request = self.db.execute_one(
            "SELECT * FROM rule_change_requests WHERE id = ? AND status = 'pending'",
            (request_id,),
        )
        if not request:
            return False, "Request not found"

        old_rule = FirewallRule.from_dict(json.loads(request["old_rule"])) if request["old_rule"] else None
        new_rule = FirewallRule.from_dict(json.loads(request["new_rule"]))
        client_id = request["client_id"]
        rule_id = request["rule_id"]

        current_rule = self.rule_manager.get_rule(client_id, rule_id)
        if old_rule:
            if not current_rule:
                reason = "Snapshot is stale: the rule no longer exists"
                self._set_request_state(request_id, "rejected", reviewer, reason)
                return False, reason
            if current_rule.calculate_checksum() != old_rule.calculate_checksum():
                reason = "Snapshot is stale: the rule changed after the request was created"
                self._set_request_state(request_id, "rejected", reviewer, reason)
                return False, reason
        elif current_rule:
            reason = "Snapshot is stale: a rule with this ID already exists"
            self._set_request_state(request_id, "rejected", reviewer, reason)
            return False, reason

        review = self.review_rule_change(
            client_id=client_id,
            rule_id=rule_id,
            old_rule=old_rule,
            new_rule=new_rule,
            change_source=request["change_source"] or "approval",
            require_approval=False,
        )
        if not review.allowed:
            reason = review.reason or "Approval rejected by validation"
            self._set_request_state(request_id, "rejected", reviewer, reason)
            return False, reason

        try:
            if current_rule:
                success = self.rule_manager.update_rule(client_id, new_rule)
            else:
                self.rule_manager.add_rule(client_id, new_rule)
                success = True
        except Exception as exc:
            rollback_reason = f"Failed to apply approved change: {exc}"
            logger.error(rollback_reason, exc_info=True)
            self._restore_snapshot(client_id, current_rule or old_rule, rule_id)
            self._set_request_state(request_id, "rejected", reviewer, rollback_reason)
            return False, rollback_reason

        if not success:
            rollback_reason = "Failed to apply approved change"
            self._restore_snapshot(client_id, current_rule or old_rule, rule_id)
            self._set_request_state(request_id, "rejected", reviewer, rollback_reason)
            return False, rollback_reason

        try:
            self._set_request_state(request_id, "approved", reviewer, None)
        except Exception as exc:
            logger.warning("Approved rule was applied but request state update failed: %s", exc, exc_info=True)
        return True, None

    def reject_request(self, request_id: str, reviewer: str, reason: str) -> bool:
        request = self.db.execute_one(
            "SELECT * FROM rule_change_requests WHERE id = ? AND status = 'pending'",
            (request_id,),
        )
        if not request:
            return False

        self._set_request_state(request_id, "rejected", reviewer, reason)
        return True
