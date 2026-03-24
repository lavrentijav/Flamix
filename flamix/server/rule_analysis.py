"""Helpers for rule conflict, shadow, and coverage analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from netaddr import IPNetwork

from flamix.common.rule_format import FirewallRule


LIMITATION_NOTE = (
    "Snapshot/rollback is guaranteed only for the server-side rule record. "
    "External firewall/plugin application remains an independent step and can fail separately."
)


@dataclass
class RuleRelation:
    """A single rule-to-rule relation discovered during analysis."""

    rule_id: str
    name: str
    action: str
    relation: str
    dimensions: List[str] = field(default_factory=list)
    details: List[str] = field(default_factory=list)


@dataclass
class RuleChangeReview:
    """Result of a rule change review."""

    allowed: bool
    status: str
    reason: Optional[str] = None
    request_id: Optional[str] = None
    conflicts: List[RuleRelation] = field(default_factory=list)
    shadowed: List[RuleRelation] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    snapshot: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "status": self.status,
            "reason": self.reason,
            "request_id": self.request_id,
            "conflicts": [relation.__dict__ for relation in self.conflicts],
            "shadowed": [relation.__dict__ for relation in self.shadowed],
            "warnings": list(self.warnings),
            "limitations": list(self.limitations),
            "snapshot": self.snapshot,
        }


def _normalize_direction(direction: str) -> str:
    return direction.lower().strip()


def _normalize_protocol(protocol: str) -> str:
    return protocol.upper().strip()


def _direction_compatible(rule_a: FirewallRule, rule_b: FirewallRule) -> bool:
    return _normalize_direction(rule_a.direction) == _normalize_direction(rule_b.direction)


def _protocol_compatible(rule_a: FirewallRule, rule_b: FirewallRule) -> bool:
    proto_a = _normalize_protocol(rule_a.protocol)
    proto_b = _normalize_protocol(rule_b.protocol)
    return "ANY" in {proto_a, proto_b} or proto_a == proto_b


def _iter_specs(values: Sequence[str]) -> List[str]:
    return [value.strip() for value in values if value and value.strip()]


def _parse_ip_spec(spec: str) -> IPNetwork:
    if "/" in spec:
        return IPNetwork(spec)
    if ":" in spec:
        return IPNetwork(f"{spec}/128")
    return IPNetwork(f"{spec}/32")


def _ip_spec_covers(existing_spec: str, candidate_spec: str) -> bool:
    return _parse_ip_spec(candidate_spec) in _parse_ip_spec(existing_spec)


def _ip_spec_overlaps(existing_spec: str, candidate_spec: str) -> bool:
    existing_net = _parse_ip_spec(existing_spec)
    candidate_net = _parse_ip_spec(candidate_spec)
    return not (existing_net.last < candidate_net.first or candidate_net.last < existing_net.first)


def _domain_spec(spec: str) -> Tuple[str, str]:
    normalized = spec.lower().strip()
    if normalized == "*":
        return ("any", "")
    if normalized.startswith("*."):
        return ("wildcard", normalized[2:])
    return ("exact", normalized)


def _domain_spec_covers(existing_spec: str, candidate_spec: str) -> bool:
    existing_kind, existing_value = _domain_spec(existing_spec)
    candidate_kind, candidate_value = _domain_spec(candidate_spec)

    if existing_kind == "any":
        return True
    if candidate_kind == "any":
        return existing_kind == "any"

    if existing_kind == "exact":
        return candidate_kind == "exact" and existing_value == candidate_value

    # existing wildcard
    if candidate_kind == "exact":
        return candidate_value == existing_value or candidate_value.endswith(f".{existing_value}")
    return candidate_value == existing_value or candidate_value.endswith(f".{existing_value}")


def _domain_spec_overlaps(existing_spec: str, candidate_spec: str) -> bool:
    existing_kind, existing_value = _domain_spec(existing_spec)
    candidate_kind, candidate_value = _domain_spec(candidate_spec)

    if existing_kind == "any" or candidate_kind == "any":
        return True

    if existing_kind == "exact" and candidate_kind == "exact":
        return existing_value == candidate_value

    if existing_kind == "exact" and candidate_kind == "wildcard":
        return existing_value == candidate_value or existing_value.endswith(f".{candidate_value}")

    if existing_kind == "wildcard" and candidate_kind == "exact":
        return candidate_value == existing_value or candidate_value.endswith(f".{existing_value}")

    # wildcard / wildcard
    return (
        existing_value == candidate_value
        or existing_value.endswith(f".{candidate_value}")
        or candidate_value.endswith(f".{existing_value}")
    )


def _parse_port_part(part: str) -> Tuple[int, int]:
    token = part.strip().lower()
    if token == "any":
        return (0, 65535)
    if "-" in token:
        start, end = token.split("-", 1)
        return (int(start), int(end))
    value = int(token)
    return (value, value)


def _parse_port_specs(values: Sequence[str]) -> List[Tuple[int, int]]:
    ranges: List[Tuple[int, int]] = []
    for spec in _iter_specs(values):
        for part in spec.split(","):
            ranges.append(_parse_port_part(part))
    return ranges


def _range_covers(existing_range: Tuple[int, int], candidate_range: Tuple[int, int]) -> bool:
    return existing_range[0] <= candidate_range[0] and existing_range[1] >= candidate_range[1]


def _range_overlaps(existing_range: Tuple[int, int], candidate_range: Tuple[int, int]) -> bool:
    return not (existing_range[1] < candidate_range[0] or candidate_range[1] < existing_range[0])


def _dimension_covers(existing_values: Sequence[str], candidate_values: Sequence[str], kind: str) -> bool:
    existing = _iter_specs(existing_values)
    candidate = _iter_specs(candidate_values)

    if not candidate:
        return not existing
    if not existing:
        return True

    if kind == "ip":
        return all(
            any(_ip_spec_covers(existing_spec, candidate_spec) for existing_spec in existing)
            for candidate_spec in candidate
        )

    if kind == "domain":
        return all(
            any(_domain_spec_covers(existing_spec, candidate_spec) for existing_spec in existing)
            for candidate_spec in candidate
        )

    if kind == "port":
        existing_ranges = _parse_port_specs(existing)
        candidate_ranges = _parse_port_specs(candidate)
        return all(
            any(_range_covers(existing_range, candidate_range) for existing_range in existing_ranges)
            for candidate_range in candidate_ranges
        )

    raise ValueError(f"Unsupported dimension kind: {kind}")


def _dimension_overlaps(existing_values: Sequence[str], candidate_values: Sequence[str], kind: str) -> bool:
    existing = _iter_specs(existing_values)
    candidate = _iter_specs(candidate_values)

    if not existing or not candidate:
        return True

    if kind == "ip":
        return any(
            _ip_spec_overlaps(existing_spec, candidate_spec)
            for existing_spec in existing
            for candidate_spec in candidate
        )

    if kind == "domain":
        return any(
            _domain_spec_overlaps(existing_spec, candidate_spec)
            for existing_spec in existing
            for candidate_spec in candidate
        )

    if kind == "port":
        existing_ranges = _parse_port_specs(existing)
        candidate_ranges = _parse_port_specs(candidate)
        return any(
            _range_overlaps(existing_range, candidate_range)
            for existing_range in existing_ranges
            for candidate_range in candidate_ranges
        )

    raise ValueError(f"Unsupported dimension kind: {kind}")


def _describe_dimension_hits(rule_a: FirewallRule, rule_b: FirewallRule) -> List[str]:
    hits: List[str] = []
    if _dimension_overlaps(rule_a.targets.ips, rule_b.targets.ips, "ip"):
        hits.append("IPs")
    if _dimension_overlaps(rule_a.targets.domains, rule_b.targets.domains, "domain"):
        hits.append("domains")
    if _dimension_overlaps(rule_a.targets.ports, rule_b.targets.ports, "port"):
        hits.append("ports")
    return hits


class RuleAnalyzer:
    """Practical baseline analyzer for rule conflicts and shadowing."""

    def analyze(
        self,
        existing_rules: Sequence[FirewallRule],
        candidate_rule: FirewallRule,
        candidate_rule_id: Optional[str] = None,
    ) -> RuleChangeReview:
        """
        Analyze the effect of placing `candidate_rule` into `existing_rules`.

        The baseline assumes order-by-created_at semantics, where an updated rule
        keeps its original position and a new rule is appended to the end.
        """

        ordered_rules = list(existing_rules)
        candidate_id = candidate_rule_id or candidate_rule.id
        candidate_index = next((idx for idx, rule in enumerate(ordered_rules) if rule.id == candidate_id), None)
        if candidate_index is None:
            candidate_index = len(ordered_rules)

        prior_rules = [rule for idx, rule in enumerate(ordered_rules) if idx < candidate_index and rule.id != candidate_id]
        later_rules = [rule for idx, rule in enumerate(ordered_rules) if idx > candidate_index and rule.id != candidate_id]

        conflicts: List[RuleRelation] = []
        shadowed: List[RuleRelation] = []
        warnings: List[str] = []

        for existing_rule in prior_rules:
            relation = self._compare_rules(existing_rule, candidate_rule)
            if relation is None:
                continue
            if relation["candidate_covered"]:
                if existing_rule.action != candidate_rule.action:
                    conflicts.append(self._build_relation(existing_rule, "conflict", relation["dimensions"]))
                    return self._reject(
                        candidate_rule,
                        conflicts,
                        shadowed,
                        warnings,
                        f"Rule is shadowed by existing rule {existing_rule.id} ({existing_rule.name}): "
                        f"an earlier {existing_rule.action} rule already covers the same traffic on {', '.join(relation['dimensions'])}.",
                    )
                shadowed.append(self._build_relation(existing_rule, "shadowed", relation["dimensions"]))
                return self._reject(
                    candidate_rule,
                    conflicts,
                    shadowed,
                    warnings,
                    f"Rule is shadowed by existing rule {existing_rule.id} ({existing_rule.name}): "
                    f"the earlier rule already covers the same traffic on {', '.join(relation['dimensions'])}.",
                )

            if relation["overlap"] and existing_rule.action != candidate_rule.action:
                conflicts.append(self._build_relation(existing_rule, "conflict", relation["dimensions"]))
                return self._reject(
                    candidate_rule,
                    conflicts,
                    shadowed,
                    warnings,
                    f"Rule conflicts with existing rule {existing_rule.id} ({existing_rule.name}): "
                    f"overlapping traffic on {', '.join(relation['dimensions'])} would receive opposite actions.",
                )

        for existing_rule in later_rules:
            relation = self._compare_rules(candidate_rule, existing_rule)
            if relation is None:
                continue
            if relation["candidate_covered"]:
                if candidate_rule.action != existing_rule.action:
                    conflicts.append(self._build_relation(existing_rule, "conflict", relation["dimensions"]))
                    return self._reject(
                        candidate_rule,
                        conflicts,
                        shadowed,
                        warnings,
                        f"Rule would shadow existing rule {existing_rule.id} ({existing_rule.name}): "
                        f"the candidate already covers the same traffic on {', '.join(relation['dimensions'])}.",
                    )
                warnings.append(
                    f"Rule {existing_rule.id} ({existing_rule.name}) would become redundant because the candidate covers the same traffic on "
                    f"{', '.join(relation['dimensions'])}."
                )
                shadowed.append(self._build_relation(existing_rule, "shadowed", relation["dimensions"]))
                continue

            if relation["overlap"] and candidate_rule.action != existing_rule.action:
                conflicts.append(self._build_relation(existing_rule, "conflict", relation["dimensions"]))
                return self._reject(
                    candidate_rule,
                    conflicts,
                    shadowed,
                    warnings,
                    f"Rule would conflict with existing rule {existing_rule.id} ({existing_rule.name}): "
                    f"overlapping traffic on {', '.join(relation['dimensions'])} would receive opposite actions.",
                )

        return RuleChangeReview(
            allowed=True,
            status="approved",
            warnings=warnings,
            conflicts=conflicts,
            shadowed=shadowed,
        )

    def _compare_rules(
        self,
        reference_rule: FirewallRule,
        compared_rule: FirewallRule,
    ) -> Optional[Dict[str, Any]]:
        if not _direction_compatible(reference_rule, compared_rule):
            return None
        if not _protocol_compatible(reference_rule, compared_rule):
            return None

        dimensions = []
        overlap = True
        candidate_covered = True

        for kind, existing_values, candidate_values, label in (
            ("ip", reference_rule.targets.ips, compared_rule.targets.ips, "IPs"),
            ("domain", reference_rule.targets.domains, compared_rule.targets.domains, "domains"),
            ("port", reference_rule.targets.ports, compared_rule.targets.ports, "ports"),
        ):
            dimension_overlap = _dimension_overlaps(existing_values, candidate_values, kind)
            dimension_covered = _dimension_covers(existing_values, candidate_values, kind)
            if dimension_overlap:
                dimensions.append(label)
            else:
                overlap = False
            if not dimension_covered:
                candidate_covered = False

        if not dimensions:
            return None

        return {
            "overlap": overlap,
            "candidate_covered": candidate_covered,
            "dimensions": dimensions,
        }

    def _build_relation(self, rule: FirewallRule, relation: str, dimensions: List[str]) -> RuleRelation:
        return RuleRelation(
            rule_id=rule.id,
            name=rule.name,
            action=rule.action,
            relation=relation,
            dimensions=list(dimensions),
            details=[f"Matches on {', '.join(dimensions)}"] if dimensions else [],
        )

    def _reject(
        self,
        candidate_rule: FirewallRule,
        conflicts: List[RuleRelation],
        shadowed: List[RuleRelation],
        warnings: List[str],
        reason: str,
    ) -> RuleChangeReview:
        review = RuleChangeReview(
            allowed=False,
            status="rejected",
            reason=reason,
            conflicts=conflicts,
            shadowed=shadowed,
            warnings=warnings,
            limitations=[LIMITATION_NOTE],
            snapshot={
                "candidate_rule": candidate_rule.to_dict(),
                "reviewed_at": datetime.utcnow().isoformat() + "Z",
            },
        )
        return review
