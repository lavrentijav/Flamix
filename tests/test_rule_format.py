"""Тесты для формата правил"""

import pytest
from flamix.common.rule_format import FirewallRule, RuleTargets


def test_rule_creation():
    """Тест создания правила"""
    rule = FirewallRule(
        name="Test Rule",
        action="block",
        direction="inbound",
        protocol="TCP"
    )
    assert rule.name == "Test Rule"
    assert rule.action == "block"
    assert rule.direction == "inbound"
    assert rule.protocol == "TCP"


def test_rule_with_targets():
    """Тест правила с целями"""
    targets = RuleTargets(
        ips=["192.168.1.1", "10.0.0.0/24"],
        domains=["example.com", "*.malicious.com"],
        ports=["80,443", "8080-8090"]
    )
    rule = FirewallRule(
        name="Test Rule",
        action="block",
        direction="inbound",
        protocol="TCP",
        targets=targets
    )
    assert len(rule.targets.ips) == 2
    assert len(rule.targets.domains) == 2
    assert len(rule.targets.ports) == 2


def test_rule_checksum():
    """Тест вычисления контрольной суммы"""
    rule1 = FirewallRule(
        name="Test Rule",
        action="block",
        direction="inbound",
        protocol="TCP"
    )
    rule2 = FirewallRule(
        name="Test Rule",
        action="block",
        direction="inbound",
        protocol="TCP"
    )
    # Одинаковые правила должны иметь одинаковую checksum
    assert rule1.calculate_checksum() == rule2.calculate_checksum()


def test_rule_matches_ip():
    """Тест проверки соответствия IP"""
    targets = RuleTargets(ips=["192.168.1.0/24"])
    rule = FirewallRule(
        name="Test Rule",
        action="block",
        direction="inbound",
        protocol="TCP",
        targets=targets
    )
    assert rule.matches_ip("192.168.1.100")
    assert not rule.matches_ip("10.0.0.1")


def test_rule_matches_domain():
    """Тест проверки соответствия домена"""
    targets = RuleTargets(domains=["*.example.com"])
    rule = FirewallRule(
        name="Test Rule",
        action="block",
        direction="inbound",
        protocol="TCP",
        targets=targets
    )
    assert rule.matches_domain("test.example.com")
    assert not rule.matches_domain("example.org")


def test_rule_matches_port():
    """Тест проверки соответствия порта"""
    targets = RuleTargets(ports=["80,443"])
    rule = FirewallRule(
        name="Test Rule",
        action="block",
        direction="inbound",
        protocol="TCP",
        targets=targets
    )
    assert rule.matches_port(80)
    assert rule.matches_port(443)
    assert not rule.matches_port(8080)
