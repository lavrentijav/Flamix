import pytest
from pathlib import Path

from run import build_runtime_components
from flamix.api.plugin_interface import PluginInterface
from flamix.client.plugins.plugin_adapter import PluginAdapter
from flamix.client.rule_converter import RuleConverter
from flamix.client.rule_sync import RuleSync
from flamix.common.rule_format import FirewallRule, RuleTargets


class FakePluginManager:
    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.active_plugin = type("ActivePlugin", (), {"plugin_id": "fake_plugin"})()

    def get_active_plugin(self):
        return self.active_plugin


class FakeClient:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.plugin_manager = kwargs["plugin_manager"]


class FakeRuleSync:
    def __init__(self, client, rule_converter, sync_interval):
        self.client = client
        self.rule_converter = rule_converter
        self.sync_interval = sync_interval


class FakeRuleMonitor:
    def __init__(self, client, rule_converter, check_interval):
        self.client = client
        self.rule_converter = rule_converter
        self.check_interval = check_interval


class FakeAnalyticsCollector:
    def __init__(self, client, enabled, interval):
        self.client = client
        self.enabled = enabled
        self.interval = interval


class RecordingPlugin:
    def __init__(self, plugin_id="fake_plugin"):
        self.plugin_id = plugin_id
        self.applied_rules = []

    def is_available(self):
        return True

    async def apply_rule(self, rule):
        self.applied_rules.append(rule)
        return {"success": True, "rule_id": rule["name"]}


class RecordingPluginManager:
    def __init__(self, plugin):
        self.plugins = {plugin.plugin_id: plugin}
        self._active_plugin = plugin

    def get_active_plugin(self):
        return self._active_plugin


class LifecyclePlugin(PluginInterface):
    def __init__(self):
        super().__init__()
        self.init_calls = 0
        self.enable_calls = 0
        self.applied_rules = []

    async def on_install(self):
        return None

    async def on_enable(self):
        self.enable_calls += 1
        self.enabled = True

    async def on_init(self, core_api):
        await super().on_init(core_api)
        self.init_calls += 1

    async def on_disable(self):
        self.enabled = False

    async def on_uninstall(self):
        return None

    async def get_health(self):
        return {"status": "ok"}

    async def apply_rule(self, rule):
        self.applied_rules.append(rule)
        return {"success": True, "rule_id": rule["name"]}


def test_build_runtime_components_wires_shared_plugin_manager():
    config = {
        "client_id": "client-1",
        "server_host": "localhost",
        "server_port": 8443,
        "cert_dir": "certs",
        "sync_interval": 15,
        "monitor_interval": 8,
        "analytics_enabled": True,
        "analytics_interval": 42,
    }
    base_dir = Path(__file__).resolve().parents[1]

    runtime = build_runtime_components(
        config,
        base_dir,
        FakeClient,
        FakeRuleSync,
        RuleConverter,
        FakeRuleMonitor,
        FakeAnalyticsCollector,
        FakePluginManager,
    )

    assert runtime["client"].plugin_manager is runtime["plugin_manager"]
    assert runtime["rule_converter"].plugin_manager is runtime["plugin_manager"]
    assert runtime["rule_converter"].active_plugin is runtime["plugin_manager"].active_plugin
    assert runtime["rule_sync"].sync_interval == 15
    assert runtime["rule_monitor"].check_interval == 8
    assert runtime["analytics_collector"].enabled is True
    assert runtime["client"].kwargs["cert_dir"] == base_dir / "certs"


@pytest.mark.asyncio
async def test_rule_sync_applies_rule_via_active_plugin():
    plugin = RecordingPlugin()
    plugin_manager = RecordingPluginManager(plugin)
    converter = RuleConverter(plugin_manager)
    rule = FirewallRule(
        id="rule-1",
        name="Block SSH",
        action="block",
        direction="inbound",
        protocol="TCP",
        targets=RuleTargets(ports=["22"], ips=["10.0.0.5"]),
    )

    class SyncClient:
        connected = True

        async def sync_rules(self):
            return [rule]

    sync = RuleSync(SyncClient(), converter, sync_interval=30)
    rules = await sync.sync()

    assert rules == [rule]
    assert sync.applied_rules[rule.id] == plugin.plugin_id
    assert plugin.applied_rules == [
        {
            "name": "Block SSH",
            "direction": "in",
            "action": "block",
            "protocol": "TCP",
            "local_port": "22",
            "remote_port": "22",
            "remote_ip": "10.0.0.5",
        }
    ]


@pytest.mark.asyncio
async def test_plugin_adapter_initializes_and_enables_once():
    plugin = LifecyclePlugin()
    adapter = PluginAdapter(
        plugin,
        "zip_plugin",
        {"platforms": [], "permissions": []},
    )

    first_result = await adapter.apply_rule({"name": "rule-1"})
    second_result = await adapter.apply_rule({"name": "rule-2"})

    assert first_result["success"] is True
    assert second_result["success"] is True
    assert plugin.init_calls == 1
    assert plugin.enable_calls == 1
    assert plugin.core_api is adapter.core_api
    assert plugin.applied_rules == [{"name": "rule-1"}, {"name": "rule-2"}]
