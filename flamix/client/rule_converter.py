"""Rule conversion helpers for firewall plugins."""

import logging
from typing import Dict, Any, Optional

from flamix.common.rule_format import FirewallRule

logger = logging.getLogger(__name__)


class RuleConverter:
    """Convert unified rules into plugin-specific commands."""

    def __init__(self, plugin_manager=None):
        self.plugin_manager = plugin_manager
        self.active_plugin = plugin_manager.get_active_plugin() if plugin_manager else None

    def _refresh_active_plugin(self):
        """Refresh cached active plugin reference from the manager."""
        if self.plugin_manager:
            self.active_plugin = self.plugin_manager.get_active_plugin()
        return self.active_plugin

    def get_plugin(self, plugin_id: Optional[str] = None):
        """Resolve an explicit plugin id or fall back to the active plugin."""
        active_plugin = self._refresh_active_plugin()
        if plugin_id:
            if active_plugin and getattr(active_plugin, "plugin_id", None) == plugin_id:
                return active_plugin
            if self.plugin_manager:
                return self.plugin_manager.plugins.get(plugin_id)
            return None
        if active_plugin:
            return active_plugin
        if self.plugin_manager:
            return self.plugin_manager.get_active_plugin()
        return None

    def get_preferred_plugin_id(self) -> Optional[str]:
        """Return the active plugin id or the first available plugin id."""
        plugin = self.get_plugin()
        if plugin:
            return getattr(plugin, "plugin_id", None)

        if self.plugin_manager:
            for plugin_id, plugin_instance in self.plugin_manager.plugins.items():
                try:
                    if plugin_instance.is_available():
                        return plugin_id
                except Exception as e:
                    logger.debug(f"Error checking availability for plugin {plugin_id}: {e}")

        return None

    def convert_to_plugin_format(self, rule: FirewallRule, plugin_id: str) -> Dict[str, Any]:
        """Convert a unified rule into plugin format."""
        plugin_rule = {
            "name": rule.name,
            "direction": "in" if rule.direction == "inbound" else "out",
            "action": rule.action,
            "protocol": rule.protocol,
        }

        if rule.targets.ports:
            ports_str = ",".join(rule.targets.ports)
            if ports_str.lower() != "any":
                plugin_rule["local_port"] = ports_str
                plugin_rule["remote_port"] = ports_str

        if rule.targets.ips:
            ips_str = ",".join(rule.targets.ips)
            if ips_str.lower() != "any":
                plugin_rule["remote_ip"] = ips_str

        if rule.targets.domains:
            plugin_rule["domains"] = rule.targets.domains

        return plugin_rule

    async def apply_rule(self, rule: FirewallRule, plugin_id: Optional[str] = None) -> Dict[str, Any]:
        """Apply a rule through the selected plugin."""
        plugin = self.get_plugin(plugin_id)
        if not plugin:
            requested_plugin = plugin_id or self.get_preferred_plugin_id()
            if requested_plugin:
                return {"success": False, "error": f"Plugin {requested_plugin} not available"}
            return {"success": False, "error": "No plugin available"}

        effective_plugin_id = plugin_id or getattr(plugin, "plugin_id", None) or "default"
        plugin_rule = self.convert_to_plugin_format(rule, effective_plugin_id)

        try:
            return await plugin.apply_rule(plugin_rule)
        except Exception as e:
            logger.error(f"Error applying rule through plugin {effective_plugin_id}: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

    def convert_from_plugin_format(self, plugin_rule: Dict[str, Any], rule_id: str) -> FirewallRule:
        """Convert a plugin rule back into the unified rule format."""
        from flamix.common.rule_format import RuleTargets

        targets = RuleTargets()

        if "local_port" in plugin_rule and plugin_rule["local_port"]:
            targets.ports.append(plugin_rule["local_port"])
        if "remote_port" in plugin_rule and plugin_rule["remote_port"]:
            if plugin_rule["remote_port"] not in targets.ports:
                targets.ports.append(plugin_rule["remote_port"])

        if "remote_ip" in plugin_rule and plugin_rule["remote_ip"]:
            ips = [ip.strip() for ip in plugin_rule["remote_ip"].split(",")]
            targets.ips.extend(ips)

        if "local_ip" in plugin_rule and plugin_rule["local_ip"]:
            ips = [ip.strip() for ip in plugin_rule["local_ip"].split(",")]
            targets.ips.extend(ips)

        if "domains" in plugin_rule:
            targets.domains.extend(plugin_rule["domains"])

        direction = "inbound" if plugin_rule.get("direction", "in") == "in" else "outbound"
        protocol = plugin_rule.get("protocol", "TCP").upper()

        return FirewallRule(
            id=rule_id,
            name=plugin_rule.get("name", "Unnamed rule"),
            action=plugin_rule.get("action", "block"),
            direction=direction,
            targets=targets,
            protocol=protocol,
            enabled=plugin_rule.get("enabled", True),
        )
