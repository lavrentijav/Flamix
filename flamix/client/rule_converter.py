"""Конвертация унифицированных правил в команды фаервола"""

import logging
from typing import Dict, Any, List, Optional

from flamix.common.rule_format import FirewallRule

logger = logging.getLogger(__name__)


class RuleConverter:
    """Конвертер правил в команды фаервола"""

    def __init__(self, plugin_manager=None):
        """
        Инициализация конвертера

        Args:
            plugin_manager: Менеджер плагинов для применения правил
        """
        self.plugin_manager = plugin_manager

    def convert_to_plugin_format(self, rule: FirewallRule, plugin_id: str) -> Dict[str, Any]:
        """
        Конвертация унифицированного правила в формат плагина

        Args:
            rule: Унифицированное правило
            plugin_id: ID плагина (например, 'netsh', 'iptables')

        Returns:
            Правило в формате плагина
        """
        plugin_rule = {
            'name': rule.name,
            'direction': 'in' if rule.direction == 'inbound' else 'out',
            'action': rule.action,
            'protocol': rule.protocol,
        }

        # Порты
        if rule.targets.ports:
            ports_str = ','.join(rule.targets.ports)
            if ports_str.lower() != 'any':
                plugin_rule['local_port'] = ports_str
                plugin_rule['remote_port'] = ports_str

        # IP адреса
        if rule.targets.ips:
            ips_str = ','.join(rule.targets.ips)
            if ips_str.lower() != 'any':
                plugin_rule['remote_ip'] = ips_str

        # Домены (для плагинов, которые поддерживают)
        if rule.targets.domains:
            plugin_rule['domains'] = rule.targets.domains

        return plugin_rule

    async def apply_rule(self, rule: FirewallRule, plugin_id: str) -> Dict[str, Any]:
        """
        Применение правила через плагин

        Args:
            rule: Унифицированное правило
            plugin_id: ID плагина

        Returns:
            Результат применения
        """
        if not self.plugin_manager:
            return {'success': False, 'error': 'Plugin manager not available'}

        # Конвертируем в формат плагина
        plugin_rule = self.convert_to_plugin_format(rule, plugin_id)

        # Получаем плагин
        plugin_info = self.plugin_manager.plugins.get(plugin_id)
        if not plugin_info or not plugin_info.get('enabled'):
            return {'success': False, 'error': f'Plugin {plugin_id} not enabled'}

        instance = plugin_info.get('instance')
        if not instance:
            return {'success': False, 'error': f'Plugin {plugin_id} instance not available'}

        # Применяем правило
        try:
            result = await instance.apply_rule(plugin_rule)
            return result
        except Exception as e:
            logger.error(f"Error applying rule through plugin {plugin_id}: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}

    def convert_from_plugin_format(self, plugin_rule: Dict[str, Any], rule_id: str) -> FirewallRule:
        """
        Конвертация правила из формата плагина в унифицированный формат

        Args:
            plugin_rule: Правило в формате плагина
            rule_id: ID правила

        Returns:
            Унифицированное правило
        """
        from flamix.common.rule_format import RuleTargets

        targets = RuleTargets()

        # Порты
        if 'local_port' in plugin_rule and plugin_rule['local_port']:
            targets.ports.append(plugin_rule['local_port'])
        if 'remote_port' in plugin_rule and plugin_rule['remote_port']:
            if plugin_rule['remote_port'] not in targets.ports:
                targets.ports.append(plugin_rule['remote_port'])

        # IP адреса
        if 'remote_ip' in plugin_rule and plugin_rule['remote_ip']:
            # Разделяем по запятой если несколько IP
            ips = [ip.strip() for ip in plugin_rule['remote_ip'].split(',')]
            targets.ips.extend(ips)

        if 'local_ip' in plugin_rule and plugin_rule['local_ip']:
            ips = [ip.strip() for ip in plugin_rule['local_ip'].split(',')]
            targets.ips.extend(ips)

        # Домены
        if 'domains' in plugin_rule:
            targets.domains.extend(plugin_rule['domains'])

        # Направление
        direction = 'inbound' if plugin_rule.get('direction', 'in') == 'in' else 'outbound'

        # Протокол
        protocol = plugin_rule.get('protocol', 'TCP').upper()

        rule = FirewallRule(
            id=rule_id,
            name=plugin_rule.get('name', 'Unnamed rule'),
            action=plugin_rule.get('action', 'block'),
            direction=direction,
            targets=targets,
            protocol=protocol,
            enabled=plugin_rule.get('enabled', True)
        )

        return rule
