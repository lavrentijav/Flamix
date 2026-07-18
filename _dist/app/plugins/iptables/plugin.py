"""
Демонстрационный плагин для iptables (Linux).
Фактически не применяет правила, а имитирует успешную работу.
"""

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class IptablesPlugin:
    plugin_id = "com.flamix.iptables"
    name = "iptables Firewall Plugin"

    async def apply_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """
        Имитация применения правила iptables.
        Реальной модификации нет (демо-режим).
        """
        logger.info(f"[{self.plugin_id}] apply_rule (demo): {rule}")
        return {
            "success": True,
            "rule_id": f"demo-{rule.get('name','rule')}"
        }


# Экспортируем класс
Plugin = IptablesPlugin
