"""Пример минимального плагина для iptables"""

from flamix.api import PluginInterface, SecurityError


class MinimalIptablesPlugin(PluginInterface):
    """Минимальный плагин для управления iptables"""

    def __init__(self):
        super().__init__()
        self.active_firewall = None

    async def on_install(self):
        """Вызывается при установке плагина"""
        pass

    async def on_enable(self):
        """Вызывается при включении плагина"""
        pass

    async def on_init(self, core_api):
        """
        Инициализация плагина
        
        Args:
            core_api: Экземпляр CoreAPI для взаимодействия с ядром
        """
        self.core_api = core_api

        # Детект доступных firewall
        firewalls = await core_api.detect_firewalls()
        if not firewalls:
            raise RuntimeError("No firewall detected")

        # Выбираем firewall с highest priority
        self.active_firewall = sorted(
            firewalls,
            key=lambda x: x.get("priority", 0),
            reverse=True
        )[0]

        if self.active_firewall["name"] != "iptables":
            raise RuntimeError(
                f"Unsupported firewall: {self.active_firewall['name']}"
            )

    async def on_disable(self):
        """Вызывается при отключении плагина"""
        pass

    async def on_uninstall(self):
        """Вызывается при удалении плагина"""
        pass

    async def get_health(self):
        """
        Проверка здоровья плагина
        
        Returns:
            dict с ключом "status": "ok" | "degraded" | "critical"
        """
        if self.active_firewall:
            return {"status": "ok"}
        return {"status": "critical"}

    async def apply_rule(self, rule: dict):
        """
        Применение правила firewall
        
        Args:
            rule: Словарь с параметрами правила
                Пример: {
                    "port": 80,
                    "protocol": "tcp",
                    "action": "accept",
                    "chain": "INPUT"
                }
        """
        # Валидация входных данных
        port = rule.get("port")
        if port and not (1 <= port <= 65535):
            raise ValueError("Invalid port: must be between 1 and 65535")

        protocol = rule.get("protocol", "tcp")
        if protocol not in ["tcp", "udp"]:
            raise ValueError("Invalid protocol: must be 'tcp' or 'udp'")

        action = rule.get("action", "accept")
        if action not in ["accept", "drop", "reject"]:
            raise ValueError("Invalid action: must be 'accept', 'drop', or 'reject'")

        chain = rule.get("chain", "INPUT")
        if chain not in ["INPUT", "OUTPUT", "FORWARD"]:
            raise ValueError("Invalid chain: must be 'INPUT', 'OUTPUT', or 'FORWARD'")

        # Генерация БЕЗОПАСНОЙ команды
        cmd = [
            "iptables",
            "-A",
            chain,
            "-p",
            protocol,
        ]

        if port:
            cmd.extend(["--dport", str(port)])

        cmd.extend(["-j", action.upper()])

        # Выполнение через ядро (проверка permissions)
        result = await self.core_api.run_command_safely("iptables", cmd)
        if result["returncode"] != 0:
            raise RuntimeError(f"Command failed: {result['stderr']}")

        # Логирование аудита
        await self.core_api.log_audit(
            "apply_rule",
            "iptables",
            {
                "port": port,
                "protocol": protocol,
                "action": action,
                "chain": chain,
            }
        )

