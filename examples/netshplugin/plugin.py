"""Плагин для управления Windows Firewall через netsh"""

import re
from flamix.api import PluginInterface, SecurityError


class WindowsFirewallPlugin(PluginInterface):
    """Плагин для управления Windows Firewall через netsh"""

    def __init__(self):
        super().__init__()
        self.active_firewall = None
        self.firewall_enabled = False

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

        if self.active_firewall["name"] != "windows_firewall":
            raise RuntimeError(
                f"Unsupported firewall: {self.active_firewall['name']}"
            )

        # Проверка состояния firewall
        await self._check_firewall_state()

    async def _check_firewall_state(self):
        """Проверка состояния Windows Firewall"""
        try:
            # Проверка через netsh
            result = await self.core_api.run_command_safely(
                "netsh",
                ["advfirewall", "show", "allprofiles", "state"]
            )

            if result["returncode"] == 0:
                output = result["stdout"]
                # Поиск состояния
                if re.search(r"State\s+ON", output, re.IGNORECASE):
                    self.firewall_enabled = True
                elif re.search(r"Состояние\s+ВКЛЮЧИТЬ", output, re.IGNORECASE):
                    self.firewall_enabled = True
                elif re.search(r"State\s+OFF", output, re.IGNORECASE):
                    self.firewall_enabled = False
                else:
                    # Альтернативный формат
                    if "enabled" in output.lower():
                        self.firewall_enabled = True
                    elif "disabled" in output.lower():
                        self.firewall_enabled = False

        except Exception as e:
            self.core_api.logger.warning(f"Could not check firewall state: {e}")

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
        if not self.active_firewall:
            return {"status": "critical"}

        # Проверка состояния firewall
        try:
            await self._check_firewall_state()
            if not self.firewall_enabled:
                return {
                    "status": "degraded",
                    "message": "Windows Firewall is disabled"
                }
            return {"status": "ok"}
        except Exception as e:
            return {
                "status": "degraded",
                "message": f"Could not check firewall state: {e}"
            }

    async def apply_rule(self, rule: dict):
        """
        Применение правила firewall
        
        Args:
            rule: Словарь с параметрами правила
                Пример: {
                    "name": "Allow HTTP",
                    "port": 80,
                    "protocol": "tcp",
                    "action": "allow",
                    "direction": "in",
                    "profile": "any"  # domain, private, public, any
                }
        """
        # Валидация входных данных
        port = rule.get("port")
        if port and not (1 <= port <= 65535):
            raise ValueError("Invalid port: must be between 1 and 65535")

        protocol = rule.get("protocol", "tcp").lower()
        if protocol not in ["tcp", "udp", "icmp", "any"]:
            raise ValueError(
                "Invalid protocol: must be 'tcp', 'udp', 'icmp', or 'any'"
            )

        action = rule.get("action", "allow").lower()
        if action not in ["allow", "block"]:
            raise ValueError("Invalid action: must be 'allow' or 'block'")

        direction = rule.get("direction", "in").lower()
        if direction not in ["in", "out"]:
            raise ValueError("Invalid direction: must be 'in' or 'out'")

        profile = rule.get("profile", "any").lower()
        if profile not in ["domain", "private", "public", "any"]:
            raise ValueError(
                "Invalid profile: must be 'domain', 'private', 'public', or 'any'"
            )

        rule_name = rule.get("name", f"Flamix Rule {port}")
        if not rule_name:
            raise ValueError("Rule name is required")

        # Генерация БЕЗОПАСНОЙ команды netsh
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule"
        ]

        # Имя правила
        cmd.extend(["name", rule_name])

        # Направление
        cmd.extend(["dir", direction])

        # Действие
        cmd.extend(["action", action])

        # Протокол
        if protocol != "any":
            cmd.extend(["protocol", protocol.upper()])

        # Порт (если указан)
        if port and protocol in ["tcp", "udp"]:
            cmd.extend(["localport", str(port)])

        # Профиль
        if profile != "any":
            cmd.extend(["profile", profile])

        # Выполнение через ядро (проверка permissions)
        result = await self.core_api.run_command_safely("netsh", cmd)
        if result["returncode"] != 0:
            error_msg = result["stderr"] or result["stdout"]
            raise RuntimeError(f"Command failed: {error_msg}")

        # Логирование аудита
        await self.core_api.log_audit(
            "apply_rule",
            "windows_firewall",
            {
                "name": rule_name,
                "port": port,
                "protocol": protocol,
                "action": action,
                "direction": direction,
                "profile": profile,
            }
        )

    async def delete_rule(self, rule_name: str):
        """
        Удаление правила firewall
        
        Args:
            rule_name: Имя правила для удаления
        """
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            "name",
            rule_name
        ]

        result = await self.core_api.run_command_safely("netsh", cmd)
        if result["returncode"] != 0:
            error_msg = result["stderr"] or result["stdout"]
            raise RuntimeError(f"Command failed: {error_msg}")

        await self.core_api.log_audit(
            "delete_rule",
            "windows_firewall",
            {"name": rule_name}
        )

    async def list_rules(self, profile: str = "any"):
        """
        Список правил firewall
        
        Args:
            profile: Профиль (domain, private, public, any)
            
        Returns:
            Список правил
        """
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "show",
            "rule",
            "name",
            "all"
        ]

        if profile != "any":
            cmd.extend(["profile", profile])

        result = await self.core_api.run_command_safely("netsh", cmd)
        if result["returncode"] != 0:
            raise RuntimeError(f"Command failed: {result['stderr']}")

        # Парсинг вывода (упрощенный)
        rules = []
        output = result["stdout"]
        # Простой парсинг - в реальности нужен более сложный
        for line in output.split("\n"):
            if "Rule Name:" in line:
                rule_name = line.split("Rule Name:")[1].strip()
                rules.append({"name": rule_name})

        return rules

