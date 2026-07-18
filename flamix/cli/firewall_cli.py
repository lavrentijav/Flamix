"""CLI модуль для управления Windows Firewall через netsh"""

import subprocess
import re
import json
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class FirewallCLIError(Exception):
    """Ошибка при работе с CLI файрвола"""
    pass


class FirewallCLI:
    """CLI для управления Windows Firewall через netsh"""

    def __init__(self):
        self.netsh_path = "netsh"
        self.profile_map = {
            "domain": "domainprofile",
            "private": "privateprofile",
            "public": "publicprofile"
        }

    def _run_netsh(self, *args, timeout: float = 30.0) -> Dict[str, Any]:
        """
        Выполнение команды netsh
        
        Args:
            *args: Аргументы команды netsh
            timeout: Таймаут выполнения в секундах
            
        Returns:
            dict с ключами: returncode, stdout, stderr
            
        Raises:
            FirewallCLIError: При ошибке выполнения команды
        """
        try:
            cmd = [self.netsh_path] + list(args)
            logger.debug(f"Executing: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='replace'
            )
            
            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        except subprocess.TimeoutExpired:
            raise FirewallCLIError(f"Command timeout after {timeout} seconds")
        except Exception as e:
            raise FirewallCLIError(f"Failed to execute netsh: {e}")

    def list_rules(self, profile: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Получение списка правил файрвола
        
        Args:
            profile: Профиль (domain, private, public) или None для всех
            
        Returns:
            Список словарей с информацией о правилах
        """
        rules = []
        
        profiles = [profile] if profile else ["domain", "private", "public"]
        
        for prof in profiles:
            profile_name = self.profile_map.get(prof, prof)
            
            # Получаем правила для профиля
            result = self._run_netsh(
                "advfirewall", "firewall", "show", "rule",
                f"name=all", f"profile={profile_name}", "verbose"
            )
            
            if result["returncode"] != 0:
                logger.warning(f"Failed to get rules for profile {prof}: {result['stderr']}")
                continue
            
            # Парсим вывод
            parsed_rules = self._parse_rules_output(result["stdout"], prof)
            rules.extend(parsed_rules)
        
        return rules

    def _parse_rules_output(self, output: str, profile: str) -> List[Dict[str, Any]]:
        """
        Парсинг вывода netsh для извлечения правил
        
        Args:
            output: Вывод команды netsh
            profile: Профиль правил
            
        Returns:
            Список словарей с правилами
        """
        rules = []
        current_rule = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if not line:
                if current_rule:
                    current_rule["profile"] = profile
                    rules.append(current_rule)
                    current_rule = {}
                continue
            
            # Определяем начало нового правила
            if line.startswith("Rule Name:"):
                if current_rule:
                    current_rule["profile"] = profile
                    rules.append(current_rule)
                current_rule = {"name": line.split(":", 1)[1].strip()}
            elif ":" in line and current_rule:
                key, value = line.split(":", 1)
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()
                
                # Обработка специальных полей
                if key == "enabled":
                    current_rule[key] = value.lower() == "yes"
                elif key == "direction":
                    current_rule[key] = value.lower()
                elif key == "profiles":
                    current_rule["profiles_list"] = [p.strip() for p in value.split(",")]
                elif key == "localip":
                    current_rule["local_ip"] = value
                elif key == "remoteip":
                    current_rule["remote_ip"] = value
                elif key == "localport":
                    current_rule["local_port"] = value
                elif key == "remoteport":
                    current_rule["remote_port"] = value
                elif key == "protocol":
                    current_rule["protocol"] = value.upper()
                elif key == "action":
                    current_rule["action"] = value.lower()
                else:
                    current_rule[key] = value
        
        # Добавляем последнее правило
        if current_rule:
            current_rule["profile"] = profile
            rules.append(current_rule)
        
        return rules

    def add_rule(
        self,
        name: str,
        direction: str = "in",
        action: str = "block",
        protocol: Optional[str] = None,
        local_port: Optional[str] = None,
        remote_port: Optional[str] = None,
        local_ip: Optional[str] = None,
        remote_ip: Optional[str] = None,
        profile: Optional[str] = None,
        enabled: bool = True
    ) -> bool:
        """
        Добавление правила файрвола
        
        Args:
            name: Имя правила
            direction: Направление (in/out)
            action: Действие (allow/block)
            protocol: Протокол (TCP, UDP, ICMP и т.д.)
            local_port: Локальный порт (число или диапазон, например "80" или "8000-9000")
            remote_port: Удаленный порт
            local_ip: Локальный IP (Any, LocalSubnet, конкретный IP)
            remote_ip: Удаленный IP
            profile: Профиль (domain, private, public) или None для всех
            enabled: Включено ли правило
            
        Returns:
            True если успешно
        """
        # Строим команду
        cmd = ["advfirewall", "firewall", "add", "rule"]
        cmd.append(f"name={name}")
        cmd.append(f"dir={direction}")
        cmd.append(f"action={action}")
        
        if protocol:
            cmd.append(f"protocol={protocol}")
        if local_port:
            cmd.append(f"localport={local_port}")
        if remote_port:
            cmd.append(f"remoteport={remote_port}")
        if local_ip:
            cmd.append(f"localip={local_ip}")
        if remote_ip:
            cmd.append(f"remoteip={remote_ip}")
        if profile:
            profile_name = self.profile_map.get(profile, profile)
            cmd.append(f"profile={profile_name}")
        if not enabled:
            cmd.append("enable=no")
        
        result = self._run_netsh(*cmd)
        
        if result["returncode"] != 0:
            error_msg = result["stderr"] or result["stdout"]
            raise FirewallCLIError(f"Failed to add rule: {error_msg}")
        
        return True

    def delete_rule(self, name: str, profile: Optional[str] = None) -> bool:
        """
        Удаление правила файрвола
        
        Args:
            name: Имя правила
            profile: Профиль (domain, private, public) или None для всех
            
        Returns:
            True если успешно
        """
        profiles = [profile] if profile else ["domain", "private", "public"]
        
        for prof in profiles:
            profile_name = self.profile_map.get(prof, prof)
            
            cmd = ["advfirewall", "firewall", "delete", "rule"]
            cmd.append(f"name={name}")
            cmd.append(f"profile={profile_name}")
            
            result = self._run_netsh(*cmd)
            
            if result["returncode"] != 0:
                logger.warning(f"Failed to delete rule {name} from profile {prof}: {result['stderr']}")
        
        return True

    def modify_rule(
        self,
        name: str,
        new_name: Optional[str] = None,
        action: Optional[str] = None,
        protocol: Optional[str] = None,
        local_port: Optional[str] = None,
        remote_port: Optional[str] = None,
        local_ip: Optional[str] = None,
        remote_ip: Optional[str] = None,
        profile: Optional[str] = None,
        enabled: Optional[bool] = None
    ) -> bool:
        """
        Изменение существующего правила файрвола
        
        Args:
            name: Имя существующего правила
            new_name: Новое имя правила
            action: Новое действие (allow/block)
            protocol: Новый протокол
            local_port: Новый локальный порт
            remote_port: Новый удаленный порт
            local_ip: Новый локальный IP
            remote_ip: Новый удаленный IP
            profile: Профиль (domain, private, public) или None для всех
            enabled: Включено ли правило
            
        Returns:
            True если успешно
        """
        # Для изменения правила нужно сначала удалить старое, затем создать новое
        # Или использовать команду set, но она работает только для некоторых полей
        
        # Получаем текущее правило
        rules = self.list_rules(profile)
        current_rule = None
        
        for rule in rules:
            if rule.get("name") == name:
                current_rule = rule
                break
        
        if not current_rule:
            raise FirewallCLIError(f"Rule {name} not found")
        
        # Используем значения из текущего правила, если новые не указаны
        final_name = new_name or current_rule.get("name")
        final_action = action or current_rule.get("action", "block")
        final_protocol = protocol or current_rule.get("protocol")
        final_local_port = local_port or current_rule.get("local_port")
        final_remote_port = remote_port or current_rule.get("remote_port")
        final_local_ip = local_ip or current_rule.get("local_ip", "Any")
        final_remote_ip = remote_ip or current_rule.get("remote_ip", "Any")
        final_enabled = enabled if enabled is not None else current_rule.get("enabled", True)
        final_direction = current_rule.get("direction", "in")
        
        # Если имя изменилось, создаем новое правило и удаляем старое
        if new_name and new_name != name:
            self.add_rule(
                name=final_name,
                direction=final_direction,
                action=final_action,
                protocol=final_protocol,
                local_port=final_local_port,
                remote_port=final_remote_port,
                local_ip=final_local_ip,
                remote_ip=final_remote_ip,
                profile=profile,
                enabled=final_enabled
            )
            self.delete_rule(name, profile)
        else:
            # Используем set для изменения существующего правила
            profiles = [profile] if profile else ["domain", "private", "public"]
            
            for prof in profiles:
                profile_name = self.profile_map.get(prof, prof)
                
                cmd = ["advfirewall", "firewall", "set", "rule"]
                cmd.append(f"name={name}")
                cmd.append(f"profile={profile_name}")
                
                if action:
                    cmd.append(f"new", f"action={action}")
                if protocol:
                    cmd.append(f"new", f"protocol={protocol}")
                if local_port:
                    cmd.append(f"new", f"localport={local_port}")
                if remote_port:
                    cmd.append(f"new", f"remoteport={remote_port}")
                if local_ip:
                    cmd.append(f"new", f"localip={local_ip}")
                if remote_ip:
                    cmd.append(f"new", f"remoteip={remote_ip}")
                if enabled is not None:
                    cmd.append("new", f"enable={'yes' if enabled else 'no'}")
                
                if len(cmd) > 4:  # Если есть изменения
                    result = self._run_netsh(*cmd)
                    
                    if result["returncode"] != 0:
                        logger.warning(f"Failed to modify rule {name} in profile {prof}: {result['stderr']}")
        
        return True

    def get_rule_by_name(self, name: str, profile: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Получение правила по имени
        
        Args:
            name: Имя правила
            profile: Профиль (domain, private, public) или None для всех
            
        Returns:
            Словарь с информацией о правиле или None если не найдено
        """
        rules = self.list_rules(profile)
        
        for rule in rules:
            if rule.get("name") == name:
                return rule
        
        return None
