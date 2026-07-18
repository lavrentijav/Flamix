"""Плагин для управления Windows Firewall через NetSh"""

import asyncio
import subprocess
import re
import logging
import sys
from typing import Dict, Any, Optional
from flamix.api.plugin_interface import PluginInterface

logger = logging.getLogger(__name__)


class NetShPlugin(PluginInterface):
    """Плагин для управления Windows Firewall через NetSh"""
    
    def __init__(self):
        super().__init__()
        self.netsh_path = "netsh"
        self._firewall_enabled = None
    
    async def on_install(self):
        """Вызывается при установке плагина"""
        logger.info(f"[{self.plugin_id}] NetSh plugin installed")
    
    async def on_enable(self):
        """Вызывается при включении плагина"""
        logger.info(f"[{self.plugin_id}] NetSh plugin enabled")
        # Проверяем доступность NetSh
        if not await self._check_netsh_available():
            raise RuntimeError("NetSh is not available on this system")
    
    async def on_init(self, core_api):
        """Вызывается при инициализации плагина"""
        await super().on_init(core_api)
        logger.info(f"[{self.plugin_id}] NetSh plugin initialized")
    
    async def on_disable(self):
        """Вызывается при отключении плагина"""
        logger.info(f"[{self.plugin_id}] NetSh plugin disabled")
    
    async def on_uninstall(self):
        """Вызывается при удалении плагина"""
        logger.info(f"[{self.plugin_id}] NetSh plugin uninstalled")
    
    async def get_health(self) -> Dict[str, Any]:
        """Проверка состояния плагина"""
        try:
            netsh_available = await self._check_netsh_available()
            firewall_state = await self._get_firewall_state()
            
            return {
                "status": "ok" if netsh_available else "error",
                "netsh_available": netsh_available,
                "firewall_enabled": firewall_state.get("enabled", False),
                "firewall_profiles": firewall_state.get("profiles", {})
            }
        except Exception as e:
            logger.error(f"[{self.plugin_id}] Health check failed: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def apply_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """
        Применение правила файрвола через NetSh
        
        Args:
            rule: Словарь с параметрами правила
            
        Returns:
            dict с результатом применения правила
        """
        # Принудительно выводим логи в самом начале
        import sys
        sys.stdout.write(f"[DEBUG PLUGIN] apply_rule method called for {self.plugin_id}\n")
        sys.stdout.write(f"[DEBUG PLUGIN] rule = {rule}\n")
        sys.stdout.write(f"[DEBUG PLUGIN] core_api = {self.core_api}\n")
        sys.stdout.flush()
        
        logger.info(f"[{self.plugin_id}] ===== apply_rule START =====")
        logger.info(f"[{self.plugin_id}] apply_rule called with rule: {rule}")
        logger.info(f"[{self.plugin_id}] CoreAPI available: {self.core_api is not None}")
        sys.stdout.write(f"[DEBUG PLUGIN] ===== apply_rule START =====\n")
        sys.stdout.write(f"[DEBUG PLUGIN] rule: {rule}\n")
        sys.stdout.write(f"[DEBUG PLUGIN] CoreAPI available: {self.core_api is not None}\n")
        sys.stdout.flush()
        
        try:
            sys.stdout.write(f"[DEBUG] Inside try block\n")
            sys.stdout.flush()
            
            # Валидация обязательных полей
            required_fields = ["name", "direction", "action", "protocol"]
            for field in required_fields:
                if field not in rule:
                    sys.stdout.write(f"[DEBUG] Missing field: {field}\n")
                    sys.stdout.flush()
                    return {
                        "success": False,
                        "error": f"Missing required field: {field}",
                        "rule_id": None
                    }
            
            sys.stdout.write(f"[DEBUG] All fields validated\n")
            sys.stdout.flush()
            
            rule_name = rule["name"]
            direction = rule["direction"]  # in или out
            action = rule["action"]  # allow или block
            protocol = rule["protocol"]  # TCP, UDP, ICMP, ANY
            
            # Формируем команду NetSh
            cmd = [
                self.netsh_path,
                "advfirewall",
                "firewall",
                "add",
                "rule"
            ]
            
            # Имя правила
            cmd.append(f"name={rule_name}")
            
            # Направление
            cmd.append(f"dir={direction}")
            
            # Действие
            cmd.append(f"action={action}")
            
            # Протокол
            if protocol.upper() == "ANY":
                cmd.append("protocol=any")
            else:
                cmd.append(f"protocol={protocol.upper()}")
            
            # Локальный порт
            if "local_port" in rule and rule["local_port"]:
                local_port = rule["local_port"]
                if local_port.lower() != "any":
                    cmd.append(f"localport={local_port}")
            
            # Удаленный порт
            if "remote_port" in rule and rule["remote_port"]:
                remote_port = rule["remote_port"]
                if remote_port.lower() != "any":
                    cmd.append(f"remoteport={remote_port}")
            
            # Локальный IP
            if "local_ip" in rule and rule["local_ip"]:
                local_ip = rule["local_ip"]
                if local_ip and local_ip.lower() not in ("any", "all"):
                    cmd.append(f"localip={local_ip}")
            
            # Удаленный IP
            if "remote_ip" in rule and rule["remote_ip"]:
                remote_ip = rule["remote_ip"]
                if remote_ip and remote_ip.lower() not in ("any", "all"):
                    cmd.append(f"remoteip={remote_ip}")
            
            # Профиль
            if "profile" in rule and rule["profile"]:
                profile = rule["profile"]
                if profile.lower() != "any":
                    cmd.append(f"profile={profile.lower()}")
            
            # Программа
            if "program" in rule and rule["program"]:
                cmd.append(f"program={rule['program']}")
            
            logger.info(f"[{self.plugin_id}] Final command: {cmd}")
            sys.stdout.write(f"[DEBUG] Final command: {cmd}\n")
            sys.stdout.flush()
            
            # Выполняем команду через CoreAPI для безопасности
            if not self.core_api:
                sys.stdout.write(f"[DEBUG] CoreAPI is not available!\n")
                sys.stdout.flush()
                logger.error(f"[{self.plugin_id}] CoreAPI is not available!")
                return {
                    "success": False,
                    "error": "CoreAPI is not available. Plugin may not be properly initialized.",
                    "rule_id": None
                }
            
            sys.stdout.write(f"[DEBUG] CoreAPI is available, proceeding\n")
            sys.stdout.flush()
            
            # Формируем аргументы (без netsh, так как он передается как command)
            args = cmd[1:]  # Убираем netsh из начала
            
            logger.info(f"[{self.plugin_id}] Executing command: {self.netsh_path} {' '.join(args)}")
            sys.stdout.write(f"[DEBUG] About to call run_command_safely with args: {args}\n")
            sys.stdout.flush()
            
            try:
                sys.stdout.write(f"[DEBUG] Calling run_command_safely...\n")
                sys.stdout.flush()
                result = await self.core_api.run_command_safely(
                    self.netsh_path,
                    args
                )
                sys.stdout.write(f"[DEBUG] run_command_safely returned\n")
                sys.stdout.flush()
                logger.info(f"[{self.plugin_id}] run_command_safely returned")
                
                # Принудительно выводим результат
                import sys
                sys.stdout.write(f"[DEBUG PLUGIN] result type: {type(result)}\n")
                sys.stdout.write(f"[DEBUG PLUGIN] result keys: {list(result.keys()) if isinstance(result, dict) else 'not a dict'}\n")
                sys.stdout.flush()
                
                returncode = result.get("returncode", -1)
                stdout = result.get("stdout", "") or ""
                stderr = result.get("stderr", "") or ""
                
                # Логируем результат
                sys.stdout.write(f"[DEBUG PLUGIN] returncode: {returncode}\n")
                sys.stdout.write(f"[DEBUG PLUGIN] stdout type: {type(stdout)}, length: {len(stdout)}, content: {repr(stdout[:500])}\n")
                sys.stdout.write(f"[DEBUG PLUGIN] stderr type: {type(stderr)}, length: {len(stderr)}, content: {repr(stderr[:500])}\n")
                sys.stdout.flush()
                
                logger.info(f"[{self.plugin_id}] Command executed: returncode={returncode}")
                logger.info(f"[{self.plugin_id}] stdout length: {len(stdout)}, stderr length: {len(stderr)}")
                if stdout:
                    logger.info(f"[{self.plugin_id}] stdout: {stdout[:500]}")
                if stderr:
                    logger.info(f"[{self.plugin_id}] stderr: {stderr[:500]}")
                
                if returncode == 0:
                    logger.info(f"[{self.plugin_id}] Rule '{rule_name}' applied successfully")
                    return {
                        "success": True,
                        "rule_id": rule_name,
                        "message": f"Rule '{rule_name}' applied successfully"
                    }
                else:
                    # Безопасно обрабатываем stdout и stderr
                    stdout_str = str(stdout) if stdout is not None else ""
                    stderr_str = str(stderr) if stderr is not None else ""
                    
                    # Объединяем stderr и stdout для получения полного сообщения
                    error_parts = []
                    if stderr_str and stderr_str.strip():
                        error_parts.append(stderr_str.strip())
                    if stdout_str and stdout_str.strip():
                        error_parts.append(stdout_str.strip())
                    error_msg = " ".join(error_parts) if error_parts else ""
                    
                    sys.stdout.write(f"[DEBUG PLUGIN] returncode != 0: {returncode}\n")
                    sys.stdout.write(f"[DEBUG PLUGIN] stdout type: {type(stdout)}, value: {repr(stdout)}\n")
                    sys.stdout.write(f"[DEBUG PLUGIN] stderr type: {type(stderr)}, value: {repr(stderr)}\n")
                    sys.stdout.write(f"[DEBUG PLUGIN] error_msg before processing: {repr(error_msg)}\n")
                    sys.stdout.flush()
                    
                    # Если сообщение пустое, создаем понятное сообщение
                    if not error_msg or error_msg.strip() == "":
                        error_msg = f"Command failed with return code {returncode}. This operation requires administrator privileges. Please run the command as administrator."
                        sys.stdout.write(f"[DEBUG PLUGIN] error_msg is empty, setting default message\n")
                        sys.stdout.flush()
                    else:
                        # Проверяем на типичные ошибки Windows (на русском и английском)
                        error_lower = error_msg.lower()
                        admin_keywords = [
                            "повышение прав", "elevation", "administrator", 
                            "права администратора", "requires elevation",
                            "запустите с правами администратора", "requires administrator"
                        ]
                        if any(keyword in error_lower for keyword in admin_keywords):
                            error_msg = "This operation requires administrator privileges. Please run the command as administrator."
                            sys.stdout.write(f"[DEBUG PLUGIN] Found admin keyword, setting admin message\n")
                            sys.stdout.flush()
                    
                    sys.stdout.write(f"[DEBUG PLUGIN] Final error_msg: {repr(error_msg)}\n")
                    sys.stdout.write(f"[DEBUG PLUGIN] Final error_msg length: {len(error_msg)}\n")
                    sys.stdout.flush()
                    
                    # Убеждаемся, что error_msg не пустой ПЕРЕД логированием
                    if not error_msg or not error_msg.strip():
                        error_msg = f"Command failed with return code {returncode}. This operation requires administrator privileges. Please run the command as administrator."
                        sys.stdout.write(f"[DEBUG PLUGIN] error_msg was empty, set to: {repr(error_msg)}\n")
                        sys.stdout.flush()
                    
                    # Еще раз проверяем перед логированием
                    final_error = error_msg if error_msg and error_msg.strip() else f"Command failed with return code {returncode}. This operation requires administrator privileges. Please run the command as administrator."
                    
                    sys.stdout.write(f"[DEBUG PLUGIN] About to log error: {repr(final_error)}\n")
                    sys.stdout.write(f"[DEBUG PLUGIN] final_error length: {len(final_error)}\n")
                    sys.stdout.flush()
                    
                    logger.error(f"[{self.plugin_id}] Failed to apply rule '{rule_name}': {final_error}")
                    logger.error(f"[{self.plugin_id}] Full stdout: {repr(stdout)}")
                    logger.error(f"[{self.plugin_id}] Full stderr: {repr(stderr)}")
                    
                    # Финальная проверка перед возвратом
                    if not final_error or not final_error.strip():
                        final_error = f"Command failed with return code {returncode}. This operation requires administrator privileges. Please run the command as administrator."
                    
                    sys.stdout.write(f"[DEBUG PLUGIN] Returning error (final): {repr(final_error)}\n")
                    sys.stdout.write(f"[DEBUG PLUGIN] Returning error length: {len(final_error)}\n")
                    sys.stdout.flush()
                    
                    result_dict = {
                        "success": False,
                        "error": final_error,
                        "rule_id": None
                    }
                    
                    sys.stdout.write(f"[DEBUG PLUGIN] Result dict: {result_dict}\n")
                    sys.stdout.flush()
                    
                    return result_dict
            except Exception as api_error:
                import sys
                import traceback
                sys.stdout.write(f"[DEBUG PLUGIN] CoreAPI exception caught: {type(api_error).__name__}: {api_error}\n")
                traceback.print_exc()
                sys.stdout.flush()
                logger.error(f"[{self.plugin_id}] CoreAPI error: {api_error}", exc_info=True)
                
                error_msg = str(api_error) if api_error else "Unknown CoreAPI error"
                if not error_msg or not error_msg.strip():
                    error_msg = f"CoreAPI error: {type(api_error).__name__}"
                
                # Проверяем на SecurityError
                from flamix.api.core_api import SecurityError
                if isinstance(api_error, SecurityError):
                    error_msg = f"Permission denied: {error_msg}. Please check plugin permissions."
                
                sys.stdout.write(f"[DEBUG PLUGIN] Returning CoreAPI error: {repr(error_msg)}\n")
                sys.stdout.flush()
                
                return {
                    "success": False,
                    "error": error_msg,
                    "rule_id": None
                }
        
        except Exception as e:
            import sys
            import traceback
            sys.stdout.write(f"[DEBUG PLUGIN] Exception caught in apply_rule: {e}\n")
            sys.stdout.write(f"[DEBUG PLUGIN] Exception type: {type(e)}\n")
            sys.stdout.write(f"[DEBUG PLUGIN] Exception str: {repr(str(e))}\n")
            traceback.print_exc()
            sys.stdout.flush()
            logger.error(f"[{self.plugin_id}] Error applying rule: {e}", exc_info=True)
            
            # Убеждаемся, что error_msg не пустой
            error_msg = str(e) if e else "Unknown error"
            if not error_msg or not error_msg.strip():
                error_msg = f"Unknown error occurred while applying rule. Exception type: {type(e).__name__}"
            
            return {
                "success": False,
                "error": error_msg,
                "rule_id": None
            }
    
    async def _check_netsh_available(self) -> bool:
        """Проверка доступности NetSh"""
        try:
            if self.core_api:
                result = await self.core_api.run_command_safely(
                    self.netsh_path,
                    ["advfirewall", "show", "allprofiles", "state"]
                )
                return result.get("returncode") == 0
            else:
                # Fallback
                process = await asyncio.create_subprocess_exec(
                    self.netsh_path,
                    "advfirewall",
                    "show",
                    "allprofiles",
                    "state",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                await process.communicate()
                return process.returncode == 0
        except Exception:
            return False
    
    async def _get_firewall_state(self) -> Dict[str, Any]:
        """Получение состояния Windows Firewall"""
        try:
            if self.core_api:
                result = await self.core_api.run_command_safely(
                    self.netsh_path,
                    ["advfirewall", "show", "allprofiles", "state"]
                )
                
                if result.get("returncode") == 0:
                    output = result.get("stdout", "")
                    profiles = {}
                    enabled = False
                    
                    # Парсим вывод
                    current_profile = None
                    for line in output.split('\n'):
                        line = line.strip()
                        if 'Profile' in line:
                            # Извлекаем имя профиля
                            match = re.search(r'Profile\s+(\w+)', line)
                            if match:
                                current_profile = match.group(1).lower()
                                profiles[current_profile] = {"enabled": False}
                        elif 'State' in line and current_profile:
                            if 'ON' in line:
                                profiles[current_profile]["enabled"] = True
                                enabled = True
                    
                    return {
                        "enabled": enabled,
                        "profiles": profiles
                    }
            
            return {"enabled": False, "profiles": {}}
        except Exception as e:
            logger.error(f"[{self.plugin_id}] Error getting firewall state: {e}")
            return {"enabled": False, "profiles": {}}


# Экспортируем класс плагина
Plugin = NetShPlugin
