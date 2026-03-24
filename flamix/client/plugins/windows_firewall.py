"""Windows Firewall plugin using netsh"""

import asyncio
import subprocess
import re
import logging
import os
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from flamix.client.plugins.base import FirewallPlugin

logger = logging.getLogger(__name__)


class WindowsFirewallPlugin(FirewallPlugin):
    """Plugin for managing Windows Firewall via netsh"""

    def __init__(self):
        super().__init__()
        self.netsh_path = self._find_netsh_path()
        self.log_path = None
        self._find_log_path()

    def _find_netsh_path(self) -> str:
        """Resolve netsh from PATH first and well-known Windows locations second."""
        resolved = shutil.which("netsh")
        if resolved:
            return resolved

        systemroot = Path(os.environ.get('SystemRoot', 'C:\\Windows'))
        candidates = [
            systemroot / "System32" / "netsh.exe",
            systemroot / "Sysnative" / "netsh.exe",
            systemroot / "system32" / "netsh.exe",
            systemroot / "sysnative" / "netsh.exe",
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)

        return "netsh"

    def _find_log_path(self):
        """Find Windows Firewall log path"""
        systemroot = os.environ.get('SystemRoot', 'C:\\Windows')
        possible_paths = [
            Path(systemroot) / "System32" / "LogFiles" / "Firewall" / "pfirewall.log",
            Path(systemroot) / "system32" / "logfiles" / "firewall" / "pfirewall.log",
        ]
        for path in possible_paths:
            if path.exists():
                self.log_path = path
                break

    def is_available(self) -> bool:
        """Check if netsh is available"""
        if os.name != 'nt':
            return False

        if self.netsh_path != "netsh" and not Path(self.netsh_path).exists():
            return False

        try:
            result = subprocess.run(
                [self.netsh_path, "advfirewall", "show", "allprofiles", "state"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutError):
            return False

    async def apply_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Apply a Windows Firewall rule via netsh"""
        try:
            required_fields = ["name", "direction", "action", "protocol"]
            for field in required_fields:
                if field not in rule:
                    return {
                        "success": False,
                        "error": f"Missing required field: {field}",
                        "rule_id": None
                    }

            rule_name = rule["name"]
            direction = rule["direction"]  # in or out
            action = rule["action"]  # allow or block
            protocol = rule.get("protocol", "TCP").upper()

            # Build netsh command
            cmd = [
                self.netsh_path,
                "advfirewall",
                "firewall",
                "add",
                "rule"
            ]

            cmd.append(f"name={rule_name}")
            cmd.append(f"dir={direction}")
            cmd.append(f"action={action}")

            if protocol == "ANY":
                cmd.append("protocol=any")
            else:
                cmd.append(f"protocol={protocol}")

            # Local port
            if "local_port" in rule and rule["local_port"]:
                port = rule["local_port"]
                if port.lower() != "any":
                    cmd.append(f"localport={port}")

            # Remote port
            if "remote_port" in rule and rule["remote_port"]:
                port = rule["remote_port"]
                if port.lower() != "any":
                    cmd.append(f"remoteport={port}")

            # Local IP
            if "local_ip" in rule and rule["local_ip"]:
                local_ip = rule["local_ip"]
                if local_ip.lower() not in ("any", "all"):
                    cmd.append(f"localip={local_ip}")

            # Remote IP
            if "remote_ip" in rule and rule["remote_ip"]:
                remote_ip = rule["remote_ip"]
                if remote_ip.lower() not in ("any", "all"):
                    cmd.append(f"remoteip={remote_ip}")

            # Profile (optional)
            if "profile" in rule and rule["profile"]:
                profile = rule["profile"]
                if profile.lower() != "any":
                    cmd.append(f"profile={profile.lower()}")

            # Execute command
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info(f"Applied Windows Firewall rule: {rule_name}")
                return {
                    "success": True,
                    "rule_id": rule_name,
                    "message": f"Rule '{rule_name}' applied successfully"
                }
            else:
                error_msg = stderr.decode('utf-8', errors='ignore') or stdout.decode('utf-8', errors='ignore')
                logger.error(f"Failed to apply Windows Firewall rule: {error_msg}")
                return {
                    "success": False,
                    "error": f"netsh command failed: {error_msg}",
                    "rule_id": None
                }

        except Exception as e:
            logger.error(f"Error applying Windows Firewall rule: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "rule_id": None
            }

    async def remove_rule(self, rule_name: str) -> Dict[str, Any]:
        """Remove a Windows Firewall rule"""
        try:
            cmd = [
                self.netsh_path,
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                f"name={rule_name}"
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info(f"Removed Windows Firewall rule: {rule_name}")
                return {"success": True}
            else:
                error_msg = stderr.decode('utf-8', errors='ignore') or stdout.decode('utf-8', errors='ignore')
                return {
                    "success": False,
                    "error": f"Failed to remove rule: {error_msg}"
                }

        except Exception as e:
            logger.error(f"Error removing Windows Firewall rule: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    async def get_current_rules(self) -> List[Dict[str, Any]]:
        """Get list of current Windows Firewall rules"""
        try:
            cmd = [
                self.netsh_path,
                "advfirewall",
                "firewall",
                "show",
                "rule",
                "name=all"
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error(f"Failed to list Windows Firewall rules: {stderr.decode('utf-8', errors='ignore')}")
                return []

            rules = []
            output = stdout.decode('utf-8', errors='ignore')
            current_rule = {}

            for line in output.split('\n'):
                line = line.strip()
                if line.startswith("Rule Name:"):
                    if current_rule:
                        rules.append(current_rule)
                    current_rule = {"name": line.split(":", 1)[1].strip()}
                elif line.startswith("Enabled:") and current_rule:
                    current_rule["enabled"] = "Yes" in line
                elif line.startswith("Direction:") and current_rule:
                    current_rule["direction"] = line.split(":", 1)[1].strip().lower()
                elif line.startswith("Profiles:") and current_rule:
                    current_rule["profiles"] = line.split(":", 1)[1].strip()
                elif line.startswith("Action:") and current_rule:
                    current_rule["action"] = line.split(":", 1)[1].strip().lower()
                elif line.startswith("Protocol:") and current_rule:
                    current_rule["protocol"] = line.split(":", 1)[1].strip()

            if current_rule:
                rules.append(current_rule)

            return rules

        except Exception as e:
            logger.error(f"Error getting Windows Firewall rules: {e}", exc_info=True)
            return []

    async def get_traffic_stats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get traffic statistics from Windows Firewall log"""
        stats = []

        if not self.log_path or not self.log_path.exists():
            # Try to read from Event Log as fallback
            return await self._get_traffic_from_event_log(limit)

        try:
            # Read last lines from log file
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                recent_lines = lines[-limit * 2:]  # Get more lines to filter

            for line in recent_lines:
                entry = self._parse_firewall_log_line(line)
                if entry:
                    stats.append(entry)
                    if len(stats) >= limit:
                        break

            # Sort by timestamp (most recent first)
            stats.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            return stats[:limit]

        except Exception as e:
            logger.debug(f"Error reading Windows Firewall log: {e}")
            # Fallback to Event Log
            return await self._get_traffic_from_event_log(limit)

    def _parse_firewall_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a Windows Firewall log line"""
        try:
            # Windows Firewall log format (CSV):
            # date,time,action,protocol,src-ip,dst-ip,src-port,dst-port,size,tcpflags,tcpsyn,tcpack,tcpwin,icmptype,icmpcode,info,path
            parts = line.split(',')
            if len(parts) < 8:
                return None

            entry = {}

            # Date and time
            if len(parts) >= 2:
                date_str = parts[0].strip()
                time_str = parts[1].strip()
                try:
                    dt = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
                    entry["timestamp"] = dt.isoformat() + "Z"
                except ValueError:
                    entry["timestamp"] = datetime.utcnow().isoformat() + "Z"

            # Action
            if len(parts) >= 3:
                action = parts[2].strip()
                entry["action"] = "allow" if action == "ALLOW" else "block"

            # Protocol
            if len(parts) >= 4:
                entry["protocol"] = parts[3].strip().upper()

            # Source IP
            if len(parts) >= 5:
                entry["src_ip"] = parts[4].strip()

            # Destination IP
            if len(parts) >= 6:
                entry["dst_ip"] = parts[5].strip()

            # Source port
            if len(parts) >= 7:
                try:
                    entry["src_port"] = int(parts[6].strip())
                except ValueError:
                    pass

            # Destination port
            if len(parts) >= 8:
                try:
                    entry["dst_port"] = int(parts[7].strip())
                except ValueError:
                    pass

            # Size (bytes)
            if len(parts) >= 9:
                try:
                    entry["bytes_in"] = int(parts[8].strip())
                except ValueError:
                    pass

            # Only return if we have at least src or dst IP
            if entry.get("src_ip") or entry.get("dst_ip"):
                return entry

        except Exception as e:
            logger.debug(f"Error parsing firewall log line: {e}")

        return None

    async def _get_traffic_from_event_log(self, limit: int) -> List[Dict[str, Any]]:
        """Get traffic stats from Windows Event Log as fallback"""
        stats = []
        try:
            # Try PowerShell Get-WinEvent
            ps_cmd = [
                "powershell",
                "-Command",
                "Get-WinEvent -LogName 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' -MaxEvents " + str(limit) + " | Select-Object TimeCreated, Message | Format-List"
            ]

            process = await asyncio.create_subprocess_exec(
                *ps_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                output = stdout.decode('utf-8', errors='ignore')
                # Parse PowerShell output (simplified)
                # This is a basic implementation - could be enhanced
                for line in output.split('\n'):
                    if 'TimeCreated' in line or 'Message' in line:
                        # Extract relevant info
                        # This is simplified - full parsing would be more complex
                        pass

        except Exception as e:
            logger.debug(f"Error reading from Event Log: {e}")

        return stats

    async def get_health(self) -> Dict[str, Any]:
        """Check plugin health"""
        try:
            available = self.is_available()
            if not available:
                return {
                    "status": "error",
                    "error": "netsh command not available",
                    "netsh_path": self.netsh_path
                }

            # Check firewall state
            cmd = [self.netsh_path, "advfirewall", "show", "allprofiles", "state"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                output = stdout.decode('utf-8', errors='ignore')
                firewall_enabled = "ON" in output or "State ON" in output

                return {
                    "status": "ok",
                    "netsh_available": True,
                    "netsh_path": self.netsh_path,
                    "firewall_enabled": firewall_enabled,
                    "log_path": str(self.log_path) if self.log_path else None
                }
            else:
                return {
                    "status": "warning",
                    "netsh_available": True,
                    "netsh_path": self.netsh_path,
                    "error": "Cannot check firewall state (may need administrator privileges)"
                }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
