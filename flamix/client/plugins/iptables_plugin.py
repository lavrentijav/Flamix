"""iptables plugin for Linux firewall management"""

import asyncio
import subprocess
import re
import logging
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from flamix.client.plugins.base import FirewallPlugin

logger = logging.getLogger(__name__)


class IptablesPlugin(FirewallPlugin):
    """Plugin for managing iptables firewall on Linux"""

    def __init__(self):
        super().__init__()
        self.iptables_cmd = "iptables"
        self.ip6tables_cmd = "ip6tables"
        self.log_paths = [
            "/var/log/kern.log",
            "/var/log/syslog",
            "/var/log/messages"
        ]

    def is_available(self) -> bool:
        """Check if iptables is available"""
        try:
            result = subprocess.run(
                [self.iptables_cmd, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutError):
            return False

    async def apply_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Apply an iptables rule"""
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

            # Build iptables command
            cmd = [self.iptables_cmd]

            # Chain selection
            if direction == "in":
                chain = "INPUT"
            else:
                chain = "OUTPUT"

            # Action
            if action == "block":
                target = "DROP"
            else:
                target = "ACCEPT"

            cmd.extend(["-A", chain])

            # Protocol
            if protocol != "ANY":
                cmd.extend(["-p", protocol.lower()])

            # Source IP
            if "remote_ip" in rule and rule["remote_ip"]:
                remote_ip = rule["remote_ip"]
                if remote_ip.lower() not in ("any", "all"):
                    if direction == "in":
                        cmd.extend(["-s", remote_ip])
                    else:
                        cmd.extend(["-d", remote_ip])

            # Destination IP
            if "local_ip" in rule and rule["local_ip"]:
                local_ip = rule["local_ip"]
                if local_ip.lower() not in ("any", "all"):
                    if direction == "in":
                        cmd.extend(["-d", local_ip])
                    else:
                        cmd.extend(["-s", local_ip])

            # Ports
            if "remote_port" in rule and rule["remote_port"]:
                port = rule["remote_port"]
                if port.lower() != "any":
                    if direction == "in":
                        cmd.extend(["--sport", port])
                    else:
                        cmd.extend(["--dport", port])

            if "local_port" in rule and rule["local_port"]:
                port = rule["local_port"]
                if port.lower() != "any":
                    if direction == "in":
                        cmd.extend(["--dport", port])
                    else:
                        cmd.extend(["--sport", port])

            # Comment for rule identification
            cmd.extend(["-m", "comment", "--comment", f"Flamix: {rule_name}"])

            # Target
            cmd.append("-j")
            cmd.append(target)

            # Execute command
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info(f"Applied iptables rule: {rule_name}")
                return {
                    "success": True,
                    "rule_id": rule_name,
                    "message": f"Rule '{rule_name}' applied successfully"
                }
            else:
                error_msg = stderr.decode('utf-8', errors='ignore') or stdout.decode('utf-8', errors='ignore')
                logger.error(f"Failed to apply iptables rule: {error_msg}")
                return {
                    "success": False,
                    "error": f"iptables command failed: {error_msg}",
                    "rule_id": None
                }

        except Exception as e:
            logger.error(f"Error applying iptables rule: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "rule_id": None
            }

    async def remove_rule(self, rule_name: str) -> Dict[str, Any]:
        """Remove an iptables rule by name"""
        try:
            # List all rules and find the one with matching comment
            cmd = [self.iptables_cmd, "-L", "-n", "--line-numbers", "-v"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to list rules: {stderr.decode('utf-8', errors='ignore')}"
                }

            # Parse output to find rule
            lines = stdout.decode('utf-8', errors='ignore').split('\n')
            for line in lines:
                if f"Flamix: {rule_name}" in line:
                    # Extract chain and line number
                    parts = line.split()
                    if len(parts) >= 1:
                        line_num = parts[0]
                        chain = None
                        # Find chain name (usually in previous lines or in the line itself)
                        for i, l in enumerate(lines):
                            if l.startswith("Chain") and i < lines.index(line):
                                chain_match = re.search(r'Chain (\w+)', l)
                                if chain_match:
                                    chain = chain_match.group(1)
                                    break

                        if chain and line_num.isdigit():
                            # Delete rule
                            del_cmd = [self.iptables_cmd, "-D", chain, line_num]
                            del_process = await asyncio.create_subprocess_exec(
                                *del_cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE
                            )
                            await del_process.communicate()

                            if del_process.returncode == 0:
                                logger.info(f"Removed iptables rule: {rule_name}")
                                return {"success": True}
                            else:
                                return {
                                    "success": False,
                                    "error": "Failed to delete rule"
                                }

            return {
                "success": False,
                "error": f"Rule '{rule_name}' not found"
            }

        except Exception as e:
            logger.error(f"Error removing iptables rule: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    async def get_current_rules(self) -> List[Dict[str, Any]]:
        """Get list of current iptables rules"""
        try:
            cmd = [self.iptables_cmd, "-L", "-n", "-v", "--line-numbers"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error(f"Failed to list iptables rules: {stderr.decode('utf-8', errors='ignore')}")
                return []

            rules = []
            lines = stdout.decode('utf-8', errors='ignore').split('\n')
            current_chain = None

            for line in lines:
                line = line.strip()
                if line.startswith("Chain"):
                    chain_match = re.search(r'Chain (\w+)', line)
                    if chain_match:
                        current_chain = chain_match.group(1)
                elif line and not line.startswith("target") and current_chain:
                    # Parse rule line
                    parts = line.split()
                    if len(parts) >= 2:
                        target = parts[0]
                        protocol = parts[1] if len(parts) > 1 else "all"
                        source = parts[3] if len(parts) > 3 else "any"
                        destination = parts[4] if len(parts) > 4 else "any"

                        # Extract comment if present
                        comment = ""
                        if "Flamix:" in line:
                            comment_match = re.search(r'Flamix: (.+?)(?:\s|$)', line)
                            if comment_match:
                                comment = comment_match.group(1)

                        if comment or target in ("DROP", "ACCEPT", "REJECT"):
                            rules.append({
                                "name": comment or f"{current_chain}-{target}",
                                "chain": current_chain,
                                "target": target,
                                "protocol": protocol,
                                "source": source,
                                "destination": destination
                            })

            return rules

        except Exception as e:
            logger.error(f"Error getting iptables rules: {e}", exc_info=True)
            return []

    async def get_traffic_stats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get traffic statistics from iptables logs"""
        stats = []

        # Try to read from log files
        for log_path in self.log_paths:
            if os.path.exists(log_path) and os.access(log_path, os.R_OK):
                try:
                    # Read last N lines
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        # Get last lines that might contain iptables entries
                        recent_lines = lines[-limit * 2:]  # Get more lines to filter

                    for line in recent_lines:
                        # Look for iptables LOG entries
                        if "iptables" in line.lower() or "IN=" in line or "OUT=" in line:
                            entry = self._parse_iptables_log_line(line)
                            if entry:
                                stats.append(entry)
                                if len(stats) >= limit:
                                    break

                    if stats:
                        break  # Found stats, no need to check other log files

                except Exception as e:
                    logger.debug(f"Error reading log file {log_path}: {e}")
                    continue

        # Also try to get counters from iptables
        try:
            cmd = [self.iptables_cmd, "-L", "-v", "-n", "-x"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                # Parse counter output
                lines = stdout.decode('utf-8', errors='ignore').split('\n')
                for line in lines:
                    if "Flamix:" in line:
                        # Extract packet and byte counts
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                packets = int(parts[0])
                                bytes_count = int(parts[1])
                                # This gives us aggregate stats, not per-connection
                                # We'll use it to supplement log data
                            except ValueError:
                                pass
        except Exception as e:
            logger.debug(f"Error getting iptables counters: {e}")

        # Sort by timestamp (most recent first) and limit
        stats.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return stats[:limit]

    def _parse_iptables_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single iptables log line"""
        try:
            # Common iptables log format:
            # IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8 LEN=... PROTO=TCP SPT=12345 DPT=80
            entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",  # Log files may not have precise timestamps
                "action": "allow",  # Default, will be determined by rule target
            }

            # Extract SRC
            src_match = re.search(r'SRC=([^\s]+)', line)
            if src_match:
                entry["src_ip"] = src_match.group(1)

            # Extract DST
            dst_match = re.search(r'DST=([^\s]+)', line)
            if dst_match:
                entry["dst_ip"] = dst_match.group(1)

            # Extract SPT (source port)
            spt_match = re.search(r'SPT=(\d+)', line)
            if spt_match:
                entry["src_port"] = int(spt_match.group(1))

            # Extract DPT (destination port)
            dpt_match = re.search(r'DPT=(\d+)', line)
            if dpt_match:
                entry["dst_port"] = int(dpt_match.group(1))

            # Extract PROTO
            proto_match = re.search(r'PROTO=(\w+)', line)
            if proto_match:
                entry["protocol"] = proto_match.group(1).upper()

            # Extract LEN (packet length, approximate bytes)
            len_match = re.search(r'LEN=(\d+)', line)
            if len_match:
                entry["bytes_in"] = int(len_match.group(1))

            # Only return if we have at least src or dst IP
            if entry.get("src_ip") or entry.get("dst_ip"):
                return entry

        except Exception as e:
            logger.debug(f"Error parsing iptables log line: {e}")

        return None

    async def get_health(self) -> Dict[str, Any]:
        """Check plugin health"""
        try:
            available = self.is_available()
            if not available:
                return {
                    "status": "error",
                    "error": "iptables command not available"
                }

            # Try to list rules as a health check
            cmd = [self.iptables_cmd, "-L", "-n"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            await process.communicate()

            if process.returncode == 0:
                return {
                    "status": "ok",
                    "iptables_available": True,
                    "can_list_rules": True
                }
            else:
                return {
                    "status": "warning",
                    "iptables_available": True,
                    "can_list_rules": False,
                    "error": "Cannot list rules (may need root privileges)"
                }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
