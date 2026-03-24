"""Core API for safe plugin operations"""

import asyncio
import subprocess
import logging
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import platform

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Security-related error in Core API"""
    pass


class CoreAPI:
    """Core API for safe plugin operations"""
    
    def __init__(self, plugin_id: str, permissions: Optional[List[str]] = None):
        """
        Initialize Core API
        
        Args:
            plugin_id: ID of the plugin using this API
            permissions: List of permissions granted to the plugin
        """
        self.plugin_id = plugin_id
        self.permissions = permissions or []
        logger.debug(f"CoreAPI initialized for plugin {plugin_id} with permissions: {permissions}")
    
    async def run_command_safely(self, command: str, args: List[str]) -> Dict[str, Any]:
        """
        Safely execute a command with arguments
        
        Args:
            command: Command to execute
            args: List of command arguments
        
        Returns:
            Dict with 'returncode' (int), 'stdout' (str), 'stderr' (str)
        
        Raises:
            SecurityError: If command is not allowed by plugin permissions
        """
        # Check if plugin has permission to run shell commands
        permission_key = f"run_shell_commands:{command}"
        if not any(perm.startswith("run_shell_commands:") for perm in self.permissions):
            # Check for wildcard permission
            if "run_shell_commands:*" not in self.permissions:
                raise SecurityError(f"Plugin {self.plugin_id} does not have permission to run command: {command}")
        
        logger.debug(f"Plugin {self.plugin_id} executing command: {command} {' '.join(args)}")
        
        try:
            # Create subprocess
            if platform.system() == "Windows":
                # On Windows, use CREATE_NO_WINDOW to hide console window
                process = await asyncio.create_subprocess_exec(
                    command,
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                process = await asyncio.create_subprocess_exec(
                    command,
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            
            stdout, stderr = await process.communicate()
            
            return {
                "returncode": process.returncode,
                "stdout": stdout.decode('utf-8', errors='replace') if stdout else "",
                "stderr": stderr.decode('utf-8', errors='replace') if stderr else ""
            }
        except FileNotFoundError:
            logger.error(f"Command not found: {command}")
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": f"Command not found: {command}"
            }
        except Exception as e:
            logger.error(f"Error executing command {command}: {e}", exc_info=True)
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": str(e)
            }
    
    async def read_file(self, path: str) -> str:
        """
        Read file contents safely
        
        Args:
            path: Path to file to read
        
        Returns:
            File contents as string
        
        Raises:
            SecurityError: If file access is not allowed
            FileNotFoundError: If file does not exist
        """
        # Check if plugin has permission to read files
        if "read_files" not in self.permissions and "*" not in self.permissions:
            raise SecurityError(f"Plugin {self.plugin_id} does not have permission to read files")
        
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading file {path}: {e}")
            raise
    
    async def write_file(self, path: str, content: str) -> bool:
        """
        Write file contents safely
        
        Args:
            path: Path to file to write
            content: Content to write
        
        Returns:
            True if successful
        
        Raises:
            SecurityError: If file access is not allowed
        """
        # Check if plugin has permission to write files
        if "write_files" not in self.permissions and "*" not in self.permissions:
            raise SecurityError(f"Plugin {self.plugin_id} does not have permission to write files")
        
        file_path = Path(path)
        try:
            # Create parent directories if needed
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return True
        except Exception as e:
            logger.error(f"Error writing file {path}: {e}")
            raise
    
    async def detect_firewalls(self) -> List[Dict[str, Any]]:
        """
        Detect available firewalls on the system
        
        Returns:
            List of firewall information dictionaries
        """
        firewalls = []
        
        # Detect Windows Firewall
        if platform.system() == "Windows":
            try:
                result = await self.run_command_safely(
                    "netsh",
                    ["advfirewall", "show", "allprofiles", "state"]
                )
                if result["returncode"] == 0:
                    firewalls.append({
                        "name": "Windows Firewall",
                        "type": "windows",
                        "available": True,
                        "enabled": "ON" in result["stdout"]
                    })
            except Exception as e:
                logger.debug(f"Windows Firewall detection failed: {e}")
        
        # Detect iptables (Linux)
        elif platform.system() == "Linux":
            try:
                result = await self.run_command_safely("iptables", ["--version"])
                if result["returncode"] == 0:
                    firewalls.append({
                        "name": "iptables",
                        "type": "linux",
                        "available": True,
                        "enabled": True
                    })
            except Exception as e:
                logger.debug(f"iptables detection failed: {e}")
        
        return firewalls
