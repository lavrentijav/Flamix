"""Конфигурация Flamix"""

import os
from pathlib import Path
from typing import Optional

# Базовые пути
if os.name == "nt":  # Windows
    BASE_DIR = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "flamix"
    PLUGINS_DIR = BASE_DIR / "plugins"
    DATA_DIR = BASE_DIR / "data"
    LOG_DIR = BASE_DIR / "logs"
    SOCKET_PATH = None  # Используем Named Pipe на Windows
    NAMED_PIPE_NAME = r"\\.\pipe\flamix_agent"
else:  # Linux/macOS
    BASE_DIR = Path("/var/lib/flamix")
    PLUGINS_DIR = BASE_DIR / "plugins"
    DATA_DIR = BASE_DIR / "data"
    LOG_DIR = Path("/var/log/flamix")
    SOCKET_PATH = BASE_DIR / "flamix_agent.sock"
    NAMED_PIPE_NAME = None

# База данных
DB_PATH = DATA_DIR / "rules.db"
SNAPSHOTS_DIR = DATA_DIR / "snapshots"
TRUSTED_KEYS_DIR = DATA_DIR / "trusted_keys"

# Настройки безопасности
IPC_TIMEOUT = 30  # секунд
IPC_HEARTBEAT_INTERVAL = 10  # секунд
IPC_HEARTBEAT_MISSED_THRESHOLD = 3

# Логирование
LOG_MAX_SIZE_MB = 100
LOG_RETENTION_DAYS = 90

# API версия
API_VERSION = "1.0"


def ensure_directories():
    """Создает необходимые директории"""
    for directory in [PLUGINS_DIR, DATA_DIR, LOG_DIR, SNAPSHOTS_DIR, TRUSTED_KEYS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)

