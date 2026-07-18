"""Конфигурация Flamix"""

import os
from pathlib import Path
from typing import Optional

# Базовые пути
# Определяем базовую директорию проекта (где находится config.py)
_PROJECT_ROOT = Path(__file__).parent.parent.resolve()

if os.name == 'nt':  # Windows
    # Для демо-версии используем директорию проекта
    BASE_DIR = _PROJECT_ROOT / 'demo' / 'data'
    # Для плагинов и логов используем директорию проекта
    SYSTEM_BASE_DIR = _PROJECT_ROOT / 'demo'
else:  # Linux/macOS
    BASE_DIR = _PROJECT_ROOT / 'demo' / 'data'
    SYSTEM_BASE_DIR = _PROJECT_ROOT / 'demo'

# Директории
DATA_DIR = BASE_DIR
# Плагины и логи в директории проекта
PLUGINS_DIR = _PROJECT_ROOT / 'plugins'
LOG_DIR = _PROJECT_ROOT / 'demo' / 'logs'

# Файлы
DB_PATH = DATA_DIR / 'rules.db'


def ensure_directories():
    """Создание необходимых директорий"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
