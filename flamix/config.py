"""Конфигурация Flamix"""

import os
from pathlib import Path
from typing import Optional

# Базовые пути
# Определяем базовую директорию проекта (где находится config.py)
_PROJECT_ROOT = Path(__file__).parent.parent.resolve()

# Спрятанная папка для сборки демо/презентации
_BUNDLE_ROOT = _PROJECT_ROOT / "_dist" / "app"

# Директории
DATA_DIR = _BUNDLE_ROOT / "data"
PLUGINS_DIR = _BUNDLE_ROOT / "plugins"
LOG_DIR = _BUNDLE_ROOT / "logs"

# Файлы
DB_PATH = DATA_DIR / "rules.db"


def ensure_directories():
    """Создание необходимых директорий"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
