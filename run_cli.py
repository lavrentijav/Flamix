#!/usr/bin/env python3
"""Запуск CLI Flamix без установки"""

import sys
from pathlib import Path

# Добавление пути к модулям
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Запуск CLI
if __name__ == "__main__":
    from flamix.cli.main import main
    main()

