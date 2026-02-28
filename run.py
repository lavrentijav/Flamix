#!/usr/bin/env python3
"""Точка входа для запуска GUI приложения Flamix"""

import sys
from pathlib import Path

# Добавляем путь к модулям
sys.path.insert(0, str(Path(__file__).parent))

from app.gui import FlamixGUI

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Flamix GUI Application")
    parser.add_argument(
        "--server-url",
        type=str,
        default="https://127.0.0.1:8080",
        help="Server URL (default: https://127.0.0.1:8080)"
    )

    args = parser.parse_args()

    app = FlamixGUI(args.server_url)
    app.run()
