#!/usr/bin/env python3
"""Тестовый скрипт для проверки GUI"""

import sys
from pathlib import Path

# Добавление пути к модулям
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from PySide6.QtWidgets import QApplication, QMainWindow, QLabel
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    """Минимальный тест GUI"""
    try:
        logger.info("Creating QApplication...")
        app = QApplication(sys.argv)
        logger.info("QApplication created")
        
        logger.info("Creating main window...")
        window = QMainWindow()
        window.setWindowTitle("Flamix Test")
        window.setGeometry(100, 100, 800, 600)
        
        label = QLabel("Flamix GUI Test - If you see this, GUI works!")
        window.setCentralWidget(label)
        
        logger.info("Showing window...")
        window.show()
        logger.info("Window shown, entering event loop...")
        
        return app.exec()
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())

