"""Точка входа для GUI приложения Flamix"""

import sys
from pathlib import Path

# Добавляем корневую директорию проекта в путь
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Импортируем и запускаем GUI из flamix.services.app
try:
    from flamix.services.app import main
except ImportError as e:
    print(f"Error importing from flamix.services.app: {e}")
    print("Trying alternative import...")
    try:
        # Попробуем из flamix.app
        from flamix.app import main
    except ImportError:
        # Последняя попытка - простой запуск MainWindow
        print("Creating simple GUI launcher...")
        from flamix.gui.main import MainWindow
        from PySide6.QtWidgets import QApplication
        import logging
        
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )
        
        def main():
            app = QApplication(sys.argv)
            window = MainWindow()
            window.show()
            return app.exec()

if __name__ == "__main__":
    main()
