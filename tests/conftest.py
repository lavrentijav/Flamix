"""Конфигурация pytest для тестов"""

import os
import pytest

# Устанавливаем переменную окружения для отключения шифрования в тестах
os.environ['FLAMIX_DISABLE_ENCRYPTION'] = '1'


@pytest.fixture(autouse=True)
def disable_encryption():
    """Автоматически отключает шифрование для всех тестов"""
    # Эта фикстура применяется ко всем тестам автоматически
    pass
