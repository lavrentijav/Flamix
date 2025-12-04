"""Windows Named Pipe клиент (альтернативная реализация)"""

import asyncio
import json
import logging
from typing import Any, Optional
import os

logger = logging.getLogger(__name__)


async def connect_named_pipe_windows(pipe_name: str):
    """
    Подключение к Named Pipe на Windows
    
    Использует win32pipe если доступен, иначе возвращает None
    """
    try:
        # Пробуем использовать win32pipe если установлен
        import win32pipe
        import win32file
        import pywintypes
        
        # Открываем Named Pipe
        handle = win32file.CreateFile(
            pipe_name,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            0,
            None
        )
        
        # Создаем обертку для asyncio
        class NamedPipeWrapper:
            def __init__(self, handle):
                self.handle = handle
                self._closed = False
            
            async def read(self, n):
                """Чтение из pipe"""
                if self._closed:
                    raise ConnectionError("Pipe closed")
                try:
                    result, data = win32file.ReadFile(self.handle, n)
                    return data
                except pywintypes.error as e:
                    if e.winerror == 109:  # ERROR_BROKEN_PIPE
                        self._closed = True
                        raise ConnectionError("Pipe broken")
                    raise
            
            async def write(self, data):
                """Запись в pipe"""
                if self._closed:
                    raise ConnectionError("Pipe closed")
                win32file.WriteFile(self.handle, data)
            
            def close(self):
                """Закрытие pipe"""
                if not self._closed:
                    win32file.CloseHandle(self.handle)
                    self._closed = True
        
        return NamedPipeWrapper(handle)
        
    except ImportError:
        logger.warning("win32pipe not available, Named Pipe client disabled")
        return None
    except Exception as e:
        logger.error(f"Failed to connect to Named Pipe: {e}")
        return None

