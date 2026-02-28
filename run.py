#!/usr/bin/env python3
"""Точка входа для запуска сервера Flamix"""

import asyncio
import logging
import sys
from pathlib import Path

# Добавляем путь к модулям
sys.path.insert(0, str(Path(__file__).parent))

from flamix.server.server import FlamixServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

logger = logging.getLogger(__name__)


def setup_asyncio_exception_handler():
    """Настраивает обработчик исключений для asyncio на Windows"""
    def exception_handler(loop, context):
        """Обработчик исключений для asyncio event loop"""
        exception = context.get('exception')
        # Подавляем ошибки разрыва соединения - это нормальное поведение
        # когда клиент закрывает соединение до завершения обработки
        if isinstance(exception, ConnectionResetError):
            # Логируем только на уровне DEBUG, чтобы не засорять логи
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Connection reset by peer (normal): {context.get('message', '')}")
            return
        
        # Для других исключений используем стандартную обработку
        if 'exception' in context:
            logger.error(f"Unhandled exception in asyncio: {context.get('message', '')}", 
                        exc_info=context.get('exception'))
        else:
            logger.error(f"Unhandled error in asyncio: {context.get('message', '')}")
    
    # Устанавливаем обработчик для нового event loop
    try:
        loop = asyncio.get_event_loop()
        loop.set_exception_handler(exception_handler)
    except RuntimeError:
        # Если нет текущего event loop, обработчик будет установлен при создании
        pass


async def main():
    """Главная функция запуска сервера"""
    import argparse

    parser = argparse.ArgumentParser(description="Flamix Server")
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8443,
        help="Port to bind to (default: 8443)"
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default="data/server.db",
        help="Path to database file (default: data/server.db)"
    )
    parser.add_argument(
        "--cert-dir",
        type=str,
        default="certs",
        help="Directory for certificates (default: certs)"
    )
    parser.add_argument(
        "--web-enabled",
        action="store_true",
        default=True,
        help="Enable web interface (default: True)"
    )
    parser.add_argument(
        "--web-disable",
        action="store_true",
        help="Disable web interface"
    )
    parser.add_argument(
        "--web-host",
        type=str,
        default="127.0.0.1",
        help="Web interface host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--web-port",
        type=int,
        default=8080,
        help="Web interface port (default: 8080)"
    )

    args = parser.parse_args()
    
    # Обработка флагов веб-интерфейса
    web_enabled = args.web_enabled and not args.web_disable

    # Создаем директории если нужно
    Path(args.db_path).parent.mkdir(parents=True, exist_ok=True)
    Path(args.cert_dir).mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("Starting Flamix Server")
    logger.info(f"Host: {args.host}")
    logger.info(f"Port: {args.port}")
    logger.info(f"Database: {args.db_path}")
    logger.info(f"Certificates: {args.cert_dir}")
    logger.info(f"Web interface: {'enabled' if web_enabled else 'disabled'}")
    if web_enabled:
        logger.info(f"Web interface: http://{args.web_host}:{args.web_port}")
    logger.info("=" * 60)

    server = FlamixServer(
        host=args.host,
        port=args.port,
        db_path=Path(args.db_path),
        cert_dir=Path(args.cert_dir),
        web_enabled=web_enabled,
        web_host=args.web_host,
        web_port=args.web_port
    )

    try:
        await server.start()
        logger.info("Server is running. Press Ctrl+C to stop.")
        await asyncio.Event().wait()  # Бесконечное ожидание
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        await server.stop()
        logger.info("Server stopped")


if __name__ == "__main__":
    # Настраиваем обработчик исключений для asyncio перед запуском
    setup_asyncio_exception_handler()
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutdown complete")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
