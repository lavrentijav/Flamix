"""Проверка доступности IP через переменные окружения"""

import os
import sys
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Переменная окружения для проверки доступности
ENV_VAR_NAME = "FLAMIX_IP_ACCESSIBLE"
TARGET_IP = "131.107.255.255"


def check_ip_accessible(ip: str = TARGET_IP) -> bool:
    """
    Проверка доступности IP через переменные окружения
    
    Args:
        ip: IP адрес для проверки
        
    Returns:
        True если IP доступен, False если заблокирован
    """
    # Читаем переменную окружения
    env_value = os.environ.get(ENV_VAR_NAME, "").lower()
    
    logger.info(f"Проверка доступности IP: {ip}")
    logger.info(f"Переменная окружения {ENV_VAR_NAME} = {env_value}")
    
    # Если переменная установлена в "true", "1", "yes" - IP доступен
    if env_value in ("true", "1", "yes", "on"):
        logger.info(f"IP {ip} доступен (согласно переменной окружения)")
        print(f"[OK] IP {ip} доступен")
        return True
    else:
        logger.info(f"IP {ip} недоступен (согласно переменной окружения)")
        print(f"[BLOCKED] IP {ip} недоступен")
        return False


def main():
    """Главная функция проверки"""
    ip = sys.argv[1] if len(sys.argv) > 1 else TARGET_IP
    
    accessible = check_ip_accessible(ip)
    
    # Возвращаем код выхода: 0 если доступен, 1 если недоступен
    sys.exit(0 if accessible else 1)


if __name__ == "__main__":
    main()
