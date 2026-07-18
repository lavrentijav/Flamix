"""CLI модуль для блокировки/разблокировки IP"""

import subprocess
import sys
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# IP адрес для блокировки (можно изменить)
TARGET_IP = "131.107.255.255"
def get_rule_name(ip: str) -> str:
    """Генерация уникального имени правила для IP"""
    return f"Flamix_Block_{ip.replace('.', '_')}"


def block_ip(ip: str = TARGET_IP):
    """Блокировка IP адреса"""
    try:
        logger.info(f"Блокируем IP: {ip}")
        
        rule_name = get_rule_name(ip)
        
        # Проверяем, существует ли правило
        check_cmd = [
            "netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}_In"
        ]
        check_result = subprocess.run(
            check_cmd,
            capture_output=True,
            text=True,
            timeout=10,
            encoding='utf-8',
            errors='replace'
        )
        
        # Если правило существует, удаляем его
        if check_result.returncode == 0 and "No rules match" not in check_result.stdout:
            logger.info(f"Правило '{rule_name}' уже существует, удаляем старое...")
            delete_cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_In"
            ]
            subprocess.run(delete_cmd, capture_output=True, timeout=10, encoding='utf-8', errors='replace')
            delete_cmd_out = [
                "netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_Out"
            ]
            subprocess.run(delete_cmd_out, capture_output=True, timeout=10, encoding='utf-8', errors='replace')
        
        # Создаем правило блокировки для входящего трафика
        cmd_in = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}_In",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
            "protocol=any",
            "enable=yes"
        ]
        
        # Создаем правило блокировки для исходящего трафика
        cmd_out = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}_Out",
            "dir=out",
            "action=block",
            f"remoteip={ip}",
            "protocol=any",
            "enable=yes"
        ]
        
        result_in = subprocess.run(
            cmd_in,
            capture_output=True,
            text=True,
            timeout=30,
            encoding='utf-8',
            errors='replace'
        )
        
        result_out = subprocess.run(
            cmd_out,
            capture_output=True,
            text=True,
            timeout=30,
            encoding='utf-8',
            errors='replace'
        )
        
        if result_in.returncode == 0 and result_out.returncode == 0:
            logger.info(f"IP {ip} успешно заблокирован (входящий и исходящий трафик)")
            print(f"[OK] IP {ip} заблокирован")
            return True
        else:
            error_msg = result_in.stderr or result_out.stderr or result_in.stdout or result_out.stdout
            logger.error(f"Ошибка блокировки: {error_msg}")
            print(f"[ERROR] Ошибка блокировки: {error_msg}")
            return False
            
    except Exception as e:
        logger.error(f"Исключение при блокировке: {e}")
        print(f"[ERROR] Исключение: {e}")
        return False


def unblock_ip(ip: str = TARGET_IP):
    """Разблокировка IP адреса"""
    try:
        logger.info(f"Разблокируем IP: {ip}")
        
        rule_name = get_rule_name(ip)
        
        # Удаляем правила для входящего и исходящего трафика
        cmd_in = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}_In"
        ]
        
        cmd_out = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}_Out"
        ]
        
        result_in = subprocess.run(
            cmd_in,
            capture_output=True,
            text=True,
            timeout=30,
            encoding='utf-8',
            errors='replace'
        )
        
        result_out = subprocess.run(
            cmd_out,
            capture_output=True,
            text=True,
            timeout=30,
            encoding='utf-8',
            errors='replace'
        )
        
        # Считаем успешным, если хотя бы одно правило удалено или оба не найдены
        success = (result_in.returncode == 0 or "No rules match" in result_in.stdout or "No rules match" in result_in.stderr) and \
                 (result_out.returncode == 0 or "No rules match" in result_out.stdout or "No rules match" in result_out.stderr)
        
        if success:
            logger.info(f"IP {ip} успешно разблокирован")
            print(f"[OK] IP {ip} разблокирован")
            return True
        else:
            error_msg = result_in.stderr or result_out.stderr
            logger.warning(f"Ошибка при разблокировке: {error_msg}")
            print(f"[WARNING] Ошибка при разблокировке: {error_msg}")
            return False
            
    except Exception as e:
        logger.error(f"Исключение при разблокировке: {e}")
        print(f"[ERROR] Исключение: {e}")
        return False


def main():
    """Главная функция CLI"""
    if len(sys.argv) < 2:
        print("Использование:")
        print("  python firewall_cli.py block [IP]   - заблокировать IP")
        print("  python firewall_cli.py unblock [IP] - разблокировать IP")
        print(f"\nПо умолчанию используется IP: {TARGET_IP}")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    ip = sys.argv[2] if len(sys.argv) > 2 else TARGET_IP
    
    if command == "block":
        success = block_ip(ip)
        sys.exit(0 if success else 1)
    elif command == "unblock":
        success = unblock_ip(ip)
        sys.exit(0 if success else 1)
    else:
        print(f"Неизвестная команда: {command}")
        print("Используйте: block или unblock")
        sys.exit(1)


if __name__ == "__main__":
    main()
