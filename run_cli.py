"""CLI интерфейс для управления файрволом через плагины"""

import sys
import argparse
import json
import logging
from pathlib import Path

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    """Главная функция CLI"""
    parser = argparse.ArgumentParser(
        description="Flamix CLI - управление файрволом через плагины"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Команды")
    
    # Команда list-rules - список правил
    list_parser = subparsers.add_parser("list-rules", help="Список правил файрвола")
    list_parser.add_argument(
        "--plugin", 
        required=True,
        help="ID плагина для управления файрволом"
    )
    list_parser.add_argument(
        "--profile",
        choices=["domain", "private", "public"],
        help="Профиль файрвола (domain, private, public)"
    )
    list_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Формат вывода (json, table)"
    )
    
    # Команда add-rule - добавление правила
    add_parser = subparsers.add_parser("add-rule", help="Добавление правила файрвола")
    add_parser.add_argument(
        "--plugin",
        required=True,
        help="ID плагина для управления файрволом"
    )
    add_parser.add_argument(
        "--name",
        required=True,
        help="Имя правила"
    )
    add_parser.add_argument(
        "--direction",
        choices=["in", "out"],
        default="in",
        help="Направление (in/out)"
    )
    add_parser.add_argument(
        "--action",
        choices=["allow", "block"],
        default="block",
        help="Действие (allow/block)"
    )
    add_parser.add_argument(
        "--protocol",
        help="Протокол (TCP, UDP, ICMP и т.д.)"
    )
    add_parser.add_argument(
        "--local-port",
        help="Локальный порт (число или диапазон)"
    )
    add_parser.add_argument(
        "--remote-port",
        help="Удаленный порт"
    )
    add_parser.add_argument(
        "--local-ip",
        default="Any",
        help="Локальный IP (Any, LocalSubnet, или конкретный IP)"
    )
    add_parser.add_argument(
        "--remote-ip",
        default="Any",
        help="Удаленный IP (Any, LocalSubnet, или конкретный IP)"
    )
    add_parser.add_argument(
        "--profile",
        choices=["domain", "private", "public"],
        help="Профиль файрвола (domain, private, public)"
    )
    add_parser.add_argument(
        "--enabled",
        action="store_true",
        default=True,
        help="Включить правило"
    )
    
    # Команда modify-rule - изменение правила
    modify_parser = subparsers.add_parser("modify-rule", help="Изменение правила файрвола")
    modify_parser.add_argument(
        "--plugin",
        required=True,
        help="ID плагина для управления файрволом"
    )
    modify_parser.add_argument(
        "--name",
        required=True,
        help="Имя существующего правила"
    )
    modify_parser.add_argument(
        "--new-name",
        help="Новое имя правила"
    )
    modify_parser.add_argument(
        "--action",
        choices=["allow", "block"],
        help="Новое действие (allow/block)"
    )
    modify_parser.add_argument(
        "--protocol",
        help="Новый протокол"
    )
    modify_parser.add_argument(
        "--local-port",
        help="Новый локальный порт"
    )
    modify_parser.add_argument(
        "--remote-port",
        help="Новый удаленный порт"
    )
    modify_parser.add_argument(
        "--local-ip",
        help="Новый локальный IP"
    )
    modify_parser.add_argument(
        "--remote-ip",
        help="Новый удаленный IP"
    )
    modify_parser.add_argument(
        "--profile",
        choices=["domain", "private", "public"],
        help="Профиль файрвола"
    )
    modify_parser.add_argument(
        "--enabled",
        type=bool,
        help="Включено ли правило (true/false)"
    )
    
    # Команда delete-rule - удаление правила
    delete_parser = subparsers.add_parser("delete-rule", help="Удаление правила файрвола")
    delete_parser.add_argument(
        "--plugin",
        required=True,
        help="ID плагина для управления файрволом"
    )
    delete_parser.add_argument(
        "--name",
        required=True,
        help="Имя правила для удаления"
    )
    delete_parser.add_argument(
        "--profile",
        choices=["domain", "private", "public"],
        help="Профиль файрвола"
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        # Импортируем CLI модуль для работы с плагинами
        from flamix.cli.firewall_cli import FirewallCLI
        
        # Для чтения правил используем старый FirewallCLI (безопасная операция)
        # Для записи будем использовать плагины, если указан --plugin
        cli = FirewallCLI()
        
        # Если указан плагин, проверяем его доступность
        plugin_instance = None
        if hasattr(args, 'plugin') and args.plugin:
            try:
                from flamix.config import ensure_directories, PLUGINS_DIR
                from flamix.security import PermissionManager
                from flamix.plugins.manager import PluginManager
                import json
                from pathlib import Path
                
                ensure_directories()
                permission_manager = PermissionManager()
                plugin_manager = PluginManager(permission_manager)
                
                # Если плагин не загружен, пытаемся загрузить его из директории
                if args.plugin not in plugin_manager.plugins:
                    plugin_dir = PLUGINS_DIR / args.plugin
                    manifest_path = plugin_dir / "manifest.json"
                    
                    if manifest_path.exists():
                        logger.info(f"Loading plugin {args.plugin} from directory...")
                        try:
                            # Загружаем manifest
                            with open(manifest_path, 'r', encoding='utf-8') as f:
                                manifest_data = json.load(f)
                            
                            from flamix.models.manifest import PluginManifest, FirewallSupport
                            firewall_support = []
                            for fw_data in manifest_data.get("firewall_support", []):
                                firewall_support.append(FirewallSupport(**fw_data))
                            manifest_data["firewall_support"] = firewall_support
                            manifest = PluginManifest(**manifest_data)
                            
                            # Регистрируем плагин
                            plugin_manager.permission_manager.register_plugin(args.plugin, manifest.permissions)
                            plugin_manager.plugins[args.plugin] = {
                                "manifest": manifest,
                                "plugin_dir": plugin_dir,
                                "instance": None,
                                "enabled": False,
                            }
                            logger.info(f"Plugin {args.plugin} loaded from directory")
                        except Exception as load_error:
                            logger.warning(f"Could not load plugin from directory: {load_error}")
                
                # Теперь пытаемся включить плагин
                if args.plugin in plugin_manager.plugins:
                    plugin_info = plugin_manager.plugins[args.plugin]
                    if plugin_info.get("enabled") and plugin_info.get("instance"):
                        plugin_instance = plugin_info["instance"]
                        logger.info(f"Using plugin: {args.plugin}")
                    else:
                        logger.info(f"Enabling plugin {args.plugin}...")
                        try:
                            plugin_manager.enable_plugin(args.plugin)
                            plugin_info = plugin_manager.plugins[args.plugin]
                            if plugin_info.get("enabled") and plugin_info.get("instance"):
                                plugin_instance = plugin_info["instance"]
                                logger.info(f"Plugin {args.plugin} enabled successfully")
                        except Exception as enable_error:
                            logger.warning(f"Could not enable plugin {args.plugin}: {enable_error}")
                else:
                    logger.warning(f"Plugin {args.plugin} not found, using direct NetSh")
            except Exception as e:
                logger.warning(f"Could not load plugin {args.plugin}: {e}, using direct NetSh")
                import traceback
                traceback.print_exc()
        
        if args.command == "list-rules":
            # Для чтения правил используем старый CLI (безопасная операция)
            rules = cli.list_rules(args.profile)
            
            if args.format == "json":
                print(json.dumps(rules, indent=2, ensure_ascii=False))
            else:
                # Табличный формат
                if not rules:
                    print("Правила не найдены")
                    return 0
                
                print(f"\n{'Имя':<30} {'Направление':<12} {'Действие':<8} {'Протокол':<10} {'Порт':<15} {'IP':<20}")
                print("-" * 100)
                for rule in rules:
                    name = rule.get("name", "N/A")[:28]
                    direction = rule.get("direction", "N/A")
                    action = rule.get("action", "N/A")
                    protocol = rule.get("protocol", "N/A")
                    port = rule.get("local_port", rule.get("remote_port", "N/A"))
                    ip = rule.get("local_ip", rule.get("remote_ip", "N/A"))
                    print(f"{name:<30} {direction:<12} {action:<8} {protocol:<10} {port:<15} {ip:<20}")
        
        elif args.command == "add-rule":
            # Используем плагин, если он доступен, иначе старый CLI
            if plugin_instance:
                import asyncio
                # Формируем правило для плагина
                rule = {
                    "name": args.name,
                    "direction": args.direction,
                    "action": args.action,
                }
                if args.protocol:
                    rule["protocol"] = args.protocol
                if args.local_port:
                    rule["local_port"] = args.local_port
                if args.remote_port:
                    rule["remote_port"] = args.remote_port
                if args.local_ip:
                    rule["local_ip"] = args.local_ip
                if args.remote_ip:
                    rule["remote_ip"] = args.remote_ip
                if args.profile:
                    rule["profile"] = args.profile
                
                # Вызываем плагин асинхронно
                try:
                    logger.info(f"Applying rule via plugin: {rule}")
                    import sys
                    import inspect
                    sys.stdout.write(f"[DEBUG run_cli] plugin_instance type: {type(plugin_instance)}\n")
                    sys.stdout.write(f"[DEBUG run_cli] plugin_instance.apply_rule: {plugin_instance.apply_rule}\n")
                    sys.stdout.write(f"[DEBUG run_cli] is coroutine function: {inspect.iscoroutinefunction(plugin_instance.apply_rule)}\n")
                    sys.stdout.write(f"[DEBUG run_cli] About to call asyncio.run(plugin_instance.apply_rule(rule))\n")
                    sys.stdout.flush()
                    
                    # Создаем корутину
                    coro = plugin_instance.apply_rule(rule)
                    sys.stdout.write(f"[DEBUG run_cli] Coroutine created: {coro}\n")
                    sys.stdout.flush()
                    
                    try:
                        result = asyncio.run(coro)
                        sys.stdout.write(f"[DEBUG run_cli] asyncio.run returned: {result}\n")
                        sys.stdout.flush()
                        logger.info(f"Plugin result: {result}")
                    except Exception as async_error:
                        sys.stdout.write(f"[DEBUG run_cli] Exception in asyncio.run: {async_error}\n")
                        import traceback
                        traceback.print_exc()
                        sys.stdout.flush()
                        raise
                    if result.get("success"):
                        print(f"Правило '{args.name}' успешно добавлено")
                        success = True
                    else:
                        error_msg = result.get("error", "Unknown error")
                        logger.error(f"Plugin returned error: {error_msg}")
                        print(f"Ошибка при добавлении правила '{args.name}': {error_msg}")
                        return 1
                except Exception as e:
                    logger.error(f"Error applying rule via plugin: {e}", exc_info=True)
                    import traceback
                    traceback.print_exc()
                    print(f"Ошибка при добавлении правила через плагин: {e}")
                    return 1
            else:
                # Используем старый CLI
                success = cli.add_rule(
                    name=args.name,
                    direction=args.direction,
                    action=args.action,
                    protocol=args.protocol,
                    local_port=args.local_port,
                    remote_port=args.remote_port,
                    local_ip=args.local_ip,
                    remote_ip=args.remote_ip,
                    profile=args.profile,
                    enabled=args.enabled
                )
                
                if success:
                    print(f"Правило '{args.name}' успешно добавлено")
                else:
                    print(f"Ошибка при добавлении правила '{args.name}'")
                    return 1
        
        elif args.command == "modify-rule":
            success = cli.modify_rule(
                name=args.name,
                new_name=args.new_name,
                action=args.action,
                protocol=args.protocol,
                local_port=args.local_port,
                remote_port=args.remote_port,
                local_ip=args.local_ip,
                remote_ip=args.remote_ip,
                profile=args.profile,
                enabled=args.enabled
            )
            
            if success:
                print(f"Правило '{args.name}' успешно изменено")
            else:
                print(f"Ошибка при изменении правила '{args.name}'")
                return 1
        
        elif args.command == "delete-rule":
            success = cli.delete_rule(
                name=args.name,
                profile=args.profile
            )
            
            if success:
                print(f"Правило '{args.name}' успешно удалено")
            else:
                print(f"Ошибка при удалении правила '{args.name}'")
                return 1
        
        return 0
        
    except Exception as e:
        logger.error(f"Error executing command: {e}", exc_info=True)
        print(f"Ошибка: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
