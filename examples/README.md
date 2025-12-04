# Примеры плагинов Flamix

## iptables_plugin

Минимальный пример плагина для управления iptables (Linux).

### Создание ZIP

```bash
cd iptables_plugin
python ../../scripts/create_plugin_zip.py . ../../iptables_plugin.zip
```

Или вручную:

```bash
cd iptables_plugin
zip -r ../../iptables_plugin.zip .
```

### Установка

```bash
# Без установки Flamix
python ../../run_cli.py install-plugin ../../iptables_plugin.zip
python ../../run_cli.py enable-plugin com.example.minimal_iptables

# После установки
flamix-cli install-plugin ../../iptables_plugin.zip
flamix-cli enable-plugin com.example.minimal_iptables
```

## netshplugin

Плагин для управления Windows Firewall через netsh (Windows).

**ID плагина (UUID):** `1d142a87-2353-47d0-9883-fed9037d0a9b`

### Создание ZIP

```bash
cd netshplugin
python ../../scripts/create_plugin_zip.py . ../../netshplugin.zip
```

### Установка

```bash
# Без установки Flamix
python ../../run_cli.py install-plugin ../../netshplugin.zip
python ../../run_cli.py enable-plugin 1d142a87-2353-47d0-9883-fed9037d0a9b

# После установки
flamix-cli install-plugin ../../netshplugin.zip
flamix-cli enable-plugin 1d142a87-2353-47d0-9883-fed9037d0a9b
```

Подробности в [netshplugin/README.md](netshplugin/README.md).

