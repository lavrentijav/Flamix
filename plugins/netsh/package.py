"""Скрипт для упаковки плагина NetSh в ZIP-архив"""

import zipfile
import sys
from pathlib import Path

def package_plugin():
    """Упаковка плагина в ZIP-архив"""
    plugin_dir = Path(__file__).parent
    output_file = plugin_dir / "netsh-plugin.zip"
    
    # Файлы для включения в архив
    files_to_include = [
        "manifest.json",
        "plugin.py"
    ]
    
    print(f"Packaging NetSh plugin to {output_file}...")
    
    with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file_name in files_to_include:
            file_path = plugin_dir / file_name
            if file_path.exists():
                zipf.write(file_path, file_name)
                print(f"  Added: {file_name}")
            else:
                print(f"  Warning: {file_name} not found!")
    
    print(f"\nPlugin packaged successfully: {output_file}")
    print(f"Size: {output_file.stat().st_size / 1024:.2f} KB")
    print("\nTo install the plugin, run from project root:")
    print(f"  python install_plugin.py {output_file}")
    print("\nOr use relative path:")
    print(f"  python install_plugin.py plugins/netsh/netsh-plugin.zip")

if __name__ == "__main__":
    package_plugin()
