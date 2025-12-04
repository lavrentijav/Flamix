#!/usr/bin/env python3
"""Скрипт для создания ZIP-архива плагина"""

import zipfile
import sys
from pathlib import Path


def create_plugin_zip(plugin_dir: Path, output_path: Path):
    """Создание ZIP-архива плагина"""
    plugin_dir = Path(plugin_dir)
    output_path = Path(output_path)

    if not plugin_dir.exists():
        print(f"Error: Plugin directory not found: {plugin_dir}")
        sys.exit(1)

    # Проверка наличия manifest.json
    manifest_path = plugin_dir / "manifest.json"
    if not manifest_path.exists():
        print(f"Error: manifest.json not found in {plugin_dir}")
        sys.exit(1)

    # Создание ZIP
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for file_path in plugin_dir.rglob("*"):
            if file_path.is_file():
                arcname = file_path.relative_to(plugin_dir)
                zipf.write(file_path, arcname)
                print(f"Added: {arcname}")

    print(f"\nPlugin ZIP created: {output_path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python create_plugin_zip.py <plugin_dir> <output.zip>")
        sys.exit(1)

    plugin_dir = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    create_plugin_zip(plugin_dir, output_path)

