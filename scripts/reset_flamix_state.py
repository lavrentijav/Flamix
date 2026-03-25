#!/usr/bin/env python3
"""Reset runtime state for Flamix without touching source code."""

from __future__ import annotations

import shutil
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


DIRECTORIES_TO_REMOVE = [
    PROJECT_ROOT / "data",
    PROJECT_ROOT / "certs",
    PROJECT_ROOT / "logs",
    PROJECT_ROOT / "temp" / "client-packages",
    PROJECT_ROOT / "server" / "data",
    PROJECT_ROOT / "server" / "certs",
    PROJECT_ROOT / "server" / "logs",
    PROJECT_ROOT / "server" / "temp",
    PROJECT_ROOT / "client" / "certs",
    PROJECT_ROOT / "client" / "temp",
]

FILES_TO_REMOVE = [
    PROJECT_ROOT / "data" / "server-runtime.json",
    PROJECT_ROOT / "server" / "data" / "server-runtime.json",
    PROJECT_ROOT / "client" / "config.json",
]


def _remove_path(path: Path):
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=False)
        print(f"removed dir  {path}")
    elif path.exists():
        path.unlink()
        print(f"removed file {path}")


def main():
    print("Resetting Flamix runtime state...")
    print(f"Project root: {PROJECT_ROOT}")

    for path in FILES_TO_REMOVE:
        if path.exists():
            _remove_path(path)

    for path in DIRECTORIES_TO_REMOVE:
        if path.exists():
            _remove_path(path)

    print("Done.")
    print("Source code and tests were not touched.")


if __name__ == "__main__":
    main()
