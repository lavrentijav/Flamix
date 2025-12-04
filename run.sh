#!/bin/bash
# Скрипт запуска Flamix без установки (Linux/macOS)

if [ "$1" == "agent" ]; then
    python3 run_agent.py
elif [ "$1" == "cli" ]; then
    shift
    python3 run_cli.py "$@"
elif [ "$1" == "gui" ]; then
    python3 run_gui.py
else
    echo "Usage: ./run.sh [agent|cli|gui] [arguments]"
    echo ""
    echo "Examples:"
    echo "  ./run.sh agent"
    echo "  ./run.sh cli list-plugins"
    echo "  ./run.sh gui"
    exit 1
fi

