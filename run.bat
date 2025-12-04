@echo off
REM Скрипт запуска Flamix без установки (Windows)

if "%1"=="agent" (
    python run_agent.py
) else if "%1"=="cli" (
    python run_cli.py %*
) else if "%1"=="gui" (
    python run_gui.py
) else (
    echo Usage: run.bat [agent^|cli^|gui] [arguments]
    echo.
    echo Examples:
    echo   run.bat agent
    echo   run.bat cli list-plugins
    echo   run.bat gui
)

