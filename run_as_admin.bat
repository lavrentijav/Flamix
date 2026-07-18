@echo off
setlocal enableextensions

@REM Папка скрипта (учитываем запуск из System32 после elevation)
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

@REM This file is UTF-8 encoded, so we need to update the current code page while executing it
@for /f "tokens=2 delims=:." %%a in ('"%SystemRoot%\System32\chcp.com"') do @set _OLD_CODEPAGE=%%a
@if defined _OLD_CODEPAGE "%SystemRoot%\System32\chcp.com" 65001 > nul

REM Скрипт запуска Flamix с правами администратора (Windows)

REM Проверка прав администратора
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Запуск с правами администратора подтвержден.
    goto :run
) else (
    echo Запуск от имени администратора необходим для работы с файрволом.
    echo Запрашиваем повышение прав...
    
    REM Запускаем скрипт с правами администратора, передавая все аргументы
    REM Проверяем, есть ли аргументы, чтобы не передавать пустой ArgumentList
    if "%~1"=="" (
        powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs -WorkingDirectory '%~dp0'"
    ) else (
        powershell -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs -WorkingDirectory '%~dp0'"
    )
    goto :end
)

:run
REM Активация виртуального окружения
@set "VIRTUAL_ENV=%SCRIPT_DIR%.venv"

@set "VIRTUAL_ENV_PROMPT="
@if NOT DEFINED VIRTUAL_ENV_PROMPT (
    @for %%d in ("%VIRTUAL_ENV%") do @set "VIRTUAL_ENV_PROMPT=%%~nxd"
)

@if defined _OLD_VIRTUAL_PROMPT (
    @set "PROMPT=%_OLD_VIRTUAL_PROMPT%"
) else (
    @if not defined PROMPT (
        @set "PROMPT=$P$G"
    )
    @if not defined VIRTUAL_ENV_DISABLE_PROMPT (
        @set "_OLD_VIRTUAL_PROMPT=%PROMPT%"
    )
)
@if not defined VIRTUAL_ENV_DISABLE_PROMPT (
    @set "PROMPT=(%VIRTUAL_ENV_PROMPT%) %PROMPT%"
)

@REM Don't use () to avoid problems with them in %PATH%
@if defined _OLD_VIRTUAL_PYTHONHOME @goto ENDIFVHOME
    @set "_OLD_VIRTUAL_PYTHONHOME=%PYTHONHOME%"
:ENDIFVHOME

@set PYTHONHOME=

@REM if defined _OLD_VIRTUAL_PATH (
@if not defined _OLD_VIRTUAL_PATH @goto ENDIFVPATH1
    @set "PATH=%_OLD_VIRTUAL_PATH%"
:ENDIFVPATH1
@REM ) else (
@if defined _OLD_VIRTUAL_PATH @goto ENDIFVPATH2
    @set "_OLD_VIRTUAL_PATH=%PATH%"
:ENDIFVPATH2

@set "PATH=%VIRTUAL_ENV%\Scripts;%PATH%"

REM Запуск демо-приложения из папки demo
if "%1"=="cli" (
    python _dist\app\flx_cli.py %*
) else if "%1"=="gui" (
    python _dist\app\flx_gui.py
) else if "%1"=="" (
    REM Если параметров нет — запускаем GUI по умолчанию
    python _dist\app\flx_gui.py
) else (
    echo Usage: run_as_admin.bat [cli^|gui] [arguments]
    echo.
    echo Examples:
    echo   run_as_admin.bat cli block 192.168.1.1
    echo   run_as_admin.bat gui
    echo   run_as_admin.bat
    pause
    exit /b 1
)

REM Пауза: если запускали GUI без аргументов — окно держит процесс; иначе держим окно
if /i not "%1"=="gui" (
    pause
)

:end
@if defined _OLD_CODEPAGE "%SystemRoot%\System32\chcp.com" %_OLD_CODEPAGE% > nul
endlocal
