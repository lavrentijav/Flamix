@echo off
setlocal
set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..
if exist "%PROJECT_ROOT%\.venv\Scripts\python.exe" (
    "%PROJECT_ROOT%\.venv\Scripts\python.exe" "%SCRIPT_DIR%reset_flamix_state.py"
) else (
    python "%SCRIPT_DIR%reset_flamix_state.py"
)
