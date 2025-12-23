@echo off
echo === Instalacja zaleznosci ===

where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Blad: Brak Pythona
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PY_VER=%%i
echo Python: %PY_VER%

pip install --upgrade pip
pip install -r "%~dp0..\requirements.txt"

if %ERRORLEVEL% neq 0 (
    echo Probuje minimalna instalacje...
    pip install PyQt6 pywin32
)

echo Done.
echo Nastepne kroki:
echo   1. scripts\build.bat
echo   2. scripts\run.bat

pause
