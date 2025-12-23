@echo off
setlocal

set ROOT=%~dp0..
set UI=%ROOT%\ui\src

where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Blad: Brak Pythona
    exit /b 1
)

net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Nie uruchomiono jako admin!
    echo Uruchomic jako admin? [T/N]
    set /p CHOICE=
    if /i "!CHOICE!"=="T" (
        powershell -Command "Start-Process '%~f0' -Verb RunAs"
        exit /b 0
    )
)

cd /d "%UI%"
python main.py

endlocal
