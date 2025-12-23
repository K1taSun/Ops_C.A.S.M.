@echo off
setlocal enabledelayedexpansion

echo === C.A.S.M. Build ===

where cl >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Blad: Brak kompilatora. Uruchom z Developer Command Prompt.
    exit /b 1
)

where cmake >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Blad: Brak CMake.
    exit /b 1
)

set ROOT=%~dp0..
set BUILD=%ROOT%\build
set TYPE=Release

:args
if "%~1"=="" goto :endargs
if /i "%~1"=="debug" set TYPE=Debug
if /i "%~1"=="release" set TYPE=Release
if /i "%~1"=="clean" (
    if exist "%BUILD%" rmdir /s /q "%BUILD%"
)
shift
goto :args
:endargs

echo Build type: %TYPE%

if not exist "%BUILD%" mkdir "%BUILD%"
cd /d "%BUILD%"

echo Konfiguracja...
cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=%TYPE%
if %ERRORLEVEL% neq 0 exit /b 1

echo Kompilacja...
cmake --build . --config %TYPE% --parallel
if %ERRORLEVEL% neq 0 exit /b 1

echo Kopiowanie DLL...
if exist "%BUILD%\bin\%TYPE%\casm_core.dll" (
    copy /y "%BUILD%\bin\%TYPE%\casm_core.dll" "%ROOT%\ui\src\"
)

echo Done.
echo Output: %BUILD%\bin\%TYPE%\

endlocal
