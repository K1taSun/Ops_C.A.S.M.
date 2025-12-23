# Architektura C.A.S.M.

## Warstwy

```
+---------------------------+
|     Python UI (PyQt6)     |  <- GUI
+---------------------------+
|       ctypes bridge       |  <- binding
+---------------------------+
|      C++ Core (DLL)       |  <- logika
+---------------------------+
|    Windows API / NTAPI    |  <- system
+---------------------------+
```

## Komponenty C++

### ProcessManager
Podstawowe operacje na procesach:
- enumeracja (CreateToolhelp32Snapshot)
- kill/suspend/resume
- zmiana priorytetu i affinity

### ProcessHider
Ukrywanie procesow przed innymi aplikacjami:
- inline hooking NtQuerySystemInformation
- filtrowanie listy procesow

### SystemInfo
Informacje o systemie:
- CPU, RAM, dyski
- PDH do monitoringu

## Technika ukrywania

1. Hook na NtQuerySystemInformation w ntdll.dll
2. Przy zapytaniu o liste procesow (SystemProcessInformation)
3. Filtruj ukryte PIDy z wynikow
4. Inne aplikacje (Task Manager) nie widza ukrytych procesow

Wymagania:
- uprawnienia administratora
- SeDebugPrivilege

## Python UI

MVC:
- Model: core_bridge.py (dane z C++)
- View: main_window.py (PyQt6 widgets)
- Controller: logika w main_window.py

## Komunikacja

Python <-> C++ przez ctypes:
- casm_core.dll eksportuje funkcje C
- core_bridge.py definiuje prototypy
- struktury: CasmProcessInfo, CasmMemoryInfo

## Pliki

```
core/
  include/       headery
  src/           implementacja
ui/
  src/
    main.py           entry point
    main_window.py    glowne okno
    core_bridge.py    binding do DLL
    widgets/          custom widgets
```
