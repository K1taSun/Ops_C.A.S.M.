# C.A.S.M. - Control And Stealth Manager

Zaawansowany menedżer procesów Windows z funkcją ukrywania.

## O projekcie

C.A.S.M. to narzędzie do zarządzania procesami wykraczające poza możliwości standardowego Task Managera:

- Pełna widoczność wszystkich procesów systemowych
- Ukrywanie wybranych procesów przed innymi narzędziami
- Zarządzanie procesami (kill, suspend, resume, priorytety)
- Edycja parametrów procesów
- Monitoring zasobów CPU/RAM

## Architektura

```
+---------------------------+
|     Python UI (PyQt6)     |
+---------------------------+
|    ctypes / pybind11      |
+---------------------------+
|    C/C++ Core (DLL)       |
+---------------------------+
|    Windows API / NTAPI    |
+---------------------------+
```

## Struktura

```
Ops_C.A.S.M/
├── core/           # rdzen C++
│   ├── include/    # headery
│   └── src/        # implementacja
├── ui/             # GUI w Pythonie
│   ├── src/
│   └── styles/
├── docs/           # dokumentacja
├── scripts/        # skrypty pomocnicze
└── tests/
```

## Wymagania

- Windows 10/11 x64
- Python 3.10+
- Visual Studio 2019+ lub MinGW-w64
- CMake 3.20+

## Instalacja

```bash
# zależności Python
pip install -r requirements.txt

# kompilacja C++
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release

# uruchomienie
python ui/src/main.py
```

## Funkcje

### Process Viewer
Lista wszystkich procesów z filtrowaniem i sortowaniem.

### Process Hider
Ukrywanie procesów przed Task Managerem i innymi narzędziami. Wymaga uprawnień admina.

### Process Manager
Zabijanie, zawieszanie, zmiana priorytetów i powinowactwa CPU.

## Uwaga

Projekt przeznaczony do celów edukacyjnych. Funkcje ukrywania mogą być wykrywane przez AV. Używaj odpowiedzialnie.

## Licencja

MIT
