# User Guide

## Instalacja

### Wymagania
- Windows 10/11 x64
- Python 3.10+
- Visual Studio 2019+ (do kompilacji)

### Kroki

```bash
# instaluj zaleznosci
pip install -r requirements.txt

# kompiluj C++
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release

# uruchom
python ui/src/main.py
```

Lub przez skrypty:
```bash
scripts\install_deps.bat
scripts\build.bat
scripts\run.bat
```

## Interfejs

```
+----------------------------------------+
| [Odswiez]  Admin/Brak admina    v0.1.0 |
+----------------------------------------+
| Szukaj: [          ] [Filtr v] [Odsw.] |
+----------------------------------------+
| PID | Nazwa      | CPU | RAM  | Stan   |
|-----|------------|-----|------|--------|
| 4   | System     | 0.1 | 0.2M | Aktyw. |
| 123 | chrome.exe | 5.2 | 450M | Aktyw. |
+----------------------------------------+
| [Zabij] [Wstrzymaj] [Wznow] [Ukryj]    |
+----------------------------------------+
| Procesy: 156 | CPU: 23% | RAM: 8/16 GB |
+----------------------------------------+
```

## Funkcje

### Przeglad procesow
- lista wszystkich procesow
- sortowanie po kolumnach
- filtrowanie: wszystkie/uzytkownika/systemowe/ukryte

### Zarzadzanie
- Zabij - konczy proces
- Wstrzymaj/Wznow - suspend/resume
- Priorytet - zmiana priorytetu
- Affinity - wybor rdzeni CPU

### Ukrywanie
- wymaga admina
- ukrywa przed Task Managerem
- tymczasowe (do restartu)

## Skroty

- F5 - odswiez
- Ctrl+F - szukaj
- Delete - zabij proces
- Escape - wyczysc zaznaczenie

## Troubleshooting

### "Brak uprawnien"
Uruchom jako administrator (PPM -> Uruchom jako admin)

### "DLL nie znaleziony"
Skompiluj C++:
```bash
cd build
cmake --build . --config Release
```

### AV blokuje
Dodaj wyjatek dla folderu projektu.
Funkcje hookowania moga byc wykrywane jako podejrzane.

## Uwagi

- Ukrywanie dziala tylko w biezacej sesji
- Nie ukrywa przed innymi instancjami C.A.S.M.
- Ostroznnie z procesami systemowymi
