#!/usr/bin/env python3
"""
C.A.S.M. - główny moduł aplikacji
"""

import sys
import os
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon

from main_window import MainWindow
from core_bridge import CoreBridge, CasmError

# logging
LOG_DIR = Path(__file__).parent.parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "casm.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("CASM")


def check_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def request_admin():
    try:
        import ctypes
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        return True
    except:
        return False


def exception_hook(exc_type, exc_value, exc_tb):
    log.critical("Unhandled exception:", exc_info=(exc_type, exc_value, exc_tb))
    if QApplication.instance():
        QMessageBox.critical(None, "Error",
            f"Nieoczekiwany blad:\n{exc_type.__name__}: {exc_value}")


def main():
    log.info("Starting C.A.S.M.")
    
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    
    app = QApplication(sys.argv)
    app.setApplicationName("C.A.S.M.")
    app.setApplicationVersion("0.1.0")
    app.setStyle("Fusion")
    
    icon_path = Path(__file__).parent.parent / "assets" / "icon.png"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))
    
    sys.excepthook = exception_hook
    
    is_admin = check_admin()
    if not is_admin:
        log.warning("Not running as admin")
        result = QMessageBox.warning(None, "Uprawnienia",
            "C.A.S.M. wymaga uprawnien administratora.\n"
            "Uruchomic ponownie jako admin?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )
        if result == QMessageBox.StandardButton.Yes:
            if request_admin():
                return 0
    
    # init C++ lib
    bridge = None
    try:
        bridge = CoreBridge()
        log.info(f"Core loaded: v{bridge.get_version()}")
    except CasmError as e:
        log.error(f"Core init failed: {e}")
        QMessageBox.warning(None, "Warning",
            f"Nie udalo sie zaladowac DLL:\n{e}\n\nNiektore funkcje moga nie dzialac.")
    except FileNotFoundError as e:
        log.warning(f"DLL not found: {e}")
    
    window = MainWindow(bridge, is_admin=is_admin)
    window.show()
    
    log.info("UI ready")
    
    code = app.exec()
    
    if bridge:
        bridge.cleanup()
    
    log.info(f"Exit code: {code}")
    return code


if __name__ == "__main__":
    sys.exit(main())
