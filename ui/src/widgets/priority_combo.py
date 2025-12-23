"""ComboBox z priorytetami"""

from PyQt6.QtWidgets import QComboBox
from PyQt6.QtCore import pyqtSignal

PRIO_IDLE = 0x40
PRIO_BELOW = 0x4000
PRIO_NORMAL = 0x20
PRIO_ABOVE = 0x8000
PRIO_HIGH = 0x80
PRIO_RT = 0x100


class PriorityCombo(QComboBox):
    changed = pyqtSignal(int)
    
    ITEMS = [
        ("Bezczynny", PRIO_IDLE),
        ("Ponizej norm.", PRIO_BELOW),
        ("Normalny", PRIO_NORMAL),
        ("Powyzej norm.", PRIO_ABOVE),
        ("Wysoki", PRIO_HIGH),
        ("Realtime", PRIO_RT),
    ]
    
    def __init__(self, parent=None):
        super().__init__(parent)
        for name, val in self.ITEMS:
            self.addItem(name, val)
        self.setCurrentIndex(2)  # normalny
        self.currentIndexChanged.connect(self._on_change)
    
    def _on_change(self, idx):
        self.changed.emit(self.itemData(idx))
    
    def get_value(self) -> int:
        return self.currentData()
    
    def set_value(self, prio: int):
        for i, (_, v) in enumerate(self.ITEMS):
            if v == prio:
                self.setCurrentIndex(i)
                return
        self.setCurrentIndex(2)
    
    @staticmethod
    def name_for(prio: int) -> str:
        for n, v in PriorityCombo.ITEMS:
            if v == prio:
                return n
        return "?"
