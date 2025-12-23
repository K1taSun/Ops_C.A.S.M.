"""Dialog wyboru CPU affinity"""

from typing import List
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QCheckBox,
    QPushButton, QLabel, QGridLayout, QGroupBox
)


class AffinityDialog(QDialog):
    def __init__(self, cpu_count: int, mask: int = None, parent=None):
        super().__init__(parent)
        self._cpus = cpu_count
        self._mask = mask if mask else (1 << cpu_count) - 1
        self._boxes: List[QCheckBox] = []
        self._init_ui()
        self._load()
    
    def _init_ui(self):
        self.setWindowTitle("CPU Affinity")
        self.setModal(True)
        self.setMinimumWidth(300)
        
        lay = QVBoxLayout(self)
        
        lay.addWidget(QLabel("Wybierz rdzenie CPU:"))
        
        grp = QGroupBox("CPU")
        grid = QGridLayout(grp)
        
        cols = 4
        for i in range(self._cpus):
            cb = QCheckBox(f"CPU {i}")
            cb.stateChanged.connect(self._validate)
            self._boxes.append(cb)
            grid.addWidget(cb, i // cols, i % cols)
        
        lay.addWidget(grp)
        
        # quick buttons
        qlay = QHBoxLayout()
        
        btn_all = QPushButton("Wszystkie")
        btn_all.clicked.connect(self._sel_all)
        qlay.addWidget(btn_all)
        
        btn_none = QPushButton("Zadne")
        btn_none.clicked.connect(self._sel_none)
        qlay.addWidget(btn_none)
        
        lay.addLayout(qlay)
        
        # ok/cancel
        blay = QHBoxLayout()
        self._btn_ok = QPushButton("OK")
        self._btn_ok.clicked.connect(self.accept)
        blay.addWidget(self._btn_ok)
        
        btn_cancel = QPushButton("Anuluj")
        btn_cancel.clicked.connect(self.reject)
        blay.addWidget(btn_cancel)
        
        lay.addLayout(blay)
    
    def _load(self):
        for i, cb in enumerate(self._boxes):
            cb.setChecked(bool(self._mask & (1 << i)))
    
    def _validate(self):
        ok = any(cb.isChecked() for cb in self._boxes)
        self._btn_ok.setEnabled(ok)
    
    def _sel_all(self):
        for cb in self._boxes:
            cb.setChecked(True)
    
    def _sel_none(self):
        for cb in self._boxes:
            cb.setChecked(False)
    
    def get_mask(self) -> int:
        m = 0
        for i, cb in enumerate(self._boxes):
            if cb.isChecked():
                m |= (1 << i)
        return m
