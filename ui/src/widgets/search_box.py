"""Pole wyszukiwania z debounce"""

from PyQt6.QtWidgets import QLineEdit, QCompleter
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QStringListModel


class SearchBox(QLineEdit):
    search = pyqtSignal(str)
    
    def __init__(self, placeholder="Szukaj...", parent=None):
        super().__init__(parent)
        
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._do_search)
        
        self._history = []
        
        self.setPlaceholderText(placeholder)
        self.setClearButtonEnabled(True)
        
        self._compl = QCompleter(self._history)
        self._compl.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.setCompleter(self._compl)
        
        self.textChanged.connect(self._on_text)
        self.returnPressed.connect(self._on_enter)
    
    def _on_text(self, text):
        self._timer.stop()
        self._timer.start(300)
    
    def _on_enter(self):
        self._timer.stop()
        self._do_search()
        self._add_history(self.text())
    
    def _do_search(self):
        self.search.emit(self.text())
    
    def _add_history(self, txt):
        txt = txt.strip()
        if not txt:
            return
        if txt in self._history:
            self._history.remove(txt)
        self._history.insert(0, txt)
        self._history = self._history[:20]
        self._compl.setModel(QStringListModel(self._history))
    
    def set_debounce(self, ms: int):
        self._timer.setInterval(ms)
    
    def clear_history(self):
        self._history.clear()
        self._compl.setModel(QStringListModel([]))
