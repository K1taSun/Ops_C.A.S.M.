"""
Glowne okno aplikacji
"""

from typing import Optional
import logging

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTableWidget, QTableWidgetItem, QHeaderView,
    QToolBar, QStatusBar, QLabel, QLineEdit, QComboBox,
    QPushButton, QMessageBox, QFrame, QProgressBar,
    QFormLayout
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QSize
from PyQt6.QtGui import QAction, QColor, QFont

from core_bridge import (
    CoreBridge, ProcessInfo,
    PRIORITY_IDLE, PRIORITY_BELOW_NORMAL, PRIORITY_NORMAL,
    PRIORITY_ABOVE_NORMAL, PRIORITY_HIGH, PRIORITY_REALTIME,
    AccessDeniedError
)

log = logging.getLogger("CASM.UI")


class ProcessTable(QTableWidget):
    proc_selected = pyqtSignal(object)
    proc_dblclick = pyqtSignal(object)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._procs = []
        self._init_ui()
    
    def _init_ui(self):
        cols = ["PID", "Nazwa", "CPU %", "Pamiec", "Watki", "Stan", "Ukryty"]
        self.setColumnCount(len(cols))
        self.setHorizontalHeaderLabels(cols)
        
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.setSortingEnabled(True)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        
        hdr = self.horizontalHeader()
        hdr.setStretchLastSection(True)
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        
        self.setColumnWidth(0, 70)
        self.setColumnWidth(1, 200)
        self.setColumnWidth(2, 70)
        self.setColumnWidth(3, 100)
        self.setColumnWidth(4, 60)
        self.setColumnWidth(5, 100)
        
        self.itemSelectionChanged.connect(self._on_sel)
        self.itemDoubleClicked.connect(self._on_dbl)
    
    def update_procs(self, procs: list):
        self._procs = procs
        
        # save selection
        curr_pid = None
        sel = self.selectedItems()
        if sel:
            item = self.item(sel[0].row(), 0)
            if item:
                curr_pid = int(item.text())
        
        self.setSortingEnabled(False)
        self.setRowCount(len(procs))
        
        for row, p in enumerate(procs):
            pid_item = QTableWidgetItem()
            pid_item.setData(Qt.ItemDataRole.DisplayRole, p.pid)
            self.setItem(row, 0, pid_item)
            
            name_item = QTableWidgetItem(p.name)
            if p.is_system:
                name_item.setForeground(QColor("#888"))
            self.setItem(row, 1, name_item)
            
            cpu_item = QTableWidgetItem()
            cpu_item.setData(Qt.ItemDataRole.DisplayRole, round(p.cpu_usage, 1))
            if p.cpu_usage > 50:
                cpu_item.setForeground(QColor("#f44"))
            elif p.cpu_usage > 20:
                cpu_item.setForeground(QColor("#fa0"))
            self.setItem(row, 2, cpu_item)
            
            self.setItem(row, 3, QTableWidgetItem(p.memory_formatted))
            
            thr_item = QTableWidgetItem()
            thr_item.setData(Qt.ItemDataRole.DisplayRole, p.thread_count)
            self.setItem(row, 4, thr_item)
            
            states = {0: "Aktywny", 1: "Wstrzymany", 2: "Zakonczony"}
            self.setItem(row, 5, QTableWidgetItem(states.get(p.state, "?")))
            
            hid = QTableWidgetItem("*" if p.is_hidden else "")
            hid.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.setItem(row, 6, hid)
        
        self.setSortingEnabled(True)
        
        # restore selection
        if curr_pid:
            for r in range(self.rowCount()):
                item = self.item(r, 0)
                if item and int(item.text()) == curr_pid:
                    self.selectRow(r)
                    break
    
    def get_selected(self) -> Optional[ProcessInfo]:
        sel = self.selectedItems()
        if not sel:
            return None
        item = self.item(sel[0].row(), 0)
        if not item:
            return None
        pid = int(item.text())
        for p in self._procs:
            if p.pid == pid:
                return p
        return None
    
    def _on_sel(self):
        self.proc_selected.emit(self.get_selected())
    
    def _on_dbl(self, item):
        p = self.get_selected()
        if p:
            self.proc_dblclick.emit(p)


class DetailsPanel(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()
    
    def _init_ui(self):
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setMinimumWidth(280)
        
        lay = QVBoxLayout(self)
        
        title = QLabel("Szczegoly")
        title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        lay.addWidget(title)
        
        form = QFormLayout()
        form.setSpacing(8)
        
        self._pid = QLabel("-")
        self._name = QLabel("-")
        self._path = QLabel("-")
        self._path.setWordWrap(True)
        self._parent = QLabel("-")
        self._threads = QLabel("-")
        self._prio = QLabel("-")
        self._mem = QLabel("-")
        self._cpu = QLabel("-")
        self._state = QLabel("-")
        self._hidden = QLabel("-")
        
        form.addRow("PID:", self._pid)
        form.addRow("Nazwa:", self._name)
        form.addRow("Sciezka:", self._path)
        form.addRow("Parent:", self._parent)
        form.addRow("Watki:", self._threads)
        form.addRow("Priorytet:", self._prio)
        form.addRow("Pamiec:", self._mem)
        form.addRow("CPU:", self._cpu)
        form.addRow("Stan:", self._state)
        form.addRow("Ukryty:", self._hidden)
        
        lay.addLayout(form)
        lay.addStretch()
    
    def show_proc(self, p: Optional[ProcessInfo]):
        if not p:
            for w in [self._pid, self._name, self._path, self._parent,
                      self._threads, self._prio, self._mem, self._cpu,
                      self._state, self._hidden]:
                w.setText("-")
            return
        
        self._pid.setText(str(p.pid))
        self._name.setText(p.name)
        self._path.setText(p.path or "(brak)")
        self._parent.setText(str(p.parent_pid))
        self._threads.setText(str(p.thread_count))
        self._prio.setText(p.priority_name)
        self._mem.setText(p.memory_formatted)
        self._cpu.setText(f"{p.cpu_usage:.1f}%")
        states = {0: "Aktywny", 1: "Wstrzymany", 2: "Zakonczony"}
        self._state.setText(states.get(p.state, "?"))
        self._hidden.setText("Tak" if p.is_hidden else "Nie")


class MainWindow(QMainWindow):
    def __init__(self, bridge: Optional[CoreBridge], is_admin: bool = False):
        super().__init__()
        self._bridge = bridge
        self._admin = is_admin
        self._procs = []
        
        self._init_ui()
        self._init_toolbar()
        self._init_statusbar()
        self._init_timers()
        self._apply_style()
        
        self._refresh()
    
    def _init_ui(self):
        self.setWindowTitle("C.A.S.M.")
        self.setMinimumSize(1000, 700)
        self.resize(1200, 800)
        
        central = QWidget()
        self.setCentralWidget(central)
        
        lay = QVBoxLayout(central)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(8)
        
        # search bar
        search_lay = QHBoxLayout()
        
        self._search = QLineEdit()
        self._search.setPlaceholderText("Szukaj...")
        self._search.textChanged.connect(self._filter)
        search_lay.addWidget(self._search)
        
        self._filter_combo = QComboBox()
        self._filter_combo.addItems(["Wszystkie", "Uzytkownika", "Systemowe", "Ukryte"])
        self._filter_combo.currentIndexChanged.connect(self._filter)
        search_lay.addWidget(self._filter_combo)
        
        btn_refresh = QPushButton("Odswiez")
        btn_refresh.clicked.connect(self._refresh)
        search_lay.addWidget(btn_refresh)
        
        lay.addLayout(search_lay)
        
        # splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        self._table = ProcessTable()
        self._table.proc_selected.connect(self._on_select)
        self._table.proc_dblclick.connect(self._on_dblclick)
        splitter.addWidget(self._table)
        
        self._details = DetailsPanel()
        splitter.addWidget(self._details)
        
        splitter.setSizes([800, 300])
        lay.addWidget(splitter)
        
        # action buttons
        act_lay = QHBoxLayout()
        
        self._btn_kill = QPushButton("Zabij")
        self._btn_kill.clicked.connect(self._kill)
        act_lay.addWidget(self._btn_kill)
        
        self._btn_suspend = QPushButton("Wstrzymaj")
        self._btn_suspend.clicked.connect(self._suspend)
        act_lay.addWidget(self._btn_suspend)
        
        self._btn_resume = QPushButton("Wznow")
        self._btn_resume.clicked.connect(self._resume)
        act_lay.addWidget(self._btn_resume)
        
        self._btn_hide = QPushButton("Ukryj")
        self._btn_hide.clicked.connect(self._hide)
        act_lay.addWidget(self._btn_hide)
        
        self._btn_unhide = QPushButton("Pokaz")
        self._btn_unhide.clicked.connect(self._unhide)
        act_lay.addWidget(self._btn_unhide)
        
        act_lay.addStretch()
        
        self._prio_combo = QComboBox()
        self._prio_combo.addItems([
            "Bezczynny", "Ponizej norm.", "Normalny",
            "Powyzej norm.", "Wysoki", "Realtime"
        ])
        self._prio_combo.setCurrentIndex(2)
        act_lay.addWidget(QLabel("Priorytet:"))
        act_lay.addWidget(self._prio_combo)
        
        btn_prio = QPushButton("Ustaw")
        btn_prio.clicked.connect(self._set_prio)
        act_lay.addWidget(btn_prio)
        
        lay.addLayout(act_lay)
    
    def _init_toolbar(self):
        tb = QToolBar()
        tb.setMovable(False)
        tb.setIconSize(QSize(24, 24))
        self.addToolBar(tb)
        
        act = QAction("Odswiez", self)
        act.setShortcut("F5")
        act.triggered.connect(self._refresh)
        tb.addAction(act)
        
        tb.addSeparator()
        
        if self._admin:
            lbl = QLabel("Admin")
            lbl.setStyleSheet("color: #0a0; padding: 0 10px;")
        else:
            lbl = QLabel("Brak admina")
            lbl.setStyleSheet("color: #f80; padding: 0 10px;")
        tb.addWidget(lbl)
        
        if self._bridge:
            ver = QLabel(f"v{self._bridge.get_version()}")
            ver.setStyleSheet("color: #888; padding: 0 10px;")
            tb.addWidget(ver)
    
    def _init_statusbar(self):
        sb = QStatusBar()
        self.setStatusBar(sb)
        
        self._lbl_count = QLabel("Procesy: 0")
        sb.addWidget(self._lbl_count)
        sb.addWidget(QLabel("|"))
        
        self._lbl_cpu = QLabel("CPU: 0%")
        sb.addWidget(self._lbl_cpu)
        
        self._ram_bar = QProgressBar()
        self._ram_bar.setMaximumWidth(150)
        self._ram_bar.setTextVisible(True)
        sb.addWidget(self._ram_bar)
        
        sb.addWidget(QLabel("|"))
        self._lbl_hidden = QLabel("Ukryte: 0")
        sb.addWidget(self._lbl_hidden)
    
    def _init_timers(self):
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(2000)
        
        self._stats_timer = QTimer(self)
        self._stats_timer.timeout.connect(self._update_stats)
        self._stats_timer.start(1000)
    
    def _apply_style(self):
        self.setStyleSheet("""
            QMainWindow { background: #1e1e2e; }
            QWidget { background: #1e1e2e; color: #cdd6f4; font-family: 'Segoe UI'; }
            QTableWidget { background: #313244; alternate-background-color: #363a4f;
                          gridline-color: #45475a; border: 1px solid #45475a; border-radius: 8px; }
            QTableWidget::item:selected { background: #89b4fa; color: #1e1e2e; }
            QHeaderView::section { background: #45475a; color: #cdd6f4; padding: 8px;
                                   border: none; font-weight: bold; }
            QPushButton { background: #45475a; color: #cdd6f4; border: none;
                         padding: 8px 16px; border-radius: 6px; }
            QPushButton:hover { background: #585b70; }
            QPushButton:pressed { background: #89b4fa; color: #1e1e2e; }
            QLineEdit { background: #313244; color: #cdd6f4; border: 1px solid #45475a;
                       padding: 8px; border-radius: 6px; }
            QLineEdit:focus { border-color: #89b4fa; }
            QComboBox { background: #313244; color: #cdd6f4; border: 1px solid #45475a;
                       padding: 6px 12px; border-radius: 6px; }
            QFrame { background: #313244; border-radius: 8px; padding: 12px; }
            QStatusBar { background: #181825; color: #a6adc8; }
            QToolBar { background: #181825; border: none; spacing: 8px; padding: 4px; }
            QProgressBar { background: #45475a; border-radius: 4px; text-align: center; }
            QProgressBar::chunk { background: #89b4fa; border-radius: 4px; }
        """)
    
    def _refresh(self):
        if not self._bridge:
            return
        try:
            self._procs = self._bridge.enumerate_processes()
            self._filter()
            self._lbl_count.setText(f"Procesy: {len(self._procs)}")
            hidden = sum(1 for p in self._procs if p.is_hidden)
            self._lbl_hidden.setText(f"Ukryte: {hidden}")
        except Exception as e:
            log.error(f"Refresh error: {e}")
    
    def _filter(self):
        txt = self._search.text().lower()
        ftype = self._filter_combo.currentIndex()
        
        filtered = []
        for p in self._procs:
            if txt and txt not in p.name.lower():
                continue
            if ftype == 1 and p.is_system:
                continue
            if ftype == 2 and not p.is_system:
                continue
            if ftype == 3 and not p.is_hidden:
                continue
            filtered.append(p)
        
        self._table.update_procs(filtered)
    
    def _on_select(self, p):
        self._details.show_proc(p)
        enabled = p is not None
        self._btn_kill.setEnabled(enabled)
        self._btn_suspend.setEnabled(enabled)
        self._btn_resume.setEnabled(enabled)
        self._btn_hide.setEnabled(enabled and not (p and p.is_hidden))
        self._btn_unhide.setEnabled(enabled and (p and p.is_hidden))
    
    def _on_dblclick(self, p):
        pass  # TODO: details dialog
    
    def _update_stats(self):
        if not self._bridge:
            return
        try:
            cpu = self._bridge.get_cpu_usage()
            self._lbl_cpu.setText(f"CPU: {cpu:.1f}%")
            
            mem = self._bridge.get_memory_info()
            self._ram_bar.setValue(int(mem.percent))
            self._ram_bar.setFormat(
                f"RAM: {mem.percent:.0f}% ({mem.used // (1024**3)}/{mem.total // (1024**3)} GB)"
            )
        except Exception as e:
            log.error(f"Stats error: {e}")
    
    def _kill(self):
        p = self._table.get_selected()
        if not p:
            return
        if p.is_system:
            QMessageBox.warning(self, "Blad", "Nie mozna zabic procesu systemowego")
            return
        
        r = QMessageBox.question(self, "Potwierdzenie",
            f"Zakonczyc {p.name} (PID: {p.pid})?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if r == QMessageBox.StandardButton.Yes:
            try:
                self._bridge.terminate_process(p.pid, force=True)
                self._refresh()
            except AccessDeniedError:
                QMessageBox.critical(self, "Blad", "Brak uprawnien")
            except Exception as e:
                QMessageBox.critical(self, "Blad", str(e))
    
    def _suspend(self):
        p = self._table.get_selected()
        if p and self._bridge:
            try:
                self._bridge.suspend_process(p.pid)
                self._refresh()
            except Exception as e:
                QMessageBox.critical(self, "Blad", str(e))
    
    def _resume(self):
        p = self._table.get_selected()
        if p and self._bridge:
            try:
                self._bridge.resume_process(p.pid)
                self._refresh()
            except Exception as e:
                QMessageBox.critical(self, "Blad", str(e))
    
    def _hide(self):
        p = self._table.get_selected()
        if not p or not self._bridge:
            return
        if not self._admin:
            QMessageBox.warning(self, "Blad", "Wymaga admina")
            return
        try:
            self._bridge.hide_process(p.pid)
            self._refresh()
        except Exception as e:
            QMessageBox.critical(self, "Blad", str(e))
    
    def _unhide(self):
        p = self._table.get_selected()
        if p and self._bridge:
            try:
                self._bridge.unhide_process(p.pid)
                self._refresh()
            except Exception as e:
                QMessageBox.critical(self, "Blad", str(e))
    
    def _set_prio(self):
        p = self._table.get_selected()
        if not p or not self._bridge:
            return
        
        prios = [PRIORITY_IDLE, PRIORITY_BELOW_NORMAL, PRIORITY_NORMAL,
                 PRIORITY_ABOVE_NORMAL, PRIORITY_HIGH, PRIORITY_REALTIME]
        prio = prios[self._prio_combo.currentIndex()]
        
        try:
            self._bridge.set_priority(p.pid, prio)
            self._refresh()
        except Exception as e:
            QMessageBox.critical(self, "Blad", str(e))
    
    def closeEvent(self, ev):
        self._timer.stop()
        self._stats_timer.stop()
        ev.accept()
