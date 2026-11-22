from __future__ import annotations

from PyQt6 import QtCore, QtWidgets

from pwnman.pwnman import discovery
from pwnman.pwnman.async_utils import run_in_thread


class DiscoveryDialog(QtWidgets.QDialog):
    """Scan for devices; the chosen host is exposed as ``selected_host``."""

    def __init__(self, parent=None, finder=discovery.discover):
        super().__init__(parent)
        self.setWindowTitle("Discover devices")
        self.resize(460, 340)
        self.selected_host = ""
        self._finder = finder
        lay = QtWidgets.QVBoxLayout(self)
        self.chk_lan = QtWidgets.QCheckBox("Also scan my local /24 network(s) for SSH (slower)")
        self.list = QtWidgets.QListWidget()
        self.status = QtWidgets.QLabel("")
        lay.addWidget(self.chk_lan)
        lay.addWidget(self.list, 1)
        lay.addWidget(self.status)
        row = QtWidgets.QHBoxLayout()
        self.btn_scan = QtWidgets.QPushButton("Scan")
        self.btn_add = QtWidgets.QPushButton("Add as profile")
        self.btn_add.setEnabled(False)
        self.btn_close = QtWidgets.QPushButton("Close")
        row.addWidget(self.btn_scan)
        row.addStretch(1)
        row.addWidget(self.btn_add)
        row.addWidget(self.btn_close)
        lay.addLayout(row)
        self.btn_scan.clicked.connect(self.scan)
        self.btn_add.clicked.connect(self._add)
        self.btn_close.clicked.connect(self.reject)
        self.list.itemSelectionChanged.connect(
            lambda: self.btn_add.setEnabled(bool(self.list.selectedItems())))
        self.list.itemDoubleClicked.connect(lambda *_: self._add())

    def scan(self):
        self.btn_scan.setEnabled(False)
        self.status.setText("Scanning…")
        self.list.clear()
        lan = self.chk_lan.isChecked()

        def done(res, err):
            self.btn_scan.setEnabled(True)
            if err:
                self.status.setText(f"Scan failed: {err}")
                return
            for f in res:
                it = QtWidgets.QListWidgetItem(
                    f"{f.host}   [{f.source}]" + (f"   {f.name}" if f.name else ""))
                it.setData(QtCore.Qt.ItemDataRole.UserRole, f.host)
                self.list.addItem(it)
            self.status.setText(f"{len(res)} device(s) with SSH open." if res else "Nothing found.")

        run_in_thread(self, lambda: self._finder(include_lan=lan), done)

    def _add(self):
        items = self.list.selectedItems()
        if items:
            self.selected_host = items[0].data(QtCore.Qt.ItemDataRole.UserRole)
            self.accept()
