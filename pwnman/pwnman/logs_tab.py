"""Logs tab: one-shot fetch of the pwnagotchi log / journal."""
from __future__ import annotations

from PyQt6 import QtCore, QtGui, QtWidgets

from pwnman.pwnman import remote_cmds
from pwnman.pwnman.async_utils import run_in_thread


class LogsTab(QtWidgets.QWidget):
    log = QtCore.pyqtSignal(str)

    def __init__(self, ssh, parent=None):
        super().__init__(parent)
        self.ssh = ssh
        lay = QtWidgets.QVBoxLayout(self)
        top = QtWidgets.QHBoxLayout()
        self.log_mode = QtWidgets.QComboBox()
        self.log_mode.addItems([
            "/var/log/pwnagotchi.log (tail)",
            "journalctl -u pwnagotchi (last N lines)",
        ])
        self.log_lines = QtWidgets.QSpinBox()
        self.log_lines.setRange(10, 5000)
        self.log_lines.setValue(200)
        self.btn_logs = QtWidgets.QPushButton("Fetch logs")
        self.btn_logs.clicked.connect(self.fetch)
        top.addWidget(self.log_mode)
        top.addWidget(QtWidgets.QLabel("Lines:"))
        top.addWidget(self.log_lines)
        top.addWidget(self.btn_logs)
        top.addStretch(1)
        self.logs = QtWidgets.QPlainTextEdit()
        self.logs.setReadOnly(True)
        self.logs.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont))
        lay.addLayout(top)
        lay.addWidget(self.logs, 1)

    def fetch(self):
        mode = self.log_mode.currentIndex()
        n = int(self.log_lines.value())

        def do():
            cmd = remote_cmds.tail_log(n) if mode == 0 else remote_cmds.journal(n)
            r = self.ssh.run(cmd, timeout_sec=20)
            return r.stdout if r.stdout else r.stderr

        def done(res, err):
            if err:
                self.log.emit(f"[ERROR] {err}")
                return
            self.logs.setPlainText(res)
            self.log.emit("Fetched logs.")

        run_in_thread(self, do, done)
