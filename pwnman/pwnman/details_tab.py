"""Details tab: raw device facts (uname/df/ip) for troubleshooting."""
from __future__ import annotations

from PyQt6 import QtCore, QtWidgets

from pwnman.pwnman.async_utils import run_in_thread

COMMANDS = [
    "hostname",
    "uptime -p || uptime",
    "uname -a",
    "df -h / | tail -n 1",
    "ip -4 addr show | grep -E 'inet ' || true",
    "systemctl is-active pwnagotchi 2>/dev/null || service pwnagotchi status 2>/dev/null || true",
]


class DetailsTab(QtWidgets.QWidget):
    log = QtCore.pyqtSignal(str)

    def __init__(self, ssh, parent=None):
        super().__init__(parent)
        self.ssh = ssh
        lay = QtWidgets.QVBoxLayout(self)
        self.btn_refresh = QtWidgets.QPushButton("Refresh device info")
        self.btn_refresh.clicked.connect(self.refresh)
        self.info = QtWidgets.QPlainTextEdit()
        self.info.setReadOnly(True)
        self.info.setMinimumHeight(220)
        lay.addWidget(self.btn_refresh)
        lay.addWidget(self.info, 1)

    def refresh(self):
        def do():
            out = []
            for c in COMMANDS:
                r = self.ssh.run(c)
                text = r.stdout.strip() if r.stdout.strip() else r.stderr.strip()
                out.append(f"$ {c}\n{text}\n")
            return "\n".join(out)

        def done(res, err):
            if err:
                self.log.emit(f"[ERROR] {err}")
                return
            self.info.setPlainText(res)
            self.log.emit("Refreshed device info.")

        run_in_thread(self, do, done)
