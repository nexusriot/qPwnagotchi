"""Services tab: systemctl status/start/stop/restart for a few known units."""
from __future__ import annotations

from PyQt6 import QtCore, QtWidgets

from pwnman.pwnman import remote_cmds
from pwnman.pwnman.async_utils import run_in_thread

SERVICES = ["pwnagotchi", "bettercap", "bluetooth", "ssh", "networking"]


class ServicesTab(QtWidgets.QWidget):
    log = QtCore.pyqtSignal(str)

    def __init__(self, ssh, parent=None):
        super().__init__(parent)
        self.ssh = ssh
        lay = QtWidgets.QVBoxLayout(self)
        top = QtWidgets.QHBoxLayout()
        self.service_name = QtWidgets.QComboBox()
        self.service_name.addItems(SERVICES)
        top.addWidget(QtWidgets.QLabel("Service:"))
        top.addWidget(self.service_name)
        for label, action in (("Status", "status"), ("Start", "start"),
                              ("Stop", "stop"), ("Restart", "restart")):
            b = QtWidgets.QPushButton(label)
            b.clicked.connect(lambda _=False, a=action: self.run(a))
            setattr(self, f"btn_{action}", b)
            top.addWidget(b)
        top.addStretch(1)
        self.svc_out = QtWidgets.QPlainTextEdit()
        self.svc_out.setReadOnly(True)
        lay.addLayout(top)
        lay.addWidget(self.svc_out, 1)

    def run(self, action: str):
        name = self.service_name.currentText().strip()

        def do():
            cmd = remote_cmds.service_action(action, name)
            r = self.ssh.run(cmd, timeout_sec=20)
            return f"$ {cmd}\n\n{r.stdout}\n{r.stderr}".strip()

        def done(res, err):
            if err:
                self.log.emit(f"[ERROR] {err}")
                return
            self.svc_out.setPlainText(res)
            self.log.emit(f"Service {name}: {action}")

        run_in_thread(self, do, done)
