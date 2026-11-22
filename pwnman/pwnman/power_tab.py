"""Power tab: reboot / shutdown and the AUTO/MANUAL mode switch."""
from __future__ import annotations

from PyQt6 import QtCore, QtWidgets

from pwnman.pwnman import remote_cmds
from pwnman.pwnman.async_utils import run_in_thread


class PowerTab(QtWidgets.QWidget):
    log = QtCore.pyqtSignal(str)
    droppedConnection = QtCore.pyqtSignal()  # device is going away: tear the session down

    def __init__(self, ssh, parent=None):
        super().__init__(parent)
        self.ssh = ssh
        lay = QtWidgets.QVBoxLayout(self)
        self.btn_reboot = QtWidgets.QPushButton("Reboot")
        self.btn_shutdown = QtWidgets.QPushButton("Shutdown")
        self.btn_reboot.clicked.connect(self.reboot)
        self.btn_shutdown.clicked.connect(self.shutdown)
        warn = QtWidgets.QLabel(
            "Power actions will immediately reboot/shutdown the device.\n"
            "Use only on devices you own/control.")
        warn.setWordWrap(True)
        lay.addWidget(warn)
        lay.addWidget(self.btn_reboot)
        lay.addWidget(self.btn_shutdown)

        mode_box = QtWidgets.QGroupBox("Pwnagotchi mode")
        ml = QtWidgets.QHBoxLayout(mode_box)
        self.mode_label = QtWidgets.QLabel("Mode: ?")
        self.btn_mode_auto = QtWidgets.QPushButton("Switch to AUTO")
        self.btn_mode_manual = QtWidgets.QPushButton("Switch to MANUAL")
        self.btn_mode_check = QtWidgets.QPushButton("Check")
        self.btn_mode_auto.clicked.connect(lambda: self.set_mode("AUTO"))
        self.btn_mode_manual.clicked.connect(lambda: self.set_mode("MANUAL"))
        self.btn_mode_check.clicked.connect(self.check_mode)
        for mw in (self.mode_label, self.btn_mode_check, self.btn_mode_auto, self.btn_mode_manual):
            ml.addWidget(mw)
        ml.addStretch(1)
        lay.addWidget(mode_box)
        lay.addStretch(1)

    def _power_action(self, title: str, cmd: str, past: str):
        if QtWidgets.QMessageBox.question(
                self, title, f"{title} the device now?"
        ) != QtWidgets.QMessageBox.StandardButton.Yes:
            return

        def do():
            try:
                r = self.ssh.run(cmd, timeout_sec=8)
            except Exception as e:  # noqa: BLE001
                # The link dying mid-command is the *expected* outcome.
                return 0, f"connection closed ({e.__class__.__name__})"
            return r.exit_status, (r.stderr or r.stdout or "").strip()

        def done(res, err):
            if err:
                self.log.emit(f"[ERROR] {err}")
                return
            status, text = res
            if status not in (0, -1):
                self.log.emit(f"[ERROR] {title} failed (exit {status}): {text}")
                QtWidgets.QMessageBox.critical(self, f"{title} failed", text or f"exit {status}")
                return
            self.log.emit(f"{past} command sent. Connection will drop.")
            self.droppedConnection.emit()

        run_in_thread(self, do, done)

    def reboot(self):
        self._power_action("Reboot", remote_cmds.power("reboot"), "Reboot")

    def shutdown(self):
        self._power_action("Shutdown", remote_cmds.power("shutdown"), "Shutdown")

    def check_mode(self):
        def do():
            return self.ssh.run(remote_cmds.mode_get(), timeout_sec=15).stdout.strip() or "UNKNOWN"

        def done(res, err):
            self.mode_label.setText(f"Mode: {res}" if not err else "Mode: ?")
            if err:
                self.log.emit(f"[ERROR] {err}")

        run_in_thread(self, do, done)

    def set_mode(self, mode: str):
        if QtWidgets.QMessageBox.question(
                self, "Switch mode",
                f"Switch pwnagotchi to {mode} mode? The service will be restarted."
        ) != QtWidgets.QMessageBox.StandardButton.Yes:
            return

        def do():
            r = self.ssh.run(remote_cmds.mode_set(mode), timeout_sec=40)
            if r.exit_status != 0:
                raise RuntimeError((r.stderr or r.stdout).strip() or "mode switch failed")
            return mode

        def done(res, err):
            if err:
                self.log.emit(f"[ERROR] {err}")
                QtWidgets.QMessageBox.critical(self, "Mode switch failed", str(err))
                return
            self.mode_label.setText(f"Mode: {res}")
            self.log.emit(f"Mode set to {res}; service restarted.")

        run_in_thread(self, do, done)
