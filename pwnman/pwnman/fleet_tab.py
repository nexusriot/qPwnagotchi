from __future__ import annotations

import time
from typing import Optional

from PyQt6 import QtCore, QtGui, QtWidgets

from pwnman.pwnman.async_utils import quote_bash
from pwnman.pwnman.fleet import DeviceStatus, probe_device, run_remote_command
from pwnman.pwnman.models import ConnectionProfile
from pwnman.pwnman.profile_store import ProfileStore

COLUMNS = ["Profile", "Host", "Online", "Service", "Uptime",
           "Temp", "Mem", "Handshakes", "AI epoch", "Polled"]


class _Signals(QtCore.QObject):
    probed = QtCore.pyqtSignal(object)            # DeviceStatus
    cmd_done = QtCore.pyqtSignal(str, bool, str)  # name, ok, text


class _ProbeTask(QtCore.QRunnable):
    def __init__(self, profile: ConnectionProfile, signals: _Signals):
        super().__init__()
        self._p = profile
        self._sig = signals

    def run(self):
        try:
            st = probe_device(self._p)
        except Exception as e:  # noqa: BLE001 - never let a pool thread die silently
            st = DeviceStatus(name=self._p.name, host=self._p.host,
                              online=False, error=str(e))
        self._sig.probed.emit(st)


class _CmdTask(QtCore.QRunnable):
    def __init__(self, profile, command, expect_drop, timeout, signals: _Signals):
        super().__init__()
        self._p = profile
        self._cmd = command
        self._drop = expect_drop
        self._timeout = timeout
        self._sig = signals

    def run(self):
        ok, text = run_remote_command(
            self._p, self._cmd, timeout=self._timeout, expect_drop=self._drop
        )
        self._sig.cmd_done.emit(self._p.name, ok, text)


class FleetTab(QtWidgets.QWidget):
    """Concurrent multi-device dashboard. Independent of the active SSH session."""

    def __init__(self, store: ProfileStore, main_window=None, parent=None):
        super().__init__(parent)
        self.store = store
        self.main_window = main_window
        self.pool = QtCore.QThreadPool.globalInstance()
        self.signals = _Signals()
        self.signals.probed.connect(self._on_probed)
        self.signals.cmd_done.connect(self._on_cmd_done)
        self._row_by_name: dict[str, int] = {}

        self._build()

        self._timer = QtCore.QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._auto_changed()

    def _build(self):
        root = QtWidgets.QVBoxLayout(self)

        bar = QtWidgets.QHBoxLayout()
        self.btn_refresh = QtWidgets.QPushButton("Refresh now")
        self.btn_refresh.clicked.connect(self.refresh)
        self.chk_auto = QtWidgets.QCheckBox("Auto")
        self.chk_auto.setChecked(True)
        self.spin_interval = QtWidgets.QSpinBox()
        self.spin_interval.setRange(5, 600)
        self.spin_interval.setValue(30)
        self.spin_interval.setSuffix(" s")
        self.chk_auto.toggled.connect(self._auto_changed)
        self.spin_interval.valueChanged.connect(self._auto_changed)

        self.btn_connect = QtWidgets.QPushButton("Connect selected")
        self.btn_connect.clicked.connect(self._connect_selected)
        self.btn_restart = QtWidgets.QPushButton("Restart pwnagotchi")
        self.btn_restart.clicked.connect(self._bulk_restart)
        self.btn_run = QtWidgets.QPushButton("Run command…")
        self.btn_run.clicked.connect(self._bulk_run)
        self.btn_reboot = QtWidgets.QPushButton("Reboot")
        self.btn_reboot.clicked.connect(self._bulk_reboot)
        self.btn_shutdown = QtWidgets.QPushButton("Shutdown")
        self.btn_shutdown.clicked.connect(self._bulk_shutdown)

        bar.addWidget(self.btn_refresh)
        bar.addWidget(self.chk_auto)
        bar.addWidget(self.spin_interval)
        bar.addSpacing(16)
        bar.addWidget(self.btn_connect)
        bar.addStretch(1)
        bar.addWidget(self.btn_restart)
        bar.addWidget(self.btn_run)
        bar.addWidget(self.btn_reboot)
        bar.addWidget(self.btn_shutdown)
        root.addLayout(bar)

        self.table = QtWidgets.QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.cellDoubleClicked.connect(lambda *_: self._connect_selected())
        root.addWidget(self.table, 3)

        root.addWidget(QtWidgets.QLabel("Fleet log"))
        self.logview = QtWidgets.QPlainTextEdit()
        self.logview.setReadOnly(True)
        self.logview.setMaximumBlockCount(1000)
        self.logview.setMaximumHeight(140)
        root.addWidget(self.logview, 1)

    def _log(self, msg: str):
        self.logview.appendPlainText(f"{time.strftime('%H:%M:%S')}  {msg}")

    def _auto_changed(self):
        if self.chk_auto.isChecked():
            self._timer.start(int(self.spin_interval.value()) * 1000)
        else:
            self._timer.stop()

    def _rebuild_rows(self):
        profiles = self.store.profiles
        self.table.setRowCount(0)
        self._row_by_name.clear()
        for i, p in enumerate(profiles):
            self.table.insertRow(i)
            self._row_by_name[p.name] = i
            self._set(i, 0, p.name)
            self._set(i, 1, f"{p.username}@{p.host}:{p.port}")
            self._set(i, 2, "…")
            for c in range(3, len(COLUMNS)):
                self._set(i, c, "")

    def _set(self, row: int, col: int, text: str):
        item = self.table.item(row, col)
        if item is None:
            item = QtWidgets.QTableWidgetItem()
            self.table.setItem(row, col, item)
        item.setText(text)

    def refresh(self):
        if not self.store.profiles:
            self.table.setRowCount(0)
            self._row_by_name.clear()
            return
        self._rebuild_rows()
        for p in self.store.profiles:
            self.pool.start(_ProbeTask(p, self.signals))

    @QtCore.pyqtSlot(object)
    def _on_probed(self, st: DeviceStatus):
        row = self._row_by_name.get(st.name)
        if row is None:
            return
        online = QtWidgets.QTableWidgetItem("yes" if st.online else "no")
        color = QtGui.QColor(0, 140, 0) if st.online else QtGui.QColor(170, 0, 0)
        online.setForeground(color)
        if st.error:
            online.setToolTip(st.error)
        self.table.setItem(row, 2, online)

        svc = st.service_active or ""
        svc_item = QtWidgets.QTableWidgetItem(svc)
        if svc and svc != "active":
            svc_item.setForeground(QtGui.QColor(170, 90, 0))
        self.table.setItem(row, 3, svc_item)

        self._set(row, 4, st.uptime)
        self._set(row, 5, st.temp_str)
        self._set(row, 6, st.mem_str)
        self._set(row, 7, "" if st.handshakes is None else str(st.handshakes))
        epoch = "" if st.ai_epoch is None else str(st.ai_epoch)
        if st.rest_ok and st.ai_reward is not None:
            epoch += f"  (r={st.ai_reward:.2f})"
        self._set(row, 8, epoch)
        self._set(row, 9, time.strftime("%H:%M:%S", time.localtime(st.polled_at)))
        if not st.online:
            self._log(f"{st.name}: offline — {st.error}")

    def _selected_profiles(self) -> list[ConnectionProfile]:
        names = []
        for idx in self.table.selectionModel().selectedRows():
            item = self.table.item(idx.row(), 0)
            if item:
                names.append(item.text())
        out = []
        for n in names:
            p = self.store.get(n)
            if p is not None:
                out.append(p)
        return out

    def _connect_selected(self):
        sel = self._selected_profiles()
        if not sel:
            QtWidgets.QMessageBox.information(
                self, "Connect", "Select a device row first.")
            return
        if self.main_window is None:
            return
        self.main_window.connect_profile_by_name(sel[0].name)

    def _confirm(self, title: str, verb: str, sel: list) -> bool:
        names = "\n  ".join(p.name for p in sel)
        return QtWidgets.QMessageBox.question(
            self, title,
            f"{verb} on {len(sel)} device(s)?\n\n  {names}",
        ) == QtWidgets.QMessageBox.StandardButton.Yes

    def _dispatch(self, sel, command, expect_drop, timeout, verb):
        for p in sel:
            self._log(f"{p.name}: {verb}…")
            self.pool.start(
                _CmdTask(p, command, expect_drop, timeout, self.signals))

    def _bulk_restart(self):
        sel = self._selected_profiles()
        if not sel or not self._confirm("Restart", "Restart pwnagotchi", sel):
            return
        cmd = ("sudo systemctl restart pwnagotchi "
               "|| sudo service pwnagotchi restart")
        self._dispatch(sel, cmd, False, 35, "restart pwnagotchi")

    def _bulk_run(self):
        sel = self._selected_profiles()
        if not sel:
            QtWidgets.QMessageBox.information(self, "Run", "Select device row(s).")
            return
        text, ok = QtWidgets.QInputDialog.getText(
            self, "Run command", f"Command to run on {len(sel)} device(s):")
        if not ok or not text.strip():
            return
        cmd = f"bash -lc {quote_bash(text.strip())}"
        if not self._confirm("Run command", f"Run '{text.strip()}'", sel):
            return
        self._dispatch(sel, cmd, False, 60, f"run: {text.strip()}")

    def _bulk_reboot(self):
        sel = self._selected_profiles()
        if not sel or not self._confirm("Reboot", "REBOOT", sel):
            return
        self._dispatch(sel, "sudo reboot || reboot", True, 8, "reboot")

    def _bulk_shutdown(self):
        sel = self._selected_profiles()
        if not sel or not self._confirm("Shutdown", "SHUTDOWN", sel):
            return
        self._dispatch(
            sel, "sudo shutdown -h now || shutdown -h now", True, 8, "shutdown")

    @QtCore.pyqtSlot(str, bool, str)
    def _on_cmd_done(self, name: str, ok: bool, text: str):
        head = "OK" if ok else "FAIL"
        first = (text or "").strip().splitlines()
        snippet = first[-1] if first else ""
        self._log(f"{name}: {head} {snippet}")
