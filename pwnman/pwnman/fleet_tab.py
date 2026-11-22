from __future__ import annotations

import time

from PyQt6 import QtCore, QtWidgets

from pwnman.pwnman.async_utils import quote_bash, run_in_thread
from pwnman.pwnman.known_hosts import KnownHosts, fetch_host_key
from pwnman.pwnman.fleet import DeviceStatus, probe_device, run_remote_command
from pwnman.pwnman import theme
from pwnman.pwnman.models import ConnectionProfile
from pwnman.pwnman.profile_store import ProfileStore

COLUMNS = ["Profile", "Host", "Online", "Service", "Uptime",
           "Temp", "Mem", "Handshakes", "AI epoch", "Polled"]


def should_probe(failures: int, cycle: int) -> bool:
    """Back off dead devices: probe every cycle for the first 2 failures, then
    every 2nd, 4th, 8th, ... (max 16th) cycle."""
    if failures < 3:
        return True
    return cycle % (2 ** min(failures - 2, 4)) == 0


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

    statusUpdated = QtCore.pyqtSignal(object)  # DeviceStatus (for alerts)

    def __init__(self, store: ProfileStore, main_window=None, parent=None):
        super().__init__(parent)
        self.store = store
        self.main_window = main_window
        self.pool = QtCore.QThreadPool.globalInstance()
        self.signals = _Signals()
        self.signals.probed.connect(self._on_probed)
        self.signals.cmd_done.connect(self._on_cmd_done)
        self._row_by_name: dict[str, int] = {}
        self._failures: dict[str, int] = {}
        self._cycle = 0
        self._shown_once = False
        self._hostkey_errors: dict[str, object] = {}

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

        self.btn_trust = QtWidgets.QPushButton("Trust host key…")
        self.btn_trust.setToolTip("Fetch and verify the SSH host key of the selected device(s)")
        self.btn_trust.clicked.connect(self._trust_selected)
        self.btn_csv = QtWidgets.QPushButton("Export CSV…")
        self.btn_csv.clicked.connect(self._export_csv)
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
        bar.addWidget(self.btn_trust)
        bar.addWidget(self.btn_csv)
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

    def showEvent(self, ev):
        super().showEvent(ev)
        if not self._shown_once:
            # The table used to stay empty until the first timer tick (30 s).
            self._shown_once = True
            QtCore.QTimer.singleShot(0, self.refresh)

    def restyle(self):
        """Re-colour status cells after a theme switch."""
        for r in range(self.table.rowCount()):
            it = self.table.item(r, 2)
            if it is not None and it.text() in ("yes", "no"):
                it.setForeground(theme.status_color("ok" if it.text() == "yes" else "bad", self))
            sv = self.table.item(r, 3)
            if sv is not None and sv.text() and sv.text() != "active":
                sv.setForeground(theme.status_color("warn", self))

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
            self._rows_sig = []
            return
        profiles = self.store.profiles
        sig = [(p.name, p.username, p.host, p.port) for p in profiles]
        if sig != getattr(self, "_rows_sig", None):
            # Rebuilding clears the selection, so only do it when the set of
            # devices actually changed (it used to run on every auto-poll and
            # silently deselect rows between the user's click and the action).
            self._rebuild_rows()
            self._rows_sig = sig
        self._cycle += 1
        for p in profiles:
            if should_probe(self._failures.get(p.name, 0), self._cycle):
                self.pool.start(_ProbeTask(p, self.signals))

    @QtCore.pyqtSlot(object)
    def _on_probed(self, st: DeviceStatus):
        self.statusUpdated.emit(st)
        row = self._row_by_name.get(st.name)
        if row is None:
            return
        self._failures[st.name] = 0 if st.online else self._failures.get(st.name, 0) + 1
        if getattr(st, "host_key_error", None) is not None:
            self._hostkey_errors[st.name] = st.host_key_error
        else:
            self._hostkey_errors.pop(st.name, None)
        online = QtWidgets.QTableWidgetItem("yes" if st.online else "no")
        color = theme.status_color("ok" if st.online else "bad", self)
        online.setForeground(color)
        if st.error:
            online.setToolTip(st.error)
        self.table.setItem(row, 2, online)

        svc = st.service_active or ""
        svc_item = QtWidgets.QTableWidgetItem(svc)
        if svc and svc != "active":
            svc_item.setForeground(theme.status_color("warn", self))
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

    def _trust_selected(self):
        sel = self._selected_profiles()
        if not sel:
            QtWidgets.QMessageBox.information(self, "Trust", "Select a device row first.")
            return
        for p in sel:
            self._trust_one(p)

    def _trust_one(self, p: ConnectionProfile):
        port = int(p.port or 22)
        kh = KnownHosts()

        def do():
            return fetch_host_key(p.host, port)

        def done(key, err):
            if err:
                self._log(f"{p.name}: cannot fetch host key: {err}")
                return
            from pwnman.pwnman.known_hosts import fingerprint
            old = kh.known_fingerprint(p.host, port)
            if old and old != fingerprint(key):
                text = (f"HOST KEY CHANGED for {p.name} ({p.host}).\n\nKnown: {old}\n"
                        f"Now:   {fingerprint(key)}\n\nReplace the stored key? Only do this "
                        "if you re-flashed the device.")
            else:
                text = (f"{p.name} ({p.host}:{port})\n{key.get_name()} {fingerprint(key)}\n\n"
                        "Trust this host key?")
            if QtWidgets.QMessageBox.question(self, "Trust host key", text) == \
                    QtWidgets.QMessageBox.StandardButton.Yes:
                kh.trust(p.host, port, key, replace=bool(old))
                self._log(f"{p.name}: host key trusted.")
                self._failures[p.name] = 0
                self.refresh()

        run_in_thread(self, do, done)

    def _export_csv(self, path: str | None = None):
        import csv
        if not path:
            path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export fleet", "fleet.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(COLUMNS)
            for r in range(self.table.rowCount()):
                w.writerow([(self.table.item(r, c).text() if self.table.item(r, c) else "")
                            for c in range(len(COLUMNS))])
        self._log(f"Exported {self.table.rowCount()} row(s) to {path}")

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
