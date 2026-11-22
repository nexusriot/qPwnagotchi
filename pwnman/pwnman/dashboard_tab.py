"""Dashboard: native cards fed by the REST session API + an SSH probe."""
from __future__ import annotations

from PyQt6 import QtCore, QtWidgets

from pwnman.pwnman.async_utils import run_in_thread
from pwnman.pwnman.fleet import DeviceStatus, collect_status


def _card(title: str) -> tuple[QtWidgets.QGroupBox, QtWidgets.QLabel]:
    box = QtWidgets.QGroupBox(title)
    lay = QtWidgets.QVBoxLayout(box)
    val = QtWidgets.QLabel("—")
    f = val.font()
    f.setPointSize(f.pointSize() + 4)
    f.setBold(True)
    val.setFont(f)
    val.setTextInteractionFlags(QtCore.Qt.TextInteractionFlag.TextSelectableByMouse)
    lay.addWidget(val)
    return box, val


class DashboardTab(QtWidgets.QWidget):
    log = QtCore.pyqtSignal(str)
    statusUpdated = QtCore.pyqtSignal(object)

    def __init__(self, session, profile_provider, parent=None):
        super().__init__(parent)
        self.session = session
        self._profile = profile_provider  # () -> ConnectionProfile
        self._busy = False
        self.last: DeviceStatus | None = None

        root = QtWidgets.QVBoxLayout(self)
        top = QtWidgets.QHBoxLayout()
        self.face = QtWidgets.QLabel("(⌐■_■)")
        ff = self.face.font()
        ff.setPointSize(28)
        self.face.setFont(ff)
        self.title = QtWidgets.QLabel("Not connected")
        tf = self.title.font()
        tf.setPointSize(tf.pointSize() + 6)
        tf.setBold(True)
        self.title.setFont(tf)
        self.btn_refresh = QtWidgets.QPushButton("Refresh")
        self.btn_refresh.clicked.connect(self.refresh)
        self.chk_auto = QtWidgets.QCheckBox("Auto (10 s)")
        self.chk_auto.setChecked(True)
        top.addWidget(self.face)
        top.addWidget(self.title, 1)
        top.addWidget(self.chk_auto)
        top.addWidget(self.btn_refresh)
        root.addLayout(top)

        grid = QtWidgets.QGridLayout()
        self.cards: dict[str, QtWidgets.QLabel] = {}
        names = ["Service", "Mode", "Epoch / reward", "Handshakes", "Peers", "Uptime",
                 "CPU temp", "Load", "Memory", "Disk", "IP", "Battery"]
        for i, n in enumerate(names):
            box, val = _card(n)
            self.cards[n] = val
            grid.addWidget(box, i // 4, i % 4)
        root.addLayout(grid)
        self.battery_bar = QtWidgets.QProgressBar()
        self.battery_bar.setRange(0, 100)
        self.battery_bar.setVisible(False)
        root.addWidget(self.battery_bar)
        self.note = QtWidgets.QLabel("")
        self.note.setWordWrap(True)
        root.addWidget(self.note)
        root.addStretch(1)

        self._timer = QtCore.QTimer(self)
        self._timer.setInterval(10_000)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    def _tick(self):
        if self.chk_auto.isChecked() and self.isVisible():
            self.refresh()

    def refresh(self):
        if self._busy or not self.session.connected:
            return
        self._busy = True
        profile = self._profile()

        def do():
            return collect_status(self.session.ssh, profile)

        def done(res, err):
            self._busy = False
            if err:
                self.log.emit(f"[ERROR] dashboard: {err}")
                return
            self.show_status(res)

        run_in_thread(self, do, done)

    def show_status(self, st: DeviceStatus):
        self.last = st
        self.statusUpdated.emit(st)
        c = self.cards
        self.title.setText(st.remote_name or st.hostname or st.host or "Device")
        self.face.setText(st.face or "(⌐■_■)")
        c["Service"].setText(st.service_active or "—")
        c["Mode"].setText(st.mode or "—")
        epoch = "—" if st.ai_epoch is None else str(st.ai_epoch)
        if st.ai_reward is not None:
            epoch += f"  (r={st.ai_reward:.2f})"
        c["Epoch / reward"].setText(epoch)
        c["Handshakes"].setText("—" if st.handshakes is None else str(st.handshakes))
        c["Peers"].setText("—" if st.peers is None else str(st.peers))
        c["Uptime"].setText(st.rest_uptime or st.uptime or "—")
        c["CPU temp"].setText(st.temp_str or "—")
        c["Load"].setText(st.load or "—")
        c["Memory"].setText(st.mem_str or "—")
        c["Disk"].setText(st.disk or "—")
        c["IP"].setText(st.ip or "—")
        if st.battery is not None:
            c["Battery"].setText(f"{st.battery:.0f}%")
            self.battery_bar.setValue(int(st.battery))
            self.battery_bar.setVisible(True)
        else:
            c["Battery"].setText("n/a")
            self.battery_bar.setVisible(False)
        self.note.setText("" if st.rest_ok else
                          "Web API not reachable — name/face/epoch/peers unavailable "
                          "(check the LCD URL and credentials).")
