"""History tab: charts of the metrics the app has recorded per device."""
from __future__ import annotations

import time

from PyQt6 import QtCore, QtWidgets

from pwnman.pwnman import metrics_store as ms
from pwnman.pwnman.chart import LineChart

# (field, title, unit, colour index, fixed range, decimals)
CHARTS = [
    ("cpu_temp", "CPU temperature", "°C", 1, None, 1),
    ("battery", "Battery", "%", 2, (0, 100), 0),
    ("mem_pct", "Memory used", "%", 0, (0, 100), 0),
    ("load1", "Load (1 min)", "", 3, None, 2),
    ("handshakes", "Handshakes", "", 4, None, 0),
    ("epoch", "AI epoch", "", 5, None, 0),
]


class MetricsTab(QtWidgets.QWidget):
    log = QtCore.pyqtSignal(str)

    def __init__(self, store: ms.MetricsStore, parent=None):
        super().__init__(parent)
        self.store = store
        lay = QtWidgets.QVBoxLayout(self)

        bar = QtWidgets.QHBoxLayout()
        self.device = QtWidgets.QComboBox()
        self.device.setMinimumWidth(160)
        self.range = QtWidgets.QComboBox()
        self.range.addItems(list(ms.RANGES))
        self.range.setCurrentText("24 hours")
        self.btn_refresh = QtWidgets.QPushButton("Refresh")
        self.btn_export = QtWidgets.QPushButton("Export CSV…")
        self.btn_clear = QtWidgets.QPushButton("Clear history…")
        for w in (QtWidgets.QLabel("Device:"), self.device, QtWidgets.QLabel("Range:"), self.range,
                  self.btn_refresh, self.btn_export, self.btn_clear):
            bar.addWidget(w)
        bar.addStretch(1)
        lay.addLayout(bar)

        self.summary = QtWidgets.QLabel("")
        self.summary.setWordWrap(True)
        lay.addWidget(self.summary)

        grid = QtWidgets.QGridLayout()
        self.charts: dict[str, LineChart] = {}
        for i, (field, title, unit, ci, rng, dec) in enumerate(CHARTS):
            c = LineChart(title, unit, ci, rng, dec)
            self.charts[field] = c
            grid.addWidget(c, i // 2, i % 2)
        lay.addLayout(grid, 1)

        self.btn_refresh.clicked.connect(self.reload)
        self.device.currentIndexChanged.connect(lambda _i: self.render())
        self.range.currentIndexChanged.connect(lambda _i: self.render())
        self.btn_export.clicked.connect(self.export_csv)
        self.btn_clear.clicked.connect(self.clear_history)

        self._timer = QtCore.QTimer(self)
        self._timer.setInterval(15_000)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    def _tick(self):
        if self.isVisible():
            self.reload()

    def showEvent(self, ev):
        super().showEvent(ev)
        self.reload()

    def reload(self):
        """Refresh the device list (keeping the selection), then redraw."""
        cur = self.device.currentText()
        names = self.store.devices()
        self.device.blockSignals(True)
        self.device.clear()
        self.device.addItems(names)
        if cur in names:
            self.device.setCurrentText(cur)
        self.device.blockSignals(False)
        self.render()

    def select(self, name: str):
        i = self.device.findText(name)
        if i >= 0:
            self.device.setCurrentIndex(i)

    def window_seconds(self) -> int:
        return ms.RANGES[self.range.currentText()]

    def render(self):
        dev = self.device.currentText()
        t1 = time.time()
        t0 = t1 - self.window_seconds()
        samples = self.store.query(dev, t0, t1) if dev else []
        avail = ms.availability(samples)
        if not samples:
            self.summary.setText("No history yet for this device in the selected range. "
                                 "Samples are collected while the app is open (Dashboard and Fleet polls).")
        else:
            self.summary.setText(
                f"{len(samples)} samples · availability {avail:.0f}% · "
                f"+{ms.handshake_gain(samples)} handshakes in range · retention "
                f"{self.store.retention_days:g} days")
        for field, _title, unit, _ci, _rng, dec in CHARTS:
            pts = ms.downsample(ms.series(samples, field), 600)
            st = ms.stats(pts)
            text = ""
            if st:
                text = (f"now {st['last']:.{dec}f}{unit} · min {st['min']:.{dec}f} · "
                        f"avg {st['avg']:.{dec}f} · max {st['max']:.{dec}f}")
            self.charts[field].set_data(pts, t0, t1, text)

    def export_csv(self, path: str | None = None):
        dev = self.device.currentText()
        if not dev:
            QtWidgets.QMessageBox.information(self, "Export", "No device selected.")
            return
        if not path:
            path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export history", f"{dev}-history.csv")
        if not path:
            return
        n = self.store.export_csv(path, dev, time.time() - self.window_seconds())
        self.log.emit(f"Exported {n} sample(s) of {dev} to {path}")

    def clear_history(self):
        dev = self.device.currentText()
        if QtWidgets.QMessageBox.question(
                self, "Clear history",
                f"Delete the stored history of '{dev}'?" if dev else "Delete ALL stored history?"
        ) != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        n = self.store.clear(dev or None)
        self.log.emit(f"Cleared {n} sample(s).")
        self.reload()
