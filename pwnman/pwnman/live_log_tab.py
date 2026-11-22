"""Live log viewer: streams `tail -F` over its own SSH channel."""
from __future__ import annotations

import threading

from PyQt6 import QtCore, QtGui, QtWidgets

from pwnman.pwnman import remote_cmds
from pwnman.pwnman.logs_model import LEVELS, LogBuffer, matches

MAX_SHOWN = 5000


class LiveLogTab(QtWidgets.QWidget):
    _line = QtCore.pyqtSignal(str)
    _ended = QtCore.pyqtSignal(str)
    log = QtCore.pyqtSignal(str)

    def __init__(self, ssh_client, parent=None):
        super().__init__(parent)
        self.ssh = ssh_client
        self.buffer = LogBuffer()
        self._paused = False
        self._pending: list[str] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

        root = QtWidgets.QVBoxLayout(self)
        bar = QtWidgets.QHBoxLayout()
        self.btn_follow = QtWidgets.QPushButton("Follow")
        self.btn_follow.setCheckable(True)
        self.btn_pause = QtWidgets.QPushButton("Pause")
        self.btn_pause.setCheckable(True)
        self.btn_clear = QtWidgets.QPushButton("Clear")
        self.level = QtWidgets.QComboBox()
        self.level.addItems(LEVELS)
        self.level.setToolTip("Minimum level (unlabelled lines count as INFO)")
        self.search = QtWidgets.QLineEdit()
        self.search.setPlaceholderText("Search…")
        self.search.setClearButtonEnabled(True)
        self.btn_copy = QtWidgets.QPushButton("Copy")
        self.btn_save = QtWidgets.QPushButton("Save…")
        for w in (self.btn_follow, self.btn_pause, self.btn_clear, QtWidgets.QLabel("Level ≥"),
                  self.level, self.search, self.btn_copy, self.btn_save):
            bar.addWidget(w)
        bar.setStretchFactor(self.search, 1)
        root.addLayout(bar)
        self.view = QtWidgets.QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setMaximumBlockCount(MAX_SHOWN)
        self.view.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont))
        root.addWidget(self.view, 1)
        self.status = QtWidgets.QLabel("Stopped")
        root.addWidget(self.status)

        self._line.connect(self._on_line)
        self._ended.connect(self._on_ended)
        self.btn_follow.toggled.connect(self._follow_toggled)
        self.btn_pause.toggled.connect(self._pause_toggled)
        self.btn_clear.clicked.connect(self.clear)
        self.level.currentIndexChanged.connect(self.rerender)
        self.search.textChanged.connect(self.rerender)
        self.btn_copy.clicked.connect(lambda: QtWidgets.QApplication.clipboard().setText(
            self.view.toPlainText()))
        self.btn_save.clicked.connect(self._save)

    # ------------------------------------------------------------- display
    def _passes(self, line: str) -> bool:
        return matches(line, self.level.currentText(), self.search.text())

    def _on_line(self, line: str):
        self.buffer.add(line)
        if self._paused:
            self._pending.append(line)
            self.status.setText(f"Paused ({len(self._pending)} new)")
            return
        if self._passes(line):
            self.view.appendPlainText(line)

    def rerender(self):
        self.view.setPlainText("\n".join(
            list(self.buffer.filtered(self.level.currentText(), self.search.text()))[-MAX_SHOWN:]))
        sb = self.view.verticalScrollBar()
        sb.setValue(sb.maximum())

    def clear(self):
        self.buffer.clear()
        self._pending.clear()
        self.view.clear()

    def _pause_toggled(self, on: bool):
        self._paused = on
        if not on:
            self._pending.clear()
            self.rerender()
            self.status.setText("Following" if self.running else "Stopped")

    def _save(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save log", "pwnagotchi.log")
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(self.buffer.lines) + "\n")

    # -------------------------------------------------------------- stream
    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _follow_toggled(self, on: bool):
        if on:
            self.start()
        else:
            self.stop()

    def start(self):
        if self.running or not getattr(self.ssh, "connected", False):
            if not getattr(self.ssh, "connected", False):
                self.btn_follow.blockSignals(True)
                self.btn_follow.setChecked(False)
                self.btn_follow.blockSignals(False)
            return
        self._stop = threading.Event()
        stop = self._stop

        def run():
            try:
                self.ssh.stream(remote_cmds.follow_log(), self._line.emit, stop)
                self._ended.emit("")
            except Exception as e:  # noqa: BLE001
                self._ended.emit(str(e))

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        self.btn_follow.setChecked(True)
        self.status.setText("Following")

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self._thread = None
        self.btn_follow.blockSignals(True)
        self.btn_follow.setChecked(False)
        self.btn_follow.blockSignals(False)
        self.status.setText("Stopped")

    def _on_ended(self, err: str):
        if self._stop.is_set():
            return
        self._thread = None
        self.btn_follow.blockSignals(True)
        self.btn_follow.setChecked(False)
        self.btn_follow.blockSignals(False)
        self.status.setText(f"Stopped: {err}" if err else "Stopped (stream ended)")
