from __future__ import annotations

from PyQt6 import QtCore, QtGui, QtWidgets


class Worker(QtCore.QObject):
    finished = QtCore.pyqtSignal(object, object)  # (result, error)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    @QtCore.pyqtSlot()
    def run(self):
        try:
            self.finished.emit(self._fn(*self._args, **self._kwargs), None)
        except Exception as e:
            self.finished.emit(None, e)


def run_in_thread(parent: QtWidgets.QWidget, fn, cb, *args, **kwargs):
    thread = QtCore.QThread(parent)
    worker = Worker(fn, *args, **kwargs)
    worker.moveToThread(thread)

    def done(res, err):
        thread.quit()
        thread.wait(1000)
        worker.deleteLater()
        thread.deleteLater()
        cb(res, err)

    worker.finished.connect(done)
    thread.started.connect(worker.run)
    thread.start()
    return thread


class SSHTerminalWidget(QtWidgets.QWidget):
    """
    Minimal SSH "terminal":
      - history output pane
      - command line input
      - runs each command via ssh_client.run("bash -lc ...")
    """

    log = QtCore.pyqtSignal(str)

    def __init__(self, ssh_client, parent=None):
        super().__init__(parent)
        self.ssh = ssh_client
        self._build()

    def _build(self):
        layout = QtWidgets.QVBoxLayout(self)

        # Top bar
        top = QtWidgets.QHBoxLayout()
        self.cwd = QtWidgets.QLineEdit("/home/pi")
        self.cwd.setToolTip("Remote working directory (best-effort)")
        self.btn_clear = QtWidgets.QPushButton("Clear")
        self.btn_clear.clicked.connect(lambda: self.out.setPlainText(""))

        self.btn_pwd = QtWidgets.QPushButton("pwd")
        self.btn_pwd.clicked.connect(self._refresh_pwd)

        top.addWidget(QtWidgets.QLabel("CWD:"))
        top.addWidget(self.cwd, 1)
        top.addWidget(self.btn_pwd)
        top.addWidget(self.btn_clear)
        layout.addLayout(top)

        # Output
        self.out = QtWidgets.QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont))
        layout.addWidget(self.out, 1)

        # Input
        bottom = QtWidgets.QHBoxLayout()
        self.inp = QtWidgets.QLineEdit()
        self.inp.setPlaceholderText("Type a command and press Enter…  (e.g. systemctl status pwnagotchi)")
        self.inp.returnPressed.connect(self._on_enter)

        self.btn_run = QtWidgets.QPushButton("Run")
        self.btn_run.clicked.connect(self._on_enter)

        bottom.addWidget(self.inp, 1)
        bottom.addWidget(self.btn_run)
        layout.addLayout(bottom)

        # Convenience shortcuts
        self.inp.installEventFilter(self)
        self._history: list[str] = []
        self._hist_idx = 0

    def eventFilter(self, obj, ev):
        if obj is self.inp and ev.type() == QtCore.QEvent.Type.KeyPress:
            if ev.key() == QtCore.Qt.Key.Key_Up:
                if self._history:
                    self._hist_idx = max(0, self._hist_idx - 1)
                    self.inp.setText(self._history[self._hist_idx])
                    return True
            if ev.key() == QtCore.Qt.Key.Key_Down:
                if self._history:
                    self._hist_idx = min(len(self._history), self._hist_idx + 1)
                    self.inp.setText("" if self._hist_idx == len(self._history) else self._history[self._hist_idx])
                    return True
        return super().eventFilter(obj, ev)

    def _append(self, text: str):
        self.out.appendPlainText(text)
        sb = self.out.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _wrap_bash(self, cmd: str) -> str:
        # run in requested CWD; keep it simple and robust
        wd = (self.cwd.text().strip() or "/").replace('"', '\\"')
        # user cmd remains as-is, executed by bash -lc
        script = f'cd "{wd}" 2>/dev/null || true; {cmd}'
        return script

    def _on_enter(self):
        if not getattr(self.ssh, "connected", False):
            QtWidgets.QMessageBox.information(self, "SSH", "Not connected.")
            return

        cmd = self.inp.text().strip()
        if not cmd:
            return

        self._history.append(cmd)
        self._hist_idx = len(self._history)
        self.inp.clear()

        self._append(f"$ {cmd}")

        def do():
            wd = (self.cwd.text().strip() or "/").replace('"', '\\"')
            script = f'cd "{wd}" 2>/dev/null || true; {cmd}'
            full = f"bash -lc {quote_bash(script)}"
            r = self.ssh.run(full, timeout_sec=120)
            return r.stdout or "", r.stderr or "", getattr(r, "exit_status", None)

        def done(res, err):
            if err:
                self._append(f"[ERROR] {err}")
                return
            out, serr, code = res
            if out:
                self._append(out.rstrip())
            if serr:
                self._append(serr.rstrip())
            if code not in (None, 0):
                self._append(f"[exit {code}]")
            if cmd.startswith("cd ") or cmd == "cd":
                self._refresh_pwd()

        run_in_thread(self, do, done)

    def _refresh_pwd(self):
        if not getattr(self.ssh, "connected", False):
            return

        def do():
            wd = (self.cwd.text().strip() or "/").replace('"', '\\"')
            script = f'cd "{wd}" 2>/dev/null || true; pwd'
            cmd = f"bash -lc {quote_bash(script)}"
            r = self.ssh.run(cmd, timeout_sec=10)
            return (r.stdout or "").strip() or wd

        def done(res, err):
            if err:
                return
            self.cwd.setText(res)

        run_in_thread(self, do, done)


def quote_bash(script: str) -> str:
    return "'" + script.replace("'", "'\"'\"'") + "'"
