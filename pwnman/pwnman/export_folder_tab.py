from __future__ import annotations

import os
import time
from PyQt6 import QtCore, QtWidgets


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


def quote_bash(script: str) -> str:
    return "'" + script.replace("'", "'\"'\"'") + "'"


class ExportFolderTab(QtWidgets.QWidget):
    """
    Safe generic exporter:
      - user chooses remote folder (must be authorized)
      - creates tar.gz with sudo
      - places archive into /home/pi/
      - chown pi:pi so regular SFTP download works
    """
    log = QtCore.pyqtSignal(str)

    def __init__(self, ssh_client, parent=None):
        super().__init__(parent)
        self.ssh = ssh_client
        self._build()

    def _build(self):
        layout = QtWidgets.QVBoxLayout(self)

        form = QtWidgets.QGridLayout()

        self.remote_folder = QtWidgets.QLineEdit("/root/handshakes")
        self.remote_folder.setToolTip("Remote folder to archive (only what you’re authorized to manage)")

        self.dest_dir = QtWidgets.QLineEdit("/home/pi")
        self.dest_dir.setToolTip("Where to place the resulting archive")

        self.archive_name = QtWidgets.QLineEdit("handshakes")
        self.archive_name.setToolTip("Base archive name (timestamp will be added)")

        self.owner_user = QtWidgets.QLineEdit("pi")
        self.owner_group = QtWidgets.QLineEdit("pi")

        form.addWidget(QtWidgets.QLabel("Remote folder:"), 0, 0)
        form.addWidget(self.remote_folder, 0, 1, 1, 3)

        form.addWidget(QtWidgets.QLabel("Destination dir:"), 1, 0)
        form.addWidget(self.dest_dir, 1, 1, 1, 3)

        form.addWidget(QtWidgets.QLabel("Archive base name:"), 2, 0)
        form.addWidget(self.archive_name, 2, 1)

        form.addWidget(QtWidgets.QLabel("Owner user:"), 2, 2)
        form.addWidget(self.owner_user, 2, 3)

        form.addWidget(QtWidgets.QLabel("Owner group:"), 3, 2)
        form.addWidget(self.owner_group, 3, 3)

        layout.addLayout(form)

        btns = QtWidgets.QHBoxLayout()
        self.btn_export = QtWidgets.QPushButton("Export folder as .tar.gz")
        self.btn_export.setToolTip("Creates archive via sudo, moves to destination, chown to user/group")
        btns.addWidget(self.btn_export)

        btns.addStretch(1)
        layout.addLayout(btns)

        self.out = QtWidgets.QPlainTextEdit()
        self.out.setReadOnly(True)
        layout.addWidget(self.out, 1)

        self.btn_export.clicked.connect(self.on_export)

    def _append(self, s: str):
        self.out.appendPlainText(s)
        sb = self.out.verticalScrollBar()
        sb.setValue(sb.maximum())

    def on_export(self):
        if not getattr(self.ssh, "connected", False):
            QtWidgets.QMessageBox.information(self, "Export", "Not connected.")
            return

        src = self.remote_folder.text().strip()
        dst = self.dest_dir.text().strip() or "/home/pi"
        base = self.archive_name.text().strip() or "export"
        u = self.owner_user.text().strip() or "pi"
        g = self.owner_group.text().strip() or "pi"

        # add timestamp to avoid overwriting
        ts = time.strftime("%Y%m%d-%H%M%S")
        fname = f"{base}-{ts}.tar.gz"
        out_path = f"{dst.rstrip('/')}/{fname}"

        if not src.startswith("/"):
            QtWidgets.QMessageBox.warning(self, "Export", "Remote folder should be an absolute path (start with /).")
            return

        if QtWidgets.QMessageBox.question(
            self, "Export",
            f"Create archive from:\n  {src}\n\nOutput:\n  {out_path}\n\nProceed?"
        ) != QtWidgets.QMessageBox.StandardButton.Yes:
            return

        self._append(f"Exporting: {src} -> {out_path}")

        def do():
            # Safety checks:
            # - folder exists
            # - destination exists (mkdir -p)
            # - tar with sudo
            # - chown to user so SFTP can download
            script = f"""
set -e

SRC={quote_sh(src)}
DST={quote_sh(dst)}
OUT={quote_sh(out_path)}
UG={quote_sh(f"{u}:{g}")}

sudo test -d "$SRC"
sudo mkdir -p "$DST"

# Create tar.gz (store as root -> then fix ownership)
sudo tar -czf "$OUT" -C "$(dirname "$SRC")" "$(basename "$SRC")"

sudo chown "$UG" "$OUT"
sudo chmod 0644 "$OUT"

echo "OK: $OUT"
ls -lah "$OUT"
"""
            r = self.ssh.run(f"bash -lc {quote_bash(script)}", timeout_sec=180)
            txt = (r.stdout or "") + ("\n" + r.stderr if r.stderr else "")
            if getattr(r, "exit_status", 0) != 0:
                raise RuntimeError(txt.strip() or "Export failed.")
            return txt.strip()

        def done(res, err):
            if err:
                self._append(f"[ERROR] {err}")
                self.log.emit(f"[ERROR] export: {err}")
                QtWidgets.QMessageBox.critical(self, "Export failed", str(err))
                return
            self._append(res)
            self.log.emit("Export complete (archive created).")
            QtWidgets.QMessageBox.information(self, "Export", "Archive created. You can download it from the Files tab.")

        run_in_thread(self, do, done)


def quote_sh(s: str) -> str:
    # simple single-quote escaping for bash variables
    return "'" + s.replace("'", "'\"'\"'") + "'"
