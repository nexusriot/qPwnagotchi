"""Handshake manager: list / download / delete captures. No analysis or attack features."""
from __future__ import annotations

import os
import posixpath
import time
import uuid

from PyQt6 import QtCore, QtGui, QtWidgets

from pwnman.pwnman import remote_cmds
from pwnman.pwnman.async_utils import run_in_thread


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


class _NumItem(QtWidgets.QTableWidgetItem):
    def __lt__(self, other):
        return (self.data(QtCore.Qt.ItemDataRole.UserRole) or 0) < (other.data(QtCore.Qt.ItemDataRole.UserRole) or 0)


class HandshakesTab(QtWidgets.QWidget):
    log = QtCore.pyqtSignal(str)

    def __init__(self, ssh_client, parent=None):
        super().__init__(parent)
        self.ssh = ssh_client
        self.directory = remote_cmds.HANDSHAKE_DIR
        root = QtWidgets.QVBoxLayout(self)
        bar = QtWidgets.QHBoxLayout()
        self.dir_edit = QtWidgets.QLineEdit(self.directory)
        self.btn_refresh = QtWidgets.QPushButton("Refresh")
        self.btn_download = QtWidgets.QPushButton("Download selected…")
        self.btn_delete = QtWidgets.QPushButton("Delete selected")
        self.btn_open = QtWidgets.QPushButton("Open last download folder")
        self.btn_open.setEnabled(False)
        for w in (QtWidgets.QLabel("Folder:"), self.dir_edit, self.btn_refresh,
                  self.btn_download, self.btn_delete, self.btn_open):
            bar.addWidget(w)
        bar.setStretch(1, 1)
        root.addLayout(bar)
        self.table = QtWidgets.QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["File", "Size", "Captured"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(True)
        root.addWidget(self.table, 1)
        self.summary = QtWidgets.QLabel("")
        root.addWidget(self.summary)

        self._last_dir = ""
        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_download.clicked.connect(self.download_selected)
        self.btn_delete.clicked.connect(self.delete_selected)
        self.btn_open.clicked.connect(lambda: QtGui.QDesktopServices.openUrl(
            QtCore.QUrl.fromLocalFile(self._last_dir)))

    # ----------------------------------------------------------------- data
    def selected_names(self) -> list[str]:
        out = []
        for idx in self.table.selectionModel().selectedRows():
            it = self.table.item(idx.row(), 0)
            if it:
                out.append(it.text())
        return out

    def refresh(self):
        self.directory = self.dir_edit.text().strip() or remote_cmds.HANDSHAKE_DIR

        def do():
            r = self.ssh.run(remote_cmds.list_handshakes(self.directory), timeout_sec=20)
            if r.exit_status != 0 and not r.stdout:
                raise RuntimeError(r.stderr.strip() or "cannot list handshakes")
            return remote_cmds.parse_handshakes(r.stdout)

        def done(rows, err):
            if err:
                self.log.emit(f"[ERROR] handshakes: {err}")
                return
            self.show_rows(rows)

        run_in_thread(self, do, done)

    def show_rows(self, rows: list[dict]):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for i, r in enumerate(rows):
            self.table.insertRow(i)
            self.table.setItem(i, 0, QtWidgets.QTableWidgetItem(r["name"]))
            sz = _NumItem(human_size(r["size"]))
            sz.setData(QtCore.Qt.ItemDataRole.UserRole, r["size"])
            self.table.setItem(i, 1, sz)
            when = _NumItem(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["mtime"])))
            when.setData(QtCore.Qt.ItemDataRole.UserRole, r["mtime"])
            self.table.setItem(i, 2, when)
        self.table.setSortingEnabled(True)
        total = sum(r["size"] for r in rows)
        self.summary.setText(f"{len(rows)} capture(s), {human_size(total)}")

    # -------------------------------------------------------------- actions
    def download_selected(self, dest: str | None = None):
        names = self.selected_names()
        if not names:
            QtWidgets.QMessageBox.information(self, "Download", "Select capture(s) first.")
            return
        if not dest:
            dest = QtWidgets.QFileDialog.getExistingDirectory(self, "Download to", os.path.expanduser("~"))
        if not dest:
            return
        directory = self.directory

        def do():
            stage = f"/tmp/qpwn-hs-{uuid.uuid4().hex}"
            r = self.ssh.run(remote_cmds.stage_for_download(names, stage, directory), timeout_sec=60)
            if r.exit_status != 0:
                raise RuntimeError(r.stderr.strip() or "staging failed")
            try:
                sftp = self.ssh.sftp()
                for n in names:
                    sftp.get(posixpath.join(stage, n), os.path.join(dest, n))
            finally:
                self.ssh.run(f"rm -rf {remote_cmds.q(stage)}", timeout_sec=20)
            return len(names)

        def done(res, err):
            if err:
                self.log.emit(f"[ERROR] handshake download: {err}")
                QtWidgets.QMessageBox.critical(self, "Download failed", str(err))
                return
            self._last_dir = dest
            self.btn_open.setEnabled(True)
            self.log.emit(f"Downloaded {res} capture(s) to {dest}")

        run_in_thread(self, do, done)

    def delete_selected(self):
        names = self.selected_names()
        if not names:
            QtWidgets.QMessageBox.information(self, "Delete", "Select capture(s) first.")
            return
        if QtWidgets.QMessageBox.question(
                self, "Delete captures",
                f"Permanently delete {len(names)} capture(s) from the device?\n\n  "
                + "\n  ".join(names[:15]) + ("\n  …" if len(names) > 15 else "")
        ) != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        directory = self.directory

        def do():
            r = self.ssh.run(remote_cmds.delete_handshakes(names, directory), timeout_sec=30)
            if r.exit_status != 0:
                raise RuntimeError(r.stderr.strip() or "delete failed")
            return len(names)

        def done(res, err):
            if err:
                self.log.emit(f"[ERROR] handshake delete: {err}")
                QtWidgets.QMessageBox.critical(self, "Delete failed", str(err))
                return
            self.log.emit(f"Deleted {res} capture(s).")
            self.refresh()

        run_in_thread(self, do, done)
