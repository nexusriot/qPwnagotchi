from __future__ import annotations

import os
import posixpath
import stat
from dataclasses import dataclass
from typing import Optional, Tuple, List

from PyQt6 import QtCore, QtWidgets


@dataclass
class ItemRow:
    name: str
    typ: str   # "dir" or "file"
    size: str  # "" for dirs


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


class FileManagerWidget(QtWidgets.QWidget):
    log = QtCore.pyqtSignal(str)

    def __init__(self, ssh_client, parent=None):
        super().__init__(parent)
        self.ssh = ssh_client

        self.local_dir = os.path.expanduser("~")
        self.remote_dir = "/home/pi"

        self._build()

    def _build(self):
        root = QtWidgets.QVBoxLayout(self)

        # Toolbar
        bar = QtWidgets.QHBoxLayout()
        self.btn_refresh = QtWidgets.QPushButton("Refresh")
        self.btn_upload = QtWidgets.QPushButton("Upload →")
        self.btn_download = QtWidgets.QPushButton("← Download")
        self.btn_delete = QtWidgets.QPushButton("Delete")
        self.btn_mkdir = QtWidgets.QPushButton("Mkdir")
        self.btn_rename = QtWidgets.QPushButton("Rename")

        for b in [self.btn_refresh, self.btn_upload, self.btn_download,
                  self.btn_delete, self.btn_mkdir, self.btn_rename]:
            bar.addWidget(b)
        bar.addStretch(1)
        root.addLayout(bar)

        split = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)
        root.addWidget(split, 1)

        # Local (table listing)
        local_box = QtWidgets.QGroupBox("Local")
        local_l = QtWidgets.QVBoxLayout(local_box)

        self.local_path_label = QtWidgets.QLabel(self.local_dir)
        local_l.addWidget(self.local_path_label)

        self.local_view = QtWidgets.QTableWidget(0, 3)
        self.local_view.setHorizontalHeaderLabels(["Name", "Type", "Size"])
        self.local_view.horizontalHeader().setStretchLastSection(True)
        self.local_view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.local_view.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.local_view.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.local_view.cellDoubleClicked.connect(self._local_double_click)
        local_l.addWidget(self.local_view, 1)

        split.addWidget(local_box)

        # Remote (SFTP)
        remote_box = QtWidgets.QGroupBox("Remote (SFTP)")
        remote_l = QtWidgets.QVBoxLayout(remote_box)

        self.remote_path_label = QtWidgets.QLabel(self.remote_dir)
        remote_l.addWidget(self.remote_path_label)

        self.remote_view = QtWidgets.QTableWidget(0, 3)
        self.remote_view.setHorizontalHeaderLabels(["Name", "Type", "Size"])
        self.remote_view.horizontalHeader().setStretchLastSection(True)
        self.remote_view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.remote_view.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.remote_view.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.remote_view.cellDoubleClicked.connect(self._remote_double_click)
        remote_l.addWidget(self.remote_view, 1)

        split.addWidget(remote_box)

        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 2)

        # Progress
        p = QtWidgets.QHBoxLayout()
        self.transfer_label = QtWidgets.QLabel("Idle")
        self.transfer_bar = QtWidgets.QProgressBar()
        self.transfer_bar.setRange(0, 100)
        self.transfer_bar.setValue(0)
        p.addWidget(self.transfer_label)
        p.addWidget(self.transfer_bar, 1)
        root.addLayout(p)

        # Wiring
        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_upload.clicked.connect(self.upload_selected)
        self.btn_download.clicked.connect(self.download_selected)
        self.btn_delete.clicked.connect(self.delete_selected_remote)
        self.btn_mkdir.clicked.connect(self.mkdir_remote)
        self.btn_rename.clicked.connect(self.rename_selected_remote)

        # Initial local listing
        self._local_refresh()

    def _local_list_dir(self, path: str) -> list[ItemRow]:
        rows: list[ItemRow] = []
        if os.path.abspath(path) != os.path.abspath(os.path.sep):
            rows.append(ItemRow("..", "dir", ""))

        try:
            with os.scandir(path) as it:
                for e in it:
                    try:
                        is_dir = e.is_dir(follow_symlinks=False)
                    except Exception:
                        is_dir = False
                    typ = "dir" if is_dir else "file"
                    size = ""
                    if not is_dir:
                        try:
                            size = str(e.stat(follow_symlinks=False).st_size)
                        except Exception:
                            size = ""
                    rows.append(ItemRow(e.name, typ, size))
        except Exception:
            pass

        rows.sort(key=lambda x: (x.typ != "dir", x.name.lower()))
        return rows

    def _local_refresh(self):
        self.local_path_label.setText(self.local_dir)
        rows = self._local_list_dir(self.local_dir)

        self.local_view.setRowCount(0)
        for i, it in enumerate(rows):
            self.local_view.insertRow(i)
            self.local_view.setItem(i, 0, QtWidgets.QTableWidgetItem(it.name))
            self.local_view.setItem(i, 1, QtWidgets.QTableWidgetItem(it.typ))
            self.local_view.setItem(i, 2, QtWidgets.QTableWidgetItem(it.size))

    def _local_double_click(self, row: int, col: int):
        name_item = self.local_view.item(row, 0)
        typ_item = self.local_view.item(row, 1)
        if not name_item or not typ_item:
            return

        name = name_item.text()
        typ = typ_item.text()
        if typ != "dir":
            return

        if name == "..":
            parent = os.path.dirname(self.local_dir.rstrip(os.sep)) or os.sep
            self.local_dir = parent
        else:
            self.local_dir = os.path.join(self.local_dir, name)

        self._local_refresh()

    def _selected_local(self) -> Optional[Tuple[str, str]]:
        r = self.local_view.currentRow()
        if r < 0:
            return None
        name_item = self.local_view.item(r, 0)
        typ_item = self.local_view.item(r, 1)
        if not name_item or not typ_item:
            return None
        name = name_item.text()
        typ = typ_item.text()
        if name == "..":
            return None
        return os.path.join(self.local_dir, name), typ

    def _selected_remote(self) -> Optional[tuple[str, str]]:
        r = self.remote_view.currentRow()
        if r < 0:
            return None
        name_item = self.remote_view.item(r, 0)
        typ_item = self.remote_view.item(r, 1)
        if not name_item or not typ_item:
            return None
        return name_item.text(), typ_item.text()

    def refresh(self):
        # always refresh local
        self._local_refresh()

        if not getattr(self.ssh, "connected", False):
            return

        def do():
            sftp = self.ssh.sftp()
            rows: list[ItemRow] = []
            if self.remote_dir != "/":
                rows.append(ItemRow("..", "dir", ""))

            for a in sftp.listdir_attr(self.remote_dir):
                is_dir = stat.S_ISDIR(a.st_mode)
                typ = "dir" if is_dir else "file"
                size = "" if is_dir else str(int(getattr(a, "st_size", 0)))
                rows.append(ItemRow(a.filename, typ, size))

            rows.sort(key=lambda x: (x.typ != "dir", x.name.lower()))
            return rows

        def done(res, err):
            if err:
                self.log.emit(f"[ERROR] Files refresh: {err}")
                return
            self.remote_path_label.setText(self.remote_dir)
            self.remote_view.setRowCount(0)
            for i, it in enumerate(res):
                self.remote_view.insertRow(i)
                self.remote_view.setItem(i, 0, QtWidgets.QTableWidgetItem(it.name))
                self.remote_view.setItem(i, 1, QtWidgets.QTableWidgetItem(it.typ))
                self.remote_view.setItem(i, 2, QtWidgets.QTableWidgetItem(it.size))
            self.log.emit("Files refreshed.")

        run_in_thread(self, do, done)

    def _remote_double_click(self, row: int, col: int):
        name_item = self.remote_view.item(row, 0)
        typ_item = self.remote_view.item(row, 1)
        if not name_item or not typ_item:
            return
        name = name_item.text()
        typ = typ_item.text()

        if name == "..":
            self.remote_dir = posixpath.dirname(self.remote_dir.rstrip("/")) or "/"
            self.refresh()
            return

        if typ == "dir":
            self.remote_dir = posixpath.join(self.remote_dir, name)
            self.refresh()

    def _ui_set_progress(self, value: int):
        QtCore.QMetaObject.invokeMethod(
            self.transfer_bar,
            "setValue",
            QtCore.Qt.ConnectionType.QueuedConnection,
            QtCore.Q_ARG(int, int(value)),
        )

    def _ui_set_label(self, text: str):
        QtCore.QMetaObject.invokeMethod(
            self.transfer_label,
            "setText",
            QtCore.Qt.ConnectionType.QueuedConnection,
            QtCore.Q_ARG(str, text),
        )

    def _sftp_mkdir_p(self, sftp, path: str):
        # posix mkdir -p
        parts = []
        p = path
        while p not in ("", "/"):
            parts.append(p)
            p = posixpath.dirname(p)
        for d in reversed(parts):
            try:
                sftp.stat(d)
            except Exception:
                try:
                    sftp.mkdir(d)
                except Exception:
                    pass

    def _local_total_bytes(self, src: str) -> int:
        total = 0
        for root, dirs, files in os.walk(src):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    total += os.path.getsize(fp)
                except Exception:
                    pass
        return total

    def _remote_total_bytes(self, sftp, src: str) -> int:
        total = 0

        def walk(p: str):
            nonlocal total
            for a in sftp.listdir_attr(p):
                rp = posixpath.join(p, a.filename)
                if stat.S_ISDIR(a.st_mode):
                    walk(rp)
                else:
                    try:
                        total += int(getattr(a, "st_size", 0) or 0)
                    except Exception:
                        pass

        walk(src)
        return total

    def _download_folder(self, sftp, remote_src: str, local_dst: str):
        os.makedirs(local_dst, exist_ok=True)
        for a in sftp.listdir_attr(remote_src):
            rpath = posixpath.join(remote_src, a.filename)
            lpath = os.path.join(local_dst, a.filename)
            if stat.S_ISDIR(a.st_mode):
                self._download_folder(sftp, rpath, lpath)
            else:
                sftp.get(rpath, lpath)

    def _upload_folder(self, sftp, local_src: str, remote_dst: str):
        self._sftp_mkdir_p(sftp, remote_dst)
        for root, dirs, files in os.walk(local_src):
            rel = os.path.relpath(root, local_src)
            rdir = remote_dst if rel == "." else posixpath.join(remote_dst, rel.replace(os.sep, "/"))
            self._sftp_mkdir_p(sftp, rdir)

            for d in dirs:
                self._sftp_mkdir_p(sftp, posixpath.join(rdir, d))

            for f in files:
                lp = os.path.join(root, f)
                rp = posixpath.join(rdir, f)
                sftp.put(lp, rp)

    def _start_transfer_any(self, direction: str, local_path: str, remote_path: str, is_dir: bool):
        if not getattr(self.ssh, "connected", False):
            return

        self.transfer_bar.setRange(0, 100)
        self.transfer_bar.setValue(0)

        base = os.path.basename(local_path if direction == "upload" else remote_path)
        self.transfer_label.setText(f"{direction}: {base}")

        def do():
            sftp = self.ssh.sftp()

            # try “overall bytes” progress; if it fails -> fallback to “file count”
            overall_total = 0
            try:
                if is_dir:
                    if direction == "upload":
                        overall_total = self._local_total_bytes(local_path)
                    else:
                        overall_total = self._remote_total_bytes(sftp, remote_path)
                else:
                    if direction == "upload":
                        overall_total = os.path.getsize(local_path)
                    else:
                        overall_total = int(sftp.stat(remote_path).st_size)
            except Exception:
                overall_total = 0

            overall_done = 0

            def report(delta: int, current: str):
                nonlocal overall_done
                overall_done += max(0, delta)
                if overall_total > 0:
                    pct = int(overall_done * 100 / overall_total)
                    pct = 100 if pct > 100 else pct
                    self._ui_set_label(f"{direction}: {current}")
                    self._ui_set_progress(pct)
                else:
                    # unknown total => indeterminate-ish progress by “pulse”
                    self._ui_set_label(f"{direction}: {current}")
                    # move a bit but clamp
                    cur = self.transfer_bar.value()
                    self._ui_set_progress(100 if cur >= 95 else cur + 5)

            if not is_dir:
                # single file with callback
                def cb(done: int, total: int):
                    if total > 0:
                        pct = int(done * 100 / total)
                        self._ui_set_label(f"{direction}: {os.path.basename(remote_path)}")
                        self._ui_set_progress(pct)

                if direction == "download":
                    sftp.get(remote_path, local_path, callback=cb)
                else:
                    sftp.put(local_path, remote_path, callback=cb)
                return True

            # folder: walk files and update “overall bytes” by file sizes
            if direction == "download":
                os.makedirs(local_path, exist_ok=True)

                def walk_download(rsrc: str, ldst: str):
                    nonlocal overall_done
                    os.makedirs(ldst, exist_ok=True)
                    for a in sftp.listdir_attr(rsrc):
                        rp = posixpath.join(rsrc, a.filename)
                        lp = os.path.join(ldst, a.filename)
                        if stat.S_ISDIR(a.st_mode):
                            walk_download(rp, lp)
                        else:
                            report(0, f"{a.filename}")
                            sftp.get(rp, lp)
                            try:
                                report(int(getattr(a, "st_size", 0) or 0), f"{a.filename}")
                            except Exception:
                                pass

                walk_download(remote_path, local_path)

            else:
                # upload
                def walk_upload(lsrc: str, rdst: str):
                    nonlocal overall_done
                    self._sftp_mkdir_p(sftp, rdst)
                    for root, dirs, files in os.walk(lsrc):
                        rel = os.path.relpath(root, lsrc)
                        rdir = rdst if rel == "." else posixpath.join(rdst, rel.replace(os.sep, "/"))
                        self._sftp_mkdir_p(sftp, rdir)

                        for d in dirs:
                            self._sftp_mkdir_p(sftp, posixpath.join(rdir, d))

                        for f in files:
                            lp = os.path.join(root, f)
                            rp = posixpath.join(rdir, f)
                            report(0, f)
                            sftp.put(lp, rp)
                            try:
                                report(os.path.getsize(lp), f)
                            except Exception:
                                pass

                walk_upload(local_path, remote_path)

            self._ui_set_progress(100)
            return True

        def done(res, err):
            if err:
                self.transfer_label.setText(f"Error: {err}")
                self.log.emit(f"[ERROR] Transfer: {err}")
                QtWidgets.QMessageBox.critical(self, "Transfer failed", str(err))
                return
            self.transfer_bar.setValue(100)
            self.transfer_label.setText("Done.")
            self.log.emit("Transfer complete.")
            self.refresh()

        run_in_thread(self, do, done)

    def upload_selected(self):
        sel = self._selected_local()
        if not sel:
            QtWidgets.QMessageBox.information(self, "Upload", "Select a local file or folder.")
            return
        lp, typ = sel
        name = os.path.basename(lp)
        rp = posixpath.join(self.remote_dir, name)
        self._start_transfer_any("upload", lp, rp, is_dir=(typ == "dir"))

    def download_selected(self):
        sel = self._selected_remote()
        if not sel:
            return
        name, typ = sel
        if name == "..":
            return
        rp = posixpath.join(self.remote_dir, name)
        lp = os.path.join(self.local_dir, name)
        self._start_transfer_any("download", lp, rp, is_dir=(typ == "dir"))

    def delete_selected_remote(self):
        sel = self._selected_remote()
        if not sel:
            return
        name, typ = sel
        if name == "..":
            return
        path = posixpath.join(self.remote_dir, name)

        if QtWidgets.QMessageBox.question(self, "Delete", f"Delete remote {typ}: {path}?") != QtWidgets.QMessageBox.StandardButton.Yes:
            return

        def do():
            sftp = self.ssh.sftp()
            if typ == "dir":
                sftp.rmdir(path)
            else:
                sftp.remove(path)
            return True

        def done(res, err):
            if err:
                self.log.emit(f"[ERROR] Delete: {err}")
                QtWidgets.QMessageBox.critical(self, "Delete failed", str(err))
                return
            self.log.emit("Deleted.")
            self.refresh()

        run_in_thread(self, do, done)

    def mkdir_remote(self):
        name, ok = QtWidgets.QInputDialog.getText(self, "Mkdir", "Remote folder name:")
        if not ok or not name.strip():
            return
        path = posixpath.join(self.remote_dir, name.strip())

        def do():
            self.ssh.sftp().mkdir(path)
            return True

        def done(res, err):
            if err:
                self.log.emit(f"[ERROR] Mkdir: {err}")
                QtWidgets.QMessageBox.critical(self, "Mkdir failed", str(err))
                return
            self.log.emit("Folder created.")
            self.refresh()

        run_in_thread(self, do, done)

    def rename_selected_remote(self):
        sel = self._selected_remote()
        if not sel:
            return
        name, typ = sel
        if name == "..":
            return

        newname, ok = QtWidgets.QInputDialog.getText(self, "Rename", f"New name for {name}:")
        if not ok or not newname.strip():
            return

        oldp = posixpath.join(self.remote_dir, name)
        newp = posixpath.join(self.remote_dir, newname.strip())

        def do():
            self.ssh.sftp().rename(oldp, newp)
            return True

        def done(res, err):
            if err:
                self.log.emit(f"[ERROR] Rename: {err}")
                QtWidgets.QMessageBox.critical(self, "Rename failed", str(err))
                return
            self.log.emit("Renamed.")
            self.refresh()

        run_in_thread(self, do, done)
