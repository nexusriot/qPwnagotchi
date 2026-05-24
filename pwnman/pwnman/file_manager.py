from __future__ import annotations

import json
import os
import posixpath
import shutil
import stat
from dataclasses import dataclass
from typing import Optional

from PyQt6 import QtCore, QtGui, QtWidgets

from pwnman.pwnman.async_utils import run_in_thread

ITEMS_MIME = "application/x-pwnman-items"
MAX_EDIT_BYTES = 2 * 1024 * 1024  # refuse to load huge files into the editor


@dataclass
class ItemRow:
    name: str
    typ: str   # "dir" or "file"
    size: str  # "" for dirs


def encode_drag_payload(side: str, names: list[str]) -> bytes:
    return json.dumps({"side": side, "names": list(names)}).encode("utf-8")


def decode_drag_payload(data: bytes) -> tuple[str, list[str]]:
    try:
        d = json.loads(bytes(data).decode("utf-8"))
        side = d.get("side", "")
        names = [str(n) for n in d.get("names", []) if isinstance(n, str)]
        return (side if side in ("local", "remote") else ""), names
    except (ValueError, AttributeError, TypeError):
        return "", []


def looks_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def sftp_rmtree(sftp, path: str) -> None:
    """Recursively delete a remote path. Fixes rmdir-fails-on-non-empty."""
    try:
        st = sftp.lstat(path)
    except (FileNotFoundError, OSError):
        return
    if stat.S_ISDIR(st.st_mode):
        for a in sftp.listdir_attr(path):
            sftp_rmtree(sftp, posixpath.join(path, a.filename))
        sftp.rmdir(path)
    else:
        sftp.remove(path)


class DnDTable(QtWidgets.QTableWidget):
    """A table that drags its selected rows and accepts drops.

    Emits itemsDropped(target_side, payload) where payload is either
    ("internal", source_side, [names]) or ("external", [os_paths]).
    """

    itemsDropped = QtCore.pyqtSignal(str, object)

    def __init__(self, side: str, rows: int, cols: int, parent=None):
        super().__init__(rows, cols, parent)
        self.side = side
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setDragDropMode(
            QtWidgets.QAbstractItemView.DragDropMode.DragDrop)
        self.setDefaultDropAction(QtCore.Qt.DropAction.CopyAction)

    def _selected_names(self) -> list[str]:
        names = []
        for idx in self.selectionModel().selectedRows():
            it = self.item(idx.row(), 0)
            if it and it.text() != "..":
                names.append(it.text())
        return names

    def startDrag(self, supportedActions):
        names = self._selected_names()
        if not names:
            return
        md = QtCore.QMimeData()
        md.setData(ITEMS_MIME,
                   QtCore.QByteArray(encode_drag_payload(self.side, names)))
        drag = QtGui.QDrag(self)
        drag.setMimeData(md)
        drag.exec(QtCore.Qt.DropAction.CopyAction)

    def _acceptable(self, md) -> bool:
        if md.hasFormat(ITEMS_MIME):
            side, _ = decode_drag_payload(bytes(md.data(ITEMS_MIME)))
            return bool(side) and side != self.side
        return md.hasUrls()

    def dragEnterEvent(self, e):
        e.acceptProposedAction() if self._acceptable(e.mimeData()) else e.ignore()

    def dragMoveEvent(self, e):
        e.acceptProposedAction() if self._acceptable(e.mimeData()) else e.ignore()

    def dropEvent(self, e):
        md = e.mimeData()
        if md.hasFormat(ITEMS_MIME):
            side, names = decode_drag_payload(bytes(md.data(ITEMS_MIME)))
            if side and side != self.side and names:
                self.itemsDropped.emit(self.side, ("internal", side, names))
                e.acceptProposedAction()
                return
        if md.hasUrls():
            paths = [u.toLocalFile() for u in md.urls() if u.isLocalFile()]
            paths = [p for p in paths if p]
            if paths:
                self.itemsDropped.emit(self.side, ("external", paths))
                e.acceptProposedAction()
                return
        e.ignore()


class RemoteEditDialog(QtWidgets.QDialog):
    def __init__(self, title: str, text: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(820, 600)
        lay = QtWidgets.QVBoxLayout(self)
        self.editor = QtWidgets.QPlainTextEdit()
        self.editor.setPlainText(text)
        self.editor.setFont(QtGui.QFontDatabase.systemFont(
            QtGui.QFontDatabase.SystemFont.FixedFont))
        lay.addWidget(self.editor, 1)
        bb = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Save
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def text(self) -> str:
        return self.editor.toPlainText()


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

        bar = QtWidgets.QHBoxLayout()
        self.btn_refresh = QtWidgets.QPushButton("Refresh")
        self.btn_upload = QtWidgets.QPushButton("Upload →")
        self.btn_download = QtWidgets.QPushButton("← Download")
        self.btn_edit = QtWidgets.QPushButton("Edit remote")
        self.btn_delete = QtWidgets.QPushButton("Delete")
        self.btn_mkdir = QtWidgets.QPushButton("Mkdir")
        self.btn_rename = QtWidgets.QPushButton("Rename")

        for b in [self.btn_refresh, self.btn_upload, self.btn_download,
                  self.btn_edit, self.btn_delete, self.btn_mkdir,
                  self.btn_rename]:
            bar.addWidget(b)
        bar.addStretch(1)
        root.addLayout(bar)

        split = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)
        root.addWidget(split, 1)

        local_box = QtWidgets.QGroupBox("Local")
        local_l = QtWidgets.QVBoxLayout(local_box)
        self.local_path_label = QtWidgets.QLabel(self.local_dir)
        local_l.addWidget(self.local_path_label)
        self.local_view = self._make_table("local")
        self.local_view.cellDoubleClicked.connect(self._local_double_click)
        local_l.addWidget(self.local_view, 1)
        split.addWidget(local_box)

        remote_box = QtWidgets.QGroupBox("Remote (SFTP)")
        remote_l = QtWidgets.QVBoxLayout(remote_box)
        self.remote_path_label = QtWidgets.QLabel(self.remote_dir)
        remote_l.addWidget(self.remote_path_label)
        self.remote_view = self._make_table("remote")
        self.remote_view.cellDoubleClicked.connect(self._remote_double_click)
        remote_l.addWidget(self.remote_view, 1)
        split.addWidget(remote_box)

        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 2)

        p = QtWidgets.QHBoxLayout()
        self.transfer_label = QtWidgets.QLabel("Idle")
        self.transfer_bar = QtWidgets.QProgressBar()
        self.transfer_bar.setRange(0, 100)
        self.transfer_bar.setValue(0)
        p.addWidget(self.transfer_label)
        p.addWidget(self.transfer_bar, 1)
        root.addLayout(p)

        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_upload.clicked.connect(self.upload_selected)
        self.btn_download.clicked.connect(self.download_selected)
        self.btn_edit.clicked.connect(self.edit_selected_remote)
        self.btn_delete.clicked.connect(self.delete_selected_remote)
        self.btn_mkdir.clicked.connect(self.mkdir_remote)
        self.btn_rename.clicked.connect(self.rename_selected_remote)

        self._local_refresh()

    def _make_table(self, side: str) -> DnDTable:
        t = DnDTable(side, 0, 3)
        t.setHorizontalHeaderLabels(["Name", "Type", "Size"])
        t.horizontalHeader().setStretchLastSection(True)
        t.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        t.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        t.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        t.itemsDropped.connect(self._on_drop)
        return t

    def _local_list_dir(self, path: str) -> list[ItemRow]:
        rows: list[ItemRow] = []
        if os.path.abspath(path) != os.path.abspath(os.path.sep):
            rows.append(ItemRow("..", "dir", ""))
        try:
            with os.scandir(path) as it:
                for e in it:
                    try:
                        is_dir = e.is_dir(follow_symlinks=False)
                    except OSError:
                        is_dir = False
                    typ = "dir" if is_dir else "file"
                    size = ""
                    if not is_dir:
                        try:
                            size = str(e.stat(follow_symlinks=False).st_size)
                        except OSError:
                            size = ""
                    rows.append(ItemRow(e.name, typ, size))
        except OSError:
            pass
        rows.sort(key=lambda x: (x.typ != "dir", x.name.lower()))
        return rows

    def _fill(self, table: QtWidgets.QTableWidget, rows: list[ItemRow]):
        table.setRowCount(0)
        for i, it in enumerate(rows):
            table.insertRow(i)
            table.setItem(i, 0, QtWidgets.QTableWidgetItem(it.name))
            table.setItem(i, 1, QtWidgets.QTableWidgetItem(it.typ))
            table.setItem(i, 2, QtWidgets.QTableWidgetItem(it.size))

    def _local_refresh(self):
        self.local_path_label.setText(self.local_dir)
        self._fill(self.local_view, self._local_list_dir(self.local_dir))

    def _local_double_click(self, row: int, col: int):
        name_item = self.local_view.item(row, 0)
        typ_item = self.local_view.item(row, 1)
        if not name_item or not typ_item or typ_item.text() != "dir":
            return
        name = name_item.text()
        if name == "..":
            self.local_dir = os.path.dirname(
                self.local_dir.rstrip(os.sep)) or os.sep
        else:
            self.local_dir = os.path.join(self.local_dir, name)
        self._local_refresh()

    def refresh(self):
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
            self._fill(self.remote_view, res)
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
            self.remote_dir = posixpath.dirname(
                self.remote_dir.rstrip("/")) or "/"
            self.refresh()
            return
        if typ == "dir":
            self.remote_dir = posixpath.join(self.remote_dir, name)
            self.refresh()

    def _selected_local_many(self) -> list[tuple[str, str]]:
        out = []
        for idx in self.local_view.selectionModel().selectedRows():
            r = idx.row()
            n = self.local_view.item(r, 0)
            t = self.local_view.item(r, 1)
            if n and t and n.text() != "..":
                out.append((os.path.join(self.local_dir, n.text()), t.text()))
        return out

    def _selected_remote_many(self) -> list[tuple[str, str]]:
        out = []
        for idx in self.remote_view.selectionModel().selectedRows():
            r = idx.row()
            n = self.remote_view.item(r, 0)
            t = self.remote_view.item(r, 1)
            if n and t and n.text() != "..":
                out.append((n.text(), t.text()))
        return out

    def _remote_type_of(self, name: str) -> str:
        for r in range(self.remote_view.rowCount()):
            n = self.remote_view.item(r, 0)
            if n and n.text() == name:
                t = self.remote_view.item(r, 1)
                return t.text() if t else "file"
        return "file"

    def _ui_set_progress(self, value: int):
        QtCore.QMetaObject.invokeMethod(
            self.transfer_bar, "setValue",
            QtCore.Qt.ConnectionType.QueuedConnection,
            QtCore.Q_ARG(int, int(value)))

    def _ui_set_label(self, text: str):
        QtCore.QMetaObject.invokeMethod(
            self.transfer_label, "setText",
            QtCore.Qt.ConnectionType.QueuedConnection,
            QtCore.Q_ARG(str, text))

    def _sftp_mkdir_p(self, sftp, path: str):
        parts = []
        p = path
        while p not in ("", "/"):
            parts.append(p)
            p = posixpath.dirname(p)
        for d in reversed(parts):
            try:
                sftp.stat(d)
            except OSError:
                try:
                    sftp.mkdir(d)
                except OSError:
                    pass

    def _local_total_bytes(self, src: str) -> int:
        total = 0
        for root, _dirs, files in os.walk(src):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
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
                    except (TypeError, ValueError):
                        pass

        walk(src)
        return total

    def _start_batch_transfer(self, direction: str,
                              entries: list[tuple[str, str, bool]]):
        """entries: list of (local_path, remote_path, is_dir)."""
        if not getattr(self.ssh, "connected", False) or not entries:
            return

        self.transfer_bar.setRange(0, 100)
        self.transfer_bar.setValue(0)
        self.transfer_label.setText(f"{direction}: {len(entries)} item(s)")

        def do():
            sftp = self.ssh.sftp()

            overall_total = 0
            for lp, rp, is_dir in entries:
                try:
                    if is_dir:
                        overall_total += (
                            self._local_total_bytes(lp)
                            if direction == "upload"
                            else self._remote_total_bytes(sftp, rp))
                    else:
                        overall_total += (
                            os.path.getsize(lp) if direction == "upload"
                            else int(sftp.stat(rp).st_size))
                except OSError:
                    pass

            overall_done = 0

            def report(delta: int, current: str):
                nonlocal overall_done
                overall_done += max(0, delta)
                self._ui_set_label(f"{direction}: {current}")
                if overall_total > 0:
                    pct = min(100, int(overall_done * 100 / overall_total))
                    self._ui_set_progress(pct)
                else:
                    cur = self.transfer_bar.value()
                    self._ui_set_progress(100 if cur >= 95 else cur + 5)

            for lp, rp, is_dir in entries:
                if not is_dir:
                    base = overall_done

                    def cb(d, t, _b=base, _n=os.path.basename(rp)):
                        if overall_total > 0:
                            pct = min(100, int((_b + d) * 100 / overall_total))
                            self._ui_set_label(f"{direction}: {_n}")
                            self._ui_set_progress(pct)

                    if direction == "download":
                        os.makedirs(os.path.dirname(lp) or ".", exist_ok=True)
                        sftp.get(rp, lp, callback=cb)
                        try:
                            report(int(sftp.stat(rp).st_size), os.path.basename(rp))
                        except OSError:
                            report(0, os.path.basename(rp))
                    else:
                        self._sftp_mkdir_p(sftp, posixpath.dirname(rp))
                        sftp.put(lp, rp, callback=cb)
                        try:
                            report(os.path.getsize(lp), os.path.basename(lp))
                        except OSError:
                            report(0, os.path.basename(lp))
                    continue

                if direction == "download":
                    def walk_dl(rsrc, ldst):
                        os.makedirs(ldst, exist_ok=True)
                        for a in sftp.listdir_attr(rsrc):
                            rp2 = posixpath.join(rsrc, a.filename)
                            lp2 = os.path.join(ldst, a.filename)
                            if stat.S_ISDIR(a.st_mode):
                                walk_dl(rp2, lp2)
                            else:
                                report(0, a.filename)
                                sftp.get(rp2, lp2)
                                report(int(getattr(a, "st_size", 0) or 0),
                                       a.filename)
                    walk_dl(rp, lp)
                else:
                    def walk_ul(lsrc, rdst):
                        self._sftp_mkdir_p(sftp, rdst)
                        for root, dirs, files in os.walk(lsrc):
                            rel = os.path.relpath(root, lsrc)
                            rdir = (rdst if rel == "."
                                    else posixpath.join(
                                        rdst, rel.replace(os.sep, "/")))
                            self._sftp_mkdir_p(sftp, rdir)
                            for d in dirs:
                                self._sftp_mkdir_p(
                                    sftp, posixpath.join(rdir, d))
                            for f in files:
                                report(0, f)
                                sftp.put(os.path.join(root, f),
                                         posixpath.join(rdir, f))
                                try:
                                    report(os.path.getsize(
                                        os.path.join(root, f)), f)
                                except OSError:
                                    pass
                    walk_ul(lp, rp)

            self._ui_set_progress(100)
            return True

        def done(res, err):
            if err:
                self.transfer_label.setText(f"Error: {err}")
                self.log.emit(f"[ERROR] Transfer: {err}")
                QtWidgets.QMessageBox.critical(
                    self, "Transfer failed", str(err))
                return
            self.transfer_bar.setValue(100)
            self.transfer_label.setText("Done.")
            self.log.emit("Transfer complete.")
            self.refresh()

        run_in_thread(self, do, done)

    def upload_selected(self):
        sel = self._selected_local_many()
        if not sel:
            QtWidgets.QMessageBox.information(
                self, "Upload", "Select local file(s) or folder(s).")
            return
        entries = [
            (lp, posixpath.join(self.remote_dir, os.path.basename(lp)),
             typ == "dir")
            for lp, typ in sel
        ]
        self._start_batch_transfer("upload", entries)

    def download_selected(self):
        sel = self._selected_remote_many()
        if not sel:
            QtWidgets.QMessageBox.information(
                self, "Download", "Select remote file(s) or folder(s).")
            return
        entries = [
            (os.path.join(self.local_dir, name),
             posixpath.join(self.remote_dir, name), typ == "dir")
            for name, typ in sel
        ]
        self._start_batch_transfer("download", entries)

    def _on_drop(self, target_side: str, payload):
        kind = payload[0]
        if kind == "internal":
            _, source_side, names = payload
            if source_side == "local" and target_side == "remote":
                entries = [
                    (os.path.join(self.local_dir, n),
                     posixpath.join(self.remote_dir, n),
                     os.path.isdir(os.path.join(self.local_dir, n)))
                    for n in names
                ]
                self._start_batch_transfer("upload", entries)
            elif source_side == "remote" and target_side == "local":
                entries = [
                    (os.path.join(self.local_dir, n),
                     posixpath.join(self.remote_dir, n),
                     self._remote_type_of(n) == "dir")
                    for n in names
                ]
                self._start_batch_transfer("download", entries)
            return

        # external OS-file drop
        paths = payload[1]
        if target_side == "remote":
            entries = [
                (p, posixpath.join(self.remote_dir, os.path.basename(
                    p.rstrip("/\\"))), os.path.isdir(p))
                for p in paths
            ]
            self._start_batch_transfer("upload", entries)
        else:
            copied = 0
            for p in paths:
                try:
                    dst = os.path.join(
                        self.local_dir, os.path.basename(p.rstrip("/\\")))
                    if os.path.isdir(p):
                        shutil.copytree(p, dst, dirs_exist_ok=True)
                    else:
                        shutil.copy2(p, dst)
                    copied += 1
                except OSError as e:
                    self.log.emit(f"[ERROR] Copy {p}: {e}")
            if copied:
                self.log.emit(f"Copied {copied} item(s) into {self.local_dir}")
                self._local_refresh()

    def delete_selected_remote(self):
        sel = self._selected_remote_many()
        if not sel:
            QtWidgets.QMessageBox.information(
                self, "Delete", "Select remote item(s).")
            return
        listing = "\n  ".join(f"{t}: {n}" for n, t in sel)
        if QtWidgets.QMessageBox.question(
            self, "Delete",
            f"Delete {len(sel)} remote item(s) (recursive)?\n\n  {listing}",
        ) != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        paths = [posixpath.join(self.remote_dir, n) for n, _ in sel]

        def do():
            sftp = self.ssh.sftp()
            for path in paths:
                sftp_rmtree(sftp, path)
            return len(paths)

        def done(res, err):
            if err:
                self.log.emit(f"[ERROR] Delete: {err}")
                QtWidgets.QMessageBox.critical(
                    self, "Delete failed", str(err))
                return
            self.log.emit(f"Deleted {res} item(s).")
            self.refresh()

        run_in_thread(self, do, done)

    def edit_selected_remote(self):
        sel = self._selected_remote_many()
        files = [n for n, t in sel if t == "file"]
        if len(sel) != 1 or len(files) != 1:
            QtWidgets.QMessageBox.information(
                self, "Edit", "Select exactly one remote file.")
            return
        name = files[0]
        path = posixpath.join(self.remote_dir, name)

        def do():
            sftp = self.ssh.sftp()
            size = int(sftp.stat(path).st_size)
            if size > MAX_EDIT_BYTES:
                raise RuntimeError(
                    f"File too large to edit ({size} bytes, "
                    f"limit {MAX_EDIT_BYTES}).")
            with sftp.open(path, "rb") as fh:
                data = fh.read()
            if looks_binary(data[:8192]):
                raise RuntimeError("File appears to be binary.")
            return data.decode("utf-8", errors="replace")

        def done(res, err):
            if err:
                self.log.emit(f"[ERROR] Edit load: {err}")
                QtWidgets.QMessageBox.critical(self, "Edit failed", str(err))
                return
            dlg = RemoteEditDialog(f"Edit: {path}", res, self)
            if dlg.exec() != QtWidgets.QDialog.DialogCode.Accepted:
                return
            new_text = dlg.text()

            def save():
                sftp = self.ssh.sftp()
                with sftp.open(path, "wb") as fh:
                    fh.write(new_text.encode("utf-8"))
                return True

            def saved(_r, e2):
                if e2:
                    self.log.emit(f"[ERROR] Edit save: {e2}")
                    QtWidgets.QMessageBox.critical(
                        self, "Save failed", str(e2))
                    return
                self.log.emit(f"Saved {path}")
                self.refresh()

            run_in_thread(self, save, saved)

        run_in_thread(self, do, done)

    def mkdir_remote(self):
        name, ok = QtWidgets.QInputDialog.getText(
            self, "Mkdir", "Remote folder name:")
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
        sel = self._selected_remote_many()
        if len(sel) != 1:
            QtWidgets.QMessageBox.information(
                self, "Rename", "Select exactly one remote item.")
            return
        name, _typ = sel[0]
        newname, ok = QtWidgets.QInputDialog.getText(
            self, "Rename", f"New name for {name}:")
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
