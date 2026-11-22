"""Config tab: edit config.toml with syntax check, diff-before-save, backups."""
from __future__ import annotations

from PyQt6 import QtCore, QtGui, QtWidgets

from pwnman.pwnman import config_tools
from pwnman.pwnman.async_utils import run_in_thread
from pwnman.pwnman.remote_config import read_remote_text, write_remote_text


class ConfigTab(QtWidgets.QWidget):
    log = QtCore.pyqtSignal(str)
    statusMessage = QtCore.pyqtSignal(str)

    def __init__(self, ssh, parent=None):
        super().__init__(parent)
        self.ssh = ssh
        self._cfg_loaded = ""
        lay = QtWidgets.QVBoxLayout(self)
        top = QtWidgets.QHBoxLayout()
        self.cfg_path = QtWidgets.QLineEdit("/etc/pwnagotchi/config.toml")
        self.btn_cfg_load = QtWidgets.QPushButton("Load")
        self.btn_cfg_save = QtWidgets.QPushButton("Save (backup first)")
        self.btn_cfg_check = QtWidgets.QPushButton("Check syntax")
        self.btn_cfg_backups = QtWidgets.QPushButton("Backups…")
        self.btn_cfg_load.clicked.connect(self.load)
        self.btn_cfg_save.clicked.connect(self.save)
        self.btn_cfg_check.clicked.connect(self.check)
        self.btn_cfg_backups.clicked.connect(self.backups)
        top.addWidget(QtWidgets.QLabel("Path:"))
        top.addWidget(self.cfg_path, 1)
        for b in (self.btn_cfg_load, self.btn_cfg_check, self.btn_cfg_backups, self.btn_cfg_save):
            top.addWidget(b)
        self.cfg_editor = QtWidgets.QPlainTextEdit()
        self.cfg_editor.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont))
        lay.addLayout(top)
        lay.addWidget(self.cfg_editor, 1)

    @property
    def path(self) -> str:
        return self.cfg_path.text().strip()

    def load(self):
        path = self.path

        def do():
            return read_remote_text(self.ssh, path)

        def done(res, err):
            if err:
                self.log.emit(f"[ERROR] {err}")
                QtWidgets.QMessageBox.critical(self, "Load failed", str(err))
                return
            self._cfg_loaded = res
            self.cfg_editor.setPlainText(res)
            self.log.emit(f"Loaded config: {path}")

        run_in_thread(self, do, done)

    def check(self) -> bool:
        problem = config_tools.check_toml(self.cfg_editor.toPlainText())
        if problem is None:
            self.statusMessage.emit("TOML syntax OK")
            self.log.emit("Config: TOML syntax OK")
            return True
        block = self.cfg_editor.document().findBlockByLineNumber(max(0, problem.line - 1))
        cur = self.cfg_editor.textCursor()
        cur.setPosition(block.position())
        self.cfg_editor.setTextCursor(cur)
        self.cfg_editor.setFocus()
        msg = f"line {problem.line}, col {problem.col}: {problem.message}"
        self.log.emit(f"Config: TOML syntax error — {msg}")
        QtWidgets.QMessageBox.warning(self, "TOML syntax error", msg)
        return False

    def save(self):
        path = self.path
        content = self.cfg_editor.toPlainText()

        problem = config_tools.check_toml(content)
        if problem is not None:
            if QtWidgets.QMessageBox.question(
                    self, "Syntax error",
                    f"The config has a TOML syntax error (line {problem.line}: "
                    f"{problem.message}). pwnagotchi may fail to start.\n\nSave anyway?"
            ) != QtWidgets.QMessageBox.StandardButton.Yes:
                return
        diff = config_tools.make_diff(self._cfg_loaded, content)
        if not diff:
            self.log.emit("Config unchanged; nothing to save.")
            QtWidgets.QMessageBox.information(self, "Save", "No changes to save.")
            return
        add, rem = config_tools.diff_summary(diff)
        shown = diff if len(diff) < 4000 else diff[:4000] + "\n…(diff truncated)"
        if QtWidgets.QMessageBox.question(
                self, "Save config",
                f"{path}: +{add} / -{rem} lines. A backup is made first.\n\n{shown}\n\nSave?"
        ) != QtWidgets.QMessageBox.StandardButton.Yes:
            return

        def do():
            bak = write_remote_text(self.ssh, path, content)
            return f"Saved. Backup: {bak}" if bak else "Saved."

        def done(res, err):
            if err:
                self.log.emit(f"[ERROR] {err}")
                QtWidgets.QMessageBox.critical(self, "Save failed", str(err))
                return
            self._cfg_loaded = content
            self.log.emit(res)
            QtWidgets.QMessageBox.information(
                self, "Saved", "Config saved. Consider restarting pwnagotchi service.")

        run_in_thread(self, do, done)

    def backups(self):
        dlg = BackupsDialog(self.ssh, self.path, self)
        dlg.restored.connect(lambda: (self.log.emit("Config restored from backup."), self.load()))
        dlg.exec()


class BackupsDialog(QtWidgets.QDialog):
    """List config backups; preview, restore (one click) or delete."""
    restored = QtCore.pyqtSignal()

    def __init__(self, ssh, cfg_path: str, parent=None):
        super().__init__(parent)
        self.ssh, self.cfg_path = ssh, cfg_path
        self.setWindowTitle(f"Backups of {cfg_path}")
        self.resize(760, 520)
        lay = QtWidgets.QVBoxLayout(self)
        self.list = QtWidgets.QListWidget()
        self.list.currentRowChanged.connect(self._preview)
        self.preview = QtWidgets.QPlainTextEdit()
        self.preview.setReadOnly(True)
        sp = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)
        sp.addWidget(self.list)
        sp.addWidget(self.preview)
        sp.setStretchFactor(1, 3)
        lay.addWidget(sp, 1)
        row = QtWidgets.QHBoxLayout()
        self.btn_restore = QtWidgets.QPushButton("Restore selected")
        self.btn_delete = QtWidgets.QPushButton("Delete selected")
        self.btn_close = QtWidgets.QPushButton("Close")
        self.btn_restore.clicked.connect(self._restore)
        self.btn_delete.clicked.connect(self._delete)
        self.btn_close.clicked.connect(self.accept)
        for b in (self.btn_restore, self.btn_delete):
            row.addWidget(b)
        row.addStretch(1)
        row.addWidget(self.btn_close)
        lay.addLayout(row)
        self.backups: list = []
        self._reload()

    def _reload(self):
        try:
            self.backups = config_tools.list_backups(self.ssh, self.cfg_path)
        except Exception as e:  # noqa: BLE001
            self.backups = []
            self.preview.setPlainText(f"Cannot list backups: {e}")
        self.list.clear()
        for b in self.backups:
            self.list.addItem(f"{b.stamp[:4]}-{b.stamp[4:6]}-{b.stamp[6:8]} {b.stamp[9:11]}:{b.stamp[11:13]}:{b.stamp[13:15]}")
        if self.backups:
            self.list.setCurrentRow(0)

    def _current(self):
        r = self.list.currentRow()
        return self.backups[r] if 0 <= r < len(self.backups) else None

    def _preview(self, _row):
        b = self._current()
        if b is None:
            return
        try:
            self.preview.setPlainText(config_tools.read_backup(self.ssh, self.cfg_path, b))
        except Exception as e:  # noqa: BLE001
            self.preview.setPlainText(f"Cannot read backup: {e}")

    def _restore(self):
        b = self._current()
        if b is None:
            return
        if QtWidgets.QMessageBox.question(
                self, "Restore", f"Restore backup {b.stamp}? The current file is backed up first."
        ) != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            config_tools.restore_backup(self.ssh, self.cfg_path, b)
        except Exception as e:  # noqa: BLE001
            QtWidgets.QMessageBox.critical(self, "Restore failed", str(e))
            return
        self.restored.emit()
        self._reload()

    def _delete(self):
        b = self._current()
        if b is None:
            return
        if QtWidgets.QMessageBox.question(
                self, "Delete backup", f"Delete backup {b.stamp}?"
        ) != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        try:
            config_tools.delete_backups(self.ssh, self.cfg_path, [b])
        except Exception as e:  # noqa: BLE001
            QtWidgets.QMessageBox.critical(self, "Delete failed", str(e))
        self._reload()
