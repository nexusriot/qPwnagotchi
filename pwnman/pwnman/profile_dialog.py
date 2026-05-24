from __future__ import annotations

import copy
import os
from typing import Optional

from PyQt6 import QtCore, QtWidgets

from pwnman.pwnman.models import ConnectionProfile
from pwnman.pwnman.profile_store import ProfileStore


class ProfileManagerDialog(QtWidgets.QDialog):
    """Add / edit / duplicate / delete saved Pwnagotchi connection profiles.

    Works on an in-memory copy; changes are only written to the store when
    the user accepts the dialog (OK), so Cancel discards everything.
    """

    def __init__(self, store: ProfileStore, parent: Optional[QtWidgets.QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Manage Pwnagotchi Profiles")
        self.resize(720, 460)

        self._store = store
        self._profiles: list[ConnectionProfile] = [
            copy.deepcopy(p) for p in store.profiles
        ]
        self._current_row = -1
        self._loading = False
        self.selected_name: str = store.active_name

        self._build_ui()
        self._reload_list(select=store.active_name)

    def _build_ui(self) -> None:
        outer = QtWidgets.QHBoxLayout(self)

        # Left: list + list buttons
        left = QtWidgets.QVBoxLayout()
        self.list = QtWidgets.QListWidget()
        self.list.currentRowChanged.connect(self._on_row_changed)
        left.addWidget(self.list, 1)

        list_btns = QtWidgets.QHBoxLayout()
        self.btn_new = QtWidgets.QPushButton("New")
        self.btn_dup = QtWidgets.QPushButton("Duplicate")
        self.btn_del = QtWidgets.QPushButton("Delete")
        self.btn_new.clicked.connect(self._on_new)
        self.btn_dup.clicked.connect(self._on_duplicate)
        self.btn_del.clicked.connect(self._on_delete)
        list_btns.addWidget(self.btn_new)
        list_btns.addWidget(self.btn_dup)
        list_btns.addWidget(self.btn_del)
        left.addLayout(list_btns)

        outer.addLayout(left, 1)

        # Right: edit form
        form_box = QtWidgets.QGroupBox("Profile")
        form = QtWidgets.QFormLayout(form_box)

        self.f_name = QtWidgets.QLineEdit()
        self.f_host = QtWidgets.QLineEdit()
        self.f_port = QtWidgets.QSpinBox()
        self.f_port.setRange(1, 65535)
        self.f_port.setValue(22)
        self.f_user = QtWidgets.QLineEdit()
        self.f_pass = QtWidgets.QLineEdit()
        self.f_pass.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.f_show_pass = QtWidgets.QCheckBox("Show")
        self.f_show_pass.toggled.connect(
            lambda on: self.f_pass.setEchoMode(
                QtWidgets.QLineEdit.EchoMode.Normal if on
                else QtWidgets.QLineEdit.EchoMode.Password
            )
        )
        pass_row = QtWidgets.QHBoxLayout()
        pass_row.addWidget(self.f_pass, 1)
        pass_row.addWidget(self.f_show_pass)

        self.f_key = QtWidgets.QLineEdit()
        self.btn_key = QtWidgets.QPushButton("Browse…")
        self.btn_key.clicked.connect(self._pick_key)
        key_row = QtWidgets.QHBoxLayout()
        key_row.addWidget(self.f_key, 1)
        key_row.addWidget(self.btn_key)

        self.f_lcd_url = QtWidgets.QLineEdit()
        self.f_lcd_user = QtWidgets.QLineEdit()
        self.f_lcd_pass = QtWidgets.QLineEdit()
        self.f_lcd_pass.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        form.addRow("Name", self.f_name)
        form.addRow("Host / IP", self.f_host)
        form.addRow("Port", self.f_port)
        form.addRow("User", self.f_user)
        form.addRow("Password", self._wrap(pass_row))
        form.addRow("SSH key (optional)", self._wrap(key_row))
        form.addRow(self._separator())
        form.addRow("LCD URL", self.f_lcd_url)
        form.addRow("LCD user", self.f_lcd_user)
        form.addRow("LCD pass", self.f_lcd_pass)

        right = QtWidgets.QVBoxLayout()
        right.addWidget(form_box, 1)

        self.buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.accepted.connect(self._on_accept)
        self.buttons.rejected.connect(self.reject)
        right.addWidget(self.buttons)

        outer.addLayout(right, 2)

    @staticmethod
    def _wrap(layout: QtWidgets.QLayout) -> QtWidgets.QWidget:
        w = QtWidgets.QWidget()
        w.setLayout(layout)
        return w

    @staticmethod
    def _separator() -> QtWidgets.QFrame:
        line = QtWidgets.QFrame()
        line.setFrameShape(QtWidgets.QFrame.Shape.HLine)
        line.setFrameShadow(QtWidgets.QFrame.Shadow.Sunken)
        return line

    def _reload_list(self, select: str = "") -> None:
        self._loading = True
        self.list.clear()
        for p in self._profiles:
            self.list.addItem(p.name)
        self._loading = False

        if not self._profiles:
            self._current_row = -1
            self._set_form_enabled(False)
            self._clear_form()
            return

        row = 0
        for i, p in enumerate(self._profiles):
            if p.name == select:
                row = i
                break
        self.list.setCurrentRow(row)

    def _on_row_changed(self, row: int) -> None:
        if self._loading:
            return
        # Commit edits of the previously selected profile first.
        self._commit_form_to(self._current_row)
        self._current_row = row
        if 0 <= row < len(self._profiles):
            self._set_form_enabled(True)
            self._load_form_from(self._profiles[row])
        else:
            self._set_form_enabled(False)
            self._clear_form()

    def _load_form_from(self, p: ConnectionProfile) -> None:
        self._loading = True
        self.f_name.setText(p.name)
        self.f_host.setText(p.host)
        self.f_port.setValue(int(p.port or 22))
        self.f_user.setText(p.username)
        self.f_pass.setText(p.password)
        self.f_key.setText(p.key_path)
        self.f_lcd_url.setText(p.lcd_url)
        self.f_lcd_user.setText(p.lcd_user)
        self.f_lcd_pass.setText(p.lcd_pass)
        self._loading = False

    def _clear_form(self) -> None:
        self._loading = True
        for w in (self.f_name, self.f_host, self.f_user, self.f_pass,
                  self.f_key, self.f_lcd_url, self.f_lcd_user, self.f_lcd_pass):
            w.clear()
        self.f_port.setValue(22)
        self._loading = False

    def _set_form_enabled(self, on: bool) -> None:
        for w in (self.f_name, self.f_host, self.f_port, self.f_user,
                  self.f_pass, self.f_show_pass, self.f_key, self.btn_key,
                  self.f_lcd_url, self.f_lcd_user, self.f_lcd_pass):
            w.setEnabled(on)
        self.btn_dup.setEnabled(on)
        self.btn_del.setEnabled(on)

    def _commit_form_to(self, row: int) -> None:
        if not (0 <= row < len(self._profiles)):
            return
        p = self._profiles[row]
        name = self.f_name.text().strip() or p.name
        p.name = name
        p.host = self.f_host.text().strip()
        p.port = int(self.f_port.value())
        p.username = self.f_user.text().strip()
        p.password = self.f_pass.text()
        p.key_path = self.f_key.text().strip()
        p.lcd_url = self.f_lcd_url.text().strip()
        p.lcd_user = self.f_lcd_user.text()
        p.lcd_pass = self.f_lcd_pass.text()
        # keep list label in sync
        item = self.list.item(row)
        if item is not None and item.text() != name:
            self._loading = True
            item.setText(name)
            self._loading = False

    def _unique_name(self, base: str) -> str:
        existing = {p.name for p in self._profiles}
        if base not in existing:
            return base
        i = 2
        while f"{base} ({i})" in existing:
            i += 1
        return f"{base} ({i})"

    def _on_new(self) -> None:
        self._commit_form_to(self._current_row)
        prof = ConnectionProfile(name=self._unique_name("New profile"))
        self._profiles.append(prof)
        self._reload_list(select=prof.name)
        self.f_name.setFocus()
        self.f_name.selectAll()

    def _on_duplicate(self) -> None:
        if not (0 <= self._current_row < len(self._profiles)):
            return
        self._commit_form_to(self._current_row)
        src = self._profiles[self._current_row]
        clone = copy.deepcopy(src)
        clone.name = self._unique_name(f"{src.name} copy")
        self._profiles.append(clone)
        self._reload_list(select=clone.name)

    def _on_delete(self) -> None:
        if not (0 <= self._current_row < len(self._profiles)):
            return
        p = self._profiles[self._current_row]
        if QtWidgets.QMessageBox.question(
            self, "Delete profile", f"Delete profile '{p.name}'?"
        ) != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        del self._profiles[self._current_row]
        self._current_row = -1
        self._reload_list()

    def _pick_key(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select SSH private key", os.path.expanduser("~")
        )
        if path:
            self.f_key.setText(path)

    def _on_accept(self) -> None:
        self._commit_form_to(self._current_row)

        names = [p.name.strip() for p in self._profiles]
        if any(not n for n in names):
            QtWidgets.QMessageBox.warning(
                self, "Invalid profile", "Every profile needs a non-empty name."
            )
            return
        if len(set(names)) != len(names):
            QtWidgets.QMessageBox.warning(
                self, "Duplicate names", "Profile names must be unique."
            )
            return

        active = ""
        if 0 <= self._current_row < len(self._profiles):
            active = self._profiles[self._current_row].name
        elif self._profiles:
            active = self._profiles[0].name

        self._store.replace_all(self._profiles, active=active)
        try:
            self._store.save()
        except OSError as e:
            QtWidgets.QMessageBox.critical(
                self, "Save failed", f"Could not write profiles file:\n{e}"
            )
            return
        self.selected_name = self._store.active_name
        self.accept()
