"""Plugins tab: searchable catalog, enable/disable, install/update/upgrade."""
from __future__ import annotations

from PyQt6 import QtCore, QtGui, QtWidgets

from pwnman.pwnman import plugin_catalog, remote_cmds
from pwnman.pwnman.async_utils import run_in_thread
from pwnman.pwnman.plugins_toml import extract_enabled_from_toml, parse_plugins_from_ls, set_plugin_enabled_in_toml
from pwnman.pwnman.remote_config import read_remote_text, write_remote_text

# NOTE: your device may have this typo-dir:
# /usr/local/share/pwnagotchi/availaible-plugins
PLUGIN_DIR_CANDIDATES = [
    "/usr/local/share/pwnagotchi/availaible-plugins",
    "/usr/local/share/pwnagotchi/custom-plugins",
    "/usr/local/share/pwnagotchi/installed-plugins",
    "/usr/local/share/pwnagotchi/available-plugins",
    "/usr/local/share/pwnagotchi/plugins",
    "/usr/share/pwnagotchi/plugins",
    "/etc/pwnagotchi/plugins",
    "/home/pi/custom-plugins",
]

COLS = ["Plugin", "Installed", "Enabled", "Version", "Status", "Update"]


class PluginsTab(QtWidgets.QWidget):
    log = QtCore.pyqtSignal(str)

    def __init__(self, ssh, cfg_path_provider, parent=None):
        super().__init__(parent)
        self.ssh = ssh
        self._cfg_path = cfg_path_provider
        self.rows: list[plugin_catalog.PluginRow] = []

        lay = QtWidgets.QVBoxLayout(self)
        top = QtWidgets.QHBoxLayout()
        self.btn_plugins_refresh = QtWidgets.QPushButton("Refresh plugins")
        self.btn_plugins_apply = QtWidgets.QPushButton("Apply changes (save config + restart)")
        self.btn_plugin_install = QtWidgets.QPushButton("Install…")
        self.btn_plugin_update = QtWidgets.QPushButton("Update lists")
        self.btn_plugin_upgrade = QtWidgets.QPushButton("Upgrade all")
        self.btn_plugins_refresh.clicked.connect(self.refresh)
        self.btn_plugins_apply.clicked.connect(self.apply)
        self.btn_plugin_install.clicked.connect(self.install_dialog)
        self.btn_plugin_update.clicked.connect(lambda: self.cli("update"))
        self.btn_plugin_upgrade.clicked.connect(lambda: self.cli("upgrade"))
        for b in (self.btn_plugins_refresh, self.btn_plugins_apply, self.btn_plugin_install,
                  self.btn_plugin_update, self.btn_plugin_upgrade):
            top.addWidget(b)
        top.addStretch(1)

        flt = QtWidgets.QHBoxLayout()
        self.search = QtWidgets.QLineEdit()
        self.search.setPlaceholderText("Search plugins…")
        self.search.setClearButtonEnabled(True)
        self.filter = QtWidgets.QComboBox()
        self.filter.addItems(plugin_catalog.FILTERS)
        self.summary = QtWidgets.QLabel("")
        flt.addWidget(self.search, 1)
        flt.addWidget(self.filter)
        flt.addWidget(self.summary)
        self.search.textChanged.connect(self.apply_filter)
        self.filter.currentIndexChanged.connect(self.apply_filter)

        self.plugins_table = QtWidgets.QTableWidget(0, len(COLS))
        self.plugins_table.setHorizontalHeaderLabels(COLS)
        self.plugins_table.horizontalHeader().setStretchLastSection(True)
        self.plugins_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.plugins_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)

        self.plugin_out = QtWidgets.QPlainTextEdit()
        self.plugin_out.setReadOnly(True)
        self.plugin_out.setMaximumHeight(130)
        self.plugin_out.setPlaceholderText("Output of `pwnagotchi plugins …` appears here")
        self.plugin_out.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont))
        lay.addLayout(top)
        lay.addLayout(flt)
        lay.addWidget(self.plugins_table, 1)
        lay.addWidget(self.plugin_out)

    # -------------------------------------------------------------- catalog
    def refresh(self):
        cfg_path = self._cfg_path()

        def do():
            cfg = read_remote_text(self.ssh, cfg_path)
            enabled_map = extract_enabled_from_toml(cfg)
            found = set()
            for d in PLUGIN_DIR_CANDIDATES:
                r = self.ssh.run(remote_cmds.list_dir(d))
                found.update(parse_plugins_from_ls(r.stdout))
            cli: list[dict] = []
            try:  # the CLI is optional: older images do not have `plugins list`
                r = self.ssh.run(remote_cmds.plugin_cli("list"), timeout_sec=30)
                if r.exit_status == 0:
                    cli = remote_cmds.parse_plugin_list(r.stdout)
            except Exception:  # noqa: BLE001
                cli = []
            return plugin_catalog.merge_catalog(found, enabled_map, cli)

        def done(rows, err):
            if err:
                self.log.emit(f"[ERROR] {err}")
                return
            self.show_rows(rows)
            self.log.emit(f"Plugins refreshed: {len(rows)} shown.")

        run_in_thread(self, do, done)

    def show_rows(self, rows: list[plugin_catalog.PluginRow]):
        self.rows = rows
        t = self.plugins_table
        t.setRowCount(0)
        for i, r in enumerate(rows):
            t.insertRow(i)
            name = QtWidgets.QTableWidgetItem(r.name)
            inst = QtWidgets.QTableWidgetItem("yes" if r.installed else "no")
            chk = QtWidgets.QTableWidgetItem()
            chk.setFlags(chk.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable)
            chk.setCheckState(QtCore.Qt.CheckState.Checked if r.enabled
                              else QtCore.Qt.CheckState.Unchecked)
            ver = QtWidgets.QTableWidgetItem(r.version)
            st = QtWidgets.QTableWidgetItem(r.status)
            upd = QtWidgets.QTableWidgetItem(
                (f"→ {r.latest}" if r.latest else "yes") if r.update_available else "")
            for c, item in enumerate((name, inst, chk, ver, st, upd)):
                t.setItem(i, c, item)
        self.apply_filter()

    def apply_filter(self):
        text, which = self.search.text().strip(), self.filter.currentText()
        shown = []
        for i, r in enumerate(self.rows):
            ok = plugin_catalog.matches(r, text, which)
            self.plugins_table.setRowHidden(i, not ok)
            if ok:
                shown.append(r)
        self.summary.setText(plugin_catalog.summary(shown) if self.rows else "")

    # --------------------------------------------------------------- actions
    def apply(self):
        cfg_path = self._cfg_path()
        desired = {}
        for row in range(self.plugins_table.rowCount()):
            name = self.plugins_table.item(row, 0).text()
            chk = self.plugins_table.item(row, 2)
            desired[name] = (chk.checkState() == QtCore.Qt.CheckState.Checked)

        def do():
            # A failed read must abort: previously it yielded "" and the
            # config was then overwritten with just the plugin entries.
            cfg = read_remote_text(self.ssh, cfg_path)
            current = extract_enabled_from_toml(cfg)
            changed = 0
            for name, en in desired.items():
                if current.get(name, False) == en and (name in current or not en):
                    continue  # unchanged (and don't add "enabled = false" noise)
                cfg = set_plugin_enabled_in_toml(cfg, name, en)
                changed += 1
            if not changed:
                return "No plugin changes to apply."
            bak = write_remote_text(self.ssh, cfg_path, cfg)
            r = self.ssh.run(remote_cmds.restart_pwnagotchi(), timeout_sec=30)
            msg = f"{changed} plugin(s) updated. Backup: {bak or 'n/a'}."
            if r.exit_status != 0:
                msg += f"\nService restart FAILED: {(r.stderr or r.stdout).strip()}"
            return msg

        def done(res, err):
            if err:
                self.log.emit(f"[ERROR] {err}")
                QtWidgets.QMessageBox.critical(self, "Apply failed", str(err))
                return
            self.log.emit(res)
            QtWidgets.QMessageBox.information(self, "Plugins", res)

        run_in_thread(self, do, done)

    def cli(self, action: str, *args: str):
        try:
            cmd = remote_cmds.plugin_cli(action, *args)
        except ValueError as e:
            QtWidgets.QMessageBox.warning(self, "Plugins", str(e))
            return
        self.plugin_out.appendPlainText(f"$ pwnagotchi plugins {action} {' '.join(args)}")

        def do():
            r = self.ssh.run(cmd, timeout_sec=180)
            return r.exit_status, (r.stdout + r.stderr).strip()

        def done(res, err):
            if err:
                self.plugin_out.appendPlainText(f"[ERROR] {err}")
                return
            code, text = res
            self.plugin_out.appendPlainText(text or "(no output)")
            if code != 0:
                self.plugin_out.appendPlainText(f"[exit {code}]")
            self.refresh()

        run_in_thread(self, do, done)

    def install_dialog(self):
        name, ok = QtWidgets.QInputDialog.getText(self, "Install plugin", "Plugin name:")
        name = name.strip()
        if ok and name:
            self.cli("install", name)

    def selected_name(self) -> str:
        r = self.plugins_table.currentRow()
        it = self.plugins_table.item(r, 0) if r >= 0 else None
        return it.text() if it else ""
