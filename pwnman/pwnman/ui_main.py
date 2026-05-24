from __future__ import annotations

import os
import re
import stat
from typing import Optional

from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6 import QtWebEngineWidgets

from pwnman.pwnman.ssh_client import SSHClient
from pwnman.pwnman.ssh_terminal import SSHTerminalWidget
from pwnman.pwnman.export_folder_tab import ExportFolderTab
from pwnman.pwnman.file_manager import FileManagerWidget
from pwnman.pwnman.async_utils import run_in_thread, quote_bash
from pwnman.pwnman.models import ConnectionProfile
from pwnman.pwnman.profile_store import ProfileStore
from pwnman.pwnman.profile_dialog import ProfileManagerDialog
from pwnman.pwnman.fleet_tab import FleetTab

MANUAL_PROFILE_LABEL = "<Manual / unsaved>"



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


def parse_plugins_from_ls(output: str) -> list[str]:
    names = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("total"):
            continue
        if line.endswith(".py"):
            base = line[:-3]
            if base and base != "__init__":
                names.append(base)
    return sorted(set(names))


def extract_enabled_from_toml(toml_text: str) -> dict[str, bool]:
    enabled: dict[str, bool] = {}

    for m in re.finditer(
        r"^\s*main\.plugins\.([a-zA-Z0-9_\-]+)\.enabled\s*=\s*(true|false)\s*$",
        toml_text,
        flags=re.MULTILINE,
    ):
        enabled[m.group(1)] = (m.group(2) == "true")

    for m in re.finditer(
        r"^\s*\[main\.plugins\.([a-zA-Z0-9_\-]+)\]\s*$",
        toml_text,
        flags=re.MULTILINE,
    ):
        name = m.group(1)
        start = m.end()
        chunk = toml_text[start:start + 800]
        m2 = re.search(r"^\s*enabled\s*=\s*(true|false)\s*$", chunk, flags=re.MULTILINE)
        if m2:
            enabled[name] = (m2.group(1) == "true")

    return enabled


def set_plugin_enabled_in_toml(toml_text: str, plugin: str, enabled: bool) -> str:
    val = "true" if enabled else "false"

    dotted = re.compile(
        rf"^(\s*main\.plugins\.{re.escape(plugin)}\.enabled\s*=\s*)(true|false)\s*$",
        flags=re.MULTILINE,
    )
    if dotted.search(toml_text):
        return dotted.sub(rf"\1{val}", toml_text)

    table = re.compile(rf"^\s*\[main\.plugins\.{re.escape(plugin)}\]\s*$", flags=re.MULTILINE)
    m = table.search(toml_text)
    if m:
        start = m.end()
        next_sec = re.search(r"^\s*\[.+\]\s*$", toml_text[start:], flags=re.MULTILINE)
        end = start + (next_sec.start() if next_sec else len(toml_text[start:]))

        block = toml_text[start:end]
        en_re = re.compile(r"^(\s*enabled\s*=\s*)(true|false)\s*$", flags=re.MULTILINE)
        if en_re.search(block):
            block2 = en_re.sub(rf"\1{val}", block)
        else:
            block2 = block.rstrip() + f"\nenabled = {val}\n"
        return toml_text[:start] + block2 + toml_text[end:]

    append = f"\n[main.plugins.{plugin}]\nenabled = {val}\n"
    return toml_text.rstrip() + append + "\n"


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Pwnagotchi Manager v.0.1.1")
        self.resize(980, 700)

        self.ssh = SSHClient()
        self._connected = False

        self.store = ProfileStore()
        self._loading_profile = False

        self._build_ui()
        self._set_connected(False)
        self._init_profiles()

    def _build_ui(self):
        root = QtWidgets.QWidget()
        self.setCentralWidget(root)
        layout = QtWidgets.QVBoxLayout(root)

        conn = QtWidgets.QGroupBox("Connection")
        conn_l = QtWidgets.QGridLayout(conn)

        self.profile_combo = QtWidgets.QComboBox()
        self.profile_combo.setMinimumWidth(220)
        self.profile_combo.currentIndexChanged.connect(self._on_profile_selected)
        self.btn_profile_save = QtWidgets.QPushButton("Save to profile")
        self.btn_profile_manage = QtWidgets.QPushButton("Manage profiles…")
        self.btn_profile_save.clicked.connect(self._on_profile_save)
        self.btn_profile_manage.clicked.connect(self._on_profile_manage)

        self.host = QtWidgets.QLineEdit("10.0.0.2")
        self.port = QtWidgets.QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(22)

        self.user = QtWidgets.QLineEdit("pi")
        self.passwd = QtWidgets.QLineEdit("raspberry")
        self.passwd.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        self.keypath = QtWidgets.QLineEdit()
        self.keypick = QtWidgets.QPushButton("Browse key…")
        self.keypick.clicked.connect(self._pick_key)

        self.btn_connect = QtWidgets.QPushButton("Connect")
        self.btn_disconnect = QtWidgets.QPushButton("Disconnect")
        self.btn_connect.clicked.connect(self.on_connect)
        self.btn_disconnect.clicked.connect(self.on_disconnect)

        row = 0
        conn_l.addWidget(QtWidgets.QLabel("Profile"), row, 0)
        conn_l.addWidget(self.profile_combo, row, 1)
        prof_btns = QtWidgets.QHBoxLayout()
        prof_btns.addWidget(self.btn_profile_save)
        prof_btns.addWidget(self.btn_profile_manage)
        prof_btns.addStretch(1)
        conn_l.addLayout(prof_btns, row, 2, 1, 2)

        row += 1
        conn_l.addWidget(QtWidgets.QLabel("Host"), row, 0)
        conn_l.addWidget(self.host, row, 1)
        conn_l.addWidget(QtWidgets.QLabel("Port"), row, 2)
        conn_l.addWidget(self.port, row, 3)

        row += 1
        conn_l.addWidget(QtWidgets.QLabel("User"), row, 0)
        conn_l.addWidget(self.user, row, 1)
        conn_l.addWidget(QtWidgets.QLabel("Password"), row, 2)
        conn_l.addWidget(self.passwd, row, 3)

        row += 1
        conn_l.addWidget(QtWidgets.QLabel("SSH key (optional)"), row, 0)
        conn_l.addWidget(self.keypath, row, 1, 1, 2)
        conn_l.addWidget(self.keypick, row, 3)

        row += 1
        btns = QtWidgets.QHBoxLayout()
        btns.addWidget(self.btn_connect)
        btns.addWidget(self.btn_disconnect)
        btns.addStretch(1)
        conn_l.addLayout(btns, row, 0, 1, 4)

        layout.addWidget(conn)

        layout.addWidget(QtWidgets.QLabel("Console"))
        self.console = QtWidgets.QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(2000)
        layout.addWidget(self.console, 1)

        self.tabs = QtWidgets.QTabWidget()
        self.tabs.currentChanged.connect(self._on_tab_changed)
        layout.addWidget(self.tabs, 3)

        self._tab_lcd()

        # then the rest
        self._tab_status()
        self._tab_services()
        self._tab_logs()
        self._tab_config()
        self._tab_files()
        self._tab_export()
        self._tab_power()
        self._tab_ssh()
        self._tab_plugins()
        self._tab_fleet()


        # ensure LCD selected
        self.tabs.setCurrentIndex(0)

        self.status = QtWidgets.QStatusBar()
        self.setStatusBar(self.status)

    def _tab_lcd(self):
        w = QtWidgets.QWidget()
        outer = QtWidgets.QVBoxLayout(w)

        webbar = QtWidgets.QHBoxLayout()

        self.lcd_url = QtWidgets.QLineEdit("http://10.0.0.2:8080/")
        self.lcd_user = QtWidgets.QLineEdit("changeme")
        self.lcd_pass = QtWidgets.QLineEdit("changeme")
        self.lcd_pass.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        self.btn_lcd_open = QtWidgets.QPushButton("Open Web LCD")
        self.btn_lcd_reload = QtWidgets.QPushButton("Reload")
        self.btn_lcd_close = QtWidgets.QPushButton("Close Web LCD")

        self.lcd_auto_reload = QtWidgets.QCheckBox("Auto reload")
        self.lcd_auto_reload.setChecked(True)

        self.lcd_reload_sec = QtWidgets.QSpinBox()
        self.lcd_reload_sec.setRange(1, 120)
        self.lcd_reload_sec.setValue(5)

        self.lcd_zoom = QtWidgets.QDoubleSpinBox()
        self.lcd_zoom.setRange(0.2, 2.0)
        self.lcd_zoom.setSingleStep(0.1)
        self.lcd_zoom.setValue(0.5)  # 50% default
        self.lcd_zoom.setSuffix("x")

        webbar.addWidget(QtWidgets.QLabel("URL:"))
        webbar.addWidget(self.lcd_url, 1)
        webbar.addWidget(QtWidgets.QLabel("User:"))
        webbar.addWidget(self.lcd_user)
        webbar.addWidget(QtWidgets.QLabel("Pass:"))
        webbar.addWidget(self.lcd_pass)
        webbar.addWidget(self.btn_lcd_open)
        webbar.addWidget(self.btn_lcd_reload)
        webbar.addWidget(self.btn_lcd_close)
        webbar.addWidget(self.lcd_auto_reload)
        webbar.addWidget(QtWidgets.QLabel("sec:"))
        webbar.addWidget(self.lcd_reload_sec)
        webbar.addWidget(QtWidgets.QLabel("Zoom:"))
        webbar.addWidget(self.lcd_zoom)

        outer.addLayout(webbar)

        self.lcd_web = QtWebEngineWidgets.QWebEngineView()
        # Reduce flicker (helps with "glitch")
        self.lcd_web.setAttribute(QtCore.Qt.WidgetAttribute.WA_OpaquePaintEvent, True)
        self.lcd_web.setStyleSheet("background: #000;")
        # Keep it compact (you can remove if you want it bigger)
        self.lcd_web.setMinimumHeight(260)

        outer.addWidget(self.lcd_web, 1)

        page = self.lcd_web.page()
        page.authenticationRequired.connect(self._lcd_on_auth_required)

        self.btn_lcd_open.clicked.connect(self._lcd_open_web)
        self.btn_lcd_reload.clicked.connect(self._lcd_reload_now)
        self.btn_lcd_close.clicked.connect(self._lcd_close_web)

        self.lcd_zoom.valueChanged.connect(lambda v: self.lcd_web.setZoomFactor(float(v)))

        self._lcd_web_timer = QtCore.QTimer(self)
        self._lcd_web_timer.timeout.connect(self._lcd_web_autoreload_tick)
        self.lcd_auto_reload.stateChanged.connect(self._lcd_web_autoreload_changed)
        self.lcd_reload_sec.valueChanged.connect(self._lcd_web_autoreload_changed)
        self.lcd_web.loadFinished.connect(self._lcd_apply_zoom)

        QtCore.QTimer.singleShot(0, self._lcd_web_autoreload_changed)

        self.tabs.addTab(w, "LCD")

    def _lcd_open_web(self):
        if not getattr(self, "_connected", False):
            self._log("LCD Web: not connected — web view is disabled.")
            return

        url = self.lcd_url.text().strip()
        if not url:
            return
        self._log(f"LCD Web: opening {url}")
        self.lcd_web.setUrl(QtCore.QUrl(url))
        self._lcd_web_autoreload_changed()

    def _lcd_reload_now(self):
        if not getattr(self, "_connected", False):
            self._log("LCD Web: not connected — reload skipped.")
            return

        if self.lcd_web.url().isValid():
            self.lcd_web.reload()
        else:
            self._lcd_open_web()
        self._lcd_apply_zoom(True)

    def _lcd_close_web(self):
        # stop reload loop (but do not change the checkbox state)
        if hasattr(self, "_lcd_web_timer"):
            self._lcd_web_timer.stop()

        # clear the view (avoid showing stale page)
        try:
            self.lcd_web.setUrl(QtCore.QUrl("about:blank"))
        except Exception:
            pass
        # show your "Connected…" placeholder only when connected, otherwise keep blank
        if getattr(self, "_connected", False):
            self.lcd_web.setHtml(
                """
                <html>
                  <body style="background:#000;color:#cfd8dc;font-family:monospace;
                               padding:24px; display:flex; flex-direction:column;
                               align-items:center; justify-content:center; height:100vh;">
                    <div style="font-size:44px;font-weight:800; margin-bottom:12px;">
                      Connected
                    </div>
                    <div style="font-size:22px; line-height:1.35; opacity:0.9; text-align:center;">
                      Open the LCD web URL to start streaming.
                    </div>
                  </body>
                </html>
                """
            )
            self._lcd_apply_zoom(True)
        else:
            self.lcd_web.setHtml("<html><body style='background:#000;'></body></html>")

        self._log("LCD Web: closed")

    def _lcd_on_auth_required(self, url, authenticator):
        authenticator.setUser(self.lcd_user.text())
        authenticator.setPassword(self.lcd_pass.text())

    def _lcd_apply_zoom(self, ok=True):
        if hasattr(self, "lcd_web") and hasattr(self, "lcd_zoom"):
            self.lcd_web.setZoomFactor(float(self.lcd_zoom.value()))

    def _lcd_web_autoreload_changed(self):
        if not hasattr(self, "_lcd_web_timer"):
            return

        # do not autoreload if disconnected
        if not getattr(self, "_connected", False):
            self._lcd_web_timer.stop()
            return

        if self.lcd_auto_reload.isChecked():
            self._lcd_web_timer.start(int(self.lcd_reload_sec.value()) * 1000)
            self._log(f"LCD Web auto reload: ON ({self.lcd_reload_sec.value()}s)")
        else:
            self._lcd_web_timer.stop()
            self._log("LCD Web auto reload: OFF")

    def _lcd_web_autoreload_tick(self):
        # do nothing while disconnected
        if not getattr(self, "_connected", False):
            return

        # avoid annoying reload while typing credentials/url
        if self.lcd_url.hasFocus() or self.lcd_user.hasFocus() or self.lcd_pass.hasFocus():
            return
        if self.lcd_web.url().isValid():
            self.lcd_web.reload()
            self._lcd_apply_zoom(True)

    def _on_tab_changed(self, idx: int):
        # helps reduce WebEngine flicker/glitch on tab switch
        try:
            if self.tabs.tabText(idx) == "LCD" and hasattr(self, "lcd_web"):
                self._lcd_apply_zoom(True)
                QtCore.QTimer.singleShot(50, self.lcd_web.repaint)
        except Exception:
            pass

    def _tab_status(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)

        self.btn_refresh = QtWidgets.QPushButton("Refresh device info")
        self.btn_refresh.clicked.connect(self.on_refresh)

        self.info = QtWidgets.QPlainTextEdit()
        self.info.setReadOnly(True)
        self.info.setMinimumHeight(220)

        l.addWidget(self.btn_refresh)
        l.addWidget(self.info, 1)
        self.tabs.addTab(w, "Status")

    def _tab_services(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)

        top = QtWidgets.QHBoxLayout()
        self.service_name = QtWidgets.QComboBox()
        self.service_name.addItems(["pwnagotchi", "bettercap", "bluetooth", "ssh", "networking"])

        self.btn_svc_status = QtWidgets.QPushButton("Status")
        self.btn_svc_start = QtWidgets.QPushButton("Start")
        self.btn_svc_stop = QtWidgets.QPushButton("Stop")
        self.btn_svc_restart = QtWidgets.QPushButton("Restart")

        self.btn_svc_status.clicked.connect(lambda: self._svc("status"))
        self.btn_svc_start.clicked.connect(lambda: self._svc("start"))
        self.btn_svc_stop.clicked.connect(lambda: self._svc("stop"))
        self.btn_svc_restart.clicked.connect(lambda: self._svc("restart"))

        top.addWidget(QtWidgets.QLabel("Service:"))
        top.addWidget(self.service_name)
        top.addWidget(self.btn_svc_status)
        top.addWidget(self.btn_svc_start)
        top.addWidget(self.btn_svc_stop)
        top.addWidget(self.btn_svc_restart)
        top.addStretch(1)

        self.svc_out = QtWidgets.QPlainTextEdit()
        self.svc_out.setReadOnly(True)

        l.addLayout(top)
        l.addWidget(self.svc_out, 1)
        self.tabs.addTab(w, "Services")

    def _tab_logs(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)

        top = QtWidgets.QHBoxLayout()
        self.log_mode = QtWidgets.QComboBox()
        self.log_mode.addItems([
            "/var/log/pwnagotchi.log (tail)",
            "journalctl -u pwnagotchi (last N lines)",
        ])
        self.log_lines = QtWidgets.QSpinBox()
        self.log_lines.setRange(10, 5000)
        self.log_lines.setValue(200)
        self.btn_logs = QtWidgets.QPushButton("Fetch logs")
        self.btn_logs.clicked.connect(self.on_logs)

        top.addWidget(self.log_mode)
        top.addWidget(QtWidgets.QLabel("Lines:"))
        top.addWidget(self.log_lines)
        top.addWidget(self.btn_logs)
        top.addStretch(1)

        self.logs = QtWidgets.QPlainTextEdit()
        self.logs.setReadOnly(True)
        self.logs.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont))

        l.addLayout(top)
        l.addWidget(self.logs, 1)
        self.tabs.addTab(w, "Logs")

    def _tab_config(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)

        top = QtWidgets.QHBoxLayout()
        self.cfg_path = QtWidgets.QLineEdit("/etc/pwnagotchi/config.toml")
        self.btn_cfg_load = QtWidgets.QPushButton("Load")
        self.btn_cfg_save = QtWidgets.QPushButton("Save (backup first)")
        self.btn_cfg_load.clicked.connect(self.on_cfg_load)
        self.btn_cfg_save.clicked.connect(self.on_cfg_save)

        top.addWidget(QtWidgets.QLabel("Path:"))
        top.addWidget(self.cfg_path, 1)
        top.addWidget(self.btn_cfg_load)
        top.addWidget(self.btn_cfg_save)

        self.cfg_editor = QtWidgets.QPlainTextEdit()
        self.cfg_editor.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont))

        l.addLayout(top)
        l.addWidget(self.cfg_editor, 1)
        self.tabs.addTab(w, "Config")

    def _tab_files(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)

        self.fileman = FileManagerWidget(self.ssh, parent=self)
        self.fileman.log.connect(self._log)
        l.addWidget(self.fileman, 1)

        self.tabs.addTab(w, "Files")

    def _tab_power(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)

        self.btn_reboot = QtWidgets.QPushButton("Reboot")
        self.btn_shutdown = QtWidgets.QPushButton("Shutdown")

        self.btn_reboot.clicked.connect(self.on_reboot)
        self.btn_shutdown.clicked.connect(self.on_shutdown)

        warn = QtWidgets.QLabel(
            "Power actions will immediately reboot/shutdown the device.\n"
            "Use only on devices you own/control."
        )
        warn.setWordWrap(True)

        l.addWidget(warn)
        l.addWidget(self.btn_reboot)
        l.addWidget(self.btn_shutdown)
        l.addStretch(1)

        self.tabs.addTab(w, "Power")

    def _tab_plugins(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)

        top = QtWidgets.QHBoxLayout()
        self.btn_plugins_refresh = QtWidgets.QPushButton("Refresh plugins")
        self.btn_plugins_refresh.clicked.connect(self.on_plugins_refresh)
        self.btn_plugins_apply = QtWidgets.QPushButton("Apply changes (save config + restart)")
        self.btn_plugins_apply.clicked.connect(self.on_plugins_apply)

        top.addWidget(self.btn_plugins_refresh)
        top.addWidget(self.btn_plugins_apply)
        top.addStretch(1)

        self.plugins_table = QtWidgets.QTableWidget(0, 3)
        self.plugins_table.setHorizontalHeaderLabels(["Plugin", "Installed", "Enabled"])
        self.plugins_table.horizontalHeader().setStretchLastSection(True)
        self.plugins_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.plugins_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)

        l.addLayout(top)
        l.addWidget(self.plugins_table, 1)

        self.tabs.addTab(w, "Plugins")

    def _init_profiles(self):
        """Populate the combo from the store and load the active profile."""
        if not self.store.profiles:
            # First run: seed a profile from the built-in defaults so the
            # user has something to edit and connection params persist.
            seed = self._widgets_to_profile("default")
            self.store.upsert(seed)
            self.store.active_name = seed.name
            try:
                self.store.save()
            except OSError as e:
                self._log(f"[WARN] Could not write profiles file: {e}")
        self._refresh_profile_combo(select=self.store.active_name)

    def _refresh_profile_combo(self, select: str = ""):
        self._loading_profile = True
        self.profile_combo.clear()
        for name in self.store.names():
            self.profile_combo.addItem(name)
        self.profile_combo.addItem(MANUAL_PROFILE_LABEL)
        self._loading_profile = False

        idx = self.profile_combo.findText(select) if select else -1
        if idx < 0:
            idx = 0 if self.store.names() else self.profile_combo.findText(MANUAL_PROFILE_LABEL)
        self.profile_combo.setCurrentIndex(idx)
        # findText/setCurrentIndex may not emit if index unchanged; force load.
        self._on_profile_selected(self.profile_combo.currentIndex())

    def _apply_profile_to_widgets(self, p: ConnectionProfile):
        self.host.setText(p.host)
        self.port.setValue(int(p.port or 22))
        self.user.setText(p.username)
        self.passwd.setText(p.password)
        self.keypath.setText(p.key_path)
        if p.lcd_url:
            self.lcd_url.setText(p.lcd_url)
        if p.lcd_user:
            self.lcd_user.setText(p.lcd_user)
        if p.lcd_pass:
            self.lcd_pass.setText(p.lcd_pass)

    def _widgets_to_profile(self, name: str) -> ConnectionProfile:
        return ConnectionProfile(
            name=name,
            host=self.host.text().strip(),
            port=int(self.port.value()),
            username=self.user.text().strip(),
            password=self.passwd.text(),
            key_path=self.keypath.text().strip(),
            lcd_url=self.lcd_url.text().strip(),
            lcd_user=self.lcd_user.text(),
            lcd_pass=self.lcd_pass.text(),
        )

    def _on_profile_selected(self, idx: int):
        if self._loading_profile or idx < 0:
            return
        name = self.profile_combo.itemText(idx)
        if name == MANUAL_PROFILE_LABEL:
            self.store.active_name = ""
            return
        p = self.store.get(name)
        if p is None:
            return

        if self._connected:
            if QtWidgets.QMessageBox.question(
                self, "Switch profile",
                f"Disconnect the current device and load profile '{name}'?",
            ) != QtWidgets.QMessageBox.StandardButton.Yes:
                # revert selection without reloading
                self._loading_profile = True
                prev = self.profile_combo.findText(self.store.active_name)
                if prev >= 0:
                    self.profile_combo.setCurrentIndex(prev)
                self._loading_profile = False
                return
            self.on_disconnect()

        self._apply_profile_to_widgets(p)
        self.store.active_name = name
        self._log(f"Loaded profile '{name}' ({p.username}@{p.host}:{p.port}).")

    def _on_profile_save(self):
        names = self.store.names()
        current = self.profile_combo.currentText()
        default_name = current if current in names else ""
        name, ok = QtWidgets.QInputDialog.getText(
            self, "Save profile",
            "Profile name (existing name overwrites):",
            text=default_name,
        )
        if not ok:
            return
        name = name.strip()
        if not name or name == MANUAL_PROFILE_LABEL:
            QtWidgets.QMessageBox.warning(self, "Invalid name", "Please enter a valid profile name.")
            return
        self.store.upsert(self._widgets_to_profile(name))
        self.store.active_name = name
        try:
            self.store.save()
        except OSError as e:
            QtWidgets.QMessageBox.critical(self, "Save failed", f"Could not write profiles file:\n{e}")
            return
        self._refresh_profile_combo(select=name)
        self._log(f"Saved profile '{name}' to {self.store.path}")

    def _on_profile_manage(self):
        dlg = ProfileManagerDialog(self.store, parent=self)
        if dlg.exec():
            self._refresh_profile_combo(select=dlg.selected_name)
            self._log(f"Profiles updated ({len(self.store.names())} saved).")

    def connect_profile_by_name(self, name: str):
        """Select a profile and connect (called from the Fleet tab)."""
        idx = self.profile_combo.findText(name)
        if idx < 0:
            return
        # Selecting handles the disconnect-confirm + field load.
        self.profile_combo.setCurrentIndex(idx)
        if self.store.active_name != name:
            return  # user declined to switch
        if self._connected:
            return  # already on this device
        self.on_connect()
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == "Status":
                self.tabs.setCurrentIndex(i)
                break

    def closeEvent(self, event):
        # Persist edits made to the active profile's fields on exit.
        active = self.store.active_name
        if active and self.store.get(active) is not None:
            self.store.upsert(self._widgets_to_profile(active))
        try:
            self.store.save()
        except OSError as e:
            self._log(f"[WARN] Could not write profiles file: {e}")
        super().closeEvent(event)

    def _pick_key(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select SSH private key", os.path.expanduser("~"))
        if path:
            self.keypath.setText(path)

    def _set_connected(self, ok: bool):
        self._connected = ok

        self.btn_connect.setEnabled(not ok)
        self.btn_disconnect.setEnabled(ok)
        fleet = getattr(self, "_fleet_container", None)
        for i in range(self.tabs.count()):
            wdg = self.tabs.widget(i)
            # Fleet works against saved profiles, not the active session.
            wdg.setEnabled(True if wdg is fleet else ok)
        self.status.showMessage("Connected" if ok else "Disconnected")

        if hasattr(self, "_lcd_web_timer"):
            if ok:
                # restore state according to checkbox
                self._lcd_web_autoreload_changed()
            else:
                self._lcd_web_timer.stop()

        if hasattr(self, "lcd_web"):
            if ok:
                # show a placeholder when connected (until you open a URL)
                self.lcd_web.setHtml(
                    """
                    <html>
                      <body style="background:#000;color:#cfd8dc;font-family:monospace;
                                   padding:24px; display:flex; flex-direction:column;
                                   align-items:center; justify-content:center; height:100vh;">
                        <div style="font-size:44px;font-weight:800; margin-bottom:12px;">
                          Connected
                        </div>
                        <div style="font-size:22px; line-height:1.35; opacity:0.9; text-align:center;">
                          Open the LCD web URL to start streaming.
                        </div>
                      </body>
                    </html>
                    """
                )
                self._lcd_apply_zoom(True)
            else:
                # truly blank while disconnected (no stale page)
                self.lcd_web.setHtml("<html><body style='background:#000;'></body></html>")

    def _log(self, msg: str):
        if hasattr(self, "console") and self.console is not None:
            self.console.appendPlainText(msg)
        else:
            print(msg)

    def on_connect(self):
        host = self.host.text().strip()
        port = int(self.port.value())
        user = self.user.text().strip()
        pw = self.passwd.text()
        key = self.keypath.text().strip()

        self._log(f"Connecting to {user}@{host}:{port} ...")

        def do():
            self.ssh.connect(host=host, port=port, username=user, password=pw, key_path=key)
            return True

        def done(res, err):
            if err:
                self._log(f"[ERROR] {err}")
                QtWidgets.QMessageBox.critical(self, "Connect failed", str(err))
                self._set_connected(False)
                return
            self._set_connected(True)
            self._log("Connected.")
            self.on_refresh()
            # refresh file manager after connect
            if hasattr(self, "fileman"):
                self.fileman.refresh()

        run_in_thread(self, do, done)

    def on_disconnect(self):
        self.ssh.close()
        self._set_connected(False)
        self._log("Disconnected.")

    def on_refresh(self):
        def do():
            cmds = [
                "hostname",
                "uptime -p || uptime",
                "uname -a",
                "df -h / | tail -n 1",
                "ip -4 addr show | grep -E 'inet ' || true",
                "systemctl is-active pwnagotchi 2>/dev/null || service pwnagotchi status 2>/dev/null || true",
            ]
            out = []
            for c in cmds:
                r = self.ssh.run(c)
                text = r.stdout.strip() if r.stdout.strip() else r.stderr.strip()
                out.append(f"$ {c}\n{text}\n")
            return "\n".join(out)

        def done(res, err):
            if err:
                self._log(f"[ERROR] {err}")
                return
            self.info.setPlainText(res)
            self._log("Refreshed device info.")

        run_in_thread(self, do, done)

    def _svc(self, action: str):
        name = self.service_name.currentText().strip()

        def do():
            cmd = (
                f"sudo systemctl {action} {name} || "
                f"sudo service {name} {action} || "
                f"systemctl {action} {name} || "
                f"service {name} {action}"
            )
            r = self.ssh.run(cmd, timeout_sec=20)
            return f"$ {cmd}\n\n{r.stdout}\n{r.stderr}".strip()

        def done(res, err):
            if err:
                self._log(f"[ERROR] {err}")
                return
            self.svc_out.setPlainText(res)
            self._log(f"Service {name}: {action}")

        run_in_thread(self, do, done)

    def on_logs(self):
        mode = self.log_mode.currentIndex()
        n = int(self.log_lines.value())

        def do():
            if mode == 0:
                cmd = f"tail -n {n} /var/log/pwnagotchi.log 2>/dev/null || tail -n {n} /var/log/syslog"
            else:
                cmd = f"journalctl -u pwnagotchi -n {n} --no-pager 2>/dev/null || true"
            r = self.ssh.run(cmd, timeout_sec=20)
            return r.stdout if r.stdout else r.stderr

        def done(res, err):
            if err:
                self._log(f"[ERROR] {err}")
                return
            self.logs.setPlainText(res)
            self._log("Fetched logs.")

        run_in_thread(self, do, done)

    def on_cfg_load(self):
        path = self.cfg_path.text().strip()

        def do():
            r = self.ssh.run(f"sudo cat {path} || cat {path}", timeout_sec=20)
            if r.exit_status != 0 and not r.stdout:
                raise RuntimeError(r.stderr.strip() or "Failed to read config")
            return r.stdout

        def done(res, err):
            if err:
                self._log(f"[ERROR] {err}")
                QtWidgets.QMessageBox.critical(self, "Load failed", str(err))
                return
            self.cfg_editor.setPlainText(res)
            self._log(f"Loaded config: {path}")

        run_in_thread(self, do, done)

    def on_cfg_save(self):
        path = self.cfg_path.text().strip()
        content = self.cfg_editor.toPlainText()

        def do():
            tmp = "/tmp/pwnagotchi_config.toml"
            bak = f"{path}.bak.$(date +%Y%m%d-%H%M%S)"
            safe = content.replace("\\", "\\\\").replace("$", "\\$").replace("`", "\\`")
            cmd = (
                f"cat > {tmp} <<'EOF'\n{safe}\nEOF\n"
                f"sudo cp -a {path} {bak} 2>/dev/null || true\n"
                f"sudo mv {tmp} {path} || mv {tmp} {path}\n"
            )
            r = self.ssh.run(f"bash -lc {quote_bash(cmd)}", timeout_sec=25)
            if r.exit_status != 0:
                raise RuntimeError((r.stderr or r.stdout).strip() or "Failed to save config")
            return "Saved (backup attempted)."

        def done(res, err):
            if err:
                self._log(f"[ERROR] {err}")
                QtWidgets.QMessageBox.critical(self, "Save failed", str(err))
                return
            self._log(res)
            QtWidgets.QMessageBox.information(self, "Saved", "Config saved. Consider restarting pwnagotchi service.")

        run_in_thread(self, do, done)

    def on_plugins_refresh(self):
        cfg_path = self.cfg_path.text().strip()

        def do():
            cfg = self.ssh.run(f"sudo cat {cfg_path} || cat {cfg_path}", timeout_sec=20).stdout
            enabled_map = extract_enabled_from_toml(cfg)

            found = set()
            for d in PLUGIN_DIR_CANDIDATES:
                r = self.ssh.run(f"ls -1 {d} 2>/dev/null || true")
                for name in parse_plugins_from_ls(r.stdout):
                    found.add(name)

            return cfg, sorted(found), enabled_map

        def done(res, err):
            if err:
                self._log(f"[ERROR] {err}")
                return

            _, installed, enabled_map = res
            all_names = sorted(set(installed) | set(enabled_map.keys()))

            self.plugins_table.setRowCount(0)
            for i, name in enumerate(all_names):
                self.plugins_table.insertRow(i)

                item_name = QtWidgets.QTableWidgetItem(name)
                item_inst = QtWidgets.QTableWidgetItem("yes" if name in installed else "no")
                item_inst.setFlags(item_inst.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)

                chk = QtWidgets.QTableWidgetItem()
                chk.setFlags(chk.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable)
                chk.setCheckState(
                    QtCore.Qt.CheckState.Checked if enabled_map.get(name, False) else QtCore.Qt.CheckState.Unchecked
                )

                self.plugins_table.setItem(i, 0, item_name)
                self.plugins_table.setItem(i, 1, item_inst)
                self.plugins_table.setItem(i, 2, chk)

            self._log(f"Plugins refreshed: {len(all_names)} shown.")

        run_in_thread(self, do, done)

    def on_plugins_apply(self):
        cfg_path = self.cfg_path.text().strip()

        desired = {}
        for row in range(self.plugins_table.rowCount()):
            name = self.plugins_table.item(row, 0).text()
            chk = self.plugins_table.item(row, 2)
            desired[name] = (chk.checkState() == QtCore.Qt.CheckState.Checked)

        def do():
            cfg = self.ssh.run(f"sudo cat {cfg_path} || cat {cfg_path}", timeout_sec=20).stdout
            for name, en in desired.items():
                cfg = set_plugin_enabled_in_toml(cfg, name, en)

            tmp = "/tmp/pwnagotchi_config.toml"
            bak = f"{cfg_path}.bak.$(date +%Y%m%d-%H%M%S)"
            safe = cfg.replace("\\", "\\\\").replace("$", "\\$").replace("`", "\\`")
            script = (
                f"cat > {tmp} <<'EOF'\n{safe}\nEOF\n"
                f"sudo cp -a {cfg_path} {bak} 2>/dev/null || true\n"
                f"sudo mv {tmp} {cfg_path} || mv {tmp} {cfg_path}\n"
                f"sudo systemctl restart pwnagotchi || sudo service pwnagotchi restart || true\n"
            )
            r = self.ssh.run(f"bash -lc {quote_bash(script)}", timeout_sec=30)
            return (r.stdout + "\n" + r.stderr).strip() or "Applied."

        def done(res, err):
            if err:
                self._log(f"[ERROR] {err}")
                QtWidgets.QMessageBox.critical(self, "Apply failed", str(err))
                return
            self._log("Applied plugin config changes.")
            self._log(res)
            QtWidgets.QMessageBox.information(self, "Done", "Plugin settings applied. Service restart attempted.")

        run_in_thread(self, do, done)

    def on_reboot(self):
        if QtWidgets.QMessageBox.question(self, "Reboot", "Reboot the device now?") != QtWidgets.QMessageBox.StandardButton.Yes:
            return

        def do():
            return (self.ssh.run("sudo reboot || reboot", timeout_sec=5).stdout or "").strip()

        def done(res, err):
            if err:
                self._log(f"[ERROR] {err}")
                return
            self._log("Reboot command sent. Connection will drop.")
            self.on_disconnect()

        run_in_thread(self, do, done)

    def on_shutdown(self):
        if QtWidgets.QMessageBox.question(self, "Shutdown", "Shutdown the device now?") != QtWidgets.QMessageBox.StandardButton.Yes:
            return

        def do():
            return (self.ssh.run("sudo shutdown -h now || shutdown -h now", timeout_sec=5).stdout or "").strip()

        def done(res, err):
            if err:
                self._log(f"[ERROR] {err}")
                return
            self._log("Shutdown command sent. Connection will drop.")
            self.on_disconnect()

        run_in_thread(self, do, done)

    def _tab_ssh(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)

        self.term = SSHTerminalWidget(self.ssh, parent=self)
        self.term.log.connect(self._log)
        l.addWidget(self.term, 1)

        self.tabs.addTab(w, "SSH")

    def _tab_export(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)

        self.export_tab = ExportFolderTab(self.ssh, parent=self)
        self.export_tab.log.connect(self._log)
        l.addWidget(self.export_tab, 1)

        self.tabs.addTab(w, "Export")

    def _tab_fleet(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)
        self.fleet_tab = FleetTab(self.store, main_window=self, parent=self)
        l.addWidget(self.fleet_tab, 1)
        self._fleet_container = w
        self.tabs.addTab(w, "Fleet")

