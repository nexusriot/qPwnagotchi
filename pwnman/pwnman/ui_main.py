from __future__ import annotations

import os
from typing import Optional

from PyQt6 import QtCore, QtGui, QtWidgets

from pwnman.pwnman.ssh_client import SSHClient  # noqa: F401
from pwnman.pwnman.session import Session, CONNECTED, RECONNECTING, DISCONNECTED, CONNECTING
from pwnman.pwnman.known_hosts import HostKeyError, KnownHosts
from pwnman.pwnman import settings as app_settings
from pwnman.pwnman.ssh_terminal import SSHTerminalWidget
from pwnman.pwnman.export_folder_tab import ExportFolderTab
from pwnman.pwnman.file_manager import FileManagerWidget
from pwnman.pwnman.async_utils import shutdown_threads
from pwnman.pwnman.models import ConnectionProfile
from pwnman.pwnman.profile_store import ProfileStore
from pwnman.pwnman.profile_dialog import ProfileManagerDialog
from pwnman.pwnman.fleet_tab import FleetTab
from pwnman.pwnman.dashboard_tab import DashboardTab
from pwnman.pwnman.handshakes_tab import HandshakesTab
from pwnman.pwnman.live_log_tab import LiveLogTab
from pwnman.pwnman.details_tab import DetailsTab
from pwnman.pwnman.services_tab import ServicesTab
from pwnman.pwnman.logs_tab import LogsTab
from pwnman.pwnman.config_tab import ConfigTab
from pwnman.pwnman.plugins_tab import PluginsTab
from pwnman.pwnman.power_tab import PowerTab
from pwnman.pwnman.lcd_tab import LcdTab
from pwnman.pwnman.metrics_store import MetricsStore
from pwnman.pwnman.metrics_tab import MetricsTab
from pwnman.pwnman import theme
from pwnman.pwnman.dialogs import AboutDialog
from pwnman.pwnman.nav_tabs import NavTabs
from pwnman.pwnman.pty_terminal import PtyTerminalTab
from pwnman.pwnman.alerts import AlertEngine
from pwnman.pwnman.discovery_dialog import DiscoveryDialog
from pwnman.pwnman.resources import app_icon
from pwnman.pwnman.plugins_toml import (  # noqa: F401 - re-exported for callers/tests
    parse_plugins_from_ls,
    extract_enabled_from_toml,
    set_plugin_enabled_in_toml,
)
from pwnman.pwnman.version import __version__ as APP_VERSION
APP_HOME_URL = "https://github.com/evilsocket/pwnagotchi"

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


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, profile: Optional[str] = None, connect: bool = False):
        super().__init__()
        self.setWindowTitle(f"Pwnagotchi Manager v.{APP_VERSION}")
        self.resize(980, 700)
        icon = app_icon()
        if not icon.isNull():
            self.setWindowIcon(icon)

        self.session = Session(self)
        self.ssh = self.session.ssh
        self._connected = False
        self._connected_profile = ""

        self.store = ProfileStore(secrets="auto")
        self.metrics = MetricsStore()
        try:
            self.metrics.prune()
        except Exception:  # noqa: BLE001 - history is a convenience, never fatal
            pass
        self._loading_profile = False

        self._build_menus()
        self._build_ui()
        self._wire_session()
        self._setup_tray()
        self.fleet_tab.statusUpdated.connect(self.on_status_sample)
        self.dashboard.statusUpdated.connect(self.on_status_sample)
        self._set_connected(False)
        self._init_profiles()
        geo = app_settings.get("window/geometry")
        if geo is not None:
            self.restoreGeometry(geo)
        self._autoconnect_pending = connect
        if profile and self.store.get(profile) is not None:
            self._refresh_profile_combo(select=profile)
        elif self.store.active() is not None and self.store.active().auto_connect:
            self._autoconnect_pending = True
        if self._autoconnect_pending:
            QtCore.QTimer.singleShot(0, self.on_connect)

    def _build_menus(self):
        mb = self.menuBar()
        # Some Linux desktops (Unity/Gnome) hide menubars by default; force
        # an in-window menubar so the menu is always visible.
        mb.setNativeMenuBar(False)

        m_file = mb.addMenu("&File")

        act_manage = QtGui.QAction("Manage &profiles…", self)
        act_manage.setShortcut(QtGui.QKeySequence("Ctrl+P"))
        act_manage.triggered.connect(self._on_profile_manage)
        m_file.addAction(act_manage)

        act_save = QtGui.QAction("&Save current as profile…", self)
        act_save.setShortcut(QtGui.QKeySequence("Ctrl+S"))
        act_save.triggered.connect(self._on_profile_save)
        m_file.addAction(act_save)

        act_discover = QtGui.QAction("&Discover devices…", self)
        act_discover.triggered.connect(self._on_discover)
        m_file.addAction(act_discover)

        m_file.addSeparator()

        act_connect = QtGui.QAction("&Connect", self)
        act_connect.setShortcut(QtGui.QKeySequence("Ctrl+Return"))
        act_connect.triggered.connect(self.on_connect)
        m_file.addAction(act_connect)

        act_disconnect = QtGui.QAction("&Disconnect", self)
        act_disconnect.triggered.connect(self.on_disconnect)
        m_file.addAction(act_disconnect)

        m_file.addSeparator()

        act_quit = QtGui.QAction("&Quit", self)
        act_quit.setShortcut(QtGui.QKeySequence.StandardKey.Quit)
        act_quit.triggered.connect(self.close)
        m_file.addAction(act_quit)

        m_view = mb.addMenu("&View")
        m_theme = m_view.addMenu("&Theme")
        grp = QtGui.QActionGroup(self)
        self._theme_actions = {}
        for mode in theme.MODES:
            a = QtGui.QAction(theme.LABELS[mode], self, checkable=True)
            a.setChecked(mode == theme.get_mode())
            a.triggered.connect(lambda _=False, m=mode: self.set_theme(m))
            grp.addAction(a)
            m_theme.addAction(a)
            self._theme_actions[mode] = a
        self._act_notify = QtGui.QAction("Desktop &notifications", self, checkable=True)
        self._act_notify.setChecked(app_settings.get("notifications", True, bool))
        self._act_notify.toggled.connect(lambda v: app_settings.put("notifications", v))
        # Tab-jump shortcuts (Ctrl+1..9) are wired up after tabs exist.
        self._menu_view = m_view

        m_help = mb.addMenu("&Help")

        act_about = QtGui.QAction("&About qPwnagotchi", self)
        act_about.triggered.connect(self._on_about)
        m_help.addAction(act_about)

        act_about_qt = QtGui.QAction("About &Qt", self)
        act_about_qt.triggered.connect(
            lambda: QtWidgets.QMessageBox.aboutQt(self, "About Qt")
        )
        m_help.addAction(act_about_qt)

    def _populate_view_menu(self):
        """Fill the View menu with one action per tab. Called after tabs exist."""
        m = getattr(self, "_menu_view", None)
        if m is None:
            return
        m.clear()
        m.addAction(self._act_notify)
        m.addSeparator()
        for i in range(self.tabs.count()):
            label = self.tabs.tabText(i)
            act = QtGui.QAction(f"&{i+1}  {label}", self)
            if i < 9:
                act.setShortcut(QtGui.QKeySequence(f"Ctrl+{i+1}"))
            act.triggered.connect(lambda _=False, idx=i: self.tabs.setCurrentIndex(idx))
            m.addAction(act)

    def set_theme(self, mode: str):
        theme.apply(QtWidgets.QApplication.instance(), mode, persist=True)
        if mode in self._theme_actions:
            self._theme_actions[mode].setChecked(True)
        self.fleet_tab.restyle()
        self._log(f"Theme: {theme.LABELS.get(mode, mode)}")

    def _on_discover(self):
        dlg = DiscoveryDialog(self)
        if dlg.exec() and dlg.selected_host:
            host = dlg.selected_host
            name, ok = QtWidgets.QInputDialog.getText(
                self, "New profile", "Profile name:", text=host)
            if ok and name.strip():
                p = ConnectionProfile(name=name.strip(), host=host,
                                      lcd_url=f"http://{host}:8080/")
                self.store.upsert(p)
                self.store.active_name = p.name
                try:
                    self.store.save()
                except OSError as e:
                    self._log(f"[WARN] Could not write profiles file: {e}")
                self._refresh_profile_combo(select=p.name)

    def _setup_tray(self):
        self.alerts = AlertEngine()
        self.tray = None
        if not QtWidgets.QSystemTrayIcon.isSystemTrayAvailable():
            return
        icon = app_icon()
        self.tray = QtWidgets.QSystemTrayIcon(icon, self)
        menu = QtWidgets.QMenu()
        menu.addAction("Show", self._show_from_tray)
        self._tray_profiles = menu.addMenu("Connect to")
        menu.aboutToShow.connect(self._fill_tray_profiles)
        menu.addSeparator()
        menu.addAction("Quit", self.close)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(lambda r: self._show_from_tray()
                                    if r == QtWidgets.QSystemTrayIcon.ActivationReason.Trigger else None)
        self.tray.show()

    def _fill_tray_profiles(self):
        self._tray_profiles.clear()
        for n in self.store.names():
            self._tray_profiles.addAction(n, lambda n=n: self.connect_profile_by_name(n))

    def _show_from_tray(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def notify(self, title: str, text: str):
        """Desktop notification (tray balloon) if enabled; always logged."""
        self._log(f"[alert] {text}")
        if self._act_notify.isChecked() and self.tray is not None:
            self.tray.showMessage(title, text, QtWidgets.QSystemTrayIcon.MessageIcon.Information, 8000)

    def on_status_sample(self, st):
        try:
            self.metrics.record(st)
        except Exception as e:  # noqa: BLE001
            self._log(f"[WARN] metrics: {e}")
        for a in self.alerts.update(st):
            self.notify("qPwnagotchi", a.text)

    def _on_about(self):
        dlg = AboutDialog(self)
        dlg.exec()

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

        self.chk_autoconnect = QtWidgets.QCheckBox("Connect on launch")
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
        btns.addWidget(self.chk_autoconnect)
        btns.addStretch(1)
        conn_l.addLayout(btns, row, 0, 1, 4)

        layout.addWidget(conn)

        self.console = QtWidgets.QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(2000)
        self.console.setPlaceholderText("Console")

        self.tabs = NavTabs()
        self.tabs.currentChanged.connect(self._on_tab_changed)
        split = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)
        split.addWidget(self.tabs)
        split.addWidget(self.console)
        split.setStretchFactor(0, 4)
        split.setStretchFactor(1, 1)
        split.setCollapsible(0, False)
        layout.addWidget(split, 1)

        self._tab_dashboard()
        self.history = MetricsTab(self.metrics, parent=self)
        self.history.log.connect(self._log)
        self.tabs.addTab(self.history, "History")
        self._tab_lcd()

        # then the rest
        self._tab_simple_tabs()
        self._tab_files()
        self._tab_handshakes()
        self._tab_export()
        self._tab_power()
        self._tab_terminal()
        self._tab_ssh()
        self._tab_plugins()
        self._tab_fleet()


        # restore the last tab (default: Dashboard)
        idx = app_settings.get("window/tab", 0, int)
        self.tabs.setCurrentIndex(idx if 0 <= idx < self.tabs.count() else 0)

        self.status = QtWidgets.QStatusBar()
        self.setStatusBar(self.status)

        # Fill the View menu now that the tabs exist.
        self._populate_view_menu()

    def _tab_dashboard(self):
        self.dashboard = DashboardTab(self.session, self._dashboard_profile, parent=self)
        self.dashboard.log.connect(self._log)
        self.tabs.addTab(self.dashboard, "Dashboard")

    def _dashboard_profile(self) -> ConnectionProfile:
        p = self._widgets_to_profile(self.profile_combo.currentText() or "active")
        # The LCD URL field still holds the factory placeholder when the user
        # only typed a host: point the REST probe at that host instead.
        if p.lcd_url in ("", "http://10.0.0.2:8080/") and p.host not in ("", "10.0.0.2"):
            p.lcd_url = f"http://{p.host}:8080/"
        return p

    def _tab_livelog(self):
        self.livelog = LiveLogTab(self.ssh, parent=self)
        self.livelog.log.connect(self._log)
        self.tabs.addTab(self.livelog, "Live log")

    def _tab_handshakes(self):
        self.handshakes = HandshakesTab(self.ssh, parent=self)
        self.handshakes.log.connect(self._log)
        self.tabs.addTab(self.handshakes, "Handshakes")

    def _tab_lcd(self):
        self.lcd = LcdTab(lambda: self.store.active_name, parent=self)
        self.lcd.log.connect(self._log)
        self.tabs.addTab(self.lcd, "LCD")

    def _on_tab_changed(self, idx: int):
        label = self.tabs.tabText(idx)
        if label == "Terminal" and self._connected:
            self.pty.start()
        elif label == "LCD":
            self.lcd.on_shown()

    def _tab_simple_tabs(self):
        self.details = DetailsTab(self.ssh, parent=self)
        self.services = ServicesTab(self.ssh, parent=self)
        self.logs_tab = LogsTab(self.ssh, parent=self)
        self.config = ConfigTab(self.ssh, parent=self)
        self.config.statusMessage.connect(lambda m: self.status.showMessage(m, 4000))
        for t, label in ((self.details, "Details"), (self.services, "Services"),
                         (self.logs_tab, "Logs")):
            self.tabs.addTab(t, label)
            t.log.connect(self._log)
        self._tab_livelog()
        self.tabs.addTab(self.config, "Config")
        self.config.log.connect(self._log)

    def _tab_files(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)

        self.fileman = FileManagerWidget(self.ssh, parent=self)
        self.fileman.log.connect(self._log)
        l.addWidget(self.fileman, 1)

        self.tabs.addTab(w, "Files")

    def _tab_power(self):
        self.power = PowerTab(self.ssh, parent=self)
        self.power.log.connect(self._log)
        self.power.droppedConnection.connect(self._on_device_going_away)
        self.tabs.addTab(self.power, "Power")

    def _on_device_going_away(self):
        self.session.expect_drop()
        self._log("Disconnected.")

    def _tab_plugins(self):
        self.plugins = PluginsTab(self.ssh, lambda: self.config.path, parent=self)
        self.plugins.log.connect(self._log)
        self.tabs.addTab(self.plugins, "Plugins")

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
        # Programmatic refresh (after save / profile manager): load silently.
        # Going through _on_profile_selected would ask "disconnect?" even
        # though the user only saved the profile they are connected with.
        self._loading_profile = True
        self.profile_combo.setCurrentIndex(idx)
        self._loading_profile = False
        name = self.profile_combo.itemText(idx)
        if name == MANUAL_PROFILE_LABEL:
            self.store.active_name = ""
            return
        p = self.store.get(name)
        if p is not None:
            self._apply_profile_to_widgets(p)
            self.store.active_name = name
            self._log(f"Loaded profile '{name}' ({p.username}@{p.host}:{p.port}).")
            self.lcd.load_prefs()

    def _apply_profile_to_widgets(self, p: ConnectionProfile):
        self.host.setText(p.host)
        self.port.setValue(int(p.port or 22))
        self.user.setText(p.username)
        self.passwd.setText(p.password)
        self.keypath.setText(p.key_path)
        self.chk_autoconnect.setChecked(bool(p.auto_connect))
        # Always overwrite: leaving the previous profile's LCD URL/credentials
        # in place would show (and authenticate against) the wrong device.
        self.lcd.url.setText(p.lcd_url or (f"http://{p.host}:8080/" if p.host else ""))
        self.lcd.user.setText(p.lcd_user or "changeme")
        self.lcd.password.setText(p.lcd_pass or "changeme")

    def _widgets_to_profile(self, name: str) -> ConnectionProfile:
        return ConnectionProfile(
            name=name,
            host=self.host.text().strip(),
            port=int(self.port.value()),
            username=self.user.text().strip(),
            password=self.passwd.text(),
            key_path=self.keypath.text().strip(),
            lcd_url=self.lcd.url.text().strip(),
            lcd_user=self.lcd.user.text(),
            lcd_pass=self.lcd.password.text(),
            auto_connect=self.chk_autoconnect.isChecked(),
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
        self.lcd.load_prefs()

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
            if self.tabs.tabText(i) == "Dashboard":
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
        app_settings.put("window/geometry", self.saveGeometry())
        app_settings.put("window/tab", self.tabs.currentIndex())
        self.livelog.stop()
        self.pty.stop()
        self.session.disconnect_now()
        shutdown_threads()
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
        self.lcd.set_connected(ok)

    def _log(self, msg: str):
        if hasattr(self, "console") and self.console is not None:
            self.console.appendPlainText(msg)
        else:
            print(msg)

    def on_connect(self):
        if self.session.state in (CONNECTING, CONNECTED):
            return
        host = self.host.text().strip()
        port = int(self.port.value())
        user = self.user.text().strip()
        self._log(f"Connecting to {user}@{host}:{port} ...")
        self._conn_params = dict(host=host, port=port, username=user,
                                 password=self.passwd.text(),
                                 key_path=self.keypath.text().strip())
        self.session.connect_to(**self._conn_params)

    def on_disconnect(self):
        self.session.disconnect_now()
        self._log("Disconnected.")

    # -- session signal handlers ------------------------------------------
    def _wire_session(self):
        self.session.stateChanged.connect(self._on_session_state)
        self.session.message.connect(self._log)
        self.session.failed.connect(self._on_connect_failed)
        self.session.hostKeyProblem.connect(self._on_host_key_problem)

    def _on_session_state(self, state: str):
        if state == CONNECTED:
            first = not getattr(self, "_was_connected_once", False) or self._connected_profile != self.store.active_name
            self._was_connected_once = True
            self._connected_profile = self.store.active_name
            self._set_connected(True)
            self._log("Connected.")
            self.details.refresh()
            self.dashboard.refresh()
            if hasattr(self, "fileman"):
                if first or not self.fileman._remote_home_resolved:
                    self.fileman.reset_remote()
                self.fileman.refresh()
        elif state == RECONNECTING:
            self.livelog.stop()
            self.pty.stop()
            self._set_connected(False)
            self.status.showMessage("Connection lost — reconnecting…")
        elif state == DISCONNECTED:
            self.livelog.stop()
            self.pty.stop()
            self._set_connected(False)

    def _on_connect_failed(self, err: str):
        self._log(f"[ERROR] {err}")
        QtWidgets.QMessageBox.critical(self, "Connect failed", err)

    def _on_host_key_problem(self, e: HostKeyError):
        kh = self.session.known_hosts or KnownHosts()
        if e.kind == "unknown":
            ans = QtWidgets.QMessageBox.question(
                self, "Unknown host key",
                f"First connection to {e.host}:{e.port}.\n\n"
                f"Key type: {e.key.get_name()}\nFingerprint: {e.fingerprint}\n\n"
                "Verify this fingerprint (e.g. on the device) and trust it?")
            if ans == QtWidgets.QMessageBox.StandardButton.Yes:
                kh.trust(e.host, e.port, e.key)
                self._log(f"Trusted host key {e.fingerprint} for {e.host}.")
                self.on_connect()
            else:
                self._log("Connection cancelled: host key not trusted.")
            return
        box = QtWidgets.QMessageBox(self)
        box.setIcon(QtWidgets.QMessageBox.Icon.Warning)
        box.setWindowTitle("HOST KEY CHANGED")
        box.setText(
            f"The host key of {e.host}:{e.port} has CHANGED.\n\n"
            f"Known:  {e.old_fingerprint or '?'}\nNow:      {e.fingerprint}\n\n"
            "This can mean the device was re-flashed — or that someone is "
            "intercepting the connection. Connection refused.")
        replace = box.addButton("Replace key and connect",
                                QtWidgets.QMessageBox.ButtonRole.DestructiveRole)
        box.addButton(QtWidgets.QMessageBox.StandardButton.Cancel)
        box.exec()
        if box.clickedButton() is replace:
            kh.trust(e.host, e.port, e.key, replace=True)
            self._log(f"Replaced host key for {e.host} ({e.fingerprint}).")
            self.on_connect()

    def _tab_terminal(self):
        self.pty = PtyTerminalTab(self.ssh, parent=self)
        self.pty.log.connect(self._log)
        self.tabs.addTab(self.pty, "Terminal")

    def _tab_ssh(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)

        self.term = SSHTerminalWidget(self.ssh, parent=self)
        self.term.log.connect(self._log)
        l.addWidget(self.term, 1)

        self.tabs.addTab(w, "Quick cmd")

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
