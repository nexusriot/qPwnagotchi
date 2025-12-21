from __future__ import annotations

import os
from PyQt6 import QtCore, QtGui, QtWidgets

from pwnman.pwnman.ssh_client import SSHClient
import re

PLUGIN_DIR_CANDIDATES = [
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
        # accept *.py filenames
        if line.endswith(".py"):
            base = line[:-3]
            if base and base != "__init__":
                names.append(base)
    return sorted(set(names))


def extract_enabled_from_toml(toml_text: str) -> dict[str, bool]:
    """
    Detect patterns like:
      main.plugins.foo.enabled = true
    or table form:
      [main.plugins.foo]
      enabled = true
    """
    enabled = {}
    # dotted form
    for m in re.finditer(r"^\s*main\.plugins\.([a-zA-Z0-9_\-]+)\.enabled\s*=\s*(true|false)\s*$",
                         toml_text, flags=re.MULTILINE):
        enabled[m.group(1)] = (m.group(2) == "true")

    # table form
    # [main.plugins.foo]
    # enabled = true
    for m in re.finditer(r"^\s*\[main\.plugins\.([a-zA-Z0-9_\-]+)\]\s*$", toml_text, flags=re.MULTILINE):
        name = m.group(1)
        # search forward a bit for enabled=
        start = m.end()
        chunk = toml_text[start:start+800]  # enough for small blocks
        m2 = re.search(r"^\s*enabled\s*=\s*(true|false)\s*$", chunk, flags=re.MULTILINE)
        if m2:
            enabled[name] = (m2.group(1) == "true")

    return enabled


def set_plugin_enabled_in_toml(toml_text: str, plugin: str, enabled: bool) -> str:
    import re
    val = "true" if enabled else "false"

    dotted = re.compile(rf"^(\s*main\.plugins\.{re.escape(plugin)}\.enabled\s*=\s*)(true|false)\s*$",
                        flags=re.MULTILINE)
    if dotted.search(toml_text):
        return dotted.sub(rf"\1{val}", toml_text)

    table = re.compile(rf"^\s*\[main\.plugins\.{re.escape(plugin)}\]\s*$", flags=re.MULTILINE)
    m = table.search(toml_text)
    if m:
        # within the block until next [section] or EOF
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
            res = self._fn(*self._args, **self._kwargs)
            self.finished.emit(res, None)
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


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Pwnagotchi Manager (Maintenance)")
        self.resize(980, 700)

        self.ssh = SSHClient()

        self._build_ui()
        self._set_connected(False)

    def _build_ui(self):
        root = QtWidgets.QWidget()
        self.setCentralWidget(root)
        layout = QtWidgets.QVBoxLayout(root)

        conn = QtWidgets.QGroupBox("Connection")
        conn_l = QtWidgets.QGridLayout(conn)

        self.host = QtWidgets.QLineEdit("10.0.0.2")
        self.port = QtWidgets.QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(22)

        self.user = QtWidgets.QLineEdit("pi")
        self.passwd = QtWidgets.QLineEdit()
        self.passwd.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        self.keypath = QtWidgets.QLineEdit()
        self.keypick = QtWidgets.QPushButton("Browse key…")
        self.keypick.clicked.connect(self._pick_key)

        self.btn_connect = QtWidgets.QPushButton("Connect")
        self.btn_disconnect = QtWidgets.QPushButton("Disconnect")
        self.btn_connect.clicked.connect(self.on_connect)
        self.btn_disconnect.clicked.connect(self.on_disconnect)

        row = 0
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

        self.tabs = QtWidgets.QTabWidget()
        layout.addWidget(self.tabs, 1)

        self._tab_status()
        self._tab_services()
        self._tab_logs()
        self._tab_config()
        self._tab_files()
        self._tab_power()

        self.console = QtWidgets.QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(2000)
        layout.addWidget(QtWidgets.QLabel("Console"))
        layout.addWidget(self.console, 1)

        self.status = QtWidgets.QStatusBar()
        self.setStatusBar(self.status)
        self._tab_plugins()
        self._tab_face()


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
        self.service_name.addItems([
            "pwnagotchi",
            "bettercap",
            "bluetooth",
            "ssh",
            "networking",
        ])

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

        grid = QtWidgets.QGridLayout()
        self.remote_path = QtWidgets.QLineEdit("/home/pi/")
        self.local_path = QtWidgets.QLineEdit(os.path.expanduser("~/"))

        self.btn_pick_local = QtWidgets.QPushButton("Pick local…")
        self.btn_pick_local.clicked.connect(self._pick_local)

        self.btn_dl = QtWidgets.QPushButton("Download remote → local")
        self.btn_ul = QtWidgets.QPushButton("Upload local → remote")
        self.btn_dl.clicked.connect(self.on_download)
        self.btn_ul.clicked.connect(self.on_upload)

        grid.addWidget(QtWidgets.QLabel("Remote path (file)"), 0, 0)
        grid.addWidget(self.remote_path, 0, 1, 1, 2)
        grid.addWidget(QtWidgets.QLabel("Local path (file)"), 1, 0)
        grid.addWidget(self.local_path, 1, 1)
        grid.addWidget(self.btn_pick_local, 1, 2)

        btns = QtWidgets.QHBoxLayout()
        btns.addWidget(self.btn_dl)
        btns.addWidget(self.btn_ul)
        btns.addStretch(1)

        l.addLayout(grid)
        l.addLayout(btns)

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

    def on_plugins_refresh(self):
        cfg_path = self.cfg_path.text().strip()

        def do():
            # 1) read config
            cfg = self.ssh.run(f"sudo cat {cfg_path} || cat {cfg_path}", timeout_sec=20).stdout

            enabled_map = extract_enabled_from_toml(cfg)

            # 2) discover installed plugins by searching dirs
            found = set()
            for d in PLUGIN_DIR_CANDIDATES:
                r = self.ssh.run(f"ls -1 {d} 2>/dev/null || true")
                for name in parse_plugins_from_ls(r.stdout):
                    found.add(name)

            # also list python packages that look like pwnagotchi plugins (optional)
            return cfg, sorted(found), enabled_map

        def done(res, err):
            if err:
                self._log(f"[ERROR] {err}")
                return

            cfg, installed, enabled_map = res
            # fill table: union of installed + enabled_map keys
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
                    QtCore.Qt.CheckState.Checked if enabled_map.get(name, False) else QtCore.Qt.CheckState.Unchecked)

                self.plugins_table.setItem(i, 0, item_name)
                self.plugins_table.setItem(i, 1, item_inst)
                self.plugins_table.setItem(i, 2, chk)

            self._log(f"Plugins refreshed: {len(all_names)} shown.")

        run_in_thread(self, do, done)

    def on_plugins_apply(self):
        cfg_path = self.cfg_path.text().strip()

        # gather desired states from table
        desired = {}
        for row in range(self.plugins_table.rowCount()):
            name = self.plugins_table.item(row, 0).text()
            chk = self.plugins_table.item(row, 2)
            desired[name] = (chk.checkState() == QtCore.Qt.CheckState.Checked)

        def do():
            # read config
            cfg = self.ssh.run(f"sudo cat {cfg_path} || cat {cfg_path}", timeout_sec=20).stdout

            # apply toggles only for plugins that appear in config or installed list
            for name, en in desired.items():
                cfg = set_plugin_enabled_in_toml(cfg, name, en)

            # save using existing save logic approach (tmp + backup + mv)
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
            if r.exit_status != 0:
                # restart might fail on non-systemd; still report file write success if possible
                pass
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

    def _tab_face(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)

        top = QtWidgets.QHBoxLayout()
        self.face_source = QtWidgets.QComboBox()
        self.face_source.addItems([
            "Parse last log line containing face",
            "Use a simple status command (fallback)",
        ])
        self.btn_face = QtWidgets.QPushButton("Refresh face")
        self.btn_face.clicked.connect(self.on_face_refresh)

        top.addWidget(self.face_source)
        top.addWidget(self.btn_face)
        top.addStretch(1)

        self.face_big = QtWidgets.QLabel("(-_-)")
        f = self.face_big.font()
        f.setPointSize(44)
        self.face_big.setFont(f)
        self.face_big.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)

        self.face_info = QtWidgets.QPlainTextEdit()
        self.face_info.setReadOnly(True)

        l.addLayout(top)
        l.addWidget(self.face_big)
        l.addWidget(self.face_info, 1)

        self.tabs.addTab(w, "Face")

    def on_face_refresh(self):
        mode = self.face_source.currentIndex()

        def do():
            if mode == 0:
                # try logs
                cmd = r"tail -n 400 /var/log/pwnagotchi.log 2>/dev/null | grep -Eo '\([^\)]*\)' | tail -n 1 || true"
                r = self.ssh.run(cmd, timeout_sec=15)
                face = r.stdout.strip()
                # also show a small device summary
                info = self.ssh.run("hostname; uptime -p || uptime", timeout_sec=10).stdout.strip()
                return face, info
            else:
                # fallback: show service + uptime and pick a face based on state
                s = self.ssh.run("systemctl is-active pwnagotchi 2>/dev/null || true").stdout.strip()
                up = self.ssh.run("uptime -p || uptime", timeout_sec=10).stdout.strip()
                face = "(^_^)" if s == "active" else "(o_O)"
                return face, f"pwnagotchi service: {s}\n{up}"

        def done(res, err):
            if err:
                self._log(f"[ERROR] {err}")
                return
            face, info = res
            if not face:
                face = "(._.)"
            self.face_big.setText(face)
            self.face_info.setPlainText(info)
            self._log("Face refreshed.")

        run_in_thread(self, do, done)

    def _pick_key(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select SSH private key", os.path.expanduser("~"))
        if path:
            self.keypath.setText(path)

    def _pick_local(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select local file", os.path.expanduser("~"))
        if path:
            self.local_path.setText(path)

    def _set_connected(self, ok: bool):
        self.btn_connect.setEnabled(not ok)
        self.btn_disconnect.setEnabled(ok)
        for i in range(self.tabs.count()):
            self.tabs.widget(i).setEnabled(ok)
        self.status.showMessage("Connected" if ok else "Disconnected")

    def _log(self, msg: str):
        self.console.appendPlainText(msg)

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

        run_in_thread(self, do, done)

    def on_disconnect(self):
        self.ssh.close()
        self._set_connected(False)
        self._log("Disconnected.")

    def on_refresh(self):
        def do():
            # keep it simple + robust
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
            # Try systemd then SysV
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
            # write to /tmp then move into place with backup
            tmp = "/tmp/pwnagotchi_config.toml"
            bak = f"{path}.bak.$(date +%Y%m%d-%H%M%S)"
            # Use a heredoc safely
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

    def on_download(self):
        rpath = self.remote_path.text().strip()
        lpath = self.local_path.text().strip()

        def do():
            self.ssh.download(rpath, lpath)
            return f"Downloaded {rpath} -> {lpath}"

        def done(res, err):
            if err:
                self._log(f"[ERROR] {err}")
                QtWidgets.QMessageBox.critical(self, "Download failed", str(err))
                return
            self._log(res)

        run_in_thread(self, do, done)

    def on_upload(self):
        rpath = self.remote_path.text().strip()
        lpath = self.local_path.text().strip()

        def do():
            self.ssh.upload(lpath, rpath)
            return f"Uploaded {lpath} -> {rpath}"

        def done(res, err):
            if err:
                self._log(f"[ERROR] {err}")
                QtWidgets.QMessageBox.critical(self, "Upload failed", str(err))
                return
            self._log(res)

        run_in_thread(self, do, done)

    def on_reboot(self):
        if QtWidgets.QMessageBox.question(self, "Reboot", "Reboot the device now?") != QtWidgets.QMessageBox.StandardButton.Yes:
            return

        def do():
            r = self.ssh.run("sudo reboot || reboot", timeout_sec=5)
            return r.stdout + r.stderr

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
            r = self.ssh.run("sudo shutdown -h now || shutdown -h now", timeout_sec=5)
            return r.stdout + r.stderr

        def done(res, err):
            if err:
                self._log(f"[ERROR] {err}")
                return
            self._log("Shutdown command sent. Connection will drop.")
            self.on_disconnect()

        run_in_thread(self, do, done)


def quote_bash(script: str) -> str:
    # wrap for bash -lc "...."
    return "'" + script.replace("'", "'\"'\"'") + "'"
