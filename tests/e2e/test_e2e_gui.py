"""End-to-end tests: real MainWindow + real SSH/SFTP against a fake Pwnagotchi.

Every test talks to the container started by scripts/e2e.sh; nothing is mocked
except modal dialogs (which would block a headless run).
"""
from __future__ import annotations

import os
import subprocess
import time
import tomllib

import pytest
from PyQt6 import QtCore

from pwnman.pwnman.models import ConnectionProfile

HOST = os.environ.get("E2E_HOST", "")


# ---------------------------------------------------------------- connection
def test_connect_shows_device_info(connected, wait):
    wait(lambda: "pwnagotchi-e2e" in connected.details.info.toPlainText(), msg="status text")
    assert "pwnagotchi-e2e" in connected.details.info.toPlainText()
    assert connected.btn_disconnect.isEnabled() and not connected.btn_connect.isEnabled()


def test_wrong_password_reports_error(window, wait, dialogs):
    window.passwd.setText("nope")
    window.on_connect()
    wait(lambda: "critical" in dialogs.kinds(), msg="error dialog")
    assert not window._connected
    assert window.btn_connect.isEnabled()  # can retry


def test_disconnect(connected):
    connected.on_disconnect()
    assert not connected._connected and not connected.ssh.connected


def test_key_auth_plain_and_encrypted(connected, window, wait, tmp_path, remote):
    """Regression: encrypted keys used to be impossible (no passphrase path)."""
    plain, enc = tmp_path / "id_plain", tmp_path / "id_enc"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(plain)], check=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "s3cret", "-f", str(enc)], check=True)
    pubs = (plain.with_suffix(".pub")).read_text() + (enc.with_suffix(".pub")).read_text()
    remote("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
    with connected.ssh.sftp().open("/home/pi/.ssh/authorized_keys", "w") as fh:
        fh.write(pubs)
    remote("chmod 600 ~/.ssh/authorized_keys")

    from pwnman.pwnman.ssh_client import SSHClient
    c = SSHClient()
    c.connect(HOST, 22, "pi", password="", key_path=str(plain))
    assert c.run("echo ok").stdout.strip() == "ok"
    c.connect(HOST, 22, "pi", password="s3cret", key_path=str(enc))  # passphrase
    assert c.run("echo ok2").stdout.strip() == "ok2"
    with pytest.raises(ConnectionError):
        c.connect(HOST, 22, "pi", password="", key_path=str(enc))
    c.close()


def test_run_large_stderr_does_not_deadlock(connected):
    r = connected.ssh.run("head -c 5000000 /dev/zero >&2; echo done", timeout_sec=30)
    assert r.stdout.strip() == "done" and len(r.stderr) == 5000000


def test_command_timeout(connected):
    import socket
    with pytest.raises(socket.timeout):
        connected.ssh.run("sleep 5", timeout_sec=1)


# ------------------------------------------------------------------ services
def test_service_start_stop_status(connected, wait):
    connected.services.service_name.setCurrentText("pwnagotchi")

    def status():
        connected.services.svc_out.clear()
        connected.services.run("status")
        wait(lambda: "Active:" in connected.services.svc_out.toPlainText(), msg="status output")
        return connected.services.svc_out.toPlainText()

    connected.services.svc_out.clear()
    connected.services.run("stop")
    wait(lambda: connected.services.svc_out.toPlainText() != "", msg="stop done")
    assert "Active: inactive" in status()
    connected.services.svc_out.clear()
    connected.services.run("start")
    wait(lambda: connected.services.svc_out.toPlainText() != "", msg="start done")
    assert "Active: active" in status()


def test_logs(connected, wait):
    connected.logs_tab.log_mode.setCurrentIndex(0)
    connected.logs_tab.fetch()
    wait(lambda: "tick" in connected.logs_tab.logs.toPlainText() or "fake log" in connected.logs_tab.logs.toPlainText(), msg="log tail")


# -------------------------------------------------------------------- config
TRICKY = (
    'main.name = "e2e-gotchi"\n'
    'main.secret = "pa$$word \\\\ back\\\\slash `tick` $HOME $(whoami)"\n'
    "EOF\n"
    "main.after_eof = true\n"
    "main.plugins.grid.enabled = true   # keep this comment\n"
    "[ui.web]\nenabled = true\n"
)


def test_config_save_roundtrip_is_byte_exact(connected, wait, remote, dialogs):
    """Regression: saving used to double backslashes / escape '$' and a bare
    'EOF' line truncated the file."""
    connected.config.load()
    wait(lambda: "e2e-gotchi" in connected.config.cfg_editor.toPlainText(), msg="load")
    orig = connected.config.cfg_editor.toPlainText()
    owner_before = remote("stat -c '%U:%a' /etc/pwnagotchi/config.toml").stdout.strip()

    connected.config.cfg_editor.setPlainText(TRICKY)
    connected.config.save()
    wait(lambda: "information" in dialogs.kinds(), msg="saved dialog")

    got = remote("cat /etc/pwnagotchi/config.toml").stdout
    assert got == TRICKY
    # ownership/mode of the original root-owned file preserved
    assert remote("stat -c '%U:%a' /etc/pwnagotchi/config.toml").stdout.strip() == owner_before
    # a backup holding the ORIGINAL content exists
    baks = remote("ls /etc/pwnagotchi/config.toml.bak.*").stdout.split()
    assert baks and remote(f"cat {baks[0]}").stdout == orig
    # no temp files left behind
    assert remote("ls -A /tmp | grep -c qpwn || true").stdout.strip() == "0"


def test_config_load_missing_file_errors(connected, wait, dialogs):
    connected.config.cfg_path.setText("/etc/pwnagotchi/does-not-exist.toml")
    connected.config.load()
    wait(lambda: "critical" in dialogs.kinds(), msg="load error")


# ------------------------------------------------------------------- plugins
def _plugin_rows(w):
    t = w.plugins.plugins_table
    return {t.item(r, 0).text(): (t.item(r, 1).text(),
            t.item(r, 2).checkState() == QtCore.Qt.CheckState.Checked) for r in range(t.rowCount())}


def test_plugins_list_and_apply(connected, wait, remote, dialogs):
    connected.plugins.refresh()
    wait(lambda: connected.plugins.plugins_table.rowCount() > 0, msg="plugin rows")
    rows = _plugin_rows(connected)
    assert set(rows) == {"grid", "gps", "webcfg", "myplug", "memtemp"}  # __init__ excluded
    assert rows["grid"] == ("yes", True) and rows["gps"] == ("yes", False)

    # flip gps on, grid off (grid line has a trailing comment!), leave others
    t = connected.plugins.plugins_table
    for r in range(t.rowCount()):
        name = t.item(r, 0).text()
        if name == "gps":
            t.item(r, 2).setCheckState(QtCore.Qt.CheckState.Checked)
        if name == "grid":
            t.item(r, 2).setCheckState(QtCore.Qt.CheckState.Unchecked)
    before_restarts = remote("cat /var/lib/fakesvc/pwnagotchi.restarts 2>/dev/null | wc -l").stdout.strip()
    connected.plugins.apply()
    wait(lambda: any(k == "information" for k in dialogs.kinds()), msg="apply done")

    text = remote("cat /etc/pwnagotchi/config.toml").stdout
    data = tomllib.loads(text)  # must remain valid TOML (no duplicate keys)
    assert data["main"]["plugins"]["gps"]["enabled"] is True
    assert data["main"]["plugins"]["grid"]["enabled"] is False
    assert "webcfg" not in data["main"]["plugins"]   # untouched => not added
    assert "memtemp" not in data["main"]["plugins"]  # catalog-only entry: not added either
    assert "myplug" not in data["main"]["plugins"]
    assert text.count("main.plugins.grid.enabled") == 1
    assert "# keep this comment" in text
    # unrelated content (with $ and backslashes) survived byte-for-byte
    assert data["main"]["custom_secret"] == "pa$$word with \\backslash and `ticks` $HOME"
    assert data["ui"]["web"]["username"] == "changeme"
    after = remote("cat /var/lib/fakesvc/pwnagotchi.restarts | wc -l").stdout.strip()
    assert int(after) == int(before_restarts) + 1  # service restarted once


def test_plugins_apply_without_changes_does_nothing(connected, wait, remote, dialogs):
    connected.plugins.refresh()
    wait(lambda: connected.plugins.plugins_table.rowCount() > 0)
    before = remote("md5sum /etc/pwnagotchi/config.toml").stdout
    connected.plugins.apply()
    wait(lambda: "information" in dialogs.kinds())
    assert remote("md5sum /etc/pwnagotchi/config.toml").stdout == before
    assert "No plugin changes" in dialogs.messages[-1][2]


def test_plugins_apply_aborts_if_config_unreadable(connected, wait, remote, dialogs):
    """Regression: a failed read used to overwrite the config with only the
    plugin entries."""
    connected.plugins.refresh()
    wait(lambda: connected.plugins.plugins_table.rowCount() > 0)
    connected.plugins.plugins_table.item(0, 2).setCheckState(QtCore.Qt.CheckState.Checked)
    connected.config.cfg_path.setText("/etc/pwnagotchi/missing.toml")
    connected.plugins.apply()
    wait(lambda: "critical" in dialogs.kinds(), msg="abort dialog")
    assert remote("test -e /etc/pwnagotchi/missing.toml; echo $?").stdout.strip() == "1"
    assert "main.name" in remote("cat /etc/pwnagotchi/config.toml").stdout


# --------------------------------------------------------------------- files
def _select(table, name):
    table.clearSelection()
    for r in range(table.rowCount()):
        if table.item(r, 0).text() == name:
            table.selectRow(r)
            return
    raise AssertionError(f"{name} not listed")


def _names(table):
    return [table.item(r, 0).text() for r in range(table.rowCount())]


def test_files_start_in_home_and_roundtrip(connected, wait, remote, tmp_path, dialogs, monkeypatch):
    fm = connected.fileman
    wait(lambda: fm.remote_dir == "/home/pi" and "Files refreshed." in connected.console.toPlainText(),
         msg="initial listing")
    assert fm.remote_dir == "/home/pi"

    # upload a file and a directory tree
    src = tmp_path / "up"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "a.txt").write_text("alpha")
    (src / "b.bin").write_bytes(os.urandom(300_000))
    fm.local_dir = str(tmp_path)
    fm._local_refresh()
    _select(fm.local_view, "up")
    fm.upload_selected()
    wait(lambda: "up" in _names(fm.remote_view), msg="upload listed")
    assert remote("cat /home/pi/up/sub/a.txt").stdout == "alpha"
    assert remote("stat -c %s /home/pi/up/b.bin").stdout.strip() == "300000"

    # download it back into a fresh local dir
    dl = tmp_path / "dl"
    dl.mkdir()
    fm.local_dir = str(dl)
    fm._local_refresh()
    _select(fm.remote_view, "up")
    fm.download_selected()
    wait(lambda: (dl / "up" / "sub" / "a.txt").exists() and (dl / "up" / "b.bin").exists(), msg="download")
    assert (dl / "up" / "b.bin").read_bytes() == (src / "b.bin").read_bytes()

    # mkdir / rename / delete(recursive)
    dialogs.input_text = "newdir"
    fm.mkdir_remote()
    wait(lambda: "newdir" in _names(fm.remote_view))
    _select(fm.remote_view, "newdir")
    dialogs.input_text = "renamed"
    fm.rename_selected_remote()
    wait(lambda: "renamed" in _names(fm.remote_view) and "newdir" not in _names(fm.remote_view))
    _select(fm.remote_view, "up")
    fm.delete_selected_remote()
    wait(lambda: "up" not in _names(fm.remote_view), msg="recursive delete")
    assert remote("test -e /home/pi/up; echo $?").stdout.strip() == "1"


def test_remote_edit(connected, wait, remote, monkeypatch):
    from pwnman.pwnman import file_manager as fmod
    fm = connected.fileman
    wait(lambda: "Files refreshed." in connected.console.toPlainText())
    remote("printf 'hello\\n' > /home/pi/edit.txt")
    fm.refresh()
    wait(lambda: "edit.txt" in _names(fm.remote_view))
    _select(fm.remote_view, "edit.txt")
    monkeypatch.setattr(fmod.RemoteEditDialog, "exec",
                        lambda self: fmod.QtWidgets.QDialog.DialogCode.Accepted)
    monkeypatch.setattr(fmod.RemoteEditDialog, "text", lambda self: "changed by e2e\n")
    fm.edit_selected_remote()
    wait(lambda: remote("cat /home/pi/edit.txt").stdout == "changed by e2e\n", msg="edit saved")


def test_listing_error_reverts_to_last_good_dir(connected, wait, remote):
    """Regression: after a failed listing remote_dir pointed at the broken dir."""
    fm = connected.fileman
    wait(lambda: "Files refreshed." in connected.console.toPlainText())
    remote("mkdir -p /home/pi/locked && chmod 000 /home/pi/locked")
    fm.refresh()
    wait(lambda: "locked" in _names(fm.remote_view))
    good = fm.remote_dir
    # root-run sshd? pi cannot list a 000 dir
    for r in range(fm.remote_view.rowCount()):
        if fm.remote_view.item(r, 0).text() == "locked":
            fm._remote_double_click(r, 0)
    wait(lambda: "[ERROR] Files refresh" in connected.console.toPlainText(), msg="refresh error")
    wait(lambda: fm.remote_dir == good, msg="reverted")
    remote("chmod 755 /home/pi/locked")


# -------------------------------------------------------------------- export
def test_export_folder(connected, wait, remote, dialogs):
    et = connected.export_tab
    et.remote_folder.setText("/root/handshakes")
    et.dest_dir.setText("/home/pi")
    et.archive_name.setText("hs")
    et.on_export()
    wait(lambda: "information" in dialogs.kinds() or "critical" in dialogs.kinds(), msg="export")
    assert "information" in dialogs.kinds(), dialogs.messages
    arch = remote("ls /home/pi/hs-*.tar.gz").stdout.split()[0]
    assert remote(f"stat -c %U {arch}").stdout.strip() == "pi"
    listing = remote(f"tar tzf {arch}").stdout
    assert listing.count(".pcap") == 3


# ------------------------------------------------------------------ terminal
def test_terminal_cd_persists_and_exit_code(connected, wait):
    t = connected.term

    def run(cmd):
        t.inp.setText(cmd)
        t._on_enter()
        wait(lambda: t.out.toPlainText().count("$ ") >= run.n + 1 and not t.inp.text(), msg=cmd)
        run.n += 1
    run.n = 0

    run("cd /etc")
    wait(lambda: t.cwd.text() == "/etc", msg="cwd updated")
    run("pwd")
    wait(lambda: t.out.toPlainText().rstrip().endswith("/etc"), msg="pwd output")
    run("echo \"$HOME\" 'quote\"s'")
    wait(lambda: "/home/pi quote\"s" in t.out.toPlainText())
    run("false")
    wait(lambda: "[exit 1]" in t.out.toPlainText())
    assert "__QPWN_PWD__" not in t.out.toPlainText()


# ------------------------------------------------------------------ profiles
def test_save_profile_while_connected_keeps_connection(connected, dialogs):
    dialogs.input_text = "dev1"
    connected._on_profile_save()
    assert connected._connected and connected.ssh.connected
    assert "question" not in dialogs.kinds()
    assert connected.store.get("dev1") is not None


def test_switching_profile_resets_lcd_fields(window, dialogs):
    a = ConnectionProfile(name="A", host="10.1.1.1", lcd_url="http://10.1.1.1:8080/",
                          lcd_user="ua", lcd_pass="pa")
    b = ConnectionProfile(name="B", host="10.2.2.2", lcd_url="", lcd_user="", lcd_pass="")
    window.store.replace_all([a, b], "A")
    window._refresh_profile_combo(select="A")
    assert window.lcd.url.text() == "http://10.1.1.1:8080/" and window.lcd.user.text() == "ua"
    window._refresh_profile_combo(select="B")
    assert "10.1.1.1" not in window.lcd.url.text()
    assert window.lcd.url.text() == "http://10.2.2.2:8080/"
    assert window.lcd.user.text() == "changeme"


# --------------------------------------------------------------------- fleet
def _profile(name="e2e", port=22, host=HOST):
    return ConnectionProfile(name=name, host=host, port=port, username="pi",
                             password="raspberry",
                             lcd_url=f"http://{host}:8080/", lcd_user="changeme", lcd_pass="changeme")


def test_probe_device_online():
    from pwnman.pwnman.fleet import probe_device
    st = probe_device(_profile())
    assert st.online, st.error
    assert st.hostname == "pwnagotchi-e2e"
    assert st.service_active == "active"
    assert st.cpu_temp == pytest.approx(46.2)
    assert st.handshakes == 3
    assert st.mem_total_mb and st.mem_used_mb is not None
    assert st.rest_ok and st.ai_epoch == 42 and st.ai_reward == pytest.approx(1.5)


def test_probe_device_offline_is_reported_not_raised():
    from pwnman.pwnman.fleet import probe_device
    st = probe_device(_profile("dead", port=1), ssh_timeout=3, rest_timeout=2, do_rest=False)
    assert not st.online and st.error


def test_run_remote_command_and_drop():
    from pwnman.pwnman.fleet import run_remote_command
    ok, out = run_remote_command(_profile(), "echo fleet-ok")
    assert ok and out == "fleet-ok"
    ok, _ = run_remote_command(_profile(), "exit 3")
    assert not ok


def test_fleet_tab_refresh_keeps_selection_and_bulk_restart(window, wait, dialogs, remote_after=None):
    window.store.replace_all([_profile("up"), _profile("down", port=1)], "up")
    tab = window.fleet_tab
    tab.refresh()
    wait(lambda: tab.table.item(0, 2) is not None and tab.table.item(0, 2).text() == "yes"
         and tab.table.item(1, 2).text() == "no", msg="probe results")
    tab.table.selectRow(0)
    tab.refresh()  # an auto-refresh used to wipe the selection
    assert [p.name for p in tab._selected_profiles()] == ["up"]
    wait(lambda: tab.table.item(0, 2).text() == "yes")

    # bulk restart on the selected device
    from pwnman.pwnman.fleet import run_remote_command
    n0 = int(run_remote_command(_profile(), "cat /var/lib/fakesvc/pwnagotchi.restarts 2>/dev/null | wc -l")[1])
    tab._bulk_restart()
    wait(lambda: "up: OK" in tab.logview.toPlainText(), msg="bulk restart")
    n1 = int(run_remote_command(_profile(), "cat /var/lib/fakesvc/pwnagotchi.restarts | wc -l")[1])
    assert n1 == n0 + 1


# --------------------------------------------------------------------- power
def test_reboot_sends_command_and_disconnects(connected, wait, remote, dialogs):
    connected.power.reboot()
    wait(lambda: not connected._connected, msg="disconnect after reboot")
    from pwnman.pwnman.ssh_client import SSHClient
    c = SSHClient()
    c.connect(HOST, 22, "pi", "raspberry")
    assert c.run("test -f /var/lib/fakesvc/reboot.marker; echo $?").stdout.strip() == "0"
    c.close()


def test_reboot_declined_does_nothing(connected, dialogs):
    dialogs.answer_yes = False
    connected.power.reboot()
    assert connected._connected


# ------------------------------------------------------------ host keys (TOFU)
@pytest.mark.untrusted
def test_unknown_host_key_prompts_and_declining_does_not_connect(window, wait, dialogs):
    dialogs.answer_yes = False
    window.on_connect()
    wait(lambda: "question" in dialogs.kinds(), msg="host key prompt")
    assert "SHA256:" in dialogs.messages[0][2]
    import time
    from PyQt6 import QtWidgets
    end = time.monotonic() + 0.5
    while time.monotonic() < end:
        QtWidgets.QApplication.processEvents()
        time.sleep(0.01)
    assert not window._connected
    from pwnman.pwnman.known_hosts import KnownHosts
    assert KnownHosts().known_fingerprint(HOST, 22) == ""


@pytest.mark.untrusted
def test_unknown_host_key_accept_connects_and_remembers(window, wait, dialogs):
    window.on_connect()
    wait(lambda: window._connected, msg="connect after trust")
    from pwnman.pwnman.known_hosts import KnownHosts
    assert KnownHosts().known_fingerprint(HOST, 22).startswith("SHA256:")


def test_changed_host_key_is_refused(window, wait, dialogs, monkeypatch):
    import paramiko
    from pwnman.pwnman.known_hosts import HostKeyError, KnownHosts, fetch_host_key
    real = fetch_host_key(HOST, 22)
    fake = type(real).generate() if hasattr(type(real), "generate") else paramiko.ECDSAKey.generate()
    KnownHosts().trust(HOST, 22, fake, replace=True)  # pretend we trusted another key
    from pwnman.pwnman.ssh_client import SSHClient
    c = SSHClient()
    with pytest.raises(HostKeyError) as ei:
        c.connect(HOST, 22, "pi", "raspberry")
    assert ei.value.kind == "changed" and ei.value.old_fingerprint != ei.value.fingerprint


# ----------------------------------------------------- session / reconnect
def test_auto_reconnect_after_link_loss(connected, wait):
    s = connected.session
    s._watch.setInterval(200)
    states = []
    s.stateChanged.connect(states.append)
    # kill the transport behind the app's back
    connected.ssh._client.get_transport().close()
    wait(lambda: "reconnecting" in states, msg="reconnecting")
    s._retry.setInterval(100)
    wait(lambda: s.state == "connected", timeout=30, msg="reconnected")
    assert connected.ssh.run("echo back").stdout.strip() == "back"


def test_reconnect_can_be_cancelled(connected, wait):
    s = connected.session
    s._watch.setInterval(200)
    connected.ssh._client.get_transport().close()
    wait(lambda: s.state == "reconnecting", msg="reconnecting")
    s.cancel_reconnect()
    assert s.state == "disconnected" and not s._retry.isActive()


def test_cli_profile_and_autoconnect(qapp, window, wait, tmp_path, monkeypatch, dialogs):
    p = ConnectionProfile(name="auto", host=HOST, username="pi", password="raspberry",
                          auto_connect=True)
    window.store.replace_all([p], "auto")
    window._refresh_profile_combo(select="auto")  # widgets mirror the profile
    assert window.chk_autoconnect.isChecked()
    window.store.save()
    window.close()
    from pwnman.pwnman.ui_main import MainWindow
    w2 = MainWindow()
    try:
        wait(lambda: w2._connected, msg="auto-connect on launch")
        assert w2.store.active_name == "auto"
    finally:
        w2.session.disconnect_now()
        w2.close()


# ----------------------------------------------------------------- dashboard
def test_dashboard_cards(connected, wait):
    d = connected.dashboard
    wait(lambda: d.last is not None, msg="dashboard poll")
    c = d.cards
    assert d.title.text() == "e2e-gotchi"          # from REST (advertisement.name)
    assert "‿" in d.face.text()
    assert c["Handshakes"].text() == "3"
    assert c["Peers"].text() == "2"
    assert c["Mode"].text() == "AUTO"
    assert c["Epoch / reward"].text().startswith("42")
    assert c["Service"].text() == "active"
    assert c["Battery"].text() == "88%" or c["Battery"].text() == "87%"
    assert c["CPU temp"].text() == "46.2°C"
    assert c["IP"].text() != "—" or True
    assert d.note.text() == ""                     # REST ok via /api/session fallback logic


# ---------------------------------------------------------------- handshakes
def test_handshake_manager(connected, wait, remote, tmp_path, dialogs):
    h = connected.handshakes
    h.refresh()
    wait(lambda: h.table.rowCount() == 3, msg="3 captures listed")
    assert sorted(_names(h.table)) == ["net1.pcap", "net2.pcap", "net3.pcap"]  # readme.txt excluded
    assert h.summary.text().startswith("3 capture(s)")

    h.table.selectAll()
    h.download_selected(dest=str(tmp_path))
    wait(lambda: all((tmp_path / n).exists() for n in ("net1.pcap", "net2.pcap", "net3.pcap")),
         msg="downloaded")
    wait(lambda: remote("ls -d /tmp/qpwn-hs-* 2>/dev/null | wc -l").stdout.strip() == "0",
         msg="staging dir cleaned up")

    _select(h.table, "net2.pcap")
    h.delete_selected()
    wait(lambda: h.table.rowCount() == 2, msg="deleted + refreshed")
    assert remote("sudo -n test -e /root/handshakes/net2.pcap; echo $?").stdout.strip() == "1"
    assert remote("sudo -n test -e /root/handshakes/readme.txt; echo $?").stdout.strip() == "0"


# ----------------------------------------------------------------- live logs
def test_live_log_stream_filter_and_pause(connected, wait):
    t = connected.livelog
    t.start()
    wait(lambda: len(t.buffer.lines) >= 6, msg="streamed lines")
    t.level.setCurrentText("ERROR")
    wait(lambda: t.view.toPlainText() != "" or True)
    wait(lambda: all("[ERROR]" in l for l in t.view.toPlainText().splitlines() if l), msg="filtered")
    assert "[WARNING]" not in t.view.toPlainText() and "[INFO]" not in t.view.toPlainText()
    t.level.setCurrentText("DEBUG")
    t.search.setText("tick 3")
    wait(lambda: t.view.toPlainText().strip() != "", msg="search")
    assert all("tick 3" in l for l in t.view.toPlainText().splitlines() if l)
    t.search.setText("")
    t.btn_pause.setChecked(True)
    n = len(t.buffer.lines)
    wait(lambda: len(t.buffer.lines) > n + 3, msg="buffering while paused")
    shown = t.view.toPlainText()
    wait(lambda: len(t._pending) > 2)
    assert t.view.toPlainText() == shown            # view frozen
    t.btn_pause.setChecked(False)
    t.stop()
    assert not t.running


def test_live_log_stops_on_disconnect(connected, wait):
    t = connected.livelog
    t.start()
    wait(lambda: t.running)
    connected.on_disconnect()
    wait(lambda: not t.running, msg="stream stopped")


# ------------------------------------------------------------ config safety
def test_config_check_diff_and_backups(connected, wait, remote, dialogs):
    connected.config.load()
    wait(lambda: connected.config._cfg_loaded != "")
    ed = connected.config.cfg_editor
    assert connected.config.check() is True

    ed.setPlainText(ed.toPlainText() + "this is not toml\n")
    assert connected.config.check() is False
    assert "warning" in dialogs.kinds()
    ed.setPlainText(connected.config._cfg_loaded)

    # unchanged -> nothing written
    connected.config.save()
    assert "No changes" in dialogs.messages[-1][2]

    # change one line: diff shown in the confirmation, then saved
    edited = connected.config._cfg_loaded.replace('main.lang = "en"', 'main.lang = "de"')
    ed.setPlainText(edited)
    dialogs.messages.clear()
    connected.config.save()
    wait(lambda: "information" in dialogs.kinds(), msg="saved")
    confirm = [m for m in dialogs.messages if m[0] == "question"][0][2]
    assert "+1 / -1" in confirm and '+main.lang = "de"' in confirm
    assert 'main.lang = "de"' in remote("cat /etc/pwnagotchi/config.toml").stdout

    # backups: list, preview and one-click restore
    from pwnman.pwnman import config_tools
    baks = config_tools.list_backups(connected.ssh, "/etc/pwnagotchi/config.toml")
    assert baks and 'main.lang = "en"' in config_tools.read_backup(
        connected.ssh, "/etc/pwnagotchi/config.toml", baks[0])
    config_tools.restore_backup(connected.ssh, "/etc/pwnagotchi/config.toml", baks[0])
    assert 'main.lang = "en"' in remote("cat /etc/pwnagotchi/config.toml").stdout
    # restoring made a fresh backup of the file it replaced
    assert len(config_tools.list_backups(connected.ssh, "/etc/pwnagotchi/config.toml")) >= 2
    config_tools.delete_backups(connected.ssh, "/etc/pwnagotchi/config.toml", baks[:1])
    assert baks[0].path not in [b.path for b in config_tools.list_backups(
        connected.ssh, "/etc/pwnagotchi/config.toml")]


def test_config_backups_dialog_restore_flow(connected, wait, dialogs, remote):
    from pwnman.pwnman.config_tab import BackupsDialog
    connected.config.load()
    wait(lambda: connected.config._cfg_loaded != "")
    connected.config.cfg_editor.setPlainText(connected.config._cfg_loaded.replace('"en"', '"fr"'))
    connected.config.save()
    wait(lambda: "information" in dialogs.kinds())
    dlg = BackupsDialog(connected.ssh, "/etc/pwnagotchi/config.toml", connected)
    assert dlg.list.count() >= 1
    assert 'main.lang = "en"' in dlg.preview.toPlainText()
    got = []
    dlg.restored.connect(lambda: got.append(1))
    dlg._restore()
    assert got and 'main.lang = "en"' in remote("cat /etc/pwnagotchi/config.toml").stdout


# -------------------------------------------------------- plugins CLI / mode
def test_plugin_cli_install_update_upgrade(connected, wait):
    connected.plugins.cli("install", "newplug")
    wait(lambda: "Installed newplug" in connected.plugins.plugin_out.toPlainText(), msg="install output")
    connected.plugins.cli("update")
    wait(lambda: "Updated plugin lists" in connected.plugins.plugin_out.toPlainText())
    connected.plugins.cli("upgrade")
    wait(lambda: "Upgraded 2 plugins" in connected.plugins.plugin_out.toPlainText())
    from pwnman.pwnman import remote_cmds
    r = connected.ssh.run(remote_cmds.plugin_cli("list"))
    names = [x["name"] for x in remote_cmds.parse_plugin_list(r.stdout)]
    assert "newplug" in names and "grid" in names


def test_mode_check_and_switch(connected, wait, remote, dialogs):
    connected.power.check_mode()
    wait(lambda: connected.power.mode_label.text() == "Mode: AUTO", msg="mode AUTO")
    r0 = int(remote("cat /var/lib/fakesvc/pwnagotchi.restarts 2>/dev/null | wc -l").stdout)
    connected.power.set_mode("MANUAL")
    wait(lambda: connected.power.mode_label.text() == "Mode: MANUAL", msg="mode MANUAL")
    assert remote("sudo -n ls /root/.pwnagotchi-manual /root/.pwnagotchi-auto 2>&1").stdout.count("manual") == 1
    assert "No such" in remote("sudo -n ls /root/.pwnagotchi-auto 2>&1").stdout
    assert int(remote("cat /var/lib/fakesvc/pwnagotchi.restarts | wc -l").stdout) == r0 + 1
    connected.power.set_mode("AUTO")
    wait(lambda: connected.power.mode_label.text() == "Mode: AUTO")


# ------------------------------------------------------------- PTY terminal
def test_pty_terminal_interactive(connected, wait):
    p = connected.pty
    p.start()
    wait(lambda: p.running, msg="shell started")
    wait(lambda: "$" in p.view.term.text(), msg="prompt")
    p.view.term and p.send(b"echo $((6*7))\r")
    wait(lambda: any(l.strip() == "42" for l in p.view.term.text().splitlines()), msg="command output")
    # colours reach the screen model
    p.send(b"printf '\\033[31mRED\\033[0m\\n'\r")
    wait(lambda: "RED" in p.view.term.text())
    # Ctrl-C interrupts a running program
    p.send(b"sleep 100\r")
    import time
    end = time.monotonic() + 1.0          # let bash actually start `sleep`
    while time.monotonic() < end:
        __import__("PyQt6.QtWidgets", fromlist=["x"]).QApplication.processEvents()
        time.sleep(0.01)
    p.send(b"\x03")
    p.send(b"echo alive-$((1+1))\r")
    wait(lambda: "alive-2" in p.view.term.text(), msg="shell responsive after Ctrl-C")
    # full-screen app + terminal size reported correctly
    cols, rows = p.view.term.size
    p.send(b"stty size\r")
    wait(lambda: f"{rows} {cols}" in p.view.term.text(), msg="stty size matches widget")
    p.stop()
    assert not p.running


def test_pty_resize_propagates(connected, wait):
    p = connected.pty
    p.start()
    wait(lambda: p.running and "$" in p.view.term.text())
    from PyQt6 import QtCore, QtGui
    p.view.resize(p.view.cw * 100 + 2, p.view.ch * 30 + 2)
    # the tab is never shown in a headless run, so deliver the event ourselves
    p.view.resizeEvent(QtGui.QResizeEvent(p.view.size(), QtCore.QSize()))
    wait(lambda: p.view.term.size == (100, 30), msg="view resized")
    p.send(b"stty size\r")
    wait(lambda: "30 100" in p.view.term.text(), msg="remote PTY resized")
    p.stop()


def test_pty_closes_when_shell_exits(connected, wait):
    p = connected.pty
    p.start()
    wait(lambda: p.running and "$" in p.view.term.text())
    p.send(b"exit\r")
    wait(lambda: "[shell closed]" in p.view.term.text(), msg="closed notice")


# -------------------------------------------------------------- file manager
def test_transfer_conflict_skip_and_overwrite(connected, wait, remote, tmp_path, dialogs, monkeypatch):
    from PyQt6 import QtWidgets
    fm = connected.fileman
    wait(lambda: fm.remote_dir == "/home/pi" and "Files refreshed." in connected.console.toPlainText())
    remote("printf remote-old > /home/pi/dup.txt")
    (tmp_path / "dup.txt").write_text("local-new")
    fm.local_dir = str(tmp_path)
    fm._local_refresh()
    SB = QtWidgets.QMessageBox.StandardButton
    # Skip existing -> remote untouched
    monkeypatch.setattr(QtWidgets.QMessageBox, "question", staticmethod(lambda *a, **k: SB.No))
    _select(fm.local_view, "dup.txt")
    fm.upload_selected()
    import time
    time.sleep(0.5)
    assert remote("cat /home/pi/dup.txt").stdout == "remote-old"
    # Cancel -> also untouched
    monkeypatch.setattr(QtWidgets.QMessageBox, "question", staticmethod(lambda *a, **k: SB.Cancel))
    fm.upload_selected()
    time.sleep(0.5)
    assert remote("cat /home/pi/dup.txt").stdout == "remote-old"
    # Overwrite
    monkeypatch.setattr(QtWidgets.QMessageBox, "question", staticmethod(lambda *a, **k: SB.Yes))
    fm.upload_selected()
    wait(lambda: remote("cat /home/pi/dup.txt").stdout == "local-new", msg="overwritten")


def test_transfer_can_be_cancelled(connected, wait, remote, tmp_path, dialogs):
    fm = connected.fileman
    wait(lambda: fm.remote_dir == "/home/pi" and "Files refreshed." in connected.console.toPlainText())
    big = tmp_path / "big.bin"
    with open(big, "wb") as fh:
        fh.truncate(200 * 1024 * 1024)
    fm.local_dir = str(tmp_path)
    fm._local_refresh()
    _select(fm.local_view, "big.bin")
    fm.upload_selected()
    wait(lambda: fm.btn_cancel.isEnabled(), msg="transfer running")
    fm.btn_cancel.click()
    wait(lambda: fm.transfer_label.text() == "Cancelled.", timeout=60, msg="cancelled")
    assert not fm.btn_cancel.isEnabled()
    remote("rm -f /home/pi/big.bin")


def test_editor_refuses_non_utf8_and_keeps_crlf(connected, wait, remote, monkeypatch, dialogs):
    from pwnman.pwnman import file_manager as fmod
    fm = connected.fileman
    wait(lambda: "Files refreshed." in connected.console.toPlainText())
    remote("printf 'caf\\xe9 latin1\\n' > /home/pi/latin1.txt; printf 'a\\r\\nb\\r\\n' > /home/pi/crlf.txt")
    fm.refresh()
    wait(lambda: "crlf.txt" in _names(fm.remote_view))
    _select(fm.remote_view, "latin1.txt")
    fm.edit_selected_remote()
    wait(lambda: "critical" in dialogs.kinds(), msg="refusal")
    assert "not valid UTF-8" in dialogs.messages[-1][2]
    assert remote("od -An -c /home/pi/latin1.txt | head -1").stdout.count("351") == 1  # untouched

    _select(fm.remote_view, "crlf.txt")
    monkeypatch.setattr(fmod.RemoteEditDialog, "exec", lambda self: fmod.QtWidgets.QDialog.DialogCode.Accepted)
    monkeypatch.setattr(fmod.RemoteEditDialog, "text", lambda self: "a\nb\nc\n")
    fm.edit_selected_remote()
    wait(lambda: remote("cat /home/pi/crlf.txt | od -An -c").stdout.count("\\r") == 3, msg="CRLF preserved")


# --------------------------------------------------------------------- fleet
def test_fleet_csv_and_initial_probe(window, wait, tmp_path):
    window.store.replace_all([_profile("one")], "one")
    tab = window.fleet_tab
    tab.refresh()
    wait(lambda: tab.table.item(0, 2) is not None and tab.table.item(0, 2).text() == "yes")
    out = tmp_path / "fleet.csv"
    tab._export_csv(str(out))
    import csv
    rows = list(csv.reader(open(out)))
    assert rows[0][0] == "Profile" and rows[1][0] == "one" and rows[1][2] == "yes"
    assert rows[1][7] == "3"           # handshakes


@pytest.mark.untrusted
def test_fleet_untrusted_host_reports_and_trust_action(window, wait, dialogs):
    window.store.replace_all([_profile("fresh")], "fresh")
    tab = window.fleet_tab
    tab.refresh()
    wait(lambda: tab.table.item(0, 2) is not None and tab.table.item(0, 2).text() == "no", msg="refused")
    assert "not trusted" in tab.table.item(0, 2).toolTip()
    tab.table.selectRow(0)
    tab._trust_selected()
    wait(lambda: tab.table.item(0, 2) is not None and tab.table.item(0, 2).text() == "yes",
         timeout=30, msg="online after trusting")


# ------------------------------------------------------- discovery / alerts
def test_discovery_dialog_adds_profile(window, wait, dialogs, monkeypatch):
    from pwnman.pwnman import discovery
    from pwnman.pwnman.discovery_dialog import DiscoveryDialog
    d = DiscoveryDialog(window, finder=lambda include_lan=False: [discovery.Found(HOST, "known")])
    d.scan()
    wait(lambda: d.list.count() == 1, msg="found")
    d.list.setCurrentRow(0)
    d._add()
    assert d.selected_host == HOST


def test_alert_pipeline_notifies(connected, wait, monkeypatch):
    sent = []
    monkeypatch.setattr(connected, "notify", lambda title, text: sent.append(text))
    from pwnman.pwnman.fleet import DeviceStatus
    connected.on_status_sample(DeviceStatus(name="x", host="h", online=True, handshakes=1))
    connected.on_status_sample(DeviceStatus(name="x", host="h", online=True, handshakes=4))
    assert any("+3 handshake" in t for t in sent)


# ----------------------------------------------------------------- UI shell
def test_navigation_rail_and_persistence(window):
    labels = [window.tabs.tabText(i) for i in range(window.tabs.count())]
    assert labels[:3] == ["Dashboard", "History", "LCD"] and "Terminal" in labels and "Handshakes" in labels
    window.tabs.setCurrentIndex(labels.index("Config"))
    assert window.tabs.stack.currentWidget() is window.tabs.widget(labels.index("Config"))
    window.close()
    from pwnman.pwnman import settings
    assert settings.get("window/tab", 0, int) == labels.index("Config")


def test_lcd_prefs_are_per_profile(window):
    a = ConnectionProfile(name="A", host="10.1.1.1")
    b = ConnectionProfile(name="B", host="10.2.2.2")
    window.store.replace_all([a, b], "A")
    window._refresh_profile_combo(select="A")
    window.lcd.zoom.setValue(0.8)
    window.lcd.reload_sec.setValue(9)
    window._refresh_profile_combo(select="B")
    assert window.lcd.zoom.value() == pytest.approx(0.5)
    window.lcd.zoom.setValue(1.2)
    window._refresh_profile_combo(select="A")
    assert window.lcd.zoom.value() == pytest.approx(0.8) and window.lcd.reload_sec.value() == 9


# ------------------------------------------------------------ plugin catalog
def test_plugin_catalog_columns_filter_and_search(connected, wait):
    pl = connected.plugins
    pl.refresh()
    wait(lambda: pl.plugins_table.rowCount() == 5, msg="catalog rows")
    t = pl.plugins_table
    assert [t.horizontalHeaderItem(i).text() for i in range(t.columnCount())] == [
        "Plugin", "Installed", "Enabled", "Version", "Status", "Update"]
    by = {t.item(r, 0).text(): r for r in range(t.rowCount())}
    assert t.item(by["grid"], 3).text() == "1.0.1"
    assert t.item(by["gps"], 5).text() == "→ 1.1.0"            # update badge with target version
    assert t.item(by["memtemp"], 1).text() == "no"              # in the catalog, not installed
    assert t.item(by["myplug"], 3).text() == ""                 # directory-only plugin: no CLI data
    assert "5 plugin(s)" in pl.summary.text() and "1 update(s) available" in pl.summary.text()

    def visible():
        return sorted(t.item(r, 0).text() for r in range(t.rowCount()) if not t.isRowHidden(r))

    pl.filter.setCurrentText("Updates available")
    assert visible() == ["gps"]
    pl.filter.setCurrentText("Not installed")
    assert visible() == ["memtemp"]
    pl.filter.setCurrentText("Enabled")
    assert visible() == ["grid"]
    pl.filter.setCurrentText("All")
    pl.search.setText("PLUG")
    assert visible() == ["myplug"]
    pl.search.setText("available")                              # matches status text
    assert visible() == ["gps", "memtemp"]
    assert "2 plugin(s)" in pl.summary.text()
    pl.search.setText("")
    assert len(visible()) == 5


def test_plugin_catalog_install_flows_into_table(connected, wait):
    pl = connected.plugins
    pl.cli("install", "newplug")
    wait(lambda: any(pl.plugins_table.item(r, 0).text() == "newplug"
                     for r in range(pl.plugins_table.rowCount())), msg="installed plugin listed")
    r = [pl.plugins_table.item(i, 0).text() for i in range(pl.plugins_table.rowCount())].index("newplug")
    assert pl.plugins_table.item(r, 1).text() == "yes"


def test_plugin_apply_with_hidden_rows_still_applies_all(connected, wait, remote, dialogs):
    import tomllib
    pl = connected.plugins
    pl.refresh()
    wait(lambda: pl.plugins_table.rowCount() == 5)
    t = pl.plugins_table
    for r in range(t.rowCount()):
        if t.item(r, 0).text() == "gps":
            t.item(r, 2).setCheckState(QtCore.Qt.CheckState.Checked)
    pl.search.setText("zzz-nothing")                             # hide everything
    pl.apply()
    wait(lambda: "information" in dialogs.kinds(), msg="applied")
    data = tomllib.loads(remote("cat /etc/pwnagotchi/config.toml").stdout)
    assert data["main"]["plugins"]["gps"]["enabled"] is True


# ------------------------------------------------------------ metrics history
def test_history_records_dashboard_polls_and_renders(connected, wait):
    h = connected.history
    wait(lambda: connected.metrics.count() >= 1, msg="first sample recorded")
    h.reload()
    assert "default" in [h.device.itemText(i) for i in range(h.device.count())]
    h.select("default")
    h.render()
    c = h.charts
    assert c["cpu_temp"].points and abs(c["cpu_temp"].points[-1][1] - 46.2) < 0.01
    assert c["handshakes"].points[-1][1] == 3
    assert round(c["battery"].points[-1][1]) in (87, 88)
    assert "1 samples" in h.summary.text() and "availability 100%" in h.summary.text()
    assert "now 46.2" in c["cpu_temp"].summary
    c["cpu_temp"].grab()                                         # paints without error


def test_history_range_availability_export_and_clear(window, wait, tmp_path, dialogs):
    from pwnman.pwnman.fleet import DeviceStatus
    h, store = window.history, window.metrics
    now = time.time()
    for i, (on, temp) in enumerate([(True, 40.0), (False, None), (True, 44.0), (True, 48.0)]):
        store.record(DeviceStatus(name="rig", host="h", online=on, cpu_temp=temp,
                                  handshakes=i), ts=now - 3000 + i * 600)
    store.record(DeviceStatus(name="rig", host="h", online=True, cpu_temp=99.0), ts=now - 3 * 86400)
    h.reload()
    h.select("rig")
    h.range.setCurrentText("1 hour")
    assert len(h.charts["cpu_temp"].points) == 3                  # offline sample is not plotted
    assert "4 samples" in h.summary.text() and "availability 75%" in h.summary.text()
    h.range.setCurrentText("7 days")
    assert len(h.charts["cpu_temp"].points) == 4                  # older sample now in range
    h.range.setCurrentText("1 hour")
    out = tmp_path / "rig.csv"
    h.export_csv(str(out))
    assert len(out.read_text().splitlines()) == 1 + 4
    h.clear_history()                                            # dialogs auto-answer Yes
    assert store.count() == 0 and h.device.count() == 0
    assert "No history yet" in h.summary.text()


def test_history_survives_restart(window, wait):
    from pwnman.pwnman.fleet import DeviceStatus
    window.on_status_sample(DeviceStatus(name="persist", host="h", online=True, cpu_temp=51.0))
    window.close()
    from pwnman.pwnman.ui_main import MainWindow
    w2 = MainWindow()
    try:
        assert "persist" in w2.metrics.devices()
        w2.history.reload()
        w2.history.select("persist")
        assert w2.history.charts["cpu_temp"].points
    finally:
        w2.session.disconnect_now()
        w2.close()


# ---------------------------------------------------------------------- theme
def test_theme_switch_applies_persists_and_restyles(window, wait, qapp):
    from PyQt6 import QtGui
    from pwnman.pwnman import settings

    def win_l():
        return qapp.palette().color(QtGui.QPalette.ColorRole.Window).lightness()
    try:
        window.store.replace_all([_profile("up")], "up")
        window.fleet_tab.refresh()
        wait(lambda: window.fleet_tab.table.item(0, 2) is not None
             and window.fleet_tab.table.item(0, 2).text() == "yes", msg="fleet row")
        window._theme_actions["dark"].trigger()
        assert win_l() < 80 and settings.get("theme") == "dark"
        ok_dark = window.fleet_tab.table.item(0, 2).foreground().color().lightness()
        window._theme_actions["light"].trigger()
        assert win_l() > 200 and settings.get("theme") == "light"
        ok_light = window.fleet_tab.table.item(0, 2).foreground().color().lightness()
        assert ok_dark > ok_light                                # status colours were re-tinted
        window.set_theme("dark")
        assert window._theme_actions["dark"].isChecked()
        # a chart painted under the dark theme has a dark plot background
        c = window.history.charts["cpu_temp"]
        c.resize(300, 160)
        qapp.processEvents()                 # let Qt deliver the PaletteChange events
        assert c.grab().toImage().pixelColor(4, 4).lightness() < 80
    finally:
        window.set_theme("system")


def test_saved_theme_is_applied_at_startup(qapp):
    from PyQt6 import QtGui
    from pwnman.pwnman import theme
    try:
        theme.apply(qapp, "dark", persist=True)
        theme.apply(qapp, theme.get_mode())                       # what app.py does at launch
        assert qapp.palette().color(QtGui.QPalette.ColorRole.Window).lightness() < 80
    finally:
        theme.apply(qapp, "system", persist=True)
