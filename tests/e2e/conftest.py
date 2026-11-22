"""E2E fixtures: drive the real MainWindow against the fake device.

Skipped automatically unless E2E_HOST is set (scripts/e2e.sh sets it).
"""
from __future__ import annotations

import os
import time

import pytest

HOST = os.environ.get("E2E_HOST")
_LAST: dict = {}



def pytest_collection_modifyitems(config, items):
    if HOST:
        return
    skip = pytest.mark.skip(reason="E2E_HOST not set (run `make e2e`)")
    for it in items:
        if "tests/e2e" in str(it.fspath).replace("\\", "/"):
            it.add_marker(skip)


@pytest.fixture(scope="session")
def qapp():
    # QtWebEngine must be imported before QApplication exists.
    from PyQt6 import QtWebEngineWidgets  # noqa: F401
    from PyQt6 import QtWidgets
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(["qpwnagotchi-e2e"])
    yield app


class Dialogs:
    """Replaces modal QMessageBox/QInputDialog so tests never block."""

    def __init__(self, monkeypatch):
        from PyQt6 import QtWidgets
        self.messages: list[tuple[str, str, str]] = []
        self.answer_yes = True
        self.input_text = ""
        mb = QtWidgets.QMessageBox
        for kind in ("information", "warning", "critical"):
            monkeypatch.setattr(mb, kind, staticmethod(self._rec(kind)))

        def question(parent, title, text, *a, **k):
            self.messages.append(("question", title, text))
            return mb.StandardButton.Yes if self.answer_yes else mb.StandardButton.No
        monkeypatch.setattr(mb, "question", staticmethod(question))

        def get_text(parent, title, label, *a, **k):
            return self.input_text, True
        monkeypatch.setattr(QtWidgets.QInputDialog, "getText", staticmethod(get_text))

    def _rec(self, kind):
        def f(parent, title, text, *a, **k):
            self.messages.append((kind, title, text))
        return f

    def kinds(self):
        return [m[0] for m in self.messages]


@pytest.fixture
def dialogs(monkeypatch):
    return Dialogs(monkeypatch)


def pump(qapp, seconds=0.05):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        qapp.processEvents()
        time.sleep(0.005)


@pytest.fixture
def wait(qapp):
    def _wait(cond, timeout=20.0, msg="condition"):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            qapp.processEvents()
            if cond():
                return
            time.sleep(0.02)
        tail = ""
        if _LAST.get("w") is not None:
            try:
                tail = "\n--- app console (tail) ---\n" + "\n".join(
                    _LAST["w"].console.toPlainText().splitlines()[-15:])
            except RuntimeError:
                pass
        raise AssertionError(f"timed out waiting for {msg}{tail}")
    return _wait


@pytest.fixture(autouse=True)
def device_reset():
    """Every test starts from the same pristine fake device (config, captures,
    home dir, service state). Uses a separate control connection, not the app."""
    if HOST:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # test harness only
        c.connect(HOST, 22, "pi", "raspberry", look_for_keys=False, allow_agent=False, timeout=15)
        try:
            _, out, err = c.exec_command("sudo -n /usr/local/bin/reset-device")
            rc = out.channel.recv_exit_status()
            assert rc == 0, err.read().decode()
        finally:
            c.close()
    yield


@pytest.fixture(autouse=True)
def cfg_home(request, tmp_path, monkeypatch):
    """Per-test config dir. The fake device's host key is pre-trusted unless the
    test is marked ``untrusted`` (then the TOFU prompt path is exercised)."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    if HOST and not request.node.get_closest_marker("untrusted"):
        from pwnman.pwnman.known_hosts import KnownHosts, fetch_host_key
        KnownHosts().trust(HOST, 22, fetch_host_key(HOST, 22))
    return tmp_path / "cfg"


@pytest.fixture
def window(qapp, tmp_path, monkeypatch, dialogs, wait, cfg_home):
    from pwnman.pwnman.ui_main import MainWindow
    w = MainWindow()
    w.host.setText(HOST)
    w.port.setValue(22)
    w.user.setText("pi")
    w.passwd.setText("raspberry")
    w.keypath.setText("")
    _LAST["w"] = w
    yield w
    _LAST["w"] = None
    w.ssh.close()
    w.close()
    # Destroy the WebEngine view/page now: leaving dozens of them to interpreter
    # shutdown makes Chromium segfault on exit (exit code 139 after a green run).
    w.lcd.dispose()
    w.deleteLater()
    pump(qapp)
    from PyQt6 import QtCore
    QtCore.QCoreApplication.sendPostedEvents(None, QtCore.QEvent.Type.DeferredDelete)
    pump(qapp)


@pytest.fixture
def connected(window, wait):
    window.on_connect()
    wait(lambda: window._connected, msg="ssh connect")
    return window


@pytest.fixture
def remote(connected):
    """Run a command on the device through the app's own SSH client."""
    def run(cmd, timeout=20):
        return connected.ssh.run(cmd, timeout_sec=timeout)
    return run


def pytest_runtest_logreport(report):
    """Print failures immediately: a native crash in teardown would otherwise
    kill the process before pytest's end-of-run summary."""
    if report.failed:
        import sys
        sys.stderr.write(f"\n--- FAILURE ({report.when}) {report.nodeid}\n{report.longreprtext}\n")
        sys.stderr.flush()


def pytest_sessionfinish(session, exitstatus):
    """Tear Qt down deterministically before the interpreter finalises."""
    if not HOST:
        return
    try:
        from PyQt6 import QtCore, QtWidgets
        app = QtWidgets.QApplication.instance()
        if app is not None:
            QtCore.QCoreApplication.sendPostedEvents(None, QtCore.QEvent.Type.DeferredDelete)
            app.processEvents()
            from PyQt6 import sip
            sip.delete(app)
    except Exception:  # noqa: BLE001 - best effort
        pass
