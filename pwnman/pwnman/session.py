"""Connection session: owns the shared SSHClient, a liveness watchdog and
auto-reconnect with exponential back-off. UI code listens to signals only.
"""
from __future__ import annotations

from typing import Optional

from PyQt6 import QtCore

from pwnman.pwnman.async_utils import run_in_thread
from pwnman.pwnman.known_hosts import HostKeyError, KnownHosts
from pwnman.pwnman.ssh_client import SSHClient

DISCONNECTED, CONNECTING, CONNECTED, RECONNECTING = (
    "disconnected", "connecting", "connected", "reconnecting")


def backoff_delay(attempt: int, base: float = 2.0, cap: float = 60.0) -> float:
    """2, 4, 8, ... capped (attempt starts at 1)."""
    return min(cap, base * (2 ** max(0, attempt - 1)))


class Session(QtCore.QObject):
    stateChanged = QtCore.pyqtSignal(str)
    message = QtCore.pyqtSignal(str)
    failed = QtCore.pyqtSignal(str)          # user-initiated connect failed
    hostKeyProblem = QtCore.pyqtSignal(object)  # HostKeyError

    def __init__(self, parent=None, known_hosts: Optional[KnownHosts] = None,
                 watch_ms: int = 4000, auto_reconnect: bool = True):
        super().__init__(parent)
        self.ssh = SSHClient()
        self.known_hosts = known_hosts
        self.auto_reconnect = auto_reconnect
        self.state = DISCONNECTED
        self._params: Optional[dict] = None
        self._attempt = 0
        self._busy = False
        self._watch = QtCore.QTimer(self)
        self._watch.setInterval(watch_ms)
        self._watch.timeout.connect(self._check)
        self._retry = QtCore.QTimer(self)
        self._retry.setSingleShot(True)
        self._retry.timeout.connect(self._attempt_connect)

    # ----------------------------------------------------------------- state
    def _set(self, state: str) -> None:
        if state != self.state:
            self.state = state
            self.stateChanged.emit(state)

    @property
    def connected(self) -> bool:
        return self.state == CONNECTED

    # ------------------------------------------------------------------- api
    def connect_to(self, **params) -> None:
        """params: host, port, username, password, key_path."""
        if self._busy:
            return
        self._params = params
        self._attempt = 0
        self._set(CONNECTING)
        self._do_connect(user_initiated=True)

    def disconnect_now(self) -> None:
        self._retry.stop()
        self._watch.stop()
        self.ssh.close()
        self._params = None
        self._set(DISCONNECTED)

    def cancel_reconnect(self) -> None:
        if self.state == RECONNECTING:
            self.disconnect_now()

    def expect_drop(self) -> None:
        """We are about to reboot/shut the device: don't auto-reconnect."""
        self.disconnect_now()

    # -------------------------------------------------------------- internals
    def _do_connect(self, user_initiated: bool) -> None:
        params = dict(self._params or {})
        self._busy = True

        def do():
            self.ssh.connect(known_hosts=self.known_hosts, **params)
            return True

        def done(_res, err):
            self._busy = False
            if self._params is None:  # disconnected meanwhile
                self.ssh.close()
                return
            if err is None:
                self._attempt = 0
                self._set(CONNECTED)
                self._watch.start()
                return
            if isinstance(err, HostKeyError):
                self._params = None
                self._set(DISCONNECTED)
                self.hostKeyProblem.emit(err)
                return
            if user_initiated:
                self._params = None
                self._set(DISCONNECTED)
                self.failed.emit(str(err))
                return
            self._schedule_retry(str(err))

        run_in_thread(self, do, done)

    def _check(self) -> None:
        if self.state != CONNECTED or self._busy:
            return
        if self.ssh.connected:
            return
        self._watch.stop()
        self.message.emit("Connection lost.")
        if self.auto_reconnect and self._params:
            self._set(RECONNECTING)
            self._schedule_retry("connection lost")
        else:
            self.ssh.close()
            self._params = None
            self._set(DISCONNECTED)

    def _schedule_retry(self, why: str) -> None:
        self._attempt += 1
        delay = backoff_delay(self._attempt)
        self._set(RECONNECTING)
        self.message.emit(f"Reconnect attempt {self._attempt} in {delay:g}s ({why})")
        self._retry.start(int(delay * 1000))

    def _attempt_connect(self) -> None:
        if self._params is None or self.state != RECONNECTING:
            return
        self._do_connect(user_initiated=False)
