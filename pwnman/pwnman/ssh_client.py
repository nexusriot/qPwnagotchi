from __future__ import annotations

import os
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional

import paramiko

from pwnman.pwnman.known_hosts import HostKeyError, KnownHosts, StrictPolicy


@dataclass
class CmdResult:
    exit_status: int
    stdout: str
    stderr: str


class _LockedProxy:
    """Serialises every call on a paramiko SFTP object (and the file objects it
    hands out). paramiko's SFTPClient is not safe for concurrent use from
    several threads: interleaved reads of the shared channel mismatched
    responses and hung operations (refresh racing a delete, for example)."""

    def __init__(self, target, lock):
        object.__setattr__(self, "_t", target)
        object.__setattr__(self, "_l", lock)

    def __getattr__(self, name):
        attr = getattr(self._t, name)
        if not callable(attr):
            return attr
        lock = self._l

        def call(*a, **kw):
            with lock:
                res = attr(*a, **kw)
            if isinstance(res, paramiko.SFTPFile):
                return _LockedProxy(res, lock)
            return res
        return call

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class SSHClient:
    def __init__(self) -> None:
        self._client: Optional[paramiko.SSHClient] = None
        self._sftp: Optional[paramiko.SFTPClient] = None
        self._sftp_lock = threading.Lock()
        self._sftp_op_lock = threading.RLock()

    @property
    def connected(self) -> bool:
        c = self._client
        if c is None:
            return False
        t = c.get_transport()
        return t is not None and t.is_active()

    def connect(
        self,
        host: str,
        port: int,
        username: str,
        password: str = "",
        key_path: str = "",
        timeout_sec: float = 8.0,
        known_hosts: Optional[KnownHosts] = None,
    ) -> None:
        """Connect with trust-on-first-use host-key checking.

        Unknown keys raise ``HostKeyError(kind="unknown")`` and changed keys
        ``HostKeyError(kind="changed")``; the caller decides whether to
        ``KnownHosts.trust(...)`` and retry. Nothing is trusted silently.
        """
        self.close()

        kh = known_hosts or KnownHosts()
        c = paramiko.SSHClient()
        kh.load_into(c)
        c.set_missing_host_key_policy(StrictPolicy())

        pkey = None
        if key_path:
            key_path = os.path.expanduser(key_path)
            if not os.path.isfile(key_path):
                raise FileNotFoundError(f"Key not found: {key_path}")
            # PKey.from_path sniffs the key type (RSA/Ed25519/ECDSA) and, for
            # encrypted keys, uses the password field as the passphrase.
            try:
                pkey = paramiko.PKey.from_path(
                    key_path, passphrase=password.encode() if password else None)
            except paramiko.PasswordRequiredException as e:
                raise ConnectionError(
                    "SSH key is encrypted: enter its passphrase in the Password field"
                ) from e
            except (TypeError, ValueError) as e:
                # cryptography reports "password-protected but no password" as
                # TypeError and a wrong passphrase as ValueError.
                if "password" in str(e).lower() and "not provided" in str(e).lower():
                    raise ConnectionError(
                        "SSH key is encrypted: enter its passphrase in the Password field"
                    ) from e
                raise ConnectionError(
                    f"Cannot load SSH key {key_path} (wrong passphrase or bad key): {e}") from e
            except paramiko.SSHException as e:
                raise ConnectionError(f"Cannot load SSH key {key_path}: {e}") from e

        try:
            c.connect(
                hostname=host,
                port=port,
                username=username,
                password=password if password else None,
                pkey=pkey,
                timeout=timeout_sec,
                banner_timeout=timeout_sec,
                auth_timeout=timeout_sec,
                look_for_keys=False,
                allow_agent=True,
            )
        except HostKeyError:
            c.close()
            raise
        except paramiko.BadHostKeyException as e:
            c.close()
            old = kh.known_fingerprint(host, port)
            raise HostKeyError("changed", host, port, e.key, old) from e
        except (socket.timeout, paramiko.SSHException) as e:
            c.close()
            raise ConnectionError(str(e)) from e
        except BaseException:
            c.close()
            raise

        tr = c.get_transport()
        if tr is not None:
            tr.set_keepalive(30)
        self._client = c

    def close(self) -> None:
        if self._sftp is not None:
            try:
                # Bypass the lock: a long transfer must not make disconnect hang.
                getattr(self._sftp, "_t", self._sftp).close()
            except Exception:
                pass
        self._sftp = None

        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
        self._client = None

    def run(self, cmd: str, timeout_sec: float = 15.0) -> CmdResult:
        """Run a command; read stdout and stderr concurrently.

        Reading one stream to EOF before the other can deadlock when the
        remote fills the other stream's window, so both are drained together.
        ``timeout_sec`` bounds the whole command.
        """
        client = self._client
        if client is None:
            raise RuntimeError("Not connected")
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            raise RuntimeError("Not connected")

        chan = transport.open_session(timeout=timeout_sec)
        out = bytearray()
        err = bytearray()
        try:
            chan.exec_command(cmd)
            deadline = time.monotonic() + timeout_sec
            while True:
                got = False
                while chan.recv_ready():
                    out += chan.recv(65536)
                    got = True
                while chan.recv_stderr_ready():
                    err += chan.recv_stderr(65536)
                    got = True
                if chan.exit_status_ready() and not (
                        chan.recv_ready() or chan.recv_stderr_ready()):
                    break
                if not got:
                    if time.monotonic() > deadline:
                        raise socket.timeout(f"Command timed out after {timeout_sec:g}s")
                    time.sleep(0.01)
            status = chan.recv_exit_status()
        finally:
            chan.close()
        return CmdResult(status, out.decode("utf-8", errors="replace"),
                         err.decode("utf-8", errors="replace"))

    def stream(self, cmd: str, on_line, stop_event: threading.Event,
               on_stderr=None) -> int:
        """Run ``cmd`` and feed output lines to ``on_line`` until it ends or
        ``stop_event`` is set (then the channel is closed). Returns exit status
        (-1 when stopped). Runs on its own channel, so it never blocks ``run``.
        """
        client = self._client
        if client is None:
            raise RuntimeError("Not connected")
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            raise RuntimeError("Not connected")
        chan = transport.open_session(timeout=10)
        buf = b""
        try:
            chan.exec_command(cmd)
            while not stop_event.is_set():
                got = False
                if chan.recv_ready():
                    buf += chan.recv(65536)
                    got = True
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        on_line(line.decode("utf-8", errors="replace").rstrip("\r"))
                if chan.recv_stderr_ready():
                    d = chan.recv_stderr(65536)
                    got = True
                    if on_stderr:
                        on_stderr(d.decode("utf-8", errors="replace"))
                if chan.exit_status_ready() and not got and not chan.recv_ready():
                    if buf:
                        on_line(buf.decode("utf-8", errors="replace"))
                    return chan.recv_exit_status()
                if not got:
                    time.sleep(0.05)
            return -1
        finally:
            chan.close()

    def open_shell(self, term: str = "xterm-256color", width: int = 80,
                   height: int = 24) -> paramiko.Channel:
        """Interactive PTY shell channel (caller reads/writes/closes it)."""
        client = self._client
        if client is None:
            raise RuntimeError("Not connected")
        return client.invoke_shell(term=term, width=width, height=height)

    def sftp(self) -> paramiko.SFTPClient:
        if self._client is None:
            raise RuntimeError("Not connected")
        with self._sftp_lock:
            if self._sftp is None:
                self._sftp = _LockedProxy(self._client.open_sftp(), self._sftp_op_lock)
            return self._sftp

    def download(self, remote_path: str, local_path: str) -> None:
        s = self.sftp()
        s.get(remote_path, local_path)

    def upload(self, local_path: str, remote_path: str) -> None:
        s = self.sftp()
        s.put(local_path, remote_path)
