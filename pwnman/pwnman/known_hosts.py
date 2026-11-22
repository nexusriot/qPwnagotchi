"""Trust-on-first-use SSH host-key handling (replaces AutoAddPolicy)."""
from __future__ import annotations

import base64
import hashlib
import os
import socket
from pathlib import Path
from typing import Optional

import paramiko


class HostKeyError(ConnectionError):
    """Raised instead of connecting when a host key is unknown or changed."""

    def __init__(self, kind: str, host: str, port: int, key: paramiko.PKey,
                 old_fingerprint: str = ""):
        self.kind = kind  # "unknown" | "changed"
        self.host, self.port, self.key = host, port, key
        self.fingerprint = fingerprint(key)
        self.old_fingerprint = old_fingerprint
        if kind == "unknown":
            msg = (f"Host key for {host}:{port} is not trusted yet "
                   f"({key.get_name()} {self.fingerprint}).")
        else:
            msg = (f"HOST KEY CHANGED for {host}:{port}! "
                   f"was {old_fingerprint or '?'}, now {self.fingerprint}. "
                   f"Possible man-in-the-middle attack.")
        super().__init__(msg)


def fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def default_path() -> Path:
    from pwnman.pwnman.profile_store import config_dir
    return config_dir() / "known_hosts"


def _hostname(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


class KnownHosts:
    def __init__(self, path: Optional[os.PathLike] = None):
        self.path = Path(path) if path else default_path()

    def load_into(self, client: paramiko.SSHClient) -> None:
        if self.path.is_file():
            try:
                client.load_host_keys(str(self.path))
            except OSError:
                pass

    def _hk(self) -> paramiko.HostKeys:
        hk = paramiko.HostKeys()
        if self.path.is_file():
            try:
                hk.load(str(self.path))
            except OSError:
                pass
        return hk

    def known_fingerprint(self, host: str, port: int) -> str:
        entry = self._hk().lookup(_hostname(host, port))
        if not entry:
            return ""
        return ", ".join(fingerprint(k) for k in entry.values())

    def trust(self, host: str, port: int, key: paramiko.PKey, replace: bool = False) -> None:
        hk = self._hk()
        name = _hostname(host, port)
        if replace:
            try:
                del hk[name]
            except KeyError:
                pass
        hk.add(name, key.get_name(), key)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.close(fd)
        hk.save(str(tmp))
        os.replace(tmp, self.path)


class StrictPolicy(paramiko.MissingHostKeyPolicy):
    """Reject unknown keys (changed keys are rejected by paramiko itself)."""

    def missing_host_key(self, client, hostname, key):
        host, port = hostname, 22
        if hostname.startswith("["):
            h, _, p = hostname[1:].partition("]:")
            host, port = h, int(p or 22)
        raise HostKeyError("unknown", host, port, key)


def fetch_host_key(host: str, port: int = 22, timeout: float = 6.0) -> paramiko.PKey:
    """Grab the server's host key without authenticating (for 'Trust…')."""
    sock = socket.create_connection((host, port), timeout=timeout)
    t = paramiko.Transport(sock)
    try:
        t.start_client(timeout=timeout)
        return t.get_remote_server_key()
    finally:
        t.close()
