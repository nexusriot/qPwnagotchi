from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from typing import Optional, Tuple

import paramiko


@dataclass
class CmdResult:
    exit_status: int
    stdout: str
    stderr: str


class SSHClient:
    def __init__(self) -> None:
        self._client: Optional[paramiko.SSHClient] = None
        self._sftp: Optional[paramiko.SFTPClient] = None

    @property
    def connected(self) -> bool:
        return self._client is not None

    def connect(
        self,
        host: str,
        port: int,
        username: str,
        password: str = "",
        key_path: str = "",
        timeout_sec: float = 8.0,
    ) -> None:
        self.close()

        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        pkey = None
        if key_path:
            key_path = os.path.expanduser(key_path)
            if not os.path.isfile(key_path):
                raise FileNotFoundError(f"Key not found: {key_path}")
            # Try common key types
            last_err = None
            for key_cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
                try:
                    pkey = key_cls.from_private_key_file(key_path)
                    last_err = None
                    break
                except Exception as e:
                    last_err = e
            if pkey is None and last_err:
                raise last_err

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
        except (socket.timeout, paramiko.SSHException) as e:
            raise ConnectionError(str(e)) from e

        self._client = c

    def close(self) -> None:
        if self._sftp is not None:
            try:
                self._sftp.close()
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
        if self._client is None:
            raise RuntimeError("Not connected")
        stdin, stdout, stderr = self._client.exec_command(cmd, timeout=timeout_sec)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        status = stdout.channel.recv_exit_status()
        return CmdResult(status, out, err)

    def sftp(self) -> paramiko.SFTPClient:
        if self._client is None:
            raise RuntimeError("Not connected")
        if self._sftp is None:
            self._sftp = self._client.open_sftp()
        return self._sftp

    def download(self, remote_path: str, local_path: str) -> None:
        s = self.sftp()
        s.get(remote_path, local_path)

    def upload(self, local_path: str, remote_path: str) -> None:
        s = self.sftp()
        s.put(local_path, remote_path)
