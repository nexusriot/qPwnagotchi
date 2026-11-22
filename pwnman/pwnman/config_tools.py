"""Qt-free helpers for safe config editing: syntax check, diff, backups."""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from typing import Optional

from pwnman.pwnman.async_utils import quote_bash
from pwnman.pwnman.remote_config import read_remote_text, write_remote_text


@dataclass
class TomlProblem:
    line: int
    col: int
    message: str


def check_toml(text: str) -> Optional[TomlProblem]:
    """None when valid, else the first syntax problem with a position."""
    try:
        import tomllib
    except ModuleNotFoundError:  # py3.10
        import tomli as tomllib
    try:
        tomllib.loads(text)
        return None
    except tomllib.TOMLDecodeError as e:
        msg = str(e)
        m = re.search(r"\(at line (\d+), column (\d+)\)", msg)
        line, col = (int(m.group(1)), int(m.group(2))) if m else (1, 1)
        return TomlProblem(line, col, re.sub(r"\s*\(at line.*\)$", "", msg))


def make_diff(old: str, new: str, context: int = 2) -> str:
    return "".join(difflib.unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True),
        "current", "edited", n=context))


def diff_summary(diff: str) -> tuple[int, int]:
    add = sum(1 for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++"))
    rem = sum(1 for l in diff.splitlines() if l.startswith("-") and not l.startswith("---"))
    return add, rem


@dataclass
class Backup:
    path: str
    stamp: str  # YYYYmmdd-HHMMSS


_BAK_RE = re.compile(r"\.bak\.(\d{8}-\d{6})(?:-\d+)?$")


def list_backups(ssh, cfg_path: str) -> list[Backup]:
    r = ssh.run(f"ls -1 {quote_bash(cfg_path + '.bak.')}* 2>/dev/null || true",
                timeout_sec=15)
    out = []
    for line in r.stdout.splitlines():
        m = _BAK_RE.search(line.strip())
        if m:
            out.append(Backup(line.strip(), m.group(1)))
    # newest first; the collision counter (-N) breaks ties within a second
    out.sort(key=lambda b: (b.stamp, len(b.path), b.path), reverse=True)
    return out


def _is_backup_of(path: str, cfg_path: str) -> bool:
    return path.startswith(cfg_path + ".bak.") and bool(_BAK_RE.search(path)) and "/" not in path[len(cfg_path):]


def read_backup(ssh, cfg_path: str, backup: Backup) -> str:
    if not _is_backup_of(backup.path, cfg_path):
        raise ValueError("not a backup of this config")
    return read_remote_text(ssh, backup.path)


def restore_backup(ssh, cfg_path: str, backup: Backup) -> str:
    """Restore ``backup`` over the config (the current file is backed up first)."""
    text = read_backup(ssh, cfg_path, backup)
    return write_remote_text(ssh, cfg_path, text)


def delete_backups(ssh, cfg_path: str, backups: list[Backup]) -> None:
    for b in backups:
        if not _is_backup_of(b.path, cfg_path):
            raise ValueError("not a backup of this config")
    files = " ".join(quote_bash(b.path) for b in backups)
    if files:
        r = ssh.run(f"sudo -n rm -f -- {files} || rm -f -- {files}", timeout_sec=20)
        if r.exit_status != 0:
            raise RuntimeError(r.stderr.strip() or "delete failed")
