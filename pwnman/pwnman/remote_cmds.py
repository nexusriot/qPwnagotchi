"""Every shell command the app sends to the device is built here.

All interpolated values go through ``quote_bash``/``shlex.quote`` and the
builders are unit-tested with hostile input (spaces, quotes, ``$()``).
"""
from __future__ import annotations

import re
import shlex
from typing import Optional

from pwnman.pwnman.async_utils import quote_bash  # noqa: F401  (re-export)

q = shlex.quote

SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@:-]+$")
LOG_FILE = "/var/log/pwnagotchi.log"
HANDSHAKE_DIR = "/root/handshakes"
PLUGIN_ACTIONS = ("list", "install", "uninstall", "update", "upgrade", "enable", "disable")


def service_action(action: str, name: str) -> str:
    if action not in ("status", "start", "stop", "restart", "enable", "disable"):
        raise ValueError(f"bad service action: {action}")
    if not SERVICE_RE.match(name):
        raise ValueError(f"bad service name: {name!r}")
    n = q(name)
    return (f"sudo -n systemctl {action} {n} || sudo -n service {n} {action} "
            f"|| systemctl {action} {n} || service {n} {action}")


def list_dir(path: str) -> str:
    return f"ls -1 {q(path)} 2>/dev/null || true"


def tail_log(n: int, path: str = LOG_FILE) -> str:
    n = int(n)
    return f"tail -n {n} {q(path)} 2>/dev/null || tail -n {n} /var/log/syslog"


def journal(n: int, unit: str = "pwnagotchi") -> str:
    return f"journalctl -u {q(unit)} -n {int(n)} --no-pager 2>/dev/null || true"


def follow_log(path: str = LOG_FILE) -> str:
    """Follow the log; falls back to the journal when the file is absent."""
    return (f"if [ -r {q(path)} ]; then exec tail -n 200 -F {q(path)}; "
            f"else exec journalctl -fu pwnagotchi -n 200 --no-pager; fi")


def power(kind: str) -> str:
    return {"reboot": "sudo -n reboot || reboot",
            "shutdown": "sudo -n shutdown -h now || shutdown -h now"}[kind]


def restart_pwnagotchi() -> str:
    return "sudo -n systemctl restart pwnagotchi || sudo -n service pwnagotchi restart"


# ---------------------------------------------------------------- handshakes
def list_handshakes(directory: str = HANDSHAKE_DIR) -> str:
    """name<TAB>size<TAB>mtime-epoch, one per capture file."""
    d = q(directory)
    return (f"sudo -n find {d} -maxdepth 1 -type f \\( -name '*.pcap' -o -name '*.22000' \\) "
            f"-printf '%f\\t%s\\t%T@\\n' 2>/dev/null || "
            f"find {d} -maxdepth 1 -type f \\( -name '*.pcap' -o -name '*.22000' \\) "
            f"-printf '%f\\t%s\\t%T@\\n'")


def parse_handshakes(out: str) -> list[dict]:
    rows = []
    for line in out.splitlines():
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 3:
            continue
        try:
            rows.append({"name": parts[0], "size": int(parts[1]),
                         "mtime": int(float(parts[2]))})
        except ValueError:
            continue
    rows.sort(key=lambda r: r["mtime"], reverse=True)
    return rows


def safe_basename(name: str) -> bool:
    return bool(name) and "/" not in name and name not in (".", "..") and "\0" not in name


def delete_handshakes(names: list[str], directory: str = HANDSHAKE_DIR) -> str:
    bad = [n for n in names if not safe_basename(n)]
    if bad or not names:
        raise ValueError(f"unsafe handshake names: {bad}")
    files = " ".join(q(f"{directory.rstrip('/')}/{n}") for n in names)
    return f"sudo -n rm -f -- {files}"


def stage_for_download(names: list[str], dest: str, directory: str = HANDSHAKE_DIR) -> str:
    """Copy root-only captures into a user-readable temp dir for SFTP."""
    bad = [n for n in names if not safe_basename(n)]
    if bad or not names:
        raise ValueError(f"unsafe handshake names: {bad}")
    files = " ".join(q(f"{directory.rstrip('/')}/{n}") for n in names)
    return (f"mkdir -p {q(dest)} && sudo -n cp -- {files} {q(dest)}/ "
            f"&& sudo -n chown -R \"$(id -u):$(id -g)\" {q(dest)}")


# ------------------------------------------------------------------- plugins
def plugin_cli(action: str, *args: str) -> str:
    if action not in PLUGIN_ACTIONS:
        raise ValueError(f"bad plugin action: {action}")
    for a in args:
        if not re.match(r"^[A-Za-z0-9_.\-]+$", a):
            raise ValueError(f"bad plugin argument: {a!r}")
    tail = " ".join(q(a) for a in args)
    return f"sudo -n pwnagotchi plugins {action} {tail}".strip() + " 2>&1"


def parse_plugin_list(out: str) -> list[dict]:
    """Parse ``pwnagotchi plugins list`` (table with | separators).

    Columns seen in the wild: Name | Version | Enabled/Status | ... Any table
    row with >= 2 cells whose first cell looks like an identifier counts.
    """
    rows = []
    for line in out.splitlines():
        if "|" not in line:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2 or not re.match(r"^[A-Za-z0-9_\-]+$", cells[0]):
            continue
        if cells[0].lower() in ("name", "plugin"):
            continue
        rows.append({"name": cells[0], "version": cells[1] if len(cells) > 1 else "",
                     "status": " ".join(cells[2:]) if len(cells) > 2 else ""})
    return rows


# ---------------------------------------------------------------------- mode
MODE_FILES = {"AUTO": "/root/.pwnagotchi-auto", "MANUAL": "/root/.pwnagotchi-manual"}


def mode_get() -> str:
    return ("if sudo -n test -e /root/.pwnagotchi-manual; then echo MANUAL; "
            "elif sudo -n test -e /root/.pwnagotchi-auto; then echo AUTO; else echo UNKNOWN; fi")


def mode_set(mode: str) -> str:
    if mode not in MODE_FILES:
        raise ValueError(mode)
    other = MODE_FILES["MANUAL" if mode == "AUTO" else "AUTO"]
    return (f"sudo -n rm -f {other} && sudo -n touch {MODE_FILES[mode]} && "
            f"{restart_pwnagotchi()}")


# ------------------------------------------------------------------- battery
BATTERY_SCRIPT = r"""
if command -v nc >/dev/null 2>&1; then
  b=$(echo "get battery" | nc -q0 127.0.0.1 8423 2>/dev/null | sed -n 's/.*battery: *\([0-9.]*\).*/\1/p')
  [ -n "$b" ] && { echo "pisugar:$b"; exit 0; }
fi
for d in /sys/class/power_supply/*; do
  [ -r "$d/capacity" ] || continue
  t=$(cat "$d/type" 2>/dev/null)
  [ "$t" = Battery ] && { echo "battery:$(cat $d/capacity)"; exit 0; }
done
echo none
"""


def parse_battery(out: str) -> Optional[float]:
    m = re.search(r"(?:pisugar|battery):([0-9.]+)", out)
    return float(m.group(1)) if m else None
