"""Qt-free plugin catalog: merge directory scan + config.toml + `pwnagotchi plugins list`."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class PluginRow:
    name: str
    installed: bool = False
    enabled: bool = False
    version: str = ""
    status: str = ""
    update_available: bool = False
    latest: str = ""
    in_config: bool = False


_UPDATE_RE = re.compile(r"(update|upgrad)", re.I)
_VER_RE = re.compile(r"(\d+(?:\.\d+)+)")


def interpret_status(status: str) -> tuple[bool, bool, str]:
    """(installed, update_available, latest_version) from a CLI status cell."""
    s = status.lower()
    update = bool(_UPDATE_RE.search(s))
    latest = ""
    if update:
        m = _VER_RE.search(status)
        latest = m.group(1) if m else ""
    installed = ("install" in s) or ("enabled" in s) or ("disabled" in s) or update
    if "not installed" in s or "available" in s and "update" not in s:
        installed = False
    return installed, update, latest


def merge_catalog(dir_installed, enabled_map: dict, cli_rows: list[dict]) -> list[PluginRow]:
    rows: dict[str, PluginRow] = {}

    def row(n: str) -> PluginRow:
        return rows.setdefault(n, PluginRow(n))

    for n in dir_installed:
        row(n).installed = True
    for n, en in enabled_map.items():
        r = row(n)
        r.enabled = bool(en)
        r.in_config = True
    for c in cli_rows:
        r = row(c["name"])
        r.version = c.get("version", "")
        r.status = c.get("status", "")
        inst, upd, latest = interpret_status(r.status)
        r.installed = r.installed or inst
        r.update_available, r.latest = upd, latest
        if "enabled" in r.status.lower() and not r.in_config:
            r.enabled = True
    return sorted(rows.values(), key=lambda r: r.name.lower())


FILTERS = ("All", "Installed", "Enabled", "Updates available", "Not installed")


def matches(r: PluginRow, text: str = "", which: str = "All") -> bool:
    if text and text.lower() not in r.name.lower() and text.lower() not in r.status.lower():
        return False
    return {
        "All": True,
        "Installed": r.installed,
        "Enabled": r.enabled,
        "Updates available": r.update_available,
        "Not installed": not r.installed,
    }.get(which, True)


def summary(rows: list[PluginRow]) -> str:
    return (f"{len(rows)} plugin(s): {sum(r.installed for r in rows)} installed, "
            f"{sum(r.enabled for r in rows)} enabled, "
            f"{sum(r.update_available for r in rows)} update(s) available")
