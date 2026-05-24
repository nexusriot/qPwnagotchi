"""Resource lookup helpers (app icon, etc.).

Resolves files across three layouts so the same code works in dev, in a
PyInstaller one-file binary, and from a system install (.deb).
"""
from __future__ import annotations

import os
import sys
from functools import lru_cache

from PyQt6 import QtGui


ICON_SVG = "qpwnagotchi.svg"
ICON_PNG_SIZES = (512, 256, 128, 64, 48, 32, 24, 16)


def _candidate_dirs() -> list[str]:
    dirs: list[str] = []
    # 1. PyInstaller bundle (--add-data "packaging:packaging")
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        dirs.append(os.path.join(meipass, "packaging"))
        dirs.append(meipass)
    # 2. Repo layout (dev): <repo>/packaging
    here = os.path.dirname(os.path.abspath(__file__))
    repo_pkg = os.path.normpath(os.path.join(here, "..", "..", "packaging"))
    dirs.append(repo_pkg)
    # 3. System install via .deb
    dirs.append("/usr/share/icons/hicolor/scalable/apps")
    return dirs


def find_resource(name: str) -> str | None:
    for d in _candidate_dirs():
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    return None


def find_icon_png(size: int) -> str | None:
    name = f"qpwnagotchi-{size}.png"
    # try packaging first
    p = find_resource(name)
    if p:
        return p
    # fall back to hicolor theme on the system
    sys_path = f"/usr/share/icons/hicolor/{size}x{size}/apps/qpwnagotchi.png"
    if os.path.isfile(sys_path):
        return sys_path
    return None


@lru_cache(maxsize=1)
def app_icon() -> QtGui.QIcon:
    """Return a multi-resolution QIcon for the application."""
    icon = QtGui.QIcon()
    # Prefer themed lookup if the system has the .deb installed.
    themed = QtGui.QIcon.fromTheme("qpwnagotchi")
    if not themed.isNull():
        icon = themed
    # Always layer in our bundled files too, so PyInstaller builds and
    # dev runs get a real icon even without a system install.
    svg = find_resource(ICON_SVG)
    if svg:
        icon.addFile(svg)
    for size in ICON_PNG_SIZES:
        png = find_icon_png(size)
        if png:
            icon.addFile(png)
    return icon


def icon_svg_path() -> str | None:
    return find_resource(ICON_SVG)
