"""Light / dark / follow-system theme.

``apply`` installs the Fusion style with an explicit palette so every widget
(and our custom-painted charts, which read ``palette()``) agree. In "system"
mode on a light desktop the application's original style/palette is restored.
"""
from __future__ import annotations

from PyQt6 import QtCore, QtGui, QtWidgets

from pwnman.pwnman import settings as app_settings

MODES = ("system", "light", "dark")
LABELS = {"system": "Follow system", "light": "Light", "dark": "Dark"}

_originals: dict = {}


def _p(**roles) -> QtGui.QPalette:
    pal = QtGui.QPalette()
    R = QtGui.QPalette.ColorRole
    for name, color in roles.items():
        pal.setColor(getattr(R, name), QtGui.QColor(color))
    return pal


def dark_palette() -> QtGui.QPalette:
    pal = _p(Window="#2b2d31", WindowText="#e6e6e6", Base="#1e1f22", AlternateBase="#2b2d31",
             ToolTipBase="#3a3d42", ToolTipText="#f0f0f0", Text="#e6e6e6", Button="#35383d",
             ButtonText="#e6e6e6", BrightText="#ff6b6b", Link="#6aa9ff", Highlight="#3d6fb6",
             HighlightedText="#ffffff", PlaceholderText="#8b8f96", Mid="#4a4e55", Dark="#17181a",
             Light="#4f535b", Midlight="#3f4248", Shadow="#000000")
    G = QtGui.QPalette.ColorGroup
    R = QtGui.QPalette.ColorRole
    for role in (R.WindowText, R.Text, R.ButtonText):
        pal.setColor(G.Disabled, role, QtGui.QColor("#7a7d83"))
    return pal


def light_palette() -> QtGui.QPalette:
    pal = _p(Window="#f2f3f5", WindowText="#1f2328", Base="#ffffff", AlternateBase="#f2f3f5",
             ToolTipBase="#ffffdc", ToolTipText="#1f2328", Text="#1f2328", Button="#e6e8eb",
             ButtonText="#1f2328", BrightText="#d00000", Link="#0a58ca", Highlight="#2f6fd0",
             HighlightedText="#ffffff", PlaceholderText="#8a8f98", Mid="#c4c8ce", Dark="#9aa0a8",
             Light="#ffffff", Midlight="#eceef0", Shadow="#777777")
    G = QtGui.QPalette.ColorGroup
    R = QtGui.QPalette.ColorRole
    for role in (R.WindowText, R.Text, R.ButtonText):
        pal.setColor(G.Disabled, role, QtGui.QColor("#9a9ea5"))
    return pal


def system_is_dark(app=None) -> bool:
    app = app or QtWidgets.QApplication.instance()
    try:
        return app.styleHints().colorScheme() == QtCore.Qt.ColorScheme.Dark
    except Exception:  # noqa: BLE001 - Qt < 6.5
        return QtGui.QGuiApplication.palette().color(QtGui.QPalette.ColorRole.Window).lightness() < 128


def get_mode() -> str:
    m = app_settings.get("theme", "system")
    return m if m in MODES else "system"


def effective_dark(mode: str, app=None) -> bool:
    return system_is_dark(app) if mode == "system" else mode == "dark"


def apply(app: QtWidgets.QApplication, mode: str = "system", persist: bool = False) -> bool:
    """Apply ``mode``; returns True when the resulting theme is dark."""
    if mode not in MODES:
        mode = "system"
    if not _originals:
        _originals["style"] = app.style().objectName()
        _originals["palette"] = QtGui.QPalette(app.palette())
    dark = effective_dark(mode, app)
    if mode == "system" and not dark:
        app.setStyle(_originals["style"])
        app.setPalette(_originals["palette"])
    else:
        app.setStyle("Fusion")
        app.setPalette(dark_palette() if dark else light_palette())
    try:  # Qt >= 6.8: lets the platform tint title bars etc.
        app.styleHints().setColorScheme(
            QtCore.Qt.ColorScheme.Unknown if mode == "system"
            else QtCore.Qt.ColorScheme.Dark if dark else QtCore.Qt.ColorScheme.Light)
    except Exception:  # noqa: BLE001
        pass
    if persist:
        app_settings.put("theme", mode)
    return dark


def watch_system(app: QtWidgets.QApplication) -> None:
    """Re-apply when the OS switches between light and dark (system mode only)."""
    try:
        app.styleHints().colorSchemeChanged.connect(
            lambda *_: apply(app, get_mode()) if get_mode() == "system" else None)
    except Exception:  # noqa: BLE001
        pass


def is_dark(widget: QtWidgets.QWidget | None = None) -> bool:
    """Whether the *application* palette is dark. (A widget's own palette is
    only refreshed once Qt has processed the PaletteChange event, so reading it
    right after ``apply`` would give the previous theme.)"""
    app = QtWidgets.QApplication.instance()
    pal = app.palette() if app is not None else QtGui.QGuiApplication.palette()
    return pal.color(QtGui.QPalette.ColorRole.Window).lightness() < 128


_STATUS = {  # (light, dark)
    "ok": ("#157f3b", "#4cc38a"),
    "bad": ("#b42318", "#ff7b72"),
    "warn": ("#b45309", "#f0b35a"),
}


def status_color(kind: str, widget: QtWidgets.QWidget | None = None) -> QtGui.QColor:
    dark = is_dark(widget) if widget is not None else effective_dark(get_mode())
    return QtGui.QColor(_STATUS[kind][1 if dark else 0])


SERIES = {
    "light": ["#2563eb", "#dc2626", "#059669", "#d97706", "#7c3aed", "#0891b2"],
    "dark": ["#6aa9ff", "#ff7b72", "#4cc38a", "#f0b35a", "#b794f6", "#56d4e6"],
}


def series_color(i: int, widget: QtWidgets.QWidget) -> QtGui.QColor:
    cols = SERIES["dark" if is_dark(widget) else "light"]
    return QtGui.QColor(cols[i % len(cols)])
