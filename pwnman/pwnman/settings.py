"""Small QSettings wrapper for UI state (geometry, last tab, LCD prefs)."""
from __future__ import annotations

from PyQt6 import QtCore


def settings() -> QtCore.QSettings:
    return QtCore.QSettings("qPwnagotchi", "qPwnagotchi")


def get(key: str, default=None, type_=None):
    s = settings()
    v = s.value(key, default)
    if type_ is bool and isinstance(v, str):
        return v.lower() == "true"
    try:
        return type_(v) if type_ and v is not None else v
    except (TypeError, ValueError):
        return default


def put(key: str, value) -> None:
    s = settings()
    s.setValue(key, value)
    s.sync()
