"""Optional OS-keyring storage for profile secrets (passwords).

``KeyringBackend.available()`` is False on headless systems without a usable
backend; callers then keep the legacy 0600 JSON behaviour and show a warning.
"""
from __future__ import annotations

from typing import Optional

SERVICE = "qPwnagotchi"


class KeyringBackend:
    def __init__(self, kr=None):
        self._kr = kr

    @staticmethod
    def detect() -> Optional["KeyringBackend"]:
        try:
            import keyring
            from keyring.backends import fail
            kr = keyring.get_keyring()
            if isinstance(kr, fail.Keyring) or kr.priority <= 0:
                return None
            return KeyringBackend(keyring)
        except Exception:  # noqa: BLE001 - keyring missing or broken
            return None

    def get(self, key: str) -> str:
        try:
            return self._kr.get_password(SERVICE, key) or ""
        except Exception:  # noqa: BLE001
            return ""

    def set(self, key: str, value: str) -> bool:
        try:
            if value:
                self._kr.set_password(SERVICE, key, value)
            else:
                self.delete(key)
            return True
        except Exception:  # noqa: BLE001
            return False

    def delete(self, key: str) -> None:
        try:
            self._kr.delete_password(SERVICE, key)
        except Exception:  # noqa: BLE001
            pass
