from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Optional

from pwnman.pwnman.models import ConnectionProfile

APP_DIR_NAME = "qPwnagotchi"
PROFILES_FILE = "profiles.json"
SCHEMA_VERSION = 1


def config_dir() -> Path:
    """Return the per-user config directory for this app (created if missing).

    Windows: %APPDATA%\\qPwnagotchi
    macOS:   ~/Library/Application Support/qPwnagotchi
    Linux:   $XDG_CONFIG_HOME/qPwnagotchi  (default ~/.config/qPwnagotchi)
    """
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        base = str(Path.home() / "Library" / "Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")

    d = Path(base) / APP_DIR_NAME
    d.mkdir(parents=True, exist_ok=True)
    if not sys.platform.startswith("win"):
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
    return d


def profiles_path() -> Path:
    return config_dir() / PROFILES_FILE


class ProfileStore:
    """Loads and persists connection profiles to the per-user config folder.

    The file holds IP addresses and passwords in plaintext, so it is written
    with owner-only permissions (0600) on POSIX systems.
    """

    def __init__(self, path: Optional[Path] = None, secrets=None) -> None:
        """``secrets``: None = plaintext 0600 JSON (legacy); ``"auto"`` = use the
        OS keyring when available; or any object with get/set/delete."""
        self.path = Path(path) if path else profiles_path()
        if secrets == "auto":
            from pwnman.pwnman.secrets_store import KeyringBackend
            secrets = KeyringBackend.detect()
        self.secrets = secrets
        self._profiles: list[ConnectionProfile] = []
        self._active: str = ""
        self.load()

    @property
    def profiles(self) -> list[ConnectionProfile]:
        return list(self._profiles)

    def names(self) -> list[str]:
        return [p.name for p in self._profiles]

    @property
    def active_name(self) -> str:
        return self._active

    @active_name.setter
    def active_name(self, name: str) -> None:
        self._active = name or ""

    def get(self, name: str) -> Optional[ConnectionProfile]:
        for p in self._profiles:
            if p.name == name:
                return p
        return None

    def active(self) -> Optional[ConnectionProfile]:
        return self.get(self._active) if self._active else None

    def upsert(self, profile: ConnectionProfile) -> None:
        for i, p in enumerate(self._profiles):
            if p.name == profile.name:
                self._profiles[i] = profile
                return
        self._profiles.append(profile)

    def delete(self, name: str) -> None:
        if self.secrets is not None:
            self.secrets.delete(f"{name}:ssh")
            self.secrets.delete(f"{name}:lcd")
        self._profiles = [p for p in self._profiles if p.name != name]
        if self._active == name:
            self._active = self._profiles[0].name if self._profiles else ""

    def replace_all(self, profiles: list[ConnectionProfile], active: str = "") -> None:
        self._profiles = list(profiles)
        existing = self.names()
        self._active = active if active in existing else (existing[0] if existing else "")

    def load(self) -> None:
        if not self.path.is_file():
            self._profiles = []
            self._active = ""
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self._profiles = []
            self._active = ""
            return

        raw = data.get("profiles", []) if isinstance(data, dict) else []
        self._profiles = [ConnectionProfile.from_dict(d) for d in raw if isinstance(d, dict)]
        if self.secrets is not None:
            for p in self._profiles:
                # Plain values in the file (pre-keyring) win; they are moved to
                # the keyring on the next save().
                if not p.password:
                    p.password = self.secrets.get(f"{p.name}:ssh")
                if not p.lcd_pass:
                    p.lcd_pass = self.secrets.get(f"{p.name}:lcd")
        active = data.get("active", "") if isinstance(data, dict) else ""
        self._active = active if active in self.names() else ""

    def save(self) -> None:
        dicts = []
        for p in self._profiles:
            d = p.to_dict()
            if self.secrets is not None:
                ok1 = self.secrets.set(f"{p.name}:ssh", p.password)
                ok2 = self.secrets.set(f"{p.name}:lcd", p.lcd_pass)
                if ok1:
                    d["password"] = ""
                if ok2:
                    d["lcd_pass"] = ""
            dicts.append(d)
        payload = {
            "version": SCHEMA_VERSION,
            "active": self._active,
            "profiles": dicts,
        }
        text = json.dumps(payload, indent=2, ensure_ascii=False)

        # Atomic write: temp file in the same dir, then replace.
        directory = self.path.parent
        directory.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".profiles-", suffix=".tmp", dir=str(directory))
        try:
            if not sys.platform.startswith("win"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.replace(tmp_path, self.path)
        except OSError:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        if not sys.platform.startswith("win"):
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
