from __future__ import annotations

from dataclasses import dataclass, asdict, fields


@dataclass
class ConnectionProfile:
    name: str
    host: str = ""
    port: int = 22
    username: str = "pi"
    password: str = ""
    key_path: str = ""  # optional path to private key
    # Web LCD settings (per-device, since URL/creds differ per pwnagotchi)
    lcd_url: str = ""
    lcd_user: str = "changeme"
    lcd_pass: str = "changeme"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ConnectionProfile":
        known = {f.name for f in fields(cls)}
        kwargs = {k: v for k, v in (data or {}).items() if k in known}
        if "name" not in kwargs:
            kwargs["name"] = "unnamed"
        try:
            kwargs["port"] = int(kwargs.get("port", 22))
        except (TypeError, ValueError):
            kwargs["port"] = 22
        return cls(**kwargs)
