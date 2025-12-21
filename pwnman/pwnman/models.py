from dataclasses import dataclass

@dataclass
class ConnectionProfile:
    name: str
    host: str
    port: int = 22
    username: str = "pi"
    password: str = ""
    key_path: str = ""  # optional path to private key
