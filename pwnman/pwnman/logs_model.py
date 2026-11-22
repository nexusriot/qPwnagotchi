"""Qt-free log filtering for the live log viewer."""
from __future__ import annotations

import re
from collections import deque
from typing import Iterable

LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR"]
_RANK = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "WARN": 2, "ERROR": 3, "CRITICAL": 3}
_LEVEL_RE = re.compile(r"\[(DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL)\]", re.I)


def line_level(line: str) -> str:
    m = _LEVEL_RE.search(line)
    return m.group(1).upper() if m else ""


def matches(line: str, min_level: str = "DEBUG", text: str = "") -> bool:
    lvl = line_level(line)
    # Unlabelled lines (stack traces, journal headers) follow "INFO" so they are
    # visible at INFO and below but hidden when only warnings/errors are wanted.
    rank = _RANK.get(lvl, 1)
    if rank < _RANK.get(min_level.upper(), 0):
        return False
    return text.lower() in line.lower() if text else True


class LogBuffer:
    def __init__(self, maxlen: int = 20000):
        self.lines: deque[str] = deque(maxlen=maxlen)

    def add(self, line: str) -> None:
        self.lines.append(line)

    def clear(self) -> None:
        self.lines.clear()

    def filtered(self, min_level: str = "DEBUG", text: str = "") -> Iterable[str]:
        return [l for l in self.lines if matches(l, min_level, text)]
