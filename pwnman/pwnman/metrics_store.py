"""Metrics history: SQLite samples of every DeviceStatus the app sees.

Qt-free. One short-lived connection per call (cheap for SQLite, and it keeps
the store usable from any thread). Retention is enforced by ``prune``.
"""
from __future__ import annotations

import csv
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    ts REAL NOT NULL,
    device TEXT NOT NULL,
    online INTEGER NOT NULL,
    cpu_temp REAL,
    mem_pct REAL,
    handshakes INTEGER,
    epoch INTEGER,
    reward REAL,
    battery REAL,
    load1 REAL
);
CREATE INDEX IF NOT EXISTS idx_samples_dev_ts ON samples(device, ts);
"""

FIELDS = ("cpu_temp", "mem_pct", "handshakes", "epoch", "reward", "battery", "load1")
RANGES = {"1 hour": 3600, "6 hours": 6 * 3600, "24 hours": 86400,
          "7 days": 7 * 86400, "30 days": 30 * 86400}


@dataclass
class Sample:
    ts: float
    device: str
    online: bool
    cpu_temp: Optional[float] = None
    mem_pct: Optional[float] = None
    handshakes: Optional[int] = None
    epoch: Optional[int] = None
    reward: Optional[float] = None
    battery: Optional[float] = None
    load1: Optional[float] = None


def sample_from_status(st, ts: Optional[float] = None) -> Sample:
    mem = None
    if st.mem_used_mb is not None and st.mem_total_mb:
        mem = 100.0 * st.mem_used_mb / st.mem_total_mb
    load1 = None
    try:
        if st.load:
            load1 = float(st.load.split()[0])
    except (ValueError, IndexError):
        pass
    return Sample(ts=ts if ts is not None else time.time(), device=st.name, online=bool(st.online),
                  cpu_temp=st.cpu_temp, mem_pct=mem, handshakes=st.handshakes,
                  epoch=st.ai_epoch, reward=st.ai_reward, battery=st.battery, load1=load1)


def default_path() -> Path:
    from pwnman.pwnman.profile_store import config_dir
    return config_dir() / "metrics.db"


class MetricsStore:
    def __init__(self, path=None, min_interval: float = 20.0, retention_days: float = 30.0):
        self.path = Path(path) if path else default_path()
        self.min_interval = min_interval
        self.retention_days = retention_days
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        c = sqlite3.connect(self.path, timeout=10)
        return c

    # ---------------------------------------------------------------- writes
    def record(self, st, ts: Optional[float] = None) -> bool:
        """Store one sample. Returns False when throttled (the fleet poller and
        the dashboard both report the same device within seconds)."""
        s = sample_from_status(st, ts)
        with self._lock:
            last = self._last.get(s.device)
            if last is not None and 0 <= s.ts - last < self.min_interval:
                return False
            self._last[s.device] = s.ts
        with self._conn() as c:
            c.execute(
                "INSERT INTO samples VALUES (?,?,?,?,?,?,?,?,?,?)",
                (s.ts, s.device, int(s.online), s.cpu_temp, s.mem_pct, s.handshakes,
                 s.epoch, s.reward, s.battery, s.load1))
        return True

    def prune(self, now: Optional[float] = None) -> int:
        cutoff = (now if now is not None else time.time()) - self.retention_days * 86400
        with self._conn() as c:
            return c.execute("DELETE FROM samples WHERE ts < ?", (cutoff,)).rowcount

    def clear(self, device: Optional[str] = None) -> int:
        with self._conn() as c:
            if device:
                n = c.execute("DELETE FROM samples WHERE device = ?", (device,)).rowcount
            else:
                n = c.execute("DELETE FROM samples").rowcount
        self._last.pop(device, None) if device else self._last.clear()
        return n

    # ----------------------------------------------------------------- reads
    def devices(self) -> list[str]:
        with self._conn() as c:
            return [r[0] for r in c.execute("SELECT DISTINCT device FROM samples ORDER BY device")]

    def query(self, device: str, since: float = 0.0, until: Optional[float] = None) -> list[Sample]:
        until = until if until is not None else time.time() + 1
        with self._conn() as c:
            rows = c.execute(
                "SELECT ts,device,online,cpu_temp,mem_pct,handshakes,epoch,reward,battery,load1 "
                "FROM samples WHERE device=? AND ts>=? AND ts<=? ORDER BY ts",
                (device, since, until)).fetchall()
        return [Sample(r[0], r[1], bool(r[2]), *r[3:]) for r in rows]

    def count(self) -> int:
        with self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM samples").fetchone()[0]

    def export_csv(self, path: str, device: str, since: float = 0.0) -> int:
        rows = self.query(device, since)
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["time", "device", "online", *FIELDS])
            for s in rows:
                w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s.ts)), s.device,
                            int(s.online), *[getattr(s, f) for f in FIELDS]])
        return len(rows)


# ------------------------------------------------------------------- analysis
def series(samples: Iterable[Sample], field: str) -> list[tuple[float, float]]:
    return [(s.ts, float(getattr(s, field))) for s in samples
            if s.online and getattr(s, field) is not None]


def downsample(points: list[tuple[float, float]], max_points: int) -> list[tuple[float, float]]:
    """Bucket-average to at most ``max_points`` (keeps the first/last timestamps)."""
    n = len(points)
    if max_points <= 0 or n <= max_points:
        return list(points)
    out = []
    size = n / max_points
    for i in range(max_points):
        chunk = points[int(i * size):int((i + 1) * size)] or [points[-1]]
        out.append((sum(p[0] for p in chunk) / len(chunk), sum(p[1] for p in chunk) / len(chunk)))
    out[0] = (points[0][0], out[0][1])
    out[-1] = (points[-1][0], out[-1][1])
    return out


def stats(points: list[tuple[float, float]]) -> Optional[dict]:
    if not points:
        return None
    vals = [p[1] for p in points]
    return {"min": min(vals), "max": max(vals), "avg": sum(vals) / len(vals),
            "last": vals[-1], "n": len(vals)}


def availability(samples: list[Sample]) -> Optional[float]:
    """Percentage of samples in which the device was online."""
    if not samples:
        return None
    return 100.0 * sum(s.online for s in samples) / len(samples)


def handshake_gain(samples: list[Sample]) -> int:
    """Handshakes captured over the window; counter resets (a wipe) are not counted
    as losses and the new counter value counts as fresh captures."""
    vals = [s.handshakes for s in samples if s.online and s.handshakes is not None]
    gain = 0
    for a, b in zip(vals, vals[1:], strict=False):
        gain += b - a if b >= a else b
    return gain


def nice_ticks(lo: float, hi: float, target: int = 5) -> list[float]:
    """Round tick values covering [lo, hi]."""
    if hi < lo:
        lo, hi = hi, lo
    if hi == lo:
        hi = lo + 1.0
    raw = (hi - lo) / max(1, target)
    import math
    mag = 10 ** math.floor(math.log10(raw))
    step = next(m * mag for m in (1, 2, 2.5, 5, 10) if m * mag >= raw)
    start = math.floor(lo / step) * step
    ticks, v = [], start
    while v <= hi + step * 0.5:
        ticks.append(round(v, 10))
        v += step
    return ticks
