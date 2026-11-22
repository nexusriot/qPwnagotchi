"""Fleet polling: per-device status probes over SSH + the Pwnagotchi REST API.

Everything here is plain Python (no Qt) so it can run on a worker thread and
be unit-tested. Each probe uses its OWN short-lived SSHClient — never the
MainWindow's shared client, whose single SFTP channel is not thread-safe.
"""
from __future__ import annotations

import base64
import json
import re
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

from pwnman.pwnman.models import ConnectionProfile
from pwnman.pwnman.known_hosts import HostKeyError
from pwnman.pwnman.ssh_client import SSHClient
from pwnman.pwnman.async_utils import quote_bash

_MARKERS = ["HOST", "UPTIME", "TEMP", "MEM", "HS", "SVC", "LOAD", "DISK", "IP", "BAT", "END"]

# One round-trip: marker line, then the value line(s) for that field.
PROBE_SCRIPT = r"""
echo '<<<HOST'; hostname 2>/dev/null
echo '<<<UPTIME'; awk '{print $1}' /proc/uptime 2>/dev/null
echo '<<<TEMP'
vcgencmd measure_temp 2>/dev/null
cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null
echo '<<<MEM'; free -m 2>/dev/null | awk '/^Mem:/{print $3" "$2}'
echo '<<<HS'; { sudo -n ls -1 /root/handshakes 2>/dev/null || ls -1 /root/handshakes 2>/dev/null; } | grep -c '\.pcap$'
echo '<<<SVC'; systemctl is-active pwnagotchi 2>/dev/null || echo unknown
echo '<<<LOAD'; cut -d' ' -f1-3 /proc/loadavg 2>/dev/null
echo '<<<DISK'; df -h / 2>/dev/null | awk 'NR==2{print $3" "$2" "$5}'
echo '<<<IP'; hostname -I 2>/dev/null | awk '{print $1}'
echo '<<<BAT'
if command -v nc >/dev/null 2>&1; then
  b=$(echo "get battery" | nc -q0 127.0.0.1 8423 2>/dev/null | sed -n 's/.*battery: *\([0-9.]*\).*/\1/p')
  [ -n "$b" ] && echo "pisugar:$b"
fi
for d in /sys/class/power_supply/*; do
  [ -r "$d/capacity" ] && [ "$(cat $d/type 2>/dev/null)" = Battery ] && { echo "battery:$(cat $d/capacity)"; break; }
done
echo '<<<END'
"""


@dataclass
class DeviceStatus:
    name: str
    host: str
    online: bool = False
    error: str = ""
    hostname: str = ""
    uptime: str = ""
    cpu_temp: Optional[float] = None  # Celsius
    mem_used_mb: Optional[int] = None
    mem_total_mb: Optional[int] = None
    handshakes: Optional[int] = None
    service_active: str = ""  # active / inactive / failed / unknown
    ai_epoch: Optional[int] = None
    ai_reward: Optional[float] = None
    rest_ok: bool = False
    load: str = ""
    disk: str = ""
    ip: str = ""
    battery: Optional[float] = None
    remote_name: str = ""
    face: str = ""
    peers: Optional[int] = None
    mode: str = ""
    rest_uptime: str = ""
    host_key_error: object = None  # HostKeyError when SSH was refused for that reason
    polled_at: float = field(default_factory=time.time)

    @property
    def mem_str(self) -> str:
        if self.mem_used_mb is None or self.mem_total_mb is None:
            return ""
        return f"{self.mem_used_mb}/{self.mem_total_mb} MB"

    @property
    def temp_str(self) -> str:
        return f"{self.cpu_temp:.1f}°C" if self.cpu_temp is not None else ""


def _fmt_uptime(seconds: float) -> str:
    s = int(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, _ = divmod(s, 60)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


def _first_float(text: str) -> Optional[float]:
    m = re.search(r"-?\d+(?:\.\d+)?", text)
    return float(m.group(0)) if m else None


def parse_probe(raw: str) -> dict:
    """Split the marker-delimited probe output into a field dict."""
    blocks: dict[str, list[str]] = {k: [] for k in _MARKERS}
    current: Optional[str] = None
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("<<<") and stripped[3:] in _MARKERS:
            current = stripped[3:]
            continue
        if current is not None:
            blocks[current].append(line)

    out: dict = {}
    out["hostname"] = "\n".join(blocks["HOST"]).strip()

    up = _first_float("\n".join(blocks["UPTIME"]))
    if up is not None:
        out["uptime"] = _fmt_uptime(up)

    temp = _first_float("\n".join(blocks["TEMP"]))
    if temp is not None:
        # thermal_zone reports millidegrees; vcgencmd reports e.g. 46.2
        out["cpu_temp"] = temp / 1000.0 if temp > 200 else temp

    mem_txt = "\n".join(blocks["MEM"]).strip()
    mem_m = re.search(r"(\d+)\s+(\d+)", mem_txt)
    if mem_m:
        out["mem_used_mb"] = int(mem_m.group(1))
        out["mem_total_mb"] = int(mem_m.group(2))

    hs = _first_float("\n".join(blocks["HS"]))
    if hs is not None:
        out["handshakes"] = int(hs)

    out["load"] = "\n".join(blocks["LOAD"]).strip()
    out["disk"] = "\n".join(blocks["DISK"]).strip()
    out["ip"] = "\n".join(blocks["IP"]).strip()
    bm = re.search(r"(?:pisugar|battery):([0-9.]+)", "\n".join(blocks["BAT"]))
    if bm:
        out["battery"] = float(bm.group(1))

    svc = "\n".join(blocks["SVC"]).strip().splitlines()
    out["service_active"] = (svc[-1].strip() if svc else "") or "unknown"
    return out


_API_PATHS = ("api/session", "api/v1/session")
_api_path_cache: dict[str, str] = {}


def _get_json(url: str, profile: ConnectionProfile, timeout: float) -> dict:
    req = urllib.request.Request(url)
    if profile.lcd_user or profile.lcd_pass:
        token = base64.b64encode(
            f"{profile.lcd_user}:{profile.lcd_pass}".encode()
        ).decode()
        req.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - user-configured host
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    return data if isinstance(data, dict) else {}


def _fetch_rest_session(profile: ConnectionProfile, timeout: float) -> dict:
    """GET the session JSON from the web UI. Best-effort.

    Pwnagotchi builds differ (``/api/session`` vs ``/api/v1/session``); both
    are tried and the working one is remembered per base URL.
    """
    base = (profile.lcd_url or "").strip()
    if not base:
        return {}
    if not base.endswith("/"):
        base += "/"
    cached = _api_path_cache.get(base)
    paths = ([cached] if cached else []) + [p for p in _API_PATHS if p != cached]
    last: Exception = ValueError("no API path")
    for path in paths:
        try:
            data = _get_json(urljoin(base, path), profile, timeout)
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (404, 405):
                continue
            raise
        except (urllib.error.URLError, OSError, ValueError) as e:
            last = e
            raise
        _api_path_cache[base] = path
        return data
    raise last


def _dig(data: dict, *paths):
    """First non-None value among dotted paths ('a.b' -> data['a']['b'])."""
    for path in paths:
        cur = data
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                cur = None
                break
        if cur is not None:
            return cur
    return None


def _extract_ai(data: dict) -> dict:
    """Tolerant extraction: field names differ between Pwnagotchi builds."""
    out: dict = {}
    epoch = _dig(data, "epoch", "ai.epoch", "brain.epoch", "state.epoch")
    if isinstance(epoch, (int, float)):
        out["ai_epoch"] = int(epoch)
    reward = _dig(data, "reward", "ai.reward", "brain.reward", "state.reward")
    if isinstance(reward, (int, float)):
        out["ai_reward"] = float(reward)
    hs = _dig(data, "num_handshakes", "state.handshakes", "handshakes")
    if isinstance(hs, int):
        out["handshakes"] = hs
    name = _dig(data, "name", "advertisement.name")
    if isinstance(name, str):
        out["remote_name"] = name
    face = _dig(data, "face", "advertisement.face")
    if isinstance(face, str):
        out["face"] = face
    peers = _dig(data, "peers", "friends", "advertisement.peers")
    if isinstance(peers, (list, dict)):
        out["peers"] = len(peers)
    elif isinstance(peers, int):
        out["peers"] = peers
    mode = _dig(data, "mode")
    if isinstance(mode, str):
        out["mode"] = mode
    up = _dig(data, "uptime")
    if isinstance(up, (int, float)):
        out["rest_uptime"] = _fmt_uptime(up)
    elif isinstance(up, str):
        out["rest_uptime"] = up
    return out


def collect_status(ssh, profile: ConnectionProfile, ssh_timeout: float = 6.0,
                   rest_timeout: float = 5.0, do_rest: bool = True) -> DeviceStatus:
    """Probe an already-connected ``ssh`` (+ REST) and return a DeviceStatus.

    Shared by the fleet poller (own short-lived client) and the dashboard
    (the main window's session)."""
    st = DeviceStatus(name=profile.name, host=profile.host)
    try:
        r = ssh.run(f"bash -lc {quote_bash(PROBE_SCRIPT)}", timeout_sec=ssh_timeout + 6)
        fields = parse_probe(r.stdout or "")
        st.online = True
        st.hostname = fields.get("hostname", "")
        st.uptime = fields.get("uptime", "")
        st.cpu_temp = fields.get("cpu_temp")
        st.mem_used_mb = fields.get("mem_used_mb")
        st.mem_total_mb = fields.get("mem_total_mb")
        st.handshakes = fields.get("handshakes")
        st.service_active = fields.get("service_active", "")
        st.load = fields.get("load", "")
        st.disk = fields.get("disk", "")
        st.ip = fields.get("ip", "")
        st.battery = fields.get("battery")
    except Exception as e:  # noqa: BLE001
        st.online = False
        st.error = str(e) or e.__class__.__name__

    if do_rest:
        _apply_rest(st, profile, rest_timeout)
    st.polled_at = time.time()
    return st


def _apply_rest(st: DeviceStatus, profile: ConnectionProfile, rest_timeout: float) -> None:
    try:
        data = _fetch_rest_session(profile, rest_timeout)
        if data:
            ai = _extract_ai(data)
            st.ai_epoch = ai.get("ai_epoch")
            st.ai_reward = ai.get("ai_reward")
            st.remote_name = ai.get("remote_name", "")
            st.face = ai.get("face", "")
            st.peers = ai.get("peers")
            st.mode = ai.get("mode", "")
            st.rest_uptime = ai.get("rest_uptime", "")
            if st.handshakes is None and "handshakes" in ai:
                st.handshakes = ai["handshakes"]
            st.rest_ok = True
    except (urllib.error.URLError, OSError, ValueError, socket.timeout):
        st.rest_ok = False


def probe_device(
    profile: ConnectionProfile,
    ssh_timeout: float = 6.0,
    rest_timeout: float = 5.0,
    do_rest: bool = True,
) -> DeviceStatus:
    ssh = SSHClient()
    try:
        ssh.connect(
            host=profile.host,
            port=int(profile.port or 22),
            username=profile.username,
            password=profile.password,
            key_path=profile.key_path,
            timeout_sec=ssh_timeout,
        )
    except Exception as e:  # noqa: BLE001
        ssh.close()
        st = DeviceStatus(name=profile.name, host=profile.host)
        st.error = str(e) or e.__class__.__name__
        st.host_key_error = e if isinstance(e, HostKeyError) else None
        if do_rest:
            _apply_rest(st, profile, rest_timeout)  # REST may work even if SSH doesn't
        st.polled_at = time.time()
        return st
    try:
        return collect_status(ssh, profile, ssh_timeout, rest_timeout, do_rest)
    finally:
        ssh.close()


def run_remote_command(
    profile: ConnectionProfile,
    command: str,
    timeout: float = 25.0,
    expect_drop: bool = False,
) -> tuple[bool, str]:
    """Run one command on a device with its own SSH client (bulk actions).

    expect_drop=True is for reboot/shutdown where the connection legitimately
    dies mid-command; that is reported as success.
    """
    ssh = SSHClient()
    try:
        ssh.connect(
            host=profile.host,
            port=int(profile.port or 22),
            username=profile.username,
            password=profile.password,
            key_path=profile.key_path,
            timeout_sec=8.0,
        )
        try:
            r = ssh.run(command, timeout_sec=timeout)
        except Exception as e:  # noqa: BLE001
            if expect_drop:
                return True, "command sent (connection dropped)"
            return False, str(e)
        text = ((r.stdout or "") + ("\n" + r.stderr if r.stderr else "")).strip()
        ok = expect_drop or getattr(r, "exit_status", 0) == 0
        return ok, text or ("ok" if ok else "failed")
    except (OSError, ConnectionError, Exception) as e:  # noqa: BLE001
        return False, str(e) or e.__class__.__name__
    finally:
        ssh.close()
