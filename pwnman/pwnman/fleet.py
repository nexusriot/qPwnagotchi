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
from pwnman.pwnman.ssh_client import SSHClient
from pwnman.pwnman.async_utils import quote_bash

_MARKERS = ["HOST", "UPTIME", "TEMP", "MEM", "HS", "SVC", "END"]

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

    svc = "\n".join(blocks["SVC"]).strip().splitlines()
    out["service_active"] = (svc[-1].strip() if svc else "") or "unknown"
    return out


def _fetch_rest_session(profile: ConnectionProfile, timeout: float) -> dict:
    """GET <lcd_url>/api/v1/session with HTTP basic auth. Best-effort."""
    base = (profile.lcd_url or "").strip()
    if not base:
        return {}
    if not base.endswith("/"):
        base += "/"
    url = urljoin(base, "api/v1/session")
    req = urllib.request.Request(url)
    if profile.lcd_user or profile.lcd_pass:
        token = base64.b64encode(
            f"{profile.lcd_user}:{profile.lcd_pass}".encode()
        ).decode()
        req.add_header("Authorization", f"Basic {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - user-configured host
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    return data if isinstance(data, dict) else {}


def _extract_ai(data: dict) -> dict:
    out: dict = {}
    epoch = data.get("epoch")
    if epoch is None and isinstance(data.get("ai"), dict):
        epoch = data["ai"].get("epoch")
    if isinstance(epoch, (int, float)):
        out["ai_epoch"] = int(epoch)

    reward = data.get("reward")
    if reward is None and isinstance(data.get("ai"), dict):
        reward = data["ai"].get("reward")
    if isinstance(reward, (int, float)):
        out["ai_reward"] = float(reward)

    if "handshakes" not in out:
        hs = data.get("num_handshakes")
        if isinstance(hs, int):
            out["handshakes"] = hs
    return out


def probe_device(
    profile: ConnectionProfile,
    ssh_timeout: float = 6.0,
    rest_timeout: float = 5.0,
    do_rest: bool = True,
) -> DeviceStatus:
    st = DeviceStatus(name=profile.name, host=profile.host)

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
    except (OSError, socket.timeout, ConnectionError, Exception) as e:  # noqa: BLE001
        st.online = False
        st.error = str(e) or e.__class__.__name__
    finally:
        ssh.close()

    if do_rest:
        try:
            data = _fetch_rest_session(profile, rest_timeout)
            if data:
                ai = _extract_ai(data)
                st.ai_epoch = ai.get("ai_epoch")
                st.ai_reward = ai.get("ai_reward")
                if st.handshakes is None and "handshakes" in ai:
                    st.handshakes = ai["handshakes"]
                st.rest_ok = True
        except (urllib.error.URLError, OSError, ValueError, socket.timeout):
            st.rest_ok = False

    st.polled_at = time.time()
    return st


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
