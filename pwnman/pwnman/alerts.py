"""Qt-free alert rules over successive DeviceStatus samples."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Alert:
    device: str
    kind: str   # offline | online | handshake | service | battery
    text: str


@dataclass
class _State:
    online: Optional[bool] = None
    misses: int = 0
    handshakes: Optional[int] = None
    service: str = ""
    low_battery_notified: bool = False


@dataclass
class AlertEngine:
    offline_after: int = 2        # consecutive failed polls before "offline"
    battery_low: float = 15.0
    states: dict = field(default_factory=dict)

    def update(self, st) -> list[Alert]:
        s: _State = self.states.setdefault(st.name, _State())
        out: list[Alert] = []

        if st.online:
            if s.online is False:
                out.append(Alert(st.name, "online", f"{st.name} is back online"))
            s.online, s.misses = True, 0
        else:
            s.misses += 1
            if s.misses >= self.offline_after and s.online is not False:
                if s.online is True:  # only announce a transition, not first sight
                    out.append(Alert(st.name, "offline", f"{st.name} went offline"))
                s.online = False
            return out

        hs = st.handshakes
        if hs is not None:
            if s.handshakes is not None and hs > s.handshakes:
                out.append(Alert(st.name, "handshake",
                                 f"{st.name}: +{hs - s.handshakes} handshake(s) (total {hs})"))
            s.handshakes = hs

        svc = st.service_active or ""
        if svc and svc != s.service and s.service == "active" and svc != "active":
            out.append(Alert(st.name, "service", f"{st.name}: pwnagotchi service is {svc}"))
        if svc:
            s.service = svc

        bat = st.battery
        if bat is not None:
            if bat <= self.battery_low and not s.low_battery_notified:
                out.append(Alert(st.name, "battery", f"{st.name}: battery low ({bat:.0f}%)"))
                s.low_battery_notified = True
            elif bat > self.battery_low + 5:
                s.low_battery_notified = False
        return out
