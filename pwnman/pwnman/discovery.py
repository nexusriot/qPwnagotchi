"""Find Pwnagotchi devices: mDNS (zeroconf) + quick port-22 scan of tether subnets."""
from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Iterable

WELL_KNOWN = ["10.0.0.2", "192.168.44.44", "pwnagotchi.local"]


@dataclass(frozen=True)
class Found:
    host: str
    source: str       # mdns | known | scan
    name: str = ""


def port_open(host: str, port: int = 22, timeout: float = 0.6) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_hosts(hosts: Iterable[str], port: int = 22, timeout: float = 0.6,
               workers: int = 64, probe: Callable[[str, int, float], bool] = port_open) -> list[str]:
    hosts = list(hosts)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        ok = list(ex.map(lambda h: probe(h, port, timeout), hosts))
    return [h for h, good in zip(hosts, ok, strict=True) if good]


def subnet_hosts(cidr: str, limit: int = 1024) -> list[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    return [str(h) for h in list(net.hosts())[:limit]]


def local_subnets() -> list[str]:
    """/24 of each local IPv4 address (best effort, stdlib only)."""
    nets = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                nets.add(str(ipaddress.ip_network(f"{ip}/24", strict=False)))
    except OSError:
        pass
    try:  # the default-route address, even if the hostname does not resolve
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        nets.add(str(ipaddress.ip_network(f"{s.getsockname()[0]}/24", strict=False)))
        s.close()
    except OSError:
        pass
    return sorted(nets)


def mdns_browse(seconds: float = 3.0) -> list[Found]:
    """Browse _ssh._tcp; keep services that look like a pwnagotchi."""
    try:
        from zeroconf import ServiceBrowser, Zeroconf
    except Exception:  # noqa: BLE001 - optional dependency
        return []
    found: dict[str, Found] = {}

    class L:
        def add_service(self, zc, type_, name):
            info = zc.get_service_info(type_, name, timeout=1500)
            if not info:
                return
            for addr in info.parsed_addresses():
                if ":" in addr:
                    continue
                host = info.server.rstrip(".") if info.server else addr
                label = name.split(".")[0]
                if "pwn" in label.lower() or "pwn" in host.lower():
                    found[addr] = Found(addr, "mdns", label)

        def update_service(self, *a): pass
        def remove_service(self, *a): pass

    zc = Zeroconf()
    try:
        ServiceBrowser(zc, "_ssh._tcp.local.", L())
        time.sleep(seconds)
    finally:
        zc.close()
    return list(found.values())


def discover(include_lan: bool = False, mdns_seconds: float = 3.0,
             probe: Callable[[str, int, float], bool] = port_open) -> list[Found]:
    out: dict[str, Found] = {}
    for f in mdns_browse(mdns_seconds):
        out[f.host] = f
    for h in scan_hosts(WELL_KNOWN, probe=probe):
        out.setdefault(h, Found(h, "known"))
    if include_lan:
        for cidr in local_subnets():
            for h in scan_hosts(subnet_hosts(cidr), probe=probe):
                out.setdefault(h, Found(h, "scan"))
    return list(out.values())
