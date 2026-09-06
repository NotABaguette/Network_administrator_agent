"""Find devices on the management network the owner forgot to onboard.

TCP-connect probes only (no SYN scanning, no exploitation), plus a Redfish
root and HTTPS server-header peek to guess the platform.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import requests

PORTS = {22: "ssh", 443: "https", 8443: "https-alt", 902: "vmware-authd", 161: "snmp"}


@dataclass
class ScanHit:
    ip: str
    open_ports: list[int] = field(default_factory=list)
    hint: str | None = None


def _open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _hint(ip: str, ports: list[int]) -> str | None:
    if 443 in ports:
        try:
            r = requests.get(f"https://{ip}/redfish/v1/", verify=False, timeout=3)
            if r.ok and "RedfishVersion" in r.text:
                return "redfish (iLO?)"
        except requests.RequestException:
            pass
        try:
            r = requests.get(f"https://{ip}/", verify=False, timeout=3)
            server = r.headers.get("Server", "")
            body = r.text[:2000].lower()
            if "vmware" in body or "esxi" in body:
                return "esxi"
            if "fortinet" in body or "fortigate" in body or "xxxxxxxx" in server:
                return "fortigate"
            if "cisco" in body:
                return "cisco"
        except requests.RequestException:
            pass
    if 902 in ports:
        return "esxi"
    if 22 in ports and 443 not in ports:
        return "ssh-only (switch?)"
    return None


def scan(cidr: str, timeout: float = 0.5, workers: int = 64) -> list[ScanHit]:
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]

    def check(ip: str) -> ScanHit | None:
        open_ports = [p for p in PORTS if p != 161 and _open(ip, p, timeout)]
        if not open_ports:
            return None
        return ScanHit(ip=ip, open_ports=open_ports, hint=_hint(ip, open_ports))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return [hit for hit in pool.map(check, hosts) if hit]
