"""FortiGate 60F collector over the FortiOS REST API (read-only api-user).

One poller, 60 s minimum interval: the 60F is a small box. Policies and
objects are parsed to rows; the full config backup goes to the git store only.
"""

from __future__ import annotations

from typing import Any

import requests

from infra_agent.collectors.base import Collector, register
from infra_agent.models.common import Credential, DeviceKind, SeedDevice


def policy_row(p: dict[str, Any]) -> dict[str, Any]:
    """Flatten a FortiOS policy object to the row the graph and the LLM see."""

    def names(items: list[dict[str, Any]] | None) -> list[str]:
        return [i.get("name", "") for i in items or []]

    return {
        "id": p.get("policyid"),
        "name": p.get("name"),
        "status": p.get("status"),
        "action": p.get("action"),
        "srcintf": names(p.get("srcintf")),
        "dstintf": names(p.get("dstintf")),
        "srcaddr": names(p.get("srcaddr")),
        "dstaddr": names(p.get("dstaddr")),
        "service": names(p.get("service")),
        "schedule": p.get("schedule"),
        "nat": p.get("nat"),
        "logtraffic": p.get("logtraffic"),
        "utm": [
            k
            for k in ("av-profile", "webfilter-profile", "ips-sensor", "ssl-ssh-profile")
            if p.get(k)
        ],
        "comments": p.get("comments"),
    }


def interface_row(i: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": i.get("name"),
        "type": i.get("type"),
        "vdom": i.get("vdom"),
        "ip": i.get("ip"),
        "vlanid": i.get("vlanid"),
        "interface": i.get("interface"),  # parent for VLAN subinterfaces
        "alias": i.get("alias"),
        "role": i.get("role"),
        "status": i.get("status"),
        "allowaccess": i.get("allowaccess"),
        "lldp_reception": i.get("lldp-reception"),
        "lldp_transmission": i.get("lldp-transmission"),
    }


@register
class FortiGateCollector(Collector):
    kind = DeviceKind.fortigate
    name = "fortigate"
    interval_seconds = 60

    ENDPOINTS = {
        "status": "monitor/system/status",
        "interfaces": "cmdb/system/interface",
        "interface_stats": "monitor/system/interface",
        "zones": "cmdb/system/zone",
        "addresses": "cmdb/firewall/address",
        "addrgrps": "cmdb/firewall/addrgrp",
        "services": "cmdb/firewall.service/custom",
        "policies": "cmdb/firewall/policy",
        "vips": "cmdb/firewall/vip",
        "static_routes": "cmdb/router/static",
        "routing_table": "monitor/router/ipv4",
        "sdwan": "cmdb/system/sdwan",
        "sdwan_health": "monitor/virtual-wan/health-check",
        "ipsec": "monitor/vpn/ipsec",
        "dhcp_leases": "monitor/system/dhcp",
        "arp": "monitor/network/arp",
        "ha": "monitor/system/ha-peer",
        "lldp": "monitor/network/lldp/neighbors",
        "resources": "monitor/system/resource/usage",
        "firmware": "monitor/system/firmware",
    }

    def _session(self, device: SeedDevice, cred: Credential) -> tuple[requests.Session, str]:
        if not cred.token:
            raise ValueError("FortiGate collector needs an API token credential")
        s = requests.Session()
        s.headers["Authorization"] = f"Bearer {cred.token.get_secret_value()}"
        s.verify = False  # pinned in Phase 1
        return s, f"https://{device.mgmt_ip}:{device.port or 443}/api/v2/"

    def collect(self, device: SeedDevice, cred: Credential) -> dict[str, Any]:
        s, base = self._session(device, cred)
        raw: dict[str, Any] = {}
        errors: dict[str, str] = {}
        for key, ep in self.ENDPOINTS.items():
            try:
                r = s.get(base + ep, timeout=20)
                r.raise_for_status()
                raw[key] = r.json().get("results", r.json())
            except requests.RequestException as exc:
                errors[key] = str(exc)
        data: dict[str, Any] = {
            "system": {
                "hostname": (raw.get("status") or {}).get("hostname"),
                "version": (raw.get("status") or {}).get("version"),
                "serial": (raw.get("status") or {}).get("serial"),
            },
            "interfaces": [interface_row(i) for i in raw.get("interfaces", [])],
            "interface_stats": raw.get("interface_stats", {}),
            "zones": [
                {
                    "name": z.get("name"),
                    "interfaces": [i["interface-name"] for i in z.get("interface", [])],
                }
                for z in raw.get("zones", [])
            ],
            "addresses": [
                {
                    "name": a.get("name"),
                    "type": a.get("type"),
                    "subnet": a.get("subnet"),
                    "fqdn": a.get("fqdn"),
                    "start_ip": a.get("start-ip"),
                    "end_ip": a.get("end-ip"),
                    "interface": a.get("associated-interface"),
                }
                for a in raw.get("addresses", [])
            ],
            "addrgrps": [
                {"name": g.get("name"), "members": [m["name"] for m in g.get("member", [])]}
                for g in raw.get("addrgrps", [])
            ],
            "services": [
                {
                    "name": sv.get("name"),
                    "tcp": sv.get("tcp-portrange"),
                    "udp": sv.get("udp-portrange"),
                    "protocol": sv.get("protocol"),
                }
                for sv in raw.get("services", [])
            ],
            "policies": [policy_row(p) for p in raw.get("policies", [])],
            "vips": [
                {
                    "name": v.get("name"),
                    "extip": v.get("extip"),
                    "mappedip": [m["range"] for m in v.get("mappedip", [])],
                    "extintf": v.get("extintf"),
                    "portforward": v.get("portforward"),
                    "extport": v.get("extport"),
                    "mappedport": v.get("mappedport"),
                }
                for v in raw.get("vips", [])
            ],
            "static_routes": [
                {
                    "seq": r.get("seq-num"),
                    "dst": r.get("dst"),
                    "gateway": r.get("gateway"),
                    "device": r.get("device"),
                    "distance": r.get("distance"),
                    "priority": r.get("priority"),
                    "status": r.get("status"),
                }
                for r in raw.get("static_routes", [])
            ],
            "routing_table": raw.get("routing_table", []),
            "sdwan": raw.get("sdwan", {}),
            "sdwan_health": raw.get("sdwan_health", {}),
            "ipsec": [
                {
                    "name": t.get("name"),
                    "status": t.get("status")
                    or (
                        "up"
                        if any(px.get("status") == "up" for px in t.get("proxyid", []))
                        else "down"
                    ),
                    "rgwy": t.get("rgwy"),
                }
                for t in raw.get("ipsec", [])
            ],
            "dhcp_leases": [
                {
                    "ip": lease.get("ip"),
                    "mac": lease.get("mac"),
                    "hostname": lease.get("hostname"),
                    "interface": lease.get("interface"),
                    "expire": lease.get("expire_time"),
                }
                for lease in raw.get("dhcp_leases", [])
            ],
            "arp": [
                {"ip": a.get("ip"), "mac": a.get("mac"), "interface": a.get("interface")}
                for a in raw.get("arp", [])
            ],
            "ha": raw.get("ha", []),
            "lldp": raw.get("lldp", []),
            "resources": raw.get("resources", {}),
            "firmware": {
                "current": ((raw.get("firmware") or {}).get("current") or {}).get("version")
            },
            "errors": errors,
        }
        return data

    def configs(self, device: SeedDevice, cred: Credential) -> dict[str, str]:
        s, base = self._session(device, cred)
        r = s.get(base + "monitor/system/config/backup", params={"scope": "global"}, timeout=60)
        r.raise_for_status()
        return {"full-config.conf": r.text}
