"""The canonical estate model shared by observation, NetBox and drift.

One model describes both sides of the comparison: `observed.build_estate()`
produces an `Estate` from collector snapshots, `drift.intended_from_netbox()`
produces an `Estate` from NetBox, and `drift.compare()` diffs the two. Nothing
in here holds raw configuration text or secrets, so an `Estate` (and anything
derived from it) is safe to hand to the redaction gateway.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from infra_agent.models.common import DeviceKind

# Sources whose IP bindings represent intent (a configured address) rather than
# a transient observation such as an ARP cache entry or a DHCP lease.
ASSIGNED_IP_SOURCES = frozenset({"interface", "vm", "vmkernel", "netbox"})

# Cisco abbreviates interface names differently per `show` command.
_IFNAME_PREFIXES = {
    "fa": "FastEthernet",
    "gi": "GigabitEthernet",
    "te": "TenGigabitEthernet",
    "tw": "TwoGigabitEthernet",
    "twe": "TwentyFiveGigE",
    "fo": "FortyGigabitEthernet",
    "hu": "HundredGigE",
    "eth": "Ethernet",
    "po": "Port-channel",
    "vl": "Vlan",
    "lo": "Loopback",
    "tu": "Tunnel",
    "se": "Serial",
    "ap": "AppGigabitEthernet",
}
_IFNAME_RE = re.compile(r"^([A-Za-z][A-Za-z\-]*?)\s*([0-9][0-9/.:]*)$")
_HEX_RE = re.compile(r"[0-9a-fA-F]")


def normalize_mac(value: Any) -> str | None:
    """`aabb.ccdd.eeff`, `AA-BB-CC-DD-EE-FF`, `aabbccddeeff` -> `aa:bb:cc:dd:ee:ff`."""
    if not value:
        return None
    digits = "".join(_HEX_RE.findall(str(value)))
    if len(digits) != 12:
        return None
    digits = digits.lower()
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def normalize_ifname(value: Any) -> str:
    """Expand an abbreviated Cisco interface name; leave anything else alone."""
    if not value:
        return ""
    name = str(value).strip()
    match = _IFNAME_RE.match(name)
    if not match:
        return name
    alpha, digits = match.group(1), match.group(2)
    key = alpha.lower().replace("-", "")
    for full in _IFNAME_PREFIXES.values():
        if key == full.lower().replace("-", ""):
            return f"{full}{digits}"
    for length in (3, 2):
        prefix = key[:length]
        if key == prefix and prefix in _IFNAME_PREFIXES:
            return f"{_IFNAME_PREFIXES[prefix]}{digits}"
    return name


def to_cidr(address: Any, netmask: Any = None) -> str | None:
    """Build a `10.0.0.1/24` string from an address plus an optional mask.

    Accepts FortiOS' single-field `"10.0.0.1 255.255.255.0"` form as well.
    """
    if not address:
        return None
    text = str(address).strip()
    if not text or text.startswith("0.0.0.0"):
        return None
    given_prefix: str | None = None
    if "/" in text:
        text, _, given_prefix = text.partition("/")
    elif netmask is None and " " in text:
        text, _, netmask = text.partition(" ")
    try:
        addr = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    if given_prefix:
        prefixlen: int | str = given_prefix.strip()
    elif netmask:
        try:
            prefixlen = ipaddress.IPv4Network(f"0.0.0.0/{str(netmask).strip()}").prefixlen
        except ValueError:
            return None
    else:
        prefixlen = 32
    try:
        return str(ipaddress.ip_interface(f"{addr}/{prefixlen}"))
    except ValueError:
        return None


def network_of(cidr: str) -> str | None:
    try:
        return str(ipaddress.ip_interface(cidr).network)
    except ValueError:
        return None


def bare_ip(address: Any) -> str | None:
    if not address:
        return None
    try:
        return str(ipaddress.ip_interface(str(address).strip()).ip)
    except ValueError:
        return None


class Interface(BaseModel):
    """A physical or logical interface on a device."""

    name: str
    device: str
    type: str = "1000base-t"
    mac: str | None = None
    enabled: bool = True
    description: str = ""
    mode: Literal["access", "tagged", "routed"] | None = None
    untagged_vlan: int | None = None
    tagged_vlans: list[int] = Field(default_factory=list)
    mtu: int | None = None
    addresses: list[str] = Field(default_factory=list)
    parent: str | None = None
    role: str | None = Field(default=None, description="wan|lan|mgmt|uplink|oob")
    link_up: bool | None = Field(
        default=None,
        description=(
            "Operational link state, kept apart from `enabled` (the admin state NetBox stores) "
            "so a cable pull never reads as an administrative shutdown."
        ),
    )

    @property
    def mgmt_only(self) -> bool:
        """NetBox's `mgmt_only`: an out-of-band or management-only port."""
        return (self.role or "").lower() in {"oob", "mgmt", "management"}

    @property
    def key(self) -> str:
        return f"{self.device}:{self.name}"

    def is_sensitive(self) -> bool:
        """Trunks, uplinks, WAN and management ports: drift here is high severity."""
        if self.mode == "tagged":
            return True
        lowered = f"{self.name} {self.description} {self.role or ''}".lower()
        return any(word in lowered for word in ("wan", "uplink", "trunk", "mgmt", "management"))


class Vlan(BaseModel):
    vid: int
    name: str = ""
    status: str = "active"
    devices: list[str] = Field(default_factory=list)
    members: list[str] = Field(default_factory=list)


class Prefix(BaseModel):
    prefix: str
    vlan: int | None = None
    description: str = ""


class IPAddress(BaseModel):
    address: str
    device: str | None = None
    virtual_machine: str | None = None
    interface: str | None = None
    mac: str | None = None
    hostname: str | None = None
    source: str = "interface"

    @property
    def ip(self) -> str | None:
        return bare_ip(self.address)


class Device(BaseModel):
    name: str
    kind: DeviceKind
    role: str
    manufacturer: str = "Unknown"
    model: str = "Unknown"
    serial: str | None = None
    os_version: str | None = None
    site: str = "hq"
    primary_ip: str | None = None
    tags: list[str] = Field(default_factory=list)
    interfaces: list[Interface] = Field(default_factory=list)

    def interface(self, name: str) -> Interface | None:
        wanted = normalize_ifname(name)
        return next((i for i in self.interfaces if normalize_ifname(i.name) == wanted), None)


class VMInterface(BaseModel):
    name: str
    mac: str | None = None
    portgroup: str | None = None
    vlan: int | None = None
    enabled: bool = True
    addresses: list[str] = Field(default_factory=list)


class VirtualMachine(BaseModel):
    name: str
    cluster: str
    status: str = "active"
    vcpus: float | None = None
    memory_mb: int | None = None
    disk_gb: int | None = None
    guest_os: str | None = None
    host: str | None = None
    interfaces: list[VMInterface] = Field(default_factory=list)


class Cluster(BaseModel):
    name: str
    type: str = "vmware-esxi"
    site: str = "hq"
    host: str | None = None


class MacEntry(BaseModel):
    """One MAC learned on a switch port (or seen in a firewall ARP cache)."""

    mac: str
    device: str
    port: str
    vlan: int | None = None
    kind: str = "dynamic"
    source: str = "cisco-mac-table"


class Estate(BaseModel):
    """Everything the platform knows about the estate, observed or intended."""

    site: str = "hq"
    site_name: str = "HQ"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    origin: str = "observed"
    devices: list[Device] = Field(default_factory=list)
    vlans: list[Vlan] = Field(default_factory=list)
    prefixes: list[Prefix] = Field(default_factory=list)
    ip_addresses: list[IPAddress] = Field(default_factory=list)
    clusters: list[Cluster] = Field(default_factory=list)
    virtual_machines: list[VirtualMachine] = Field(default_factory=list)
    mac_entries: list[MacEntry] = Field(default_factory=list)
    ilo_links: dict[str, str] = Field(
        default_factory=dict, description="iLO seed device name -> the ESXi host it was folded into"
    )
    sources: dict[str, str] = Field(
        default_factory=dict, description="'device/collector' -> snapshot timestamp"
    )
    warnings: list[str] = Field(default_factory=list)

    def device(self, name: str) -> Device | None:
        return next((d for d in self.devices if d.name == name), None)

    def vm(self, name: str) -> VirtualMachine | None:
        return next((v for v in self.virtual_machines if v.name == name), None)

    def vlan(self, vid: int) -> Vlan | None:
        return next((v for v in self.vlans if v.vid == vid), None)

    def cluster(self, name: str) -> Cluster | None:
        return next((c for c in self.clusters if c.name == name), None)

    def assigned_ips(self) -> list[IPAddress]:
        return [ip for ip in self.ip_addresses if ip.source in ASSIGNED_IP_SOURCES]

    def counts(self) -> dict[str, int]:
        return {
            "devices": len(self.devices),
            "interfaces": sum(len(d.interfaces) for d in self.devices),
            "vlans": len(self.vlans),
            "prefixes": len(self.prefixes),
            "ip_addresses": len(self.ip_addresses),
            "clusters": len(self.clusters),
            "virtual_machines": len(self.virtual_machines),
            "vm_interfaces": sum(len(v.interfaces) for v in self.virtual_machines),
            "mac_entries": len(self.mac_entries),
        }

    def fingerprint(self) -> str:
        """Stable digest of the estate's *intended* content.

        Transient observations are excluded on purpose: the MAC table, ARP and DHCP
        bindings and operational link state churn on every poll, so hashing them would
        make `Baseline.matches()` false minutes after acceptance and say nothing about
        whether the estate actually changed.
        """
        payload = self.model_dump(
            mode="json",
            exclude={
                "generated_at": True,
                "sources": True,
                "warnings": True,
                "origin": True,
                "mac_entries": True,
                "devices": {"__all__": {"interfaces": {"__all__": {"link_up"}}}},
            },
        )
        payload["ip_addresses"] = [
            ip for ip in payload.get("ip_addresses", []) if ip.get("source") in ASSIGNED_IP_SOURCES
        ]
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()

    def summary(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "origin": self.origin,
            "generated_at": self.generated_at.isoformat(),
            "counts": self.counts(),
            "sources": self.sources,
            "warnings": self.warnings,
        }
