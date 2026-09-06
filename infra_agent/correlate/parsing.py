"""Normalisers shared by the graph builder.

Collector snapshots come from three different parsers (ntc-templates, the
FortiOS REST API and pyvmomi), so the same object arrives spelled several ways:
`Gi1/0/1` vs `GigabitEthernet1/0/1`, `00:50:56:aa:bb:cc` vs `0050.56aa.bbcc`,
`esx-01.lab.local` vs `esx-01`. Everything is canonicalised here so the graph
has one node per real object.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from typing import Any

# Canonical Cisco interface names, longest-plausible-match first.
_CANONICAL_IFNAMES = (
    "FastEthernet",
    "GigabitEthernet",
    "TenGigabitEthernet",
    "TwentyFiveGigE",
    "FortyGigabitEthernet",
    "HundredGigE",
    "Ethernet",
    "Port-channel",
    "Vlan",
    "Loopback",
    "Tunnel",
    "Management",
    "AppGigabitEthernet",
)

_IFNAME_SPLIT = re.compile(r"^([A-Za-z][A-Za-z\-]*)\s*(.*)$")
_HEX = re.compile(r"[^0-9a-f]")


def normalize_ifname(name: str | None) -> str:
    """`Gi1/0/1` -> `GigabitEthernet1/0/1`; non-Cisco names pass through."""
    if not name:
        return ""
    raw = str(name).strip()
    match = _IFNAME_SPLIT.match(raw)
    if not match:
        return raw
    prefix, rest = match.group(1), match.group(2).strip()
    if not rest:
        return raw
    lowered = prefix.lower()
    for canonical in _CANONICAL_IFNAMES:
        if canonical.lower().startswith(lowered) and lowered:
            return f"{canonical}{rest}"
    return raw


def normalize_mac(mac: str | None) -> str:
    """Any MAC spelling -> `00:50:56:aa:bb:cc` ("" when it is not a MAC)."""
    if not mac:
        return ""
    hexonly = _HEX.sub("", str(mac).lower())
    if len(hexonly) != 12:
        return ""
    return ":".join(hexonly[i : i + 2] for i in range(0, 12, 2))


def short_hostname(name: str | None) -> str:
    """`esx-01.lab.local(FDO123)` -> `esx-01`."""
    if not name:
        return ""
    text = str(name).strip()
    text = text.split("(")[0].strip()
    return text.split(".")[0].strip()


def expand_vlan_list(value: Any) -> set[int]:
    """`"1-3,10,20"` / `["1-3", "10"]` / `10` -> {1, 2, 3, 10, 20}."""
    if value is None:
        return set()
    if isinstance(value, int):
        return {value}
    parts: list[str] = []
    if isinstance(value, (list, tuple, set)):
        for item in value:
            parts.extend(str(item).split(","))
    else:
        parts.extend(str(value).split(","))
    vlans: set[int] = set()
    for part in parts:
        token = part.strip()
        if not token or token.lower() in ("none", "all", "-"):
            if token.lower() == "all":
                vlans.update(range(1, 4095))
            continue
        if "-" in token:
            lo, _, hi = token.partition("-")
            try:
                start, end = int(lo), int(hi)
            except ValueError:
                continue
            if start <= end and end - start < 4096:
                vlans.update(range(start, end + 1))
            continue
        try:
            vlans.add(int(token))
        except ValueError:
            continue
    return vlans


def compact_vlan_list(vlans: Iterable[int]) -> str:
    """{1, 2, 3, 10, 20} -> `"1-3,10,20"` (how switches print allowed lists)."""
    ordered = sorted(set(vlans))
    if not ordered:
        return ""
    spans: list[str] = []
    start = previous = ordered[0]
    for vlan in ordered[1:]:
        if vlan == previous + 1:
            previous = vlan
            continue
        spans.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = vlan
    spans.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(spans)


def parse_ip_mask(value: Any) -> tuple[str, str] | None:
    """FortiOS `"10.20.0.1 255.255.255.0"` (or a 2-list, or CIDR) -> (ip, cidr)."""
    if not value:
        return None
    if isinstance(value, (list, tuple)):
        parts = [str(v) for v in value]
    else:
        parts = str(value).replace("/", " ").split()
    parts = [p for p in parts if p]
    if not parts:
        return None
    address = parts[0]
    if address in ("0.0.0.0", ""):
        return None
    mask = parts[1] if len(parts) > 1 else "32"
    try:
        iface = ipaddress.ip_interface(f"{address}/{mask}")
    except ValueError:
        return None
    return str(iface.ip), str(iface.network)


def parse_prefix(value: Any) -> str | None:
    """`"10.20.0.0 255.255.255.0"` / `"10.20.0.0/24"` -> `"10.20.0.0/24"`."""
    parsed = parse_ip_mask(value)
    if parsed is None:
        return None
    return parsed[1]


def is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
    except (ValueError, TypeError):
        return False
    return True


def ip_in_prefix(address: str, prefix: str) -> bool:
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return False


def naa_key(value: Any) -> str:
    """Strip an ESXi `naa.600508...` / HPE `600508...` id down to its hex tail.

    ESXi reports `naa.600508b1001c...` for a Smart Array volume while iLO
    reports the same volume as `VolumeUniqueIdentifier: 600508B1001C...`.
    """
    if not value:
        return ""
    text = str(value).strip().lower()
    for prefix in ("naa.", "eui.", "t10.", "wwn."):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    hexonly = _HEX.sub("", text)
    return hexonly[-32:] if len(hexonly) > 32 else hexonly


def datastore_from_vmdk(path: Any) -> str:
    """`"[datastore1] mgmt-01/mgmt-01.vmdk"` -> `datastore1`."""
    if not path:
        return ""
    match = re.match(r"^\s*\[([^\]]+)\]", str(path))
    return match.group(1).strip() if match else ""


def first(row: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """First present, non-empty value among `keys` (ntc-templates key drift)."""
    for key in keys:
        if key in row:
            value = row[key]
            if value not in (None, "", [], {}):
                return value
    return default


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def rows(data: Any) -> list[dict[str, Any]]:
    """Snapshot sections are either parsed rows or (on a parser miss) raw text."""
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def is_unparsed(data: Any) -> bool:
    """True when a section arrived as raw text instead of parsed rows.

    `ntc_templates` ships no template for some commands and none at all for the
    `cisco_xe` platform, so the collector stores the raw output. Callers use
    this to raise a `collector_parse_gap` finding instead of silently building
    an empty graph for the device.
    """
    return isinstance(data, str) and bool(data.strip())


# --- `show interfaces trunk` ----------------------------------------------
#
# ntc-templates has no cisco_ios template for `show interfaces trunk` (verified
# against 9.2.0), so the collector stores either `[]` or the raw text. The
# output is four fixed blocks, stable across IOS 12.2/15.x and IOS-XE 16/17:
#
#     Port        Mode             Encapsulation  Status        Native vlan
#     Port        Vlans allowed on trunk
#     Port        Vlans allowed and active in management domain
#     Port        Vlans in spanning tree forwarding state and not pruned
#
# Long VLAN lists wrap onto an indented continuation line with no port column.

_TRUNK_BLOCKS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("mode", ("mode", "encapsulation", "status")),
    ("vlans_allowed", ("vlans allowed on trunk",)),
    ("vlans_allowed_active", ("vlans allowed and active",)),
    ("vlans_forwarding", ("forwarding state",)),
)
_VLAN_LIST = re.compile(r"^[0-9,\-]+$")


def parse_trunk_text(text: Any) -> list[dict[str, Any]]:
    """Raw `show interfaces trunk` output -> one row per trunk port."""
    if not isinstance(text, str):
        return []
    parsed: dict[str, dict[str, Any]] = {}
    block: str | None = None
    last_port: str | None = None
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped:
            last_port = None
            continue
        lowered = stripped.lower()
        if lowered.startswith("port"):
            block = next(
                (name for name, hints in _TRUNK_BLOCKS if all(h in lowered for h in hints)), None
            )
            last_port = None
            continue
        if block is None:
            continue
        if last_port and raw[:1].isspace() and _VLAN_LIST.match(stripped):
            previous = parsed[last_port].get(block, "")
            parsed[last_port][block] = f"{previous},{stripped}".strip(",")
            continue
        parts = stripped.split()
        port = normalize_ifname(parts[0])
        if not port:
            continue
        row = parsed.setdefault(port, {"port": port})
        if block == "mode":
            for index, key in enumerate(("mode", "encapsulation", "status", "native_vlan"), 1):
                if len(parts) > index:
                    row[key] = parts[index]
        elif len(parts) > 1:
            row[block] = parts[1]
        last_port = port
    return list(parsed.values())
