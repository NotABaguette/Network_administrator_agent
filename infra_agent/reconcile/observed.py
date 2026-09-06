"""Build the canonical `Estate` from the latest collector snapshots.

Snapshots hold parsed rows only (see `collectors/base.py`), so nothing here
ever touches raw configuration text. Parsing is deliberately tolerant: field
names differ between ntc-templates versions, FortiOS releases and the ESXi and
iLO collectors, so every lookup accepts a handful of spellings and a missing
key is a warning, never an exception.
"""

from __future__ import annotations

import re
from typing import Any

from infra_agent.models.common import DeviceKind, SeedDevice, SeedInventory, Snapshot
from infra_agent.reconcile.model import (
    Cluster,
    Device,
    Estate,
    Interface,
    IPAddress,
    MacEntry,
    Prefix,
    VirtualMachine,
    Vlan,
    VMInterface,
    bare_ip,
    network_of,
    normalize_ifname,
    normalize_mac,
    to_cidr,
)
from infra_agent.store.snapshots import FileSnapshotStore

COLLECTOR_NAMES: dict[DeviceKind, str] = {
    DeviceKind.fortigate: "fortigate",
    DeviceKind.cisco_ios: "cisco",
    DeviceKind.cisco_iosxe: "cisco",
    DeviceKind.esxi: "esxi",
    DeviceKind.ilo: "ilo",
}

DEVICE_ROLES: dict[DeviceKind, str] = {
    DeviceKind.fortigate: "firewall",
    DeviceKind.cisco_ios: "access-switch",
    DeviceKind.cisco_iosxe: "access-switch",
    DeviceKind.esxi: "hypervisor",
    DeviceKind.ilo: "management",
}

MANUFACTURERS: dict[DeviceKind, str] = {
    DeviceKind.fortigate: "Fortinet",
    DeviceKind.cisco_ios: "Cisco",
    DeviceKind.cisco_iosxe: "Cisco",
    DeviceKind.esxi: "HPE",
    DeviceKind.ilo: "HPE",
}

_UP_WORDS = {"up", "connected", "enable", "enabled", "true", "yes", "1", "active", "ok"}
_MAX_TAGGED_VLANS = 64


# --------------------------------------------------------------------------- helpers
def _rows(data: dict[str, Any], *keys: str) -> list[dict[str, Any]]:
    """Rows under the first key that holds a list of dicts (or a dict of dicts)."""
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            return [r for r in value if isinstance(r, dict)]
        if isinstance(value, dict):
            rows = [{"name": k, **v} for k, v in value.items() if isinstance(v, dict)]
            if rows:
                return rows
    return []


def _row(data: dict[str, Any], *keys: str) -> dict[str, Any]:
    """A single dict under the first matching key (the first row of a list is fine)."""
    for key in keys:
        value = data.get(key)
        if isinstance(value, dict):
            return value
        if isinstance(value, list) and value and isinstance(value[0], dict):
            return value[0]
    return {}


def _field(row: dict[str, Any], *keys: str, default: Any = None) -> Any:
    lowered = {str(k).lower(): v for k, v in row.items()}
    for key in keys:
        for candidate in (row.get(key), lowered.get(key.lower())):
            if candidate not in (None, "", [], {}):
                return candidate
    return default


def _one(value: Any) -> Any:
    """ntc-templates returns single-valued fields as lists on some templates."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _text(value: Any, default: str = "") -> str:
    value = _one(value)
    return str(value).strip() if value not in (None, "") else default


def _int(value: Any) -> int | None:
    value = _one(value)
    if value in (None, ""):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> float | None:
    value = _one(value)
    if value in (None, ""):
        return None
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _is_up(value: Any, default: bool = True) -> bool:
    value = _one(value)
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in _UP_WORDS


def parse_vlan_list(spec: Any, known: set[int] | None = None) -> list[int]:
    """`"10,20,30-32"` -> `[10, 20, 30, 31, 32]`, intersected with known VLANs."""
    if spec in (None, "", []):
        return []
    parts: list[str] = []
    for chunk in spec if isinstance(spec, list) else [spec]:
        parts.extend(str(chunk).replace(" ", "").split(","))
    vlans: set[int] = set()
    for part in parts:
        if not part or part.lower() in {"none", "all"}:
            continue
        if "-" in part:
            low, _, high = part.partition("-")
            start, end = _int(low), _int(high)
            if start is None or end is None or end < start:
                continue
            span = range(start, end + 1)
            vlans.update(span if known is None else (v for v in span if v in known))
            continue
        value = _int(part)
        if value is not None and (known is None or value in known):
            vlans.add(value)
    if known is None and len(vlans) > _MAX_TAGGED_VLANS:
        return []
    return sorted(vlans)


class _Builder:
    """Accumulates the estate while collectors are parsed one by one."""

    def __init__(self, site: str, site_name: str):
        self.estate = Estate(site=site, site_name=site_name)
        self._vlans: dict[int, Vlan] = {}
        self._vlan_name_rank: dict[int, int] = {}
        self._prefixes: dict[str, Prefix] = {}
        self._ips: dict[tuple[Any, ...], IPAddress] = {}

    def add_vlan(
        self,
        vid: int | None,
        name: str = "",
        device: str | None = None,
        members: list[str] | None = None,
        status: str = "active",
        name_rank: int = 0,
    ) -> None:
        """`name_rank` decides who names a VLAN: the switch VLAN database beats a
        FortiOS interface alias, which beats an ESXi portgroup name."""
        if vid is None or vid <= 0 or vid > 4094:
            return
        vlan = self._vlans.get(vid)
        if vlan is None:
            vlan = Vlan(vid=vid, name=f"vlan{vid}", status=status)
            self._vlans[vid] = vlan
        if name and name_rank >= self._vlan_name_rank.get(vid, -1):
            vlan.name = name
            vlan.status = status
            self._vlan_name_rank[vid] = name_rank
        if device and device not in vlan.devices:
            vlan.devices.append(device)
        for member in members or []:
            if member not in vlan.members:
                vlan.members.append(member)

    def add_prefix(self, cidr: str | None, vlan: int | None = None, description: str = "") -> None:
        network = network_of(cidr) if cidr else None
        if not network or network.endswith("/32") or network.startswith("127."):
            return
        existing = self._prefixes.get(network)
        if existing is None:
            self._prefixes[network] = Prefix(prefix=network, vlan=vlan, description=description)
            return
        existing.vlan = existing.vlan or vlan
        existing.description = existing.description or description

    def add_ip(self, ip: IPAddress) -> None:
        if not bare_ip(ip.address):
            return
        key = (ip.address, ip.device, ip.virtual_machine, ip.interface, ip.source)
        self._ips.setdefault(key, ip)

    @staticmethod
    def add_address(interface: Interface, cidr: str | None) -> None:
        """Add an address to an interface, preferring the masked form of the same host IP."""
        if not cidr:
            return
        host = bare_ip(cidr)
        for index, existing in enumerate(interface.addresses):
            if bare_ip(existing) != host:
                continue
            if existing.endswith("/32") and not cidr.endswith("/32"):
                interface.addresses[index] = cidr
            return
        interface.addresses.append(cidr)

    def add_device(self, device: Device) -> None:
        self.estate.devices.append(device)

    def warn(self, message: str) -> None:
        if message not in self.estate.warnings:
            self.estate.warnings.append(message)

    def finish(self) -> Estate:
        self.estate.vlans = [self._vlans[v] for v in sorted(self._vlans)]
        self.estate.prefixes = sorted(self._prefixes.values(), key=lambda p: p.prefix)
        self.estate.ip_addresses = sorted(
            self._ips.values(), key=lambda i: (i.address, i.source, i.device or "")
        )
        self.estate.devices.sort(key=lambda d: d.name)
        self.estate.virtual_machines.sort(key=lambda v: v.name)
        self.estate.clusters.sort(key=lambda c: c.name)
        self.estate.mac_entries.sort(key=lambda m: (m.mac, m.device, m.port))
        return self.estate


# --------------------------------------------------------------------------- cisco
def _cisco_iface_type(name: str, raw: Any) -> str:
    lowered = f"{raw or ''}".lower()
    if name.lower().startswith("vlan") or name.lower().startswith("loopback"):
        return "virtual"
    if name.lower().startswith("port-channel"):
        return "lag"
    if "10gbase" in lowered or "sfp+" in lowered or "sfp-10g" in lowered:
        return "10gbase-x-sfpp"
    if "1000base" in lowered and ("sx" in lowered or "lx" in lowered or "bx" in lowered):
        return "1000base-x-sfp"
    if "10/100baset" in lowered.replace(" ", ""):
        return "100base-tx"
    return "1000base-t"


def _cisco_role(seed: SeedDevice) -> str:
    tags = {t.lower() for t in seed.tags}
    if {"core", "distribution", "core-switch"} & tags:
        return "core-switch"
    return "access-switch"


def parse_cisco(seed: SeedDevice, data: dict[str, Any], builder: _Builder) -> Device:
    version = _row(data, "version")
    inventory = _rows(data, "inventory")
    chassis = next((r for r in inventory if "chassis" in _text(_field(r, "name")).lower()), None)
    model = _text(_field(version, "hardware"), "") or _text(_field(chassis or {}, "pid"), "")
    serial = _text(_field(version, "serial"), "") or _text(_field(chassis or {}, "sn"), "")

    device = Device(
        name=seed.name,
        kind=seed.kind,
        role=_cisco_role(seed),
        manufacturer=MANUFACTURERS[seed.kind],
        model=model or "Catalyst",
        serial=serial or None,
        os_version=_text(_field(version, "version"), "") or None,
        site=builder.estate.site,
        primary_ip=seed.mgmt_ip,
        tags=list(seed.tags),
    )

    known_vlans: set[int] = set()
    for row in _rows(data, "vlans"):
        vid = _int(_field(row, "vlan_id", "vlan"))
        if vid is None:
            continue
        known_vlans.add(vid)
        members = [
            f"{seed.name}:{normalize_ifname(port)}"
            for port in (_field(row, "interfaces", default=[]) or [])
            if str(port).strip()
        ]
        builder.add_vlan(
            vid,
            name=_text(_field(row, "vlan_name", "name")),
            device=seed.name,
            members=members,
            status="active" if _is_up(_field(row, "status"), True) else "reserved",
            name_rank=3,
        )

    interfaces: dict[str, Interface] = {}

    def slot(name: Any) -> Interface | None:
        canonical = normalize_ifname(name)
        if not canonical:
            return None
        if canonical not in interfaces:
            interfaces[canonical] = Interface(name=canonical, device=seed.name)
        return interfaces[canonical]

    for row in _rows(data, "interfaces"):
        iface = slot(_field(row, "interface", "port", "name"))
        if iface is None:
            continue
        iface.mac = normalize_mac(_field(row, "address", "mac_address", "bia")) or iface.mac
        iface.description = _text(_field(row, "description"), iface.description)
        # NetBox's `enabled` is the admin state: "down" is a dark link, only
        # "administratively down" means the port is shut.
        iface.enabled = "admin" not in _text(_field(row, "link_status", "status")).lower()
        iface.mtu = _int(_field(row, "mtu")) or iface.mtu
        builder.add_address(iface, to_cidr(_field(row, "ip_address")))

    for row in _rows(data, "ip_int_brief"):
        iface = slot(_field(row, "interface"))
        if iface is None:
            continue
        builder.add_address(iface, to_cidr(_field(row, "ip_address")))

    for row in _rows(data, "interfaces_status"):
        iface = slot(_field(row, "port", "interface"))
        if iface is None:
            continue
        iface.type = _cisco_iface_type(iface.name, _field(row, "type"))
        iface.description = _text(_field(row, "name", "description"), iface.description)
        status = _text(_field(row, "status")).lower()
        if status:
            iface.enabled = status not in {"disabled", "err-disabled", "inactive"}
        vlan = _text(_field(row, "vlan")).lower()
        if vlan.isdigit():
            iface.mode = "access"
            iface.untagged_vlan = int(vlan)
        elif vlan == "trunk":
            iface.mode = "tagged"
        elif vlan == "routed":
            iface.mode = "routed"

    for row in _rows(data, "trunks"):
        iface = slot(_field(row, "interface", "port"))
        if iface is None:
            continue
        iface.mode = "tagged"
        iface.untagged_vlan = _int(_field(row, "native_vlan")) or iface.untagged_vlan
        allowed = parse_vlan_list(
            _field(row, "vlans_allowed", "vlans_allowed_on_trunk", "vlans"), known_vlans or None
        )
        if allowed:
            iface.tagged_vlans = allowed

    for iface in interfaces.values():
        if iface.name.lower().startswith("vlan"):
            iface.mode = "routed"
            iface.untagged_vlan = _int(iface.name[4:])
        for cidr in iface.addresses:
            builder.add_prefix(cidr, vlan=iface.untagged_vlan, description=f"{seed.name} SVI")
            builder.add_ip(
                IPAddress(
                    address=cidr,
                    device=seed.name,
                    interface=iface.name,
                    mac=iface.mac,
                    source="interface",
                )
            )
    device.interfaces = [interfaces[name] for name in sorted(interfaces)]

    for row in _rows(data, "mac_table", "mac_address_table"):
        mac = normalize_mac(_field(row, "destination_address", "mac", "mac_address"))
        if not mac:
            continue
        ports = _field(row, "destination_port", "port", "ports", default=[])
        for port in ports if isinstance(ports, list) else [ports]:
            port_name = normalize_ifname(port)
            if not port_name or port_name.lower() in {"cpu", "drop"}:
                continue
            builder.estate.mac_entries.append(
                MacEntry(
                    mac=mac,
                    device=seed.name,
                    port=port_name,
                    vlan=_int(_field(row, "vlan")),
                    kind=_text(_field(row, "type"), "dynamic").lower(),
                    source="cisco-mac-table",
                )
            )

    for row in _rows(data, "arp"):
        address = bare_ip(_field(row, "ip_address", "address", "ip"))
        if not address:
            continue
        builder.add_ip(
            IPAddress(
                address=address,
                device=seed.name,
                interface=normalize_ifname(_field(row, "interface")) or None,
                mac=normalize_mac(_field(row, "mac_address", "mac")),
                source="cisco-arp",
            )
        )
    return device


# --------------------------------------------------------------------------- fortigate
def fortigate_model(serial: str | None) -> str:
    match = re.match(r"^FGT?([0-9]{2,4}[A-Z]?)", (serial or "").upper())
    return f"FortiGate-{match.group(1)}" if match else "FortiGate"


def parse_fortigate(seed: SeedDevice, data: dict[str, Any], builder: _Builder) -> Device:
    system = _row(data, "system")
    serial = _text(_field(system, "serial"), "") or None
    device = Device(
        name=seed.name,
        kind=seed.kind,
        role=DEVICE_ROLES[seed.kind],
        manufacturer=MANUFACTURERS[seed.kind],
        model=_text(_field(system, "model"), "") or fortigate_model(serial),
        serial=serial,
        os_version=_text(_field(system, "version"), "") or None,
        site=builder.estate.site,
        primary_ip=seed.mgmt_ip,
        tags=list(seed.tags),
    )

    macs: dict[str, str] = {}
    for row in _rows(data, "interface_stats"):
        name = _text(_field(row, "name", "interface"))
        mac = normalize_mac(_field(row, "mac", "mac_address"))
        if name and mac:
            macs[name] = mac

    for row in _rows(data, "interfaces"):
        name = _text(_field(row, "name"))
        if not name:
            continue
        vlan_id = _int(_field(row, "vlanid", "vlan_id"))
        parent = _text(_field(row, "interface"), "") or None
        cidr = to_cidr(_field(row, "ip"))
        iface = Interface(
            name=name,
            device=seed.name,
            type="virtual" if vlan_id else "1000base-t",
            mac=macs.get(name),
            enabled=_is_up(_field(row, "status"), True),
            description=_text(_field(row, "alias", "description")),
            mode="access" if vlan_id else None,
            untagged_vlan=vlan_id,
            parent=parent,
            role=_text(_field(row, "role"), "") or None,
            addresses=[cidr] if cidr else [],
        )
        if iface.role in {"undefined", ""}:
            iface.role = None
        device.interfaces.append(iface)
        if vlan_id:
            builder.add_vlan(
                vlan_id,
                name=iface.description or name,
                device=seed.name,
                members=[iface.key],
                name_rank=2,
            )
        if cidr:
            builder.add_prefix(cidr, vlan=vlan_id, description=iface.description or name)
            builder.add_ip(
                IPAddress(
                    address=cidr,
                    device=seed.name,
                    interface=name,
                    mac=iface.mac,
                    source="interface",
                )
            )
    device.interfaces.sort(key=lambda i: i.name)

    for row in _rows(data, "arp"):
        address = bare_ip(_field(row, "ip", "ip_address"))
        mac = normalize_mac(_field(row, "mac", "mac_address"))
        interface = _text(_field(row, "interface"), "") or None
        if not address:
            continue
        builder.add_ip(
            IPAddress(
                address=address,
                device=seed.name,
                interface=interface,
                mac=mac,
                source="fortigate-arp",
            )
        )
        if mac and interface:
            builder.estate.mac_entries.append(
                MacEntry(
                    mac=mac,
                    device=seed.name,
                    port=interface,
                    kind="arp",
                    source="fortigate-arp",
                )
            )

    for row in _rows(data, "dhcp_leases", "dhcp"):
        address = bare_ip(_field(row, "ip", "ip_address"))
        mac = normalize_mac(_field(row, "mac", "mac_address"))
        interface = _text(_field(row, "interface"), "") or None
        if not address:
            continue
        builder.add_ip(
            IPAddress(
                address=address,
                device=seed.name,
                interface=interface,
                mac=mac,
                hostname=_text(_field(row, "hostname", "name"), "") or None,
                source="fortigate-dhcp",
            )
        )
        if mac and interface:
            builder.estate.mac_entries.append(
                MacEntry(
                    mac=mac,
                    device=seed.name,
                    port=interface,
                    kind="dhcp",
                    source="fortigate-dhcp",
                )
            )
    return device


# --------------------------------------------------------------------------- esxi
def _portgroup_vlans(data: dict[str, Any]) -> dict[str, int]:
    mapping: dict[str, int] = {}
    for row in _rows(data, "portgroups", "port_groups", "networks"):
        name = _text(_field(row, "name", "portgroup"))
        vid = _int(_field(row, "vlan", "vlan_id", "vlanid"))
        if name and vid is not None:
            mapping[name] = vid
    return mapping


def _esxi_vm(row: dict[str, Any], cluster: str, portgroups: dict[str, int]) -> VirtualMachine:
    power = _text(_field(row, "power_state", "power", "state"), "").lower()
    memory_mb = _int(_field(row, "memory_mb", "memorymb", "memory_size_mb", "memory"))
    if memory_mb is None:
        memory_gb = _float(_field(row, "memory_gb"))
        memory_mb = int(memory_gb * 1024) if memory_gb else None
    disk_gb = _float(_field(row, "disk_gb", "provisioned_gb", "storage_gb"))
    if disk_gb is None:
        disks = _rows(row, "disks")
        sizes = [_float(_field(d, "size_gb", "capacity_gb")) or 0.0 for d in disks]
        disk_gb = sum(sizes) or None

    vm = VirtualMachine(
        name=_text(_field(row, "name", "vm", "hostname")),
        cluster=cluster,
        status="active" if power in {"poweredon", "powered_on", "on", "running"} else "offline",
        vcpus=_float(_field(row, "vcpus", "num_cpu", "numcpu", "cpus")),
        memory_mb=memory_mb,
        disk_gb=round(disk_gb, 1) if disk_gb else None,
        guest_os=_text(_field(row, "guest_os", "guest_full_name", "guestfullname", "guest"), "")
        or None,
        host=_text(_field(row, "host"), "") or None,
    )
    for index, nic in enumerate(_rows(row, "nics", "vnics", "interfaces", "networks")):
        portgroup = _text(_field(nic, "portgroup", "network", "port_group"), "") or None
        addresses = _field(nic, "ips", "addresses", default=None)
        if addresses is None:
            single = _field(nic, "ip", "ip_address")
            addresses = [single] if single else []
        vm.interfaces.append(
            VMInterface(
                name=_text(_field(nic, "name", "label", "device"), f"nic{index}"),
                mac=normalize_mac(_field(nic, "mac", "mac_address")),
                portgroup=portgroup,
                vlan=portgroups.get(portgroup) if portgroup else None,
                enabled=_is_up(_field(nic, "connected", "status"), True),
                addresses=[a for a in (to_cidr(x) for x in addresses) if a],
            )
        )
    if not vm.interfaces:
        guest_ip = to_cidr(_field(row, "ip", "ip_address", "guest_ip"))
        if guest_ip:
            vm.interfaces.append(VMInterface(name="nic0", addresses=[guest_ip]))
    return vm


def parse_esxi(seed: SeedDevice, data: dict[str, Any], builder: _Builder) -> Device:
    host = _row(data, "host", "hosts", "system")
    device = Device(
        name=seed.name,
        kind=seed.kind,
        role=DEVICE_ROLES[seed.kind],
        manufacturer=_text(_field(host, "vendor", "manufacturer"), "") or MANUFACTURERS[seed.kind],
        model=_text(_field(host, "model"), "") or "ProLiant",
        serial=_text(_field(host, "serial", "serial_number", "service_tag"), "") or None,
        os_version=" ".join(
            part
            for part in (
                _text(_field(host, "version", "product_version")),
                _text(_field(host, "build")),
            )
            if part
        )
        or None,
        site=builder.estate.site,
        primary_ip=seed.mgmt_ip,
        tags=list(seed.tags),
    )

    portgroups = _portgroup_vlans(data)
    for name, vid in sorted(portgroups.items()):
        builder.add_vlan(vid, name=name, device=seed.name, name_rank=1)

    for row in _rows(data, "pnics", "vmnics", "physical_nics", "nics"):
        name = _text(_field(row, "device", "name"))
        if not name:
            continue
        speed = _int(_field(row, "speed", "link_speed", "speed_mb"))
        device.interfaces.append(
            Interface(
                name=name,
                device=seed.name,
                type="10gbase-x-sfpp" if (speed or 0) >= 10000 else "1000base-t",
                mac=normalize_mac(_field(row, "mac", "mac_address")),
                enabled=_is_up(_field(row, "link", "status", "link_up"), True),
                description=_text(_field(row, "driver", "description")),
                mode="tagged" if _is_up(_field(row, "uplink"), False) else None,
            )
        )

    for row in _rows(data, "vmknics", "vmkernel_nics", "vmkernel", "vmk"):
        name = _text(_field(row, "device", "name"))
        if not name:
            continue
        cidr = to_cidr(_field(row, "ip", "ip_address"), _field(row, "netmask", "mask"))
        portgroup = _text(_field(row, "portgroup", "port_group"), "") or None
        iface = Interface(
            name=name,
            device=seed.name,
            type="virtual",
            mac=normalize_mac(_field(row, "mac", "mac_address")),
            description=portgroup or "",
            untagged_vlan=portgroups.get(portgroup) if portgroup else None,
            addresses=[cidr] if cidr else [],
            role="mgmt" if _is_up(_field(row, "management"), False) else None,
        )
        device.interfaces.append(iface)
        if cidr:
            builder.add_prefix(cidr, vlan=iface.untagged_vlan, description=portgroup or name)
            builder.add_ip(
                IPAddress(
                    address=cidr,
                    device=seed.name,
                    interface=name,
                    mac=iface.mac,
                    source="vmkernel",
                )
            )
    device.interfaces.sort(key=lambda i: i.name)

    cluster_name = seed.name
    builder.estate.clusters.append(
        Cluster(name=cluster_name, site=builder.estate.site, host=seed.name)
    )
    for row in _rows(data, "vms", "virtual_machines"):
        vm = _esxi_vm(row, cluster_name, portgroups)
        if not vm.name:
            continue
        vm.host = vm.host or seed.name
        builder.estate.virtual_machines.append(vm)
        for nic in vm.interfaces:
            for cidr in nic.addresses:
                builder.add_ip(
                    IPAddress(
                        address=cidr,
                        virtual_machine=vm.name,
                        interface=nic.name,
                        mac=nic.mac,
                        hostname=vm.name,
                        source="vm",
                    )
                )
    return device


# --------------------------------------------------------------------------- ilo
def ilo_host_name(seed: SeedDevice) -> str | None:
    """Which ESXi host this iLO belongs to: a `host:<name>` tag, else the name stem."""
    for tag in seed.tags:
        if tag.lower().startswith("host:"):
            return tag.split(":", 1)[1].strip() or None
    name = seed.name
    for suffix in ("-ilo", "_ilo", ".ilo"):
        if name.lower().endswith(suffix):
            return name[: -len(suffix)]
    if name.lower().startswith("ilo-"):
        return name[4:]
    return None


def apply_ilo(seed: SeedDevice, data: dict[str, Any], builder: _Builder) -> None:
    """Fold iLO serial/model into its ESXi host, and record the OOB address."""
    identity = _row(data, "system", "identity", "chassis") or data
    model = _text(_field(identity, "model", "sku"), "") or None
    serial = _text(_field(identity, "serial", "serial_number", "serialnumber"), "") or None
    host_name = ilo_host_name(seed)
    host = builder.estate.device(host_name) if host_name else None

    if host is None:
        builder.warn(
            f"{seed.name}: no ESXi host matches this iLO; tag it `host:<device>` to link them"
        )
        builder.add_device(
            Device(
                name=seed.name,
                kind=seed.kind,
                role=DEVICE_ROLES[seed.kind],
                manufacturer=MANUFACTURERS[seed.kind],
                model=model or "iLO",
                serial=serial,
                os_version=_text(_field(identity, "ilo_firmware", "firmware"), "") or None,
                site=builder.estate.site,
                primary_ip=seed.mgmt_ip,
                tags=list(seed.tags),
            )
        )
        return

    if model and host.model in ("", "Unknown", "ProLiant"):
        host.model = model
    if serial:
        host.serial = serial
    if host.manufacturer in ("", "Unknown"):
        host.manufacturer = MANUFACTURERS[seed.kind]

    address = to_cidr(seed.mgmt_ip)
    if host.interface("iLO") is None:
        host.interfaces.append(
            Interface(
                name="iLO",
                device=host.name,
                type="1000base-t",
                description=f"out-of-band management ({seed.name})",
                role="oob",
                addresses=[address] if address else [],
            )
        )
        host.interfaces.sort(key=lambda i: i.name)
    if address:
        builder.add_ip(
            IPAddress(
                address=address,
                device=host.name,
                interface="iLO",
                hostname=seed.name,
                source="interface",
            )
        )


# --------------------------------------------------------------------------- entry point
PARSERS = {
    DeviceKind.cisco_ios: parse_cisco,
    DeviceKind.cisco_iosxe: parse_cisco,
    DeviceKind.fortigate: parse_fortigate,
    DeviceKind.esxi: parse_esxi,
}


def latest_snapshot(store: FileSnapshotStore, seed: SeedDevice) -> Snapshot | None:
    """The newest snapshot for a device, preferring its collector's own name."""
    preferred = COLLECTOR_NAMES.get(seed.kind)
    if preferred:
        found = store.latest(seed.name, preferred)
        if found is not None:
            return found
    device_dir = store.root / seed.name
    if not device_dir.exists():
        return None
    candidates = [
        snapshot
        for sub in sorted(p.name for p in device_dir.iterdir() if p.is_dir())
        if (snapshot := store.latest(seed.name, sub)) is not None
    ]
    return max(candidates, key=lambda s: s.taken_at, default=None)


def build_estate(
    store: FileSnapshotStore,
    inventory: SeedInventory,
    site: str = "hq",
    site_name: str = "HQ",
) -> Estate:
    """The observed estate: latest snapshot per seed device, parsed and merged."""
    builder = _Builder(site=site, site_name=site_name)
    ilo_seeds: list[tuple[SeedDevice, dict[str, Any]]] = []

    for seed in sorted(inventory.devices, key=lambda d: d.name):
        snapshot = latest_snapshot(store, seed)
        if snapshot is None:
            builder.warn(f"{seed.name}: no snapshot yet, run `infra collect`")
            continue
        builder.estate.sources[f"{seed.name}/{snapshot.collector}"] = snapshot.taken_at.isoformat()
        if seed.kind is DeviceKind.ilo:
            ilo_seeds.append((seed, snapshot.data))
            continue
        parser = PARSERS.get(seed.kind)
        if parser is None:
            builder.warn(f"{seed.name}: no parser for {seed.kind.value}")
            continue
        builder.add_device(parser(seed, snapshot.data, builder))

    for seed, data in ilo_seeds:
        apply_ilo(seed, data, builder)
    return builder.finish()
