"""Drift: observed estate vs intended estate.

Intended state comes from NetBox when it is configured, and from the accepted
baseline otherwise -- both are read back into the same `Estate` model, so one
comparison function serves both. The result is a `DriftReport`: added, removed
and changed objects grouped by device and object type, each with a severity and
a one-line human summary.

A `DriftReport` is built entirely from parsed fields. It never contains raw
configuration text, which is what lets the inventory tool return it to the
language model through the redaction gateway.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from infra_agent.models.common import DeviceKind
from infra_agent.reconcile.model import (
    Cluster,
    Device,
    Estate,
    Interface,
    IPAddress,
    Prefix,
    VirtualMachine,
    Vlan,
    VMInterface,
    normalize_ifname,
    normalize_mac,
)
from infra_agent.reconcile.netbox import NetBoxLike


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"


SEVERITY_ORDER = {Severity.info: 0, Severity.low: 1, Severity.medium: 2, Severity.high: 3}

ROLE_KINDS = {
    "firewall": DeviceKind.fortigate,
    "core-switch": DeviceKind.cisco_ios,
    "access-switch": DeviceKind.cisco_ios,
    "hypervisor": DeviceKind.esxi,
    "management": DeviceKind.ilo,
}

# Interface fields worth comparing, and how badly a mismatch reads.
_INTERFACE_FIELDS: dict[str, Severity] = {
    "untagged_vlan": Severity.medium,
    "tagged_vlans": Severity.medium,
    "mode": Severity.medium,
    "enabled": Severity.medium,
    "mac": Severity.medium,
    "description": Severity.info,
    "type": Severity.info,
}
_VM_FIELDS: dict[str, Severity] = {
    "cluster": Severity.medium,
    "status": Severity.low,
    "vcpus": Severity.low,
    "memory_mb": Severity.low,
    "disk_gb": Severity.low,
}
_VM_INTERFACE_FIELDS: dict[str, Severity] = {
    "mac": Severity.medium,
    "vlan": Severity.medium,
    "enabled": Severity.low,
}


def project_mode(mode: str | None) -> str | None:
    """NetBox models access and tagged only; a routed port simply has no 802.1Q mode,
    so comparing `routed` against NetBox's empty mode would be a permanent false
    positive."""
    return mode if mode in ("access", "tagged") else None


_PROJECTIONS = {"mode": project_mode}


class DriftItem(BaseModel):
    device: str
    object_type: str
    object: str
    change: Literal["added", "removed", "changed"]
    severity: Severity
    summary: str
    field: str | None = None
    observed: Any = None
    intended: Any = None


class DriftReport(BaseModel):
    """Structured drift. No raw config text ever lands in here."""

    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    site: str = "hq"
    source: str = "netbox"
    devices: list[str] = Field(default_factory=list)
    items: list[DriftItem] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    observed_at: dict[str, str] = Field(default_factory=dict)

    @property
    def clean(self) -> bool:
        return not self.items

    @property
    def worst(self) -> Severity | None:
        return max((i.severity for i in self.items), key=lambda s: SEVERITY_ORDER[s], default=None)

    def counts(self) -> dict[str, int]:
        table: dict[str, int] = defaultdict(int)
        for item in self.items:
            table[item.change] += 1
            table[item.severity.value] += 1
        return dict(table)

    def by_device(self) -> dict[str, list[DriftItem]]:
        table: dict[str, list[DriftItem]] = defaultdict(list)
        for item in self.items:
            table[item.device].append(item)
        return dict(sorted(table.items()))

    def by_type(self) -> dict[str, list[DriftItem]]:
        table: dict[str, list[DriftItem]] = defaultdict(list)
        for item in self.items:
            table[item.object_type].append(item)
        return dict(sorted(table.items()))

    def for_device(self, device: str) -> list[DriftItem]:
        return [i for i in self.items if i.device == device]

    def headline(self) -> str:
        if self.clean:
            return f"no drift against {self.source}"
        worst = self.worst
        return (
            f"{len(self.items)} drift item(s) against {self.source}, "
            f"worst severity {worst.value if worst else 'info'}"
        )

    def llm_view(self) -> dict[str, Any]:
        """Structured drift only: object identifiers, fields and summaries."""
        return {
            "generated_at": self.generated_at.isoformat(),
            "site": self.site,
            "source": self.source,
            "devices": self.devices,
            "headline": self.headline(),
            "counts": self.counts(),
            "observed_at": self.observed_at,
            "warnings": self.warnings,
            "by_device": {
                device: [i.model_dump(mode="json") for i in items]
                for device, items in self.by_device().items()
            },
        }


# --------------------------------------------------------------------------- helpers
def _sorted_items(items: list[DriftItem]) -> list[DriftItem]:
    return sorted(
        items,
        key=lambda i: (
            -SEVERITY_ORDER[i.severity],
            i.device,
            i.object_type,
            i.object,
            i.field or "",
        ),
    )


def _bump(severity: Severity, sensitive: bool) -> Severity:
    if not sensitive:
        return severity
    return (
        Severity.high if SEVERITY_ORDER[severity] >= SEVERITY_ORDER[Severity.medium] else severity
    )


def _show(value: Any) -> str:
    if value is None or value == "":
        return "unset"
    if isinstance(value, list):
        return ",".join(str(v) for v in value) or "none"
    return str(value)


# --------------------------------------------------------------------------- NetBox -> Estate
class _NetBoxReader:
    """Reads NetBox back into the canonical `Estate` so one differ serves both sides."""

    def __init__(self, client: NetBoxLike, site: str):
        self.client = client
        self.site = site
        self.roles = {r["id"]: r.get("slug", "") for r in client.all("dcim.device_roles")}
        self.manufacturers = {m["id"]: m.get("name", "") for m in client.all("dcim.manufacturers")}
        self.types = {t["id"]: t for t in client.all("dcim.device_types")}
        self.sites = {s["id"]: s.get("slug", "") for s in client.all("dcim.sites")}
        self.vlans = {v["id"]: v for v in client.all("ipam.vlans")}
        self.clusters = {c["id"]: c for c in client.all("virtualization.clusters")}

    def _site_slug(self, record: dict[str, Any]) -> str | None:
        value = record.get("site")
        if isinstance(value, dict):
            value = value.get("id")
        if isinstance(value, int):
            return self.sites.get(value)
        return str(value) if value else None

    def _in_site(self, record: dict[str, Any]) -> bool:
        slug = self._site_slug(record)
        return slug is None or slug == self.site

    def _vid(self, value: Any) -> int | None:
        if isinstance(value, dict):
            value = value.get("id")
        if isinstance(value, int):
            vlan = self.vlans.get(value)
            return int(vlan["vid"]) if vlan and vlan.get("vid") is not None else None
        return None

    @staticmethod
    def _fk(value: Any) -> int | None:
        if isinstance(value, dict):
            value = value.get("id")
        return value if isinstance(value, int) else None

    def estate(self) -> Estate:
        estate = Estate(site=self.site, origin="netbox")
        devices = [d for d in self.client.all("dcim.devices") if self._in_site(d)]
        device_names = {d["id"]: d.get("name", "") for d in devices}

        interfaces: dict[int, list[Interface]] = defaultdict(list)
        interface_owners: dict[int, tuple[str, str]] = {}
        for row in self.client.all("dcim.interfaces"):
            device_id = self._fk(row.get("device"))
            name = device_names.get(device_id) if device_id is not None else None
            if not name:
                continue
            mode = row.get("mode") or None
            interface_owners[int(row["id"])] = (name, row.get("name", ""))
            interfaces[device_id].append(
                Interface(
                    name=row.get("name", ""),
                    device=name,
                    type=row.get("type") or "1000base-t",
                    mac=normalize_mac(row.get("mac_address") or row.get("primary_mac_address")),
                    enabled=bool(row.get("enabled", True)),
                    description=row.get("description") or "",
                    mode=mode if mode in ("access", "tagged", "routed") else None,
                    untagged_vlan=self._vid(row.get("untagged_vlan")),
                    tagged_vlans=sorted(
                        v for v in (self._vid(t) for t in row.get("tagged_vlans") or []) if v
                    ),
                    mtu=row.get("mtu"),
                )
            )

        for row in devices:
            device_type = self.types.get(self._fk(row.get("device_type")) or -1, {})
            role = self.roles.get(self._fk(row.get("role")) or -1, "")
            estate.devices.append(
                Device(
                    name=row.get("name", ""),
                    kind=ROLE_KINDS.get(role, DeviceKind.cisco_ios),
                    role=role,
                    manufacturer=self.manufacturers.get(
                        self._fk(device_type.get("manufacturer")) or -1, "Unknown"
                    ),
                    model=device_type.get("model", "Unknown"),
                    serial=row.get("serial") or None,
                    site=self.site,
                    interfaces=sorted(interfaces[row["id"]], key=lambda i: i.name),
                )
            )

        for row in self.vlans.values():
            if not self._in_site(row) or row.get("vid") is None:
                continue
            estate.vlans.append(
                Vlan(
                    vid=int(row["vid"]),
                    name=row.get("name") or "",
                    status=str(row.get("status") or "active"),
                )
            )
        estate.vlans.sort(key=lambda v: v.vid)

        for row in self.client.all("ipam.prefixes"):
            if not self._in_site(row) or not row.get("prefix"):
                continue
            estate.prefixes.append(
                Prefix(
                    prefix=str(row["prefix"]),
                    vlan=self._vid(row.get("vlan")),
                    description=row.get("description") or "",
                )
            )
        estate.prefixes.sort(key=lambda p: p.prefix)

        cluster_names: dict[int, str] = {}
        for row in self.clusters.values():
            if not self._in_site(row):
                continue
            cluster_names[row["id"]] = row.get("name", "")
            estate.clusters.append(
                Cluster(name=row.get("name", ""), site=self.site, host=row.get("name"))
            )
        estate.clusters.sort(key=lambda c: c.name)

        vms = {
            row["id"]: row
            for row in self.client.all("virtualization.virtual_machines")
            if self._fk(row.get("cluster")) in cluster_names
        }
        vm_nics: dict[int, list[VMInterface]] = defaultdict(list)
        vm_nic_owners: dict[int, tuple[str, str]] = {}
        for row in self.client.all("virtualization.interfaces"):
            vm_id = self._fk(row.get("virtual_machine"))
            if vm_id not in vms:
                continue
            vm_nic_owners[int(row["id"])] = (
                vms[vm_id].get("name", ""),
                row.get("name", ""),
            )
            vm_nics[vm_id].append(
                VMInterface(
                    name=row.get("name", ""),
                    mac=normalize_mac(row.get("mac_address")),
                    portgroup=row.get("description") or None,
                    vlan=self._vid(row.get("untagged_vlan")),
                    enabled=bool(row.get("enabled", True)),
                )
            )
        for vm_id, row in vms.items():
            disk = row.get("disk")
            estate.virtual_machines.append(
                VirtualMachine(
                    name=row.get("name", ""),
                    cluster=cluster_names.get(self._fk(row.get("cluster")) or -1, ""),
                    status=str(row.get("status") or "active"),
                    vcpus=float(row["vcpus"]) if row.get("vcpus") is not None else None,
                    memory_mb=row.get("memory"),
                    disk_gb=float(disk) if disk is not None else None,
                    guest_os=row.get("comments") or None,
                    interfaces=sorted(vm_nics[vm_id], key=lambda i: i.name),
                )
            )
        estate.virtual_machines.sort(key=lambda v: v.name)

        for row in self.client.all("ipam.ip_addresses"):
            address = row.get("address")
            if not address:
                continue
            object_id = row.get("assigned_object_id")
            object_type = str(row.get("assigned_object_type") or "")
            owner: tuple[str, str] | None = None
            if isinstance(object_id, int):
                if object_type.endswith("vminterface"):
                    owner = vm_nic_owners.get(object_id)
                else:
                    owner = interface_owners.get(object_id)
            if owner is None:
                continue
            is_vm = object_type.endswith("vminterface")
            estate.ip_addresses.append(
                IPAddress(
                    address=str(address),
                    device=None if is_vm else owner[0],
                    virtual_machine=owner[0] if is_vm else None,
                    interface=owner[1],
                    hostname=row.get("dns_name") or None,
                    source="netbox",
                )
            )
        estate.ip_addresses.sort(key=lambda i: i.address)
        return estate


def intended_from_netbox(client: NetBoxLike, site: str = "hq") -> Estate:
    """Read NetBox back as an `Estate` so it can be diffed against observation."""
    return _NetBoxReader(client, site).estate()


# --------------------------------------------------------------------------- comparison
class _Comparer:
    def __init__(self, observed: Estate, intended: Estate, source: str):
        self.observed = observed
        self.intended = intended
        self.items: list[DriftItem] = []
        self.source = source

    def add(self, **kwargs: Any) -> None:
        self.items.append(DriftItem(**kwargs))

    # -- devices ------------------------------------------------------------
    def devices(self) -> None:
        observed = {d.name: d for d in self.observed.devices}
        intended = {d.name: d for d in self.intended.devices}
        for name in sorted(set(observed) | set(intended)):
            here, there = observed.get(name), intended.get(name)
            if there is None and here is not None:
                self.add(
                    device=name,
                    object_type="device",
                    object=name,
                    change="added",
                    severity=Severity.high,
                    summary=f"{name}: {here.model} is on the network but not in {self.source}",
                )
                continue
            if here is None and there is not None:
                self.add(
                    device=name,
                    object_type="device",
                    object=name,
                    change="removed",
                    severity=Severity.high,
                    summary=f"{name}: in {self.source} but no snapshot shows it on the network",
                )
                continue
            if here is not None and there is not None:
                self._device_fields(here, there)
                self._interfaces(here, there)

    def _device_fields(self, here: Device, there: Device) -> None:
        for field, severity in (
            ("serial", Severity.high),
            ("model", Severity.medium),
            ("role", Severity.low),
        ):
            mine, theirs = getattr(here, field), getattr(there, field)
            if not mine or not theirs or mine == theirs:
                continue
            self.add(
                device=here.name,
                object_type="device",
                object=here.name,
                change="changed",
                field=field,
                observed=mine,
                intended=theirs,
                severity=severity,
                summary=(
                    f"{here.name}: {field} is {_show(mine)} on the device, "
                    f"{_show(theirs)} in {self.source}"
                ),
            )

    def _interfaces(self, here: Device, there: Device) -> None:
        observed = {normalize_ifname(i.name): i for i in here.interfaces}
        intended = {normalize_ifname(i.name): i for i in there.interfaces}
        for name in sorted(set(observed) | set(intended)):
            mine, theirs = observed.get(name), intended.get(name)
            if theirs is None and mine is not None:
                self.add(
                    device=here.name,
                    object_type="interface",
                    object=f"{here.name}:{name}",
                    change="added",
                    severity=_bump(Severity.low, mine.is_sensitive()),
                    summary=f"{here.name}: interface {name} exists on the device but not in "
                    f"{self.source}",
                )
                continue
            if mine is None and theirs is not None:
                self.add(
                    device=here.name,
                    object_type="interface",
                    object=f"{here.name}:{name}",
                    change="removed",
                    severity=_bump(Severity.medium, theirs.is_sensitive()),
                    summary=f"{here.name}: interface {name} is in {self.source} but the device "
                    f"does not report it",
                )
                continue
            if mine is not None and theirs is not None:
                self._interface_fields(here.name, name, mine, theirs)

    def _interface_fields(self, device: str, name: str, mine: Interface, theirs: Interface) -> None:
        sensitive = mine.is_sensitive() or theirs.is_sensitive()
        for field, severity in _INTERFACE_FIELDS.items():
            projection = _PROJECTIONS.get(field, lambda v: v)
            a, b = projection(getattr(mine, field)), projection(getattr(theirs, field))
            # One side simply not knowing a description or a MAC is not drift.
            if field in ("description", "mac") and (not a or not b):
                continue
            if a == b:
                continue
            self.add(
                device=device,
                object_type="interface",
                object=f"{device}:{name}",
                change="changed",
                field=field,
                observed=a,
                intended=b,
                severity=_bump(severity, sensitive),
                summary=(
                    f"{device}: interface {name} {field} is {_show(a)} on the device, "
                    f"{_show(b)} in {self.source}"
                ),
            )

    # -- site-scoped objects -------------------------------------------------
    def _vlan_owner(self, vlan: Vlan | None) -> str:
        """Attribute VLAN drift to the switch or firewall that defines it, not to a
        hypervisor that merely has a portgroup on it."""
        if not vlan or not vlan.devices:
            return self.observed.site
        rank = {DeviceKind.cisco_ios: 0, DeviceKind.cisco_iosxe: 0, DeviceKind.fortigate: 1}
        return min(
            vlan.devices,
            key=lambda name: (
                rank.get(getattr(self.observed.device(name), "kind", None), 2),
                name,
            ),
        )

    def vlans(self) -> None:
        observed = {v.vid: v for v in self.observed.vlans}
        intended = {v.vid: v for v in self.intended.vlans}
        for vid in sorted(set(observed) | set(intended)):
            mine, theirs = observed.get(vid), intended.get(vid)
            owner = self._vlan_owner(mine)
            if theirs is None and mine is not None:
                self.add(
                    device=owner,
                    object_type="vlan",
                    object=f"vlan{vid}",
                    change="added",
                    severity=Severity.low,
                    summary=f"VLAN {vid} ({mine.name}) is configured on "
                    f"{', '.join(mine.devices) or 'the estate'} but is not in {self.source}",
                )
                continue
            if mine is None and theirs is not None:
                self.add(
                    device=owner,
                    object_type="vlan",
                    object=f"vlan{vid}",
                    change="removed",
                    severity=Severity.medium,
                    summary=f"VLAN {vid} ({theirs.name}) is in {self.source} but no device "
                    f"reports it",
                )
                continue
            if mine is None or theirs is None:
                continue
            for field, severity in (("name", Severity.medium), ("status", Severity.medium)):
                a, b = getattr(mine, field), getattr(theirs, field)
                if not a or not b or a == b:
                    continue
                self.add(
                    device=owner,
                    object_type="vlan",
                    object=f"vlan{vid}",
                    change="changed",
                    field=field,
                    observed=a,
                    intended=b,
                    severity=severity,
                    summary=(
                        f"VLAN {vid} {field} is {_show(a)} on "
                        f"{', '.join(mine.devices) or 'the estate'}; "
                        f"{self.source} says {_show(b)}"
                    ),
                )

    def prefixes(self) -> None:
        observed = {p.prefix: p for p in self.observed.prefixes}
        intended = {p.prefix: p for p in self.intended.prefixes}
        for prefix in sorted(set(observed) | set(intended)):
            mine, theirs = observed.get(prefix), intended.get(prefix)
            if theirs is None:
                self.add(
                    device=self.observed.site,
                    object_type="prefix",
                    object=prefix,
                    change="added",
                    severity=Severity.low,
                    summary=f"prefix {prefix} is configured but not in {self.source}",
                )
            elif mine is None:
                self.add(
                    device=self.observed.site,
                    object_type="prefix",
                    object=prefix,
                    change="removed",
                    severity=Severity.low,
                    summary=f"prefix {prefix} is in {self.source} but no device configures it",
                )
            elif mine.vlan and theirs.vlan and mine.vlan != theirs.vlan:
                self.add(
                    device=self.observed.site,
                    object_type="prefix",
                    object=prefix,
                    change="changed",
                    field="vlan",
                    observed=mine.vlan,
                    intended=theirs.vlan,
                    severity=Severity.low,
                    summary=f"prefix {prefix} is on VLAN {mine.vlan}, "
                    f"VLAN {theirs.vlan} in {self.source}",
                )

    # -- virtualization ------------------------------------------------------
    def clusters(self) -> None:
        observed = {c.name for c in self.observed.clusters}
        intended = {c.name for c in self.intended.clusters}
        for name in sorted(observed - intended):
            self.add(
                device=name,
                object_type="cluster",
                object=name,
                change="added",
                severity=Severity.medium,
                summary=f"cluster {name} exists on the estate but not in {self.source}",
            )
        for name in sorted(intended - observed):
            self.add(
                device=name,
                object_type="cluster",
                object=name,
                change="removed",
                severity=Severity.medium,
                summary=f"cluster {name} is in {self.source} but no ESXi host reports it",
            )

    def virtual_machines(self) -> None:
        observed = {v.name: v for v in self.observed.virtual_machines}
        intended = {v.name: v for v in self.intended.virtual_machines}
        for name in sorted(set(observed) | set(intended)):
            mine, theirs = observed.get(name), intended.get(name)
            if theirs is None and mine is not None:
                self.add(
                    device=mine.cluster,
                    object_type="vm",
                    object=name,
                    change="added",
                    severity=Severity.low,
                    summary=f"{mine.cluster}: VM {name} is running on the host but is not in "
                    f"{self.source}",
                )
                continue
            if mine is None and theirs is not None:
                self.add(
                    device=theirs.cluster,
                    object_type="vm",
                    object=name,
                    change="removed",
                    severity=Severity.medium,
                    summary=f"{theirs.cluster}: VM {name} is in {self.source} but no host "
                    f"reports it",
                )
                continue
            if mine is None or theirs is None:
                continue
            for field, severity in _VM_FIELDS.items():
                a, b = getattr(mine, field), getattr(theirs, field)
                if a is None or b is None or a == b:
                    continue
                self.add(
                    device=mine.cluster,
                    object_type="vm",
                    object=name,
                    change="changed",
                    field=field,
                    observed=a,
                    intended=b,
                    severity=severity,
                    summary=(
                        f"{mine.cluster}: VM {name} {field} is {_show(a)} on the host, "
                        f"{_show(b)} in {self.source}"
                    ),
                )
            self._vm_interfaces(mine, theirs)

    def _vm_interfaces(self, mine: VirtualMachine, theirs: VirtualMachine) -> None:
        observed = {i.name: i for i in mine.interfaces}
        intended = {i.name: i for i in theirs.interfaces}
        for name in sorted(set(observed) | set(intended)):
            a, b = observed.get(name), intended.get(name)
            if b is None:
                self.add(
                    device=mine.cluster,
                    object_type="vm_interface",
                    object=f"{mine.name}:{name}",
                    change="added",
                    severity=Severity.low,
                    summary=f"VM {mine.name} has vNIC {name} that {self.source} does not know",
                )
                continue
            if a is None:
                self.add(
                    device=mine.cluster,
                    object_type="vm_interface",
                    object=f"{mine.name}:{name}",
                    change="removed",
                    severity=Severity.medium,
                    summary=f"VM {mine.name} vNIC {name} is in {self.source} but not on the host",
                )
                continue
            for field, severity in _VM_INTERFACE_FIELDS.items():
                x, y = getattr(a, field), getattr(b, field)
                if x is None or y is None or x == y:
                    continue
                self.add(
                    device=mine.cluster,
                    object_type="vm_interface",
                    object=f"{mine.name}:{name}",
                    change="changed",
                    field=field,
                    observed=x,
                    intended=y,
                    severity=severity,
                    summary=(
                        f"VM {mine.name} vNIC {name} {field} is {_show(x)} on the host, "
                        f"{_show(y)} in {self.source}"
                    ),
                )

    def ip_addresses(self) -> None:
        observed = {ip.address: ip for ip in self.observed.assigned_ips()}
        intended = {ip.address: ip for ip in self.intended.assigned_ips()}
        for address in sorted(set(observed) | set(intended)):
            mine, theirs = observed.get(address), intended.get(address)
            if theirs is None and mine is not None:
                owner = mine.device or mine.virtual_machine or self.observed.site
                self.add(
                    device=owner,
                    object_type="ip",
                    object=address,
                    change="added",
                    severity=Severity.low,
                    summary=f"{owner}: {address} is configured on {mine.interface or 'the device'} "
                    f"but not in {self.source}",
                )
            elif mine is None and theirs is not None:
                owner = theirs.device or theirs.virtual_machine or self.intended.site
                self.add(
                    device=owner,
                    object_type="ip",
                    object=address,
                    change="removed",
                    severity=Severity.low,
                    summary=f"{owner}: {address} is in {self.source} but nothing reports it",
                )
            elif mine is not None and theirs is not None:
                here = (mine.device or mine.virtual_machine, mine.interface)
                there = (theirs.device or theirs.virtual_machine, theirs.interface)
                if here != there and all(there):
                    self.add(
                        device=here[0] or self.observed.site,
                        object_type="ip",
                        object=address,
                        change="changed",
                        field="assignment",
                        observed=f"{here[0]}:{here[1]}",
                        intended=f"{there[0]}:{there[1]}",
                        severity=Severity.medium,
                        summary=(
                            f"{address} is on {here[0]} {here[1]}; "
                            f"{self.source} has it on {there[0]} {there[1]}"
                        ),
                    )

    def run(self) -> list[DriftItem]:
        self.devices()
        self.vlans()
        self.prefixes()
        self.clusters()
        self.virtual_machines()
        self.ip_addresses()
        return self.items


def compare(
    observed: Estate,
    intended: Estate,
    *,
    source: str = "netbox",
    devices: list[str] | None = None,
) -> DriftReport:
    """Diff observed against intended and group the result by device."""
    items = _Comparer(observed, intended, source).run()
    if devices is not None:
        wanted = set(devices)
        items = [i for i in items if i.device in wanted]
    return DriftReport(
        site=observed.site,
        source=source,
        devices=sorted({d.name for d in observed.devices}) if devices is None else sorted(devices),
        items=_sorted_items(items),
        warnings=list(observed.warnings),
        observed_at=dict(observed.sources),
    )
