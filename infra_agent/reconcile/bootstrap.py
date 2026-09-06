"""Reconcile the observed estate into NetBox.

`bootstrap()` creates everything the estate implies -- site, manufacturers,
device roles, device types, platforms, devices, interfaces (with MACs), VLANs,
prefixes, IP addresses, one virtualization cluster per ESXi host, VMs and VM
interfaces -- and `sync()` refreshes a subset of it. Both are idempotent: every
write goes through `NetBoxBase.ensure`, which patches only fields that actually
differ, so a second run reports nothing but `unchanged`.

The payloads follow NetBox 4.2+ semantics (the deployment pins
`netboxcommunity/netbox:v4.3-3.3.0`), which differ from 4.0 in four ways this
package depends on and `FakeNetBox` reproduces:

* an interface with no 802.1Q mode may not carry `untagged_vlan`/`tagged_vlans`;
* `mac_address` is read-only -- a MAC is a `dcim.mac_addresses` object that the
  interface points at through `primary_mac_address`;
* a cluster is scoped with `scope_type`/`scope_id`, not `site`;
* a VM's `disk` and `memory` are both in MB.

Only parsed structure is written, and never into fields a human curates:
`comments` is left alone, and `serial` is sent only when a collector actually
reported one. Raw configs live in the config git store and never reach NetBox or
the language model.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from pydantic import BaseModel, Field

from infra_agent.models.common import DeviceKind
from infra_agent.reconcile.model import Device, Estate, Interface, VirtualMachine, network_of
from infra_agent.reconcile.netbox import OMIT, EnsureResult, NetBoxLike

# NetBox stores a VM's disk in MB since 4.1 (`virtualization` migration
# 0040_convert_disk_size); 4.0 stored GB. The pinned release is 4.3.
VM_DISK_UNIT = "MB"

ROLE_COLORS = {
    "firewall": "f44336",
    "core-switch": "2196f3",
    "access-switch": "03a9f4",
    "hypervisor": "4caf50",
    "management": "9e9e9e",
}

CLUSTER_TYPE = {"name": "VMware ESXi (standalone)", "slug": "vmware-esxi"}

# The operating system family behind a device kind, used to name a NetBox platform
# so the OS never has to be smuggled into the owner's `comments` field.
OS_FAMILIES: dict[DeviceKind, str] = {
    DeviceKind.fortigate: "FortiOS",
    DeviceKind.cisco_ios: "Cisco IOS",
    DeviceKind.cisco_iosxe: "Cisco IOS-XE",
    DeviceKind.esxi: "VMware ESXi",
    DeviceKind.ilo: "HPE iLO",
}

# NetBox's own filter shortcuts for objects assigned to an interface.
_ASSIGNMENT = {
    "dcim.interfaces": ("dcim.interface", "interface_id"),
    "virtualization.interfaces": ("virtualization.vminterface", "vminterface_id"),
}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(value: str) -> str:
    return _SLUG_RE.sub("-", str(value).strip().lower()).strip("-") or "unnamed"


def netbox_mode(interface: Interface) -> str:
    """NetBox 802.1Q mode. A routed port has no mode -- and therefore no VLANs."""
    if interface.mode == "access":
        return "access"
    if interface.mode == "tagged":
        return "tagged"
    return ""


def disk_mb(gigabytes: float | None) -> int | None:
    """GB as the estate models it -> MB as NetBox stores it."""
    if not gigabytes:
        return None
    return int(round(float(gigabytes) * 1024))


def disk_gb(megabytes: Any) -> float | None:
    """MB as NetBox stores it -> GB as the estate models it."""
    if megabytes in (None, ""):
        return None
    try:
        return round(float(megabytes) / 1024, 1)
    except (TypeError, ValueError):
        return None


def platform_name(kind: DeviceKind, os_version: str | None) -> str:
    family = OS_FAMILIES.get(kind, "Unknown")
    return f"{family} {os_version}".strip() if os_version else family


class ReconcileAction(BaseModel):
    endpoint: str
    object: str
    status: str
    fields: list[str] = Field(default_factory=list)


class ReconcileReport(BaseModel):
    """What the reconciler did. Safe to show the model and to print in the CLI."""

    site: str
    dry_run: bool = False
    devices: list[str] = Field(default_factory=list)
    actions: list[ReconcileAction] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @property
    def created(self) -> int:
        return sum(1 for a in self.actions if a.status in ("created", "would-create"))

    @property
    def updated(self) -> int:
        return sum(1 for a in self.actions if a.status in ("updated", "would-update"))

    @property
    def unchanged(self) -> int:
        return sum(1 for a in self.actions if a.status == "unchanged")

    @property
    def failed(self) -> int:
        return sum(1 for a in self.actions if a.status == "error")

    @property
    def changed(self) -> bool:
        return bool(self.created or self.updated)

    def by_endpoint(self) -> dict[str, dict[str, int]]:
        table: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for action in self.actions:
            table[action.endpoint][action.status] += 1
        return {k: dict(v) for k, v in sorted(table.items())}

    def summary_line(self) -> str:
        verb = "would create" if self.dry_run else "created"
        line = (
            f"{verb} {self.created}, "
            f"{'would update' if self.dry_run else 'updated'} {self.updated}, "
            f"unchanged {self.unchanged}"
        )
        return f"{line}, rejected {self.failed}" if self.failed else line

    def llm_view(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "dry_run": self.dry_run,
            "devices": self.devices,
            "created": self.created,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "failed": self.failed,
            "by_endpoint": self.by_endpoint(),
            "changes": [a.model_dump() for a in self.actions if a.status != "unchanged"],
            "warnings": self.warnings,
        }


class Reconciler:
    """Writes an `Estate` into NetBox, creating only what is missing."""

    def __init__(self, client: NetBoxLike, estate: Estate):
        self.client = client
        self.estate = estate
        self.report = ReconcileReport(
            site=estate.site,
            dry_run=bool(getattr(client, "dry_run", False)),
            warnings=list(estate.warnings),
        )
        self._site_id: int | None = None
        self._vlan_ids: dict[int, int] = {}
        self._cluster_ids: dict[str, int] = {}
        self._platform_ids: dict[str, int] = {}

    # -- plumbing -----------------------------------------------------------
    def _ensure(
        self,
        endpoint: str,
        label: str,
        key: dict[str, Any],
        defaults: dict[str, Any],
        create: dict[str, Any] | None = None,
    ) -> EnsureResult:
        """One upsert, with the failure of a single object contained.

        NetBox rejects an individual write for reasons the estate cannot always
        predict (a validation rule, a duplicate, a permission). Letting that abort
        the run would leave NetBox half-populated -- the site and two devices in,
        the switch and every VM out -- so a rejection becomes a warning and the
        run carries on with the next object.
        """
        try:
            result = self.client.ensure(endpoint, key, defaults, create)
        except Exception as error:  # noqa: BLE001 - any rejection must stay contained
            detail = str(error).replace("\n", " ")[:200]
            self.report.warnings.append(
                f"{endpoint} {label}: NetBox rejected the write ({type(error).__name__}: "
                f"{detail}); skipped, the rest of the run continues"
            )
            self.report.actions.append(
                ReconcileAction(endpoint=endpoint, object=label, status="error")
            )
            return EnsureResult(endpoint, {}, "error")
        self.report.actions.append(
            ReconcileAction(
                endpoint=endpoint,
                object=label,
                status=result.status,
                fields=result.changed_fields,
            )
        )
        return result

    @staticmethod
    def _clean(payload: dict[str, Any]) -> dict[str, Any]:
        """Drop unknown values: `None` means "the collector did not say", and must
        never overwrite something a human curated in NetBox."""
        return {k: v for k, v in payload.items() if v is not None}

    # -- scaffolding --------------------------------------------------------
    def site(self) -> int:
        result = self._ensure(
            "dcim.sites",
            self.estate.site,
            {"slug": self.estate.site},
            {"name": self.estate.site_name, "status": "active"},
        )
        self._site_id = result.id
        return result.id or 0

    def manufacturers(self, devices: list[Device]) -> dict[str, int]:
        ids: dict[str, int] = {}
        for name in sorted({d.manufacturer for d in devices if d.manufacturer}):
            result = self._ensure(
                "dcim.manufacturers", name, {"slug": slugify(name)}, {"name": name}
            )
            ids[name] = result.id or 0
        return ids

    def roles(self, devices: list[Device]) -> dict[str, int]:
        ids: dict[str, int] = {}
        for role in sorted({d.role for d in devices if d.role}):
            result = self._ensure(
                "dcim.device_roles",
                role,
                {"slug": role},
                {"name": role.replace("-", " ").title(), "color": ROLE_COLORS.get(role, "9e9e9e")},
            )
            ids[role] = result.id or 0
        return ids

    def device_types(self, devices: list[Device], manufacturers: dict[str, int]) -> dict[str, int]:
        ids: dict[str, int] = {}
        for device in devices:
            if device.model in ids:
                continue
            result = self._ensure(
                "dcim.device_types",
                device.model,
                {"model": device.model},
                {
                    "slug": slugify(f"{device.manufacturer}-{device.model}"),
                    "manufacturer": manufacturers.get(device.manufacturer),
                },
            )
            ids[device.model] = result.id or 0
        return ids

    def platform(self, name: str) -> int | None:
        """A NetBox platform per OS string: the field NetBox has for "what it runs"."""
        if not name:
            return None
        if name in self._platform_ids:
            return self._platform_ids[name]
        result = self._ensure("dcim.platforms", name, {"slug": slugify(name)}, {"name": name})
        if result.id is not None:
            self._platform_ids[name] = result.id
        return result.id

    def clusters(self, devices: list[Device]) -> None:
        hypervisors = [d for d in devices if d.kind is DeviceKind.esxi]
        wanted = [c for c in self.estate.clusters if any(d.name == c.host for d in hypervisors)]
        if not wanted:
            return
        type_result = self._ensure(
            "virtualization.cluster_types",
            CLUSTER_TYPE["slug"],
            {"slug": CLUSTER_TYPE["slug"]},
            {"name": CLUSTER_TYPE["name"]},
        )
        for cluster in wanted:
            result = self._ensure(
                "virtualization.clusters",
                cluster.name,
                {"name": cluster.name},
                self._clean(
                    {
                        "type": type_result.id,
                        # 4.2 replaced the cluster's `site` with a generic scope.
                        "scope_type": "dcim.site" if self._site_id else None,
                        "scope_id": self._site_id,
                        "status": "active",
                    }
                ),
            )
            self._cluster_ids[cluster.name] = result.id or 0

    def vlans(self, devices: list[Device]) -> None:
        names = {d.name for d in devices}
        for vlan in self.estate.vlans:
            if vlan.devices and not (set(vlan.devices) & names):
                continue
            result = self._ensure(
                "ipam.vlans",
                f"VLAN {vlan.vid}",
                {"vid": vlan.vid, "site": self.estate.site},
                {"name": vlan.name or f"vlan{vlan.vid}", "status": vlan.status},
                create={"site": self._site_id},
            )
            self._vlan_ids[vlan.vid] = result.id or 0

    def prefixes(self, devices: list[Device]) -> None:
        """Only the prefixes the selected devices actually configure an address in."""
        networks = {
            network_of(address)
            for device in devices
            for interface in device.interfaces
            for address in interface.addresses
        }
        for prefix in self.estate.prefixes:
            if prefix.prefix not in networks:
                continue
            self._ensure(
                "ipam.prefixes",
                prefix.prefix,
                {"prefix": prefix.prefix},
                self._clean(
                    {
                        "site": self._site_id,
                        "status": "active",
                        "vlan": self._vlan_ids.get(prefix.vlan) if prefix.vlan else None,
                        "description": prefix.description[:200],
                    }
                ),
            )

    # -- addresses ----------------------------------------------------------
    def mac_address(self, endpoint: str, object_id: int, label: str, mac: str | None) -> None:
        """Store a MAC the way NetBox 4.2+ does: an object, then a pointer to it.

        `mac_address` on an interface is read-only, so writing it there is silently
        dropped and every later sync sees a difference it can never close.
        """
        if not mac:
            return
        content_type, filter_name = _ASSIGNMENT[endpoint]
        mac_result = self._ensure(
            "dcim.mac_addresses",
            f"{label} {mac}",
            {"mac_address": mac, filter_name: object_id},
            {},
            create={
                filter_name: OMIT,  # queryable, not writable
                "assigned_object_type": content_type,
                "assigned_object_id": object_id,
            },
        )
        if mac_result.id is None:
            return
        self._ensure(
            endpoint,
            f"{label} primary MAC",
            {"id": object_id},
            {"primary_mac_address": mac_result.id},
        )

    def ip_address(self, address: str, endpoint: str, object_id: int) -> None:
        """Bind an address to an interface without stealing it from another object.

        The same address legitimately exists on several objects (an HA/VRRP VIP),
        and NetBox returns them in an arbitrary order, so keying on the address
        alone would move the assignment back and forth on every sync.
        """
        content_type, filter_name = _ASSIGNMENT[endpoint]
        mine = self.client.get("ipam.ip_addresses", address=address, **{filter_name: object_id})
        if mine is not None:
            self.report.actions.append(
                ReconcileAction(endpoint="ipam.ip_addresses", object=address, status="unchanged")
            )
            return
        existing = self.client.get("ipam.ip_addresses", address=address)
        if existing is not None and existing.get("assigned_object_id"):
            self.report.warnings.append(
                f"{address}: already assigned to another object in NetBox, left as it is"
            )
            self.report.actions.append(
                ReconcileAction(endpoint="ipam.ip_addresses", object=address, status="unchanged")
            )
            return
        self._ensure(
            "ipam.ip_addresses",
            address,
            {"address": address},
            {
                "status": "active",
                "assigned_object_type": content_type,
                "assigned_object_id": object_id,
            },
        )

    # -- devices ------------------------------------------------------------
    def device(self, device: Device, roles: dict[str, int], types: dict[str, int]) -> int | None:
        payload = self._clean(
            {
                "device_type": types.get(device.model),
                "role": roles.get(device.role),
                "site": self._site_id,
                "status": "active",
                # Only send a serial the collector actually read: an empty string
                # would blank a serial NetBox already knows and then read as drift.
                "serial": device.serial,
                "cluster": self._cluster_ids.get(device.name),
                "platform": self.platform(platform_name(device.kind, device.os_version)),
            }
        )
        result = self._ensure("dcim.devices", device.name, {"name": device.name}, payload)
        device_id = result.id
        if device_id is None:
            return None
        interface_ids: dict[str, int] = {}
        for interface in device.interfaces:
            interface_id = self.interface(device_id, device, interface)
            if interface_id is not None:
                interface_ids[interface.name] = interface_id
        self.interface_parents(device, interface_ids)
        self.primary_ip(device_id, device)
        return device_id

    def interface(self, device_id: int, device: Device, interface: Interface) -> int | None:
        mode = netbox_mode(interface)
        tagged = [self._vlan_ids[v] for v in interface.tagged_vlans if v in self._vlan_ids]
        untagged = self._vlan_ids.get(interface.untagged_vlan) if interface.untagged_vlan else None
        payload: dict[str, Any] = {
            "type": interface.type,
            "enabled": interface.enabled,
            "description": interface.description[:200],
            "mode": mode,
            # NetBox rejects VLANs on an interface with no 802.1Q mode, so an SVI or
            # a vmkernel port records its VLAN through its prefix, not through a
            # mode it does not have. Both are sent explicitly (not dropped) so a
            # port that stops being a trunk really is cleared.
            "untagged_vlan": untagged if mode in ("access", "tagged") else None,
            "tagged_vlans": tagged if mode == "tagged" else [],
        }
        if interface.mgmt_only:
            # Only ever set it: a collector cannot tell that a port a human marked
            # management-only has stopped being one, so it must not clear the flag.
            payload["mgmt_only"] = True
        if interface.mtu:
            payload["mtu"] = interface.mtu
        result = self._ensure(
            "dcim.interfaces",
            interface.key,
            {"device": device.name, "name": interface.name},
            payload,
            create={"device": device_id},
        )
        if result.id is None:
            return None
        self.mac_address("dcim.interfaces", result.id, interface.key, interface.mac)
        for address in interface.addresses:
            self.ip_address(address, "dcim.interfaces", result.id)
        return result.id

    def interface_parents(self, device: Device, interface_ids: dict[str, int]) -> None:
        """Hang a VLAN sub-interface off its physical parent (FortiOS `internal`)."""
        for interface in device.interfaces:
            child = interface_ids.get(interface.name)
            parent = interface_ids.get(interface.parent) if interface.parent else None
            if child is None or parent is None or child == parent:
                continue
            self._ensure(
                "dcim.interfaces",
                f"{interface.key} parent",
                {"id": child},
                {"parent": parent},
            )

    def primary_ip(self, device_id: int, device: Device) -> None:
        if not device.primary_ip:
            return
        match = next(
            (
                ip
                for ip in self.estate.assigned_ips()
                if ip.device == device.name and ip.ip == device.primary_ip
            ),
            None,
        )
        if match is None:
            return
        record = self.client.get("ipam.ip_addresses", address=match.address)
        if record and record.get("id"):
            self._ensure(
                "dcim.devices",
                f"{device.name} primary_ip4",
                {"name": device.name},
                {"primary_ip4": record["id"]},
            )

    # -- virtual machines ---------------------------------------------------
    def virtual_machine(self, vm: VirtualMachine) -> None:
        cluster_id = self._cluster_ids.get(vm.cluster)
        if cluster_id is None:
            return
        result = self._ensure(
            "virtualization.virtual_machines",
            vm.name,
            {"name": vm.name},
            self._clean(
                {
                    "cluster": cluster_id,
                    "site": self._site_id,
                    "status": vm.status,
                    "vcpus": vm.vcpus,
                    "memory": vm.memory_mb,
                    # NetBox stores MB, the estate models GB.
                    "disk": disk_mb(vm.disk_gb),
                    "platform": self.platform(vm.guest_os or ""),
                }
            ),
        )
        if result.id is None:
            return
        for nic in vm.interfaces:
            # A VM NIC on a VLAN'd portgroup is an access port; without a mode
            # NetBox silently drops the VLAN in `BaseInterface.save()`.
            vlan_id = self._vlan_ids.get(nic.vlan) if nic.vlan else None
            mode = "access" if vlan_id else ""
            nic_result = self._ensure(
                "virtualization.interfaces",
                f"{vm.name}:{nic.name}",
                {"virtual_machine": vm.name, "name": nic.name},
                {
                    "enabled": nic.enabled,
                    "description": (nic.portgroup or "")[:200],
                    "mode": mode,
                    "untagged_vlan": vlan_id,
                },
                create={"virtual_machine": result.id},
            )
            if nic_result.id is None:
                continue
            self.mac_address(
                "virtualization.interfaces", nic_result.id, f"{vm.name}:{nic.name}", nic.mac
            )
            for address in nic.addresses:
                self.ip_address(address, "virtualization.interfaces", nic_result.id)

    # -- entry point --------------------------------------------------------
    def run(self, devices: list[str] | None = None) -> ReconcileReport:
        selected = [d for d in self.estate.devices if devices is None or d.name in devices]
        self.report.devices = [d.name for d in selected]
        if devices is not None:
            missing = sorted(set(devices) - {d.name for d in self.estate.devices})
            for name in missing:
                self.report.warnings.append(f"{name}: not in the observed estate, skipped")

        self.site()
        self.clusters(selected)
        manufacturers = self.manufacturers(selected)
        roles = self.roles(selected)
        types = self.device_types(selected, manufacturers)
        self.vlans(selected)
        for device in selected:
            self.device(device, roles, types)
        self.prefixes(selected)

        clusters = set(self._cluster_ids)
        for vm in self.estate.virtual_machines:
            if vm.cluster in clusters:
                self.virtual_machine(vm)
        return self.report


def bootstrap(estate: Estate, client: NetBoxLike) -> ReconcileReport:
    """Create the whole estate in NetBox. Safe to re-run: nothing changes twice."""
    return Reconciler(client, estate).run()


def sync(estate: Estate, client: NetBoxLike, devices: list[str] | None = None) -> ReconcileReport:
    """Refresh NetBox from the newest snapshots, optionally for a subset of devices."""
    return Reconciler(client, estate).run(devices=devices)
