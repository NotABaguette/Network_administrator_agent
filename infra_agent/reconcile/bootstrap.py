"""Reconcile the observed estate into NetBox.

`bootstrap()` creates everything the estate implies -- site, manufacturers,
device roles, device types, devices, interfaces (with MACs), VLANs, prefixes,
IP addresses, one virtualization cluster per ESXi host, VMs and VM interfaces
-- and `sync()` refreshes a subset of it. Both are idempotent: every write
goes through `NetBoxBase.ensure`, which patches only fields that actually
differ, so a second run reports nothing but `unchanged`.

Only parsed structure is written. Raw configs live in the config git store and
never reach NetBox or the language model.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from pydantic import BaseModel, Field

from infra_agent.models.common import DeviceKind
from infra_agent.reconcile.model import Device, Estate, Interface, VirtualMachine, network_of
from infra_agent.reconcile.netbox import EnsureResult, NetBoxLike

# NetBox has used both GB and MB for a VM's disk over its 4.x releases; the
# platform stores GB and says so, rather than guessing per deployment.
VM_DISK_UNIT = "GB"

ROLE_COLORS = {
    "firewall": "f44336",
    "core-switch": "2196f3",
    "access-switch": "03a9f4",
    "hypervisor": "4caf50",
    "management": "9e9e9e",
}

CLUSTER_TYPE = {"name": "VMware ESXi (standalone)", "slug": "vmware-esxi"}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(value: str) -> str:
    return _SLUG_RE.sub("-", str(value).strip().lower()).strip("-") or "unnamed"


def netbox_mode(interface: Interface) -> str:
    """NetBox 802.1Q mode. A routed port has no mode."""
    if interface.mode == "access":
        return "access"
    if interface.mode == "tagged":
        return "tagged"
    return ""


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
    def changed(self) -> bool:
        return bool(self.created or self.updated)

    def by_endpoint(self) -> dict[str, dict[str, int]]:
        table: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for action in self.actions:
            table[action.endpoint][action.status] += 1
        return {k: dict(v) for k, v in sorted(table.items())}

    def summary_line(self) -> str:
        verb = "would create" if self.dry_run else "created"
        return (
            f"{verb} {self.created}, "
            f"{'would update' if self.dry_run else 'updated'} {self.updated}, "
            f"unchanged {self.unchanged}"
        )

    def llm_view(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "dry_run": self.dry_run,
            "devices": self.devices,
            "created": self.created,
            "updated": self.updated,
            "unchanged": self.unchanged,
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

    # -- plumbing -----------------------------------------------------------
    def _ensure(
        self,
        endpoint: str,
        label: str,
        key: dict[str, Any],
        defaults: dict[str, Any],
        create: dict[str, Any] | None = None,
    ) -> EnsureResult:
        result = self.client.ensure(endpoint, key, defaults, create)
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
                {"type": type_result.id, "site": self._site_id, "status": "active"},
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

    # -- devices ------------------------------------------------------------
    def device(self, device: Device, roles: dict[str, int], types: dict[str, int]) -> int | None:
        payload = self._clean(
            {
                "device_type": types.get(device.model),
                "role": roles.get(device.role),
                "site": self._site_id,
                "status": "active",
                "serial": device.serial or "",
                "cluster": self._cluster_ids.get(device.name),
                "comments": f"{device.kind.value} {device.os_version}" if device.os_version else "",
            }
        )
        result = self._ensure("dcim.devices", device.name, {"name": device.name}, payload)
        device_id = result.id
        if device_id is None:
            return None
        for interface in device.interfaces:
            self.interface(device_id, device, interface)
        self.primary_ip(device_id, device)
        return device_id

    def interface(self, device_id: int, device: Device, interface: Interface) -> None:
        tagged = [self._vlan_ids[v] for v in interface.tagged_vlans if v in self._vlan_ids]
        payload = self._clean(
            {
                "type": interface.type,
                "enabled": interface.enabled,
                "description": interface.description[:200],
                "mac_address": interface.mac or "",
                "mtu": interface.mtu,
                "mode": netbox_mode(interface),
                "untagged_vlan": self._vlan_ids.get(interface.untagged_vlan)
                if interface.untagged_vlan
                else None,
                "tagged_vlans": tagged if interface.mode == "tagged" else [],
            }
        )
        result = self._ensure(
            "dcim.interfaces",
            interface.key,
            {"device": device.name, "name": interface.name},
            payload,
            create={"device": device_id},
        )
        if result.id is None:
            return
        for address in interface.addresses:
            self._ensure(
                "ipam.ip_addresses",
                address,
                {"address": address},
                {
                    "status": "active",
                    "assigned_object_type": "dcim.interface",
                    "assigned_object_id": result.id,
                },
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
                    "disk": int(vm.disk_gb) if vm.disk_gb else None,
                    "comments": vm.guest_os or "",
                }
            ),
        )
        if result.id is None:
            return
        for nic in vm.interfaces:
            nic_result = self._ensure(
                "virtualization.interfaces",
                f"{vm.name}:{nic.name}",
                {"virtual_machine": vm.name, "name": nic.name},
                self._clean(
                    {
                        "enabled": nic.enabled,
                        "mac_address": nic.mac or "",
                        "description": nic.portgroup or "",
                        "untagged_vlan": self._vlan_ids.get(nic.vlan) if nic.vlan else None,
                    }
                ),
                create={"virtual_machine": result.id},
            )
            if nic_result.id is None:
                continue
            for address in nic.addresses:
                self._ensure(
                    "ipam.ip_addresses",
                    address,
                    {"address": address},
                    {
                        "status": "active",
                        "assigned_object_type": "virtualization.vminterface",
                        "assigned_object_id": nic_result.id,
                    },
                )

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
