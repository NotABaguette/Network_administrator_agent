"""Standalone ESXi collector over pyvmomi (read-only role).

There is no vCenter, so every host is queried on its own hostd. The collector
never writes: it holds a read-only role and only issues `Retrieve*`/`Query*`
calls. The one thing that leaves the API path is the host-config backup in
`configs()`, which shells out over SSH because `vim-cmd
hostsvc/firmware/backup_config` is the only supported way to produce a bundle;
that bundle goes to the config git store base64-encoded and never to the LLM.

Free-licence detection matters downstream: a host whose licence name contains
"Hypervisor" rejects API writes, so the change executor has to take the SSH
path for it (see `docs/architecture.md`).

Everything returned by `collect()` is parsed structure — rows, not raw text.
`pyVim`/`pyVmomi` are imported lazily so the package imports without them.
"""

from __future__ import annotations

import base64
import logging
import re
import ssl
from datetime import UTC, datetime, timedelta
from typing import Any

from infra_agent.collectors.base import Collector, register
from infra_agent.models.common import Credential, DeviceKind, SeedDevice
from infra_agent.monitoring import metrics

log = logging.getLogger(__name__)

MIB = 1024 * 1024
KIB = 1024

#: Host events worth keeping: who powered a VM off, who changed the host.
EVENT_TYPE_IDS: tuple[str, ...] = (
    # power / lifecycle
    "VmPoweredOffEvent",
    "VmPoweredOnEvent",
    "VmSuspendedEvent",
    "VmResettingEvent",
    "VmGuestShutdownEvent",
    "VmGuestRebootEvent",
    "VmStartingEvent",
    "VmStoppingEvent",
    "VmCreatedEvent",
    "VmRemovedEvent",
    "VmRegisteredEvent",
    "VmClonedEvent",
    "VmRenamedEvent",
    # configuration
    "VmReconfiguredEvent",
    "VmMacChangedEvent",
    "VmMacAssignedEvent",
    "VmDiskFailedEvent",
    "HostConfigAppliedEvent",
    "EnteringMaintenanceModeEvent",
    "EnteredMaintenanceModeEvent",
    "ExitMaintenanceModeEvent",
    "HostShutdownEvent",
    "LocalDatastoreCreatedEvent",
    "DatastoreRenamedEvent",
    "DatastoreRemovedOnHostEvent",
    "AccountCreatedEvent",
    "AccountRemovedEvent",
    "AccountUpdatedEvent",
    "PermissionAddedEvent",
    "PermissionUpdatedEvent",
    "PermissionRemovedEvent",
)

EVENT_WINDOW = timedelta(hours=24)
MAX_EVENTS = 200

#: vSwitch link discovery has to be `both` or CDP tells us nothing about the
#: switch side and the switch nothing about the host side.
WANTED_CDP_OPERATION = "both"

BACKUP_COMMAND = "vim-cmd hostsvc/firmware/backup_config"
BACKUP_FILENAME = "host-config.tgz.b64"
# The URL's path part only. The host part is normally the literal `*`, so the
# match is anchored on /downloads/ rather than on the first slash.
_BUNDLE_RE = re.compile(r"(/downloads/[^\s\"'<>]*configBundle[^\s\"'<>]*\.tgz)")


# --------------------------------------------------------------------------
# small pure helpers (unit-tested directly)
# --------------------------------------------------------------------------
def iso(value: Any) -> str | None:
    """ISO-8601 for a datetime, passthrough for a string, None for anything else."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str):
        return value
    return None


def _num(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def ratio(used: Any, total: Any) -> float | None:
    used_f, total_f = _num(used), _num(total)
    if used_f is None or not total_f:
        return None
    return round(used_f / total_f, 4)


def datastore_from_path(path: str | None) -> str | None:
    """`[datastore1] vm-01/vm-01.vmdk` -> `datastore1`."""
    if not path:
        return None
    match = re.match(r"^\[([^\]]+)\]", path.strip())
    return match.group(1) if match else None


def is_free_license(*names: str | None) -> bool:
    """The free licence is the one whose product name says "Hypervisor"."""
    return any("hypervisor" in (name or "").lower() for name in names)


def short_type_name(obj: Any) -> str:
    """`vim.event.VmPoweredOffEvent` (or a fake of it) -> `VmPoweredOffEvent`."""
    return type(obj).__name__.rsplit(".", 1)[-1]


def bundle_paths(command_output: str) -> list[str]:
    """Candidate on-host paths for the bundle `backup_config` just wrote.

    The command answers with a download URL whose host part is a literal `*`,
    e.g. `Bundle can be downloaded at : http://*/downloads/52f.../
    configBundle-esx-01.tgz`. The same file is on disk under /scratch.
    """
    match = _BUNDLE_RE.search(command_output or "")
    if not match:
        raise ValueError("backup_config did not report a configBundle path")
    remote = match.group(1)
    # /scratch is the real location; the bare URL path is the fallback for hosts
    # whose scratch partition is mounted elsewhere.
    return list(dict.fromkeys([f"/scratch{remote}", remote]))


def _section(errors: dict[str, str], key: str, fn: Any, default: Any) -> Any:
    """Run one collection section; a failure degrades to `default` plus an error row."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - one bad section must not lose the run
        errors[key] = f"{type(exc).__name__}: {exc}"
        return default


def first_host(content: Any) -> Any:
    """The single HostSystem of a standalone host."""
    for datacenter in getattr(content.rootFolder, "childEntity", None) or []:
        host_folder = getattr(datacenter, "hostFolder", None)
        for compute in getattr(host_folder, "childEntity", None) or []:
            for host in getattr(compute, "host", None) or []:
                return host
    raise LookupError("no HostSystem in the ESXi inventory")


# --------------------------------------------------------------------------
# row builders
# --------------------------------------------------------------------------
def host_row(host: Any) -> dict[str, Any]:
    summary = host.summary
    hardware = summary.hardware
    runtime = summary.runtime
    quick = getattr(summary, "quickStats", None)
    bios = getattr(getattr(host, "hardware", None), "biosInfo", None)
    identifiers = {
        str(getattr(getattr(i, "identifierType", None), "key", "")): getattr(
            i, "identifierValue", None
        )
        for i in getattr(hardware, "otherIdentifyingInfo", None) or []
    }
    cores = getattr(hardware, "numCpuCores", None)
    mhz = getattr(hardware, "cpuMhz", None)
    cpu_capacity = (cores or 0) * (mhz or 0) or None
    memory_bytes = getattr(hardware, "memorySize", None)
    cpu_used = getattr(quick, "overallCpuUsage", None)
    memory_used_mb = _num(getattr(quick, "overallMemoryUsage", None))
    memory_used_bytes = memory_used_mb * MIB if memory_used_mb is not None else None
    return {
        "name": getattr(host, "name", None),
        "vendor": getattr(hardware, "vendor", None),
        "model": getattr(hardware, "model", None),
        "uuid": getattr(hardware, "uuid", None),
        "service_tag": identifiers.get("ServiceTag") or identifiers.get("AssetTag"),
        "cpu_model": (getattr(hardware, "cpuModel", None) or "").strip() or None,
        "cpu_packages": getattr(hardware, "numCpuPkgs", None),
        "cpu_cores": cores,
        "cpu_threads": getattr(hardware, "numCpuThreads", None),
        "cpu_mhz": mhz,
        "cpu_capacity_mhz": cpu_capacity,
        "cpu_usage_mhz": cpu_used,
        "cpu_usage_ratio": ratio(cpu_used, cpu_capacity),
        "memory_bytes": memory_bytes,
        "memory_usage_bytes": memory_used_bytes,
        "memory_usage_ratio": ratio(memory_used_bytes, memory_bytes),
        "nic_count": getattr(hardware, "numNics", None),
        "hba_count": getattr(hardware, "numHBAs", None),
        "bios_version": getattr(bios, "biosVersion", None),
        "bios_release_date": iso(getattr(bios, "releaseDate", None)),
        "power_state": str(getattr(runtime, "powerState", "") or "") or None,
        "connection_state": str(getattr(runtime, "connectionState", "") or "") or None,
        "in_maintenance_mode": getattr(runtime, "inMaintenanceMode", None),
        "boot_time": iso(getattr(runtime, "bootTime", None)),
        "uptime_seconds": getattr(quick, "uptime", None),
    }


def version_row(about: Any) -> dict[str, Any]:
    return {
        "product": getattr(about, "fullName", None),
        "name": getattr(about, "name", None),
        "version": getattr(about, "version", None),
        "build": getattr(about, "build", None),
        "api_version": getattr(about, "apiVersion", None),
        "os_type": getattr(about, "osType", None),
        "license_product_name": getattr(about, "licenseProductName", None),
        "license_product_version": getattr(about, "licenseProductVersion", None),
    }


def license_row(license_info: Any) -> dict[str, Any]:
    """Licence metadata only: the licence key itself never leaves the host."""
    name = getattr(license_info, "name", None)
    return {
        "name": name,
        "edition": getattr(license_info, "editionKey", None),
        "total": getattr(license_info, "total", None),
        "used": getattr(license_info, "used", None),
    }


def pnic_row(pnic: Any) -> dict[str, Any]:
    link = getattr(pnic, "linkSpeed", None)
    return {
        "name": getattr(pnic, "device", None),
        "mac": getattr(pnic, "mac", None),
        "driver": getattr(pnic, "driver", None),
        "pci": getattr(pnic, "pci", None),
        "link": link is not None,
        "speed_mb": getattr(link, "speedMb", None),
        "duplex": getattr(link, "duplex", None),
        "autonegotiate": getattr(pnic, "autoNegotiateSupported", None),
    }


def vswitch_row(vswitch: Any, pnic_names: dict[str, str]) -> dict[str, Any]:
    spec = getattr(vswitch, "spec", None)
    bridge = getattr(spec, "bridge", None)
    discovery = getattr(bridge, "linkDiscoveryProtocolConfig", None)
    operation = getattr(discovery, "operation", None)
    protocol = getattr(discovery, "protocol", None)
    uplinks = [pnic_names.get(str(key), str(key)) for key in getattr(vswitch, "pnic", None) or []]
    warnings: list[str] = []
    if operation != WANTED_CDP_OPERATION:
        warnings.append(
            f"link discovery is '{operation or 'none'}', not '{WANTED_CDP_OPERATION}': "
            "the switch side of this uplink cannot be correlated"
        )
    if not uplinks:
        warnings.append("no uplink attached")
    policy = getattr(spec, "policy", None)
    security = getattr(policy, "security", None)
    return {
        "name": getattr(vswitch, "name", None),
        "uplinks": uplinks,
        "mtu": getattr(vswitch, "mtu", None) or getattr(spec, "mtu", None),
        "num_ports": getattr(vswitch, "numPorts", None) or getattr(spec, "numPorts", None),
        "num_ports_available": getattr(vswitch, "numPortsAvailable", None),
        "cdp_protocol": protocol,
        "cdp_mode": operation,
        "cdp_ok": operation == WANTED_CDP_OPERATION,
        "security": {
            "promiscuous_mode": getattr(security, "allowPromiscuous", None),
            "forged_transmits": getattr(security, "forgedTransmits", None),
            "mac_changes": getattr(security, "macChanges", None),
        },
        "warnings": warnings,
    }


def portgroup_row(portgroup: Any) -> dict[str, Any]:
    spec = getattr(portgroup, "spec", None)
    policy = getattr(spec, "policy", None)
    security = getattr(policy, "security", None)
    return {
        "name": getattr(spec, "name", None),
        "vlan": getattr(spec, "vlanId", None),
        "vswitch": getattr(spec, "vswitchName", None),
        "key": getattr(portgroup, "key", None),
        "active_ports": len(getattr(portgroup, "port", None) or []),
        "security_override": {
            "promiscuous_mode": getattr(security, "allowPromiscuous", None),
            "forged_transmits": getattr(security, "forgedTransmits", None),
            "mac_changes": getattr(security, "macChanges", None),
        },
    }


def vmkernel_services(net_config: Any) -> dict[str, list[str]]:
    """device name -> enabled services (management, vmotion, vSphereProvisioning...)."""
    services: dict[str, list[str]] = {}
    for config in net_config or []:
        selected = list(getattr(config, "selectedVnic", None) or [])
        nic_type = getattr(config, "nicType", None)
        for candidate in getattr(config, "candidateVnic", None) or []:
            key = getattr(candidate, "key", None)
            device = getattr(candidate, "device", None)
            if not key or not device:
                continue
            if any(str(entry).endswith(str(key)) for entry in selected):
                services.setdefault(device, []).append(str(nic_type))
    return {device: sorted(set(names)) for device, names in services.items()}


def vmkernel_row(vnic: Any, services: dict[str, list[str]]) -> dict[str, Any]:
    spec = getattr(vnic, "spec", None)
    ip = getattr(spec, "ip", None)
    device = getattr(vnic, "device", None)
    return {
        "name": device,
        "portgroup": getattr(vnic, "portgroup", None),
        "mac": getattr(spec, "mac", None),
        "ip": getattr(ip, "ipAddress", None),
        "netmask": getattr(ip, "subnetMask", None),
        "dhcp": getattr(ip, "dhcp", None),
        "mtu": getattr(spec, "mtu", None),
        "tcpip_stack": getattr(spec, "netStackInstanceKey", None),
        "services": services.get(str(device), []),
    }


def datastore_row(datastore: Any) -> dict[str, Any]:
    summary = datastore.summary
    info = getattr(datastore, "info", None)
    capacity = getattr(summary, "capacity", None)
    free = getattr(summary, "freeSpace", None)
    row: dict[str, Any] = {
        "name": getattr(summary, "name", None),
        "type": getattr(summary, "type", None),
        "url": getattr(summary, "url", None),
        "accessible": getattr(summary, "accessible", None),
        "maintenance_mode": getattr(summary, "maintenanceMode", None),
        "capacity_bytes": capacity,
        "free_bytes": free,
        "uncommitted_bytes": getattr(summary, "uncommitted", None),
        "free_ratio": ratio(free, capacity),
        "backing": None,
    }
    vmfs = getattr(info, "vmfs", None)
    nas = getattr(info, "nas", None)
    if vmfs is not None:
        row["backing"] = {
            "kind": "vmfs",
            "uuid": getattr(vmfs, "uuid", None),
            "version": getattr(vmfs, "version", None),
            "ssd": getattr(vmfs, "ssd", None),
            "local": getattr(vmfs, "local", None),
            "devices": [
                getattr(extent, "diskName", None) for extent in getattr(vmfs, "extent", None) or []
            ],
        }
    elif nas is not None:
        row["backing"] = {
            "kind": "nas",
            "type": getattr(nas, "type", None),
            "remote_host": getattr(nas, "remoteHost", None),
            "remote_path": getattr(nas, "remotePath", None),
        }
    return row


def _is_disk(device: Any) -> bool:
    return hasattr(device, "capacityInKB") and getattr(device, "backing", None) is not None


def _is_vnic(device: Any) -> bool:
    return getattr(device, "macAddress", None) is not None


def _portgroup_of(backing: Any) -> str | None:
    name = getattr(backing, "deviceName", None)
    if name:
        return name
    port = getattr(backing, "port", None)
    return getattr(port, "portgroupKey", None)


def vm_disk_row(device: Any) -> dict[str, Any]:
    backing = getattr(device, "backing", None)
    file_name = getattr(backing, "fileName", None)
    capacity_kb = _num(getattr(device, "capacityInKB", None))
    return {
        "label": getattr(getattr(device, "deviceInfo", None), "label", None),
        "key": getattr(device, "key", None),
        "capacity_bytes": capacity_kb * KIB if capacity_kb is not None else None,
        "file": file_name,
        "datastore": datastore_from_path(file_name),
        "disk_mode": getattr(backing, "diskMode", None),
        "thin_provisioned": getattr(backing, "thinProvisioned", None),
        "uuid": getattr(backing, "uuid", None),
    }


def vm_nic_row(device: Any) -> dict[str, Any]:
    connectable = getattr(device, "connectable", None)
    return {
        "label": getattr(getattr(device, "deviceInfo", None), "label", None),
        "key": getattr(device, "key", None),
        "type": short_type_name(device),
        "mac": getattr(device, "macAddress", None),
        "address_type": getattr(device, "addressType", None),
        "portgroup": _portgroup_of(getattr(device, "backing", None)),
        "connected": getattr(connectable, "connected", None),
        "start_connected": getattr(connectable, "startConnected", None),
    }


def snapshot_rows(nodes: Any, now: datetime, depth: int = 0) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for node in nodes or []:
        created = getattr(node, "createTime", None)
        age = None
        if isinstance(created, datetime):
            reference = now if created.tzinfo else now.replace(tzinfo=None)
            age = round((reference - created).total_seconds(), 1)
        rows.append(
            {
                "id": getattr(node, "id", None),
                "name": getattr(node, "name", None),
                "description": getattr(node, "description", None),
                "created_at": iso(created),
                "age_seconds": age,
                "state": str(getattr(node, "state", "") or "") or None,
                "quiesced": getattr(node, "quiesced", None),
                "depth": depth,
            }
        )
        rows.extend(snapshot_rows(getattr(node, "childSnapshotList", None), now, depth + 1))
    return rows


def guest_ips(guest: Any) -> list[str]:
    addresses: list[str] = []
    primary = getattr(guest, "ipAddress", None)
    if primary:
        addresses.append(primary)
    for nic in getattr(guest, "net", None) or []:
        for address in getattr(nic, "ipAddress", None) or []:
            addresses.append(address)
        ip_config = getattr(nic, "ipConfig", None)
        for entry in getattr(ip_config, "ipAddress", None) or []:
            address = getattr(entry, "ipAddress", None)
            if address:
                addresses.append(address)
    return sorted(dict.fromkeys(addresses))


def vm_row(vm: Any, now: datetime) -> dict[str, Any]:
    summary = vm.summary
    config = getattr(summary, "config", None)
    runtime = getattr(summary, "runtime", None)
    quick = getattr(summary, "quickStats", None)
    storage = getattr(summary, "storage", None)
    guest = getattr(vm, "guest", None)
    devices = getattr(getattr(getattr(vm, "config", None), "hardware", None), "device", None) or []
    snapshots = snapshot_rows(getattr(getattr(vm, "snapshot", None), "rootSnapshotList", None), now)
    ages = [s["age_seconds"] for s in snapshots if s["age_seconds"] is not None]
    guest_nets = [
        {
            "network": getattr(nic, "network", None),
            "mac": getattr(nic, "macAddress", None),
            "connected": getattr(nic, "connected", None),
            "ips": list(getattr(nic, "ipAddress", None) or []),
        }
        for nic in getattr(guest, "net", None) or []
    ]
    return {
        "name": getattr(config, "name", None),
        "uuid": getattr(config, "uuid", None),
        "instance_uuid": getattr(config, "instanceUuid", None),
        "path": getattr(config, "vmPathName", None),
        "datastore": datastore_from_path(getattr(config, "vmPathName", None)),
        "template": bool(getattr(config, "template", False)),
        "annotation": getattr(config, "annotation", None),
        "power_state": str(getattr(runtime, "powerState", "") or "") or None,
        "connection_state": str(getattr(runtime, "connectionState", "") or "") or None,
        "boot_time": iso(getattr(runtime, "bootTime", None)),
        "cpu": getattr(config, "numCpu", None),
        "memory_mb": getattr(config, "memorySizeMB", None),
        "guest_os": getattr(config, "guestFullName", None),
        "guest_state": getattr(guest, "guestState", None),
        "guest_hostname": getattr(guest, "hostName", None),
        "guest_ips": guest_ips(guest),
        "guest_nets": guest_nets,
        "tools": {
            "status": str(getattr(guest, "toolsStatus", "") or "") or None,
            "running": str(getattr(guest, "toolsRunningStatus", "") or "") or None,
            "version": getattr(guest, "toolsVersion", None),
            "version_status": str(getattr(guest, "toolsVersionStatus2", "") or "") or None,
        },
        "usage": {
            "cpu_mhz": getattr(quick, "overallCpuUsage", None),
            "guest_memory_mb": getattr(quick, "guestMemoryUsage", None),
            "host_memory_mb": getattr(quick, "hostMemoryUsage", None),
            "uptime_seconds": getattr(quick, "uptimeSeconds", None),
            "committed_bytes": getattr(storage, "committed", None),
            "uncommitted_bytes": getattr(storage, "uncommitted", None),
        },
        "disks": [vm_disk_row(d) for d in devices if _is_disk(d)],
        "nics": [vm_nic_row(d) for d in devices if _is_vnic(d)],
        "guest_disks": [
            {
                "path": getattr(disk, "diskPath", None),
                "capacity_bytes": getattr(disk, "capacity", None),
                "free_bytes": getattr(disk, "freeSpace", None),
            }
            for disk in getattr(guest, "disk", None) or []
        ],
        "snapshots": snapshots,
        "snapshot_count": len(snapshots),
        "oldest_snapshot_age_seconds": max(ages) if ages else None,
    }


def event_row(event: Any) -> dict[str, Any]:
    vm = getattr(event, "vm", None)
    host = getattr(event, "host", None)
    datastore = getattr(event, "ds", None)
    return {
        "id": getattr(event, "key", None),
        "type": short_type_name(event),
        "at": iso(getattr(event, "createdTime", None)),
        "user": getattr(event, "userName", None) or None,
        "vm": getattr(vm, "name", None),
        "host": getattr(host, "name", None),
        "datastore": getattr(datastore, "name", None),
        "message": getattr(event, "fullFormattedMessage", None),
    }


@register
class EsxiCollector(Collector):
    """Read-only inventory of one standalone ESXi host and its VMs."""

    kind = DeviceKind.esxi
    name = "esxi"
    interval_seconds = 300

    # -- transport ---------------------------------------------------------
    def _connect(self, device: SeedDevice, cred: Credential) -> Any:
        from pyVim.connect import SmartConnect

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # thumbprint pinning lands with the executors
        return SmartConnect(
            host=device.mgmt_ip,
            port=device.port or 443,
            user=cred.username,
            pwd=cred.password.get_secret_value() if cred.password else "",
            sslContext=context,
        )

    def _disconnect(self, service_instance: Any) -> None:
        from pyVim.connect import Disconnect

        Disconnect(service_instance)

    # -- collection --------------------------------------------------------
    def collect(self, device: SeedDevice, cred: Credential) -> dict[str, Any]:
        service_instance = self._connect(device, cred)
        try:
            data = self.collect_from_content(service_instance.RetrieveContent())
        finally:
            try:
                self._disconnect(service_instance)
            except Exception as exc:  # noqa: BLE001 - never fail a run on teardown
                log.debug("esxi disconnect failed for %s: %s", device.name, exc)
        self.publish_metrics(device.name, data)
        return data

    def collect_from_content(self, content: Any, now: datetime | None = None) -> dict[str, Any]:
        """Everything below works off a RetrieveContent() result, so it is testable
        against a fake object tree without a host."""
        now = now or datetime.now(UTC)
        errors: dict[str, str] = {}
        host = first_host(content)
        network: Any = getattr(getattr(host, "config", None), "network", None)

        pnics = _section(errors, "pnics", lambda: [pnic_row(p) for p in network.pnic or []], [])
        pnic_names: dict[str, str] = {
            str(getattr(p, "key", "")): str(getattr(p, "device", ""))
            for p in (getattr(network, "pnic", None) or [])
            if getattr(p, "key", None)
        }
        vswitches = _section(
            errors,
            "vswitches",
            lambda: [vswitch_row(v, pnic_names) for v in network.vswitch or []],
            [],
        )
        portgroups = _section(
            errors, "portgroups", lambda: [portgroup_row(p) for p in network.portgroup or []], []
        )
        services = _section(
            errors,
            "vmkernel_services",
            lambda: vmkernel_services(
                getattr(getattr(host.config, "virtualNicManagerInfo", None), "netConfig", None)
            ),
            {},
        )
        vmkernels = _section(
            errors, "vmkernel", lambda: [vmkernel_row(v, services) for v in network.vnic or []], []
        )
        datastores = _section(
            errors, "datastores", lambda: [datastore_row(d) for d in host.datastore or []], []
        )
        vms = _section(errors, "vms", lambda: [vm_row(vm, now) for vm in host.vm or []], [])
        version = _section(errors, "version", lambda: version_row(content.about), {})
        licenses = _section(
            errors,
            "license",
            lambda: [license_row(lic) for lic in content.licenseManager.licenses or []],
            [],
        )
        events = _section(
            errors, "events", lambda: self.collect_events(content, now - EVENT_WINDOW), []
        )

        license_names = [lic.get("name") for lic in licenses]
        free = is_free_license(*license_names, version.get("license_product_name"))
        warnings: list[str] = []
        if free:
            warnings.append(
                "free licence (Hypervisor): the API rejects writes, "
                "the change executor must use the SSH path for this host"
            )
        for vswitch in vswitches:
            for warning in vswitch["warnings"]:
                warnings.append(f"vswitch {vswitch['name']}: {warning}")

        return {
            "host": _section(errors, "host", lambda: host_row(host), {}),
            "version": version,
            "license": {
                "names": license_names,
                "free": free,
                "details": licenses,
            },
            "pnics": pnics,
            "vswitches": vswitches,
            "portgroups": portgroups,
            "vmkernel": vmkernels,
            "datastores": datastores,
            "vms": vms,
            "events": events,
            "warnings": warnings,
            "errors": errors,
        }

    def collect_events(self, content: Any, since: datetime) -> list[dict[str, Any]]:
        """Power and configuration events since `since`, with the user behind each.

        Some builds reject an unknown `eventTypeId`; fall back to a time-only
        query and filter here rather than losing the whole section.
        """
        manager = content.eventManager
        try:
            raw = manager.QueryEvents(self.event_filter_spec(since, list(EVENT_TYPE_IDS)))
        except Exception as exc:  # noqa: BLE001 - degrade to a time-only query
            log.debug("filtered event query rejected (%s); retrying without types", exc)
            raw = manager.QueryEvents(self.event_filter_spec(since, None))
        rows = [event_row(e) for e in raw or [] if short_type_name(e) in EVENT_TYPE_IDS]
        return rows[-MAX_EVENTS:]

    @staticmethod
    def event_filter_spec(since: datetime, type_ids: list[str] | None) -> Any:
        from pyVmomi import vim

        spec = vim.event.EventFilterSpec()
        spec.time = vim.event.EventFilterSpec.ByTime(beginTime=since)
        if type_ids:
            spec.eventTypeId = type_ids
        return spec

    # -- metrics -----------------------------------------------------------
    def publish_metrics(self, device_name: str, data: dict[str, Any]) -> None:
        host = data.get("host") or {}
        cpu = host.get("cpu_usage_ratio")
        if cpu is not None:
            metrics.ESXI_HOST_CPU_USAGE_RATIO.labels(device=device_name).set(cpu)
        memory = host.get("memory_usage_ratio")
        if memory is not None:
            metrics.ESXI_HOST_MEMORY_USAGE_RATIO.labels(device=device_name).set(memory)
        uptime = _num(host.get("uptime_seconds"))
        if uptime is not None:
            metrics.ESXI_HOST_UPTIME_SECONDS.labels(device=device_name).set(uptime)

        for pnic in data.get("pnics") or []:
            if pnic.get("name"):
                metrics.ESXI_PNIC_LINK_UP.labels(device=device_name, pnic=pnic["name"]).set(
                    1 if pnic.get("link") else 0
                )

        for datastore in data.get("datastores") or []:
            name = datastore.get("name")
            if not name:
                continue
            capacity = _num(datastore.get("capacity_bytes"))
            free = _num(datastore.get("free_bytes"))
            if capacity is not None:
                metrics.ESXI_DATASTORE_CAPACITY_BYTES.labels(
                    device=device_name, datastore=name
                ).set(capacity)
            if free is not None:
                metrics.ESXI_DATASTORE_FREE_BYTES.labels(device=device_name, datastore=name).set(
                    free
                )

        for vm in data.get("vms") or []:
            name = vm.get("name")
            if not name:
                continue
            metrics.ESXI_VM_POWER_STATE.labels(device=device_name, vm=name).set(
                1 if vm.get("power_state") == "poweredOn" else 0
            )
            metrics.ESXI_VM_SNAPSHOT_COUNT.labels(device=device_name, vm=name).set(
                vm.get("snapshot_count") or 0
            )
            metrics.ESXI_VM_SNAPSHOT_AGE_SECONDS.labels(device=device_name, vm=name).set(
                _num(vm.get("oldest_snapshot_age_seconds")) or 0.0
            )

    # -- host config backup (SSH) -----------------------------------------
    def _ssh_client(self, device: SeedDevice, cred: Credential) -> Any:
        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # pinned with the executors
        kwargs: dict[str, Any] = {
            "hostname": device.mgmt_ip,
            "port": 22,  # device.port is the API port, SSH is always 22 on ESXi
            "username": cred.username,
            "timeout": 20,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if cred.ssh_key_path:
            kwargs["key_filename"] = cred.ssh_key_path
        if cred.password:
            kwargs["password"] = cred.password.get_secret_value()
        client.connect(**kwargs)
        return client

    @staticmethod
    def _run(client: Any, command: str) -> str:
        _stdin, stdout, stderr = client.exec_command(command, timeout=120)
        out = stdout.read()
        err = stderr.read()
        status = getattr(getattr(stdout, "channel", None), "recv_exit_status", lambda: 0)()
        text = out.decode("utf-8", "replace") if isinstance(out, bytes) else str(out)
        if status:
            detail = err.decode("utf-8", "replace") if isinstance(err, bytes) else str(err)
            raise RuntimeError(f"{command!r} exited {status}: {detail.strip()[:200]}")
        return text

    @staticmethod
    def _download(client: Any, candidates: list[str]) -> bytes:
        sftp = client.open_sftp()
        try:
            last: Exception | None = None
            for path in candidates:
                try:
                    with sftp.open(path, "rb") as handle:
                        return handle.read()
                except OSError as exc:
                    last = exc
            raise FileNotFoundError(f"no host-config bundle at any of {candidates}") from last
        finally:
            sftp.close()

    def configs(self, device: SeedDevice, cred: Credential) -> dict[str, str]:
        """Host-config bundle, base64-encoded, for the config git store.

        The bundle is a tarball, so it is stored base64 (line-wrapped, so git
        still produces a usable diff). It is a backup artefact: like every raw
        config it stays in the git store and never reaches the language model.
        Without an SSH credential there is no supported way to take it, so the
        collector returns nothing rather than guessing.
        """
        if not (cred.ssh_key_path or cred.password):
            log.info("no SSH credential for %s: skipping host-config backup", device.name)
            return {}
        client = self._ssh_client(device, cred)
        try:
            output = self._run(client, BACKUP_COMMAND)
            blob = self._download(client, bundle_paths(output))
        finally:
            client.close()
        return {BACKUP_FILENAME: base64.encodebytes(blob).decode("ascii")}
