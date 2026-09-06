"""Read-only inventory tools.

Every function answers from the observed snapshot store first and enriches
from NetBox when it is configured. They return parsed rows only -- device
names, interfaces, VLANs, MACs, addresses and structured drift -- never raw
configuration text, and they never change device state.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from infra_agent.reconcile import service
from infra_agent.reconcile.model import Estate, bare_ip, normalize_ifname, normalize_mac
from infra_agent.reconcile.netbox import NetBoxLike
from infra_agent.tools.registry import tool

MAX_MATCHES = 25


def _estate() -> Estate:
    return service.observed_estate()


def _netbox() -> NetBoxLike | None:
    try:
        return service.netbox_client()
    except Exception:  # pragma: no cover - NetBox misconfiguration must not break reads
        return None


def _netbox_rows(endpoint: str, **filters: Any) -> list[dict[str, Any]]:
    client = _netbox()
    if client is None:
        return []
    try:
        return client.all(endpoint, **filters)
    except Exception:  # pragma: no cover - NetBox being down is not an inventory failure
        return []


def _interface_view(interface: Any) -> dict[str, Any]:
    return {
        "name": interface.name,
        "type": interface.type,
        "enabled": interface.enabled,
        "mode": interface.mode,
        "untagged_vlan": interface.untagged_vlan,
        "tagged_vlans": interface.tagged_vlans,
        "mac": interface.mac,
        "description": interface.description,
        "addresses": interface.addresses,
        "role": interface.role,
        # `enabled` is the admin state NetBox stores; `link_up` is what the device
        # currently sees on the wire, so a cable pull is not read as a shutdown.
        "link_up": interface.link_up,
    }


def _vm_view(vm: Any) -> dict[str, Any]:
    return {
        "name": vm.name,
        "cluster": vm.cluster,
        "host": vm.host,
        "status": vm.status,
        "vcpus": vm.vcpus,
        "memory_mb": vm.memory_mb,
        "disk_gb": vm.disk_gb,
        "guest_os": vm.guest_os,
        "interfaces": [
            {
                "name": nic.name,
                "mac": nic.mac,
                "portgroup": nic.portgroup,
                "vlan": nic.vlan,
                "addresses": nic.addresses,
            }
            for nic in vm.interfaces
        ],
    }


def _device_summary(estate: Estate, device: Any) -> dict[str, Any]:
    return {
        "name": device.name,
        "kind": device.kind.value,
        "role": device.role,
        "manufacturer": device.manufacturer,
        "model": device.model,
        "serial": device.serial,
        "os_version": device.os_version,
        "primary_ip": device.primary_ip,
        "tags": device.tags,
        "interface_count": len(device.interfaces),
        "vm_count": sum(1 for vm in estate.virtual_machines if vm.cluster == device.name),
        "last_seen": next(
            (at for key, at in estate.sources.items() if key.startswith(f"{device.name}/")), None
        ),
    }


def _ilo_note(ilo: str, host: str) -> str:
    return (
        f"{ilo} is the iLO of {host}: its serial, model and out-of-band address are folded "
        f"into that host, which is the device NetBox holds"
    )


def _folded_ilo(estate: Estate, ilo: str, host_name: str) -> dict[str, Any]:
    """An onboarded iLO still has to be findable after being folded into its host."""
    host = estate.device(host_name)
    interface = host.interface("iLO") if host else None
    return {
        "name": ilo,
        "kind": "ilo",
        "role": "management",
        "manufacturer": host.manufacturer if host else "Unknown",
        "model": host.model if host else "Unknown",
        "serial": host.serial if host else None,
        "os_version": None,
        "primary_ip": bare_ip(interface.addresses[0])
        if interface and interface.addresses
        else None,
        "tags": [],
        "interface_count": 1 if interface else 0,
        "vm_count": 0,
        "last_seen": next(
            (at for key, at in estate.sources.items() if key.startswith(f"{ilo}/")), None
        ),
        "folded_into": host_name,
        "note": _ilo_note(ilo, host_name),
    }


@tool("inventory")
def list_devices(kind: str | None = None) -> dict[str, Any]:
    """List onboarded devices, optionally filtered by kind (fortigate, cisco_ios, esxi, ilo)."""
    estate = _estate()
    devices = [
        _device_summary(estate, d)
        for d in estate.devices
        if kind is None or d.kind.value == kind or d.kind.platform == kind
    ]
    if kind in (None, "ilo"):
        devices.extend(
            _folded_ilo(estate, ilo, host) for ilo, host in sorted(estate.ilo_links.items())
        )
    return {
        "site": estate.site,
        "count": len(devices),
        "devices": sorted(devices, key=lambda d: d["name"]),
        "warnings": estate.warnings,
    }


@tool("inventory")
def get_device(name: str) -> dict[str, Any]:
    """Everything known about one device: model, serial, interfaces, VLANs, VMs and its drift."""
    estate = _estate()
    device = estate.device(name)
    resolved_from: str | None = None
    if device is None and name in estate.ilo_links:
        # An onboarded iLO answers as its ESXi host, and says so.
        resolved_from, name = name, estate.ilo_links[name]
        device = estate.device(name)
    if device is None:
        return {
            "name": name,
            "found": False,
            "known_devices": sorted(
                [d.name for d in estate.devices] + list(estate.ilo_links),
            ),
        }
    vlans = sorted(
        {i.untagged_vlan for i in device.interfaces if i.untagged_vlan}
        | {v for i in device.interfaces for v in i.tagged_vlans}
    )
    view = _device_summary(estate, device)
    view.update(
        {
            "found": True,
            "site": device.site,
            "vlans": vlans,
            "interfaces": [_interface_view(i) for i in device.interfaces],
            "virtual_machines": [
                vm.name for vm in estate.virtual_machines if vm.cluster == device.name
            ],
            "snapshots": {
                key.split("/", 1)[1]: at
                for key, at in estate.sources.items()
                if key.startswith(f"{name}/")
            },
            "netbox": _netbox_device(name),
        }
    )
    if resolved_from is not None:
        view["resolved_from"] = resolved_from
        view["note"] = _ilo_note(resolved_from, name)
    return view


def _netbox_device(name: str) -> dict[str, Any] | None:
    rows = _netbox_rows("dcim.devices", name=name)
    if not rows:
        return None
    row = rows[0]
    return {"id": row.get("id"), "serial": row.get("serial"), "status": row.get("status")}


@tool("inventory")
def find_vm(query: str) -> dict[str, Any]:
    """Find VMs by name, guest OS, cluster, MAC or IP. Substring match, case-insensitive."""
    estate = _estate()
    needle = (query or "").strip().lower()
    mac = normalize_mac(query)
    ip = bare_ip(query)
    matches: list[dict[str, Any]] = []
    for vm in estate.virtual_machines:
        reasons: list[str] = []
        if needle and needle in vm.name.lower():
            reasons.append("name")
        if needle and vm.guest_os and needle in vm.guest_os.lower():
            reasons.append("guest_os")
        if needle and needle in vm.cluster.lower():
            reasons.append("cluster")
        for nic in vm.interfaces:
            if mac and nic.mac == mac:
                reasons.append(f"mac {nic.name}")
            if ip and any(bare_ip(a) == ip for a in nic.addresses):
                reasons.append(f"ip {nic.name}")
        if reasons:
            view = _vm_view(vm)
            view["matched_on"] = sorted(set(reasons))
            matches.append(view)
    return {
        "query": query,
        "count": len(matches),
        "vms": matches[:MAX_MATCHES],
        "truncated": len(matches) > MAX_MATCHES,
    }


@tool("inventory")
def list_vlans() -> dict[str, Any]:
    """Every VLAN observed on the estate with the devices, ports and prefixes that use it."""
    estate = _estate()
    vlans = []
    for vlan in estate.vlans:
        prefixes = [p.prefix for p in estate.prefixes if p.vlan == vlan.vid]
        vm_count = sum(
            1 for vm in estate.virtual_machines for nic in vm.interfaces if nic.vlan == vlan.vid
        )
        vlans.append(
            {
                "vid": vlan.vid,
                "name": vlan.name,
                "status": vlan.status,
                "devices": vlan.devices,
                "members": vlan.members,
                "member_count": len(vlan.members),
                "prefixes": prefixes,
                "vm_count": vm_count,
            }
        )
    return {"site": estate.site, "count": len(vlans), "vlans": vlans}


@tool("inventory")
def where_is_mac(mac: str) -> dict[str, Any]:
    """Locate a MAC: switch port from the Cisco MAC table, FortiGate ARP/DHCP, ESXi vNICs."""
    estate = _estate()
    wanted = normalize_mac(mac)
    if wanted is None:
        return {"mac": mac, "found": False, "error": "not a MAC address"}

    switch_ports = [
        {
            "device": e.device,
            "port": e.port,
            "vlan": e.vlan,
            "kind": e.kind,
            "source": e.source,
        }
        for e in estate.mac_entries
        if e.mac == wanted
    ]
    device_interfaces = [
        {"device": d.name, "interface": i.name, "addresses": i.addresses}
        for d in estate.devices
        for i in d.interfaces
        if i.mac == wanted
    ]
    vm_interfaces = [
        {
            "vm": vm.name,
            "cluster": vm.cluster,
            "interface": nic.name,
            "portgroup": nic.portgroup,
            "vlan": nic.vlan,
            "addresses": nic.addresses,
        }
        for vm in estate.virtual_machines
        for nic in vm.interfaces
        if nic.mac == wanted
    ]
    addresses = [
        {
            "address": ip.address,
            "device": ip.device,
            "virtual_machine": ip.virtual_machine,
            "interface": ip.interface,
            "hostname": ip.hostname,
            "source": ip.source,
        }
        for ip in estate.ip_addresses
        if ip.mac == wanted
    ]
    # NetBox 4.2+ keeps MACs as their own objects; both interface endpoints still
    # filter on `mac_address` through the related MAC.
    netbox = [
        {"id": row.get("id"), "name": row.get("name"), "device": row.get("device")}
        for row in _netbox_rows("dcim.interfaces", mac_address=wanted)
    ] + [
        {
            "id": row.get("id"),
            "name": row.get("name"),
            "virtual_machine": row.get("virtual_machine"),
        }
        for row in _netbox_rows("virtualization.interfaces", mac_address=wanted)
    ]

    parts: list[str] = []
    for entry in switch_ports:
        if entry["source"] == "cisco-mac-table":
            vlan = f" VLAN {entry['vlan']}" if entry["vlan"] else ""
            parts.append(f"learned on {entry['device']} {entry['port']}{vlan}")
        else:
            parts.append(f"seen by {entry['device']} on {entry['port']} ({entry['kind']})")
    for entry in vm_interfaces:
        parts.append(f"belongs to VM {entry['vm']} ({entry['interface']}) on {entry['cluster']}")
    for entry in device_interfaces:
        parts.append(f"is {entry['device']} interface {entry['interface']}")
    for entry in addresses:
        parts.append(f"holds {entry['address']} via {entry['source']}")

    return {
        "mac": wanted,
        "found": bool(switch_ports or device_interfaces or vm_interfaces or addresses or netbox),
        "switch_ports": switch_ports,
        "device_interfaces": device_interfaces,
        "vm_interfaces": vm_interfaces,
        "ip_addresses": addresses,
        "netbox_interfaces": netbox,
        "summary": f"{wanted} " + "; ".join(parts) if parts else f"{wanted} is not known here",
    }


@tool("inventory")
def where_is_ip(ip: str) -> dict[str, Any]:
    """Locate an IP: FortiGate ARP/DHCP, Cisco ARP, device interfaces, ESXi vNICs, and its port."""
    estate = _estate()
    wanted = bare_ip(ip)
    if wanted is None:
        return {"ip": ip, "found": False, "error": "not an IP address"}

    bindings = [
        {
            "address": entry.address,
            "device": entry.device,
            "virtual_machine": entry.virtual_machine,
            "interface": entry.interface,
            "mac": entry.mac,
            "hostname": entry.hostname,
            "source": entry.source,
        }
        for entry in estate.ip_addresses
        if entry.ip == wanted
    ]
    macs = sorted({b["mac"] for b in bindings if b["mac"]})
    switch_ports = [
        {"device": e.device, "port": e.port, "vlan": e.vlan, "source": e.source}
        for e in estate.mac_entries
        if e.mac in macs
    ]
    vms = [
        {"vm": vm.name, "cluster": vm.cluster, "interface": nic.name, "vlan": nic.vlan}
        for vm in estate.virtual_machines
        for nic in vm.interfaces
        if (nic.mac and nic.mac in macs) or any(bare_ip(a) == wanted for a in nic.addresses)
    ]
    prefix = next(
        (
            {"prefix": p.prefix, "vlan": p.vlan, "description": p.description}
            for p in estate.prefixes
            if _in_prefix(wanted, p.prefix)
        ),
        None,
    )
    netbox = [
        {"id": row.get("id"), "address": row.get("address"), "dns_name": row.get("dns_name")}
        for row in _netbox_rows("ipam.ip_addresses", address=wanted)
    ]

    parts: list[str] = []
    for binding in bindings:
        owner = binding["device"] or binding["virtual_machine"] or "unknown"
        where = f" {binding['interface']}" if binding["interface"] else ""
        parts.append(f"{binding['source']}: {owner}{where}")
    for entry in switch_ports:
        if entry["source"] == "cisco-mac-table":
            parts.append(f"reachable through {entry['device']} {entry['port']}")
    for vm in vms:
        parts.append(f"is VM {vm['vm']} on {vm['cluster']}")

    return {
        "ip": wanted,
        "found": bool(bindings or vms or netbox),
        "bindings": bindings,
        "macs": macs,
        "switch_ports": switch_ports,
        "virtual_machines": vms,
        "prefix": prefix,
        "netbox_ip_addresses": netbox,
        "summary": f"{wanted} " + "; ".join(parts) if parts else f"{wanted} is not known here",
    }


def _in_prefix(address: str, prefix: str) -> bool:
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(prefix)
    except ValueError:
        return False


@tool("inventory")
def drift_report(device: str | None = None) -> dict[str, Any]:
    """Structured drift between observed state and NetBox (or the accepted baseline)."""
    try:
        return service.drift_report(device=device).llm_view()
    except Exception as error:  # noqa: BLE001 - a read tool must always return
        # `service.intended_estate` already degrades to the baseline when NetBox is
        # down; this is the backstop that keeps any other failure from escaping as
        # an exception mid-triage.
        return {
            "source": "none",
            "devices": [device] if device else [],
            "headline": "drift could not be computed",
            "counts": {},
            "by_device": {},
            "warnings": [f"drift report failed ({type(error).__name__}: {str(error)[:160]})"],
        }


@tool("inventory")
def find_port(name: str) -> dict[str, Any]:
    """Look up one switch or firewall port by `device:interface` or `device Gi1/0/5`."""
    estate = _estate()
    raw = (name or "").replace(":", " ").split()
    if len(raw) != 2:
        return {"query": name, "found": False, "error": "use 'device:interface'"}
    device_name, interface_name = raw
    device = estate.device(device_name)
    interface = device.interface(interface_name) if device else None
    if device is None or interface is None:
        return {"query": name, "found": False}
    canonical = normalize_ifname(interface.name)
    learned = [
        {"mac": e.mac, "vlan": e.vlan, "kind": e.kind}
        for e in estate.mac_entries
        if e.device == device.name and normalize_ifname(e.port) == canonical
    ]
    return {
        "query": name,
        "found": True,
        "device": device.name,
        "interface": _interface_view(interface),
        "learned_macs": learned,
        "sensitive": interface.is_sensitive(),
    }
