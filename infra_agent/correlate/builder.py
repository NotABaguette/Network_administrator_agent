"""Builds the estate topology graph from the latest collector snapshots.

The builder reads the newest snapshot per device from `FileSnapshotStore` (and,
for MAC tables, a short history so aged-out entries survive with a decaying
confidence) and derives:

* **L1** from Cisco CDP/LLDP, FortiGate LLDP and ESXi pNIC CDP/LLDP.
* **L2** from VM vNIC MAC -> switch MAC table -> port -> VLANs allowed on the
  trunks -> portgroup VLAN -> FortiGate VLAN interface.
* **L3** from guest IPs, FortiGate ARP and DHCP leases, interface prefixes and
  the firewall policies that reference those addresses.
* **Storage** from VM -> VMDK -> datastore -> iLO logical drive -> physical
  drives.
* **The platform's own path**: every object between the management VM and the
  firewall is marked `mgmt_path=True`, which escalates any change touching it
  to Tier 2 (see `docs/risk-tiers.md`).

Only parsed snapshot rows are read; raw configurations live in the config git
store and never enter the graph.

Snapshot shapes consumed (all sections optional, all key names tolerant):

* `cisco`: `version`, `interfaces_status`, `interfaces`, `ip_int_brief`,
  `vlans`, `trunks`, `cdp`, `lldp`, `mac_table`, `arp`, `etherchannel`.
* `fortigate`: `system`, `interfaces`, `zones`, `addresses`, `addrgrps`,
  `policies`, `arp`, `dhcp_leases`, `lldp`, `sdwan`, `static_routes`.
* `esxi`: `host`, `pnics`, `vswitches`, `portgroups`, `vmknics`, `datastores`,
  `vms` (with `vnics` and `disks`).
* `ilo`: `system`, `logical_drives`, `physical_drives`.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import networkx as nx

from infra_agent.config import Settings, get_settings
from infra_agent.correlate.model import (
    EdgeKind,
    Evidence,
    NodeKind,
    TopologyGraph,
    datastore_id,
    device_id,
    fw_policy_id,
    interface_id,
    ip_id,
    iso,
    logical_drive_id,
    physical_drive_id,
    portgroup_id,
    prefix_id,
    vlan_id,
    vm_id,
    vnic_id,
    vswitch_id,
    wan_link_id,
)
from infra_agent.correlate.parsing import (
    as_list,
    compact_vlan_list,
    datastore_from_vmdk,
    expand_vlan_list,
    first,
    ip_in_prefix,
    is_ip,
    naa_key,
    normalize_ifname,
    normalize_mac,
    parse_ip_mask,
    parse_prefix,
    rows,
    short_hostname,
)
from infra_agent.models.common import DeviceKind, SeedDevice, SeedInventory, Snapshot
from infra_agent.store.snapshots import FileSnapshotStore

log = logging.getLogger(__name__)

MAC_HALF_LIFE_HOURS = 4.0
MIN_MAC_CONFIDENCE = 0.1
FRESH_MAC_CONFIDENCE = 0.95
L1_ONE_SIDED_CONFIDENCE = 0.9
L1_CONFIRMED_CONFIDENCE = 0.99

DEVICE_ROLES: dict[DeviceKind, str] = {
    DeviceKind.fortigate: "firewall",
    DeviceKind.cisco_ios: "switch",
    DeviceKind.cisco_iosxe: "switch",
    DeviceKind.esxi: "host",
    DeviceKind.ilo: "bmc",
}


@dataclass
class _L1Observation:
    local: str
    observer: str
    collector: str
    observed_at: str
    protocol: str
    neighbor_name: str
    neighbor_port: str
    neighbor_mgmt_ip: str | None = None
    neighbor_platform: str | None = None


@dataclass
class _MacObservation:
    mac: str
    interface: str
    vlan: int | None
    observer: str
    collector: str
    observed_at: str
    confidence: float
    stale: bool


@dataclass
class _BuildState:
    aliases: dict[str, str] = field(default_factory=dict)
    l1: list[_L1Observation] = field(default_factory=list)
    macs: list[_MacObservation] = field(default_factory=list)
    mac_owner: dict[str, str] = field(default_factory=dict)
    ip_by_mac: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    prefixes: set[str] = field(default_factory=set)
    fw_addresses: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    fw_addrgrps: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    fw_zones: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    datastore_volumes: list[tuple[str, str]] = field(default_factory=list)
    logical_volumes: dict[str, str] = field(default_factory=dict)
    pending_ips: list[tuple[str, str, Evidence]] = field(default_factory=list)


class GraphBuilder:
    """Turns collector snapshots into a `TopologyGraph`."""

    def __init__(
        self,
        store: FileSnapshotStore,
        inventory: SeedInventory,
        *,
        settings: Settings | None = None,
        now: datetime | None = None,
        history: int = 12,
        mac_half_life_hours: float = MAC_HALF_LIFE_HOURS,
    ) -> None:
        self.store = store
        self.inventory = inventory
        self.settings = settings or get_settings()
        self.now = now or datetime.now(UTC)
        self.history = history
        self.mac_half_life_hours = mac_half_life_hours
        self.graph = TopologyGraph(built_at=self.now)
        self.state = _BuildState()

    # -- entry point --------------------------------------------------------
    def build(self) -> TopologyGraph:
        for device in self.inventory.devices:
            self._add_seed_device(device)
        for device in self.inventory.devices:
            snapshot = self.store.latest(device.name, device.kind.platform)
            if snapshot is None:
                log.info("no %s snapshot for %s yet", device.kind.platform, device.name)
                continue
            handler = {
                "cisco": self._ingest_cisco,
                "fortigate": self._ingest_fortigate,
                "esxi": self._ingest_esxi,
                "ilo": self._ingest_ilo,
            }.get(device.kind.platform)
            if handler is None:
                continue
            try:
                handler(device, snapshot)
            except Exception:  # a bad snapshot must not lose the whole graph
                log.exception(
                    "failed to ingest %s snapshot for %s", device.kind.platform, device.name
                )
        self._resolve_l1()
        self._resolve_l2()
        self._resolve_l3()
        self._resolve_storage()
        self.mark_mgmt_path()
        self.graph.g.graph["built_at"] = iso(self.now)
        return self.graph

    # -- helpers ------------------------------------------------------------
    def _evidence(
        self,
        collector: str,
        device: str,
        snapshot: Snapshot | None = None,
        confidence: float = 1.0,
        note: str | None = None,
        stale: bool = False,
    ) -> Evidence:
        observed = iso(snapshot.taken_at) if snapshot is not None else iso(self.now)
        return Evidence(
            collector=collector,
            device=device,
            observed_at=observed,
            confidence=confidence,
            note=note,
            stale=stale,
        )

    def _alias(self, alias: str | None, device: str) -> None:
        if alias:
            self.state.aliases.setdefault(str(alias).strip().lower(), device)

    def _add_seed_device(self, device: SeedDevice) -> str:
        node = self.graph.add_node(
            device_id(device.name),
            NodeKind.device,
            label=device.name,
            device_kind=device.kind.value,
            platform=device.kind.platform,
            role=DEVICE_ROLES.get(device.kind, "unknown"),
            mgmt_ip=device.mgmt_ip,
            tags=list(device.tags),
            discovered=False,
        )
        self._alias(device.name, device.name)
        self._alias(short_hostname(device.name), device.name)
        self._alias(device.mgmt_ip, device.name)
        return node

    def _discovered_device(self, name: str, platform_hint: str | None = None) -> str:
        node = device_id(name)
        if node not in self.graph:
            self.graph.add_node(
                node,
                NodeKind.device,
                label=name,
                device_kind="unknown",
                platform=platform_hint or "unknown",
                role=_role_from_platform(platform_hint),
                discovered=True,
                tags=[],
            )
            self._alias(name, name)
        return node

    def _interface(
        self,
        device: str,
        name: str,
        evidence: Evidence,
        **attrs: Any,
    ) -> str:
        ifname = normalize_ifname(name)
        node = interface_id(device, ifname)
        self.graph.add_node(
            node, NodeKind.interface, label=f"{device} {ifname}", device=device, **attrs
        )
        parent = device_id(device)
        if parent in self.graph:
            self.graph.add_edge(parent, node, EdgeKind.has_interface, evidence)
        return node

    def _vlan(self, vlan: int, evidence: Evidence, name: str | None = None) -> str:
        node = vlan_id(vlan)
        existing = self.graph.g.nodes.get(node)
        if name is None and existing is not None:
            name = existing.get("name")  # a later sighting must not drop the name
        label = f"VLAN {vlan}" + (f" ({name})" if name else "")
        self.graph.add_node(node, NodeKind.vlan, label=label, vlan_id=int(vlan), name=name)
        return node

    def _prefix(self, prefix: str) -> str:
        node = prefix_id(prefix)
        self.graph.add_node(node, NodeKind.prefix, label=prefix, prefix=prefix)
        self.state.prefixes.add(prefix)
        return node

    def _ip(self, address: str, **attrs: Any) -> str:
        node = ip_id(address)
        self.graph.add_node(node, NodeKind.ip, label=address, address=address, **attrs)
        return node

    # -- cisco --------------------------------------------------------------
    def _ingest_cisco(self, device: SeedDevice, snapshot: Snapshot) -> None:
        name = device.name
        data = snapshot.data
        ev = self._evidence("cisco", name, snapshot)
        for row in rows(data.get("version")):
            self._alias(short_hostname(first(row, "hostname", "host")), name)
            self.graph.add_node(
                device_id(name),
                NodeKind.device,
                os_version=first(row, "version"),
                model=first(row, "hardware", "platform"),
            )

        known_vlans: set[int] = set()
        for row in rows(data.get("vlans")):
            raw_id = first(row, "vlan_id", "vlan", "id")
            try:
                number = int(str(raw_id))
            except (TypeError, ValueError):
                continue
            known_vlans.add(number)
            vlan_node = self._vlan(number, ev, name=first(row, "vlan_name", "name"))
            for member in as_list(first(row, "interfaces", "ports", default=[])):
                if not str(member).strip():
                    continue
                iface = self._interface(name, str(member), ev, mode="access", access_vlan=number)
                self.graph.add_edge(iface, vlan_node, EdgeKind.access_vlan, ev)

        for row in rows(data.get("interfaces_status")):
            port = first(row, "port", "interface", "name")
            if not port:
                continue
            vlan_field = str(first(row, "vlan", default="") or "").strip().lower()
            mode = (
                "trunk"
                if vlan_field == "trunk"
                else ("routed" if vlan_field == "routed" else "access")
            )
            access_vlan = int(vlan_field) if vlan_field.isdigit() else None
            iface = self._interface(
                name,
                str(port),
                ev,
                description=first(row, "name", "description"),
                status=first(row, "status", "link_status"),
                mode=mode,
                access_vlan=access_vlan,
                speed=first(row, "speed"),
                duplex=first(row, "duplex"),
                media=first(row, "type", "media"),
            )
            if access_vlan is not None and access_vlan in known_vlans:
                self.graph.add_edge(iface, self._vlan(access_vlan, ev), EdgeKind.access_vlan, ev)

        for row in rows(data.get("trunks")):
            port = first(row, "port", "interface", "name")
            if not port:
                continue
            allowed = expand_vlan_list(
                first(row, "vlans_allowed", "vlans_allowed_on_trunk", "allowed_vlans")
            )
            active = expand_vlan_list(
                first(row, "vlans_allowed_active", "vlans_active", default=[])
            ) or (allowed & known_vlans)
            native = first(row, "native_vlan", "native")
            iface = self._interface(
                name,
                str(port),
                ev,
                mode="trunk",
                allowed_vlans=compact_vlan_list(allowed),
                active_vlans=compact_vlan_list(active),
                native_vlan=int(native) if str(native).isdigit() else None,
                trunk_status=first(row, "status"),
            )
            for vlan in sorted(active & (known_vlans or active)):
                self.graph.add_edge(iface, self._vlan(vlan, ev), EdgeKind.trunk_vlan, ev)

        self._ingest_cisco_l3(name, data, ev)
        self._ingest_cisco_portchannels(name, data, ev)
        self._ingest_cisco_discovery(name, data, ev, snapshot)
        self._ingest_cisco_macs(device)

        for row in rows(data.get("arp")):
            mac = normalize_mac(first(row, "mac", "mac_address", "hardware_addr"))
            address = first(row, "address", "ip", "ip_address")
            if mac and address and is_ip(address):
                self.state.ip_by_mac[mac].add(str(address))

    def _ingest_cisco_l3(self, name: str, data: dict[str, Any], ev: Evidence) -> None:
        addresses: dict[str, str] = {}
        for row in rows(data.get("interfaces")) + rows(data.get("ip_int_brief")):
            ifname = normalize_ifname(str(first(row, "interface", "port", "name") or ""))
            value = first(row, "ip_address", "ipaddr", "ip")
            if ifname and value and str(value).lower() not in ("unassigned", "none"):
                addresses.setdefault(ifname, str(value))
        for ifname, value in addresses.items():
            parsed = parse_ip_mask(value)
            iface = self._interface(name, ifname, ev, layer3=True)
            if parsed is None:
                continue
            address, network = parsed
            ip_node = self._ip(address, owner_device=name)
            self.graph.add_edge(iface, ip_node, EdgeKind.has_ip, ev)
            self.state.pending_ips.append((address, iface, ev))
            if not network.endswith("/32"):
                prefix_node = self._prefix(network)
                self.graph.add_edge(iface, prefix_node, EdgeKind.gateway_for, ev)
            if ifname.lower().startswith("vlan") and ifname[4:].isdigit():
                vlan = int(ifname[4:])
                self.graph.add_edge(iface, self._vlan(vlan, ev), EdgeKind.svi_for, ev)
                self.graph.add_node(iface, NodeKind.interface, svi=True, vlan=vlan)

    def _ingest_cisco_portchannels(self, name: str, data: dict[str, Any], ev: Evidence) -> None:
        for row in rows(data.get("etherchannel")):
            group = first(row, "bundle_name", "port_channel", "group", "po_name")
            members = [
                str(m) for m in as_list(first(row, "member_interface", "interfaces", default=[]))
            ]
            if not group:
                continue
            po = self._interface(name, str(group), ev, mode="trunk", portchannel=True)
            for member in members:
                if not member.strip():
                    continue
                self._interface(name, member, ev, portchannel_member=normalize_ifname(str(group)))
            self.graph.add_node(
                po,
                NodeKind.interface,
                members=[normalize_ifname(m) for m in members if m.strip()],
            )

    def _ingest_cisco_discovery(
        self, name: str, data: dict[str, Any], ev: Evidence, snapshot: Snapshot
    ) -> None:
        for protocol, section in (("cdp", "cdp"), ("lldp", "lldp")):
            for row in rows(data.get(section)):
                local = first(row, "local_port", "local_interface", "local_port_id", "interface")
                neighbor = first(
                    row, "destination_host", "neighbor", "system_name", "neighbor_name", "device_id"
                )
                port = first(
                    row,
                    "remote_port",
                    "neighbor_interface",
                    "neighbor_port_id",
                    "port_id",
                    "remote_interface",
                )
                if not (local and neighbor):
                    continue
                self._interface(name, str(local), ev)
                self.state.l1.append(
                    _L1Observation(
                        local=interface_id(name, normalize_ifname(str(local))),
                        observer=name,
                        collector="cisco",
                        observed_at=iso(snapshot.taken_at),
                        protocol=protocol,
                        neighbor_name=short_hostname(str(neighbor)),
                        neighbor_port=normalize_ifname(str(port or "")),
                        neighbor_mgmt_ip=first(
                            row, "management_ip", "mgmt_ip", "management_address"
                        ),
                        neighbor_platform=first(
                            row, "platform", "system_description", "capabilities"
                        ),
                    )
                )

    def _ingest_cisco_macs(self, device: SeedDevice) -> None:
        """Newest sighting per MAC across the snapshot history; older sightings
        survive with a confidence that decays with age (MAC aging tolerance)."""
        seen: set[str] = set()
        for index, snapshot in enumerate(self.store.history(device.name, "cisco", self.history)):
            age_hours = max(0.0, (self.now - snapshot.taken_at).total_seconds() / 3600.0)
            fresh = index == 0
            for row in rows(snapshot.data.get("mac_table")):
                mac = normalize_mac(
                    first(row, "destination_address", "mac", "mac_address", "address")
                )
                if not mac or mac in seen:
                    continue
                ports = [
                    str(p)
                    for p in as_list(first(row, "destination_port", "ports", "port", default=[]))
                    if str(p).strip()
                ]
                entry_type = str(first(row, "type", default="") or "").lower()
                if entry_type in ("static", "self") and not ports:
                    continue
                raw_vlan = str(first(row, "vlan", "vlan_id", default="") or "")
                vlan = int(raw_vlan) if raw_vlan.isdigit() else None
                for port in ports:
                    if port.lower() in ("cpu", "drop", "router", "switch"):
                        continue
                    seen.add(mac)
                    self.state.macs.append(
                        _MacObservation(
                            mac=mac,
                            interface=interface_id(device.name, normalize_ifname(port)),
                            vlan=vlan,
                            observer=device.name,
                            collector="cisco",
                            observed_at=iso(snapshot.taken_at),
                            confidence=self._mac_confidence(age_hours, fresh),
                            stale=not fresh,
                        )
                    )

    def _mac_confidence(self, age_hours: float, fresh: bool) -> float:
        """Current MAC-table entries are trusted; a MAC that has aged out keeps
        its last sighting with a confidence that halves every few hours."""
        if fresh:
            return FRESH_MAC_CONFIDENCE
        decayed = FRESH_MAC_CONFIDENCE * (0.5 ** (max(age_hours, 0.0) / self.mac_half_life_hours))
        return round(max(MIN_MAC_CONFIDENCE, decayed), 4)

    # -- fortigate ----------------------------------------------------------
    def _ingest_fortigate(self, device: SeedDevice, snapshot: Snapshot) -> None:
        name = device.name
        data = snapshot.data
        ev = self._evidence("fortigate", name, snapshot)
        system = data.get("system") or {}
        self._alias(short_hostname(system.get("hostname")), name)
        self.graph.add_node(
            device_id(name),
            NodeKind.device,
            os_version=system.get("version"),
            serial=system.get("serial"),
        )

        sdwan_members = {
            str(first(m, "interface", "name", default=""))
            for m in rows((data.get("sdwan") or {}).get("members"))
        }
        zones = {
            str(z.get("name")): [str(i) for i in as_list(z.get("interfaces"))]
            for z in rows(data.get("zones"))
            if z.get("name")
        }
        self.state.fw_zones[name] = zones

        for row in rows(data.get("interfaces")):
            ifname = str(first(row, "name", default="") or "")
            if not ifname:
                continue
            role = str(first(row, "role", default="") or "").lower()
            iface = self._interface(
                name,
                ifname,
                ev,
                fw_type=first(row, "type"),
                role=role or None,
                alias=first(row, "alias"),
                status=first(row, "status"),
                vdom=first(row, "vdom"),
                zone=next((z for z, members in zones.items() if ifname in members), None),
            )
            parent = first(row, "interface", "parent")
            if parent and str(parent) != ifname:
                parent_node = self._interface(name, str(parent), ev)
                self.graph.add_edge(iface, parent_node, EdgeKind.subinterface_of, ev)
                self.graph.add_node(iface, NodeKind.interface, parent=normalize_ifname(str(parent)))
            raw_vlan = first(row, "vlanid", "vlan_id")
            if raw_vlan not in (None, "", 0, "0"):
                try:
                    vlan = int(raw_vlan)
                except (TypeError, ValueError):
                    vlan = None
                if vlan:
                    self.graph.add_edge(iface, self._vlan(vlan, ev), EdgeKind.svi_for, ev)
                    self.graph.add_node(iface, NodeKind.interface, vlan=vlan)
            parsed = parse_ip_mask(first(row, "ip"))
            if parsed:
                address, network = parsed
                ip_node = self._ip(address, owner_device=name)
                self.graph.add_edge(iface, ip_node, EdgeKind.has_ip, ev)
                self.state.pending_ips.append((address, iface, ev))
                if not network.endswith("/32"):
                    self.graph.add_edge(iface, self._prefix(network), EdgeKind.gateway_for, ev)
            mac = normalize_mac(first(row, "macaddr", "mac"))
            if mac:
                self.state.mac_owner.setdefault(mac, iface)
            if role == "wan" or ifname in sdwan_members:
                link = self.graph.add_node(
                    wan_link_id(name, ifname),
                    NodeKind.wan_link,
                    label=f"{name} {ifname}",
                    device=name,
                    interface=ifname,
                    sdwan_member=ifname in sdwan_members,
                    status=first(row, "status"),
                )
                self.graph.add_edge(iface, link, EdgeKind.wan_uplink, ev)
                self.graph.add_node(iface, NodeKind.interface, is_wan=True)

        self.state.fw_addresses[name] = {
            str(a.get("name")): a for a in rows(data.get("addresses")) if a.get("name")
        }
        self.state.fw_addrgrps[name] = {
            str(g.get("name")): [str(m) for m in as_list(g.get("members"))]
            for g in rows(data.get("addrgrps"))
            if g.get("name")
        }

        for row in rows(data.get("arp")) + rows(data.get("dhcp_leases")):
            mac = normalize_mac(first(row, "mac", "mac_address"))
            address = first(row, "ip", "address")
            if mac and address and is_ip(address):
                self.state.ip_by_mac[mac].add(str(address))

        for entry in rows(data.get("lldp")):
            interface = first(entry, "interface", "local_interface", "port")
            neighbors = rows(entry.get("neighbors")) or [entry]
            for neighbor in neighbors:
                neighbor_name = first(
                    neighbor, "system_name", "neighbor", "device_id", "chassis_id", "sys_name"
                )
                port = first(
                    neighbor, "port_id", "neighbor_interface", "port_description", "remote_port"
                )
                if not (interface and neighbor_name):
                    continue
                self._interface(name, str(interface), ev)
                self.state.l1.append(
                    _L1Observation(
                        local=interface_id(name, normalize_ifname(str(interface))),
                        observer=name,
                        collector="fortigate",
                        observed_at=iso(snapshot.taken_at),
                        protocol="lldp",
                        neighbor_name=short_hostname(str(neighbor_name)),
                        neighbor_port=normalize_ifname(str(port or "")),
                        neighbor_mgmt_ip=first(neighbor, "management_ip", "mgmt_ip"),
                        neighbor_platform=first(neighbor, "system_description", "platform"),
                    )
                )

        self._ingest_fortigate_policies(name, data, ev)

    def _ingest_fortigate_policies(self, name: str, data: dict[str, Any], ev: Evidence) -> None:
        for row in rows(data.get("policies")):
            policy_key = first(row, "id", "policyid", "name")
            if policy_key in (None, ""):
                continue
            node = self.graph.add_node(
                fw_policy_id(name, policy_key),
                NodeKind.fw_policy,
                label=str(first(row, "name", default=f"policy {policy_key}")),
                device=name,
                policy_id=policy_key,
                action=first(row, "action"),
                status=first(row, "status"),
                srcintf=[str(i) for i in as_list(row.get("srcintf"))],
                dstintf=[str(i) for i in as_list(row.get("dstintf"))],
                service=[str(s) for s in as_list(row.get("service"))],
            )
            for intf in as_list(row.get("srcintf")) + as_list(row.get("dstintf")):
                for member in self._expand_zone(name, str(intf)):
                    target = interface_id(name, normalize_ifname(member))
                    if target in self.graph:
                        self.graph.add_edge(node, target, EdgeKind.references, ev, via="interface")
            for address in as_list(row.get("srcaddr")) + as_list(row.get("dstaddr")):
                for resolved in self._resolve_address(name, str(address)):
                    self.graph.add_edge(node, resolved, EdgeKind.references, ev, via="address")

    def _expand_zone(self, device: str, name: str) -> list[str]:
        if name.lower() in ("any", "all"):
            return []
        members = self.state.fw_zones.get(device, {}).get(name)
        return members if members else [name]

    def _resolve_address(self, device: str, name: str, depth: int = 0) -> list[str]:
        """Firewall address / group name -> prefix and ip nodes it covers."""
        if depth > 4 or name.lower() in ("all", "any", "none"):
            return []
        group = self.state.fw_addrgrps.get(device, {}).get(name)
        if group:
            resolved: list[str] = []
            for member in group:
                resolved.extend(self._resolve_address(device, member, depth + 1))
            return resolved
        address = self.state.fw_addresses.get(device, {}).get(name)
        if not address:
            return []
        subnet = parse_prefix(address.get("subnet"))
        if subnet:
            if subnet.endswith("/32"):
                return [self._ip(subnet.split("/")[0])]
            return [self._prefix(subnet)]
        start = address.get("start_ip")
        if start and is_ip(start):
            return [self._ip(str(start))]
        return []

    # -- esxi ---------------------------------------------------------------
    def _ingest_esxi(self, device: SeedDevice, snapshot: Snapshot) -> None:
        name = device.name
        data = snapshot.data
        ev = self._evidence("esxi", name, snapshot)
        host = data.get("host") or {}
        self._alias(short_hostname(host.get("name")), name)
        self.graph.add_node(
            device_id(name),
            NodeKind.device,
            os_version=host.get("version"),
            build=host.get("build"),
            license=host.get("license") or device.license,
            model=host.get("model"),
        )

        for row in rows(data.get("pnics")):
            ifname = str(first(row, "name", "device", default="") or "")
            if not ifname:
                continue
            iface = self._interface(
                name,
                ifname,
                ev,
                mac=normalize_mac(first(row, "mac", "mac_address")),
                link_up=first(row, "link_up", "link"),
                speed=first(row, "speed_mb", "speed"),
                pnic=True,
            )
            mac = normalize_mac(first(row, "mac", "mac_address"))
            if mac:
                self.state.mac_owner.setdefault(mac, iface)
            for protocol in ("cdp", "lldp"):
                info = row.get(protocol)
                if not isinstance(info, dict):
                    continue
                neighbor = first(info, "device_id", "system_name", "neighbor", "chassis_id")
                port = first(info, "port_id", "port", "neighbor_interface", "port_description")
                if not neighbor:
                    continue
                self.state.l1.append(
                    _L1Observation(
                        local=iface,
                        observer=name,
                        collector="esxi",
                        observed_at=iso(snapshot.taken_at),
                        protocol=protocol,
                        neighbor_name=short_hostname(str(neighbor)),
                        neighbor_port=normalize_ifname(str(port or "")),
                        neighbor_mgmt_ip=first(info, "management_ip", "address", "mgmt_ip"),
                        neighbor_platform=first(info, "platform", "system_description"),
                    )
                )

        for row in rows(data.get("vswitches")):
            vsname = str(first(row, "name", default="") or "")
            if not vsname:
                continue
            node = self.graph.add_node(
                vswitch_id(name, vsname),
                NodeKind.vswitch,
                label=f"{name} {vsname}",
                device=name,
                mtu=first(row, "mtu"),
            )
            for uplink in as_list(first(row, "uplinks", "pnics", default=[])):
                if not str(uplink).strip():
                    continue
                iface = self._interface(name, str(uplink), ev, pnic=True, uplink=True)
                self.graph.add_edge(node, iface, EdgeKind.uplink_of, ev)

        for row in rows(data.get("portgroups")):
            pgname = str(first(row, "name", default="") or "")
            if not pgname:
                continue
            raw_vlan = first(row, "vlan", "vlan_id", "vlanid", default=0)
            try:
                vlan = int(raw_vlan)
            except (TypeError, ValueError):
                vlan = 0
            node = self.graph.add_node(
                portgroup_id(name, pgname),
                NodeKind.portgroup,
                label=f"{name} {pgname}",
                device=name,
                vlan=vlan,
                vswitch=first(row, "vswitch", "switch"),
            )
            vswitch = first(row, "vswitch", "switch")
            if vswitch:
                vs_node = vswitch_id(name, str(vswitch))
                if vs_node not in self.graph:
                    self.graph.add_node(
                        vs_node, NodeKind.vswitch, label=f"{name} {vswitch}", device=name
                    )
                self.graph.add_edge(node, vs_node, EdgeKind.portgroup_on, ev)
            if vlan:
                self.graph.add_edge(node, self._vlan(vlan, ev), EdgeKind.portgroup_vlan, ev)

        for row in rows(data.get("vmknics")):
            ifname = str(first(row, "name", "device", default="") or "")
            if not ifname:
                continue
            iface = self._interface(
                name,
                ifname,
                ev,
                vmkernel=True,
                portgroup=first(row, "portgroup", "portgroup_name"),
                services=[str(s) for s in as_list(row.get("services"))],
            )
            mac = normalize_mac(first(row, "mac", "mac_address"))
            if mac:
                self.state.mac_owner.setdefault(mac, iface)
            address = first(row, "ip", "ip_address")
            if address and is_ip(address):
                ip_node = self._ip(str(address), owner_device=name)
                self.graph.add_edge(iface, ip_node, EdgeKind.has_ip, ev)
                self.state.pending_ips.append((str(address), iface, ev))
                mask = first(row, "netmask", "mask", "prefix")
                network = parse_ip_mask([str(address), str(mask)]) if mask else None
                if network and not network[1].endswith("/32"):
                    self._prefix(network[1])
            portgroup = first(row, "portgroup", "portgroup_name")
            if portgroup:
                pg_node = portgroup_id(name, str(portgroup))
                if pg_node in self.graph:
                    self.graph.add_edge(iface, pg_node, EdgeKind.attached_to, ev)

        self._ingest_esxi_datastores(name, data, ev)
        self._ingest_esxi_vms(name, data, ev)

    def _ingest_esxi_datastores(self, name: str, data: dict[str, Any], ev: Evidence) -> None:
        for row in rows(data.get("datastores")):
            dsname = str(first(row, "name", default="") or "")
            if not dsname:
                continue
            node = self.graph.add_node(
                datastore_id(name, dsname),
                NodeKind.datastore,
                label=f"{name} {dsname}",
                device=name,
                ds_type=first(row, "type"),
                capacity_gb=first(row, "capacity_gb", "capacity"),
                free_gb=first(row, "free_gb", "free"),
                accessible=first(row, "accessible"),
            )
            volumes = {
                naa_key(first(extent, "disk_name", "name", "device", default=""))
                for extent in rows(row.get("extents"))
            }
            for key in ("naa", "device", "disk_name", "volume_id", "logical_drive"):
                if row.get(key):
                    volumes.add(naa_key(row[key]))
            for volume in sorted(v for v in volumes if v):
                self.state.datastore_volumes.append((node, volume))

    def _ingest_esxi_vms(self, name: str, data: dict[str, Any], ev: Evidence) -> None:
        for row in rows(data.get("vms")):
            vmname = str(first(row, "name", default="") or "")
            if not vmname:
                continue
            node = self.graph.add_node(
                vm_id(vmname),
                NodeKind.vm,
                label=vmname,
                host=name,
                power_state=first(row, "power_state", "runtime_power_state"),
                uuid=first(row, "uuid", "instance_uuid"),
                guest_os=first(row, "guest_os", "guest_full_name"),
                tags=[str(t) for t in as_list(row.get("tags"))],
                annotation=first(row, "annotation", "notes"),
            )
            self.graph.add_edge(node, device_id(name), EdgeKind.runs_on, ev)
            guest_ips = [
                str(i) for i in as_list(first(row, "guest_ips", "ip_addresses", default=[]))
            ]
            vnics = rows(row.get("vnics")) or rows(row.get("nics"))
            for index, nic in enumerate(vnics, start=1):
                label = str(first(nic, "label", "name", "key", default=f"nic{index}"))
                mac = normalize_mac(first(nic, "mac", "mac_address"))
                connected = first(nic, "connected", "connect_status", default=True)
                vnic_node = self.graph.add_node(
                    vnic_id(vmname, label),
                    NodeKind.vnic,
                    label=f"{vmname} {label}",
                    vm=vmname,
                    mac=mac or None,
                    connected=bool(connected),
                    portgroup=first(nic, "portgroup", "network", "portgroup_name"),
                )
                self.graph.add_edge(node, vnic_node, EdgeKind.has_vnic, ev)
                if mac:
                    self.state.mac_owner.setdefault(mac, vnic_node)
                portgroup = first(nic, "portgroup", "network", "portgroup_name")
                if portgroup:
                    pg_node = portgroup_id(name, str(portgroup))
                    if pg_node not in self.graph:
                        self.graph.add_node(
                            pg_node,
                            NodeKind.portgroup,
                            label=f"{name} {portgroup}",
                            device=name,
                            vlan=None,
                        )
                    self.graph.add_edge(vnic_node, pg_node, EdgeKind.attached_to, ev)
                for address in as_list(first(nic, "ips", "ip_addresses", default=[])):
                    if is_ip(address):
                        ip_node = self._ip(str(address), owner_vm=vmname)
                        self.graph.add_edge(vnic_node, ip_node, EdgeKind.has_ip, ev)
                        self.state.pending_ips.append((str(address), vnic_node, ev))
                if mac:
                    for address in sorted(self.state.ip_by_mac.get(mac, set())):
                        ip_node = self._ip(address, owner_vm=vmname)
                        self.graph.add_edge(vnic_node, ip_node, EdgeKind.has_ip, ev)
                        self.state.pending_ips.append((address, vnic_node, ev))
            connected_vnics = [
                n
                for n, _d in self.graph.out_edges(node, EdgeKind.has_vnic)
                if self.graph.node(n).get("connected")
            ]
            if len(connected_vnics) == 1:
                for address in guest_ips:
                    if not is_ip(address):
                        continue
                    ip_node = self._ip(str(address), owner_vm=vmname)
                    self.graph.add_edge(connected_vnics[0], ip_node, EdgeKind.has_ip, ev)
                    self.state.pending_ips.append((str(address), connected_vnics[0], ev))
            for disk in rows(row.get("disks")):
                dsname = str(
                    first(disk, "datastore", default="") or datastore_from_vmdk(disk.get("vmdk"))
                )
                if not dsname:
                    continue
                ds_node = datastore_id(name, dsname)
                if ds_node not in self.graph:
                    self.graph.add_node(
                        ds_node, NodeKind.datastore, label=f"{name} {dsname}", device=name
                    )
                self.graph.add_edge(
                    node,
                    ds_node,
                    EdgeKind.stored_on,
                    ev,
                    vmdk=first(disk, "vmdk", "file_name"),
                    size_gb=first(disk, "size_gb", "capacity_gb"),
                )

    # -- ilo ----------------------------------------------------------------
    def _ingest_ilo(self, device: SeedDevice, snapshot: Snapshot) -> None:
        name = device.name
        data = snapshot.data
        ev = self._evidence("ilo", name, snapshot)
        system = data.get("system") or {}
        self.graph.add_node(
            device_id(name),
            NodeKind.device,
            model=system.get("model"),
            serial=system.get("serial"),
            ilo_generation=system.get("ilo_generation"),
        )
        host = self._ilo_host(device, system)
        if host:
            self.graph.add_edge(device_id(name), device_id(host), EdgeKind.manages, ev)
            self.graph.add_node(device_id(name), NodeKind.device, manages_host=host)

        drives_by_logical: dict[str, list[str]] = defaultdict(list)
        for row in rows(data.get("physical_drives")):
            location = str(first(row, "location", "id", "name", default="") or "")
            if not location:
                continue
            node = self.graph.add_node(
                physical_drive_id(name, location),
                NodeKind.physical_drive,
                label=f"{name} disk {location}",
                device=name,
                model=first(row, "model"),
                serial=first(row, "serial", "serial_number"),
                capacity_gb=first(row, "capacity_gb", "capacity"),
                media_type=first(row, "media_type", "media"),
                status=first(row, "status", "health"),
            )
            parent = first(row, "logical_drive", "logical_drive_id", "array")
            if parent:
                drives_by_logical[str(parent)].append(node)

        for row in rows(data.get("logical_drives")):
            ident = str(first(row, "id", "name", "logical_drive", default="") or "")
            if not ident:
                continue
            volume = naa_key(
                first(row, "volume_unique_identifier", "volume_id", "naa", "wwn", default="")
            )
            node = self.graph.add_node(
                logical_drive_id(name, ident),
                NodeKind.logical_drive,
                label=f"{name} LD{ident}",
                device=name,
                raid=first(row, "raid", "raid_level"),
                capacity_gb=first(row, "capacity_gb", "capacity"),
                status=first(row, "status", "health"),
                volume_id=volume or None,
            )
            if volume:
                self.state.logical_volumes[volume] = node
            members = [
                physical_drive_id(name, str(location))
                for location in as_list(
                    first(row, "physical_drives", "drives", "members", default=[])
                )
                if str(location).strip()
            ]
            members += drives_by_logical.get(ident, [])
            for member in dict.fromkeys(members):
                if member not in self.graph:
                    self.graph.add_node(
                        member,
                        NodeKind.physical_drive,
                        label=f"{name} disk {member.rsplit(':', 1)[-1]}",
                        device=name,
                    )
                self.graph.add_edge(node, member, EdgeKind.spans, ev)

    def _ilo_host(self, device: SeedDevice, system: dict[str, Any]) -> str | None:
        for tag in device.tags:
            if tag.startswith("host:"):
                candidate = tag.split(":", 1)[1]
                if device_id(candidate) in self.graph:
                    return candidate
        candidate = short_hostname(system.get("host") or system.get("host_name"))
        if candidate and device_id(candidate) in self.graph:
            return candidate
        lowered = device.name.lower()
        for suffix in ("-ilo", "_ilo", ".ilo", "-oob", "-bmc"):
            if lowered.endswith(suffix):
                stripped = device.name[: -len(suffix)]
                if device_id(stripped) in self.graph:
                    return stripped
        return None

    # -- cross-collector resolution ----------------------------------------
    def _resolve_l1(self) -> None:
        pairs: dict[frozenset[str], list[_L1Observation]] = defaultdict(list)
        for obs in self.state.l1:
            remote_device = self._match_device(obs)
            if remote_device is None:
                continue
            remote = interface_id(remote_device, obs.neighbor_port or "unknown")
            if remote not in self.graph:
                self.graph.add_node(
                    remote,
                    NodeKind.interface,
                    label=f"{remote_device} {obs.neighbor_port or 'unknown'}",
                    device=remote_device,
                    discovered=True,
                )
                if device_id(remote_device) in self.graph:
                    self.graph.add_edge(
                        device_id(remote_device),
                        remote,
                        EdgeKind.has_interface,
                        Evidence(
                            collector=obs.collector,
                            device=obs.observer,
                            observed_at=obs.observed_at,
                            confidence=L1_ONE_SIDED_CONFIDENCE,
                            note=f"learned from {obs.protocol} on {obs.observer}",
                        ),
                    )
            pairs[frozenset({obs.local, remote})].append(obs)

        for pair, observations in pairs.items():
            observers = {o.observer for o in observations}
            protocols = sorted({o.protocol for o in observations})
            confirmed = len(observers) > 1
            confidence = L1_CONFIRMED_CONFIDENCE if confirmed else L1_ONE_SIDED_CONFIDENCE
            newest = max(observations, key=lambda o: o.observed_at)
            note = (
                f"{'/'.join(protocols)} confirmed by {', '.join(sorted(observers))}"
                if confirmed
                else f"{'/'.join(protocols)} seen only by {newest.observer}"
            )
            endpoints = sorted(pair)
            if len(endpoints) != 2:
                continue
            a, b = endpoints
            for source, target in ((a, b), (b, a)):
                self.graph.add_edge(
                    source,
                    target,
                    EdgeKind.l1_neighbor,
                    Evidence(
                        collector=newest.collector,
                        device=newest.observer,
                        observed_at=newest.observed_at,
                        confidence=confidence,
                        note=note,
                    ),
                    protocols=protocols,
                    confirmed_both_sides=confirmed,
                )

    def _match_device(self, obs: _L1Observation) -> str | None:
        alias = self.state.aliases.get(obs.neighbor_name.lower())
        if alias:
            return alias
        if obs.neighbor_mgmt_ip:
            alias = self.state.aliases.get(str(obs.neighbor_mgmt_ip).strip().lower())
            if alias:
                return alias
        if not obs.neighbor_name:
            return None
        return self._discovered_device(obs.neighbor_name, _platform_hint(obs.neighbor_platform))

    def _resolve_l2(self) -> None:
        """vNIC MAC -> switch MAC table -> switch port."""
        for obs in self.state.macs:
            owner = self.state.mac_owner.get(obs.mac)
            if owner is None or obs.interface not in self.graph:
                continue
            if owner == obs.interface:
                continue
            self.graph.add_edge(
                owner,
                obs.interface,
                EdgeKind.mac_seen_on,
                Evidence(
                    collector=obs.collector,
                    device=obs.observer,
                    observed_at=obs.observed_at,
                    confidence=obs.confidence,
                    stale=obs.stale,
                    note="last seen in the MAC table" if obs.stale else "current MAC table entry",
                ),
                mac=obs.mac,
                vlan=obs.vlan,
            )

    def _resolve_l3(self) -> None:
        prefixes = sorted(self.state.prefixes, key=lambda p: (-int(p.split("/")[1]), p))
        for address, owner, evidence in self.state.pending_ips:
            node = ip_id(address)
            if node not in self.graph:
                continue
            if owner in self.graph:
                self.graph.add_edge(owner, node, EdgeKind.has_ip, evidence)
            for prefix in prefixes:
                if ip_in_prefix(address, prefix):
                    self.graph.add_edge(node, self._prefix(prefix), EdgeKind.in_prefix, evidence)
                    break
        # IPs that only the firewall knows about (ARP / DHCP) still get a prefix.
        for node in self.graph.nodes_of_kind(NodeKind.ip):
            known = self.graph.node(node).get("address")
            if not known or any(True for _ in self.graph.out_edges(node, EdgeKind.in_prefix)):
                continue
            for prefix in prefixes:
                if ip_in_prefix(str(known), prefix):
                    self.graph.add_edge(
                        node,
                        self._prefix(prefix),
                        EdgeKind.in_prefix,
                        Evidence(collector="correlate", confidence=0.8, note="prefix containment"),
                    )
                    break

    def _resolve_storage(self) -> None:
        for datastore, volume in self.state.datastore_volumes:
            logical = self.state.logical_volumes.get(volume)
            if logical is None or datastore not in self.graph:
                continue
            self.graph.add_edge(
                datastore,
                logical,
                EdgeKind.backed_by,
                Evidence(
                    collector="correlate",
                    device=self.graph.node(logical).get("device"),
                    observed_at=iso(self.now),
                    confidence=0.95,
                    note=f"volume id {volume} matches the ESXi extent",
                ),
                volume_id=volume,
            )

    # -- the platform's own path -------------------------------------------
    def find_mgmt_vm(self) -> str | None:
        wanted = (self.settings.mgmt_vm_name or "").strip().lower()
        if not wanted:
            return None
        for node in self.graph.nodes_of_kind(NodeKind.vm):
            data = self.graph.node(node)
            tags = {str(t).lower() for t in data.get("tags") or []}
            if str(data.get("label", "")).lower() == wanted or wanted in tags:
                return node
        return None

    def mark_mgmt_path(self) -> list[str]:
        """Mark the platform's own path: mgmt-01, its host, uplinks, the switch
        ports it hangs off, everything between them and the firewall."""
        vm = self.find_mgmt_vm()
        self.graph.g.graph["mgmt_vm"] = vm
        if vm is None:
            return []
        marked: set[str] = {vm}
        uplinks: set[str] = set()
        vlans: set[int] = set()
        for vnic, _e in self.graph.out_edges(vm, EdgeKind.has_vnic):
            marked.add(vnic)
            for ip, _e2 in self.graph.out_edges(vnic, EdgeKind.has_ip):
                marked.add(ip)
            for pg, _e2 in self.graph.out_edges(vnic, EdgeKind.attached_to):
                marked.add(pg)
                pg_vlan = self.graph.node(pg).get("vlan")
                if pg_vlan:
                    vlans.add(int(pg_vlan))
                for vswitch, _e3 in self.graph.out_edges(pg, EdgeKind.portgroup_on):
                    marked.add(vswitch)
                    for uplink, _e4 in self.graph.out_edges(vswitch, EdgeKind.uplink_of):
                        marked.add(uplink)
                        uplinks.add(uplink)
        for host, _e in self.graph.out_edges(vm, EdgeKind.runs_on):
            marked.add(host)
        # The management VLAN itself is deliberately not marked: it is its own
        # escalation (`feeds_ilo_or_mgmt_vlan`), and marking it would put every
        # trunk in the estate on the platform's path. Its gateways are marked.
        for vlan in vlans:
            node = vlan_id(vlan)
            if node in self.graph:
                for iface, _e in self.graph.in_edges(node, EdgeKind.svi_for):
                    marked.add(iface)
                    owner = self.graph.node(iface).get("device")
                    if owner:
                        marked.add(device_id(owner))

        switch_devices: set[str] = set()
        for uplink in uplinks:
            for peer, _e in self.graph.out_edges(uplink, EdgeKind.l1_neighbor):
                marked.add(peer)
                owner = self.graph.node(peer).get("device")
                if owner:
                    switch_devices.add(device_id(owner))
                    marked.add(device_id(owner))

        physical = self._physical_view()
        firewalls = [n for n, d in self.graph.g.nodes(data=True) if d.get("role") == "firewall"]
        starts = switch_devices or {n for n in marked if n.startswith("device:")}
        for firewall in firewalls:
            marked.add(firewall)
            for iface, _e in self.graph.out_edges(firewall, EdgeKind.has_interface):
                for link, _e2 in self.graph.out_edges(iface, EdgeKind.wan_uplink):
                    marked.add(link)
                    marked.add(iface)
            for switch in starts:
                if switch not in physical or firewall not in physical:
                    continue
                try:
                    marked.update(nx.shortest_path(physical, switch, firewall))
                except nx.NetworkXNoPath:
                    continue
        self.graph.mark_mgmt_path(marked)
        self.graph.g.graph["mgmt_vlans"] = sorted(vlans)
        return sorted(marked)

    def _physical_view(self) -> nx.Graph:
        view = nx.Graph()
        for source, target, data in self.graph.edges_of_kind(EdgeKind.has_interface):
            view.add_edge(source, target, kind=data.get("kind"))
        for source, target, data in self.graph.edges_of_kind(EdgeKind.l1_neighbor):
            view.add_edge(source, target, kind=data.get("kind"))
        return view


def _platform_hint(text: str | None) -> str | None:
    if not text:
        return None
    lowered = str(text).lower()
    if "fortigate" in lowered or "fortios" in lowered:
        return "fortigate"
    if "cisco" in lowered or "catalyst" in lowered or "ws-c" in lowered:
        return "cisco"
    if "vmware" in lowered or "esx" in lowered:
        return "esxi"
    return None


def _role_from_platform(platform: str | None) -> str:
    return {
        "fortigate": "firewall",
        "cisco": "switch",
        "esxi": "host",
        "ilo": "bmc",
    }.get(platform or "", "unknown")


def build_graph(
    store: FileSnapshotStore | None = None,
    inventory: SeedInventory | None = None,
    *,
    settings: Settings | None = None,
    now: datetime | None = None,
) -> TopologyGraph:
    """Build the graph from the configured snapshot store and seed inventory."""
    settings = settings or get_settings()
    store = store or FileSnapshotStore(settings.snapshot_dir)
    inventory = inventory if inventory is not None else SeedInventory.load(settings.seed_inventory)
    return GraphBuilder(store, inventory, settings=settings, now=now).build()
