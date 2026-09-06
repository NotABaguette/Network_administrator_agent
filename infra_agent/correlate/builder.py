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
    is_unparsed,
    naa_key,
    normalize_ifname,
    normalize_mac,
    parse_ip_mask,
    parse_prefix,
    parse_trunk_text,
    rows,
    short_hostname,
)
from infra_agent.models.common import DeviceKind, SeedDevice, SeedInventory, Snapshot
from infra_agent.store.snapshots import FileSnapshotStore

log = logging.getLogger(__name__)

MAC_HALF_LIFE_HOURS = 4.0
#: How far back a MAC sighting may be re-used. A *count* of snapshots is not a
#: window: at the Cisco collector's 300 s interval twelve snapshots are one
#: hour, far short of the decay curve, so the window is an age.
MAC_MAX_AGE_HOURS = 24.0
#: Upper bound on snapshots read per switch, so a busy store cannot be walked
#: forever: 24 h at the collector's 300 s interval, plus a little slack.
MAC_HISTORY_LIMIT = 300
MIN_MAC_CONFIDENCE = 0.1
FRESH_MAC_CONFIDENCE = 0.95
L1_ONE_SIDED_CONFIDENCE = 0.9
L1_CONFIRMED_CONFIDENCE = 0.99

#: FortiOS interface types whose member ports are the real cable endpoints.
HARDWARE_SWITCH_TYPES = frozenset({"hard-switch", "switch", "virtual-switch"})

#: Cisco's internal FDDI / token-ring VLANs; never carry anything.
RESERVED_VLANS = frozenset(range(1002, 1006))

#: Spanning-tree roles that make a port matter for loop prevention.
STP_SIGNIFICANT_ROLES = frozenset({"Root", "Altn", "Back", "Bkup"})

#: Cisco snapshot sections the graph is built from; a raw-text (unparsed)
#: section here is reported as a `collector_parse_gap` finding.
CISCO_SECTIONS = (
    "version",
    "vlans",
    "interfaces_status",
    "interfaces",
    "ip_int_brief",
    "trunks",
    "switchport",
    "cdp",
    "lldp",
    "mac_table",
    "arp",
    "stp",
    "etherchannel",
)

DEVICE_ROLES: dict[DeviceKind, str] = {
    DeviceKind.fortigate: "firewall",
    DeviceKind.cisco_ios: "switch",
    DeviceKind.cisco_iosxe: "switch",
    DeviceKind.esxi: "host",
    DeviceKind.ilo: "bmc",
}


@dataclass(frozen=True)
class _TrunkVlans:
    """The VLANs one trunk carries, and where that came from."""

    allowed: set[int]
    active: set[int]
    native: int | None
    source: str
    confidence: float


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
    #: (mac, ip) -> (collector, device, how) for the ARP / DHCP evidence.
    ip_source: dict[tuple[str, str], tuple[str, str, str]] = field(default_factory=dict)
    parse_gaps: list[dict[str, str]] = field(default_factory=list)
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
        mac_max_age_hours: float = MAC_MAX_AGE_HOURS,
        mac_history_limit: int = MAC_HISTORY_LIMIT,
        mac_half_life_hours: float = MAC_HALF_LIFE_HOURS,
    ) -> None:
        self.store = store
        self.inventory = inventory
        self.settings = settings or get_settings()
        self.now = now or datetime.now(UTC)
        self.mac_max_age_hours = mac_max_age_hours
        self.mac_history_limit = mac_history_limit
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
                self._parse_gap(
                    device.name,
                    device.kind.platform,
                    "no snapshot has been collected for this device yet",
                )
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
        self._classify_uplinks()
        self._resolve_l2()
        self._resolve_l3()
        self._resolve_storage()
        self.mark_mgmt_path()
        self.graph.g.graph["built_at"] = iso(self.now)
        self.graph.g.graph["parse_gaps"] = list(self.state.parse_gaps)
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

    def _parse_gap(self, device: str, section: str, reason: str) -> None:
        """A snapshot section the graph needs but could not use.

        Silence here is the dangerous failure: an unparsed switch would present
        as a device with no ports, and the tier engine would see no trunks. The
        gap is logged, kept on the graph and surfaced as a finding.
        """
        gap = {"device": device, "section": section, "reason": reason}
        if gap not in self.state.parse_gaps:
            self.state.parse_gaps.append(gap)
            log.warning("collector parse gap on %s (%s): %s", device, section, reason)

    def _note_cisco_parse_gaps(self, name: str, data: dict[str, Any]) -> None:
        for section in CISCO_SECTIONS:
            if is_unparsed(data.get(section)) and section != "trunks":
                self._parse_gap(
                    name,
                    section,
                    "the collector stored raw text: ntc-templates has no template for this "
                    "command on the platform the collector used",
                )
        if not rows(data.get("interfaces_status")) and not rows(data.get("interfaces")):
            self._parse_gap(name, "interfaces_status", "the snapshot yielded no interfaces")

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
        """A neighbour that is not in the seed inventory. Returns its *name*, so
        callers can build interface ids from it exactly like a seeded device."""
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
        return name

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
        self._note_cisco_parse_gaps(name, data)
        for row in rows(data.get("version")):
            self._alias(short_hostname(first(row, "hostname", "host")), name)
            self.graph.add_node(
                device_id(name),
                NodeKind.device,
                os_version=first(row, "version"),
                model=_scalar(first(row, "hardware", "platform")),
            )

        known_vlans = self._ingest_cisco_vlans(name, data, ev)
        status = _cisco_interface_status(data)
        trunks = self._cisco_trunk_vlans(name, data, known_vlans, status)
        self._ingest_cisco_ports(name, ev, known_vlans, status, trunks)
        self._ingest_cisco_stp(name, data, ev)
        self._ingest_cisco_l3(name, data, ev)
        self._ingest_cisco_portchannels(name, data, ev)
        self._ingest_cisco_discovery(name, data, ev, snapshot)
        self._ingest_cisco_macs(device)

        for row in rows(data.get("arp")):
            mac = normalize_mac(first(row, "mac", "mac_address", "hardware_addr"))
            address = first(row, "address", "ip", "ip_address")
            if mac and address and is_ip(address):
                self.state.ip_by_mac[mac].add(str(address))
                self.state.ip_source.setdefault((mac, str(address)), ("cisco", name, "arp"))

    def _ingest_cisco_vlans(self, name: str, data: dict[str, Any], ev: Evidence) -> set[int]:
        known_vlans: set[int] = set()
        for row in rows(data.get("vlans")):
            number = _int_or_none(first(row, "vlan_id", "vlan", "id"))
            if number is None or number in RESERVED_VLANS:
                continue
            known_vlans.add(number)
            vlan_node = self._vlan(number, ev, name=first(row, "vlan_name", "name"))
            for member in as_list(first(row, "interfaces", "ports", default=[])):
                if not str(member).strip():
                    continue
                iface = self._interface(name, str(member), ev, mode="access", access_vlan=number)
                self.graph.add_edge(iface, vlan_node, EdgeKind.access_vlan, ev)
        return known_vlans

    def _cisco_trunk_vlans(
        self,
        name: str,
        data: dict[str, Any],
        known_vlans: set[int],
        status: dict[str, dict[str, Any]],
    ) -> dict[str, _TrunkVlans]:
        """Which VLANs each trunk carries, from whichever source the box gives us.

        `ntc_templates` has no `show interfaces trunk` template, so on a real
        Catalyst that section arrives as `[]` (IOS) or as raw text (IOS-XE, which
        has no templates at all). Three fallbacks, best evidence first:

        1. `trunks` — parsed rows if a template ever lands, else the raw text;
        2. `switchport` — `show interfaces switchport`, which ntc *does* parse
           (`mode`, `admin_mode`, `trunking_vlans`, `native_vlan`);
        3. `stp` — `show spanning-tree` lists every port in each VLAN instance,
           so the VLANs a trunk forwards fall straight out of it.
        """
        found: dict[str, _TrunkVlans] = {}
        section = data.get("trunks")
        for row in rows(section) or parse_trunk_text(section):
            port = normalize_ifname(str(first(row, "port", "interface", "name", default="") or ""))
            allowed = expand_vlan_list(
                first(row, "vlans_allowed", "vlans_allowed_on_trunk", "allowed_vlans")
            )
            active = expand_vlan_list(
                first(row, "vlans_allowed_active", "vlans_active", "vlans_forwarding", default=[])
            )
            if not port or not (allowed or active):
                continue
            found[port] = _TrunkVlans(
                allowed=allowed or active,
                active=active or (allowed & known_vlans) or allowed,
                native=_int_or_none(first(row, "native_vlan", "native")),
                source="show interfaces trunk",
                confidence=1.0,
            )

        for row in rows(data.get("switchport")):
            port = normalize_ifname(str(first(row, "interface", "port", "name", default="") or ""))
            mode = str(first(row, "mode", "admin_mode", default="") or "").lower()
            allowed = expand_vlan_list(first(row, "trunking_vlans", "vlans_allowed"))
            if not port or port in found or "trunk" not in mode or not allowed:
                continue
            found[port] = _TrunkVlans(
                allowed=allowed,
                active=allowed & known_vlans or allowed,
                native=_int_or_none(first(row, "native_vlan", "native")),
                source="show interfaces switchport",
                confidence=1.0,
            )

        stp_vlans = _cisco_stp_vlans(data)
        for port, vlans in stp_vlans.items():
            is_trunk = status.get(port, {}).get("mode") == "trunk" or len(vlans) > 1
            if port in found or not is_trunk or not vlans:
                continue
            found[port] = _TrunkVlans(
                allowed=vlans,
                active=vlans,
                native=None,
                source="show spanning-tree",
                confidence=0.9,
            )

        for port, entry in status.items():
            if entry.get("mode") == "trunk" and port not in found:
                self._parse_gap(
                    name,
                    "trunks",
                    f"{port} is a trunk but no source lists the VLANs it carries "
                    "(no `show interfaces trunk` template, no `show interfaces switchport` "
                    "and no `show spanning-tree` rows)",
                )
        return found

    def _ingest_cisco_ports(
        self,
        name: str,
        ev: Evidence,
        known_vlans: set[int],
        status: dict[str, dict[str, Any]],
        trunks: dict[str, _TrunkVlans],
    ) -> None:
        for ifname, entry in status.items():
            mode = "trunk" if ifname in trunks else entry["mode"]
            access_vlan = entry["access_vlan"]
            iface = self._interface(
                name,
                ifname,
                ev,
                description=entry["description"],
                status=entry["status"],
                mode=mode,
                access_vlan=access_vlan if mode == "access" else None,
                speed=entry["speed"],
                duplex=entry["duplex"],
                media=entry["media"],
            )
            if mode == "access" and access_vlan is not None:
                self.graph.add_edge(iface, self._vlan(access_vlan, ev), EdgeKind.access_vlan, ev)
        for ifname, info in trunks.items():
            self._apply_trunk(name, ifname, ev, info, known_vlans)

    def _apply_trunk(
        self, name: str, ifname: str, ev: Evidence, info: _TrunkVlans, known_vlans: set[int]
    ) -> None:
        iface = self._interface(
            name,
            ifname,
            ev,
            mode="trunk",
            allowed_vlans=compact_vlan_list(info.allowed),
            active_vlans=compact_vlan_list(info.active),
            native_vlan=info.native,
            vlan_source=info.source,
        )
        evidence = ev.model_copy(
            update={"confidence": info.confidence, "note": f"VLANs on the trunk from {info.source}"}
        )
        for vlan in sorted(info.active or info.allowed):
            self.graph.add_edge(iface, self._vlan(vlan, ev), EdgeKind.trunk_vlan, evidence)

    def _ingest_cisco_stp(self, name: str, data: dict[str, Any], ev: Evidence) -> None:
        """Per-port spanning-tree facts, so STP relevance is a fact and not a
        substring of somebody's port description."""
        roles: dict[str, set[str]] = defaultdict(set)
        states: dict[str, set[str]] = defaultdict(set)
        edge: dict[str, bool] = {}
        for row in rows(data.get("stp")):
            port = normalize_ifname(str(first(row, "interface", "port", default="") or ""))
            if not port:
                continue
            roles[port].add(str(first(row, "role", default="") or "").strip())
            states[port].add(str(first(row, "status", "state", default="") or "").strip())
            is_edge = "edge" in str(first(row, "type", default="") or "").lower()
            edge[port] = edge.get(port, True) and is_edge
        for port, port_roles in roles.items():
            node = interface_id(name, port)
            if node not in self.graph:
                continue
            self.graph.add_node(
                node,
                NodeKind.interface,
                stp_roles=sorted(r for r in port_roles if r),
                stp_states=sorted(s for s in states[port] if s),
                stp_edge_port=edge.get(port, False),
                stp_significant=bool(port_roles & STP_SIGNIFICANT_ROLES),
            )

    def _ingest_cisco_l3(self, name: str, data: dict[str, Any], ev: Evidence) -> None:
        addresses: dict[str, str] = {}
        for row in rows(data.get("interfaces")) + rows(data.get("ip_int_brief")):
            ifname = normalize_ifname(str(first(row, "interface", "port", "name") or ""))
            value = first(row, "ip_address", "ipaddr", "ip")
            if not ifname or not value or str(value).lower() in ("unassigned", "none"):
                continue
            # `show interfaces` reports the address and its length separately.
            mask = first(row, "prefix_length", "prefix_len", "netmask", "mask")
            spelt = f"{value}/{mask}" if mask and "/" not in str(value) else str(value)
            addresses.setdefault(ifname, spelt)
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
                port = _neighbor_port(row, protocol)
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
                        neighbor_port=normalize_ifname(port),
                        neighbor_mgmt_ip=first(
                            row, "mgmt_address", "management_ip", "mgmt_ip", "management_address"
                        ),
                        neighbor_platform=first(
                            row,
                            "platform",
                            "neighbor_description",
                            "system_description",
                            "capabilities",
                        ),
                    )
                )

    def _ingest_cisco_macs(self, device: SeedDevice) -> None:
        """Newest sighting per MAC across the snapshot history; older sightings
        survive with a confidence that decays with age (MAC aging tolerance).

        The history is bounded by *age*, not by a snapshot count: at the Cisco
        collector's 300 s interval a count of a dozen snapshots would be one
        hour, so a quiet VM would vanish from L2 long before the decay curve
        reached its floor.
        """
        seen: set[str] = set()
        history = self.store.history(device.name, "cisco", self.mac_history_limit)
        for index, snapshot in enumerate(history):
            age_hours = max(0.0, (self.now - snapshot.taken_at).total_seconds() / 3600.0)
            if index and age_hours > self.mac_max_age_hours:
                break
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
        ha_peers = rows(data.get("ha"))
        self.graph.add_node(
            device_id(name),
            NodeKind.device,
            os_version=system.get("version"),
            serial=system.get("serial"),
            # A non-empty ha-peer list is the structured fact that this box is
            # clustered; a change on its heartbeat links is a Tier 2 change.
            ha_enabled=bool(ha_peers),
            ha_peers=[str(first(p, "hostname", "serial_no", default="")) for p in ha_peers],
        )
        ha_interfaces = {str(i) for i in as_list(data.get("ha_interfaces")) if str(i).strip()} | {
            str(first(p, "interface", default="") or "") for p in ha_peers
        }

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
                sdwan_member=ifname in sdwan_members or None,
                ha_member=ifname in ha_interfaces or None,
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

        self._ingest_fortigate_hardware_switch(name, data, ev)

        self.state.fw_addresses[name] = {
            str(a.get("name")): a for a in rows(data.get("addresses")) if a.get("name")
        }
        self.state.fw_addrgrps[name] = {
            str(g.get("name")): [str(m) for m in as_list(g.get("members"))]
            for g in rows(data.get("addrgrps"))
            if g.get("name")
        }

        for how, section in (("arp", "arp"), ("dhcp lease", "dhcp_leases")):
            for row in rows(data.get(section)):
                mac = normalize_mac(first(row, "mac", "mac_address"))
                address = first(row, "ip", "address")
                if mac and address and is_ip(address):
                    self.state.ip_by_mac[mac].add(str(address))
                    self.state.ip_source.setdefault((mac, str(address)), ("fortigate", name, how))

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

    def _ingest_fortigate_hardware_switch(
        self, name: str, data: dict[str, Any], ev: Evidence
    ) -> None:
        """Join a 60F's hardware-switch member ports to their parent.

        On a 60F the LAN ports are `internal1`..`internal5`, members of the
        `internal` hard switch, and every VLAN gateway hangs off `internal`.
        LLDP is reported on the *member* port, so without this edge a change on
        the member port that carries every gateway looks like it affects
        nothing at all.

        `cmdb/system/interface` (all the FortiGate collector fetches today) does
        not return the membership list, so members are matched by the naming
        FortiOS enforces for a hard switch. An explicit `member` list is used
        when a collector starts returning `cmdb/system/virtual-switch`.
        """
        rows_by_name = {
            str(first(row, "name", default="") or ""): row for row in rows(data.get("interfaces"))
        }
        parents = {
            ifname: row
            for ifname, row in rows_by_name.items()
            if ifname and str(first(row, "type", default="") or "").lower() in HARDWARE_SWITCH_TYPES
        }
        for parent_name, parent_row in parents.items():
            parent = interface_id(name, normalize_ifname(parent_name))
            if parent not in self.graph:
                continue
            declared = [str(m) for m in as_list(first(parent_row, "member", "members", default=[]))]
            members = declared or [
                ifname
                for ifname in rows_by_name
                if ifname.startswith(parent_name) and ifname[len(parent_name) :].isdigit()
            ]
            note = "declared member" if declared else "hardware-switch member (matched by name)"
            for member_name in sorted(members):
                member = interface_id(name, normalize_ifname(member_name))
                if member == parent or member not in self.graph:
                    continue
                self.graph.add_edge(
                    member,
                    parent,
                    EdgeKind.switch_member_of,
                    ev.model_copy(update={"note": note, "confidence": 1.0 if declared else 0.9}),
                )
                self.graph.add_node(
                    member, NodeKind.interface, switch_member_of=normalize_ifname(parent_name)
                )
            self.graph.add_node(parent, NodeKind.interface, hardware_switch=True, uplink=True)

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
            # Addresses only ARP and the DHCP server know about are joined in
            # `_resolve_l3`, once every device has been ingested: doing it here
            # would make the L3 layer depend on the seed inventory's order.
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

    def _classify_uplinks(self) -> None:
        """Mark every interface that carries more than its own access VLAN.

        A Catalyst says so itself (`show interfaces status` prints `trunk`), but
        a FortiGate never does: the parent of a set of VLAN sub-interfaces, a
        hardware-switch member and a port facing a switch trunk are all uplinks
        carrying every VLAN behind them, and a change on one is a Tier 2 change
        (`docs/risk-tiers.md`). Runs after L1 so the neighbour is known.
        """
        for node in self.graph.nodes_of_kind(NodeKind.interface):
            data = self.graph.node(node)
            if data.get("uplink") or data.get("mode") == "trunk":
                continue
            carries_vlans = any(
                True for _s, _e in self.graph.in_edges(node, EdgeKind.subinterface_of)
            )
            member = any(True for _t, _e in self.graph.out_edges(node, EdgeKind.switch_member_of))
            facing_trunk = any(
                self.graph.node(peer).get("mode") == "trunk"
                for peer, _e in self.graph.out_edges(node, EdgeKind.l1_neighbor)
            )
            if carries_vlans or member or facing_trunk:
                self.graph.add_node(
                    node,
                    NodeKind.interface,
                    uplink=True,
                    uplink_reason=(
                        "parent of VLAN sub-interfaces"
                        if carries_vlans
                        else "hardware-switch member"
                        if member
                        else "faces a switch trunk"
                    ),
                )

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

    def _join_arp_and_leases(self) -> None:
        """MAC -> IP from ARP tables and DHCP leases, attached to whoever owns
        the MAC.

        This runs after every device has been ingested. Joining at ingest time
        would silently drop half of L3 whenever `inventory/seed.yaml` happens to
        list the ESXi hosts before the switches and the firewall — the file is
        written in whatever order `infra onboard add-device` was run.
        """
        for mac, addresses in sorted(self.state.ip_by_mac.items()):
            owner = self.state.mac_owner.get(mac)
            if owner is None or owner not in self.graph:
                continue
            owner_data = self.graph.node(owner)
            for address in sorted(addresses):
                collector, device, how = self.state.ip_source.get(
                    (mac, address), ("correlate", None, "arp")
                )
                ip_node = self._ip(
                    address,
                    owner_vm=owner_data.get("vm"),
                    owner_device=owner_data.get("device"),
                )
                evidence = self._evidence(
                    collector,
                    device or "",
                    confidence=0.9,
                    note=f"{how} entry for {mac}",
                )
                self.graph.add_edge(owner, ip_node, EdgeKind.has_ip, evidence)
                self.state.pending_ips.append((address, owner, evidence))

    def _resolve_l3(self) -> None:
        self._join_arp_and_leases()
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
                    # Every equally short route, not one of them: with two
                    # trunks to the firewall or two port-channel members, only
                    # marking one leaves a change on the other computing as if
                    # it were nowhere near the platform's own path.
                    for route in nx.all_shortest_paths(physical, switch, firewall):
                        marked.update(route)
                except nx.NetworkXNoPath:
                    continue
        marked |= self._parallel_links(marked)
        for node in sorted(marked):
            for parent, _e in self.graph.out_edges(node, EdgeKind.switch_member_of):
                marked.add(parent)
        self.graph.mark_mgmt_path(marked)
        self.graph.g.graph["mgmt_vlans"] = sorted(vlans)
        return sorted(marked)

    def _parallel_links(self, marked: set[str]) -> set[str]:
        """Every other physical link between two devices already on the path.

        A second trunk to the firewall is not a longer route to be ignored, it
        is the redundancy that keeps the platform reachable; both ends belong on
        the path even when the shortest-path walk never traverses them.
        """
        extra: set[str] = set()
        for source, target, _data in self.graph.edges_of_kind(EdgeKind.l1_neighbor):
            owners = [self.graph.node(node).get("device") for node in (source, target)]
            if not all(owners):
                continue
            devices = [device_id(str(owner)) for owner in owners]
            if not all(d in marked for d in devices):
                continue
            if all(self.graph.node(d).get("role") in ("switch", "firewall") for d in devices):
                extra.update({source, target})
        return extra

    def _physical_view(self) -> nx.Graph:
        """Devices and ports a management packet can transit.

        Only switches and firewalls forward for the platform; letting a path run
        through an ESXi host, an iLO or an access point that two switches happen
        to both see would mark objects that carry none of its traffic.
        """
        transit = {
            node
            for node, data in self.graph.g.nodes(data=True)
            if data.get("role") in ("switch", "firewall")
        }

        def forwards(node: str) -> bool:
            if node in transit:
                return True
            device = self.graph.node(node).get("device")
            return bool(device) and device_id(str(device)) in transit

        view = nx.Graph()
        for kind in (EdgeKind.has_interface, EdgeKind.l1_neighbor, EdgeKind.switch_member_of):
            for source, target, data in self.graph.edges_of_kind(kind):
                if forwards(source) and forwards(target):
                    view.add_edge(source, target, kind=data.get("kind"))
        return view


def _int_or_none(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _scalar(value: Any) -> Any:
    """ntc-templates returns some single values as one-element lists."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _cisco_interface_status(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """`show interfaces status` rows, keyed by canonical interface name.

    ntc-templates >= 5 names the VLAN column `vlan_id` (it was `vlan` before);
    a trunk prints the literal `trunk` there, which is how a trunk port is
    recognised when no `show interfaces trunk` template exists.
    """
    status: dict[str, dict[str, Any]] = {}
    for row in rows(data.get("interfaces_status")):
        port = first(row, "port", "interface", "name")
        if not port:
            continue
        raw_vlan = str(first(row, "vlan_id", "vlan", default="") or "").strip().lower()
        mode = "trunk" if raw_vlan == "trunk" else ("routed" if raw_vlan == "routed" else "access")
        status[normalize_ifname(str(port))] = {
            "mode": mode,
            "access_vlan": int(raw_vlan) if raw_vlan.isdigit() else None,
            "description": first(row, "name", "description"),
            "status": first(row, "status", "link_status"),
            "speed": first(row, "speed"),
            "duplex": first(row, "duplex"),
            "media": first(row, "type", "media"),
        }
    return status


def _neighbor_port(row: dict[str, Any], protocol: str) -> str:
    """The neighbour's port name from a CDP or LLDP row.

    CDP reports the port name in `neighbor_interface`. LLDP reports a port *id*
    (`neighbor_port_id`) that is a port name on sane implementations and the
    port's MAC address on others, plus a free-text `neighbor_interface` port
    description; prefer the id unless it is a MAC.
    """
    if protocol == "lldp":
        port_id = str(first(row, "neighbor_port_id", "port_id", "remote_port", default="") or "")
        if port_id and not normalize_mac(port_id):
            return port_id
        described = str(first(row, "neighbor_interface", "remote_interface", default="") or "")
        return described or port_id
    return str(
        first(
            row,
            "remote_port",
            "neighbor_interface",
            "neighbor_port_id",
            "port_id",
            "remote_interface",
            default="",
        )
        or ""
    )


def _cisco_stp_vlans(data: dict[str, Any]) -> dict[str, set[int]]:
    """`show spanning-tree` -> the VLAN instances each port takes part in."""
    by_port: dict[str, set[int]] = defaultdict(set)
    for row in rows(data.get("stp")):
        port = normalize_ifname(str(first(row, "interface", "port", default="") or ""))
        vlan = _int_or_none(first(row, "vlan_id", "vlan", "instance"))
        if port and vlan:
            by_port[port].add(vlan)
    return dict(by_port)


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
