"""Impact analysis: what breaks, and what merely loses redundancy, if an object dies.

The graph is read as a dependency relation — *X depends on Y* — grouped so that
redundancy is explicit: a vSwitch with two uplinks tolerates losing one, a RAID 5
logical drive tolerates losing one physical drive, a VLAN carried by two trunks
tolerates losing one. Everything else is a single point of failure.

The result feeds two consumers:

* `ImpactSummary` (from `infra_agent.change.tiers`) drives the *computed* risk
  tier of a `ChangePlan` — see `docs/risk-tiers.md`;
* the affected-object list answers the owner's "what breaks if X dies?".
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from typing import Any, Literal

from pydantic import BaseModel, Field

from infra_agent.change.tiers import ImpactSummary
from infra_agent.correlate.model import EdgeKind, NodeKind, TopologyGraph, node_kind_of
from infra_agent.correlate.parsing import expand_vlan_list

Effect = Literal["connectivity", "redundancy"]

# Groups whose members back each other up; anything else is a hard dependency.
REDUNDANT_GROUPS = frozenset(
    {"vnic", "uplink", "trunk", "gateway", "member", "l1", "switch_member"}
)

# Redundancy loss is reported at the VLAN itself, never fanned out to every
# portgroup, vNIC and VM that happens to sit on it.
NO_FANOUT_GROUPS = frozenset({"vlan"})

# How many physical drives a RAID level survives.
RAID_TOLERANCE: dict[str, int] = {
    "0": 0,
    "raid0": 0,
    "1": 1,
    "raid1": 1,
    "10": 1,
    "raid10": 1,
    "1+0": 1,
    "5": 1,
    "raid5": 1,
    "50": 1,
    "6": 2,
    "raid6": 2,
    "60": 2,
    "adm": 2,
    "raid1adm": 2,
}

# Last-resort hints, matched as whole tokens (with an optional index, so `wan1`
# counts and `Hallway`, `chassis`, `shared` and `channel` do not). Structured
# facts are consulted first; a description is never more than a hint.
WAN_HINTS = re.compile(
    r"\b(wan|internet|isp|ipsec|vpn|tunnel|sdwan|sd-wan|ha|stp|hsrp|vrrp)\d*\b",
    re.IGNORECASE,
)

# FortiOS interface types that are a VPN tunnel by construction.
TUNNEL_TYPES = frozenset({"tunnel", "vpn", "ipsec"})


class AffectedObject(BaseModel):
    id: str
    kind: str
    label: str
    effect: Effect
    reason: str
    mgmt_path: bool = False

    def line(self) -> str:
        flag = " [mgmt path]" if self.mgmt_path else ""
        verb = "loses connectivity" if self.effect == "connectivity" else "loses redundancy"
        return f"{self.label} ({self.kind}) {verb}: {self.reason}{flag}"


class ImpactReport(BaseModel):
    """`summary` is what the tier engine consumes; the two lists are what the
    owner reads."""

    object_id: str
    kind: str
    label: str
    found: bool = True
    summary: ImpactSummary = Field(default_factory=ImpactSummary)
    loses_connectivity: list[AffectedObject] = Field(default_factory=list)
    loses_redundancy: list[AffectedObject] = Field(default_factory=list)

    @property
    def affected(self) -> list[AffectedObject]:
        return self.loses_connectivity + self.loses_redundancy

    def describe(self) -> list[str]:
        """Human-readable list of affected objects, connectivity losses first."""
        return [obj.line() for obj in self.affected]

    def as_dict(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        payload["description"] = self.describe()
        return payload


class DependencyIndex:
    """`providers[dependent][group]` and its inverse, with a per-group tolerance."""

    def __init__(self, graph: TopologyGraph) -> None:
        self.graph = graph
        self.providers: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        self.dependents: dict[str, set[tuple[str, str]]] = defaultdict(set)
        self._build()

    def _add(self, dependent: str, group: str, provider: str) -> None:
        if dependent == provider:
            return
        self.providers[dependent][group].add(provider)
        self.dependents[provider].add((dependent, group))

    def _build(self) -> None:
        g = self.graph
        for node, data in g.g.nodes(data=True):
            kind = data.get("kind")
            if kind == NodeKind.vm:
                connected = [
                    vnic
                    for vnic, _e in g.out_edges(node, EdgeKind.has_vnic)
                    if g.node(vnic).get("connected", True)
                ]
                for vnic in connected:
                    self._add(node, "vnic", vnic)
                for datastore, _e in g.out_edges(node, EdgeKind.stored_on):
                    self._add(node, "datastore", datastore)
                for host, _e in g.out_edges(node, EdgeKind.runs_on):
                    self._add(node, "host", host)
            elif kind == NodeKind.vnic:
                for portgroup, _e in g.out_edges(node, EdgeKind.attached_to):
                    self._add(node, "portgroup", portgroup)
            elif kind == NodeKind.portgroup:
                for vswitch, _e in g.out_edges(node, EdgeKind.portgroup_on):
                    self._add(node, "vswitch", vswitch)
                for vlan, _e in g.out_edges(node, EdgeKind.portgroup_vlan):
                    self._add(node, "vlan", vlan)
            elif kind == NodeKind.vswitch:
                for uplink, _e in g.out_edges(node, EdgeKind.uplink_of):
                    self._add(node, "uplink", uplink)
            elif kind == NodeKind.vlan:
                for trunk, _e in g.in_edges(node, EdgeKind.trunk_vlan):
                    self._add(node, "trunk", trunk)
                for svi, _e in g.in_edges(node, EdgeKind.svi_for):
                    self._add(node, "gateway", svi)
            elif kind == NodeKind.interface:
                self._interface_dependencies(node, data)
            elif kind == NodeKind.datastore:
                for logical, _e in g.out_edges(node, EdgeKind.backed_by):
                    self._add(node, "logical_drive", logical)
            elif kind == NodeKind.logical_drive:
                for drive, _e in g.out_edges(node, EdgeKind.spans):
                    self._add(node, "physical_drive", drive)
            elif kind == NodeKind.ip:
                for owner, _e in g.in_edges(node, EdgeKind.has_ip):
                    self._add(node, "owner", owner)
            elif kind == NodeKind.fw_policy:
                for target, _e in g.out_edges(node, EdgeKind.references):
                    if node_kind_of(target) == NodeKind.interface:
                        self._add(node, "interface", target)
            elif kind == NodeKind.wan_link:
                for iface, _e in g.in_edges(node, EdgeKind.wan_uplink):
                    self._add(node, "interface", iface)

    def _interface_dependencies(self, node: str, data: dict[str, Any]) -> None:
        g = self.graph
        for device, _e in g.in_edges(node, EdgeKind.has_interface):
            self._add(node, "device", device)
        for parent, _e in g.out_edges(node, EdgeKind.subinterface_of):
            self._add(node, "parent", parent)
        members = data.get("members") or []
        for member in members:
            member_node = f"interface:{data.get('device')}:{member}"
            if member_node in g:
                self._add(node, "member", member_node)
        # A FortiGate hardware switch is only as reachable as its wired members.
        switch_members = [m for m, _e in g.in_edges(node, EdgeKind.switch_member_of)]
        wired = [
            m
            for m in switch_members
            if any(True for _p, _e in g.out_edges(m, EdgeKind.l1_neighbor))
        ]
        for member in wired or switch_members:
            self._add(node, "switch_member", member)
        if data.get("pnic") or data.get("uplink"):
            for peer, _e in g.out_edges(node, EdgeKind.l1_neighbor):
                self._add(node, "l1", peer)
        access_vlan = data.get("access_vlan")
        if access_vlan and data.get("mode") == "access":
            vlan_node = f"vlan:{int(access_vlan)}"
            if vlan_node in g:
                self._add(node, "vlan", vlan_node)

    def tolerance(self, dependent: str, group: str) -> int:
        providers = self.providers[dependent][group]
        if group == "physical_drive":
            raid = str(self.graph.node(dependent).get("raid") or "").strip().lower()
            raid = raid.replace("raid ", "raid").replace(" ", "")
            return min(RAID_TOLERANCE.get(raid, 0), max(len(providers) - 1, 0))
        if group in REDUNDANT_GROUPS:
            return max(len(providers) - 1, 0)
        return 0


def _describe(graph: TopologyGraph, node: str) -> tuple[str, str]:
    data = graph.node(node)
    return str(data.get("kind", node_kind_of(node))), str(data.get("label", node))


def _is_trunk_or_uplink(graph: TopologyGraph, node: str) -> bool:
    if node_kind_of(node) != NodeKind.interface:
        return False
    data = graph.node(node)
    return bool(
        data.get("mode") == "trunk"
        or data.get("uplink")
        or data.get("svi")
        or data.get("portchannel")
        or data.get("hardware_switch")
        or str(data.get("label", "")).lower().find("port-channel") >= 0
    )


def _is_wan_ha_vpn_stp(graph: TopologyGraph, node: str) -> bool:
    """WAN, SD-WAN, HA, VPN or STP relevance — from facts where there are any.

    A port description is free text an engineer typed; matching `ha` inside
    `chassis` or `Hallway` would force a maintenance window and a confirmation
    phrase on an ordinary access port, which is how owners learn to rubber-stamp
    Tier 2. Structured evidence decides first and text is matched as whole
    tokens.
    """
    kind = node_kind_of(node)
    if kind == NodeKind.wan_link:
        return True
    if kind != NodeKind.interface:
        return False
    data = graph.node(node)
    if data.get("is_wan") or str(data.get("role", "")).lower() == "wan":
        return True
    if str(data.get("fw_type", "")).lower() in TUNNEL_TYPES:
        return True
    # `ha_member` is only set when the box reports HA peers (or a collector
    # returns the heartbeat interfaces): a clustered firewall does not make
    # every one of its ports an HA change, only its heartbeat links.
    if data.get("sdwan_member") or data.get("ha_member"):
        return True
    if data.get("stp_significant"):  # a root, alternate or backup port
        return True
    haystack = " ".join(str(data.get(key, "")) for key in ("label", "alias", "description"))
    return bool(WAN_HINTS.search(haystack))


def _feeds_ilo_or_mgmt_vlan(graph: TopologyGraph, node: str) -> bool:
    if node_kind_of(node) != NodeKind.interface:
        return False
    data = graph.node(node)
    mgmt_vlans = {int(v) for v in graph.g.graph.get("mgmt_vlans", []) or []}
    vlans: set[int] = set()
    if data.get("access_vlan"):
        vlans.add(int(data["access_vlan"]))
    if data.get("vlan"):
        vlans.add(int(data["vlan"]))
    vlans |= expand_vlan_list(data.get("allowed_vlans"))
    if mgmt_vlans & vlans:
        return True
    for peer, _e in graph.out_edges(node, EdgeKind.l1_neighbor):
        device = graph.node(peer).get("device")
        device_node = f"device:{device}" if device else None
        if device_node and device_node in graph and graph.node(device_node).get("role") == "bmc":
            return True
    return False


def _vlan_has_members_or_svi(graph: TopologyGraph, node: str) -> bool:
    if node_kind_of(node) != NodeKind.vlan:
        return False
    for kind in (EdgeKind.access_vlan, EdgeKind.trunk_vlan, EdgeKind.svi_for):
        if any(True for _s, _e in graph.in_edges(node, kind)):
            return True
    return any(True for _s, _e in graph.in_edges(node, EdgeKind.portgroup_vlan))


def _propagate_degradation(
    graph: TopologyGraph,
    index: DependencyIndex,
    failed: dict[str, str],
    degraded: dict[str, str],
) -> None:
    """A degraded object degrades whatever depends on it *and only on it*.

    Losing one of an ESXi host's two uplinks degrades the vSwitch, and with it
    the portgroups, vNICs and VMs that have nowhere else to go. VLAN redundancy
    is deliberately not fanned out: a VLAN losing one of several carriers is
    reported at the VLAN, not repeated for every member.
    """
    queue: deque[str] = deque(degraded)
    while queue:
        node = queue.popleft()
        _kind, label = _describe(graph, node)
        for dependent, group in sorted(index.dependents.get(node, ())):
            if dependent in failed or dependent in degraded or group in NO_FANOUT_GROUPS:
                continue
            if index.tolerance(dependent, group) != 0:
                continue
            degraded[dependent] = f"its only {group} ({label}) lost redundancy"
            queue.append(dependent)


def impact_analyze(
    object_id: str,
    graph: TopologyGraph,
    *,
    index: DependencyIndex | None = None,
) -> ImpactReport:
    """What breaks if `object_id` is lost or changed disruptively."""
    resolved = graph.resolve(object_id) or object_id
    if resolved not in graph:
        return ImpactReport(object_id=object_id, kind="unknown", label=object_id, found=False)
    index = index or DependencyIndex(graph)
    kind, label = _describe(graph, resolved)

    failed: dict[str, str] = {resolved: "the object under change"}
    degraded: dict[str, str] = {}
    queue: deque[str] = deque([resolved])
    while queue:
        provider = queue.popleft()
        for dependent, group in sorted(index.dependents.get(provider, ())):
            if dependent in failed:
                continue
            providers = index.providers[dependent][group]
            lost = providers & set(failed)
            tolerance = index.tolerance(dependent, group)
            _pkind, plabel = _describe(graph, provider)
            if len(lost) > tolerance:
                if len(providers) > 1:
                    reason = f"all {len(providers)} of its {group} providers are gone"
                else:
                    reason = f"its only {group} is {plabel}"
                failed[dependent] = reason
                degraded.pop(dependent, None)
                queue.append(dependent)
            else:
                degraded.setdefault(
                    dependent,
                    f"{len(lost)} of {len(providers)} {group} providers gone ({plabel})",
                )

    _propagate_degradation(graph, index, failed, degraded)

    connectivity = [
        _affected(graph, node, "connectivity", reason)
        for node, reason in sorted(failed.items())
        if node != resolved
    ]
    redundancy = [
        _affected(graph, node, "redundancy", reason) for node, reason in sorted(degraded.items())
    ]
    touched = [resolved, *failed, *degraded]
    summary = ImpactSummary(
        touches_mgmt_path=any(graph.node(n).get("mgmt_path") for n in touched),
        touches_trunk_or_uplink=any(_is_trunk_or_uplink(graph, n) for n in touched),
        touches_wan_ha_vpn_stp=any(_is_wan_ha_vpn_stp(graph, n) for n in touched),
        vlan_has_members_or_svi=_vlan_has_members_or_svi(graph, resolved),
        feeds_ilo_or_mgmt_vlan=_feeds_ilo_or_mgmt_vlan(graph, resolved),
        affected_objects=sorted((set(failed) | set(degraded)) - {resolved}),
    )
    return ImpactReport(
        object_id=resolved,
        kind=kind,
        label=label,
        summary=summary,
        loses_connectivity=connectivity,
        loses_redundancy=redundancy,
    )


def _affected(graph: TopologyGraph, node: str, effect: Effect, reason: str) -> AffectedObject:
    kind, label = _describe(graph, node)
    return AffectedObject(
        id=node,
        kind=kind,
        label=label,
        effect=effect,
        reason=reason,
        mgmt_path=bool(graph.node(node).get("mgmt_path")),
    )


def impact_summary(object_id: str, graph: TopologyGraph) -> ImpactSummary:
    """Just the `ImpactSummary` the tier engine needs for `compute_tier`."""
    return impact_analyze(object_id, graph).summary


#: The change a reader most likely means for each kind of object, so an
#: illustrative tier is not computed from a switch-port action for a datastore.
DEFAULT_ACTIONS: dict[str, str] = {
    NodeKind.vm: "vm.resize",
    NodeKind.vnic: "vm.resize",
    NodeKind.datastore: "storage.rebuild",
    NodeKind.logical_drive: "storage.rebuild",
    NodeKind.physical_drive: "storage.rebuild",
    NodeKind.vlan: "vlan.remove",
    NodeKind.fw_policy: "fortigate.policy",
    NodeKind.wan_link: "fortigate.wan",
    NodeKind.portgroup: "esxi.host_setting",
    NodeKind.vswitch: "esxi.host_setting",
    NodeKind.prefix: "fortigate.static_route",
    NodeKind.ip: "fortigate.address",
}


def default_action(graph: TopologyGraph, object_id: str) -> str:
    """The change action `infra graph impact` computes its example tier from."""
    node = graph.resolve(object_id) or object_id
    if node not in graph:
        return "switch.access_port_config"
    data = graph.node(node)
    kind = str(data.get("kind", node_kind_of(node)))
    if kind == NodeKind.device:
        return "esxi.host_setting" if data.get("role") == "host" else "firmware.update"
    if kind == NodeKind.interface:
        device = data.get("device")
        device_node = f"device:{device}" if device else None
        role = graph.node(device_node).get("role") if device_node in graph else None
        if role == "firewall":
            return "fortigate.wan" if _is_wan_ha_vpn_stp(graph, node) else "fortigate.policy"
        if role == "host":
            return "esxi.host_setting"
        return (
            "switch.trunk_port_config"
            if _is_trunk_or_uplink(graph, node)
            else "switch.access_port_config"
        )
    return DEFAULT_ACTIONS.get(kind, "switch.access_port_config")
