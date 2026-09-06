"""Consistency checks over the topology graph.

These are the questions a human would ask while auditing the estate, answered
from evidence the collectors already gathered:

* a VLAN allowed on one side of a trunk but not the other,
* a portgroup tagging a VLAN that no switch actually carries,
* the same IP claimed by two different owners,
* VMs whose vNIC is not connected.

Findings are plain data, safe to hand to the language model.
"""

from __future__ import annotations

import hashlib
from typing import Any, Literal

from pydantic import BaseModel, Field

from infra_agent.correlate.model import EdgeKind, NodeKind, TopologyGraph
from infra_agent.correlate.parsing import expand_vlan_list

Severity = Literal["info", "warning", "critical"]


class Finding(BaseModel):
    id: str
    kind: str
    severity: Severity = "warning"
    title: str
    detail: str
    objects: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


def _label(graph: TopologyGraph, node: str) -> str:
    return str(graph.node(node).get("label", node)) if node in graph else node


def _digest(value: object) -> str:
    """Stable short id fragment (`hash()` is salted per process, ids are persisted)."""
    return hashlib.blake2s(str(value).encode(), digest_size=3).hexdigest()


def check_trunk_vlan_mismatch(graph: TopologyGraph) -> list[Finding]:
    """A VLAN allowed on one trunk side only: traffic is black-holed one way."""
    findings: list[Finding] = []
    seen: set[frozenset[str]] = set()
    for source, target, _data in graph.edges_of_kind(EdgeKind.l1_neighbor):
        pair = frozenset({source, target})
        if pair in seen or len(pair) != 2:
            continue
        left = graph.node(source)
        right = graph.node(target)
        if left.get("mode") != "trunk" or right.get("mode") != "trunk":
            continue
        seen.add(pair)
        left_vlans = expand_vlan_list(left.get("allowed_vlans"))
        right_vlans = expand_vlan_list(right.get("allowed_vlans"))
        if not left_vlans or not right_vlans:
            continue
        only_left = sorted(left_vlans - right_vlans)
        only_right = sorted(right_vlans - left_vlans)
        if not only_left and not only_right:
            continue
        findings.append(
            Finding(
                id=f"trunk-vlan-mismatch:{min(source, target)}|{max(source, target)}",
                kind="trunk_vlan_mismatch",
                severity="warning",
                title=(
                    f"VLAN mismatch on the trunk between {_label(graph, source)} "
                    f"and {_label(graph, target)}"
                ),
                detail=(
                    f"{_label(graph, source)} allows {only_left or 'nothing extra'} that "
                    f"{_label(graph, target)} does not; {_label(graph, target)} allows "
                    f"{only_right or 'nothing extra'} that {_label(graph, source)} does not. "
                    "Traffic in those VLANs is dropped in one direction."
                ),
                objects=sorted(pair),
                evidence={
                    "allowed_only_on": {
                        source: only_left,
                        target: only_right,
                    }
                },
            )
        )
    return findings


def _device_role(graph: TopologyGraph, node: str) -> str | None:
    device = graph.node(node).get("device")
    device_node = f"device:{device}" if device else None
    if device_node and device_node in graph:
        return str(graph.node(device_node).get("role"))
    return None


def _switch_port_vlans(graph: TopologyGraph, node: str) -> set[int]:
    """The VLANs one switch port actually carries: its trunk list, or its access VLAN."""
    if _device_role(graph, node) != "switch":
        return set()
    data = graph.node(node)
    vlans = expand_vlan_list(data.get("allowed_vlans"))
    vlans |= expand_vlan_list(data.get("active_vlans"))
    for kind in (EdgeKind.access_vlan, EdgeKind.trunk_vlan):
        for target, _edge in graph.out_edges(node, kind):
            carried = graph.node(target).get("vlan_id")
            if carried is not None:
                vlans.add(int(carried))
    return vlans


def _portgroup_uplinks(graph: TopologyGraph, node: str) -> list[str]:
    """The host pNICs a portgroup's traffic can leave through."""
    uplinks: list[str] = []
    for vswitch, _e in graph.out_edges(node, EdgeKind.portgroup_on):
        for uplink, _e2 in graph.out_edges(vswitch, EdgeKind.uplink_of):
            uplinks.append(uplink)
    return sorted(set(uplinks))


def check_portgroup_vlan_not_carried(graph: TopologyGraph) -> list[Finding]:
    """A portgroup tags a VLAN the switch port feeding its host does not carry.

    Asked per host uplink, not estate-wide: a VLAN trunked between the core and
    the firewall is no use to a VM whose host hangs off an access switch whose
    trunk does not allow it. A FortiGate VLAN interface is a gateway, not a
    carrier, so it never satisfies this check on its own.
    """
    everywhere: set[int] = set()
    port_vlans: dict[str, set[int]] = {}
    for port in graph.nodes_of_kind(NodeKind.interface):
        vlans = _switch_port_vlans(graph, port)
        if vlans:
            port_vlans[port] = vlans
            everywhere |= vlans

    findings: list[Finding] = []
    for node in graph.nodes_of_kind(NodeKind.portgroup):
        data = graph.node(node)
        vlan = data.get("vlan")
        if not vlan:  # 0 / None means untagged, nothing to carry
            continue
        vlan = int(vlan)
        offending: dict[str, str] = {}
        carriers: dict[str, str] = {}
        uplinks = _portgroup_uplinks(graph, node)
        for uplink in uplinks:
            for peer, _edge in graph.out_edges(uplink, EdgeKind.l1_neighbor):
                if peer not in port_vlans:  # nothing known about that port: no claim
                    continue
                (carriers if vlan in port_vlans[peer] else offending)[uplink] = peer
        if not uplinks:  # no vSwitch uplink information: fall back to the estate
            if vlan in everywhere:
                continue
            offending = {}
        elif not offending:
            continue

        vms = sorted(
            str(graph.node(vnic)["vm"])
            for vnic, _e in graph.in_edges(node, EdgeKind.attached_to)
            if graph.node(vnic).get("vm")
        )
        host = data.get("device")
        blocked = ", ".join(
            f"{_label(graph, uplink)} -> {_label(graph, peer)}"
            for uplink, peer in sorted(offending.items())
        )
        findings.append(
            Finding(
                id=f"portgroup-vlan-not-carried:{node}",
                kind="portgroup_vlan_not_carried",
                severity="critical" if vms and not carriers else "warning",
                title=(
                    f"Portgroup {_label(graph, node)} tags VLAN {vlan}, which the switch "
                    f"port{'s' if len(offending) != 1 else ''} feeding {host} do"
                    f"{'' if len(offending) != 1 else 'es'} not carry"
                ),
                detail=(
                    (
                        f"VLAN {vlan} is missing on {blocked}. "
                        if blocked
                        else f"No switch trunk or access port carries VLAN {vlan}. "
                    )
                    + (
                        f"Traffic from {', '.join(vms)} in that VLAN is black-holed"
                        + (" on that uplink." if carriers else ".")
                        if vms
                        else "No VM is attached yet."
                    )
                ),
                objects=[node] + [f"vm:{vm}" for vm in vms] + sorted(offending.values()),
                evidence={
                    "vlan": vlan,
                    "host": host,
                    "uplinks_without_the_vlan": dict(sorted(offending.items())),
                    "uplinks_with_the_vlan": dict(sorted(carriers.items())),
                    "carried_vlans": sorted(everywhere),
                },
            )
        )
    return findings


def check_duplicate_ips(graph: TopologyGraph) -> list[Finding]:
    """The same address claimed by two different owners."""
    findings: list[Finding] = []
    for node in graph.nodes_of_kind(NodeKind.ip):
        owners: dict[str, str] = {}
        for owner, _data in graph.in_edges(node, EdgeKind.has_ip):
            owner_data = graph.node(owner)
            entity = owner_data.get("vm") or owner_data.get("device") or owner
            owners[str(entity)] = owner
        if len(owners) < 2:
            continue
        findings.append(
            Finding(
                id=f"duplicate-ip:{node}",
                kind="duplicate_ip",
                severity="critical",
                title=f"{graph.node(node).get('address')} is claimed by {len(owners)} owners",
                detail=(
                    "Duplicate address on "
                    + ", ".join(
                        f"{entity} ({_label(graph, owner)})"
                        for entity, owner in sorted(owners.items())
                    )
                    + "."
                ),
                objects=[node] + sorted(owners.values()),
                evidence={"owners": dict(sorted(owners.items()))},
            )
        )
    return findings


def check_disconnected_vnics(graph: TopologyGraph) -> list[Finding]:
    """VMs with a vNIC that is not connected."""
    findings: list[Finding] = []
    for node in graph.nodes_of_kind(NodeKind.vnic):
        data = graph.node(node)
        if data.get("connected", True):
            continue
        vm = data.get("vm")
        vm_node = f"vm:{vm}" if vm else None
        powered = graph.node(vm_node).get("power_state") if vm_node and vm_node in graph else None
        findings.append(
            Finding(
                id=f"vnic-disconnected:{node}",
                kind="vm_disconnected_vnic",
                severity="warning" if powered == "poweredOn" else "info",
                title=f"{vm or 'a VM'} has a disconnected vNIC ({data.get('label')})",
                detail=(
                    f"vNIC {data.get('label')} is not connected"
                    + (f" while {vm} is {powered}" if powered else "")
                    + ". It carries no traffic until it is reconnected."
                ),
                objects=[node] + ([vm_node] if vm_node else []),
                evidence={"portgroup": data.get("portgroup"), "power_state": powered},
            )
        )
    return findings


def check_collector_parse_gaps(graph: TopologyGraph) -> list[Finding]:
    """Snapshot sections the graph could not use.

    A switch whose `show` output no template matched arrives as raw text and
    would otherwise appear in the graph as a device with no ports — and in the
    tier engine as a device with no trunks. Say so instead of building an empty
    picture quietly.
    """
    findings: list[Finding] = []
    for gap in graph.g.graph.get("parse_gaps", []) or []:
        device = str(gap.get("device", "?"))
        section = str(gap.get("section", "?"))
        findings.append(
            Finding(
                id=f"collector-parse-gap:{device}:{section}:{_digest(gap.get('reason'))}",
                kind="collector_parse_gap",
                severity="warning",
                title=f"{device}: the {section} snapshot section could not be used",
                detail=(
                    f"{gap.get('reason', 'unusable section')}. The topology graph is "
                    f"incomplete for {device} until the collector returns parsed rows."
                ),
                objects=[f"device:{device}"],
                evidence={"device": device, "section": section, "reason": gap.get("reason")},
            )
        )
    return findings


CHECKS = (
    check_trunk_vlan_mismatch,
    check_portgroup_vlan_not_carried,
    check_duplicate_ips,
    check_disconnected_vnics,
    check_collector_parse_gaps,
)

_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def run_checks(graph: TopologyGraph) -> list[Finding]:
    """Every consistency check, most severe first, deterministically ordered."""
    findings: list[Finding] = []
    for check in CHECKS:
        findings.extend(check(graph))
    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 3), f.kind, f.id))
    return findings
