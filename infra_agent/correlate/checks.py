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


def check_portgroup_vlan_not_carried(graph: TopologyGraph) -> list[Finding]:
    """A portgroup tags a VLAN that no switch carries: the VMs on it are isolated."""
    carried: set[int] = set()
    for kind in (EdgeKind.access_vlan, EdgeKind.trunk_vlan, EdgeKind.svi_for):
        for source, target, _data in graph.edges_of_kind(kind):
            device = graph.node(source).get("device")
            device_node = f"device:{device}" if device else None
            role = (
                graph.node(device_node).get("role")
                if device_node and device_node in graph
                else None
            )
            if role in ("switch", "firewall"):
                vlan = graph.node(target).get("vlan_id")
                if vlan is not None:
                    carried.add(int(vlan))
    findings: list[Finding] = []
    for node in graph.nodes_of_kind(NodeKind.portgroup):
        data = graph.node(node)
        vlan = data.get("vlan")
        if not vlan:  # 0 / None means untagged, nothing to carry
            continue
        if int(vlan) in carried:
            continue
        vms = sorted(
            str(graph.node(vnic)["vm"])
            for vnic, _e in graph.in_edges(node, EdgeKind.attached_to)
            if graph.node(vnic).get("vm")
        )
        findings.append(
            Finding(
                id=f"portgroup-vlan-not-carried:{node}",
                kind="portgroup_vlan_not_carried",
                severity="critical" if vms else "warning",
                title=f"Portgroup {_label(graph, node)} tags VLAN {vlan}, which no switch carries",
                detail=(
                    f"No switch trunk, access port or SVI carries VLAN {vlan}. "
                    + (
                        f"VMs stranded on it: {', '.join(vms)}."
                        if vms
                        else "No VM is attached yet."
                    )
                ),
                objects=[node] + [f"vm:{vm}" for vm in vms],
                evidence={"vlan": int(vlan), "carried_vlans": sorted(carried)},
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


CHECKS = (
    check_trunk_vlan_mismatch,
    check_portgroup_vlan_not_carried,
    check_duplicate_ips,
    check_disconnected_vnics,
)

_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def run_checks(graph: TopologyGraph) -> list[Finding]:
    """Every consistency check, most severe first, deterministically ordered."""
    findings: list[Finding] = []
    for check in CHECKS:
        findings.extend(check(graph))
    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 3), f.kind, f.id))
    return findings
