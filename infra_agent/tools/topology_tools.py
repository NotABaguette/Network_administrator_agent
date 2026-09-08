"""Topology tools: where things are, what they touch, what breaks if they die.

Everything returned here is derived from parsed snapshot rows — node ids,
labels, evidence and Mermaid text. No raw configuration and no approval
material is reachable through these tools, so they are safe for the model
(results still pass through the redaction gateway on the way out).
"""

from __future__ import annotations

from typing import Any

from infra_agent.correlate import service
from infra_agent.correlate.impact import impact_analyze as _impact_analyze
from infra_agent.correlate.mermaid import render as _render
from infra_agent.correlate.model import TopologyGraph
from infra_agent.tools.registry import tool


def _graph() -> TopologyGraph:
    return service.load_graph()


def _fresh(graph: TopologyGraph, payload: dict[str, Any]) -> dict[str, Any]:
    """Every answer says how old the graph behind it is."""
    return {**payload, "graph": service.freshness(graph)}


def _unknown(object_id: str, graph: TopologyGraph) -> dict[str, Any]:
    return {
        "found": False,
        "object_id": object_id,
        "graph": service.freshness(graph),
        "hint": "use a node id like device:sw-core-01, vm:mgmt-01, vlan:20 or "
        "interface:sw-core-01:GigabitEthernet1/0/1",
        "known_kinds": sorted({str(d.get("kind")) for _n, d in graph.g.nodes(data=True)}),
    }


@tool("topology")
def neighbors(object_id: str) -> dict[str, Any]:
    """Everything adjacent to an object, with the evidence for each relation."""
    graph = _graph()
    node = graph.resolve(object_id)
    if node is None:
        return _unknown(object_id, graph)
    data = graph.node(node)
    return _fresh(
        graph,
        {
            "found": True,
            "object_id": node,
            "kind": data.get("kind"),
            "label": data.get("label"),
            "mgmt_path": bool(data.get("mgmt_path")),
            "neighbors": graph.neighbors(node),
        },
    )


@tool("topology")
def path(a: str, b: str) -> dict[str, Any]:
    """Shortest path between two objects, hop by hop with the edge evidence."""
    graph = _graph()
    source, target = graph.resolve(a), graph.resolve(b)
    if source is None:
        return _unknown(a, graph)
    if target is None:
        return _unknown(b, graph)
    return _fresh(graph, {"from": source, "to": target, **graph.path_detail(source, target)})


@tool("topology")
def impact_analyze(object_id: str) -> dict[str, Any]:
    """What breaks if this object is lost: connectivity losses, redundancy
    losses and the escalation flags that decide a change's risk tier."""
    graph = _graph()
    return _fresh(graph, _impact_analyze(object_id, graph).as_dict())


@tool("topology")
def findings() -> dict[str, Any]:
    """Consistency findings: trunk VLAN mismatches, portgroup VLANs the uplink
    feeding their host does not carry, duplicate IPs, disconnected vNICs, and
    snapshot sections the collectors could not parse."""
    return _fresh(
        _graph(), {"findings": [f.model_dump(mode="json") for f in service.load_findings()]}
    )


@tool("topology")
def render(diagram: str = "physical", vlan: int | None = None) -> str:
    """Mermaid text for a topology view: `physical`, `storage`, `applications`
    (services, the ports they listen on and what depends on them), or `vlan`
    with a vlan id."""
    return _render(_graph(), diagram=diagram, vlan=vlan)


@tool("topology")
def summary() -> dict[str, Any]:
    """Size and shape of the current graph: nodes and edges per kind."""
    graph = _graph()
    return _fresh(graph, graph.summary())
