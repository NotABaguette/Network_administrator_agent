"""Typed topology nodes, evidence-bearing edges and JSON persistence.

Every node carries a `kind` from `NodeKind`. Every edge carries the evidence
that produced it: the edge `kind`, the `collector` that observed it, the
`device` the observation came from, `observed_at` (ISO-8601 UTC) and a
`confidence` in [0, 1].

Nothing here talks to a device, and nothing here holds raw configuration: the
graph is built from parsed snapshot rows only, so it is safe to hand to the
redaction gateway.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import networkx as nx
from pydantic import BaseModel, Field

GRAPH_FORMAT_VERSION = 1


class NodeKind(StrEnum):
    device = "device"
    interface = "interface"
    vlan = "vlan"
    vswitch = "vswitch"
    portgroup = "portgroup"
    vm = "vm"
    vnic = "vnic"
    datastore = "datastore"
    logical_drive = "logical_drive"
    physical_drive = "physical_drive"
    prefix = "prefix"
    ip = "ip"
    fw_policy = "fw_policy"
    wan_link = "wan_link"
    # Phase 5, the application layer inside the guests
    # (`infra_agent/correlate/guest.py`).
    service = "service"
    listener = "listener"
    certificate = "certificate"
    external_endpoint = "external_endpoint"


class EdgeKind(StrEnum):
    """How two objects relate. Direction is dependent -> provider where that
    makes sense and container -> contained otherwise."""

    has_interface = "has_interface"  # device -> interface
    l1_neighbor = "l1_neighbor"  # interface -> interface (CDP/LLDP)
    access_vlan = "access_vlan"  # interface -> vlan (untagged)
    trunk_vlan = "trunk_vlan"  # interface -> vlan (allowed on a trunk)
    svi_for = "svi_for"  # interface -> vlan (SVI / FortiGate VLAN interface)
    mac_seen_on = "mac_seen_on"  # vnic -> interface (switch MAC table)
    attached_to = "attached_to"  # vnic -> portgroup
    portgroup_on = "portgroup_on"  # portgroup -> vswitch
    portgroup_vlan = "portgroup_vlan"  # portgroup -> vlan
    uplink_of = "uplink_of"  # vswitch -> interface (host pNIC)
    has_vnic = "has_vnic"  # vm -> vnic
    runs_on = "runs_on"  # vm -> device (ESXi host)
    has_ip = "has_ip"  # vnic|interface -> ip
    in_prefix = "in_prefix"  # ip -> prefix
    gateway_for = "gateway_for"  # interface -> prefix
    references = "references"  # fw_policy -> ip|prefix|interface
    stored_on = "stored_on"  # vm -> datastore
    backed_by = "backed_by"  # datastore -> logical_drive
    spans = "spans"  # logical_drive -> physical_drive
    wan_uplink = "wan_uplink"  # interface -> wan_link
    manages = "manages"  # iLO device -> host device
    subinterface_of = "subinterface_of"  # VLAN subinterface -> parent interface
    switch_member_of = "switch_member_of"  # member port -> FortiGate hardware switch
    # Phase 5, the application layer inside the guests.
    guest_of = "guest_of"  # guest device (SSH/WinRM endpoint) -> the VM it is
    runs_service = "runs_service"  # vm|device -> service
    listens_on = "listens_on"  # service -> listener (a port it answers on)
    connects_to = "connects_to"  # service|vm -> listener|device it depends on
    has_certificate = "has_certificate"  # vm|listener -> certificate


# --- node identifiers ------------------------------------------------------


def device_id(name: str) -> str:
    return f"device:{name}"


def interface_id(device: str, name: str) -> str:
    return f"interface:{device}:{name}"


def vlan_id(vlan: int | str) -> str:
    return f"vlan:{vlan}"


def vswitch_id(host: str, name: str) -> str:
    return f"vswitch:{host}:{name}"


def portgroup_id(host: str, name: str) -> str:
    return f"portgroup:{host}:{name}"


def vm_id(name: str) -> str:
    return f"vm:{name}"


def vnic_id(vm: str, label: str) -> str:
    return f"vnic:{vm}:{label}"


def datastore_id(host: str, name: str) -> str:
    return f"datastore:{host}:{name}"


def logical_drive_id(device: str, ident: str) -> str:
    return f"logical_drive:{device}:{ident}"


def physical_drive_id(device: str, location: str) -> str:
    return f"physical_drive:{device}:{location}"


def prefix_id(prefix: str) -> str:
    return f"prefix:{prefix}"


def ip_id(address: str) -> str:
    return f"ip:{address}"


def fw_policy_id(device: str, policy: str | int) -> str:
    return f"fw_policy:{device}:{policy}"


def wan_link_id(device: str, name: str) -> str:
    return f"wan_link:{device}:{name}"


def service_id(guest: str, name: str) -> str:
    return f"service:{guest}:{name}"


def listener_id(guest: str, proto: str, port: int | str) -> str:
    return f"listener:{guest}:{proto}/{port}"


def certificate_id(guest: str, subject: str) -> str:
    return f"certificate:{guest}:{subject}"


def external_endpoint_id(network: str) -> str:
    return f"external_endpoint:{network}"


def node_kind_of(node_id: str) -> str:
    return node_id.split(":", 1)[0]


def iso(when: datetime) -> str:
    return when.astimezone(UTC).isoformat()


def atomic_write(path: Path, text: str) -> Path:
    """Replace `path` in one step.

    The MCP server and the CLI read `graph.json`, `findings.json` and the
    rendered docs while `infra graph build` rewrites them; a plain write lets a
    reader see a half-written file and every `topology.*` call fails until the
    next build.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
    )
    try:
        with tmp as handle:
            handle.write(text)
        os.replace(tmp.name, path)
    except BaseException:
        Path(tmp.name).unlink(missing_ok=True)
        raise
    return path


# --- evidence --------------------------------------------------------------


class Evidence(BaseModel):
    """Why an edge exists. Flattened onto every edge in the graph."""

    collector: str
    device: str | None = None
    observed_at: str = Field(default_factory=lambda: iso(datetime.now(UTC)))
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    stale: bool = False
    note: str | None = None

    def as_attrs(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


# --- graph -----------------------------------------------------------------


class TopologyGraph:
    """A `networkx.MultiDiGraph` with typed nodes and evidence-bearing edges.

    Edges are keyed by their `kind`, so re-observing the same relation refreshes
    the evidence instead of duplicating the edge; the highest-confidence
    observation wins.
    """

    def __init__(
        self,
        graph: nx.MultiDiGraph | None = None,
        built_at: datetime | None = None,
    ) -> None:
        self.g: nx.MultiDiGraph = graph if graph is not None else nx.MultiDiGraph()
        self.built_at = built_at or datetime.now(UTC)

    # -- mutation -----------------------------------------------------------
    def add_node(
        self, node_id: str, kind: NodeKind | str, label: str | None = None, **attrs: Any
    ) -> str:
        kind = NodeKind(kind)
        existing = self.g.nodes.get(node_id)
        if existing is None:
            self.g.add_node(
                node_id,
                kind=str(kind),
                label=label or node_id.split(":", 1)[-1],
                mgmt_path=False,
                **attrs,
            )
            return node_id
        if label:
            existing["label"] = label
        for key, value in attrs.items():
            if value is not None or key not in existing:
                existing[key] = value
        return node_id

    def add_edge(
        self,
        source: str,
        target: str,
        kind: EdgeKind | str,
        evidence: Evidence,
        **attrs: Any,
    ) -> None:
        if source not in self.g or target not in self.g:
            raise KeyError(f"both endpoints must exist before adding {kind}: {source} -> {target}")
        key = str(EdgeKind(kind))
        data = {"kind": key, **evidence.as_attrs(), **attrs}
        current = self.g.get_edge_data(source, target, key=key)
        if current is not None and current.get("confidence", 0.0) > data["confidence"]:
            current.update({k: v for k, v in attrs.items() if v is not None})
            return
        self.g.add_edge(source, target, key=key, **data)

    def mark_mgmt_path(self, node_ids: Iterable[str]) -> None:
        for node_id in node_ids:
            if node_id in self.g:
                self.g.nodes[node_id]["mgmt_path"] = True

    # -- queries ------------------------------------------------------------
    def __contains__(self, node_id: object) -> bool:
        return node_id in self.g

    def __len__(self) -> int:
        return self.g.number_of_nodes()

    def node(self, node_id: str) -> dict[str, Any]:
        return dict(self.g.nodes[node_id])

    def has(self, node_id: str) -> bool:
        return node_id in self.g

    def nodes_of_kind(self, kind: NodeKind | str) -> list[str]:
        want = str(kind)
        return sorted(n for n, d in self.g.nodes(data=True) if d.get("kind") == want)

    def edges_of_kind(self, kind: EdgeKind | str) -> list[tuple[str, str, dict[str, Any]]]:
        want = str(kind)
        return [
            (u, v, dict(d))
            for u, v, k, d in self.g.edges(keys=True, data=True)
            if k == want or d.get("kind") == want
        ]

    def edge(self, source: str, target: str, kind: EdgeKind | str) -> dict[str, Any] | None:
        data = self.g.get_edge_data(source, target, key=str(kind))
        return dict(data) if data else None

    def out_edges(
        self, node_id: str, kind: EdgeKind | str | None = None
    ) -> Iterator[tuple[str, dict[str, Any]]]:
        want = str(kind) if kind is not None else None
        for _u, v, k, d in self.g.out_edges(node_id, keys=True, data=True):
            if want is None or k == want:
                yield v, dict(d)

    def in_edges(
        self, node_id: str, kind: EdgeKind | str | None = None
    ) -> Iterator[tuple[str, dict[str, Any]]]:
        want = str(kind) if kind is not None else None
        for u, _v, k, d in self.g.in_edges(node_id, keys=True, data=True):
            if want is None or k == want:
                yield u, dict(d)

    def neighbors(self, node_id: str) -> list[dict[str, Any]]:
        """Every adjacent object with its edge evidence, both directions."""
        rows = [
            self._neighbor_row(v, d, "out")
            for _u, v, _k, d in self.g.out_edges(node_id, keys=True, data=True)
        ]
        rows += [
            self._neighbor_row(u, d, "in")
            for u, _v, _k, d in self.g.in_edges(node_id, keys=True, data=True)
        ]
        rows.sort(key=lambda r: (str(r["edge"]["kind"]), r["id"]))
        return rows

    def _neighbor_row(self, other: str, data: dict[str, Any], direction: str) -> dict[str, Any]:
        node = self.g.nodes[other]
        return {
            "id": other,
            "kind": node.get("kind"),
            "label": node.get("label"),
            "mgmt_path": bool(node.get("mgmt_path")),
            "direction": direction,
            "edge": {
                "kind": data.get("kind"),
                "collector": data.get("collector"),
                "device": data.get("device"),
                "observed_at": data.get("observed_at"),
                "confidence": data.get("confidence"),
                "stale": data.get("stale", False),
            },
        }

    def undirected(self) -> nx.Graph:
        return nx.Graph(self.g)

    def path(self, a: str, b: str) -> list[str]:
        """Shortest undirected path between two objects ([] when unreachable)."""
        if a not in self.g or b not in self.g:
            return []
        try:
            return list(nx.shortest_path(self.undirected(), a, b))
        except nx.NetworkXNoPath:
            return []

    def path_detail(self, a: str, b: str) -> dict[str, Any]:
        nodes = self.path(a, b)
        hops: list[dict[str, Any]] = []
        for src, dst in zip(nodes, nodes[1:], strict=False):
            edges: list[dict[str, Any]] = []
            for first, second in ((src, dst), (dst, src)):
                for _u, target, _k, d in self.g.out_edges(first, keys=True, data=True):
                    if target == second:
                        edges.append(
                            {
                                "kind": d.get("kind"),
                                "from": first,
                                "to": second,
                                "collector": d.get("collector"),
                                "observed_at": d.get("observed_at"),
                                "confidence": d.get("confidence"),
                            }
                        )
            hops.append({"from": src, "to": dst, "edges": edges})
        return {
            "found": bool(nodes),
            "nodes": [
                {
                    "id": n,
                    "kind": self.g.nodes[n].get("kind"),
                    "label": self.g.nodes[n].get("label"),
                    "mgmt_path": bool(self.g.nodes[n].get("mgmt_path")),
                }
                for n in nodes
            ],
            "hops": hops,
        }

    def mgmt_path_nodes(self) -> list[str]:
        return sorted(n for n, d in self.g.nodes(data=True) if d.get("mgmt_path"))

    def resolve(self, ref: str) -> str | None:
        """Best-effort lookup of a node from a loose reference: an exact id, a
        device or VM name, a VLAN number, or a unique `<name>` suffix."""
        if ref in self.g:
            return ref
        for candidate in (device_id(ref), vm_id(ref), vlan_id(ref), prefix_id(ref), ip_id(ref)):
            if candidate in self.g:
                return candidate
        lowered = ref.lower()
        by_suffix = [n for n in self.g if n.lower().endswith(f":{lowered}")]
        if len(by_suffix) == 1:
            return by_suffix[0]
        by_label = [
            n for n, d in self.g.nodes(data=True) if str(d.get("label", "")).lower() == lowered
        ]
        if len(by_label) == 1:
            return by_label[0]
        return None

    def summary(self) -> dict[str, Any]:
        nodes_by_kind: dict[str, int] = {}
        for _n, d in self.g.nodes(data=True):
            key = str(d.get("kind", "?"))
            nodes_by_kind[key] = nodes_by_kind.get(key, 0) + 1
        edges_by_kind: dict[str, int] = {}
        for _u, _v, k in self.g.edges(keys=True):
            edges_by_kind[k] = edges_by_kind.get(k, 0) + 1
        return {
            "built_at": iso(self.built_at),
            "nodes": self.g.number_of_nodes(),
            "edges": self.g.number_of_edges(),
            "nodes_by_kind": dict(sorted(nodes_by_kind.items())),
            "edges_by_kind": dict(sorted(edges_by_kind.items())),
            "mgmt_path_nodes": len(self.mgmt_path_nodes()),
        }

    # -- persistence --------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "version": GRAPH_FORMAT_VERSION,
            "built_at": iso(self.built_at),
            "graph": dict(sorted(self.g.graph.items())),
            "nodes": [
                {"id": n, **dict(sorted(d.items()))} for n, d in sorted(self.g.nodes(data=True))
            ],
            "edges": [
                {"source": u, "target": v, **dict(sorted(d.items()))}
                for u, v, _k, d in sorted(
                    self.g.edges(keys=True, data=True), key=lambda e: (e[0], e[1], e[2])
                )
            ],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> TopologyGraph:
        g = nx.MultiDiGraph()
        g.graph.update(payload.get("graph", {}))
        for node in payload.get("nodes", []):
            g.add_node(node["id"], **{k: v for k, v in node.items() if k != "id"})
        for edge in payload.get("edges", []):
            attrs = {k: v for k, v in edge.items() if k not in ("source", "target")}
            g.add_edge(edge["source"], edge["target"], key=attrs.get("kind"), **attrs)
        built_at = payload.get("built_at")
        return cls(g, built_at=datetime.fromisoformat(built_at) if built_at else None)

    def save(self, path: Path) -> Path:
        return atomic_write(path, json.dumps(self.to_dict(), indent=1))

    @classmethod
    def load(cls, path: Path) -> TopologyGraph:
        return cls.from_dict(json.loads(path.read_text()))
