"""Topology and dependency graph (Phase 2).

`GraphBuilder` turns collector snapshots into a `TopologyGraph` of typed nodes
and evidence-bearing edges; `run_checks` audits it; `impact_analyze` answers
"what breaks if this dies" and feeds the computed risk tier; `mermaid` renders
`docs/topology/`.

Everything here reads *parsed* snapshot rows. Where a collector cannot give the
correlator what it needs, the graph says so (`collector_parse_gap` findings,
`topology.findings`) rather than presenting a smaller estate as a healthy one.
Three such gaps are open, each owned by a collector rather than by this package:

* **Cisco, `show interfaces trunk`** — ntc-templates ships no template for it
  (verified against 9.2.0), so `parse_output` returns `[]` on `cisco_ios` and
  the raw text is lost. VLANs on trunks are derived from `show spanning-tree`
  instead, which is one instance per carried VLAN, and the raw text is parsed
  when a collector stores it. Adding `show interfaces switchport` to
  `infra_agent/collectors/cisco.py` would give the allowed list directly; this
  builder already consumes a `switchport` section when one appears.
* **Cisco IOS-XE** — ntc-templates has no `cisco_xe` templates at all, so a
  `CiscoIOSXECollector` snapshot is raw text end to end and yields a device
  with no ports. IOS-XE output parses under `cisco_ios`; until the collector
  switches platform, those switches raise a parse gap per section.
* **FortiGate hardware switch** — `cmdb/system/interface` does not return the
  member list, so a 60F's `internal1..internal5` are matched to their `internal`
  parent by the naming FortiOS enforces. `cmdb/system/virtual-switch` would make
  that exact; a `member` list on the parent row is used when one appears.
"""

from infra_agent.correlate.builder import GraphBuilder, build_graph
from infra_agent.correlate.checks import Finding, run_checks
from infra_agent.correlate.impact import (
    AffectedObject,
    DependencyIndex,
    ImpactReport,
    default_action,
    impact_analyze,
    impact_summary,
)
from infra_agent.correlate.mermaid import (
    render,
    render_physical,
    render_storage,
    render_vlan,
    write_docs,
)
from infra_agent.correlate.model import (
    EdgeKind,
    Evidence,
    NodeKind,
    TopologyGraph,
)
from infra_agent.correlate.service import (
    build_and_persist,
    freshness,
    graph_path,
    load_findings,
    load_graph,
    persist,
    render_docs,
)

__all__ = [
    "AffectedObject",
    "DependencyIndex",
    "EdgeKind",
    "Evidence",
    "Finding",
    "GraphBuilder",
    "ImpactReport",
    "NodeKind",
    "TopologyGraph",
    "build_and_persist",
    "build_graph",
    "default_action",
    "freshness",
    "graph_path",
    "impact_analyze",
    "impact_summary",
    "load_findings",
    "load_graph",
    "persist",
    "render",
    "render_docs",
    "render_physical",
    "render_storage",
    "render_vlan",
    "run_checks",
    "write_docs",
]
