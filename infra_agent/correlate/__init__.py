"""Topology and dependency graph (Phase 2).

`GraphBuilder` turns collector snapshots into a `TopologyGraph` of typed nodes
and evidence-bearing edges; `run_checks` audits it; `impact_analyze` answers
"what breaks if this dies" and feeds the computed risk tier; `mermaid` renders
`docs/topology/`.
"""

from infra_agent.correlate.builder import GraphBuilder, build_graph
from infra_agent.correlate.checks import Finding, run_checks
from infra_agent.correlate.impact import (
    AffectedObject,
    DependencyIndex,
    ImpactReport,
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
