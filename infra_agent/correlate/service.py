"""Build, persist and load the topology graph.

The graph lives at `data_dir/graph/graph.json` with the findings next to it, so
the tool layer and the CLI answer questions from the last build instead of
re-reading every snapshot on every call.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from infra_agent.config import Settings, get_settings
from infra_agent.correlate.builder import GraphBuilder
from infra_agent.correlate.checks import Finding, run_checks
from infra_agent.correlate.mermaid import write_docs
from infra_agent.correlate.model import TopologyGraph
from infra_agent.models.common import SeedInventory
from infra_agent.store.snapshots import FileSnapshotStore

GRAPH_FILENAME = "graph.json"
FINDINGS_FILENAME = "findings.json"

_CACHE: dict[str, tuple[float, TopologyGraph]] = {}


def graph_path(settings: Settings | None = None) -> Path:
    return (settings or get_settings()).graph_dir / GRAPH_FILENAME


def findings_path(settings: Settings | None = None) -> Path:
    return (settings or get_settings()).graph_dir / FINDINGS_FILENAME


def build_graph(
    settings: Settings | None = None,
    *,
    store: FileSnapshotStore | None = None,
    inventory: SeedInventory | None = None,
    now: datetime | None = None,
) -> TopologyGraph:
    settings = settings or get_settings()
    store = store or FileSnapshotStore(settings.snapshot_dir)
    inventory = inventory if inventory is not None else SeedInventory.load(settings.seed_inventory)
    return GraphBuilder(store, inventory, settings=settings, now=now).build()


def persist(
    graph: TopologyGraph,
    settings: Settings | None = None,
    findings: list[Finding] | None = None,
) -> Path:
    settings = settings or get_settings()
    path = graph_path(settings)
    graph.save(path)
    findings = run_checks(graph) if findings is None else findings
    findings_path(settings).write_text(
        json.dumps([f.model_dump(mode="json") for f in findings], indent=1)
    )
    _CACHE.pop(str(path), None)
    return path


def build_and_persist(
    settings: Settings | None = None,
    *,
    store: FileSnapshotStore | None = None,
    inventory: SeedInventory | None = None,
) -> tuple[TopologyGraph, list[Finding], Path]:
    settings = settings or get_settings()
    graph = build_graph(settings, store=store, inventory=inventory)
    findings = run_checks(graph)
    path = persist(graph, settings, findings)
    return graph, findings, path


def load_graph(settings: Settings | None = None, *, rebuild: bool = True) -> TopologyGraph:
    """The persisted graph, rebuilt from snapshots when it is missing."""
    settings = settings or get_settings()
    path = graph_path(settings)
    if path.exists():
        stamp = path.stat().st_mtime
        cached = _CACHE.get(str(path))
        if cached and cached[0] == stamp:
            return cached[1]
        graph = TopologyGraph.load(path)
        _CACHE[str(path)] = (stamp, graph)
        return graph
    if not rebuild:
        return TopologyGraph()
    return build_graph(settings)


def load_findings(settings: Settings | None = None) -> list[Finding]:
    settings = settings or get_settings()
    path = findings_path(settings)
    if path.exists():
        return [Finding.model_validate(row) for row in json.loads(path.read_text())]
    return run_checks(load_graph(settings))


def render_docs(
    settings: Settings | None = None,
    graph: TopologyGraph | None = None,
    directory: Path | None = None,
) -> list[Path]:
    settings = settings or get_settings()
    graph = graph or load_graph(settings)
    target = directory or settings.topology_docs_dir
    return write_docs(graph, target, run_checks(graph))


def clear_cache() -> None:
    _CACHE.clear()


def summary(settings: Settings | None = None) -> dict[str, Any]:
    return load_graph(settings).summary()
