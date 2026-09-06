"""Build, persist and load the topology graph.

The graph lives at `data_dir/graph/graph.json` with the findings next to it, so
the tool layer and the CLI answer questions from the last build instead of
re-reading every snapshot on every call.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from infra_agent.config import Settings, get_settings
from infra_agent.correlate.builder import GraphBuilder
from infra_agent.correlate.checks import Finding, run_checks
from infra_agent.correlate.mermaid import write_docs
from infra_agent.correlate.model import TopologyGraph, atomic_write, iso
from infra_agent.models.common import SeedInventory
from infra_agent.store.snapshots import FileSnapshotStore

log = logging.getLogger(__name__)

GRAPH_FILENAME = "graph.json"
FINDINGS_FILENAME = "findings.json"

#: A graph older than this is served with `stale: true`; the collectors run on
#: a five-minute cycle, so an hour means nothing has rebuilt it in twelve runs.
STALE_AFTER_SECONDS = 3600.0

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
    atomic_write(
        findings_path(settings),
        json.dumps([f.model_dump(mode="json") for f in findings], indent=1),
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
    """The persisted graph, rebuilt from snapshots (and kept) when it is missing."""
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
    graph = build_graph(settings)
    try:
        # Keep it: otherwise every topology.* call walks every snapshot again.
        persist(graph, settings)
    except OSError:  # a read-only data dir must not break a read-only tool
        log.warning("could not persist the rebuilt graph under %s", settings.graph_dir)
    return graph


def freshness(graph: TopologyGraph, now: datetime | None = None) -> dict[str, Any]:
    """How old the answer is — every tool result carries it.

    Nothing rebuilds the graph on a schedule yet (that hook belongs to the
    scheduler package), so a caller must be able to see that it is reading a
    picture from yesterday.
    """
    now = now or datetime.now(UTC)
    built_at = graph.built_at if graph.built_at.tzinfo else graph.built_at.replace(tzinfo=UTC)
    age = max(0.0, (now - built_at).total_seconds())
    return {
        "built_at": iso(built_at),
        "age_seconds": round(age, 1),
        "stale": age > STALE_AFTER_SECONDS,
    }


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
