"""Prometheus metrics for the platform itself. A stale collector is an alert."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, start_http_server

LABELS = ["collector", "device"]

COLLECTOR_LAST_SUCCESS = Gauge(
    "infra_collector_last_success_timestamp_seconds",
    "Unix time of the last successful collector run",
    LABELS,
)
COLLECTOR_ERRORS = Counter("infra_collector_errors_total", "Collector run failures", LABELS)
COLLECTOR_DURATION = Histogram(
    "infra_collector_duration_seconds",
    "Collector run duration",
    LABELS,
    buckets=(1, 5, 15, 30, 60, 120, 300),
)
SNAPSHOT_CHANGES = Gauge(
    "infra_snapshot_changes", "Structured changes between the last two snapshots", LABELS
)
CONFIG_COMMITS = Counter(
    "infra_config_commits_total", "Config backup commits (config changed)", LABELS
)

AGENT_RUNS = Counter(
    "infra_agent_runs_total", "Agent runs by kind and outcome", ["kind", "outcome"]
)
AGENT_TOOL_CALLS = Counter("infra_agent_tool_calls_total", "Tool calls made by the agent", ["tool"])
AGENT_TIER0_ACTIONS = Counter(
    "infra_agent_tier0_actions_total", "Tier 0 actions", ["action", "mode"]
)
HEARTBEAT_LAST_OK = Gauge(
    "infra_heartbeat_last_ok_timestamp_seconds", "Last successful dead-man heartbeat ping"
)
FROZEN = Gauge("infra_frozen", "1 when the break-glass freeze is active")


def start_metrics_server(port: int) -> None:
    start_http_server(port)
