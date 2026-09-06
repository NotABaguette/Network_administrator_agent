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


# ---------------------------------------------------------------------------
# Phase 1 collector gauges.
#
# Health gauges use one scale everywhere: 1 = OK, 0.5 = warning / degraded /
# non-redundant, 0 = critical / failed. A subsystem the device does not report
# simply has no series, so `< 1` alert expressions never fire on absent data.
# ---------------------------------------------------------------------------

HEALTH_OK = 1.0
HEALTH_WARNING = 0.5
HEALTH_CRITICAL = 0.0

# -- ESXi (infra_agent/collectors/esxi.py) ----------------------------------
ESXI_HOST_CPU_USAGE_RATIO = Gauge(
    "infra_esxi_host_cpu_usage_ratio",
    "ESXi host CPU usage as a fraction of total capacity",
    ["device"],
)
ESXI_HOST_MEMORY_USAGE_RATIO = Gauge(
    "infra_esxi_host_memory_usage_ratio",
    "ESXi host memory usage as a fraction of installed memory",
    ["device"],
)
ESXI_HOST_UPTIME_SECONDS = Gauge("infra_esxi_host_uptime_seconds", "ESXi host uptime", ["device"])
ESXI_DATASTORE_CAPACITY_BYTES = Gauge(
    "infra_esxi_datastore_capacity_bytes", "Datastore capacity", ["device", "datastore"]
)
ESXI_DATASTORE_FREE_BYTES = Gauge(
    "infra_esxi_datastore_free_bytes", "Datastore free space", ["device", "datastore"]
)
ESXI_VM_POWER_STATE = Gauge(
    "infra_esxi_vm_power_state", "1 when the VM is powered on, 0 otherwise", ["device", "vm"]
)
ESXI_VM_SNAPSHOT_AGE_SECONDS = Gauge(
    "infra_esxi_vm_snapshot_age_seconds", "Age of the oldest snapshot of a VM", ["device", "vm"]
)
ESXI_VM_SNAPSHOT_COUNT = Gauge(
    "infra_esxi_vm_snapshot_count", "Number of snapshots a VM carries", ["device", "vm"]
)
ESXI_PNIC_LINK_UP = Gauge(
    "infra_esxi_pnic_link_up", "1 when the physical uplink has link", ["device", "pnic"]
)

# -- iLO / Redfish (infra_agent/collectors/ilo.py) --------------------------
ILO_HEALTH_ROLLUP = Gauge(
    "infra_ilo_health_rollup",
    "Subsystem health rollup (1 OK, 0.5 warning, 0 critical)",
    ["device", "subsystem"],
)
ILO_TEMPERATURE_CELSIUS = Gauge(
    "infra_ilo_temperature_celsius", "Temperature sensor reading", ["device", "sensor"]
)
ILO_TEMPERATURE_CRITICAL_CELSIUS = Gauge(
    "infra_ilo_temperature_critical_celsius",
    "Upper critical threshold reported for the sensor",
    ["device", "sensor"],
)
ILO_FAN_PERCENT = Gauge(
    "infra_ilo_fan_percent", "Fan speed in percent of maximum", ["device", "fan"]
)
ILO_FAN_HEALTH = Gauge(
    "infra_ilo_fan_health", "Fan health (1 OK, 0.5 warning, 0 critical)", ["device", "fan"]
)
ILO_PSU_HEALTH = Gauge(
    "infra_ilo_psu_health",
    "Power supply health (1 OK, 0.5 warning, 0 critical)",
    ["device", "psu"],
)
ILO_PSU_OUTPUT_WATTS = Gauge(
    "infra_ilo_psu_output_watts",
    "Last power output reported by the power supply",
    ["device", "psu"],
)
ILO_POWER_CONSUMED_WATTS = Gauge("infra_ilo_power_consumed_watts", "Chassis power draw", ["device"])
ILO_DRIVE_HEALTH = Gauge(
    "infra_ilo_drive_health",
    "Physical drive health (1 OK, 0.5 warning, 0 critical)",
    ["device", "controller", "drive"],
)
ILO_LOGICAL_DRIVE_HEALTH = Gauge(
    "infra_ilo_logical_drive_health",
    "Logical drive health (1 OK, 0.5 warning, 0 critical)",
    ["device", "controller", "drive"],
)
ILO_CONTROLLER_HEALTH = Gauge(
    "infra_ilo_controller_health",
    "Storage controller health (1 OK, 0.5 warning, 0 critical)",
    ["device", "controller"],
)
ILO_ACTIVE_FAULTS = Gauge(
    "infra_ilo_active_faults", "Unrepaired IML entries above informational severity", ["device"]
)
