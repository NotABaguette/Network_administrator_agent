"""Runs collectors on their own intervals against the seed inventory (NetBox later).

Each collector kind gets its own APScheduler job at its declared interval (60 s
for the FortiGate, 300 s for ESXi, iLO and Cisco), so the 60F is polled once a
minute without dragging iLO4 along. After every round that produced changes the
topology graph is rebuilt and persisted so impact analysis never trails the
observed state by more than one interval.
"""

from __future__ import annotations

import logging

from infra_agent.collectors.base import COLLECTORS, Collector, get_collector, run_collector
from infra_agent.config import get_settings
from infra_agent.configstore.git_store import ConfigGitStore
from infra_agent.models.common import Credential, DeviceKind, SeedInventory
from infra_agent.monitoring.metrics import start_metrics_server
from infra_agent.onboarding.secrets import SecretsStore
from infra_agent.store.snapshots import FileSnapshotStore

log = logging.getLogger(__name__)


def _load_collectors() -> None:
    # Import side effects register collectors.
    from infra_agent.collectors import cisco, esxi, fortigate, guest, ilo  # noqa: F401


def _context():
    settings = get_settings()
    _load_collectors()
    return (
        settings,
        SeedInventory.load(settings.seed_inventory),
        SecretsStore(settings.secrets_dir),
        FileSnapshotStore(settings.snapshot_dir),
        ConfigGitStore(settings.config_repo),
    )


def run_once(kinds: set[DeviceKind] | None = None, *, rebuild_graph: bool = True) -> int:
    """Run the collectors for `kinds` (all when None) once. Returns the number of
    devices whose snapshot changed or whose config was committed."""
    settings, inv, secrets, store, cfg = _context()
    creds = secrets.read("devices") if secrets.available() else {}
    changed = 0
    for device in inv.devices:
        if kinds is not None and device.kind not in kinds:
            continue
        if device.kind not in COLLECTORS:
            log.info("no collector for %s (%s) yet", device.name, device.kind.value)
            continue
        raw = creds.get(device.credential_ref)
        if not raw:
            log.warning("no credential for %s", device.name)
            continue
        try:
            result = run_collector(
                get_collector(device.kind), device, Credential.model_validate(raw), store, cfg
            )
            log.info(
                "%s: %d changes, %d config commits, %.1fs",
                device.name,
                len(result.changes),
                len(result.config_commits),
                result.duration_seconds,
            )
            if result.changes or result.config_commits:
                changed += 1
            _correlate_config_commits(device.name, result.config_commits)
        except Exception:
            log.exception("collector failed for %s", device.name)
    if rebuild_graph and changed:
        _rebuild_graph()
    return changed


def _correlate_config_commits(device: str, commits: dict[str, str]) -> None:
    """Phase 4 hook: a config commit that no executed ChangePlan explains is an
    `UnapprovedConfigChange` - recorded, counted and paged by the change engine."""
    if not commits:
        return
    try:
        from infra_agent.change.engine import config_change_hook

        for correlation in config_change_hook(device, commits):
            if not correlation.matched:
                log.warning(
                    "unapproved config change on %s (%s)",
                    device,
                    correlation.commit_sha[:12],
                )
    except Exception:
        log.exception("config change correlation failed for %s", device)


def _rebuild_graph() -> None:
    try:
        from infra_agent.correlate.service import build_and_persist

        _graph, findings, path = build_and_persist()
        log.info("topology graph rebuilt: %s (%d findings)", path, len(findings))
    except Exception:
        log.exception("topology graph rebuild failed")


def _kinds_by_interval() -> dict[int, set[DeviceKind]]:
    groups: dict[int, set[DeviceKind]] = {}
    cls: type[Collector]
    for kind, cls in COLLECTORS.items():
        groups.setdefault(cls.interval_seconds, set()).add(kind)
    return groups


def run_forever() -> None:
    from apscheduler.schedulers.blocking import BlockingScheduler

    settings, *_ = _context()
    start_metrics_server(settings.metrics_port)
    sched = BlockingScheduler()
    for interval, kinds in sorted(_kinds_by_interval().items()):
        sched.add_job(
            run_once,
            "interval",
            seconds=interval,
            kwargs={"kinds": kinds},
            id=f"collect-{interval}s",
            max_instances=1,
            coalesce=True,
        )
        log.info("scheduled %s every %ds", ", ".join(sorted(k.value for k in kinds)), interval)
    run_once()
    sched.start()
