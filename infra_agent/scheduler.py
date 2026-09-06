"""Runs collectors on their intervals against the seed inventory (NetBox later)."""

from __future__ import annotations

import logging

from infra_agent.collectors.base import COLLECTORS, get_collector, run_collector
from infra_agent.config import get_settings
from infra_agent.configstore.git_store import ConfigGitStore
from infra_agent.models.common import Credential, SeedInventory
from infra_agent.monitoring.metrics import start_metrics_server
from infra_agent.onboarding.secrets import SecretsStore
from infra_agent.store.snapshots import FileSnapshotStore

log = logging.getLogger(__name__)


def _load_collectors() -> None:
    # Import side effects register collectors.
    from infra_agent.collectors import cisco, esxi, fortigate, ilo  # noqa: F401


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


def run_once() -> None:
    settings, inv, secrets, store, cfg = _context()
    creds = secrets.read("devices") if secrets.available() else {}
    for device in inv.devices:
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
        except Exception:
            log.exception("collector failed for %s", device.name)


def run_forever() -> None:
    from apscheduler.schedulers.blocking import BlockingScheduler

    settings, *_ = _context()
    start_metrics_server(settings.metrics_port)
    sched = BlockingScheduler()
    interval = min((c.interval_seconds for c in COLLECTORS.values()), default=300)
    sched.add_job(run_once, "interval", seconds=interval, next_run_time=None, id="collect")
    run_once()
    sched.start()
