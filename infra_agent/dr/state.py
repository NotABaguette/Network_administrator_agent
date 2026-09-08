"""What the platform remembers about its own disaster recovery.

`data_dir/dr-state.json` is small, boring and shared: the nightly export writes
it, the weekly verify updates it, and every process that starts a metrics
server republishes it. Without a file the DR gauges would be per-process, so
the collectors container would report "never exported" forever because the
export ran in the agent container, and `DRExportStale` would fire every night.

Nothing secret goes in here. The target is stored as the operator wrote it
(`user@host:/path`), which is a destination, not a credential: the runbook
requires key auth, and a target string carrying a password would be a
misconfiguration to fix rather than a field to redact.
"""

from __future__ import annotations

import logging
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from infra_agent.config import Settings, get_settings
from infra_agent.monitoring import metrics

log = logging.getLogger(__name__)


class DRState(BaseModel):
    last_export_at: datetime | None = None
    last_export_bundle: str | None = None
    last_export_bytes: int | None = None
    last_export_ok: bool | None = None
    last_export_error: str | None = None
    last_push_at: datetime | None = None
    last_push_target: str | None = None
    last_verify_at: datetime | None = None
    last_verify_bundle: str | None = None
    last_verify_ok: bool | None = None
    last_verify_detail: str | None = None

    def age_seconds(self, field: str, now: datetime | None = None) -> float | None:
        value = getattr(self, field, None)
        if not isinstance(value, datetime):
            return None
        moment = now or datetime.now(UTC)
        return (moment - value).total_seconds()


def state_path(settings: Settings | None = None) -> Path:
    return (settings or get_settings()).dr_state_file


def load(settings: Settings | None = None) -> DRState:
    path = state_path(settings)
    try:
        if not path.exists():
            return DRState()
        return DRState.model_validate_json(path.read_text())
    except Exception:
        log.exception("could not read %s; treating DR history as unknown", path)
        return DRState()


def save(state: DRState, settings: Settings | None = None) -> Path:
    """Atomic write: a half-written state file reads as 'never exported'."""
    path = state_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w", dir=path.parent, prefix=path.name, suffix=".tmp", delete=False
    )
    try:
        with handle as out:
            out.write(state.model_dump_json(indent=1))
            out.flush()
            os.fsync(out.fileno())
        os.replace(handle.name, path)
    except BaseException:
        Path(handle.name).unlink(missing_ok=True)
        raise
    publish_metrics(state)
    return path


def update(settings: Settings | None = None, **fields: object) -> DRState:
    state = load(settings)
    state = state.model_copy(update=fields)
    save(state, settings)
    return state


#: Gauge name -> what it reads, and what it reads when nothing is known. The
#: "never" conventions live here because two modules depend on them: a
#: timestamp that has never been recorded is 0, so `time() - <gauge>` is
#: enormous and the staleness alert fires; `last_verify_ok` is 1 until a
#: verification has actually failed, so DRVerifyFailed means a failure rather
#: than "nobody has run one" (that is DRVerifyStale).
GAUGE_DEFAULTS = {
    "last_export": 0.0,
    "last_export_bytes": 0.0,
    "last_push": 0.0,
    "last_verify": 0.0,
    "last_verify_ok": 1.0,
    "configured": 0.0,
}


def gauge_value(name: str, settings: Settings | None = None) -> float:
    """One DR gauge, read from `dr-state.json` at scrape time.

    Called from `infra_agent.monitoring.metrics` through a lazy import, so the
    gauges can be armed while this module is still being imported - which is
    what happens whenever something imports `infra_agent.dr` before it imports
    the metrics module.
    """
    if name == "configured":
        return _configured(settings)
    current = load(settings)
    if name == "last_export":
        return _stamp(current.last_export_at)
    if name == "last_export_bytes":
        return float(current.last_export_bytes or 0)
    if name == "last_push":
        return _stamp(current.last_push_at)
    if name == "last_verify":
        return _stamp(current.last_verify_at)
    if name == "last_verify_ok":
        return _verify_ok(current)
    raise KeyError(f"no DR gauge called {name!r}")


def publish_metrics(state: DRState | None = None, settings: Settings | None = None) -> None:
    """Mirror the state file into the DR gauges once.

    `arm_metrics` is the version that keeps mirroring; this one is for
    processes and tests that only want the current value.
    """
    state = state if state is not None else load(settings)
    metrics.DR_LAST_EXPORT.set(_stamp(state.last_export_at))
    metrics.DR_BUNDLE_BYTES.set(float(state.last_export_bytes or 0))
    metrics.DR_STANDBY_LAST_SYNC.set(_stamp(state.last_push_at))
    metrics.DR_LAST_VERIFY.set(_stamp(state.last_verify_at))
    metrics.DR_LAST_VERIFY_OK.set(_verify_ok(state))
    metrics.DR_CONFIGURED.set(_configured(settings))


def arm_metrics(settings: Settings | None = None) -> None:
    """Make the DR gauges read `dr-state.json` at scrape time.

    Four containers expose `/metrics` and only one of them runs the export, so
    a gauge set in memory is right in one process and permanently wrong in the
    other three - `DRExportStale` would fire from the collectors every night
    while the export is working perfectly. Reading the shared file per scrape
    costs one `stat` a minute and makes every process give the same answer.

    Two conventions make the alert expressions honest about "never":

    * a timestamp that has never been recorded reads as 0, so
      `time() - <gauge>` is enormous and the staleness alert fires;
    * `infra_dr_last_verify_ok` reads as 1 until a verification has actually
      failed, so `DRVerifyFailed` means "a verification failed", not "nobody
      has run one". That second case is `DRVerifyStale`.
    """
    for gauge, name in metrics.DR_GAUGES:
        gauge.set_function(_reader(name, settings))


def _reader(name: str, settings: Settings | None):
    def read() -> float:
        return gauge_value(name, settings)

    return read


def _stamp(value: datetime | None) -> float:
    return value.timestamp() if isinstance(value, datetime) else 0.0


def _verify_ok(state: DRState) -> float:
    return 0.0 if state.last_verify_ok is False else 1.0


def _configured(settings: Settings | None) -> float:
    """1 when this platform has somewhere to export to.

    Read at scrape time rather than at start-up so a target added to
    `deploy/.env` takes effect on the next restart of anything, and so the
    gauge is honest in a process that never loaded the settings.
    """
    try:
        current = settings or get_settings()
        return 1.0 if current.dr_target else 0.0
    except Exception:  # noqa: BLE001 - unreadable settings are not "configured"
        return 0.0
