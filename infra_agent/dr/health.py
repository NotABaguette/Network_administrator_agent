"""`infra dr health`: is the platform itself in a state it could recover from?

Every other health view in this repo answers "is the estate healthy". This one
answers "is the administrator healthy" - the question nobody asks until the
morning the digest stops arriving. It reads only local state (snapshot files,
the plan store, the graph, the config repository, the secrets store, the DR
state file), so it works when Prometheus, NetBox and the Claude API are all
gone, which is exactly when it is worth running.

The report is structured and secret-free by construction: names, counts, ages
and booleans. Nothing here reads a credential value, a config file, or a plan
body, so the daily digest can carry it through the redaction gateway without
special handling.
"""

from __future__ import annotations

import logging
import subprocess
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from infra_agent.config import Settings, get_settings
from infra_agent.dr import state as dr_state
from infra_agent.monitoring import metrics

log = logging.getLogger(__name__)

#: A collector that has not succeeded in this long is an incident in itself.
STALE_SNAPSHOT_SECONDS = 3600
#: The graph is rebuilt after every collector round that changed anything.
STALE_GRAPH_SECONDS = 6 * 3600
#: The dead-man ping runs every five minutes.
STALE_HEARTBEAT_SECONDS = 900
#: Nightly export plus a missed night.
STALE_EXPORT_SECONDS = 36 * 3600
#: Weekly verify plus a missed week.
STALE_VERIFY_SECONDS = 14 * 24 * 3600

GitRunner = Callable[[Sequence[str]], tuple[int, str]]


class HealthCheck(BaseModel):
    name: str
    ok: bool
    detail: str = ""
    age_seconds: float | None = None

    def line(self) -> str:
        age = f" ({int(self.age_seconds)}s ago)" if self.age_seconds is not None else ""
        return f"{'ok  ' if self.ok else 'FAIL'} {self.name}{age}: {self.detail}"


class HealthReport(BaseModel):
    generated_at: datetime
    ok: bool = True
    frozen: bool = False
    checks: list[HealthCheck] = Field(default_factory=list)

    def failures(self) -> list[HealthCheck]:
        return [check for check in self.checks if not check.ok]

    def get(self, name: str) -> HealthCheck | None:
        return next((check for check in self.checks if check.name == name), None)

    def headline(self) -> str:
        bad = self.failures()
        if not bad:
            return f"platform healthy: {len(self.checks)} checks passed"
        return f"platform degraded: {', '.join(check.name for check in bad)}"

    def llm_view(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "ok": self.ok,
            "frozen": self.frozen,
            "headline": self.headline(),
            "checks": [check.model_dump() for check in self.checks],
        }


def health_report(
    settings: Settings | None = None,
    *,
    now: datetime | None = None,
    git_runner: GitRunner | None = None,
    heartbeat_age: float | None = None,
) -> HealthReport:
    settings = settings or get_settings()
    moment = now or datetime.now(UTC)
    report = HealthReport(generated_at=moment)
    report.frozen = _frozen(settings)
    report.checks = [
        _collectors(settings, moment),
        _plan_store(settings),
        _graph(settings, moment),
        _config_repo(settings, git_runner or _git),
        _secrets(settings),
        _heartbeat(moment, heartbeat_age),
        *_dr(settings, moment),
    ]
    report.ok = all(check.ok for check in report.checks)
    return report


def _frozen(settings: Settings) -> bool:
    from infra_agent.agent.freeze import marker_present

    return settings.frozen or marker_present(settings)


def _collectors(settings: Settings, now: datetime) -> HealthCheck:
    """Freshness of the newest snapshot per device, straight off the filesystem."""
    from infra_agent.models.common import SeedInventory
    from infra_agent.store.snapshots import FileSnapshotStore

    try:
        inventory = SeedInventory.load(settings.seed_inventory)
    except Exception as exc:  # noqa: BLE001 - an unloadable seed file is the finding
        return HealthCheck(name="collectors", ok=False, detail=f"seed inventory unreadable: {exc}")
    if not inventory.devices:
        return HealthCheck(
            name="collectors", ok=False, detail=f"no devices in {settings.seed_inventory}"
        )
    store = FileSnapshotStore(settings.snapshot_dir)
    oldest: float | None = None
    stale: list[str] = []
    for device in inventory.devices:
        age = _newest_snapshot_age(store, device, now)
        if age is None:
            stale.append(f"{device.name} (never)")
            continue
        oldest = age if oldest is None else max(oldest, age)
        if age > STALE_SNAPSHOT_SECONDS:
            stale.append(f"{device.name} ({int(age // 60)}m)")
    if stale:
        return HealthCheck(
            name="collectors",
            ok=False,
            detail=f"{len(stale)}/{len(inventory.devices)} devices stale: {', '.join(stale[:6])}",
            age_seconds=oldest,
        )
    return HealthCheck(
        name="collectors",
        ok=True,
        detail=f"{len(inventory.devices)} devices, newest snapshot per device within the hour",
        age_seconds=oldest,
    )


def _newest_snapshot_age(store: Any, device: Any, now: datetime) -> float | None:
    ages: list[float] = []
    directory = Path(store.root) / device.name
    collectors = (
        sorted(p.name for p in directory.iterdir() if p.is_dir()) if directory.exists() else []
    )
    for collector in collectors:
        snapshot = store.latest(device.name, collector)
        if snapshot is not None:
            ages.append((now - snapshot.taken_at).total_seconds())
    return min(ages) if ages else None


def _plan_store(settings: Settings) -> HealthCheck:
    path = settings.data_dir / "plans.db"
    if not path.exists():
        return HealthCheck(
            name="plan_store", ok=True, detail="no plans.db yet; it is created on first plan"
        )
    try:
        from infra_agent.change.store import PlanStore

        store = PlanStore(path)
        plans = store.list()
        pending = store.pending()
    except Exception as exc:  # noqa: BLE001 - an unopenable plan store is the finding
        return HealthCheck(name="plan_store", ok=False, detail=f"{type(exc).__name__}: {exc}")
    return HealthCheck(
        name="plan_store", ok=True, detail=f"{len(plans)} plans, {len(pending)} awaiting approval"
    )


def _graph(settings: Settings, now: datetime) -> HealthCheck:
    from infra_agent.correlate.service import graph_path

    path = graph_path(settings)
    if not path.exists():
        return HealthCheck(
            name="graph", ok=False, detail=f"no graph at {path}; run `infra graph build`"
        )
    try:
        from infra_agent.correlate.model import TopologyGraph

        graph = TopologyGraph.load(path)
        summary = graph.summary()
        built = graph.built_at
    except Exception as exc:  # noqa: BLE001
        return HealthCheck(name="graph", ok=False, detail=f"{type(exc).__name__}: {exc}")
    age = (now - built).total_seconds() if built else None
    if age is not None and age > STALE_GRAPH_SECONDS:
        return HealthCheck(
            name="graph",
            ok=False,
            detail=f"built {int(age // 3600)}h ago; impact analysis is answering from stale data",
            age_seconds=age,
        )
    return HealthCheck(
        name="graph",
        ok=True,
        detail=f"{summary.get('nodes')} nodes, {summary.get('edges')} edges",
        age_seconds=age,
    )


def _config_repo(settings: Settings, runner: GitRunner) -> HealthCheck:
    repo = settings.config_repo
    if not (repo / ".git").exists():
        return HealthCheck(name="config_repo", ok=False, detail=f"{repo} is not a git repository")
    code, output = runner(["git", "-C", str(repo), "fsck", "--no-progress"])
    if code != 0:
        return HealthCheck(name="config_repo", ok=False, detail=f"fsck failed: {_tail(output)}")
    code, count = runner(["git", "-C", str(repo), "rev-list", "--count", "--all"])
    return HealthCheck(
        name="config_repo",
        ok=True,
        detail=f"fsck clean, {count.strip() if code == 0 else '?'} commits",
    )


def _secrets(settings: Settings) -> HealthCheck:
    """Can the platform still open its own secrets? Names and counts only."""
    try:
        from infra_agent.onboarding.secrets import SecretsStore

        store = SecretsStore(settings.secrets_dir)
        if not store.available():
            return HealthCheck(
                name="secrets",
                ok=False,
                detail="sops or the age key is missing; nothing can be decrypted on this host",
            )
        files = sorted(p.name for p in settings.secrets_dir.glob("*.enc.yaml"))
        counts = {
            name.removesuffix(".enc.yaml"): len(store.keys(name.removesuffix(".enc.yaml")))
            for name in files
        }
    except Exception as exc:  # noqa: BLE001 - never leak what failed to decrypt
        return HealthCheck(
            name="secrets", ok=False, detail=f"decryption failed ({type(exc).__name__})"
        )
    if not counts:
        return HealthCheck(
            name="secrets", ok=False, detail=f"no *.enc.yaml in {settings.secrets_dir}"
        )
    detail = ", ".join(f"{name}: {n} keys" for name, n in sorted(counts.items()))
    return HealthCheck(name="secrets", ok=True, detail=detail)


def _heartbeat(now: datetime, override: float | None) -> HealthCheck:
    """Age of the dead-man ping.

    The gauge lives in whichever process sends the ping (the agent service), so
    from the CLI it usually reads as never-sent. That is reported as unknown,
    not as failure: `HeartbeatNotSent` in Prometheus is the authority, and this
    check exists for the digest, which runs in the process that does the ping.
    """
    age = override if override is not None else _gauge_age(metrics.HEARTBEAT_LAST_OK, now)
    if age is None:
        return HealthCheck(
            name="heartbeat",
            ok=True,
            detail="no ping recorded in this process; Prometheus HeartbeatNotSent is authoritative",
        )
    if age > STALE_HEARTBEAT_SECONDS:
        return HealthCheck(
            name="heartbeat",
            ok=False,
            detail=f"last successful ping {int(age // 60)}m ago",
            age_seconds=age,
        )
    return HealthCheck(name="heartbeat", ok=True, detail=f"pinged {int(age)}s ago", age_seconds=age)


def _gauge_age(gauge: Any, now: datetime) -> float | None:
    try:
        for metric in gauge.collect():
            for sample in metric.samples:
                if sample.value:
                    return now.timestamp() - float(sample.value)
    except Exception:  # noqa: BLE001 - a gauge we cannot read is simply unknown
        return None
    return None


def _dr(settings: Settings, now: datetime) -> list[HealthCheck]:
    current = dr_state.load(settings)
    checks = []

    export_age = current.age_seconds("last_export_at", now)
    if export_age is None:
        checks.append(
            HealthCheck(name="dr_export", ok=False, detail="no DR export has ever been recorded")
        )
    elif export_age > STALE_EXPORT_SECONDS:
        checks.append(
            HealthCheck(
                name="dr_export",
                ok=False,
                detail=f"newest bundle {current.last_export_bundle} is "
                f"{int(export_age // 3600)}h old",
                age_seconds=export_age,
            )
        )
    else:
        detail = f"{current.last_export_bundle}"
        if current.last_push_target:
            detail += f" -> {current.last_push_target}"
        if current.last_export_ok is False:
            detail += f" (incomplete: {current.last_export_error})"
        checks.append(
            HealthCheck(
                name="dr_export",
                ok=current.last_export_ok is not False,
                detail=detail,
                age_seconds=export_age,
            )
        )

    verify_age = current.age_seconds("last_verify_at", now)
    if verify_age is None:
        checks.append(
            HealthCheck(
                name="dr_verify",
                ok=False,
                detail="no bundle has ever been verified; `infra dr verify` proves the backup",
            )
        )
    elif current.last_verify_ok is False:
        checks.append(
            HealthCheck(
                name="dr_verify",
                ok=False,
                detail=f"{current.last_verify_bundle} failed: {current.last_verify_detail}",
                age_seconds=verify_age,
            )
        )
    elif verify_age > STALE_VERIFY_SECONDS:
        checks.append(
            HealthCheck(
                name="dr_verify",
                ok=False,
                detail=f"last verified {int(verify_age // 86400)} days ago",
                age_seconds=verify_age,
            )
        )
    else:
        checks.append(
            HealthCheck(
                name="dr_verify",
                ok=True,
                detail=f"{current.last_verify_bundle} verified",
                age_seconds=verify_age,
            )
        )
    return checks


def _git(argv: Sequence[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(list(argv), capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        return 127, "git is not installed on this host"
    except subprocess.TimeoutExpired:
        return 124, "git timed out"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _tail(text: str, limit: int = 200) -> str:
    cleaned = " ".join(text.split())
    return cleaned[-limit:] if len(cleaned) > limit else cleaned
