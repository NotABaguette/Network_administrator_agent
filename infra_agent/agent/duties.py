"""Scheduled duties: daily digest, weekly report, firmware inventory, heartbeat.

Each duty assembles a small, redacted context out of what the platform already
knows - collector metrics, snapshot ages, config-git commits, plan state - and
hands it to one bounded `AgentRunner` run. The model writes the prose; the
facts are computed here so a hallucinated number cannot become a report.

Nothing in this module changes anything. The digest may notice an unapproved
config change or a datastore about to fill, but acting on either is a
`ChangePlan` the owner approves.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import yaml

from infra_agent.agent.notify import LogNotifier, Notifier
from infra_agent.agent.runner import AgentRunner, AgentRunResult
from infra_agent.change.plan import ChangePlan, ChangeState
from infra_agent.change.store import PlanStore
from infra_agent.config import Settings, get_settings
from infra_agent.configstore.git_store import ConfigGitStore
from infra_agent.models.common import SeedDevice, SeedInventory
from infra_agent.redaction.gateway import RedactionGateway
from infra_agent.store.snapshots import FileSnapshotStore

log = logging.getLogger(__name__)

KNOWN_GOOD_VERSIONS = Path(__file__).with_name("known_good_versions.yaml")

STALE_SNAPSHOT_SECONDS = 3600
DATASTORE_WARN_DAYS = 30
DATASTORE_WARN_PERCENT = 15.0

#: Collector health has to come from Prometheus, not from this process's own
#: registry: `run_collector` sets these gauges inside the `infra-collectors`
#: container (`deploy/docker-compose.yml`), so in the agent the families exist
#: with no samples and a registry scan silently reports "nothing wrong".
COLLECTOR_QUERIES: dict[str, str] = {
    "last_success": "infra_collector_last_success_timestamp_seconds",
    "errors_last_24h": "increase(infra_collector_errors_total[24h])",
    "changes_last_run": "infra_snapshot_changes",
}

_VERSION_RE = re.compile(r"(\d+(?:\.\d+)+(?:\([0-9a-zA-Z]+\))?[0-9a-zA-Z.]*)")

#: Where each collector tends to record the running firmware version.
VERSION_PATHS: tuple[tuple[str, ...], ...] = (
    ("system", "version"),
    ("host", "version"),
    ("firmware", "current"),
    ("firmware", "version"),
    ("firmware", "ilo"),
    ("version",),
    ("resources", "version"),
)

DIGEST_TASK = """\
Write the owner's daily digest from the context below. Lead with anything that
needs a decision today, then the rest in one short section each: collector
health, stale snapshots, unapproved configuration changes, drift, and the
datastore forecast. Name devices explicitly. If a section has nothing to say,
say so in one line rather than padding it. If something in the context looks
wrong or missing, say that too - do not fill the gap with a guess. End with a
single recommended next action, or "nothing needed today".
"""

WEEKLY_TASK = """\
Write the weekly capacity and unused-objects report from the context below.
Cover: where capacity is actually running out (with the number and the date it
would matter), which objects look unused and are candidates for removal, and
which of those removals would be risky. Rank by what saves the owner the most
trouble. Anything you suggest removing is a proposal for a human, not a
decision - say what evidence would confirm it is genuinely unused.
"""

FIRMWARE_TASK = """\
Write the firmware inventory report from the context below. For every device,
state the running version and whether it matches the maintained known-good
list. Group the findings: matching, drifted, below minimum, unknown. For each
device that is not on a known-good version, say what the risk of leaving it is
and what an upgrade would need (firmware changes are Tier 2: maintenance
window, confirmation phrase, healthy heartbeat, OOB access for the edge).
Do not propose an upgrade plan unless the context shows the device is below
the minimum version.
"""


def _get(data: Any, path: Iterable[str]) -> Any:
    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def normalise_version(value: Any) -> str | None:
    """Pull a comparable version out of whatever the collector recorded."""
    if isinstance(value, list) and value:
        value = value[0]
    if isinstance(value, dict):
        for key in ("version", "running_image", "sw_version", "current"):
            if value.get(key):
                value = value[key]
                break
    if not isinstance(value, str):
        return None
    match = _VERSION_RE.search(value)
    return match.group(1) if match else None


def extract_version(data: dict[str, Any]) -> str | None:
    for path in VERSION_PATHS:
        found = normalise_version(_get(data, path))
        if found:
            return found
    return None


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version)) or (0,)


def load_known_good(path: Path | None = None) -> dict[str, Any]:
    target = path or KNOWN_GOOD_VERSIONS
    if not target.exists():
        return {}
    return yaml.safe_load(target.read_text()) or {}


def _as_plans(rows: Any) -> list[ChangePlan]:
    """`PlanStore.list` shadows the builtin inside its own class, so the store's
    declared return types do not survive type checking. Narrow them back here."""
    return cast("list[ChangePlan]", rows)


def _bytes_of(entry: dict[str, Any], *names: str) -> float | None:
    for name in names:
        value = entry.get(name)
        if isinstance(value, (int, float)):
            return float(value)
    return None


def datastores_of(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Datastore rows out of an ESXi snapshot, tolerant of the exact key spelling."""
    raw = data.get("datastores") or _get(data, ("storage", "datastores")) or []
    rows: list[dict[str, Any]] = []
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict):
            continue
        capacity = _bytes_of(entry, "capacity_bytes", "capacity", "capacity_gb")
        free = _bytes_of(entry, "free_bytes", "free_space", "free", "free_gb")
        if capacity is None or free is None:
            continue
        rows.append({"name": entry.get("name"), "capacity": capacity, "free": free})
    return rows


class Duties:
    """The scheduled work the agent does without being asked."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        runner: AgentRunner | None = None,
        notifier: Notifier | None = None,
        gateway: RedactionGateway | None = None,
        snapshots: FileSnapshotStore | None = None,
        plan_store: PlanStore | None = None,
        config_store: ConfigGitStore | None = None,
        inventory: Callable[[], SeedInventory] | None = None,
        metrics_query: Callable[[str], dict[str, Any]] | None = None,
        known_good: dict[str, Any] | None = None,
        drift_provider: Callable[[], dict[str, Any]] | None = None,
        heartbeat_url_provider: Callable[[], str | None] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.gateway = gateway or RedactionGateway(audit_log=self.settings.audit_log)
        self.runner = runner or AgentRunner(settings=self.settings, gateway=self.gateway)
        self.notifier = notifier or LogNotifier()
        self.snapshots = snapshots or FileSnapshotStore(self.settings.snapshot_dir)
        self.plans = plan_store or PlanStore(self.settings.data_dir / "plans.db")
        self.configs = config_store or ConfigGitStore(self.settings.config_repo)
        self._inventory = inventory or (lambda: SeedInventory.load(self.settings.seed_inventory))
        self._metrics_query = metrics_query
        #: An explicit list pins the baseline (tests); otherwise the maintained
        #: YAML is re-read on every run, which is what "maintained" implies.
        self._known_good = known_good
        self.drift_provider = drift_provider
        self.heartbeat_url_provider = heartbeat_url_provider
        self._now = now or (lambda: datetime.now(UTC))

    # -- shared plumbing ----------------------------------------------------
    def devices(self) -> list[SeedDevice]:
        return list(self._inventory().devices)

    def metrics_query(self, query: str) -> dict[str, Any]:
        """One instant PromQL query, through the same tool the model uses."""
        if self._metrics_query is not None:
            return self._metrics_query(query)
        from infra_agent.tools import observability_tools

        return observability_tools.promql(query=query)

    def known_good(self) -> dict[str, Any]:
        """The maintained known-good firmware list, re-read on every run."""
        if self._known_good is not None:
            return self._known_good
        try:
            return load_known_good()
        except Exception:
            log.exception("could not read %s", KNOWN_GOOD_VERSIONS)
            return {}

    def latest(self, device: SeedDevice) -> Any:
        for collector in (device.platform, device.kind.value):
            snapshot = self.snapshots.latest(device.name, collector)
            if snapshot is not None:
                return snapshot
        return None

    def _run(self, task: str, kind: str, context: dict[str, Any], title: str) -> AgentRunResult:
        result = self.runner.run(task, kind=kind, context=context)
        self.notifier.send_report(title, result.report)
        return result

    # -- context builders ---------------------------------------------------
    def collector_health(self) -> dict[str, Any]:
        """Freshness and error counts of the collectors, out of Prometheus.

        A silence here is never reported as health: if Prometheus cannot be
        reached, or has no `infra_collector_*` series at all, the digest says
        so. A stale collector is an incident in itself
        (`docs/architecture.md`), and so is not knowing.
        """
        now = self._now().timestamp()
        series: dict[str, dict[tuple[str, str], float]] = {}
        for name, query in COLLECTOR_QUERIES.items():
            try:
                answer = self.metrics_query(query)
            except Exception as exc:
                log.exception("collector health query %r failed", query)
                return self._collector_health_unavailable(f"{type(exc).__name__}: {exc}", query)
            if not isinstance(answer, dict) or answer.get("error"):
                reason = str((answer or {}).get("error", "no answer from Prometheus"))
                return self._collector_health_unavailable(reason, query)
            series[name] = _samples_by_collector(answer)
        keys = sorted(set().union(*(s.keys() for s in series.values())) if series else set())
        rows = []
        for key in keys:
            collector, device = key
            success = series.get("last_success", {}).get(key)
            rows.append(
                {
                    "collector": collector,
                    "device": device,
                    "age_seconds": int(now - success) if success else None,
                    "stale": success is None or (now - success) > STALE_SNAPSHOT_SECONDS,
                    "errors_last_24h": round(series.get("errors_last_24h", {}).get(key, 0.0), 2),
                    "changes_last_run": int(series.get("changes_last_run", {}).get(key, 0.0)),
                }
            )
        if not rows:
            return {
                "available": False,
                "source": "prometheus",
                "reason": (
                    "Prometheus has no infra_collector_* series: the collectors have not "
                    "reported since its retention window, or are not being scraped"
                ),
                "collectors": [],
            }
        return {"available": True, "source": "prometheus", "collectors": rows}

    @staticmethod
    def _collector_health_unavailable(reason: str, query: str) -> dict[str, Any]:
        return {
            "available": False,
            "source": "prometheus",
            "reason": f"could not query Prometheus ({reason}); query was {query!r}",
            "collectors": [],
        }

    def snapshot_ages(self) -> list[dict[str, Any]]:
        now = self._now()
        rows = []
        for device in self.devices():
            snapshot = self.latest(device)
            age = int((now - snapshot.taken_at).total_seconds()) if snapshot else None
            rows.append(
                {
                    "device": device.name,
                    "kind": device.kind.value,
                    "age_seconds": age,
                    "stale": age is None or age > STALE_SNAPSHOT_SECONDS,
                }
            )
        return rows

    def unapproved_config_changes(self, hours: int = 24) -> list[dict[str, Any]]:
        """Config-git commits in the window with no approved ChangePlan behind them."""
        since = self._now() - timedelta(hours=hours)
        approved = self._approved_plans(since - timedelta(hours=2))
        findings: list[dict[str, Any]] = []
        for device in self.devices():
            try:
                history = self.configs.history(device.name, limit=50)
            except Exception:
                log.exception("could not read the config store history for %s", device.name)
                continue
            for entry in history:
                when = _parse_time(entry.get("at"))
                if when is None or when < since:
                    continue
                match = next(
                    (
                        plan
                        for plan in approved
                        if device.name in plan.targets
                        and plan.approval is not None
                        and abs((plan.approval.at - when).total_seconds()) <= 7200
                    ),
                    None,
                )
                findings.append(
                    {
                        "device": device.name,
                        "sha": entry.get("sha", "")[:12],
                        "at": entry.get("at"),
                        "subject": entry.get("subject"),
                        "approved_plan": match.id if match else None,
                        "unapproved": match is None,
                    }
                )
        return findings

    def _approved_plans(self, since: datetime) -> list[ChangePlan]:
        wanted = {
            ChangeState.approved,
            ChangeState.executing,
            ChangeState.verifying,
            ChangeState.done,
        }
        try:
            plans = _as_plans(self.plans.list())
        except Exception:
            log.exception("could not read the plan store")
            return []
        return [
            plan
            for plan in plans
            if plan.state in wanted and plan.approval is not None and plan.approval.at >= since
        ]

    def pending_approvals(self) -> list[dict[str, Any]]:
        try:
            pending = _as_plans(self.plans.pending())
        except Exception:
            log.exception("could not read pending approvals")
            return []
        return [
            {
                "id": plan.id,
                "title": plan.title,
                "tier": int(plan.tier),
                "action": plan.action,
                "targets": plan.targets,
                "age_hours": int((self._now() - plan.created_at).total_seconds() // 3600),
            }
            for plan in pending
        ]

    def drift(self) -> dict[str, Any]:
        if self.drift_provider is None:
            return {"available": False, "reason": "NetBox reconciliation is not wired here yet"}
        try:
            return {"available": True, **self.drift_provider()}
        except Exception as exc:
            log.exception("drift provider failed")
            return {"available": False, "reason": f"{type(exc).__name__}: {exc}"}

    def datastore_forecast(self, window: int = 12) -> list[dict[str, Any]]:
        """Linear free-space forecast per datastore from the recent snapshot series."""
        rows: list[dict[str, Any]] = []
        for device in self.devices():
            history = self._history(device, limit=window)
            if not history:
                continue
            newest, oldest = history[0], history[-1]
            latest = {d["name"]: d for d in datastores_of(newest.data)}
            earliest = {d["name"]: d for d in datastores_of(oldest.data)}
            days = max((newest.taken_at - oldest.taken_at).total_seconds() / 86400, 0.0)
            for name, current in latest.items():
                capacity = current["capacity"] or 0.0
                free_pct = (current["free"] / capacity * 100) if capacity else None
                burn = None
                days_to_full = None
                before = earliest.get(name)
                if before is not None and days > 0:
                    burn = (before["free"] - current["free"]) / days
                    if burn > 0:
                        days_to_full = int(current["free"] / burn)
                rows.append(
                    {
                        "host": device.name,
                        "datastore": name,
                        "free_percent": round(free_pct, 1) if free_pct is not None else None,
                        "daily_burn_bytes": int(burn) if burn is not None else None,
                        "days_to_full": days_to_full,
                        "observed_over_days": round(days, 2),
                        "concerning": bool(
                            (free_pct is not None and free_pct < DATASTORE_WARN_PERCENT)
                            or (days_to_full is not None and days_to_full < DATASTORE_WARN_DAYS)
                        ),
                    }
                )
        return rows

    def _history(self, device: SeedDevice, limit: int) -> list[Any]:
        for collector in (device.platform, device.kind.value):
            history = self.snapshots.history(device.name, collector, limit=limit)
            if history:
                return history
        return []

    def capacity(self) -> list[dict[str, Any]]:
        """Coarse per-device capacity signals, from whatever the snapshot recorded."""
        rows: list[dict[str, Any]] = []
        for device in self.devices():
            snapshot = self.latest(device)
            if snapshot is None:
                continue
            data = snapshot.data
            row: dict[str, Any] = {"device": device.name, "kind": device.kind.value}
            resources = data.get("resources")
            if isinstance(resources, dict):
                row["resources"] = resources
            interfaces = data.get("interfaces_status")
            if isinstance(interfaces, list):
                states = [
                    str(i.get("status", "")).lower() for i in interfaces if isinstance(i, dict)
                ]
                row["ports_total"] = len(states)
                row["ports_connected"] = sum(
                    1 for s in states if "connect" in s and s != "notconnect"
                )
                row["ports_free"] = sum(1 for s in states if s in {"notconnect", "disabled"})
            vms = data.get("vms")
            if isinstance(vms, list):
                row["vms_total"] = len(vms)
                row["vms_powered_off"] = sum(
                    1
                    for vm in vms
                    if isinstance(vm, dict) and "off" in str(vm.get("power_state", "")).lower()
                )
            datastores = datastores_of(data)
            if datastores:
                row["datastores"] = [
                    {
                        "name": d["name"],
                        "free_percent": round(d["free"] / d["capacity"] * 100, 1)
                        if d["capacity"]
                        else None,
                    }
                    for d in datastores
                ]
            if len(row) > 2:
                rows.append(row)
        return rows

    def unused_objects(self) -> list[dict[str, Any]]:
        """Firewall objects no policy references, and ports that have never come up."""
        findings: list[dict[str, Any]] = []
        for device in self.devices():
            snapshot = self.latest(device)
            if snapshot is None:
                continue
            data = snapshot.data
            policies = data.get("policies")
            if isinstance(policies, list):
                referenced: set[str] = set()
                for policy in policies:
                    if not isinstance(policy, dict):
                        continue
                    for key in ("srcaddr", "dstaddr", "service"):
                        referenced.update(str(v) for v in policy.get(key) or [])
                for group in data.get("addrgrps") or []:
                    if isinstance(group, dict):
                        referenced.update(str(m) for m in group.get("members") or [])
                for collection, kind in (("addresses", "address"), ("services", "service")):
                    for obj in data.get(collection) or []:
                        name = obj.get("name") if isinstance(obj, dict) else None
                        if name and name not in referenced:
                            findings.append({"device": device.name, "type": kind, "name": name})
            interfaces = data.get("interfaces_status")
            if isinstance(interfaces, list):
                for port in interfaces:
                    if not isinstance(port, dict):
                        continue
                    if str(port.get("status", "")).lower() in {"notconnect", "disabled"}:
                        findings.append(
                            {
                                "device": device.name,
                                "type": "switchport",
                                "name": port.get("port") or port.get("interface"),
                                "vlan": port.get("vlan"),
                                "description": port.get("name") or port.get("description"),
                            }
                        )
        return findings

    def firmware_versions(self) -> list[dict[str, Any]]:
        """Observed firmware per device against the maintained known-good list."""
        known_good = self.known_good()
        rows: list[dict[str, Any]] = []
        for device in self.devices():
            snapshot = self.latest(device)
            observed = extract_version(snapshot.data) if snapshot else None
            baseline = known_good.get(device.kind.value) or {}
            good = [str(v) for v in baseline.get("known_good") or []]
            minimum = baseline.get("minimum")
            if observed is None:
                status = "unknown"
            elif observed in good:
                status = "known_good"
            elif minimum and version_key(observed) < version_key(str(minimum)):
                status = "below_minimum"
            else:
                status = "drift"
            rows.append(
                {
                    "device": device.name,
                    "kind": device.kind.value,
                    "observed": observed,
                    "known_good": good,
                    "minimum": minimum,
                    "status": status,
                    "notes": baseline.get("notes"),
                }
            )
        return rows

    # -- duties -------------------------------------------------------------
    def digest_context(self) -> dict[str, Any]:
        return {
            "generated_at": self._now(),
            "frozen": self.settings.frozen,
            "tier0_shadow_mode": self.settings.tier0_shadow_mode,
            "collector_health": self.collector_health(),
            "snapshot_ages": self.snapshot_ages(),
            "unapproved_config_changes": self.unapproved_config_changes(),
            "pending_approvals": self.pending_approvals(),
            "drift": self.drift(),
            "datastore_forecast": self.datastore_forecast(),
            "platform_health": self.platform_health(),
        }

    def daily_digest(self) -> AgentRunResult:
        return self._run(DIGEST_TASK, "daily_digest", self.digest_context(), "Daily digest")

    def weekly_context(self) -> dict[str, Any]:
        return {
            "generated_at": self._now(),
            "capacity": self.capacity(),
            "unused_objects": self.unused_objects(),
            "datastore_forecast": self.datastore_forecast(),
            "pending_approvals": self.pending_approvals(),
        }

    def weekly_report(self) -> AgentRunResult:
        return self._run(
            WEEKLY_TASK, "weekly_report", self.weekly_context(), "Weekly capacity report"
        )

    def firmware_context(self) -> dict[str, Any]:
        return {
            "generated_at": self._now(),
            "known_good_source": str(KNOWN_GOOD_VERSIONS.name),
            "devices": self.firmware_versions(),
        }

    def firmware_inventory(self) -> AgentRunResult:
        return self._run(
            FIRMWARE_TASK, "firmware_inventory", self.firmware_context(), "Firmware inventory"
        )

    # -- disaster recovery --------------------------------------------------
    def platform_health(self) -> dict[str, Any]:
        """Can this platform still recover? Structured, secret-free, local-only.

        Carried in the daily digest so a degraded administrator is noticed on
        an ordinary morning rather than on the morning it matters.
        """
        try:
            from infra_agent.dr.health import health_report

            return health_report(self.settings, now=self._now()).llm_view()
        except Exception as exc:
            log.exception("platform health report failed")
            return {"available": False, "reason": f"{type(exc).__name__}: {exc}"}

    def dr_export(self) -> dict[str, Any]:
        """Nightly: ship the platform state to the standby and prune by retention.

        Runs even when the platform is frozen. A freeze stops changes to the
        estate; an export changes nothing and is worth most precisely when
        somebody has just pulled the handle.
        """
        from infra_agent.dr.errors import DRError
        from infra_agent.dr.export import export_bundle

        if not self.settings.dr_target:
            log.info("no INFRA_DR_TARGET configured; skipping the nightly DR export")
            return {"ok": False, "skipped": "INFRA_DR_TARGET is not set"}
        try:
            result = export_bundle(self.settings, now=self._now())
        except DRError as exc:
            log.error("DR export failed: %s", exc)
            self.notifier.send(f"DR export failed: {exc}", critical=True)
            return {"ok": False, "error": str(exc)}
        summary = result.summary()
        if not result.ok:
            self.notifier.send(
                f"DR export incomplete ({result.bundle.name}): {'; '.join(result.warnings)}",
                critical=False,
            )
        return {"ok": result.ok, **summary}

    def dr_verify(self) -> dict[str, Any]:
        """Weekly: verify the newest local bundle and tell the owner either way.

        A backup nobody restored is a rumour, so the schedule proves it once a
        week and the quarterly restore test (docs/runbooks/restore-test.md)
        proves it the whole way into a scratch VM.
        """
        from infra_agent.dr.transfer import newest_bundle
        from infra_agent.dr.verify import verify_and_record

        bundle = newest_bundle(self.settings.dr_dir)
        if bundle is None:
            message = f"no DR bundle in {self.settings.dr_dir}; nothing to verify"
            log.warning(message)
            self.notifier.send(message, critical=True)
            return {"ok": False, "error": message}
        report = verify_and_record(bundle, self.settings, now=self._now())
        self.notifier.send(report.headline(), critical=not report.ok)
        return report.llm_view()

    def heartbeat(self) -> bool:
        """Dead-man ping. No model involved: this must work when everything else does not."""
        from infra_agent.agent.heartbeat import ping

        url = self._heartbeat_url()
        ok = ping(url)
        if not ok and url:
            log.warning("dead-man heartbeat ping failed")
        return ok

    def _heartbeat_url(self) -> str | None:
        if self.heartbeat_url_provider is not None:
            return self.heartbeat_url_provider()
        try:
            from infra_agent.onboarding.secrets import SecretsStore

            store = SecretsStore(self.settings.secrets_dir)
            if not store.available():
                return None
            value = store.get("platform", "heartbeat_url")
            return str(value) if value else None
        except Exception:
            log.exception("could not read the heartbeat url")
            return None

    # -- scheduling ---------------------------------------------------------
    def register(self, scheduler: Any) -> Any:
        """Add every duty to an APScheduler scheduler.

        The times are the owner's mornings, which means the scheduler has to be
        built in the owner's timezone (`infra_agent.agent.service.scheduler_timezone`,
        from `INFRA_AGENT_TIMEZONE` or `TZ`) - 07:30 UTC is not a morning
        everywhere.
        """
        scheduler.add_job(self.daily_digest, "cron", hour=7, minute=30, id="daily-digest")
        scheduler.add_job(
            self.weekly_report, "cron", day_of_week="mon", hour=8, minute=0, id="weekly-report"
        )
        scheduler.add_job(
            self.firmware_inventory,
            "cron",
            day_of_week="sun",
            hour=9,
            minute=0,
            id="firmware-inventory",
        )
        scheduler.add_job(self.heartbeat, "interval", minutes=5, id="heartbeat")
        # Disaster recovery: export in the quiet hours, verify before the week
        # starts so a failed bundle has a working day to be fixed in.
        scheduler.add_job(self.dr_export, "cron", hour=2, minute=15, id="dr-export")
        scheduler.add_job(
            self.dr_verify, "cron", day_of_week="sat", hour=5, minute=0, id="dr-verify"
        )
        return scheduler


def _samples_by_collector(answer: dict[str, Any]) -> dict[tuple[str, str], float]:
    """`metrics.promql` rows keyed by (collector, device), values as floats."""
    samples: dict[tuple[str, str], float] = {}
    for row in answer.get("rows") or []:
        if not isinstance(row, dict):
            continue
        labels = row.get("labels") or {}
        key = (str(labels.get("collector", "")), str(labels.get("device", "")))
        value = row.get("value")
        if value is None:
            continue
        try:
            samples[key] = float(value)
        except (TypeError, ValueError):
            continue
    return samples


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
