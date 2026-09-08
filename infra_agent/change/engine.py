"""The change engine: the only thing that drives a ChangePlan onto a device.

    engine = ChangeEngine.from_settings()
    engine.dry_run(plan_id)                     # renders the diff, computes the tier
    token = engine.request_approval(plan_id)    # human channel only
    engine.execute(plan_id)                     # only from `approved`

What this module guarantees, and what `tests/test_change_engine.py` holds it to:

* **Nothing runs unapproved.** `execute` refuses unless the plan is in
  `approved`. A Tier 0 plan reaches `approved` only through `run_tier0`, after
  `Tier0Guard.allow()` said yes and with shadow mode off.
* **A plan body is never its own evidence.** Every field of a `ChangePlan` is
  content the model may have written, so `state`, `approval`, `tier` and
  `history` prove nothing on their own. `execute` believes only
  `PlanStore.provenance`, which this engine and the store write and nothing
  else can: it dry-ran *this* plan (the fingerprint over its targets and steps
  still matches), the human approved *this* tier, and a Tier 0 plan was
  released by `run_tier0` after a live guard decision. The tier is recomputed
  once more at execution time and anything that grew past the approved tier is
  refused rather than run.
* **Nothing runs while frozen.** `settings.frozen` or the `data_dir/FROZEN`
  marker stops every write path, and the marker is re-read on each call rather
  than at start-up: `infra change freeze` has to stop the change that is about
  to happen, not the one after the next restart.
* **Tier 2 runs only inside its window and with a live heartbeat.** The window
  is the plan's own `MaintenanceWindow`; "live" means the dead-man heartbeat
  succeeded within `HEARTBEAT_MAX_AGE`.
* **The tier is computed, never taken.** `dry_run` re-runs impact analysis over
  every target and recomputes the tier with `compute_tier`, so a plan the model
  wrote cannot arrive pre-labelled as harmless. A Tier 0 action whose target is
  not in the topology graph is blocked rather than run blind.
* **The model never sees anything but structure.** Executors return structured
  diffs; `_assert_structured` refuses anything that still looks like a raw
  device configuration before it can reach `plan.diff` and therefore
  `ChangePlan.llm_view`. Every free-text note is redacted first.
* **Approval material never leaves the human channel.** `request_approval` is
  the only method that touches a token; it hands it to the `Notifier` and to its
  caller (the CLI, which is a human channel) and never logs it or writes it to a
  plan. No tool in `infra_agent/tools/change_tools.py` exposes it to the model.

Rollback follows `infra_agent/change/executors/base.py`: the engine hands the
executor the steps it applied, **in the order they were applied**, and the
executor undoes them in reverse using the state each step captured. That order
is what every executor's `rollback` docstring promises to honour, so the engine
must not pre-reverse the list and leave two packages disagreeing about it.

A failed post-check is a rollback, not a warning: the engine rolls back, pages
the owner through `Notifier.send(critical=True)` and records the whole attempt
as an `ExecutionRecord`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets as _secrets
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from pydantic import BaseModel

from infra_agent.change.executors.base import (
    CheckResult,
    ExecutionContext,
    Executor,
    StepResult,
    get_executor,
)
from infra_agent.change.executors.base import load_all as load_executors
from infra_agent.change.plan import ChangePlan, ChangeState, ChangeStep, HistoryEntry, Tier
from infra_agent.change.store import (
    CheckOutcome,
    ExecutionRecord,
    PlanStore,
    UnapprovedConfigChange,
)
from infra_agent.change.tiers import ImpactSummary, Tier0Guard, compute_tier
from infra_agent.config import Settings, get_settings
from infra_agent.models.common import Credential, SeedDevice, SeedInventory
from infra_agent.monitoring import metrics
from infra_agent.redaction.gateway import RedactionGateway

log = logging.getLogger(__name__)

#: File name of the break-glass marker inside `settings.data_dir`. A literal
#: here rather than an import from `infra_agent.agent.freeze` so the change
#: package never depends on the agent package.
FREEZE_MARKER = "FROZEN"

#: A dead-man heartbeat older than this is not a heartbeat. Tier 2 changes are
#: the ones the owner cannot be told about once the WAN is gone, so they are the
#: ones that refuse to run without it.
HEARTBEAT_MAX_AGE = timedelta(minutes=15)

#: How far either side of a config commit the engine looks for the plan that
#: explains it.
CONFIG_CHANGE_WINDOW = timedelta(minutes=15)

#: States a plan can still be validated from. Everything else has either run
#: already or been abandoned, so there is nothing left to dry-run.
_NEVER_DRY_RUN = frozenset(
    {
        ChangeState.executing,
        ChangeState.verifying,
        ChangeState.done,
        ChangeState.rolled_back,
        ChangeState.cancelled,
        ChangeState.failed,
    }
)

#: A check whose name starts with this is advisory: it is recorded and paged
#: about, but it does not roll a confirmed change back. `write memory` failing
#: after a successful `configure confirm` is the case this exists for - the
#: change is live and correct, it just is not saved yet, and reverting a good
#: change over that would be the worse outcome.
ADVISORY_PREFIX = "advisory:"

#: Words a Tier 2 confirmation phrase is built from. The phrase is minted by the
#: platform and typed back by the owner, so it is never something the model
#: chose or ever saw.
CONFIRMATION_WORDS = (
    "amber",
    "basalt",
    "cobalt",
    "cypress",
    "harbour",
    "lantern",
    "meridian",
    "quarry",
    "sable",
    "tundra",
)


class EngineError(RuntimeError):
    """The engine could not do what was asked."""


class ChangeRefused(EngineError):
    """A safety gate said no. The plan is left as it was."""


def mint_confirmation_phrase() -> str:
    """A Tier 2 phrase the owner types back, minted where the model cannot see it."""
    return "-".join(_secrets.choice(CONFIRMATION_WORDS) for _ in range(3))


def _aware(when: datetime) -> datetime:
    return when if when.tzinfo else when.replace(tzinfo=UTC)


# -- heartbeat ---------------------------------------------------------------
class HeartbeatStatus(Protocol):
    """Is the external dead-man heartbeat alive? Tier 2 asks before it runs."""

    def healthy(self, now: datetime | None = None) -> tuple[bool, str]: ...


class MetricsHeartbeat:
    """`metrics.HEARTBEAT_LAST_OK` within `max_age`, with an optional fallback.

    The gauge is set by whichever process pings the heartbeat
    (`infra_agent.agent.heartbeat.ping`). A CLI run is not that process, so a
    fallback that asks Prometheus for the same series is consulted before the
    heartbeat is declared dead. Both fail closed.
    """

    def __init__(
        self,
        max_age: timedelta = HEARTBEAT_MAX_AGE,
        *,
        fallback: Callable[[], float | None] | None = None,
    ) -> None:
        self.max_age = max_age
        self.fallback = fallback

    @staticmethod
    def _gauge_value() -> float:
        try:
            samples = list(metrics.HEARTBEAT_LAST_OK.collect())[0].samples
            return float(samples[0].value) if samples else 0.0
        except Exception:  # pragma: no cover - a registry that cannot be read
            return 0.0

    def healthy(self, now: datetime | None = None) -> tuple[bool, str]:
        now = now or datetime.now(UTC)
        stamp = self._gauge_value()
        source = "this process"
        if not stamp and self.fallback is not None:
            try:
                stamp = self.fallback() or 0.0
            except Exception as exc:
                return False, f"the heartbeat could not be read ({type(exc).__name__}: {exc})"
            source = "prometheus"
        if not stamp:
            return False, "the dead-man heartbeat has never reported a successful ping"
        age = now - datetime.fromtimestamp(stamp, tz=UTC)
        if age > self.max_age:
            return (
                False,
                f"the last dead-man heartbeat ({source}) was "
                f"{int(age.total_seconds() // 60)} minutes ago",
            )
        return True, f"last heartbeat {int(age.total_seconds())}s ago ({source})"


def prometheus_heartbeat(settings: Settings, timeout: float = 5.0) -> Callable[[], float | None]:
    """Ask Prometheus for the newest `infra_heartbeat_last_ok_timestamp_seconds`."""

    def read() -> float | None:
        import requests

        url = settings.prometheus_url.rstrip("/") + "/api/v1/query"
        query = "max(infra_heartbeat_last_ok_timestamp_seconds)"
        try:
            body = requests.get(url, params={"query": query}, timeout=timeout).json()
        except Exception as exc:
            log.warning("could not read the heartbeat from prometheus: %s", exc)
            return None
        for item in (body.get("data") or {}).get("result") or []:
            value = item.get("value") or []
            if len(value) > 1:
                try:
                    return float(value[1])
                except (TypeError, ValueError):
                    return None
        return None

    return read


def default_heartbeat(settings: Settings) -> HeartbeatStatus:
    return MetricsHeartbeat(fallback=prometheus_heartbeat(settings))


# -- tiering -----------------------------------------------------------------
@dataclass(frozen=True)
class ImpactTarget:
    """One object whose impact is part of a plan's tier.

    `candidates` are the graph references to try, best spelling first;
    `required` marks an object the tier cannot honestly be computed without.
    """

    label: str
    candidates: tuple[str, ...]
    required: bool = True


@dataclass
class Retier:
    """The recomputed tier, and what stood in the way of computing it."""

    tier: Tier
    reasons: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# -- resolution --------------------------------------------------------------
@dataclass
class DeviceWork:
    """One device, its executor, its read-write credential and its steps."""

    device: SeedDevice
    executor: Executor
    credential: Credential
    steps: list[ChangeStep] = field(default_factory=list)
    checks: dict[str, list[str]] = field(default_factory=lambda: {"pre": [], "post": []})

    def context(self, plan_id: str, *, dry_run: bool = False, **extra: Any) -> ExecutionContext:
        return ExecutionContext(
            plan_id=plan_id,
            device=self.device,
            credential=self.credential,
            dry_run=dry_run,
            extra=dict(extra),
        )


@dataclass
class Resolution:
    """Which device (and executor, and credential) each step belongs to."""

    work: list[DeviceWork] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.blockers

    def for_step(self, step: ChangeStep) -> DeviceWork | None:
        return next((w for w in self.work if any(s is step for s in w.steps)), None)


class Tier0Outcome(BaseModel):
    """What `run_tier0` did. `summary` is what the triage path reports."""

    action: str
    plan_id: str
    ran: bool = False
    #: live | shadow | refused | escalated | failed
    mode: str = "refused"
    summary: str = ""
    execution_id: str | None = None


class ConfigChangeCorrelation(BaseModel):
    """Whether a config commit is explained by a plan the engine executed."""

    device: str
    commit_sha: str
    at: datetime
    matched: bool
    plan_id: str | None = None
    execution_id: str | None = None
    reason: str = ""
    recorded: UnapprovedConfigChange | None = None

    def llm_view(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


InventorySource = SeedInventory | Callable[[], SeedInventory]

#: Given a target, what impact analysis says about it. The default asks
#: `correlate.impact.impact_analyze`; tests hand in a fake.
ImpactProvider = Callable[[str], Any]


class ChangeEngine:
    """Drives ChangePlans. Every write path in the platform goes through here."""

    def __init__(
        self,
        plan_store: PlanStore,
        secrets: Any = None,
        inventory: InventorySource | None = None,
        settings: Settings | None = None,
        notifier: Any = None,
        guard: Tier0Guard | None = None,
        config_store: Any = None,
        impact: ImpactProvider | None = None,
        *,
        heartbeat: HeartbeatStatus | None = None,
        gateway: RedactionGateway | None = None,
        executor_factory: Callable[[str], Executor] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.plans = plan_store
        self.secrets = secrets
        self._inventory = inventory
        self.notifier = notifier or _log_notifier()
        self.guard = guard or Tier0Guard(
            frozen=self.settings.frozen, shadow_mode=self.settings.tier0_shadow_mode
        )
        self.config_store = config_store
        self.impact = impact or self._graph_impact
        self.heartbeat = heartbeat or default_heartbeat(self.settings)
        self.gateway = gateway or RedactionGateway(audit_log=self.settings.audit_log)
        self._executor_factory = executor_factory or _default_executor_factory
        self._executors: dict[str, Executor] = {}

    @classmethod
    def from_settings(
        cls, settings: Settings | None = None, *, notifier: Any = None, **overrides: Any
    ) -> ChangeEngine:
        """The engine the CLI, the tool layer and the scheduler hook build.

        The notifier defaults to the owner's real channel rather than the log.
        The two things this engine pages about - a change that failed and rolled
        back, and a configuration change nobody approved - happen in the
        collector and CLI processes, where a log line is a message nobody reads.
        """
        settings = settings or get_settings()
        from infra_agent.configstore.git_store import ConfigGitStore
        from infra_agent.onboarding.secrets import SecretsStore

        defaults: dict[str, Any] = {
            "plan_store": PlanStore(settings.data_dir / "plans.db"),
            "secrets": SecretsStore(settings.secrets_dir),
            "inventory": lambda: SeedInventory.load(settings.seed_inventory),
            "settings": settings,
            "notifier": notifier or _owner_notifier(settings),
            "config_store": ConfigGitStore(settings.config_repo),
        }
        defaults.update(overrides)
        return cls(**defaults)

    # -- inventory, credentials, executors ----------------------------------
    def inventory(self) -> SeedInventory:
        source = self._inventory
        if source is None:
            return SeedInventory.load(self.settings.seed_inventory)
        return source() if callable(source) else source

    def executor(self, platform: str) -> Executor:
        """One executor instance per platform per engine, so an executor may keep
        per-plan state (the Cisco revert timer) across the steps of one plan."""
        if platform not in self._executors:
            self._executors[platform] = self._executor_factory(platform)
        return self._executors[platform]

    def _device_credentials(self) -> dict[str, Any]:
        """The decrypted `devices` secrets, read once per operation.

        Never logged and never returned to a caller: the values become
        `Credential` (SecretStr) immediately.
        """
        if self.secrets is None:
            return {}
        try:
            if hasattr(self.secrets, "available") and not self.secrets.available():
                return {}
            return dict(self.secrets.read("devices"))
        except Exception as exc:
            log.warning("could not read the devices secrets store: %s", type(exc).__name__)
            return {}

    # -- safety gates --------------------------------------------------------
    def frozen(self) -> bool:
        """`settings.frozen` or the break-glass marker, re-read every time."""
        if self.settings.frozen:
            return True
        try:
            return (self.settings.data_dir / FREEZE_MARKER).exists()
        except OSError:  # an unreadable data dir is not a reason to unfreeze
            return True

    def _refuse_when_frozen(self, what: str) -> None:
        if self.frozen():
            raise ChangeRefused(
                f"the platform is frozen (break-glass): {what} is refused. "
                "Run `infra change unfreeze` and clear INFRA_FROZEN first."
            )

    # -- notes ---------------------------------------------------------------
    def _clean(self, text: str) -> str:
        """Redact anything free-text before it is stored on a plan or a record."""
        try:
            return str(self.gateway.redact(text))
        except Exception:  # pragma: no cover - redaction must never break a change
            return text

    def _note(self, plan: ChangePlan, note: str) -> None:
        """Record a note against the plan's current state, without a transition."""
        plan.history.append(
            HistoryEntry(state=plan.state, at=datetime.now(UTC), note=self._clean(note))
        )

    def _assert_structured(self, diff: Any) -> None:
        """`plan.diff` reaches the model through `llm_view`; raw config must not."""
        self.gateway.refuse_raw_config(diff)

    # -- impact and tier -----------------------------------------------------
    def _graph_impact(self, target: str) -> Any:
        from infra_agent.correlate.impact import impact_analyze
        from infra_agent.correlate.service import load_graph

        # `rebuild=False`: a change path must not pay for a full graph rebuild,
        # and an absent graph becomes a blocker rather than a silent empty impact.
        return impact_analyze(target, load_graph(self.settings, rebuild=False))

    def _impact_targets(self, plan: ChangePlan) -> list[ImpactTarget]:
        """Every object whose impact decides this plan's tier.

        The plan's own targets, plus the objects its *steps* actually touch: the
        interface named in a step's params and the VLAN a `vlan.*` step creates
        or deletes. Without those, a plan that targets `sw-core-01` and whose
        step reconfigures the ESXi trunk on `Gi1/0/48` would be tiered as if it
        touched the switch in general, which is how a trunk change escapes the
        maintenance window `docs/risk-tiers.md` requires for it.

        The graph spells interfaces out (`interface:sw-core-01:GigabitEthernet1/0/48`)
        while plans and Tier 0 candidates use the short form an engineer types,
        so both spellings are offered.
        """
        from infra_agent.correlate.model import interface_id, vlan_id
        from infra_agent.correlate.parsing import normalize_ifname

        targets: list[ImpactTarget] = []
        for target in plan.targets:
            device, _, qualifier = str(target).partition(":")
            spellings = [str(target)]
            if qualifier.strip():
                # `sw-core-01:Gi1/0/48` is how a plan (and a Tier 0 candidate)
                # names a port; the graph calls the same thing
                # `interface:sw-core-01:GigabitEthernet1/0/48`.
                spellings += [
                    interface_id(device.strip(), normalize_ifname(qualifier.strip())),
                    interface_id(device.strip(), qualifier.strip()),
                ]
            targets.append(
                ImpactTarget(
                    label=str(target), candidates=tuple(dict.fromkeys(spellings)), required=False
                )
            )
        seen = {t.candidates for t in targets}
        for index, step in enumerate(plan.steps, start=1):
            device = self._step_device_name(step, plan)
            interface = str(step.params.get("interface") or "").strip()
            if device and interface:
                candidates = tuple(
                    dict.fromkeys(
                        [
                            interface_id(device, normalize_ifname(interface)),
                            interface_id(device, interface),
                            f"{device}:{interface}",
                        ]
                    )
                )
                if candidates not in seen:
                    seen.add(candidates)
                    targets.append(
                        ImpactTarget(
                            label=f"{device} {interface} (step {index})", candidates=candidates
                        )
                    )
            if step.action.startswith("vlan.") and step.params.get("vlan") is not None:
                try:
                    vlan = int(str(step.params["vlan"]).strip())
                except (TypeError, ValueError):
                    continue
                candidates = (vlan_id(vlan),)
                if candidates in seen:
                    continue
                seen.add(candidates)
                targets.append(
                    ImpactTarget(
                        label=f"vlan {vlan} (step {index})",
                        candidates=candidates,
                        # A VLAN being created does not exist yet, so the graph
                        # not knowing it is the expected answer rather than a
                        # gap in what the tier was computed from.
                        required=step.action != "vlan.add",
                    )
                )
        return targets

    @staticmethod
    def _step_device_name(step: ChangeStep, plan: ChangePlan) -> str:
        named = step.params.get("device") or step.params.get("target")
        if named:
            return str(named).split(":", 1)[0].strip()
        if len(plan.targets) == 1:
            return str(plan.targets[0]).split(":", 1)[0].strip()
        return ""

    def _retier(self, plan: ChangePlan) -> Retier:
        """Recompute the tier from impact analysis over targets *and* steps.

        The tier is the maximum over the plan's action and every step's action,
        each computed against the merged impact of every object the plan
        touches: a Tier 1 `vlan.add` whose step reconfigures a trunk is a Tier 2
        change, whatever the plan calls itself.
        """
        if not plan.targets:
            return Retier(
                tier=plan.tier,
                reasons=list(plan.tier_reasons),
                blockers=["the plan names no targets, so its impact cannot be analysed"],
            )
        summaries: list[ImpactSummary] = []
        unresolved: list[ImpactTarget] = []
        warnings: list[str] = []
        for target in self._impact_targets(plan):
            summary, problem = self._analyse(target)
            if summary is None:
                unresolved.append(target)
                if problem:
                    warnings.append(problem)
                continue
            summaries.append(summary)
        merged = _merge_summaries(summaries)
        tier = Tier.AUTO
        reasons: list[str] = []
        for action in _actions_of(plan):
            action_tier, action_reasons = compute_tier(action, merged)
            tier = max(tier, action_tier)
            reasons.extend(r for r in action_reasons if r not in reasons)
        missing = sorted(t.label for t in unresolved)
        if missing:
            reasons.append("impact analysis could not resolve " + ", ".join(missing))

        blockers: list[str] = []
        if not summaries:
            blockers.append(
                "no target of this plan is in the topology graph, so its risk tier cannot be "
                "computed; run `infra graph build` and dry-run again"
            )
        else:
            required = sorted(t.label for t in unresolved if t.required)
            if required and tier is not Tier.WINDOW:
                # The graph is how the platform knows whether that port is an
                # uplink, feeds an iLO or carries the management VLAN. Guessing
                # is the one option that is not available.
                blockers.append(
                    "the topology graph does not know "
                    + ", ".join(required)
                    + ", so this change cannot be shown to be safe at its computed tier; "
                    "run `infra graph build` and dry-run again"
                )
            elif missing and tier is Tier.AUTO:
                blockers.append(
                    "a tier 0 action must not run against an object the topology graph does not "
                    "know: " + ", ".join(missing)
                )
            elif missing:
                warnings.append("the tier was computed without " + ", ".join(missing))
        return Retier(tier=tier, reasons=reasons, blockers=blockers, warnings=warnings)

    def _analyse(self, target: ImpactTarget) -> tuple[ImpactSummary | None, str]:
        """The impact of the first candidate spelling the graph knows."""
        problem = ""
        for candidate in target.candidates:
            try:
                report = self.impact(candidate)
            except Exception as exc:
                problem = f"impact analysis of {target.label} failed: {type(exc).__name__}: {exc}"
                continue
            if getattr(report, "found", True) is False:
                continue
            summary = getattr(report, "summary", report)
            if isinstance(summary, ImpactSummary):
                return summary, ""
        return None, problem

    # -- plan resolution -----------------------------------------------------
    def resolve(self, plan: ChangePlan) -> Resolution:
        """Map the plan's targets and steps onto devices, executors and credentials."""
        resolution = Resolution()
        inventory = self.inventory()
        devices: list[SeedDevice] = []
        for target in plan.targets:
            name = str(target).split(":", 1)[0].strip()
            if not name:
                resolution.blockers.append(f"target {target!r} does not name a device")
                continue
            device = inventory.get(name)
            if device is None:
                resolution.blockers.append(f"target {target!r} is not a device in the inventory")
            elif device.name not in {d.name for d in devices}:
                devices.append(device)
        if not plan.steps:
            resolution.blockers.append("the plan has no steps to apply")
        if not devices:
            return resolution

        # Steps first, credentials second: only a device that actually receives a
        # step needs read-write access, so a plan that names a peer as context is
        # not blocked for lacking a credential it was never going to use.
        assignments: dict[str, list[ChangeStep]] = {}
        for index, step in enumerate(plan.steps, start=1):
            device = self._device_for_step(step, devices)
            if device is None:
                resolution.blockers.append(
                    f"step {index} ({step.action}) does not name a device and its platform "
                    f"{step.platform!r} does not identify exactly one target"
                )
                continue
            if step.platform and step.platform != device.platform:
                resolution.blockers.append(
                    f"step {index} declares platform {step.platform!r} but {device.name} "
                    f"is {device.platform!r}"
                )
                continue
            assignments.setdefault(device.name, []).append(step)

        raw_credentials = self._device_credentials()
        work_by_device: dict[str, DeviceWork] = {}
        for device in devices:
            steps = assignments.get(device.name)
            if not steps:
                continue
            problem = self._prepare(device, raw_credentials, work_by_device)
            if problem:
                resolution.blockers.append(problem)
                continue
            work = work_by_device[device.name]
            for step in steps:
                if step.action not in work.executor.supported_actions():
                    resolution.blockers.append(
                        f"the {device.platform} executor does not implement action "
                        f"{step.action!r} ({device.name})"
                    )
                    continue
                work.steps.append(step)

        resolution.work = [w for w in work_by_device.values() if w.steps]
        for work in resolution.work:
            work.checks = {
                "pre": _checks_for(plan.pre_checks, work.device.name, devices),
                "post": _checks_for(plan.post_checks, work.device.name, devices),
            }
        return resolution

    def _prepare(
        self,
        device: SeedDevice,
        raw_credentials: Mapping[str, Any],
        work_by_device: dict[str, DeviceWork],
    ) -> str | None:
        """Build the `DeviceWork` for one device, or say why it cannot be built."""
        if not device.rw_credential_ref:
            return (
                f"{device.name} has no read-write credential: collectors keep the read-only "
                "one, so a change needs `rw_credential_ref` on its inventory record"
            )
        raw = raw_credentials.get(device.rw_credential_ref)
        if not raw:
            return (
                f"the devices secrets store holds no read-write credential for {device.name}; "
                "run `infra onboard add-device` again to record one"
            )
        try:
            credential = Credential.model_validate(raw)
        except Exception:
            return f"the stored read-write credential for {device.name} is not usable"
        try:
            executor = self.executor(device.platform)
        except LookupError:
            return f"no executor is registered for platform {device.platform!r} ({device.name})"
        work_by_device[device.name] = DeviceWork(
            device=device, executor=executor, credential=credential
        )
        return None

    @staticmethod
    def _device_for_step(step: ChangeStep, devices: Sequence[SeedDevice]) -> SeedDevice | None:
        named = step.params.get("device") or step.params.get("target")
        if named:
            name = str(named).split(":", 1)[0].strip()
            return next((d for d in devices if d.name == name), None)
        if len(devices) == 1:
            return devices[0]
        candidates = [d for d in devices if d.platform == step.platform]
        return candidates[0] if len(candidates) == 1 else None

    @staticmethod
    def _execution_extra(plan: ChangePlan, resolution: Resolution) -> dict[str, Any]:
        """What every executor is told about the shape of the whole plan.

        `plan_devices` and `plan_steps` are how the Cisco executor sizes its
        revert timer: the timer has to outlive every other device's steps and
        checks, because the change is only confirmed once all of them passed.
        """
        return {
            "persist": _persist(plan),
            "plan_devices": len(resolution.work) or 1,
            "plan_steps": len(plan.steps) or 1,
        }

    # -- dry run -------------------------------------------------------------
    def dry_run(self, plan_id: str) -> ChangePlan:
        """Validate a plan against live state, compute its tier, record provenance.

        Blockers (executor blockers, a missing read-write credential, an unknown
        action, a target impact analysis cannot resolve) leave the plan where it
        was with the reasons in its history. A clean run moves a `proposed` plan
        to `dry_run` with a structured diff and the recomputed tier, and tells
        the store that *this* engine validated *this* plan - which is what
        `execute` later insists on having seen.

        A plan that is already past `proposed` (one the triage path recorded and
        the owner has approved, say) can be re-validated here: nothing is
        changed on any device and the state does not move, but the plan gets the
        diff, the recomputed tier and the provenance a first dry run would have
        given it. The tier is never lowered that way - a plan approved as Tier 2
        stays Tier 2.
        """
        plan = self.plans.get(plan_id)
        if plan.state in _NEVER_DRY_RUN:
            raise ChangeRefused(
                f"{plan.id} is {plan.state.value}; there is nothing left to dry-run"
            )
        revalidation = plan.state is not ChangeState.proposed
        retier = self._retier(plan)
        tier = retier.tier
        reasons = list(retier.reasons)
        if revalidation and int(plan.tier) > int(tier):
            reasons.append(f"kept the higher tier this plan was already carrying: {plan.tier.name}")
            tier = plan.tier
        plan.tier, plan.tier_reasons = tier, reasons
        resolution = self.resolve(plan)
        blockers = list(resolution.blockers) + retier.blockers
        warnings = [*retier.warnings, *resolution.warnings]

        diffs: dict[str, Any] = {}
        extra = self._execution_extra(plan, resolution)
        if not blockers:
            for work in resolution.work:
                name = work.device.name
                context = work.context(plan.id, dry_run=True, **extra)
                try:
                    result = work.executor.dry_run(context, work.steps)
                except Exception as exc:
                    blockers.append(f"{name}: the dry run failed ({type(exc).__name__}: {exc})")
                    continue
                diffs[name] = result.diff
                warnings.extend(f"{name}: {w}" for w in result.warnings)
                blockers.extend(f"{name}: {b}" for b in result.blockers)
                if not result.ok and not result.blockers:
                    blockers.append(f"{name}: the executor rejected the plan without saying why")

        diff: dict[str, Any] = {
            "targets": list(plan.targets),
            "devices": sorted(diffs),
            "by_device": diffs,
            "warnings": [self._clean(w) for w in warnings],
        }
        if blockers:
            diff["blockers"] = [self._clean(b) for b in blockers]
        # The diff is what `llm_view` shows the model: structure only, never the
        # raw `show running-config` text the executor parsed it out of.
        self._assert_structured(diff)
        plan.diff = diff

        if blockers:
            self._note(plan, "dry run blocked: " + "; ".join(blockers))
            self.plans.save(plan)
            return plan
        note = self._clean(
            f"dry run ok on {', '.join(sorted(diffs)) or 'no device'}; "
            f"computed tier {plan.tier.name}"
        )
        if revalidation:
            self._note(plan, f"re-validated while {plan.state.value}: {note}")
        else:
            plan.transition(ChangeState.dry_run, note)
        self.plans.save(plan)
        # Written last and only on a clean run: the provenance is the engine's
        # own record that it validated exactly these steps against these
        # devices, and `execute` refuses a plan it cannot find one for.
        self.plans.record_dry_run(plan.id, plan_fingerprint(plan), plan.tier)
        return plan

    # -- approval (human channel only) ---------------------------------------
    def request_approval(self, plan_id: str) -> str:
        """Mint the approval token and hand it to the owner's channel.

        The return value is for a human channel too: the CLI prints it to the
        operator's own terminal, which `docs/risk-tiers.md` names alongside
        Telegram. It is never logged, never stored on the plan, and no tool in
        `infra_agent/tools/change_tools.py` exposes this method to the model.
        """
        plan = self.plans.get(plan_id)
        if plan.tier is Tier.WINDOW and not plan.confirmation_phrase:
            plan.confirmation_phrase = mint_confirmation_phrase()
            self.plans.save(plan)
        token = self.plans.request_approval(plan)
        self._deliver_approval_request(plan, token)
        return token

    def _deliver_approval_request(self, plan: ChangePlan, token: str) -> None:
        """Hand the request to the owner's channel, phrase included where it can take it.

        A Tier 2 approval needs two things the model never sees: the token and
        the exact confirmation phrase. A notifier that accepts a `phrase`
        keyword gets both, so an approval requested from anywhere (the Tier 0
        escalation path, a duty, the CLI) is actually answerable in the channel
        it was asked in. One that does not is called exactly as before, and the
        phrase stays where it already was - in the plan row, readable through
        `infra change show`. It is never logged and never returned to a tool.
        """
        phrase = plan.confirmation_phrase if plan.tier is Tier.WINDOW else None
        if phrase and _accepts_phrase(self.notifier.send_approval_request):
            self.notifier.send_approval_request(plan, token, phrase=phrase)
            return
        if phrase:
            # Not an error: the request still has to go out, and the owner can
            # read the phrase with `infra change show`.
            log.debug("the notifier takes no confirmation phrase; sending the request without it")
        self.notifier.send_approval_request(plan, token)

    # -- execution -----------------------------------------------------------
    def execute(self, plan_id: str, *, now: datetime | None = None) -> ExecutionRecord:
        """Run an approved plan: pre-checks, steps, post-checks, rollback on failure."""
        now = now or datetime.now(UTC)
        plan = self.plans.get(plan_id)
        self._gate(plan, now)

        resolution = self.resolve(plan)
        started = datetime.now(UTC)
        record = ExecutionRecord(
            plan_id=plan.id,
            action=plan.action,
            tier=int(plan.tier),
            devices=[w.device.name for w in resolution.work],
            started_at=started,
        )
        if not resolution.ok:
            record.outcome = "blocked"
            record.notes = [self._clean(b) for b in resolution.blockers]
            self._finish(record, started)
            self._note(plan, "execution blocked: " + "; ".join(resolution.blockers))
            self.plans.save(plan)
            self.plans.record_execution(record)
            metrics.CHANGE_EXECUTIONS.labels(tier=plan.tier.name, outcome="blocked").inc()
            raise ChangeRefused("; ".join(resolution.blockers))

        plan.transition(ChangeState.executing, f"executing {len(plan.steps)} step(s)")
        self.plans.save(plan)

        extra = self._execution_extra(plan, resolution)
        contexts = {w.device.name: w.context(plan.id, **extra) for w in resolution.work}

        failures = self._run_checks(resolution, contexts, "pre", record)
        if failures:
            return self._fail(plan, record, started, failures, [], resolution, contexts)

        applied: list[StepResult] = []
        for step in plan.steps:
            work = resolution.for_step(step)
            if work is None:  # pragma: no cover - resolve() would have blocked
                return self._fail(
                    plan,
                    record,
                    started,
                    [f"step {step.action} was not assigned to a device"],
                    applied,
                    resolution,
                    contexts,
                )
            try:
                result = work.executor.apply(contexts[work.device.name], step)
            except Exception as exc:
                result = StepResult(
                    step=step,
                    ok=False,
                    error=self._clean(f"{type(exc).__name__}: {exc}"),
                    finished_at=datetime.now(UTC),
                )
            applied.append(result)
            record.steps = list(applied)
            if not result.ok:
                return self._fail(
                    plan,
                    record,
                    started,
                    [f"step {step.action} on {work.device.name} failed: {result.error}"],
                    applied,
                    resolution,
                    contexts,
                )

        plan.transition(ChangeState.verifying, "applied; verifying")
        self.plans.save(plan)
        failures = self._run_checks(resolution, contexts, "post", record)
        if failures:
            return self._fail(plan, record, started, failures, applied, resolution, contexts)

        # Only now, with every device's post-checks passed, is anything made
        # permanent. Verifying device A and committing it before device B has
        # even been checked is what turns "the plan failed and was rolled back"
        # into "A kept the change and B did not": on IOS a `configure confirm`
        # cannot be taken back by `configure revert now`.
        failures = self._commit(resolution, contexts, record)
        if failures:
            return self._fail(plan, record, started, failures, applied, resolution, contexts)

        record.outcome = "done"
        self._finish(record, started)
        plan.transition(ChangeState.done, self._clean(f"done: {len(applied)} step(s) applied"))
        self.plans.save(plan)
        self.plans.record_execution(record)
        metrics.CHANGE_EXECUTIONS.labels(tier=plan.tier.name, outcome="done").inc()
        self._page_advisories(plan, record)
        self.notifier.send(
            f"Change {plan.id} ({plan.title}) applied: {len(applied)} step(s) on "
            f"{', '.join(record.devices)}."
        )
        return record

    def _gate(self, plan: ChangePlan, now: datetime) -> None:
        """Every reason a plan may not run, checked before anything is touched.

        None of these questions is answered from the plan body alone: a plan is
        a document the model may have written, and `state: approved` in it is a
        claim, not a fact. The facts live in `PlanStore.provenance`, which only
        this engine and the store write.
        """
        self._refuse_when_frozen(f"executing {plan.id}")
        if plan.state is not ChangeState.approved:
            raise ChangeRefused(
                f"{plan.id} is {plan.state.value}; a plan executes only from 'approved'"
            )
        provenance = self.plans.provenance(plan.id)
        if provenance is None:
            raise ChangeRefused(
                f"{plan.id} was never dry-run by this engine, so nothing has checked what it "
                "would do; run `infra change dry-run` first"
            )
        if provenance.fingerprint != plan_fingerprint(plan):
            raise ChangeRefused(
                f"{plan.id} changed after its dry run (its targets, steps or checks are not the "
                "ones that were validated and approved); dry-run and approve it again"
            )
        if plan.tier is Tier.AUTO:
            # A Tier 0 plan reaches `approved` only through `run_tier0`, which
            # asked the guard and then said so in the store. Shadow mode is
            # re-read here so a plan approved before the flag flipped still does
            # not run, and it is checked first because it is the answer the
            # operator is most likely looking for.
            if self.settings.tier0_shadow_mode:
                raise ChangeRefused(
                    "tier 0 shadow mode is on: the action is reported, not run "
                    "(INFRA_TIER0_SHADOW_MODE=0 enables it)"
                )
            if provenance.tier0_released_at is None:
                raise ChangeRefused(
                    f"{plan.id} claims to be a tier 0 change but no Tier0Guard decision released "
                    "it; tier 0 runs only through the guard"
                )
        elif plan.approval is None:
            raise ChangeRefused(f"{plan.id} carries no approval record")
        elif provenance.approved_tier is None:
            raise ChangeRefused(
                f"{plan.id} carries an approval this store never issued for the plan as it "
                "stands; approve it through `infra change approve` (or the owner's chat) with "
                "the token that was minted"
            )
        self._recheck_tier(plan, provenance)
        if plan.tier is Tier.WINDOW:
            if plan.window is None or not plan.window.contains(now):
                raise ChangeRefused(
                    "tier 2 changes execute only inside their declared maintenance window"
                )
            healthy, why = self.heartbeat.healthy(now)
            if not healthy:
                raise ChangeRefused(f"tier 2 changes need a healthy dead-man heartbeat: {why}")

    def _recheck_tier(self, plan: ChangePlan, provenance: Any) -> None:
        """Compute the tier once more, against the graph as it is right now.

        The estate moves between the approval and the change: a port that was an
        access port when the owner said yes may be an ESXi uplink by the time
        the window opens. A plan whose tier has grown does not run on the old
        approval, and the tier it *is* gated by is the one that was approved,
        never a freshly computed lower one.
        """
        approved = (
            Tier(provenance.approved_tier) if provenance.approved_tier is not None else plan.tier
        )
        retier = self._retier(plan)
        if int(retier.tier) > int(approved):
            self._note(
                plan,
                f"refused: impact analysis now makes this a {retier.tier.name} change "
                f"({'; '.join(retier.reasons)})",
            )
            self.plans.save(plan)
            raise ChangeRefused(
                f"{plan.id} was approved as tier {approved.name} but is now tier "
                f"{retier.tier.name}: {'; '.join(retier.reasons)}. Dry-run and approve it again."
            )
        if retier.blockers and plan.tier is Tier.AUTO:
            raise ChangeRefused("; ".join(retier.blockers))
        if retier.blockers:
            self._note(
                plan, "executed with an incomplete impact analysis: " + "; ".join(retier.blockers)
            )
        plan.tier = approved

    def _run_checks(
        self,
        resolution: Resolution,
        contexts: Mapping[str, ExecutionContext],
        phase: str,
        record: ExecutionRecord,
    ) -> list[str]:
        """Run one phase of checks on every device. Returns the blocking failures."""
        failures: list[str] = []
        for work in resolution.work:
            name = work.device.name
            checks = work.checks[phase]
            runner = work.executor.pre_check if phase == "pre" else work.executor.post_check
            try:
                results: Iterable[CheckResult] = runner(contexts[name], list(checks))
            except Exception as exc:
                failures.append(f"{name}: the {phase}-checks failed ({type(exc).__name__}: {exc})")
                record.checks.append(
                    CheckOutcome(
                        device=name,
                        phase=phase,
                        check="(all)",
                        ok=False,
                        detail=self._clean(f"{type(exc).__name__}: {exc}"),
                    )
                )
                continue
            for result in results:
                advisory = result.check.strip().lower().startswith(ADVISORY_PREFIX)
                record.checks.append(
                    CheckOutcome(
                        device=name,
                        phase=phase,
                        check=result.check,
                        ok=result.ok,
                        detail=self._clean(result.detail),
                        advisory=advisory,
                    )
                )
                if not result.ok and not advisory:
                    failures.append(f"{name}: {phase}-check {result.check!r} failed")
        return failures

    def _commit(
        self,
        resolution: Resolution,
        contexts: Mapping[str, ExecutionContext],
        record: ExecutionRecord,
    ) -> list[str]:
        """Make the change permanent on every device that has a commit step.

        An executor whose change is already permanent the moment it is applied
        (an inverse-operation platform such as FortiOS) has no `commit` and this
        is a no-op for it. The Cisco executor has one: it holds an armed revert
        timer from `apply` until here, so the second phase of the plan is what
        cancels it. A device that commits is marked as such in its context, so a
        rollback after this point undoes the change with an inverse
        configuration instead of a `configure revert now` that has nothing left
        to revert.
        """
        failures: list[str] = []
        for work in resolution.work:
            name = work.device.name
            commit = getattr(work.executor, "commit", None)
            if commit is None:
                contexts[name].extra["committed"] = True
                continue
            try:
                results: Iterable[CheckResult] = commit(contexts[name])
            except Exception as exc:
                failures.append(f"{name}: the commit failed ({type(exc).__name__}: {exc})")
                record.checks.append(
                    CheckOutcome(
                        device=name,
                        phase="commit",
                        check="(commit)",
                        ok=False,
                        detail=self._clean(f"{type(exc).__name__}: {exc}"),
                    )
                )
                continue
            committed = True
            for result in results:
                advisory = result.check.strip().lower().startswith(ADVISORY_PREFIX)
                record.checks.append(
                    CheckOutcome(
                        device=name,
                        phase="commit",
                        check=result.check,
                        ok=result.ok,
                        detail=self._clean(result.detail),
                        advisory=advisory,
                    )
                )
                if not result.ok and not advisory:
                    committed = False
                    failures.append(f"{name}: commit step {result.check!r} failed")
            contexts[name].extra["committed"] = committed
        return failures

    def _fail(
        self,
        plan: ChangePlan,
        record: ExecutionRecord,
        started: datetime,
        failures: list[str],
        applied: list[StepResult],
        resolution: Resolution,
        contexts: Mapping[str, ExecutionContext],
    ) -> ExecutionRecord:
        """A pre-check, a step or a post-check failed: roll back and page."""
        record.notes.extend(self._clean(f) for f in failures)
        rolled: list[StepResult] = []
        rollback_errors: list[str] = []
        if applied:
            for work in resolution.work:
                mine = [r for r in applied if any(s is r.step for s in work.steps)]
                if not mine:
                    continue
                metrics.CHANGE_ROLLBACKS.labels(platform=work.device.platform).inc()
                try:
                    # Handed over in application order: every executor's
                    # `rollback` contract is to undo them in reverse itself.
                    rolled.extend(work.executor.rollback(contexts[work.device.name], mine))
                except Exception as exc:
                    rollback_errors.append(
                        f"{work.device.name}: rollback raised {type(exc).__name__}: {exc}"
                    )
            if not rolled and not rollback_errors:
                # Silence is not success: without a result there is nothing to
                # say the device was put back, so the owner is told that.
                rollback_errors.append(
                    "the executor reported no rollback result, so the undo is unconfirmed"
                )
            rolled_ok = all(r.ok for r in rolled) and not rollback_errors
        else:
            rolled_ok = True  # nothing was applied, so nothing needed undoing
        record.rollback_steps = rolled
        record.notes.extend(self._clean(e) for e in rollback_errors)

        if applied:
            record.outcome = "rolled_back" if rolled_ok else "rollback_failed"
            plan.transition(
                ChangeState.rolled_back, self._clean("rolled back after: " + "; ".join(failures))
            )
        else:
            record.outcome = "failed"
            plan.transition(ChangeState.failed, self._clean("failed: " + "; ".join(failures)))
        self._finish(record, started)
        self.plans.save(plan)
        self.plans.record_execution(record)
        metrics.CHANGE_EXECUTIONS.labels(tier=plan.tier.name, outcome=record.outcome).inc()

        if record.outcome == "rollback_failed":
            headline = (
                f"Change {plan.id} ({plan.title}) FAILED and the rollback did not complete. "
                "The device may be half-changed; check it now."
            )
        elif record.outcome == "rolled_back":
            headline = f"Change {plan.id} ({plan.title}) FAILED and was rolled back."
        else:
            headline = f"Change {plan.id} ({plan.title}) FAILED before anything was applied."
        self.notifier.send(
            self._clean(" ".join([headline, *failures, *rollback_errors])), critical=True
        )
        return record

    def _page_advisories(self, plan: ChangePlan, record: ExecutionRecord) -> None:
        advisories = [c for c in record.checks if c.advisory and not c.ok]
        if not advisories:
            return
        self.notifier.send(
            self._clean(
                f"Change {plan.id} succeeded but "
                + "; ".join(f"{c.device}: {c.check} ({c.detail})" for c in advisories)
            ),
            critical=True,
        )

    @staticmethod
    def _finish(record: ExecutionRecord, started: datetime) -> None:
        record.finished_at = datetime.now(UTC)
        record.duration_seconds = round((record.finished_at - _aware(started)).total_seconds(), 3)

    # -- manual rollback -----------------------------------------------------
    def rollback(self, plan_id: str) -> ExecutionRecord:
        """Undo the last recorded execution of a plan on the owner's say-so."""
        self._refuse_when_frozen(f"rolling {plan_id} back")
        plan = self.plans.get(plan_id)
        previous = self.plans.last_execution(plan.id)
        if previous is None or not previous.steps:
            raise ChangeRefused(f"{plan.id} has no recorded execution to roll back")
        resolution = self.resolve(plan)
        if not resolution.ok:
            raise ChangeRefused("; ".join(resolution.blockers))
        started = datetime.now(UTC)
        record = ExecutionRecord(
            plan_id=plan.id,
            action=plan.action,
            tier=int(plan.tier),
            devices=[w.device.name for w in resolution.work],
            started_at=started,
            notes=[f"manual rollback of execution {previous.id}"],
        )
        rolled: list[StepResult] = []
        errors: list[str] = []
        # The recorded steps came back from the store, so they are equal to the
        # plan's steps but not the same objects: they are routed to a device by
        # the same rule that assigned them in the first place.
        known = [w.device for w in resolution.work]
        extra = self._execution_extra(plan, resolution)
        for work in resolution.work:
            mine = [
                r for r in previous.steps if self._device_for_step(r.step, known) is work.device
            ]
            if not mine:
                continue
            metrics.CHANGE_ROLLBACKS.labels(platform=work.device.platform).inc()
            # Whether that device's change was made permanent decides how it is
            # undone: a committed change needs an inverse configuration, an
            # uncommitted one is still holding its own undo.
            context = work.context(
                plan.id, **extra, committed=_was_committed(previous, work.device.name)
            )
            try:
                rolled.extend(work.executor.rollback(context, mine))
            except Exception as exc:
                errors.append(f"{work.device.name}: rollback raised {type(exc).__name__}: {exc}")
        if not rolled and not errors:
            errors.append("the executor reported no rollback result, so the undo is unconfirmed")
        record.rollback_steps = rolled
        record.notes.extend(self._clean(e) for e in errors)
        record.outcome = (
            "rolled_back" if all(r.ok for r in rolled) and not errors else "rollback_failed"
        )
        self._finish(record, started)
        if plan.can_transition(ChangeState.rolled_back):
            plan.transition(ChangeState.rolled_back, "rolled back on request")
        else:
            self._note(plan, f"rollback requested while {plan.state.value}: {record.outcome}")
        self.plans.save(plan)
        self.plans.record_execution(record)
        metrics.CHANGE_EXECUTIONS.labels(tier=plan.tier.name, outcome=record.outcome).inc()
        self.notifier.send(
            self._clean(f"Change {plan.id} ({plan.title}) rolled back: {record.outcome}."),
            critical=True,
        )
        return record

    # -- tier 0 --------------------------------------------------------------
    def can_run_tier0(self, action: str, object_id: str) -> bool:
        """Could the platform act on that object at all? Cheap and offline.

        The triage hook asks first, so a Tier 0 candidate naming an object with
        no read-write credential (or no executor for its platform) is reported
        as unwired rather than attempted.
        """
        device = self.inventory().get(str(object_id).split(":", 1)[0].strip())
        if device is None or not device.rw_credential_ref:
            return False
        try:
            executor = self.executor(device.platform)
        except LookupError:
            return False
        return action in executor.supported_actions()

    def tier0_plan(
        self,
        action: str,
        object_id: str,
        *,
        cause: str | None = None,
        title: str | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> ChangePlan:
        """Build the one-step Tier 0 plan for an action on an object.

        `object_id` is what the triage path names the object: a device, or
        `device:qualifier` where the qualifier is whatever that action acts on -
        a switch port for `switch.clear_errdisable`, a VM for `vm.*`, a service
        for `guest.service_restart`. Each executor wants that under its own
        parameter name, so the qualifier is placed per action family rather than
        posted as `interface` to platforms that have no interfaces. A caller
        with better information passes `params` and this decides nothing.
        """
        device_name, _, qualifier = str(object_id).partition(":")
        device = self.inventory().get(device_name.strip())
        if device is None:
            raise ChangeRefused(f"{object_id!r} is not a device in the inventory")
        step_params: dict[str, Any] = {"device": device.name}
        step_params.update(_tier0_params(action, device.name, qualifier.strip()))
        step_params.update(dict(params or {}))
        interface = str(step_params.get("interface") or "")
        checks: list[str] = []
        if interface and action == "switch.clear_errdisable":
            checks = [f"no errdisable on {interface}", f"interface {interface} is up"]
        return ChangePlan(
            title=title or f"{action} on {object_id}",
            action=action,
            targets=[object_id],
            summary=f"tier 0 {action} on {object_id}" + (f" (cause: {cause})" if cause else ""),
            tier=Tier.AUTO,
            proposed_by="change-engine-tier0",
            steps=[
                ChangeStep(
                    description=f"{action} on {object_id}",
                    platform=device.platform,
                    action=action,
                    params=step_params,
                )
            ],
            post_checks=checks,
        )

    def run_tier0(
        self,
        plan: ChangePlan,
        *,
        guard_checked: bool = False,
        object_id: str | None = None,
        object_tags: Sequence[str] | None = None,
        cause: str | None = None,
    ) -> Tier0Outcome:
        """Dry-run, verify the tier is still 0, then execute - or refuse.

        `guard_checked=True` says the caller (the triage path) already asked
        `Tier0Guard.allow()` and recorded the run, so the guard is not consulted
        twice and its cooldown is not spent twice. The freeze and shadow-mode
        gates still apply here, and so does the recomputed tier: an action that
        impact analysis escalates goes to the approval channel instead.
        """
        outcome = Tier0Outcome(action=plan.action, plan_id=plan.id)
        target = object_id or (plan.targets[0] if plan.targets else "")
        if self.frozen():
            outcome.summary = "the platform is frozen (break-glass); nothing was done"
            return outcome
        if not guard_checked:
            allowed, reason = self.guard.allow(plan.action, target, list(object_tags or []), cause)
            if not allowed:
                outcome.summary = f"tier 0 refused: {reason}"
                return outcome
            self.guard.record(plan.action, target)
        if self.settings.tier0_shadow_mode or self.guard.shadow_mode:
            outcome.mode = "shadow"
            outcome.summary = f"shadow: would have run {plan.action} on {target}"
            return outcome

        if plan.state is ChangeState.proposed:
            self.plans.save(plan)
            plan = self.dry_run(plan.id)
        if plan.state is not ChangeState.dry_run:
            blockers = plan.diff.get("blockers") if isinstance(plan.diff, dict) else None
            outcome.summary = "tier 0 blocked: " + "; ".join(blockers or ["the dry run failed"])
            return outcome
        if plan.tier is not Tier.AUTO:
            # Impact analysis escalated it, so it is the owner's decision now.
            outcome.mode = "escalated"
            self.request_approval(plan.id)
            plan = self.plans.get(plan.id)
            outcome.summary = (
                f"escalated to tier {plan.tier.name} by impact analysis "
                f"({'; '.join(plan.tier_reasons)}); approval requested"
            )
            return outcome
        try:
            # The guard said yes, just now, for this plan: recorded where the
            # plan body cannot reach, because `execute` refuses a Tier 0 plan
            # that carries no live guard decision.
            self.plans.release_tier0(plan.id)
        except Exception as exc:
            outcome.summary = f"tier 0 blocked: {exc}"
            return outcome
        plan.transition(ChangeState.approved, "tier 0 guard allowed this action")
        self.plans.save(plan)
        try:
            record = self.execute(plan.id)
        except ChangeRefused as exc:
            outcome.summary = f"tier 0 refused: {exc}"
            return outcome
        outcome.ran = record.outcome == "done"
        outcome.mode = "live" if outcome.ran else "failed"
        outcome.execution_id = record.id
        outcome.summary = f"{plan.action} on {target}: {record.outcome}"
        return outcome

    # -- unapproved config changes -------------------------------------------
    def correlate_config_change(
        self,
        device: str,
        commit_sha: str,
        at: datetime | None = None,
        *,
        filename: str | None = None,
    ) -> ConfigChangeCorrelation:
        """Does a config commit match a plan this engine executed on that device?

        If not it is an `UnapprovedConfigChange` (`docs/architecture.md`):
        recorded in the store, counted, and paged to the owner.
        """
        at = _aware(at) if at else self._commit_time(device, commit_sha)
        window = CONFIG_CHANGE_WINDOW
        candidates = self.plans.executions(
            device=device, since=at - window - window, until=at + window, limit=200
        )
        for record in candidates:
            if record.outcome == "blocked":
                continue  # nothing was sent to the device
            if _touches(record, at, window):
                return ConfigChangeCorrelation(
                    device=device,
                    commit_sha=commit_sha,
                    at=at,
                    matched=True,
                    plan_id=record.plan_id,
                    execution_id=record.id,
                    reason=(
                        f"matches plan {record.plan_id} executed at "
                        f"{_aware(record.started_at).isoformat()} ({record.outcome})"
                    ),
                )
        reason = (
            f"no ChangePlan was executed on {device} within "
            f"{int(window.total_seconds() // 60)} minutes of this commit"
        )
        change = UnapprovedConfigChange(
            device=device, commit_sha=commit_sha, filename=filename, at=at, reason=reason
        )
        self.plans.record_unapproved_change(change)
        metrics.UNAPPROVED_CONFIG_CHANGES.labels(device=device).inc()
        self.notifier.send(
            f"Unapproved configuration change on {device}: commit {commit_sha[:12]}"
            + (f" ({filename})" if filename else "")
            + f" at {at.isoformat()}. {reason}.",
            critical=True,
        )
        log.warning("unapproved config change on %s (%s)", device, commit_sha[:12])
        return ConfigChangeCorrelation(
            device=device,
            commit_sha=commit_sha,
            at=at,
            matched=False,
            reason=reason,
            recorded=change,
        )

    def _commit_time(self, device: str, commit_sha: str) -> datetime:
        """When the config store recorded that commit; now, if it cannot say."""
        if self.config_store is not None:
            try:
                for entry in self.config_store.history(device, limit=50):
                    if str(entry.get("sha", "")).startswith(commit_sha[:12]):
                        return _aware(datetime.fromisoformat(str(entry["at"])))
            except Exception as exc:  # pragma: no cover - a broken config store
                log.warning("could not read the config history for %s: %s", device, exc)
        return datetime.now(UTC)

    def unapproved_changes(
        self, device: str | None = None, *, limit: int = 50
    ) -> list[UnapprovedConfigChange]:
        return list(self.plans.unapproved_changes(device, limit=limit))


# -- helpers -----------------------------------------------------------------
#: Where the `device:qualifier` half of a Tier 0 object id belongs, per action.
#: Anything not listed here takes no qualifier at all: `discovery.rerun`,
#: `esxi.log_bundle` and `alert.silence` act on the device itself.
TIER0_QUALIFIER_PARAM: dict[str, str] = {
    "switch.clear_errdisable": "interface",
    "vm.power_on": "vm",
    "vm.snapshot": "vm",
    "guest.service_restart": "service",
}


def _tier0_params(action: str, device: str, qualifier: str) -> dict[str, Any]:
    """The step parameters a Tier 0 action needs, named the way its executor reads them."""
    if not qualifier:
        return {}
    key = TIER0_QUALIFIER_PARAM.get(action)
    if key is None:
        log.debug("no tier 0 parameter mapping for %s on %s:%s", action, device, qualifier)
        return {}
    return {key: qualifier}


def _accepts_phrase(send_approval_request: Callable[..., Any]) -> bool:
    """Does this notifier take the Tier 2 confirmation phrase as well as the token?"""
    import inspect

    try:
        signature = inspect.signature(send_approval_request)
    except (TypeError, ValueError):  # pragma: no cover - a builtin or a C callable
        return False
    if any(p.kind is p.VAR_KEYWORD for p in signature.parameters.values()):
        return True
    return "phrase" in signature.parameters


def _actions_of(plan: ChangePlan) -> list[str]:
    """The plan's action and every step's action, in order, without repeats.

    The tier is the maximum over all of them: a plan is as risky as the riskiest
    thing it sends, not as the label it gave itself.
    """
    actions = [plan.action]
    actions.extend(step.action for step in plan.steps)
    return list(dict.fromkeys(a for a in actions if a))


def plan_fingerprint(plan: ChangePlan) -> str:
    """What the engine dry-ran, hashed: the targets, steps and checks.

    Not the title, summary or tier: those are prose and computed state. If any
    of this changed after the dry run, whatever a human approved is not what is
    about to be sent, and `execute` refuses.
    """
    payload = {
        "action": plan.action,
        "targets": sorted(str(t) for t in plan.targets),
        "steps": [
            {"platform": s.platform, "action": s.action, "params": s.params} for s in plan.steps
        ],
        "pre_checks": list(plan.pre_checks),
        "post_checks": list(plan.post_checks),
    }
    blob = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def _merge_summaries(summaries: Sequence[ImpactSummary]) -> ImpactSummary:
    """One summary for the whole plan: any escalation on any target escalates."""
    return ImpactSummary(
        touches_mgmt_path=any(s.touches_mgmt_path for s in summaries),
        touches_trunk_or_uplink=any(s.touches_trunk_or_uplink for s in summaries),
        touches_wan_ha_vpn_stp=any(s.touches_wan_ha_vpn_stp for s in summaries),
        vlan_has_members_or_svi=any(s.vlan_has_members_or_svi for s in summaries),
        feeds_ilo_or_mgmt_vlan=any(s.feeds_ilo_or_mgmt_vlan for s in summaries),
        affected_objects=sorted({o for s in summaries for o in s.affected_objects}),
    )


def _checks_for(checks: Sequence[str], device: str, devices: Sequence[SeedDevice]) -> list[str]:
    """Route a plan's checks to a device.

    A check may name its device with a `sw-core-01: ...` prefix; an unprefixed
    check is evaluated on every device the plan touches, which is what a
    single-device plan wants.
    """
    names = {d.name for d in devices}
    mine: list[str] = []
    for check in checks:
        prefix, sep, rest = str(check).partition(":")
        if sep and prefix.strip() in names:
            if prefix.strip() == device:
                mine.append(rest.strip())
        else:
            mine.append(str(check).strip())
    return mine


def _persist(plan: ChangePlan) -> bool:
    """Whether a confirmed change is saved to startup-config. Default true.

    A plan says otherwise by setting `persist: false` on any of its steps.
    """
    for step in plan.steps:
        if "persist" in step.params:
            return bool(step.params["persist"])
    return True


def _was_committed(record: ExecutionRecord, device: str) -> bool:
    """Did that device's change survive to the commit phase of that execution?

    A recorded commit check is the evidence; a finished execution that recorded
    no commit at all (an executor without the hook, whose changes are permanent
    as soon as they are applied) counts too.
    """
    commits = [c for c in record.checks if c.device == device and c.phase == "commit"]
    if commits:
        return all(c.ok for c in commits if not c.advisory)
    return record.outcome == "done"


def _touches(record: ExecutionRecord, at: datetime, window: timedelta) -> bool:
    started = _aware(record.started_at)
    finished = _aware(record.finished_at) if record.finished_at else started
    return (started - window) <= at <= (finished + window)


def _default_executor_factory(platform: str) -> Executor:
    load_executors()
    return get_executor(platform)


def _log_notifier() -> Any:
    from infra_agent.agent.notify import LogNotifier

    return LogNotifier()


def _owner_notifier(settings: Settings) -> Any:
    """The Telegram channel when the owner configured one, the log otherwise.

    Imported lazily and defensively: a notifier that cannot be built is a
    degraded channel, never a reason for a change engine not to exist.
    """
    try:
        from infra_agent.agent.service import build_notifier

        return build_notifier(settings)
    except Exception:
        log.info("no owner channel available; change notifications go to the log", exc_info=True)
        return _log_notifier()


# -- scheduler hook ----------------------------------------------------------
def config_change_hook(
    device: str,
    commits: Mapping[str, str],
    *,
    at: datetime | None = None,
    engine: ChangeEngine | None = None,
) -> list[ConfigChangeCorrelation]:
    """What the collector scheduler calls for every config commit it just made."""
    if not commits:
        return []
    engine = engine or ChangeEngine.from_settings()
    return [
        engine.correlate_config_change(device, sha, at, filename=filename)
        for filename, sha in commits.items()
    ]


def default_engine(settings: Settings | None = None, **overrides: Any) -> ChangeEngine:
    """A ChangeEngine wired from settings; the tool layer and the CLI share one."""
    return ChangeEngine.from_settings(settings, **overrides)


__all__ = [
    "ADVISORY_PREFIX",
    "CONFIG_CHANGE_WINDOW",
    "HEARTBEAT_MAX_AGE",
    "ChangeEngine",
    "ChangeRefused",
    "ConfigChangeCorrelation",
    "EngineError",
    "HeartbeatStatus",
    "ImpactTarget",
    "MetricsHeartbeat",
    "Tier0Outcome",
    "config_change_hook",
    "default_engine",
    "default_heartbeat",
    "mint_confirmation_phrase",
    "plan_fingerprint",
    "prometheus_heartbeat",
]
