"""Change engine tests: the state machine, every safety gate, and rollback.

Everything here runs offline. `FakeExecutor` records what the engine asked it
to do and is scripted to fail wherever a test needs a failure, `FakeSecrets`
stands in for the SOPS store, and impact analysis is a plain callable so the
computed tier is under the test's control rather than the graph's.

The invariants these tests exist to hold:

* a plan executes only from `approved`, and a Tier 0 plan only with the guard's
  blessing and shadow mode off;
* `INFRA_FROZEN` and the `data_dir/FROZEN` marker stop every write path;
* Tier 2 refuses outside its window and without a live dead-man heartbeat;
* a failed post-check rolls back and pages;
* a config commit no plan explains is an `UnapprovedConfigChange`;
* the approval token never appears in an `llm_view`, an execution record, a
  plan's history or the log.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from prometheus_client import REGISTRY

from infra_agent.change.engine import (
    ChangeEngine,
    ChangeRefused,
    MetricsHeartbeat,
    config_change_hook,
)
from infra_agent.change.executors.base import (
    CheckResult,
    DryRunResult,
    ExecutionContext,
    Executor,
    StepResult,
)
from infra_agent.change.plan import (
    ChangePlan,
    ChangeState,
    ChangeStep,
    MaintenanceWindow,
    Tier,
)
from infra_agent.change.store import PlanStore
from infra_agent.change.tiers import ImpactSummary, Tier0Guard
from infra_agent.config import Settings
from infra_agent.models.common import DeviceKind, SeedDevice, SeedInventory

PASSWORD = "sup3r-s3cret-rw"

INVENTORY = SeedInventory(
    devices=[
        SeedDevice(
            name="sw-core-01",
            kind=DeviceKind.cisco_ios,
            mgmt_ip="10.0.0.11",
            credential_ref="sw-core-01",
            rw_credential_ref="sw-core-01-rw",
            tags=["auto:errdisable"],
        ),
        SeedDevice(
            name="sw-edge-02",
            kind=DeviceKind.cisco_iosxe,
            mgmt_ip="10.0.0.12",
            credential_ref="sw-edge-02",
            # deliberately read-only: the engine must refuse to touch it
        ),
    ]
)


# -- fakes --------------------------------------------------------------------
class FakeSecrets:
    """The SOPS store, without SOPS."""

    def __init__(self, entries: dict[str, Any] | None = None, available: bool = True) -> None:
        self.entries = (
            entries
            if entries is not None
            else {"sw-core-01-rw": {"username": "svc-change", "password": PASSWORD}}
        )
        self._available = available

    def available(self) -> bool:
        return self._available

    def read(self, name: str) -> dict[str, Any]:
        assert name == "devices"
        return dict(self.entries)


class RecordingNotifier:
    def __init__(self) -> None:
        self.messages: list[tuple[str, bool]] = []
        self.approvals: list[tuple[str, str]] = []
        self.reports: list[tuple[str, str]] = []

    def send(self, text: str, *, critical: bool = False) -> None:
        self.messages.append((text, critical))

    def send_approval_request(self, plan: ChangePlan, token: str) -> None:
        self.approvals.append((plan.id, token))

    def send_report(self, title: str, body_markdown: str) -> None:
        self.reports.append((title, body_markdown))

    @property
    def text(self) -> str:
        return "\n".join(m for m, _ in self.messages)

    @property
    def critical(self) -> list[str]:
        return [m for m, c in self.messages if c]


class FakeExecutor(Executor):
    """Scriptable stand-in for a device executor.

    It also asserts the parts of the contract the engine relies on: it is handed
    the read-write credential, and it never writes it anywhere.
    """

    platform = "cisco"

    def __init__(
        self,
        *,
        actions: tuple[str, ...] = (
            "vlan.add",
            "switch.access_port_config",
            "switch.clear_errdisable",
        ),
        dry_run_blockers: tuple[str, ...] = (),
        dry_run_warnings: tuple[str, ...] = (),
        fail_pre: bool = False,
        fail_step: str | None = None,
        fail_post: bool = False,
        advisory_fails: bool = False,
        rollback_ok: bool = True,
        rollback_raises: bool = False,
    ) -> None:
        self.actions = actions
        self.dry_run_blockers = dry_run_blockers
        self.dry_run_warnings = dry_run_warnings
        self.fail_pre = fail_pre
        self.fail_step = fail_step
        self.fail_post = fail_post
        self.advisory_fails = advisory_fails
        self.rollback_ok = rollback_ok
        self.rollback_raises = rollback_raises
        self.calls: list[tuple[str, Any]] = []
        self.credentials_seen: list[str] = []

    def _seen(self, ctx: ExecutionContext) -> None:
        assert ctx.credential.password is not None
        # A `SecretStr`, so a stray f-string in an executor cannot leak it.
        assert PASSWORD not in str(ctx.credential.password)
        self.credentials_seen.append(ctx.device.name)

    def supported_actions(self) -> set[str]:
        return set(self.actions)

    def dry_run(self, ctx: ExecutionContext, steps: list[ChangeStep]) -> DryRunResult:
        self._seen(ctx)
        self.calls.append(("dry_run", [s.action for s in steps]))
        return DryRunResult(
            ok=not self.dry_run_blockers,
            diff={
                "device": ctx.device.name,
                "commands": [f"! {s.action}" for s in steps],
                "changes": [{"object": "vlan 20", "before": {}, "after": {"exists": True}}],
            },
            warnings=list(self.dry_run_warnings),
            blockers=list(self.dry_run_blockers),
        )

    def pre_check(self, ctx: ExecutionContext, checks: list[str]) -> list[CheckResult]:
        self._seen(ctx)
        self.calls.append(("pre_check", list(checks)))
        return [CheckResult(check=c, ok=not self.fail_pre, detail="fake") for c in checks]

    def apply(self, ctx: ExecutionContext, step: ChangeStep) -> StepResult:
        self._seen(ctx)
        self.calls.append(("apply", step.action))
        if self.fail_step == step.action:
            return StepResult(step=step, ok=False, error="the switch said no")
        return StepResult(step=step, ok=True, output={"commands": [f"! {step.action}"]})

    def post_check(self, ctx: ExecutionContext, checks: list[str]) -> list[CheckResult]:
        self._seen(ctx)
        self.calls.append(("post_check", list(checks)))
        results = [CheckResult(check=c, ok=not self.fail_post, detail="fake") for c in checks]
        if self.advisory_fails:
            results.append(
                CheckResult(check="advisory: write memory", ok=False, detail="flash is full")
            )
        return results

    def rollback(self, ctx: ExecutionContext, applied: list[StepResult]) -> list[StepResult]:
        self._seen(ctx)
        self.calls.append(("rollback", [r.step.action for r in applied]))
        if self.rollback_raises:
            raise RuntimeError("the console is unreachable")
        return [
            StepResult(step=r.step, ok=self.rollback_ok, output={"reverted": self.rollback_ok})
            for r in reversed(applied)
        ]


class FakeImpact:
    """Impact analysis as a callable, so the computed tier is the test's choice."""

    def __init__(self, summaries: dict[str, ImpactSummary] | None = None) -> None:
        self.summaries = summaries or {}
        self.asked: list[str] = []

    def __call__(self, target: str) -> Any:
        self.asked.append(target)
        summary = self.summaries.get(target, ImpactSummary(affected_objects=[f"{target}:peer"]))
        return type("Report", (), {"found": summary is not None, "summary": summary})()


class MissingImpact:
    """Everything is unknown to the graph."""

    def __call__(self, target: str) -> Any:
        return type("Report", (), {"found": False, "summary": ImpactSummary()})()


# -- fixtures ------------------------------------------------------------------
@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        secrets_dir=tmp_path / "secrets",
        seed_inventory=tmp_path / "seed.yaml",
        frozen=False,
        tier0_shadow_mode=True,
    )


@pytest.fixture
def store(settings) -> PlanStore:
    return PlanStore(settings.data_dir / "plans.db")


class OkHeartbeat:
    def healthy(self, now: datetime | None = None) -> tuple[bool, str]:
        return True, "fresh"


class DeadHeartbeat:
    def healthy(self, now: datetime | None = None) -> tuple[bool, str]:
        return False, "the last dead-man heartbeat was 90 minutes ago"


def build_engine(
    settings: Settings,
    store: PlanStore,
    executor: FakeExecutor | None = None,
    **overrides: Any,
) -> tuple[ChangeEngine, FakeExecutor, RecordingNotifier]:
    executor = executor or FakeExecutor()
    notifier = overrides.pop("notifier", None) or RecordingNotifier()
    engine = ChangeEngine(
        plan_store=store,
        secrets=overrides.pop("secrets", None) or FakeSecrets(),
        inventory=overrides.pop("inventory", lambda: INVENTORY),
        settings=settings,
        notifier=notifier,
        guard=overrides.pop("guard", None) or Tier0Guard(frozen=False, shadow_mode=False),
        config_store=overrides.pop("config_store", None),
        impact=overrides.pop("impact", None) or FakeImpact(),
        heartbeat=overrides.pop("heartbeat", None) or OkHeartbeat(),
        executor_factory=overrides.pop("executor_factory", lambda platform: executor),
        **overrides,
    )
    return engine, executor, notifier


def vlan_plan(**kw: Any) -> ChangePlan:
    defaults: dict[str, Any] = dict(
        title="add vlan 20",
        action="vlan.add",
        targets=["sw-core-01"],
        pre_checks=["vlan 20 does not exist"],
        post_checks=["vlan 20 exists"],
        steps=[
            ChangeStep(
                description="create vlan 20",
                platform="cisco",
                action="vlan.add",
                params={"device": "sw-core-01", "vlan": 20, "name": "servers"},
            )
        ],
    )
    defaults.update(kw)
    return ChangePlan(**defaults)


def approve(store: PlanStore, plan: ChangePlan, phrase: str | None = None) -> str:
    token = store.request_approval(plan)
    store.approve(plan.id, token, "owner", "cli", phrase)
    return token


def counter(name: str, labels: dict[str, str]) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


# -- dry run -------------------------------------------------------------------
def test_dry_run_merges_the_diff_computes_the_tier_and_advances_the_state(settings, store):
    engine, executor, _ = build_engine(settings, store)
    plan = vlan_plan()
    store.save(plan)

    result = engine.dry_run(plan.id)

    assert result.state is ChangeState.dry_run
    assert store.get(plan.id).state is ChangeState.dry_run
    assert result.diff["by_device"]["sw-core-01"]["commands"] == ["! vlan.add"]
    assert result.tier is Tier.APPROVAL
    assert result.tier_reasons[0].startswith("base tier for vlan.add")
    assert ("dry_run", ["vlan.add"]) in executor.calls


def test_dry_run_recomputes_the_tier_from_impact_rather_than_trusting_the_plan(settings, store):
    impact = FakeImpact({"sw-core-01": ImpactSummary(touches_mgmt_path=True)})
    engine, _, _ = build_engine(settings, store, impact=impact)
    plan = vlan_plan(tier=Tier.AUTO)  # a proposal claiming to be harmless
    store.save(plan)

    result = engine.dry_run(plan.id)

    assert impact.asked == ["sw-core-01"]
    assert result.tier is Tier.WINDOW
    assert any("management path" in r for r in result.tier_reasons)


def test_dry_run_escalation_is_the_max_over_every_target(settings, store):
    impact = FakeImpact(
        {
            "sw-core-01": ImpactSummary(),
            "sw-edge-02": ImpactSummary(touches_trunk_or_uplink=True),
        }
    )
    engine, _, _ = build_engine(settings, store, impact=impact)
    plan = vlan_plan(targets=["sw-core-01", "sw-edge-02"])
    store.save(plan)

    # No step touches sw-edge-02, so its lack of a read-write credential is not
    # a blocker - but its impact still escalates the whole plan.
    result = engine.dry_run(plan.id)

    assert result.state is ChangeState.dry_run
    assert result.tier is Tier.WINDOW
    assert result.diff["devices"] == ["sw-core-01"]


def _retarget(device: str):
    """Point the plan (target and step) at another switch."""

    def mutate(plan: ChangePlan) -> None:
        plan.targets[0] = device
        plan.steps[0] = plan.steps[0].model_copy(
            update={"params": {**plan.steps[0].params, "device": device}}
        )

    return mutate


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (_retarget("sw-edge-02"), "no read-write credential"),
        (lambda p: p.targets.__setitem__(0, "sw-nope"), "not a device in the inventory"),
        (
            lambda p: p.steps.__setitem__(
                0, p.steps[0].model_copy(update={"action": "vlan.paint"})
            ),
            "does not implement",
        ),
        (lambda p: p.steps.clear(), "no steps"),
    ],
)
def test_blockers_leave_the_plan_proposed_with_the_reason_in_its_history(
    settings, store, mutate, expected
):
    engine, _, _ = build_engine(settings, store)
    plan = vlan_plan()
    mutate(plan)
    store.save(plan)

    result = engine.dry_run(plan.id)

    assert result.state is ChangeState.proposed
    assert any(expected in b for b in result.diff["blockers"]), result.diff["blockers"]
    assert any(expected in h.note for h in result.history)


def test_an_executor_blocker_is_a_blocker(settings, store):
    engine, _, _ = build_engine(
        settings, store, FakeExecutor(dry_run_blockers=("the archive feature is not configured",))
    )
    plan = vlan_plan()
    store.save(plan)

    result = engine.dry_run(plan.id)

    assert result.state is ChangeState.proposed
    assert "sw-core-01: the archive feature is not configured" in result.diff["blockers"]


def test_a_missing_secret_blocks_even_though_the_inventory_names_one(settings, store):
    engine, _, _ = build_engine(settings, store, secrets=FakeSecrets(entries={}))
    plan = vlan_plan()
    store.save(plan)

    assert "holds no read-write credential" in " ".join(engine.dry_run(plan.id).diff["blockers"])


def test_a_target_the_graph_does_not_know_is_a_warning_for_tier_1(settings, store):
    engine, _, _ = build_engine(settings, store, impact=MissingImpact())
    plan = vlan_plan()
    store.save(plan)

    result = engine.dry_run(plan.id)

    assert result.state is ChangeState.proposed
    assert any("topology graph" in b for b in result.diff["blockers"])


def test_dry_run_only_runs_from_proposed(settings, store):
    engine, _, _ = build_engine(settings, store)
    plan = vlan_plan()
    store.save(plan)
    engine.dry_run(plan.id)

    with pytest.raises(ChangeRefused, match="only a proposed plan"):
        engine.dry_run(plan.id)


class LeakyExecutor(FakeExecutor):
    """An executor that forgets and hands back the raw running configuration."""

    RAW = "Building configuration...\n" + "\n".join(f" line {i}" for i in range(40))

    def dry_run(self, ctx: ExecutionContext, steps: list[ChangeStep]) -> DryRunResult:
        return DryRunResult(ok=True, diff={"running": self.RAW})


def test_the_diff_never_carries_a_raw_configuration(settings, store):
    engine, _, _ = build_engine(settings, store, LeakyExecutor())
    plan = vlan_plan()
    store.save(plan)

    from infra_agent.redaction.gateway import RawConfigError

    with pytest.raises(RawConfigError):
        engine.dry_run(plan.id)


# -- approval gate --------------------------------------------------------------
def test_execute_refuses_anything_that_is_not_approved(settings, store):
    engine, executor, _ = build_engine(settings, store)
    plan = vlan_plan()
    store.save(plan)
    engine.dry_run(plan.id)

    with pytest.raises(ChangeRefused, match="executes only from 'approved'"):
        engine.execute(plan.id)
    assert not [c for c in executor.calls if c[0] == "apply"]


def test_request_approval_sends_the_token_only_to_the_owner_channel(settings, store, caplog):
    engine, _, notifier = build_engine(settings, store)
    plan = vlan_plan()
    store.save(plan)
    engine.dry_run(plan.id)

    with caplog.at_level(logging.DEBUG):
        token = engine.request_approval(plan.id)

    assert notifier.approvals == [(plan.id, token)]
    stored = store.get(plan.id)
    assert stored.state is ChangeState.awaiting_approval
    assert token not in json.dumps(stored.llm_view())
    assert token not in json.dumps([h.model_dump(mode="json") for h in stored.history])
    assert token not in caplog.text
    assert token not in notifier.text


def test_a_tier2_plan_gets_a_phrase_the_model_never_saw(settings, store):
    impact = FakeImpact({"sw-core-01": ImpactSummary(touches_wan_ha_vpn_stp=True)})
    engine, _, _ = build_engine(settings, store, impact=impact)
    plan = vlan_plan()
    store.save(plan)
    engine.dry_run(plan.id)

    engine.request_approval(plan.id)

    stored = store.get(plan.id)
    assert stored.tier is Tier.WINDOW
    assert stored.confirmation_phrase
    assert stored.confirmation_phrase not in json.dumps(stored.llm_view())


def test_the_full_happy_path_records_an_execution(settings, store):
    engine, executor, notifier = build_engine(settings, store)
    plan = vlan_plan()
    store.save(plan)
    engine.dry_run(plan.id)
    approve(store, store.get(plan.id))

    record = engine.execute(plan.id)

    assert record.outcome == "done"
    assert store.get(plan.id).state is ChangeState.done
    assert [c[0] for c in executor.calls] == ["dry_run", "pre_check", "apply", "post_check"]
    assert [c.check for c in record.checks if c.phase == "post"] == ["vlan 20 exists"]
    assert record.duration_seconds >= 0
    assert store.executions(plan.id)[0].id == record.id
    assert notifier.critical == []


def test_post_checks_run_even_when_the_plan_declares_none(settings, store):
    """The Cisco `configure confirm` lives in post_check; skipping the call would
    let the revert timer undo a change that worked."""
    engine, executor, _ = build_engine(settings, store)
    plan = vlan_plan(post_checks=[])
    store.save(plan)
    engine.dry_run(plan.id)
    approve(store, store.get(plan.id))

    engine.execute(plan.id)

    assert ("post_check", []) in executor.calls


# -- freeze --------------------------------------------------------------------
def test_the_settings_freeze_stops_execution(settings, store):
    engine, executor, _ = build_engine(settings, store)
    plan = vlan_plan()
    store.save(plan)
    engine.dry_run(plan.id)
    approve(store, store.get(plan.id))
    settings.frozen = True

    with pytest.raises(ChangeRefused, match="frozen"):
        engine.execute(plan.id)
    assert not [c for c in executor.calls if c[0] == "apply"]


def test_the_marker_freezes_a_running_engine(settings, store):
    engine, executor, _ = build_engine(settings, store)
    plan = vlan_plan()
    store.save(plan)
    engine.dry_run(plan.id)
    approve(store, store.get(plan.id))
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    (settings.data_dir / "FROZEN").touch()

    with pytest.raises(ChangeRefused, match="frozen"):
        engine.execute(plan.id)
    with pytest.raises(ChangeRefused, match="frozen"):
        engine.rollback(plan.id)
    assert not [c for c in executor.calls if c[0] == "apply"]


# -- tier 2 gates ---------------------------------------------------------------
def tier2_plan(now: datetime, *, window: tuple[int, int] = (-5, 30)) -> ChangePlan:
    return vlan_plan(
        title="move the trunk",
        action="switch.trunk_port_config",
        window=MaintenanceWindow(
            start=now + timedelta(minutes=window[0]), end=now + timedelta(minutes=window[1])
        ),
        confirmation_phrase="amber-basalt-cobalt",
    )


def prepare_tier2(settings, store, **overrides) -> tuple[ChangeEngine, ChangePlan, Any]:
    now = datetime.now(UTC)
    impact = FakeImpact({"sw-core-01": ImpactSummary(touches_trunk_or_uplink=True)})
    engine, executor, notifier = build_engine(
        settings,
        store,
        FakeExecutor(actions=("vlan.add", "switch.trunk_port_config")),
        impact=impact,
        **overrides,
    )
    plan = tier2_plan(now)
    plan.steps[0] = plan.steps[0].model_copy(update={"action": "switch.trunk_port_config"})
    store.save(plan)
    engine.dry_run(plan.id)
    stored = store.get(plan.id)
    assert stored.tier is Tier.WINDOW
    approve(store, stored, phrase="amber-basalt-cobalt")
    return engine, store.get(plan.id), notifier


def test_tier2_runs_inside_its_window_with_a_live_heartbeat(settings, store):
    engine, plan, _ = prepare_tier2(settings, store)

    assert engine.execute(plan.id).outcome == "done"


def test_tier2_refuses_outside_its_window(settings, store):
    engine, plan, _ = prepare_tier2(settings, store)

    with pytest.raises(ChangeRefused, match="maintenance window"):
        engine.execute(plan.id, now=datetime.now(UTC) + timedelta(hours=3))


def test_tier2_refuses_without_a_healthy_heartbeat(settings, store):
    engine, plan, _ = prepare_tier2(settings, store, heartbeat=DeadHeartbeat())

    with pytest.raises(ChangeRefused, match="dead-man heartbeat"):
        engine.execute(plan.id)


def test_the_default_heartbeat_reads_the_metric_and_falls_back_to_prometheus():
    from infra_agent.monitoring import metrics

    now = datetime.now(UTC)
    heartbeat = MetricsHeartbeat(max_age=timedelta(minutes=15))
    metrics.HEARTBEAT_LAST_OK.set(0)
    assert heartbeat.healthy(now)[0] is False

    metrics.HEARTBEAT_LAST_OK.set((now - timedelta(hours=2)).timestamp())
    ok, why = heartbeat.healthy(now)
    assert ok is False and "120 minutes ago" in why

    metrics.HEARTBEAT_LAST_OK.set((now - timedelta(minutes=1)).timestamp())
    assert heartbeat.healthy(now)[0] is True

    metrics.HEARTBEAT_LAST_OK.set(0)
    fallback = MetricsHeartbeat(fallback=lambda: (now - timedelta(minutes=2)).timestamp())
    ok, why = fallback.healthy(now)
    assert ok is True and "prometheus" in why
    assert MetricsHeartbeat(fallback=lambda: None).healthy(now)[0] is False


# -- failure and rollback --------------------------------------------------------
def test_a_failed_post_check_rolls_back_and_pages(settings, store):
    engine, executor, notifier = build_engine(settings, store, FakeExecutor(fail_post=True))
    plan = vlan_plan()
    store.save(plan)
    engine.dry_run(plan.id)
    approve(store, store.get(plan.id))

    before = counter("infra_change_rollbacks_total", {"platform": "cisco"})
    record = engine.execute(plan.id)

    assert record.outcome == "rolled_back"
    assert store.get(plan.id).state is ChangeState.rolled_back
    assert ("rollback", ["vlan.add"]) in executor.calls
    assert record.rollback_steps and all(s.ok for s in record.rollback_steps)
    assert counter("infra_change_rollbacks_total", {"platform": "cisco"}) == before + 1
    assert any("rolled back" in m.lower() for m in notifier.critical)


def test_a_failed_step_rolls_back_what_was_applied_in_order(settings, store):
    executor = FakeExecutor(
        actions=("vlan.add", "switch.access_port_config"), fail_step="switch.access_port_config"
    )
    engine, executor, notifier = build_engine(settings, store, executor)
    plan = vlan_plan(
        steps=[
            ChangeStep(
                description="vlan",
                platform="cisco",
                action="vlan.add",
                params={"device": "sw-core-01", "vlan": 20},
            ),
            ChangeStep(
                description="port",
                platform="cisco",
                action="switch.access_port_config",
                params={"device": "sw-core-01", "interface": "Gi1/0/5", "access_vlan": 20},
            ),
        ]
    )
    store.save(plan)
    engine.dry_run(plan.id)
    approve(store, store.get(plan.id))

    record = engine.execute(plan.id)

    assert record.outcome == "rolled_back"
    # The engine hands the executor the steps in application order; the executor
    # is the one that undoes them in reverse (executors/base.py).
    assert ("rollback", ["vlan.add", "switch.access_port_config"]) in executor.calls
    assert [s.step.action for s in record.rollback_steps] == [
        "switch.access_port_config",
        "vlan.add",
    ]
    assert notifier.critical


def test_a_failed_pre_check_stops_before_anything_is_applied(settings, store):
    engine, executor, notifier = build_engine(settings, store, FakeExecutor(fail_pre=True))
    plan = vlan_plan()
    store.save(plan)
    engine.dry_run(plan.id)
    approve(store, store.get(plan.id))

    record = engine.execute(plan.id)

    assert record.outcome == "failed"
    assert store.get(plan.id).state is ChangeState.failed
    assert not [c for c in executor.calls if c[0] in ("apply", "rollback")]
    assert notifier.critical


def test_a_rollback_that_fails_pages_harder(settings, store):
    engine, _, notifier = build_engine(
        settings, store, FakeExecutor(fail_post=True, rollback_raises=True)
    )
    plan = vlan_plan()
    store.save(plan)
    engine.dry_run(plan.id)
    approve(store, store.get(plan.id))

    record = engine.execute(plan.id)

    assert record.outcome == "rollback_failed"
    assert any("half-changed" in m for m in notifier.critical)


def test_an_advisory_check_pages_but_keeps_the_change(settings, store):
    engine, _, notifier = build_engine(settings, store, FakeExecutor(advisory_fails=True))
    plan = vlan_plan()
    store.save(plan)
    engine.dry_run(plan.id)
    approve(store, store.get(plan.id))

    record = engine.execute(plan.id)

    assert record.outcome == "done"
    assert [c.advisory for c in record.checks if c.check.startswith("advisory")] == [True]
    assert any("write memory" in m for m in notifier.critical)


def test_manual_rollback_undoes_the_last_execution(settings, store):
    engine, executor, notifier = build_engine(settings, store)
    plan = vlan_plan()
    store.save(plan)
    engine.dry_run(plan.id)
    approve(store, store.get(plan.id))
    engine.execute(plan.id)

    record = engine.rollback(plan.id)

    assert record.outcome == "rolled_back"
    assert ("rollback", ["vlan.add"]) in executor.calls
    assert notifier.critical


def test_rollback_refuses_a_plan_that_never_ran(settings, store):
    engine, _, _ = build_engine(settings, store)
    plan = vlan_plan()
    store.save(plan)

    with pytest.raises(ChangeRefused, match="no recorded execution"):
        engine.rollback(plan.id)


# -- tier 0 ----------------------------------------------------------------------
def errdisable_plan(engine: ChangeEngine) -> ChangePlan:
    return engine.tier0_plan("switch.clear_errdisable", "sw-core-01:Gi1/0/12", cause="link-flap")


def test_tier0_shadow_mode_reports_and_changes_nothing(settings, store):
    settings.tier0_shadow_mode = True
    engine, executor, _ = build_engine(
        settings,
        store,
        FakeExecutor(actions=("switch.clear_errdisable",)),
        guard=Tier0Guard(frozen=False, shadow_mode=True),
    )

    outcome = engine.run_tier0(errdisable_plan(engine), guard_checked=True)

    assert outcome.mode == "shadow"
    assert outcome.ran is False
    assert "would have run" in outcome.summary
    assert executor.calls == []


def test_tier0_live_dry_runs_approves_and_executes(settings, store):
    settings.tier0_shadow_mode = False
    engine, executor, notifier = build_engine(
        settings,
        store,
        FakeExecutor(actions=("switch.clear_errdisable",)),
        guard=Tier0Guard(frozen=False, shadow_mode=False),
    )
    plan = errdisable_plan(engine)

    outcome = engine.run_tier0(plan, guard_checked=True)

    assert outcome.mode == "live" and outcome.ran is True
    stored = store.get(plan.id)
    assert stored.state is ChangeState.done
    assert stored.approval is None  # tier 0 needs no approval record...
    assert any("tier 0 guard allowed" in h.note for h in stored.history)  # ...but says why
    assert [c[0] for c in executor.calls] == ["dry_run", "pre_check", "apply", "post_check"]


def test_tier0_consults_the_guard_when_the_caller_has_not(settings, store):
    settings.tier0_shadow_mode = False
    guard = Tier0Guard(frozen=False, shadow_mode=False)
    engine, executor, _ = build_engine(
        settings, store, FakeExecutor(actions=("switch.clear_errdisable",)), guard=guard
    )

    refused = engine.run_tier0(
        errdisable_plan(engine), object_id="sw-core-01:Gi1/0/12", object_tags=[], cause="link-flap"
    )
    assert refused.mode == "refused" and "opt-in" in refused.summary
    assert executor.calls == []

    allowed = engine.run_tier0(
        errdisable_plan(engine),
        object_id="sw-core-01:Gi1/0/12",
        object_tags=["auto:errdisable"],
        cause="link-flap",
    )
    assert allowed.mode == "live"

    # The cooldown was spent by the run above.
    again = engine.run_tier0(
        errdisable_plan(engine),
        object_id="sw-core-01:Gi1/0/12",
        object_tags=["auto:errdisable"],
        cause="link-flap",
    )
    assert again.mode == "refused" and "cooldown" in again.summary


def test_tier0_that_impact_analysis_escalates_goes_to_the_approval_channel(settings, store):
    settings.tier0_shadow_mode = False
    impact = FakeImpact({"sw-core-01:Gi1/0/12": ImpactSummary(feeds_ilo_or_mgmt_vlan=True)})
    engine, executor, notifier = build_engine(
        settings,
        store,
        FakeExecutor(actions=("switch.clear_errdisable",)),
        guard=Tier0Guard(frozen=False, shadow_mode=False),
        impact=impact,
    )
    plan = errdisable_plan(engine)

    outcome = engine.run_tier0(plan, guard_checked=True)

    assert outcome.mode == "escalated" and outcome.ran is False
    assert store.get(plan.id).state is ChangeState.awaiting_approval
    assert notifier.approvals and notifier.approvals[0][0] == plan.id
    assert not [c for c in executor.calls if c[0] == "apply"]


def test_tier0_is_blocked_when_the_graph_does_not_know_the_object(settings, store):
    settings.tier0_shadow_mode = False
    engine, executor, _ = build_engine(
        settings,
        store,
        FakeExecutor(actions=("switch.clear_errdisable",)),
        guard=Tier0Guard(frozen=False, shadow_mode=False),
        impact=MissingImpact(),
    )

    outcome = engine.run_tier0(errdisable_plan(engine), guard_checked=True)

    assert outcome.mode == "refused"
    assert "topology graph" in outcome.summary
    assert not [c for c in executor.calls if c[0] == "apply"]


def test_tier0_is_blocked_when_only_one_of_its_targets_is_unknown(settings, store):
    """A Tier 0 action must not run blind, even against a partly known plan."""
    settings.tier0_shadow_mode = False

    class HalfKnown:
        def __call__(self, target: str) -> Any:
            found = target.startswith("sw-core-01:")
            return type("Report", (), {"found": found, "summary": ImpactSummary()})()

    engine, executor, _ = build_engine(
        settings,
        store,
        FakeExecutor(actions=("switch.clear_errdisable",)),
        guard=Tier0Guard(frozen=False, shadow_mode=False),
        impact=HalfKnown(),
    )
    plan = engine.tier0_plan("switch.clear_errdisable", "sw-core-01:Gi1/0/12")
    plan.targets.append("sw-core-01")  # a target the graph cannot resolve

    outcome = engine.run_tier0(plan, guard_checked=True)

    assert outcome.mode == "refused"
    assert "tier 0 action must not run against an object" in outcome.summary
    assert not [c for c in executor.calls if c[0] == "apply"]


def test_a_tier0_plan_still_refuses_to_execute_in_shadow_mode(settings, store):
    settings.tier0_shadow_mode = False
    engine, _, _ = build_engine(
        settings,
        store,
        FakeExecutor(actions=("switch.clear_errdisable",)),
        guard=Tier0Guard(frozen=False, shadow_mode=False),
    )
    plan = errdisable_plan(engine)
    store.save(plan)
    engine.dry_run(plan.id)
    plan = store.get(plan.id)
    plan.transition(ChangeState.approved, "by hand")
    store.save(plan)
    settings.tier0_shadow_mode = True

    with pytest.raises(ChangeRefused, match="shadow mode"):
        engine.execute(plan.id)


def test_can_run_tier0_declines_what_the_platform_cannot_touch(settings, store):
    engine, _, _ = build_engine(settings, store, FakeExecutor(actions=("switch.clear_errdisable",)))

    assert engine.can_run_tier0("switch.clear_errdisable", "sw-core-01:Gi1/0/12") is True
    assert engine.can_run_tier0("switch.clear_errdisable", "sw-edge-02:Gi1/0/1") is False
    assert engine.can_run_tier0("switch.clear_errdisable", "no-such-switch") is False
    assert engine.can_run_tier0("vm.power_on", "sw-core-01") is False


# -- unapproved config changes ---------------------------------------------------
class FakeConfigStore:
    def __init__(self, entries: list[dict[str, str]] | None = None) -> None:
        self.entries = entries or []

    def history(self, device: str, limit: int = 20) -> list[dict[str, str]]:
        return list(self.entries)


def test_a_commit_that_matches_an_execution_is_not_flagged(settings, store):
    engine, _, notifier = build_engine(settings, store)
    plan = vlan_plan()
    store.save(plan)
    engine.dry_run(plan.id)
    approve(store, store.get(plan.id))
    record = engine.execute(plan.id)

    result = engine.correlate_config_change(
        "sw-core-01", "abc123def456", record.started_at + timedelta(minutes=2)
    )

    assert result.matched is True
    assert result.plan_id == plan.id
    assert engine.unapproved_changes() == []
    assert not [m for m in notifier.critical if "Unapproved" in m]


def test_a_commit_outside_the_window_is_an_unapproved_change(settings, store):
    engine, _, notifier = build_engine(settings, store)
    plan = vlan_plan()
    store.save(plan)
    engine.dry_run(plan.id)
    approve(store, store.get(plan.id))
    record = engine.execute(plan.id)

    before = counter("infra_unapproved_config_changes_total", {"device": "sw-core-01"})
    result = engine.correlate_config_change(
        "sw-core-01",
        "deadbeefcafe",
        record.started_at + timedelta(hours=2),
        filename="running-config.txt",
    )

    assert result.matched is False
    assert result.recorded is not None
    recorded = engine.unapproved_changes("sw-core-01")
    assert [c.commit_sha for c in recorded] == ["deadbeefcafe"]
    assert recorded[0].filename == "running-config.txt"
    assert counter("infra_unapproved_config_changes_total", {"device": "sw-core-01"}) == before + 1
    assert any("Unapproved configuration change" in m for m in notifier.critical)


def test_recording_the_same_commit_twice_does_not_duplicate_it(settings, store):
    engine, _, _ = build_engine(settings, store)
    at = datetime.now(UTC)

    engine.correlate_config_change("sw-core-01", "abc", at)
    engine.correlate_config_change("sw-core-01", "abc", at)

    assert len(engine.unapproved_changes("sw-core-01")) == 1


def test_the_commit_time_comes_from_the_config_store_when_it_is_not_given(settings, store):
    at = datetime.now(UTC) - timedelta(days=1)
    config_store = FakeConfigStore([{"sha": "feedface0001", "at": at.isoformat()}])
    engine, _, _ = build_engine(settings, store, config_store=config_store)

    result = engine.correlate_config_change("sw-core-01", "feedface0001")

    assert result.at == at


def test_the_scheduler_hook_correlates_every_commit_it_is_given(settings, store):
    engine, _, notifier = build_engine(settings, store)

    results = config_change_hook("sw-core-01", {"running-config.txt": "aaa111"}, engine=engine)

    assert [r.matched for r in results] == [False]
    assert engine.unapproved_changes("sw-core-01")[0].filename == "running-config.txt"
    assert config_change_hook("sw-core-01", {}, engine=engine) == []


# -- secrecy ---------------------------------------------------------------------
def test_no_llm_visible_payload_ever_carries_credentials_or_approval_material(
    settings, store, caplog
):
    engine, _, notifier = build_engine(settings, store)
    plan = vlan_plan()
    store.save(plan)
    with caplog.at_level(logging.DEBUG):
        engine.dry_run(plan.id)
        token = engine.request_approval(plan.id)
        store.approve(plan.id, token, "owner", "cli")
        record = engine.execute(plan.id)

    payloads = json.dumps(
        {
            "plan": store.get(plan.id).llm_view(),
            "record": record.llm_view(),
            "executions": [r.llm_view() for r in store.executions(plan.id)],
            "messages": notifier.messages,
        }
    )
    for secret in (token, PASSWORD, "sw-core-01-rw"):
        assert secret not in payloads
    assert token not in caplog.text
    assert PASSWORD not in caplog.text


# -- the tool layer ----------------------------------------------------------------
def test_the_change_tools_expose_dry_run_and_hide_everything_that_writes():
    from infra_agent.tools.registry import REGISTRY, human_only_tools, llm_tools, load_all

    load_all()
    llm = {t.name for t in llm_tools()}
    human = {t.name for t in human_only_tools()}

    assert "change.dry_run" in llm
    assert "change.unapproved" in llm
    assert {"change.approve", "change.execute", "change.rollback"} <= human
    assert not {"change.approve", "change.execute", "change.rollback"} & llm
    assert REGISTRY["change.dry_run"].parallel_safe is False


def test_the_dry_run_tool_returns_the_llm_view_and_nothing_else(settings, store, monkeypatch):
    from infra_agent.tools import change_tools

    engine, _, _ = build_engine(settings, store)
    monkeypatch.setattr(change_tools, "store", lambda: store)
    change_tools.configure(engine)
    try:
        plan = vlan_plan()
        store.save(plan)

        view = change_tools.dry_run(plan.id)

        assert view["state"] == ChangeState.dry_run.value
        assert "approval" not in view and "confirmation_phrase" not in view
        assert view == store.get(plan.id).llm_view()

        assert view["diff"]["by_device"]["sw-core-01"]["commands"] == ["! vlan.add"]
    finally:
        change_tools.configure(None)


def test_the_execute_and_rollback_tools_drive_the_engine(settings, store, monkeypatch):
    from infra_agent.tools import change_tools

    engine, executor, _ = build_engine(settings, store)
    monkeypatch.setattr(change_tools, "store", lambda: store)
    change_tools.configure(engine)
    try:
        plan = vlan_plan()
        store.save(plan)
        change_tools.dry_run(plan.id)
        approve(store, store.get(plan.id))

        assert change_tools.execute(plan.id)["outcome"] == "done"
        assert change_tools.rollback(plan.id)["outcome"] == "rolled_back"
        assert change_tools.unapproved() == []
    finally:
        change_tools.configure(None)


# -- the triage tier 0 hook ----------------------------------------------------------
def build_triage(settings, store):
    from infra_agent.agent.triage import TriageService

    return TriageService(
        settings=settings,
        runner=object(),  # never used: the hook is tested without a model run
        notifier=RecordingNotifier(),
        plan_store=store,
        guard=Tier0Guard(frozen=False, shadow_mode=False),
        inventory=lambda: INVENTORY,
    )


def test_the_triage_hook_declines_what_the_platform_cannot_act_on(settings, store):
    from infra_agent.agent.triage import Tier0Candidate

    service = build_triage(settings, store)

    for object_id in ("sw-edge-02:Gi1/0/1", "no-such-switch:Gi1/0/1"):
        candidate = Tier0Candidate(action="switch.clear_errdisable", object_id=object_id)
        assert service.change_engine_executor(candidate) is None
    assert (
        service.change_engine_executor(Tier0Candidate(action="vm.power_on", object_id="sw-core-01"))
        is None
    )


def test_the_triage_hook_is_wired_for_a_device_with_a_read_write_credential(settings, store):
    from infra_agent.agent.triage import Tier0Candidate

    service = build_triage(settings, store)
    candidate = Tier0Candidate(action="switch.clear_errdisable", object_id="sw-core-01:Gi1/0/12")

    assert callable(service.change_engine_executor(candidate))


def test_the_tier0_plan_the_hook_builds_names_the_port_and_its_checks(settings, store):
    engine, _, _ = build_engine(settings, store, FakeExecutor(actions=("switch.clear_errdisable",)))

    plan = engine.tier0_plan("switch.clear_errdisable", "sw-core-01:Gi1/0/12", cause="link-flap")

    assert plan.tier is Tier.AUTO
    assert plan.steps[0].params == {"device": "sw-core-01", "interface": "Gi1/0/12"}
    assert plan.post_checks == ["no errdisable on Gi1/0/12", "interface Gi1/0/12 is up"]
    assert "link-flap" in plan.summary
    with pytest.raises(ChangeRefused, match="not a device"):
        engine.tier0_plan("switch.clear_errdisable", "no-such-switch:Gi1/0/1")


# -- the scheduler hook ---------------------------------------------------------------
def test_the_collector_scheduler_calls_the_engine_for_every_commit(settings, store, monkeypatch):
    import infra_agent.scheduler as scheduler

    engine, _, notifier = build_engine(settings, store)
    monkeypatch.setattr(
        "infra_agent.change.engine.ChangeEngine.from_settings",
        classmethod(lambda cls, *a, **k: engine),
    )

    scheduler._correlate_config_commits("sw-core-01", {"running-config.txt": "c0ffee"})

    assert [c.commit_sha for c in engine.unapproved_changes()] == ["c0ffee"]
    assert any("Unapproved configuration change" in m for m in notifier.critical)


def test_the_scheduler_hook_never_lets_a_correlation_failure_break_collection(
    settings, store, monkeypatch
):
    import infra_agent.scheduler as scheduler

    def explode(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the plan store is locked")

    monkeypatch.setattr("infra_agent.change.engine.config_change_hook", explode)

    scheduler._correlate_config_commits("sw-core-01", {"running-config.txt": "c0ffee"})
