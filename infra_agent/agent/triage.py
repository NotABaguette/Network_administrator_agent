"""Alert triage: Alertmanager webhook -> grouped incident -> one advisory agent run.

The model is advisory. It may propose a `ChangePlan` and may nominate a single
Tier 0 candidate; it can do neither by itself, and nothing it writes is taken
as a fact about the estate:

* a proposed plan contributes *content only* (`PLAN_CONTENT_FIELDS`). Its id,
  tier, state, approval record, history, window, timestamps and Tier 2
  confirmation phrase are minted here, so the model cannot hand itself an
  approved plan, choose a phrase it then knows, or overwrite a plan the owner
  is already looking at. The token minted by `PlanStore.request_approval` goes
  straight to `Notifier.send_approval_request` and nowhere else - not the
  model, not the returned `Triage`, not the log.
* a Tier 0 candidate names an action and an object; the opt-in tags come from
  the inventory record for that object and the cause is derived from the
  incident, never read off the model's own JSON. `docs/risk-tiers.md` makes
  both properties of the estate, not assertions by the proposer.
* the guard honours `settings.frozen` - re-read from the break-glass marker on
  every run - and `settings.tier0_shadow_mode`, and at most one Tier 0 action
  runs (or is shadowed) per triage run. Its cooldowns and per-day caps survive
  a restart via `AgentStateStore` and are serialised across the webhook's
  threads by one lock.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from infra_agent.agent.freeze import refresh_frozen
from infra_agent.agent.notify import LogNotifier, Notifier
from infra_agent.agent.runner import AgentRunner, AgentRunResult
from infra_agent.agent.state import AgentStateStore
from infra_agent.change.plan import ChangePlan, ChangeState, Tier
from infra_agent.change.store import PlanStore
from infra_agent.change.tiers import TIER0_POLICIES, ImpactSummary, Tier0Guard, compute_tier
from infra_agent.config import Settings, get_settings
from infra_agent.models.common import SeedInventory
from infra_agent.monitoring import metrics
from infra_agent.redaction.gateway import RedactionGateway

log = logging.getLogger(__name__)

SEVERITY_ORDER = ["critical", "warning", "info", "none"]

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

#: The only fields a proposed plan may contribute: its content. Everything else
#: about a `ChangePlan` is platform state, and a model that could set `state`
#: could persist an already-approved plan, one that could set `id` could swap
#: the body of a plan the owner is being asked to approve, and one that could
#: set `confirmation_phrase` would know the Tier 2 phrase.
PLAN_CONTENT_FIELDS = (
    "title",
    "action",
    "targets",
    "summary",
    "diff",
    "pre_checks",
    "steps",
    "post_checks",
    "rollback",
)

#: Labels an alert may carry that state the cause outright.
CAUSE_LABEL_KEYS = ("cause", "reason", "errdisable_reason", "err_disable_reason")

TRIAGE_INSTRUCTIONS = """\
Triage this grouped alert. Use the read tools to gather evidence before you
conclude anything; say what you do not know rather than guessing.

Answer with a short paragraph of reasoning followed by exactly one JSON object,
last in your message, with these keys:

  probable_cause      string, one sentence
  confidence          "low" | "medium" | "high"
  evidence            array of strings, each naming a tool result you relied on
  recommended_action  string, one clear recommendation for the owner
  proposed_plan       a ChangePlan object, or null if no change is warranted.
                      Use the same fields as the `change_propose` tool: title,
                      action, targets, summary, diff (structured, never raw
                      config), pre_checks, steps, post_checks, rollback. Any
                      other field is ignored: the platform owns the plan's id,
                      tier, state and approval.
  tier0_candidate     null, or an object {action, object_id, cause, rationale}
                      naming ONE idempotent, reversible, single-object Tier 0
                      action from the allowlist. The opt-in tag is read from
                      the inventory and the cause from the alert itself, so
                      nominate the object by its real name and expect a refusal
                      if it is not opted in.

You cannot approve or execute anything. Proposing a plan only puts it in front
of the owner; a Tier 0 candidate is still checked against its guard.
"""


class Alert(BaseModel):
    """One alert inside an Alertmanager webhook payload."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    status: str = "firing"
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    starts_at: datetime | None = Field(default=None, alias="startsAt")
    ends_at: datetime | None = Field(default=None, alias="endsAt")
    fingerprint: str = ""
    generator_url: str | None = Field(default=None, alias="generatorURL")

    @property
    def device(self) -> str | None:
        for key in ("device", "instance", "host", "target"):
            if self.labels.get(key):
                return self.labels[key]
        return None


class AlertmanagerWebhook(BaseModel):
    """The Alertmanager v4 webhook body."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    version: str = "4"
    group_key: str = Field(default="", alias="groupKey")
    status: str = "firing"
    receiver: str = ""
    group_labels: dict[str, str] = Field(default_factory=dict, alias="groupLabels")
    common_labels: dict[str, str] = Field(default_factory=dict, alias="commonLabels")
    common_annotations: dict[str, str] = Field(default_factory=dict, alias="commonAnnotations")
    external_url: str = Field(default="", alias="externalURL")
    alerts: list[Alert] = Field(default_factory=list)


class Incident(BaseModel):
    """One grouped incident: what the agent is asked to explain."""

    id: str
    status: str
    severity: str
    receiver: str = ""
    alertnames: list[str] = Field(default_factory=list)
    devices: list[str] = Field(default_factory=list)
    group_labels: dict[str, str] = Field(default_factory=dict)
    common_labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    started_at: datetime | None = None
    firing: int = 0
    resolved: int = 0
    alerts: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def title(self) -> str:
        names = ", ".join(self.alertnames) or "alert"
        where = ", ".join(self.devices)
        return f"{names} on {where}" if where else names


class Tier0Candidate(BaseModel):
    """A Tier 0 action the model nominates. Only `action` and `object_id` are used.

    `claimed_tags` and `claimed_cause` are kept under their wire names so the
    model's own JSON still parses and so the record shows what it asserted, but
    they are evidence about the model, not about the estate: the guard is given
    the tags on the inventory object and the cause derived from the incident.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    action: str
    object_id: str
    claimed_tags: list[str] = Field(default_factory=list, alias="object_tags")
    claimed_cause: str | None = Field(default=None, alias="cause")
    rationale: str = ""


class Tier0Decision(BaseModel):
    """What the guard said, and what was actually done about it."""

    action: str
    object_id: str
    allowed: bool
    mode: str  # shadow | live | unwired | refused | skipped | failed
    reason: str
    executed: bool = False
    #: The tags and cause the guard actually judged, from the platform's records.
    object_tags: list[str] = Field(default_factory=list)
    cause: str | None = None


class Triage(BaseModel):
    """The outcome of one triage run. Contains no approval material."""

    incident_id: str
    incident_title: str = ""
    status: str = "firing"
    severity: str = "none"
    probable_cause: str = ""
    confidence: str = "low"
    evidence: list[str] = Field(default_factory=list)
    recommended_action: str = ""
    proposed_plan: dict[str, Any] | None = None
    plan_id: str | None = None
    plan_tier: int | None = None
    approval_requested: bool = False
    tier0_candidate: Tier0Candidate | None = None
    tier0_decisions: list[Tier0Decision] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    run: AgentRunResult | None = None


def _requested_tier(proposed: dict[str, Any]) -> Tier | None:
    """The tier the proposal asked for, if it asked for one at all."""
    try:
        return Tier(int(proposed["tier"]))
    except (KeyError, TypeError, ValueError):
        return None


def mint_confirmation_phrase() -> str:
    """A Tier 2 phrase the owner types back. Minted here so the model never sees it."""
    return "-".join(secrets.choice(CONFIRMATION_WORDS) for _ in range(3))


def _label_sources(incident: Incident) -> Iterable[dict[str, str]]:
    yield incident.common_labels
    yield incident.group_labels
    yield incident.annotations
    for alert in incident.alerts:
        for key in ("labels", "annotations"):
            value = alert.get(key)
            if isinstance(value, dict):
                yield {str(k): str(v) for k, v in value.items()}


def derive_cause(action: str, incident: Incident) -> str | None:
    """The cause of this incident, taken from the alert rather than the model.

    An explicit `cause`/`reason` label wins. Otherwise the incident's own text
    is searched for one of the action's known causes, and a denied cause found
    anywhere wins over an allowed one: `bpduguard` mentioned next to `link-flap`
    must not clear an err-disable. An ambiguous or absent cause returns None,
    which the guard refuses for any action with a cause allowlist.
    """
    policy = TIER0_POLICIES.get(action)
    if policy is None:
        return None
    for labels in _label_sources(incident):
        for key in CAUSE_LABEL_KEYS:
            value = labels.get(key)
            if value:
                return str(value)
    haystack = " ".join(
        str(value) for labels in _label_sources(incident) for value in labels.values()
    ).lower()
    denied = [c for c in policy.cause_denylist if c.lower() in haystack]
    if denied:
        return denied[0]
    allowed = [c for c in (policy.cause_allowlist or []) if c.lower() in haystack]
    return allowed[0] if len(allowed) == 1 else None


def group_incident(payload: AlertmanagerWebhook) -> Incident:
    """Fold an Alertmanager group into the single incident the agent reasons about."""
    alerts = payload.alerts
    severities = {a.labels.get("severity", "none") for a in alerts}
    severity = next((s for s in SEVERITY_ORDER if s in severities), "none")
    devices = sorted({d for d in (a.device for a in alerts) if d})
    alertnames = sorted({a.labels.get("alertname", "unknown") for a in alerts})
    starts = [a.starts_at for a in alerts if a.starts_at]
    key = payload.group_key or f"{payload.receiver}:{sorted(payload.group_labels.items())}"
    return Incident(
        id=hashlib.sha256(key.encode()).hexdigest()[:12],
        status=payload.status,
        severity=severity,
        receiver=payload.receiver,
        alertnames=alertnames,
        devices=devices,
        group_labels=payload.group_labels,
        common_labels=payload.common_labels,
        annotations=payload.common_annotations,
        started_at=min(starts) if starts else None,
        firing=sum(1 for a in alerts if a.status == "firing"),
        resolved=sum(1 for a in alerts if a.status == "resolved"),
        alerts=[
            {
                "status": a.status,
                "labels": a.labels,
                "annotations": a.annotations,
                "starts_at": a.starts_at,
                "device": a.device,
                "fingerprint": a.fingerprint,
            }
            for a in alerts
        ],
    )


class TriageService:
    """Turns Alertmanager webhooks into one advisory agent run and its consequences."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        runner: AgentRunner | None = None,
        notifier: Notifier | None = None,
        plan_store: PlanStore | None = None,
        guard: Tier0Guard | None = None,
        gateway: RedactionGateway | None = None,
        impact_provider: Callable[[ChangePlan], ImpactSummary] | None = None,
        tier0_executor: Callable[[Tier0Candidate, Incident], str] | None = None,
        inventory: Callable[[], SeedInventory] | None = None,
        state: AgentStateStore | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.gateway = gateway or RedactionGateway(audit_log=self.settings.audit_log)
        self.runner = runner or AgentRunner(settings=self.settings, gateway=self.gateway)
        self.notifier = notifier or LogNotifier()
        self.plans = plan_store or PlanStore(self.settings.data_dir / "plans.db")
        self.guard = guard or Tier0Guard(
            frozen=self.settings.frozen, shadow_mode=self.settings.tier0_shadow_mode
        )
        self.impact_provider = impact_provider
        self.tier0_executor = tier0_executor
        self._inventory = inventory or (lambda: SeedInventory.load(self.settings.seed_inventory))
        self.state = state or AgentStateStore(self.settings.data_dir / "agent-state.db")
        # The webhook triages in FastAPI's threadpool, so two alerts for the
        # same object can reach the guard at once. allow+record is one step.
        self._tier0_lock = threading.RLock()
        self._history_loaded = False

    # -- entry points -------------------------------------------------------
    def parse(self, payload: dict[str, Any]) -> Incident:
        return group_incident(AlertmanagerWebhook.model_validate(payload))

    def handle(self, payload: dict[str, Any]) -> Triage:
        return self.triage(self.parse(payload))

    def triage(self, incident: Incident) -> Triage:
        # A freeze issued while the service is running must be visible to this
        # run, not to the one after the next restart.
        refresh_frozen(self.settings)
        result = self.runner.run_json(
            TRIAGE_INSTRUCTIONS,
            kind="triage",
            context=incident.model_dump(mode="json"),
        )
        triage = Triage(
            incident_id=incident.id,
            incident_title=incident.title,
            status=incident.status,
            severity=incident.severity,
            run=result,
        )
        answer = result.payload
        if answer is None:
            triage.notes.append(
                f"The agent run ended as {result.outcome} without a structured answer."
            )
            self.notifier.send(
                f"Triage of {incident.title} produced no structured answer ({result.outcome}).",
                critical=incident.severity == "critical",
            )
            return triage

        triage.probable_cause = str(answer.get("probable_cause") or "")
        triage.confidence = str(answer.get("confidence") or "low")
        triage.evidence = [str(e) for e in (answer.get("evidence") or [])]
        triage.recommended_action = str(answer.get("recommended_action") or "")

        self._handle_plan(triage, answer.get("proposed_plan"))
        self._handle_tier0(triage, incident, answer.get("tier0_candidate"))

        self.notifier.send(self.summary(triage), critical=incident.severity == "critical")
        return triage

    # -- consequences -------------------------------------------------------
    def _handle_plan(self, triage: Triage, proposed: Any) -> None:
        if not isinstance(proposed, dict) or not proposed:
            return
        # Content only. `tier` is read separately by `_retier`, which allows an
        # escalation and nothing else; every other field is platform state.
        content = {key: proposed[key] for key in PLAN_CONTENT_FIELDS if key in proposed}
        ignored = sorted(set(proposed) - set(PLAN_CONTENT_FIELDS) - {"tier"})
        try:
            plan = ChangePlan.model_validate({**content, "proposed_by": "agent-triage"})
        except Exception as exc:
            triage.notes.append(f"The proposed plan was not a valid ChangePlan: {exc}")
            return
        if ignored:
            triage.notes.append(
                "Ignored proposed plan fields the platform owns: " + ", ".join(ignored)
            )
        self._retier(plan, _requested_tier(proposed))
        if plan.tier is Tier.WINDOW:
            # Always minted, never kept: a phrase the model chose is a phrase
            # the model knows, and the phrase is half of the Tier 2 gate.
            plan.confirmation_phrase = mint_confirmation_phrase()
        try:
            plan.transition(
                ChangeState.dry_run,
                "no executor wired yet (Phase 4); recorded so the plan can await approval",
            )
        except Exception as exc:  # pragma: no cover - a fresh plan is always `proposed`
            triage.notes.append(f"Could not record the proposed plan: {exc}")
            return
        # Saved only once it is in a state the engine recognises, so a failure
        # above never leaves a half-built plan in the store.
        self.plans.save(plan)
        triage.proposed_plan = plan.llm_view()
        triage.plan_id = plan.id
        triage.plan_tier = int(plan.tier)
        try:
            token = self.plans.request_approval(plan)
        except Exception as exc:
            triage.notes.append(f"Could not request approval for {plan.id}: {exc}")
            return
        # The token exists in this scope only: it goes to the human channel and
        # is never logged, never returned, never shown to the model.
        self.notifier.send_approval_request(plan, token)
        del token
        triage.approval_requested = True
        triage.proposed_plan = plan.llm_view()  # now shows awaiting_approval

    def _retier(self, plan: ChangePlan, requested: Tier | None) -> None:
        """The tier is computed, never taken from the model. The model may only escalate."""
        impact = self.impact_provider(plan) if self.impact_provider else ImpactSummary()
        computed, reasons = compute_tier(plan.action, impact)
        tier = computed
        if computed is Tier.AUTO:
            # Tier 0 is reached through Tier0Guard on a tagged object, never by
            # a plan the model wrote.
            tier = Tier.APPROVAL
            reasons.append("agent-proposed plans always need at least one human approval")
        if requested is not None and int(requested) > int(tier):
            reasons.append(f"kept the higher tier the proposal asked for: {requested.name}")
            tier = requested
        plan.tier = tier
        plan.tier_reasons = reasons

    def _handle_tier0(self, triage: Triage, incident: Incident, candidate: Any) -> None:
        candidates = candidate if isinstance(candidate, list) else [candidate]
        parsed: list[Tier0Candidate] = []
        for item in candidates:
            if not isinstance(item, dict) or not item.get("action"):
                continue
            try:
                parsed.append(Tier0Candidate.model_validate(item))
            except Exception as exc:
                triage.notes.append(f"Ignored a malformed Tier 0 candidate: {exc}")
        if not parsed:
            return
        triage.tier0_candidate = parsed[0]
        for extra in parsed[1:]:
            triage.tier0_decisions.append(
                Tier0Decision(
                    action=extra.action,
                    object_id=extra.object_id,
                    allowed=False,
                    mode="skipped",
                    reason="at most one Tier 0 action runs per triage run",
                )
            )
        triage.tier0_decisions.insert(0, self._apply_tier0(parsed[0], incident))

    def object_tags(self, object_id: str) -> tuple[list[str], str | None]:
        """The opt-in tags the *platform* holds for an object, or why it cannot say.

        `object_id` is `device` or `device:port`; the device part is looked up
        in the seed inventory (NetBox later). The model's own claim about the
        tags is never consulted - that is the whole point of an opt-in tag.
        """
        device_name = object_id.split(":", 1)[0].strip()
        if not device_name:
            return [], f"{object_id!r} does not name an object"
        try:
            device = self._inventory().get(device_name)
        except Exception as exc:
            log.exception("could not read the inventory for %s", object_id)
            return [], f"the inventory could not be read ({type(exc).__name__})"
        if device is None:
            return [], f"{device_name!r} is not a device in the inventory"
        return list(device.tags), None

    def _load_tier0_history(self) -> None:
        """Replay the persisted Tier 0 history into the guard, once per process.

        Without this a restart (or a crash loop) hands every object a fresh
        cooldown and a fresh per-day retry cap.
        """
        if self._history_loaded:
            return
        self._history_loaded = True
        try:
            self.state.prune_tier0()
            for action, object_id, at in self.state.tier0_history():
                self.guard.record(action, object_id, now=at)
        except Exception:
            log.exception("could not restore the Tier 0 history; cooldowns start empty")

    def change_engine_executor(
        self, candidate: Tier0Candidate
    ) -> Callable[[Tier0Candidate, Incident], str] | None:
        """Phase 4 hook: run an allowed Tier 0 candidate through the change engine.

        Returns None - so the decision stays `unwired`, exactly as it did before
        the engine existed - whenever the platform cannot act on that object at
        all: it is not a device in the inventory, it has no read-write
        credential (collectors keep the read-only one), or no executor
        implements the action for its platform. Shadow mode never reaches here;
        the caller has already reported "would have done X".

        The guard has already allowed the action and recorded the run, so
        `run_tier0` is told not to consult it twice; its own freeze check, its
        dry run and the recomputed tier still apply, and an action impact
        analysis escalates goes to the approval channel instead of running.
        """
        try:
            from infra_agent.change.engine import ChangeEngine
        except Exception:  # pragma: no cover - the change package is always present
            return None
        engine = ChangeEngine.from_settings(
            self.settings,
            notifier=self.notifier,
            plan_store=self.plans,
            guard=self.guard,
            inventory=self._inventory,
            gateway=self.gateway,
        )
        if not engine.can_run_tier0(candidate.action, candidate.object_id):
            return None

        def run(one: Tier0Candidate, incident: Incident) -> str:
            plan = engine.tier0_plan(
                one.action,
                one.object_id,
                cause=derive_cause(one.action, incident),
                title=f"tier 0: {one.action} on {one.object_id}",
            )
            return engine.run_tier0(plan, guard_checked=True, object_id=one.object_id).summary

        return run

    def _tier0_refusal(
        self, candidate: Tier0Candidate, reason: str, tags: list[str], cause: str | None
    ) -> Tier0Decision:
        metrics.AGENT_TIER0_ACTIONS.labels(action=candidate.action, mode="refused").inc()
        self.notifier.send(
            f"Tier 0 refused: {candidate.action} on {candidate.object_id} ({reason})."
        )
        return Tier0Decision(
            action=candidate.action,
            object_id=candidate.object_id,
            allowed=False,
            mode="refused",
            reason=reason,
            object_tags=tags,
            cause=cause,
        )

    def _apply_tier0(self, candidate: Tier0Candidate, incident: Incident) -> Tier0Decision:
        # The break-glass marker is re-read here and not only at start-up: the
        # freeze has to stop the action this run is about to take.
        frozen = refresh_frozen(self.settings)
        self.guard.frozen = frozen
        self.guard.shadow_mode = self.settings.tier0_shadow_mode
        if frozen:
            # `cause` stays None: the decision record carries what the platform
            # established, and a frozen run establishes nothing.
            return self._tier0_refusal(candidate, "platform is frozen (break-glass)", [], None)
        policy = TIER0_POLICIES.get(candidate.action)
        tags: list[str] = []
        if policy is not None and policy.required_tag:
            # Only an action with an opt-in tag needs the object to be one the
            # platform knows: `alert.silence` and `discovery.rerun` are not
            # inventory objects at all.
            tags, problem = self.object_tags(candidate.object_id)
            if problem is not None:
                return self._tier0_refusal(candidate, problem, tags, None)
        cause = derive_cause(candidate.action, incident)
        with self._tier0_lock:
            self._load_tier0_history()
            allowed, reason = self.guard.allow(candidate.action, candidate.object_id, tags, cause)
            if allowed:
                # Cooldowns and retry caps must behave the same in shadow mode,
                # otherwise a week of shadow proves nothing about live, and they
                # are recorded before the action so a crash cannot retry it.
                self.guard.record(candidate.action, candidate.object_id)
                try:
                    self.state.record_tier0(candidate.action, candidate.object_id)
                except Exception:
                    log.exception("could not persist the Tier 0 record for %s", candidate.action)
        if not allowed:
            return self._tier0_refusal(candidate, reason, tags, cause)
        decision = Tier0Decision(
            action=candidate.action,
            object_id=candidate.object_id,
            allowed=True,
            mode="shadow",
            reason=reason,
            object_tags=tags,
            cause=cause,
        )
        if self.guard.shadow_mode:
            metrics.AGENT_TIER0_ACTIONS.labels(action=candidate.action, mode="shadow").inc()
            self.notifier.send(
                f"Tier 0 (shadow): would have run {candidate.action} on "
                f"{candidate.object_id} for {incident.title}. {candidate.rationale}".strip()
            )
            return decision
        executor = self.tier0_executor or self.change_engine_executor(candidate)
        if executor is None:
            metrics.AGENT_TIER0_ACTIONS.labels(action=candidate.action, mode="unwired").inc()
            self.notifier.send(
                f"Tier 0 allowed but no executor is wired for {candidate.action} "
                f"on {candidate.object_id}; nothing was done."
            )
            return decision.model_copy(
                update={
                    "mode": "unwired",
                    "reason": "allowed, but no Tier 0 executor is wired yet",
                }
            )
        try:
            outcome = executor(candidate, incident)
        except Exception as exc:
            # The cooldown slot is already spent, so the owner is told what was
            # attempted and on what; swallowing this would leave a Tier 0 action
            # that failed silently on a device.
            log.exception(
                "Tier 0 executor failed for %s on %s", candidate.action, candidate.object_id
            )
            metrics.AGENT_TIER0_ACTIONS.labels(action=candidate.action, mode="failed").inc()
            self.notifier.send(
                f"Tier 0 FAILED: {candidate.action} on {candidate.object_id} raised "
                f"{type(exc).__name__}: {exc}. The object may be half-changed; check it.",
                critical=True,
            )
            return decision.model_copy(
                update={"mode": "failed", "reason": f"{type(exc).__name__}: {exc}"}
            )
        metrics.AGENT_TIER0_ACTIONS.labels(action=candidate.action, mode="live").inc()
        self.notifier.send(
            f"Tier 0 executed: {candidate.action} on {candidate.object_id} -> {outcome}",
            critical=True,
        )
        return decision.model_copy(update={"mode": "live", "reason": outcome, "executed": True})

    # -- presentation -------------------------------------------------------
    def summary(self, triage: Triage) -> str:
        lines = [
            f"Incident {triage.incident_id}: {triage.incident_title} "
            f"[{triage.status}/{triage.severity}]",
            f"Probable cause ({triage.confidence} confidence): "
            f"{triage.probable_cause or 'unknown'}",
            f"Recommended: {triage.recommended_action or 'no action recommended'}",
        ]
        if triage.plan_id:
            state = "awaiting your approval" if triage.approval_requested else "recorded"
            lines.append(f"ChangePlan {triage.plan_id} (tier {triage.plan_tier}) is {state}.")
        for decision in triage.tier0_decisions:
            # The cause is the platform's reading of the alert, not the model's
            # claim, so it belongs in what the owner is shown.
            cause = f", cause {decision.cause}" if decision.cause else ""
            lines.append(
                f"Tier 0 {decision.mode}: {decision.action} on {decision.object_id}"
                f"{cause} ({decision.reason})"
            )
        lines.extend(triage.notes)
        return "\n".join(lines)
