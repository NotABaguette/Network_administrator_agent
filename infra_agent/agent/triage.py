"""Alert triage: Alertmanager webhook -> grouped incident -> one advisory agent run.

The model is advisory. It may propose a `ChangePlan` and may nominate a single
Tier 0 candidate; it can do neither by itself:

* a proposed plan is re-tiered here (the model can escalate a tier, never lower
  one), persisted through `PlanStore`, and put in front of a human. The approval
  token minted by `PlanStore.request_approval` is handed straight to
  `Notifier.send_approval_request` and to nothing else - not the model, not the
  returned `Triage`, not the log.
* a Tier 0 candidate is checked by `Tier0Guard`, which honours
  `settings.frozen` and `settings.tier0_shadow_mode`. At most one Tier 0 action
  runs (or is shadowed) per triage run.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from collections.abc import Callable
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from infra_agent.agent.notify import LogNotifier, Notifier
from infra_agent.agent.runner import AgentRunner, AgentRunResult
from infra_agent.change.plan import ChangePlan, ChangeState, Tier
from infra_agent.change.store import PlanStore
from infra_agent.change.tiers import ImpactSummary, Tier0Guard, compute_tier
from infra_agent.config import Settings, get_settings
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
                      Use the same fields as `change.propose`: title, action,
                      targets, summary, diff (structured, never raw config),
                      pre_checks, steps, post_checks, rollback.
  tier0_candidate     null, or an object {action, object_id, object_tags,
                      cause, rationale} naming ONE idempotent, reversible,
                      single-object Tier 0 action from the allowlist.

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
    model_config = ConfigDict(extra="ignore")

    action: str
    object_id: str
    object_tags: list[str] = Field(default_factory=list)
    cause: str | None = None
    rationale: str = ""


class Tier0Decision(BaseModel):
    """What the guard said, and what was actually done about it."""

    action: str
    object_id: str
    allowed: bool
    mode: str  # shadow | live | unwired | refused | skipped
    reason: str
    executed: bool = False


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

    # -- entry points -------------------------------------------------------
    def parse(self, payload: dict[str, Any]) -> Incident:
        return group_incident(AlertmanagerWebhook.model_validate(payload))

    def handle(self, payload: dict[str, Any]) -> Triage:
        return self.triage(self.parse(payload))

    def triage(self, incident: Incident) -> Triage:
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
        try:
            plan = ChangePlan.model_validate({**proposed, "proposed_by": "agent-triage"})
        except Exception as exc:
            triage.notes.append(f"The proposed plan was not a valid ChangePlan: {exc}")
            return
        self._retier(plan, _requested_tier(proposed))
        triage.proposed_plan = plan.llm_view()
        triage.plan_id = plan.id
        triage.plan_tier = int(plan.tier)
        if plan.tier is Tier.WINDOW and not plan.confirmation_phrase:
            plan.confirmation_phrase = "-".join(
                secrets.choice(CONFIRMATION_WORDS) for _ in range(3)
            )
        self.plans.save(plan)
        try:
            if plan.state is ChangeState.proposed:
                plan.transition(
                    ChangeState.dry_run,
                    "no executor wired yet (Phase 4); recorded so the plan can await approval",
                )
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

    def _apply_tier0(self, candidate: Tier0Candidate, incident: Incident) -> Tier0Decision:
        # Re-read the safety flags every time so a freeze between runs takes effect.
        self.guard.frozen = self.settings.frozen
        self.guard.shadow_mode = self.settings.tier0_shadow_mode
        allowed, reason = self.guard.allow(
            candidate.action, candidate.object_id, candidate.object_tags, candidate.cause
        )
        if not allowed:
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
            )
        # Cooldowns and retry caps must behave the same in shadow mode, otherwise
        # a week of shadow proves nothing about the live behaviour.
        self.guard.record(candidate.action, candidate.object_id)
        if self.guard.shadow_mode:
            metrics.AGENT_TIER0_ACTIONS.labels(action=candidate.action, mode="shadow").inc()
            self.notifier.send(
                f"Tier 0 (shadow): would have run {candidate.action} on "
                f"{candidate.object_id} for {incident.title}. {candidate.rationale}".strip()
            )
            return Tier0Decision(
                action=candidate.action,
                object_id=candidate.object_id,
                allowed=True,
                mode="shadow",
                reason=reason,
                executed=False,
            )
        if self.tier0_executor is None:
            metrics.AGENT_TIER0_ACTIONS.labels(action=candidate.action, mode="unwired").inc()
            self.notifier.send(
                f"Tier 0 allowed but no executor is wired for {candidate.action} "
                f"on {candidate.object_id}; nothing was done."
            )
            return Tier0Decision(
                action=candidate.action,
                object_id=candidate.object_id,
                allowed=True,
                mode="unwired",
                reason="allowed, but no Tier 0 executor is wired yet",
                executed=False,
            )
        outcome = self.tier0_executor(candidate, incident)
        metrics.AGENT_TIER0_ACTIONS.labels(action=candidate.action, mode="live").inc()
        self.notifier.send(
            f"Tier 0 executed: {candidate.action} on {candidate.object_id} -> {outcome}",
            critical=True,
        )
        return Tier0Decision(
            action=candidate.action,
            object_id=candidate.object_id,
            allowed=True,
            mode="live",
            reason=outcome,
            executed=True,
        )

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
            lines.append(
                f"Tier 0 {decision.mode}: {decision.action} on {decision.object_id} "
                f"({decision.reason})"
            )
        lines.extend(triage.notes)
        return "\n".join(lines)
