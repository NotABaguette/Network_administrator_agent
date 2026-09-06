"""Alert triage tests: grouping, Tier 0 shadow vs live, and approval-token secrecy.

The model is a FakeClient scripted to return the JSON answer we want to test the
consequences of, so every path here runs offline.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from prometheus_client import REGISTRY

from infra_agent.agent.runner import AgentRunner
from infra_agent.agent.triage import (
    AlertmanagerWebhook,
    Incident,
    Tier0Candidate,
    TriageService,
    group_incident,
)
from infra_agent.change.plan import ChangePlan, ChangeState, Tier
from infra_agent.change.store import ApprovalError, PlanStore
from infra_agent.change.tiers import Tier0Guard
from infra_agent.config import Settings
from infra_agent.redaction.gateway import RedactionGateway
from tests.test_agent_runner import FakeClient, say

# -- fakes --------------------------------------------------------------------


class RecordingNotifier:
    """Stands in for the Telegram bot. Keeps the token out of everything but itself."""

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


PAYLOAD: dict[str, Any] = {
    "version": "4",
    "groupKey": '{}:{alertname="PortErrDisabled", device="sw-core-01"}',
    "status": "firing",
    "receiver": "infra-agent",
    "groupLabels": {"alertname": "PortErrDisabled", "device": "sw-core-01"},
    "commonLabels": {"severity": "warning", "device": "sw-core-01"},
    "commonAnnotations": {"summary": "Gi1/0/12 is err-disabled"},
    "externalURL": "http://alertmanager:9093",
    "alerts": [
        {
            "status": "firing",
            "labels": {
                "alertname": "PortErrDisabled",
                "device": "sw-core-01",
                "severity": "warning",
                "interface": "Gi1/0/12",
            },
            "annotations": {"summary": "link-flap err-disable on Gi1/0/12"},
            "startsAt": "2026-02-01T10:00:00Z",
            "fingerprint": "abc123",
        },
        {
            "status": "firing",
            "labels": {
                "alertname": "InterfaceFlapping",
                "device": "sw-core-01",
                "severity": "critical",
            },
            "annotations": {},
            "startsAt": "2026-02-01T09:58:00Z",
            "fingerprint": "def456",
        },
    ],
}


def answer(**overrides: Any) -> str:
    body = {
        "probable_cause": "A flapping link put Gi1/0/12 into err-disable.",
        "confidence": "high",
        "evidence": ["device.show sw-core-01 show interfaces status"],
        "recommended_action": "Clear err-disable once the cable is reseated.",
        "proposed_plan": None,
        "tier0_candidate": None,
    }
    body.update(overrides)
    return "Here is the triage.\n" + json.dumps(body)


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        secrets_dir=tmp_path / "secrets",
        seed_inventory=tmp_path / "seed.yaml",
        tier0_shadow_mode=True,
        frozen=False,
    )


@pytest.fixture
def gateway(tmp_path) -> RedactionGateway:
    return RedactionGateway(audit_log=tmp_path / "audit.jsonl")


def build(settings, gateway, text: str, **kwargs: Any) -> tuple[TriageService, FakeClient]:
    client = FakeClient([say(text)])
    runner = AgentRunner(
        settings=settings,
        gateway=gateway,
        client=client,
        tools=[],
        summary_provider=lambda: {"device_count": 1},
    )
    service = TriageService(
        settings=settings,
        runner=runner,
        gateway=gateway,
        plan_store=PlanStore(settings.data_dir / "plans.db"),
        guard=Tier0Guard(frozen=settings.frozen, shadow_mode=settings.tier0_shadow_mode),
        **kwargs,
    )
    return service, client


def tier0_counter(action: str, mode: str) -> float:
    return (
        REGISTRY.get_sample_value(
            "infra_agent_tier0_actions_total", {"action": action, "mode": mode}
        )
        or 0.0
    )


# -- grouping -----------------------------------------------------------------


def test_a_webhook_group_becomes_one_incident():
    incident = group_incident(AlertmanagerWebhook.model_validate(PAYLOAD))

    assert incident.severity == "critical", "the worst severity in the group wins"
    assert incident.devices == ["sw-core-01"]
    assert incident.alertnames == ["InterfaceFlapping", "PortErrDisabled"]
    assert incident.firing == 2 and incident.resolved == 0
    assert incident.started_at is not None
    assert incident.started_at.isoformat().startswith("2026-02-01T09:58")
    assert incident.title == "InterfaceFlapping, PortErrDisabled on sw-core-01"
    assert len(incident.id) == 12


def test_the_same_group_key_always_gives_the_same_incident_id():
    first = group_incident(AlertmanagerWebhook.model_validate(PAYLOAD))
    second = group_incident(AlertmanagerWebhook.model_validate(PAYLOAD))
    assert first.id == second.id


def test_a_device_is_found_from_instance_when_there_is_no_device_label():
    payload = {"alerts": [{"labels": {"alertname": "Down", "instance": "10.0.0.11:161"}}]}
    incident = group_incident(AlertmanagerWebhook.model_validate(payload))
    assert incident.devices == ["10.0.0.11:161"]


def test_the_incident_reaches_the_model_redacted(settings, gateway):
    service, client = build(settings, gateway, answer())
    payload = json.loads(json.dumps(PAYLOAD))
    payload["alerts"][0]["annotations"]["detail"] = "snmp-server community S3cret RO"

    service.handle(payload)

    content = client.calls[0]["messages"][0]["content"]
    assert "S3cret" not in content
    assert "<REDACTED>" in content
    assert "Gi1/0/12" in content


# -- the advisory answer ------------------------------------------------------


def test_a_structured_answer_becomes_a_triage(settings, gateway):
    notifier = RecordingNotifier()
    service, _ = build(settings, gateway, answer(), notifier=notifier)

    triage = service.handle(PAYLOAD)

    assert triage.probable_cause.startswith("A flapping link")
    assert triage.confidence == "high"
    assert triage.evidence == ["device.show sw-core-01 show interfaces status"]
    assert triage.plan_id is None
    assert triage.tier0_candidate is None
    assert notifier.messages and notifier.messages[0][1] is True, "critical bypasses quiet hours"
    assert "A flapping link" in notifier.text


def test_an_unstructured_answer_is_reported_not_invented(settings, gateway):
    notifier = RecordingNotifier()
    service, _ = build(settings, gateway, "I could not work it out.", notifier=notifier)

    triage = service.handle(PAYLOAD)

    assert triage.probable_cause == ""
    assert triage.notes and "structured answer" in triage.notes[0]
    assert "no structured answer" in notifier.text


# -- proposed plans -----------------------------------------------------------

PLAN = {
    "title": "Add VLAN 40 for the new printers",
    "action": "vlan.add",
    "targets": ["sw-core-01"],
    "summary": "VLAN 40 does not exist on the access switch",
    "diff": {"vlan": {"add": {"id": 40, "name": "printers"}}},
    "steps": [
        {
            "description": "create vlan 40",
            "platform": "cisco",
            "action": "vlan.add",
            "params": {"vlan": 40},
        }
    ],
    "post_checks": ["show vlan brief"],
    "rollback": [
        {
            "description": "remove vlan 40",
            "platform": "cisco",
            "action": "vlan.remove",
            "params": {"vlan": 40},
        }
    ],
}


def test_a_proposed_plan_is_persisted_and_waits_for_a_human(settings, gateway):
    notifier = RecordingNotifier()
    service, _ = build(settings, gateway, answer(proposed_plan=PLAN), notifier=notifier)

    triage = service.handle(PAYLOAD)

    assert triage.plan_id is not None
    assert triage.plan_tier == int(Tier.APPROVAL)
    assert triage.approval_requested is True
    stored = service.plans.get(triage.plan_id)
    assert stored.state is ChangeState.awaiting_approval
    assert stored.approval is None, "nothing is approved by the agent"
    assert stored.proposed_by == "agent-triage"
    assert notifier.approvals and notifier.approvals[0][0] == triage.plan_id
    assert triage.proposed_plan is not None
    assert triage.proposed_plan["state"] == "awaiting_approval"
    assert "approval" not in triage.proposed_plan


def test_the_tier_is_computed_and_the_model_cannot_lower_it(settings, gateway):
    sneaky = {**PLAN, "action": "fortigate.wan", "tier": 0}
    service, _ = build(settings, gateway, answer(proposed_plan=sneaky))

    triage = service.handle(PAYLOAD)

    assert triage.plan_tier == int(Tier.WINDOW)
    stored = service.plans.get(triage.plan_id or "")
    assert stored.tier is Tier.WINDOW
    assert any("base tier" in reason for reason in stored.tier_reasons)


def test_the_model_may_escalate_a_tier(settings, gateway):
    cautious = {**PLAN, "tier": int(Tier.WINDOW)}
    service, _ = build(settings, gateway, answer(proposed_plan=cautious))

    triage = service.handle(PAYLOAD)

    assert triage.plan_tier == int(Tier.WINDOW)
    stored = service.plans.get(triage.plan_id or "")
    assert any("higher tier" in reason for reason in stored.tier_reasons)


def test_an_agent_proposal_is_never_tier_0(settings, gateway):
    auto = {**PLAN, "action": "vm.snapshot"}
    service, _ = build(settings, gateway, answer(proposed_plan=auto))

    triage = service.handle(PAYLOAD)

    assert triage.plan_tier == int(Tier.APPROVAL)
    stored = service.plans.get(triage.plan_id or "")
    assert any("at least one human approval" in r for r in stored.tier_reasons)


def test_a_tier_2_plan_gets_a_confirmation_phrase_the_model_never_sees(settings, gateway):
    service, _ = build(settings, gateway, answer(proposed_plan={**PLAN, "action": "fortigate.wan"}))

    triage = service.handle(PAYLOAD)

    stored = service.plans.get(triage.plan_id or "")
    assert stored.confirmation_phrase
    assert "confirmation_phrase" not in stored.llm_view()
    assert stored.confirmation_phrase not in json.dumps(triage.model_dump(mode="json"))


def test_a_malformed_plan_is_reported_not_stored(settings, gateway):
    service, _ = build(settings, gateway, answer(proposed_plan={"nonsense": True}))

    triage = service.handle(PAYLOAD)

    assert triage.plan_id is None
    assert triage.notes and "not a valid ChangePlan" in triage.notes[0]
    assert service.plans.list() == []


# -- the approval token -------------------------------------------------------


def test_the_approval_token_never_reaches_the_model_a_log_or_the_record(
    settings, gateway, caplog, tmp_path
):
    notifier = RecordingNotifier()
    service, client = build(settings, gateway, answer(proposed_plan=PLAN), notifier=notifier)

    with caplog.at_level("DEBUG"):
        triage = service.handle(PAYLOAD)

    assert notifier.approvals, "the human channel is the only place the token goes"
    token = notifier.approvals[0][1]
    assert len(token) > 20

    # Nothing the model saw, nothing that was logged, nothing returned, and
    # nothing persisted contains it.
    assert token not in json.dumps(client.calls, default=str)
    assert token not in caplog.text
    assert token not in json.dumps(triage.model_dump(mode="json"), default=str)
    assert token not in json.dumps(notifier.text)
    assert token not in service.plans.dump_json(service.plans.get(triage.plan_id or ""))
    assert token not in (tmp_path / "audit.jsonl").read_text()
    assert token not in (settings.data_dir / "plans.db").read_bytes().decode(errors="replace")


def test_only_the_token_hash_is_stored(settings, gateway):
    notifier = RecordingNotifier()
    service, _ = build(settings, gateway, answer(proposed_plan=PLAN), notifier=notifier)
    triage = service.handle(PAYLOAD)
    token = notifier.approvals[0][1]

    with pytest.raises(ApprovalError):
        service.plans.approve(triage.plan_id or "", "wrong-token", "owner", "cli")

    approved = service.plans.approve(triage.plan_id or "", token, "owner", "cli")
    assert approved.state is ChangeState.approved
    assert approved.approval is not None
    assert approved.approval.token_sha256 != token


# -- tier 0 -------------------------------------------------------------------

TIER0 = {
    "action": "switch.clear_errdisable",
    "object_id": "sw-core-01:Gi1/0/12",
    "object_tags": ["auto:errdisable"],
    "cause": "link-flap",
    "rationale": "The port flapped and is not a trunk.",
}


def test_tier0_in_shadow_mode_records_what_it_would_have_done(settings, gateway):
    settings.tier0_shadow_mode = True
    executed: list[Any] = []
    notifier = RecordingNotifier()
    service, _ = build(
        settings,
        gateway,
        answer(tier0_candidate=TIER0),
        notifier=notifier,
        tier0_executor=lambda c, i: executed.append(c) or "done",
    )
    before = tier0_counter("switch.clear_errdisable", "shadow")

    triage = service.handle(PAYLOAD)

    (decision,) = triage.tier0_decisions
    assert decision.allowed is True
    assert decision.mode == "shadow"
    assert decision.executed is False
    assert executed == [], "shadow mode never touches the device"
    assert tier0_counter("switch.clear_errdisable", "shadow") == before + 1
    assert "would have run" in notifier.text


def test_tier0_live_runs_exactly_once_through_the_executor(settings, gateway):
    settings.tier0_shadow_mode = False
    executed: list[Tier0Candidate] = []
    notifier = RecordingNotifier()
    service, _ = build(
        settings,
        gateway,
        answer(tier0_candidate=TIER0),
        notifier=notifier,
        tier0_executor=lambda c, i: (executed.append(c), "err-disable cleared")[1],
    )
    before = tier0_counter("switch.clear_errdisable", "live")

    triage = service.handle(PAYLOAD)

    (decision,) = triage.tier0_decisions
    assert decision.mode == "live"
    assert decision.executed is True
    assert [c.object_id for c in executed] == ["sw-core-01:Gi1/0/12"]
    assert tier0_counter("switch.clear_errdisable", "live") == before + 1
    assert "Tier 0 executed" in notifier.text


def test_tier0_live_without_an_executor_does_nothing(settings, gateway):
    settings.tier0_shadow_mode = False
    service, _ = build(settings, gateway, answer(tier0_candidate=TIER0))

    (decision,) = service.handle(PAYLOAD).tier0_decisions

    assert decision.allowed is True
    assert decision.executed is False
    assert decision.mode == "unwired"
    assert "no Tier 0 executor" in decision.reason


def test_frozen_refuses_every_tier0_action(settings, gateway):
    settings.frozen = True
    settings.tier0_shadow_mode = False
    executed: list[Any] = []
    service, _ = build(
        settings,
        gateway,
        answer(tier0_candidate=TIER0),
        tier0_executor=lambda c, i: executed.append(c) or "done",
    )

    (decision,) = service.handle(PAYLOAD).tier0_decisions

    assert decision.allowed is False
    assert decision.mode == "refused"
    assert "frozen" in decision.reason
    assert executed == []


def test_a_freeze_between_runs_takes_effect(settings, gateway):
    settings.tier0_shadow_mode = True
    service, client = build(settings, gateway, answer(tier0_candidate=TIER0))

    assert service.handle(PAYLOAD).tier0_decisions[0].allowed is True
    settings.frozen = True
    client.turns = [say(answer(tier0_candidate={**TIER0, "object_id": "sw-core-01:Gi1/0/13"}))]

    assert service.handle(PAYLOAD).tier0_decisions[0].allowed is False


def test_a_denied_cause_is_refused(settings, gateway):
    settings.tier0_shadow_mode = False
    service, _ = build(settings, gateway, answer(tier0_candidate={**TIER0, "cause": "bpduguard"}))

    (decision,) = service.handle(PAYLOAD).tier0_decisions

    assert decision.allowed is False
    assert "denied" in decision.reason


def test_a_missing_opt_in_tag_is_refused(settings, gateway):
    settings.tier0_shadow_mode = False
    service, _ = build(settings, gateway, answer(tier0_candidate={**TIER0, "object_tags": []}))

    (decision,) = service.handle(PAYLOAD).tier0_decisions

    assert decision.allowed is False
    assert "opt-in" in decision.reason


def test_at_most_one_tier0_action_runs_per_triage_run(settings, gateway):
    settings.tier0_shadow_mode = False
    executed: list[Tier0Candidate] = []
    second = {**TIER0, "object_id": "sw-core-01:Gi1/0/13"}
    service, _ = build(
        settings,
        gateway,
        answer(tier0_candidate=[TIER0, second]),
        tier0_executor=lambda c, i: (executed.append(c), "cleared")[1],
    )

    triage = service.handle(PAYLOAD)

    assert len(executed) == 1, "the second candidate must never run"
    assert executed[0].object_id == "sw-core-01:Gi1/0/12"
    modes = [d.mode for d in triage.tier0_decisions]
    assert modes == ["live", "skipped"]
    assert "at most one Tier 0 action" in triage.tier0_decisions[1].reason


def test_shadow_mode_still_honours_cooldowns(settings, gateway):
    """A week in shadow mode only proves something if the guards behave the same."""
    settings.tier0_shadow_mode = True
    service, client = build(settings, gateway, answer(tier0_candidate=TIER0))

    assert service.handle(PAYLOAD).tier0_decisions[0].mode == "shadow"
    client.turns = [say(answer(tier0_candidate=TIER0))]
    second = service.handle(PAYLOAD).tier0_decisions[0]

    assert second.allowed is False
    assert "cooldown" in second.reason


def test_a_malformed_tier0_candidate_is_ignored(settings, gateway):
    service, _ = build(settings, gateway, answer(tier0_candidate={"action": "vm.power_on"}))

    triage = service.handle(PAYLOAD)

    assert triage.tier0_candidate is None
    assert triage.notes and "malformed Tier 0 candidate" in triage.notes[0]


def test_the_summary_names_the_incident_the_plan_and_the_tier0_decision(settings, gateway):
    settings.tier0_shadow_mode = True
    service, _ = build(settings, gateway, answer(proposed_plan=PLAN, tier0_candidate=TIER0))

    triage = service.handle(PAYLOAD)
    summary = service.summary(triage)

    assert triage.incident_id in summary
    assert "sw-core-01" in summary
    assert (triage.plan_id or "") in summary
    assert "awaiting your approval" in summary
    assert "Tier 0 shadow" in summary


def test_triage_accepts_an_incident_directly(settings, gateway):
    service, _ = build(settings, gateway, answer())
    incident = Incident(id="deadbeef", status="firing", severity="warning", devices=["esx-01"])

    triage = service.triage(incident)

    assert triage.incident_id == "deadbeef"
    assert triage.incident_title == "alert on esx-01"
