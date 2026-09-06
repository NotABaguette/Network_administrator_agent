import json
from datetime import UTC, datetime, timedelta

import pytest

from infra_agent.change.approvals import ApprovalError, ApprovalService
from infra_agent.change.plan import (
    ChangePlan,
    ChangeState,
    InvalidTransition,
    MaintenanceWindow,
    Tier,
)


def make(tier=Tier.APPROVAL, **kw):
    return ChangePlan(title="t", action="vlan.add", targets=["sw-01"], tier=tier, **kw)


def test_lifecycle_happy_path():
    plan = make()
    svc = ApprovalService()
    plan.transition(ChangeState.dry_run)
    token = svc.request(plan)
    assert plan.state is ChangeState.awaiting_approval
    svc.approve(plan, token, approver="owner", channel="telegram")
    assert plan.state is ChangeState.approved
    plan.transition(ChangeState.executing)
    plan.transition(ChangeState.verifying)
    plan.transition(ChangeState.done)
    assert [h.state for h in plan.history][-1] is ChangeState.done


def test_cannot_approve_without_record():
    plan = make()
    plan.transition(ChangeState.dry_run)
    plan.transition(ChangeState.awaiting_approval)
    with pytest.raises(InvalidTransition):
        plan.transition(ChangeState.approved)


def test_invalid_transition_rejected():
    plan = make()
    with pytest.raises(InvalidTransition):
        plan.transition(ChangeState.done)


def test_wrong_token_rejected():
    plan = make()
    plan.transition(ChangeState.dry_run)
    svc = ApprovalService()
    svc.request(plan)
    with pytest.raises(ApprovalError):
        svc.approve(plan, "nope", "owner", "cli")
    assert plan.state is ChangeState.awaiting_approval


def test_tier2_needs_phrase_and_window():
    now = datetime.now(UTC)
    plan = make(
        tier=Tier.WINDOW,
        confirmation_phrase="CHANGE WAN1",
        window=MaintenanceWindow(start=now - timedelta(minutes=5), end=now + timedelta(hours=1)),
    )
    plan.transition(ChangeState.dry_run)
    svc = ApprovalService()
    token = svc.request(plan)
    with pytest.raises(ApprovalError):
        svc.approve(plan, token, "owner", "telegram")
    svc.approve(plan, token, "owner", "telegram", confirmation_phrase="CHANGE WAN1")
    assert plan.state is ChangeState.approved


def test_tier2_outside_window_rejected():
    now = datetime.now(UTC)
    plan = make(
        tier=Tier.WINDOW,
        confirmation_phrase="GO",
        window=MaintenanceWindow(start=now + timedelta(hours=1), end=now + timedelta(hours=2)),
    )
    plan.transition(ChangeState.dry_run)
    svc = ApprovalService()
    token = svc.request(plan)
    with pytest.raises(InvalidTransition):
        svc.approve(plan, token, "owner", "telegram", confirmation_phrase="GO")


def test_llm_view_never_contains_approval_material():
    now = datetime.now(UTC)
    plan = make(
        tier=Tier.WINDOW,
        confirmation_phrase="SECRET PHRASE",
        window=MaintenanceWindow(start=now - timedelta(minutes=1), end=now + timedelta(hours=1)),
    )
    plan.transition(ChangeState.dry_run)
    svc = ApprovalService()
    token = svc.request(plan)
    svc.approve(plan, token, "owner", "cli", confirmation_phrase="SECRET PHRASE")
    view = json.dumps(plan.llm_view())
    assert token not in view
    assert "SECRET PHRASE" not in view
    assert "token_sha256" not in view
