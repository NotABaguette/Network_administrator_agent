import json

import pytest

from infra_agent.change.plan import ChangePlan, ChangeState, Tier
from infra_agent.change.store import ApprovalError, PlanStore


def test_store_roundtrip_and_approval(tmp_path):
    store = PlanStore(tmp_path / "plans.db")
    plan = ChangePlan(title="t", action="vlan.add", targets=["sw-01"])
    plan.transition(ChangeState.dry_run)
    token = store.request_approval(plan)
    assert store.get(plan.id).state is ChangeState.awaiting_approval
    assert [p.id for p in store.pending()] == [plan.id]
    with pytest.raises(ApprovalError):
        store.approve(plan.id, "wrong", "owner", "telegram")
    approved = store.approve(plan.id, token, "owner", "telegram")
    assert approved.state is ChangeState.approved
    assert store.pending() == []
    with pytest.raises(ApprovalError):
        store.approve(plan.id, token, "owner", "telegram")  # single use
    assert token not in json.dumps(store.get(plan.id).llm_view())


def test_tier0_has_no_approval_channel(tmp_path):
    store = PlanStore(tmp_path / "plans.db")
    plan = ChangePlan(title="t", action="vm.snapshot", targets=["vm"], tier=Tier.AUTO)
    with pytest.raises(ApprovalError):
        store.request_approval(plan)
