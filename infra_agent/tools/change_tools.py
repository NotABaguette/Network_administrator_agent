"""Change tools. `approve` and `execute` are NOT callable by the language model."""

from __future__ import annotations

from typing import Any

from infra_agent.change.plan import ChangePlan, ChangeState, Tier
from infra_agent.tools.registry import tool

# Phase 0 keeps plans in memory; Phase 4 moves them to Postgres.
PLANS: dict[str, ChangePlan] = {}


@tool("change", tier=Tier.APPROVAL, parallel_safe=False)
def propose(plan: dict[str, Any]) -> dict[str, Any]:
    """Propose a ChangePlan. Returns the plan as the model may see it (no approval material)."""
    cp = ChangePlan.model_validate(plan)
    PLANS[cp.id] = cp
    return cp.llm_view()


@tool("change")
def status(plan_id: str) -> dict[str, Any]:
    """Current state and history of a ChangePlan."""
    return PLANS[plan_id].llm_view()


@tool("change")
def list_plans(state: str | None = None) -> list[dict[str, Any]]:
    """List ChangePlans, optionally filtered by state."""
    plans = PLANS.values()
    if state:
        plans = [p for p in plans if p.state is ChangeState(state)]
    return [p.llm_view() for p in plans]


@tool("change", llm_callable=False, parallel_safe=False)
def approve(
    plan_id: str, token: str, approver: str, channel: str, phrase: str | None = None
) -> None:
    """Human-only. Called by the CLI and the Telegram bot, never by the model."""
    from infra_agent.change.approvals import ApprovalService

    ApprovalService().approve(PLANS[plan_id], token, approver, channel, phrase)


@tool("change", llm_callable=False, parallel_safe=False)
def execute(plan_id: str) -> None:
    """Human-only trigger for an approved plan (Phase 4 wires the executors)."""
    plan = PLANS[plan_id]
    plan.transition(ChangeState.executing, "execution requested")
