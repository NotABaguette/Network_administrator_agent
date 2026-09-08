"""Change tools.

`change.approve`, `change.execute` and `change.rollback` are NOT callable by the
language model: they are registered with `llm_callable=False`, the agent runner
refuses them a second time by name, and nothing here ever returns an approval
token or a Tier 2 confirmation phrase. The model may propose a plan, ask for a
dry run and read a plan's state; a human approves and a human (or the Tier 0
guard, through `ChangeEngine.run_tier0`) executes.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from infra_agent.change.engine import ChangeEngine
from infra_agent.change.plan import ChangePlan, ChangeState, Tier
from infra_agent.change.store import PlanStore
from infra_agent.config import get_settings
from infra_agent.tools.registry import tool


@lru_cache
def store() -> PlanStore:
    return PlanStore(get_settings().data_dir / "plans.db")


_engine: ChangeEngine | None = None


def engine() -> ChangeEngine:
    """The engine the tools and the CLI share, on the same `PlanStore`."""
    global _engine
    if _engine is None:
        _engine = ChangeEngine.from_settings(plan_store=store())
    return _engine


def configure(engine_: ChangeEngine | None) -> None:
    """Replace the engine (the agent service wires its own notifier; tests fake it)."""
    global _engine
    _engine = engine_


@tool("change", tier=Tier.APPROVAL, parallel_safe=False)
def propose(plan: dict[str, Any]) -> dict[str, Any]:
    """Propose a ChangePlan. Returns the plan as the model may see it (no approval material)."""
    cp = ChangePlan.model_validate(plan)
    store().save(cp)
    return cp.llm_view()


@tool("change", parallel_safe=False)
def dry_run(plan_id: str) -> dict[str, Any]:
    """Dry-run a proposed ChangePlan: render its diff and compute its risk tier.

    Nothing is changed on any device. The plan comes back with a structured
    before/after diff, the tier impact analysis computed for it and the reasons
    behind that tier. If anything blocks it the plan stays `proposed` and the
    blockers are in the diff and in the plan's history.

    Args:
        plan_id: Id of a ChangePlan in state `proposed`.
    """
    return engine().dry_run(plan_id).llm_view()


@tool("change")
def status(plan_id: str) -> dict[str, Any]:
    """Current state and history of a ChangePlan."""
    return store().get(plan_id).llm_view()


@tool("change")
def list_plans(state: str | None = None) -> list[dict[str, Any]]:
    """List ChangePlans, optionally filtered by state."""
    return [p.llm_view() for p in store().list(ChangeState(state) if state else None)]


@tool("change")
def unapproved(device: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    """Configuration commits that matched no ChangePlan executed on that device.

    Args:
        device: Limit to one device name.
        limit: Maximum rows to return.
    """
    return [c.llm_view() for c in engine().unapproved_changes(device, limit=int(limit))]


@tool("change", llm_callable=False, parallel_safe=False)
def approve(
    plan_id: str, token: str, approver: str, channel: str, phrase: str | None = None
) -> None:
    """Human-only. Called by the CLI and the Telegram bot, never by the model."""
    store().approve(plan_id, token, approver, channel, phrase)


@tool("change", llm_callable=False, parallel_safe=False)
def execute(plan_id: str) -> dict[str, Any]:
    """Human-only trigger for an approved plan. Returns the execution record."""
    return engine().execute(plan_id).llm_view()


@tool("change", llm_callable=False, parallel_safe=False)
def rollback(plan_id: str) -> dict[str, Any]:
    """Human-only. Undo the last recorded execution of a plan."""
    return engine().rollback(plan_id).llm_view()
