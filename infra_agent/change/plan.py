"""ChangePlan: the only way anything in the estate gets modified."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Tier(IntEnum):
    AUTO = 0
    APPROVAL = 1
    WINDOW = 2


class ChangeState(StrEnum):
    proposed = "proposed"
    dry_run = "dry_run"
    awaiting_approval = "awaiting_approval"
    approved = "approved"
    executing = "executing"
    verifying = "verifying"
    done = "done"
    rolled_back = "rolled_back"
    cancelled = "cancelled"
    failed = "failed"


TRANSITIONS: dict[ChangeState, set[ChangeState]] = {
    ChangeState.proposed: {ChangeState.dry_run, ChangeState.cancelled},
    ChangeState.dry_run: {
        ChangeState.awaiting_approval,
        ChangeState.approved,
        ChangeState.cancelled,
    },
    ChangeState.awaiting_approval: {ChangeState.approved, ChangeState.cancelled},
    ChangeState.approved: {ChangeState.executing, ChangeState.cancelled},
    ChangeState.executing: {ChangeState.verifying, ChangeState.rolled_back, ChangeState.failed},
    ChangeState.verifying: {ChangeState.done, ChangeState.rolled_back},
    ChangeState.done: set(),
    ChangeState.rolled_back: set(),
    ChangeState.cancelled: set(),
    ChangeState.failed: set(),
}


class InvalidTransition(RuntimeError):
    pass


class ChangeStep(BaseModel):
    description: str
    platform: str
    action: str
    params: dict[str, Any] = Field(default_factory=dict)


class ApprovalRecord(BaseModel):
    """Who approved, through which human channel. Only the token HASH is stored."""

    approver: str
    channel: str  # "cli" | "telegram"
    at: datetime
    token_sha256: str


class HistoryEntry(BaseModel):
    state: ChangeState
    at: datetime
    note: str = ""


class MaintenanceWindow(BaseModel):
    start: datetime
    end: datetime

    def contains(self, when: datetime) -> bool:
        return self.start <= when <= self.end


class ChangePlan(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    title: str
    action: str
    targets: list[str]
    summary: str = ""
    diff: dict[str, Any] | str = Field(default_factory=dict, description="Structured diff only")
    pre_checks: list[str] = Field(default_factory=list)
    steps: list[ChangeStep] = Field(default_factory=list)
    post_checks: list[str] = Field(default_factory=list)
    rollback: list[ChangeStep] = Field(default_factory=list)
    tier: Tier = Tier.APPROVAL
    tier_reasons: list[str] = Field(default_factory=list)
    state: ChangeState = ChangeState.proposed
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    proposed_by: str = "agent"
    history: list[HistoryEntry] = Field(default_factory=list)
    approval: ApprovalRecord | None = None
    window: MaintenanceWindow | None = None
    confirmation_phrase: str | None = None

    def can_transition(self, new_state: ChangeState) -> bool:
        return new_state in TRANSITIONS[self.state]

    def transition(self, new_state: ChangeState, note: str = "") -> None:
        if not self.can_transition(new_state):
            raise InvalidTransition(f"{self.state.value} -> {new_state.value} is not allowed")
        if new_state is ChangeState.approved:
            if self.tier is not Tier.AUTO and self.approval is None:
                raise InvalidTransition("tier 1/2 changes need an approval record")
            if self.tier is Tier.WINDOW:
                now = datetime.now(UTC)
                if self.window is None or not self.window.contains(now):
                    raise InvalidTransition("tier 2 changes execute only inside their window")
        self.state = new_state
        self.history.append(HistoryEntry(state=new_state, at=datetime.now(UTC), note=note))

    def llm_view(self) -> dict[str, Any]:
        """What the language model may see about this plan. No approval material."""
        return self.model_dump(mode="json", exclude={"approval", "confirmation_phrase"})
