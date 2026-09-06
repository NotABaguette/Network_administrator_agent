"""Human-only approval channel.

The token is minted here and handed to the CLI or the Telegram bot. It is
never placed in a ChangePlan payload, tool result or prompt. Only its hash is
stored on the plan.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime

from infra_agent.change.plan import ApprovalRecord, ChangePlan, ChangeState, Tier


class ApprovalError(RuntimeError):
    pass


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class ApprovalService:
    def __init__(self) -> None:
        self._pending: dict[str, str] = {}  # plan id -> token hash

    def request(self, plan: ChangePlan) -> str:
        """Move the plan to awaiting_approval and return the token for the human channel."""
        if plan.tier is Tier.AUTO:
            raise ApprovalError("tier 0 plans do not use the approval channel")
        if plan.state is not ChangeState.awaiting_approval:
            plan.transition(ChangeState.awaiting_approval, "approval requested")
        token = secrets.token_urlsafe(24)
        self._pending[plan.id] = _hash(token)
        return token

    def approve(
        self,
        plan: ChangePlan,
        token: str,
        approver: str,
        channel: str,
        confirmation_phrase: str | None = None,
    ) -> None:
        expected = self._pending.get(plan.id)
        if expected is None:
            raise ApprovalError("no approval pending for this plan")
        if not hmac.compare_digest(expected, _hash(token)):
            raise ApprovalError("invalid approval token")
        if plan.tier is Tier.WINDOW:
            if not plan.confirmation_phrase or confirmation_phrase != plan.confirmation_phrase:
                raise ApprovalError("tier 2 requires the exact confirmation phrase")
        plan.approval = ApprovalRecord(
            approver=approver, channel=channel, at=datetime.now(UTC), token_sha256=expected
        )
        plan.transition(ChangeState.approved, f"approved by {approver} via {channel}")
        del self._pending[plan.id]

    def reject(self, plan: ChangePlan, approver: str, channel: str, reason: str = "") -> None:
        self._pending.pop(plan.id, None)
        plan.transition(ChangeState.cancelled, f"rejected by {approver} via {channel}: {reason}")
