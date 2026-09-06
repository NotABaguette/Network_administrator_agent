"""Persisted ChangePlans and pending approval tokens (SQLite in data_dir).

Shared by the CLI, the agent service and the Telegram bot, which run in
different processes. Only token HASHES are stored.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from infra_agent.change.plan import ApprovalRecord, ChangePlan, ChangeState, Tier


class ApprovalError(RuntimeError):
    pass


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class PlanStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS plans (id TEXT PRIMARY KEY, state TEXT, tier INTEGER,"
                " created_at TEXT, body TEXT NOT NULL)"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS approvals (plan_id TEXT PRIMARY KEY,"
                " token_sha256 TEXT NOT NULL, requested_at TEXT NOT NULL)"
            )

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, isolation_level=None)
        try:
            conn.execute("BEGIN")
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    # -- plans ---------------------------------------------------------------
    def save(self, plan: ChangePlan) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO plans (id, state, tier, created_at, body)"
                " VALUES (?,?,?,?,?)",
                (
                    plan.id,
                    plan.state.value,
                    int(plan.tier),
                    plan.created_at.isoformat(),
                    plan.model_dump_json(),
                ),
            )

    def get(self, plan_id: str) -> ChangePlan:
        with self._conn() as c:
            row = c.execute("SELECT body FROM plans WHERE id=?", (plan_id,)).fetchone()
        if row is None:
            raise KeyError(plan_id)
        return ChangePlan.model_validate_json(row[0])

    def list(self, state: ChangeState | None = None) -> list[ChangePlan]:
        query, params = "SELECT body FROM plans", ()
        if state is not None:
            query, params = query + " WHERE state=?", (state.value,)
        with self._conn() as c:
            rows = c.execute(query + " ORDER BY created_at DESC", params).fetchall()
        return [ChangePlan.model_validate_json(r[0]) for r in rows]

    # -- approvals (human channel only) -------------------------------------
    def request_approval(self, plan: ChangePlan) -> str:
        """Move to awaiting_approval, mint a token for the human channel, return it."""
        if plan.tier is Tier.AUTO:
            raise ApprovalError("tier 0 plans do not use the approval channel")
        if plan.state is not ChangeState.awaiting_approval:
            plan.transition(ChangeState.awaiting_approval, "approval requested")
        token = secrets.token_urlsafe(24)
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO approvals (plan_id, token_sha256, requested_at)"
                " VALUES (?,?,?)",
                (plan.id, _hash(token), datetime.now(UTC).isoformat()),
            )
        self.save(plan)
        return token

    def approve(
        self,
        plan_id: str,
        token: str,
        approver: str,
        channel: str,
        confirmation_phrase: str | None = None,
    ) -> ChangePlan:
        plan = self.get(plan_id)
        with self._conn() as c:
            row = c.execute(
                "SELECT token_sha256 FROM approvals WHERE plan_id=?", (plan_id,)
            ).fetchone()
        if row is None:
            raise ApprovalError("no approval pending for this plan")
        if not hmac.compare_digest(row[0], _hash(token)):
            raise ApprovalError("invalid approval token")
        if plan.tier is Tier.WINDOW and (
            not plan.confirmation_phrase or confirmation_phrase != plan.confirmation_phrase
        ):
            raise ApprovalError("tier 2 requires the exact confirmation phrase")
        plan.approval = ApprovalRecord(
            approver=approver, channel=channel, at=datetime.now(UTC), token_sha256=row[0]
        )
        plan.transition(ChangeState.approved, f"approved by {approver} via {channel}")
        with self._conn() as c:
            c.execute("DELETE FROM approvals WHERE plan_id=?", (plan_id,))
        self.save(plan)
        return plan

    def reject(self, plan_id: str, approver: str, channel: str, reason: str = "") -> ChangePlan:
        plan = self.get(plan_id)
        plan.transition(ChangeState.cancelled, f"rejected by {approver} via {channel}: {reason}")
        with self._conn() as c:
            c.execute("DELETE FROM approvals WHERE plan_id=?", (plan_id,))
        self.save(plan)
        return plan

    def pending(self) -> list[ChangePlan]:
        return self.list(ChangeState.awaiting_approval)

    def dump_json(self, plan: ChangePlan) -> str:
        return json.dumps(plan.llm_view())
