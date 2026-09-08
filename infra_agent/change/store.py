"""Persisted ChangePlans, pending approval tokens, execution records and the
config commits that matched no plan (SQLite in data_dir).

Shared by the CLI, the agent service and the Telegram bot, which run in
different processes. Only token HASHES are stored.

`ExecutionRecord` and `UnapprovedConfigChange` live here rather than next to the
change engine so that the engine can import the store without the store having
to import the engine. Both are secret-free by construction: an executor puts
only structured, secret-free material into `StepResult.output`
(`infra_agent/change/executors/base.py`), and nothing here ever holds an
approval token or a Tier 2 confirmation phrase.
"""

from __future__ import annotations

import builtins
import hashlib
import hmac
import json
import secrets
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from infra_agent.change.executors.base import StepResult
from infra_agent.change.plan import ApprovalRecord, ChangePlan, ChangeState, Tier


class ApprovalError(RuntimeError):
    pass


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _iso(when: datetime) -> str:
    return (when if when.tzinfo else when.replace(tzinfo=UTC)).isoformat()


class CheckOutcome(BaseModel):
    """One pre- or post-check as it was evaluated against one device."""

    device: str
    phase: str  # "pre" | "post"
    check: str
    ok: bool
    detail: str = ""
    advisory: bool = False


class ExecutionRecord(BaseModel):
    """What one `ChangeEngine.execute` (or rollback) actually did.

    Secret-free: step outputs are the executor's structured capture, the notes
    are engine prose, and no approval material ever reaches this model.
    """

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    plan_id: str
    action: str = ""
    tier: int = int(Tier.APPROVAL)
    devices: list[str] = Field(default_factory=list)
    #: done | rolled_back | rollback_failed | failed | blocked
    outcome: str = "failed"
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    duration_seconds: float = 0.0
    steps: list[StepResult] = Field(default_factory=list)
    rollback_steps: list[StepResult] = Field(default_factory=list)
    checks: list[CheckOutcome] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.outcome == "done"

    def llm_view(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class PlanProvenance(BaseModel):
    """What the *platform* (never the model) knows about how a plan got here.

    A `ChangePlan` body is content the language model may author, so nothing in
    it can be taken as evidence that the plan was validated or approved. This
    row is written only by `ChangeEngine` and `PlanStore` and answers three
    questions `ChangeEngine.execute` asks before it touches a device:

    * did *this* engine dry-run the plan (`fingerprint`, over the steps and
      targets that were rendered), and is the plan still the one it dry-ran?
    * what risk tier did the human actually approve (`approved_tier`)?
    * for a Tier 0 plan, did `ChangeEngine.run_tier0` release it after
      `Tier0Guard.allow()` said yes (`tier0_released_at`)?
    """

    plan_id: str
    fingerprint: str
    dry_run_tier: int
    dry_run_at: datetime
    approved_tier: int | None = None
    tier0_released_at: datetime | None = None


class UnapprovedConfigChange(BaseModel):
    """A config-git commit that matched no ChangePlan executed on that device."""

    id: str = ""
    device: str
    commit_sha: str
    filename: str | None = None
    at: datetime
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    reason: str = ""
    nearest_plan_id: str | None = None

    def model_post_init(self, _context: Any) -> None:
        # Derived from the device and the commit, so re-running the correlation
        # for the same commit replaces the row instead of duplicating it.
        if not self.id:
            self.id = hashlib.sha256(f"{self.device}\0{self.commit_sha}".encode()).hexdigest()[:16]

    def llm_view(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


#: A stand-in used only to read `approved_tier` off a missing provenance row.
_NO_PROVENANCE = PlanProvenance(
    plan_id="", fingerprint="", dry_run_tier=int(Tier.APPROVAL), dry_run_at=datetime.now(UTC)
)


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
            # Phase 4, additive: what the engine actually did, and the config
            # commits that matched none of it.
            c.execute(
                "CREATE TABLE IF NOT EXISTS executions (id TEXT PRIMARY KEY,"
                " plan_id TEXT NOT NULL, devices TEXT NOT NULL, outcome TEXT NOT NULL,"
                " started_at TEXT NOT NULL, finished_at TEXT, body TEXT NOT NULL)"
            )
            c.execute("CREATE INDEX IF NOT EXISTS executions_plan ON executions (plan_id)")
            c.execute("CREATE INDEX IF NOT EXISTS executions_started ON executions (started_at)")
            c.execute(
                "CREATE TABLE IF NOT EXISTS unapproved_changes (id TEXT PRIMARY KEY,"
                " device TEXT NOT NULL, commit_sha TEXT NOT NULL, at TEXT NOT NULL,"
                " body TEXT NOT NULL)"
            )
            # Phase 4, additive: platform-written provenance for a plan. The
            # plan body is model-authorable; this table is not.
            c.execute(
                "CREATE TABLE IF NOT EXISTS plan_provenance (plan_id TEXT PRIMARY KEY,"
                " fingerprint TEXT NOT NULL, dry_run_tier INTEGER NOT NULL,"
                " dry_run_at TEXT NOT NULL, approved_tier INTEGER, tier0_released_at TEXT)"
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
            # A new approval cycle: whatever tier an earlier one was granted for
            # says nothing about this one.
            c.execute("UPDATE plan_provenance SET approved_tier=NULL WHERE plan_id=?", (plan.id,))
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
            # The tier the human was shown when they typed the token. The engine
            # recomputes the tier before it executes and refuses anything that
            # has grown past this, so an escalation cannot ride an old approval.
            c.execute(
                "UPDATE plan_provenance SET approved_tier=? WHERE plan_id=?",
                (int(plan.tier), plan_id),
            )
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

    # -- provenance (Phase 4, additive) --------------------------------------
    def record_dry_run(self, plan_id: str, fingerprint: str, tier: Tier | int) -> PlanProvenance:
        """Remember that *this* platform dry-ran this exact plan.

        Written only by `ChangeEngine.dry_run`. The Tier 0 release is cleared: a
        plan that is dry-run again has to be released again. An approval is kept
        across a re-validation only while the plan is still the one that was
        approved - re-validating an *edited* plan drops it, because what the
        human said yes to is no longer what would be sent.
        """
        previous = self.provenance(plan_id)
        approved = (
            previous.approved_tier if previous and previous.fingerprint == fingerprint else None
        )
        row = PlanProvenance(
            plan_id=plan_id,
            fingerprint=fingerprint,
            dry_run_tier=int(tier),
            dry_run_at=datetime.now(UTC),
            approved_tier=approved,
        )
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO plan_provenance"
                " (plan_id, fingerprint, dry_run_tier, dry_run_at, approved_tier,"
                " tier0_released_at) VALUES (?,?,?,?,?,NULL)",
                (
                    row.plan_id,
                    row.fingerprint,
                    row.dry_run_tier,
                    _iso(row.dry_run_at),
                    row.approved_tier,
                ),
            )
        return row

    def release_tier0(self, plan_id: str) -> None:
        """`ChangeEngine.run_tier0` says the guard allowed this plan, just now.

        Nothing else may write this: it is what tells `execute` that an
        `approved` Tier 0 plan reached that state through a live guard decision
        rather than through a plan body that claimed it.
        """
        with self._conn() as c:
            updated = c.execute(
                "UPDATE plan_provenance SET tier0_released_at=? WHERE plan_id=?",
                (datetime.now(UTC).isoformat(), plan_id),
            ).rowcount
        if not updated:
            raise ApprovalError(f"{plan_id} has no dry run to release")

    def provenance(self, plan_id: str) -> PlanProvenance | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT plan_id, fingerprint, dry_run_tier, dry_run_at, approved_tier,"
                " tier0_released_at FROM plan_provenance WHERE plan_id=?",
                (plan_id,),
            ).fetchone()
        if row is None:
            return None
        return PlanProvenance(
            plan_id=row[0],
            fingerprint=row[1],
            dry_run_tier=row[2],
            dry_run_at=datetime.fromisoformat(row[3]),
            approved_tier=row[4],
            tier0_released_at=datetime.fromisoformat(row[5]) if row[5] else None,
        )

    # -- execution records (Phase 4, additive) -------------------------------
    def record_execution(self, record: ExecutionRecord) -> ExecutionRecord:
        """Persist what one execution or rollback did. Idempotent on `record.id`."""
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO executions"
                " (id, plan_id, devices, outcome, started_at, finished_at, body)"
                " VALUES (?,?,?,?,?,?,?)",
                (
                    record.id,
                    record.plan_id,
                    json.dumps(record.devices),
                    record.outcome,
                    _iso(record.started_at),
                    _iso(record.finished_at) if record.finished_at else None,
                    record.model_dump_json(),
                ),
            )
        return record

    def execution(self, execution_id: str) -> ExecutionRecord:
        with self._conn() as c:
            row = c.execute("SELECT body FROM executions WHERE id=?", (execution_id,)).fetchone()
        if row is None:
            raise KeyError(execution_id)
        return ExecutionRecord.model_validate_json(row[0])

    def executions(
        self,
        plan_id: str | None = None,
        *,
        device: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> builtins.list[ExecutionRecord]:
        """Execution records, newest first. `device` is matched in Python because
        a record names every device it touched."""
        query = "SELECT body FROM executions"
        clauses: list[str] = []
        params: list[Any] = []
        if plan_id is not None:
            clauses.append("plan_id=?")
            params.append(plan_id)
        if since is not None:
            clauses.append("started_at>=?")
            params.append(_iso(since))
        if until is not None:
            clauses.append("started_at<=?")
            params.append(_iso(until))
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(int(limit))
        with self._conn() as c:
            rows = c.execute(query, tuple(params)).fetchall()
        records = [ExecutionRecord.model_validate_json(r[0]) for r in rows]
        if device is not None:
            records = [r for r in records if device in r.devices]
        return records

    def last_execution(self, plan_id: str) -> ExecutionRecord | None:
        records = self.executions(plan_id, limit=1)
        return records[0] if records else None

    # -- unapproved config changes (Phase 4, additive) -----------------------
    def record_unapproved_change(self, change: UnapprovedConfigChange) -> UnapprovedConfigChange:
        """Persist an `UnapprovedConfigChange`. The id is derived from device and
        commit, so re-running the correlation never duplicates a row."""
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO unapproved_changes (id, device, commit_sha, at, body)"
                " VALUES (?,?,?,?,?)",
                (
                    change.id,
                    change.device,
                    change.commit_sha,
                    _iso(change.at),
                    change.model_dump_json(),
                ),
            )
        return change

    def unapproved_changes(
        self, device: str | None = None, *, limit: int = 100
    ) -> builtins.list[UnapprovedConfigChange]:
        query = "SELECT body FROM unapproved_changes"
        params: list[Any] = []
        if device is not None:
            query += " WHERE device=?"
            params.append(device)
        query += " ORDER BY at DESC LIMIT ?"
        params.append(int(limit))
        with self._conn() as c:
            rows = c.execute(query, tuple(params)).fetchall()
        return [UnapprovedConfigChange.model_validate_json(r[0]) for r in rows]
