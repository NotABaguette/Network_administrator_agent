"""Durable agent state: what has already been triaged, and Tier 0 history.

Two things the agent must not forget across a restart or a crash loop:

* **Which alert groups have already been triaged.** Alertmanager re-sends a
  firing group every `repeat_interval` (1h for critical, 4h otherwise) and
  again when it resolves. Without this, one flapping alert costs a full
  40-tool-call run every hour and can re-nominate a Tier 0 candidate each time.
* **When each Tier 0 action last ran on each object.** `Tier0Guard` keeps that
  in memory, so a restart would reset every cooldown and per-day retry cap -
  exactly the guarantees `docs/risk-tiers.md` promises.

SQLite in `data_dir`, next to (not inside) the change engine's `plans.db`: the
change package owns that schema.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

#: Tier 0 policies look back at most a day, so nothing older is worth keeping.
TIER0_HISTORY_DAYS = 1


def _now() -> datetime:
    return datetime.now(UTC)


def _parse(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class AgentStateStore:
    """Small SQLite store for the agent's own bookkeeping."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS triage_runs (group_key TEXT PRIMARY KEY,"
                " last_at TEXT NOT NULL, signature TEXT NOT NULL)"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS tier0_history (action TEXT NOT NULL,"
                " object_id TEXT NOT NULL, at TEXT NOT NULL)"
            )

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = sqlite3.connect(self.path, isolation_level=None, timeout=10.0)
            try:
                conn.execute("BEGIN")
                yield conn
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    # -- triage dedup --------------------------------------------------------
    def last_triage(self, group_key: str) -> tuple[datetime, str] | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT last_at, signature FROM triage_runs WHERE group_key=?", (group_key,)
            ).fetchone()
        if row is None:
            return None
        when = _parse(row[0])
        return None if when is None else (when, row[1])

    def record_triage(self, group_key: str, signature: str, at: datetime | None = None) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO triage_runs (group_key, last_at, signature) VALUES (?,?,?)",
                (group_key, (at or _now()).isoformat(), signature),
            )

    def forget_triage(self, group_key: str) -> None:
        """A resolved group starts over: the next firing is a new incident."""
        with self._conn() as c:
            c.execute("DELETE FROM triage_runs WHERE group_key=?", (group_key,))

    # -- tier 0 history ------------------------------------------------------
    def record_tier0(self, action: str, object_id: str, at: datetime | None = None) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO tier0_history (action, object_id, at) VALUES (?,?,?)",
                (action, object_id, (at or _now()).isoformat()),
            )

    def tier0_history(self, since: datetime | None = None) -> list[tuple[str, str, datetime]]:
        cutoff = since or (_now() - timedelta(days=TIER0_HISTORY_DAYS))
        with self._conn() as c:
            rows = c.execute(
                "SELECT action, object_id, at FROM tier0_history WHERE at >= ? ORDER BY at",
                (cutoff.isoformat(),),
            ).fetchall()
        history = []
        for action, object_id, at in rows:
            when = _parse(at)
            if when is not None:
                history.append((action, object_id, when))
        return history

    def prune_tier0(self, before: datetime | None = None) -> None:
        cutoff = before or (_now() - timedelta(days=TIER0_HISTORY_DAYS))
        with self._conn() as c:
            c.execute("DELETE FROM tier0_history WHERE at < ?", (cutoff.isoformat(),))


def incident_signature(incident: Any) -> str:
    """A stable fingerprint of *which* alerts are in a group, not how many times
    Alertmanager has sent them. A repeat delivery has the same signature; a
    group that gained or lost an alert does not, and is triaged again."""
    alerts = getattr(incident, "alerts", None) or []
    parts = sorted(
        json.dumps(
            {
                "fingerprint": alert.get("fingerprint") or "",
                "alertname": (alert.get("labels") or {}).get("alertname", ""),
                "device": alert.get("device") or "",
                "status": alert.get("status") or "",
            },
            sort_keys=True,
        )
        for alert in alerts
        if isinstance(alert, dict)
    )
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


class TriageGate:
    """Decides whether an incoming Alertmanager delivery is worth an agent run.

    A "no" here is the difference between one run per real incident and one run
    per delivery: `deploy/alertmanager/alertmanager.yml` sets `send_resolved`
    and repeats a firing group hourly.
    """

    def __init__(self, store: AgentStateStore, repeat_window: timedelta) -> None:
        self.store = store
        self.repeat_window = repeat_window

    def decide(self, incident: Any, now: datetime | None = None) -> tuple[bool, str]:
        now = now or _now()
        key = str(getattr(incident, "id", "") or "")
        status = str(getattr(incident, "status", "firing"))
        firing = int(getattr(incident, "firing", 0) or 0)
        if status == "resolved" or firing == 0:
            # Nothing to explain: report it and let the next firing start clean.
            try:
                self.store.forget_triage(key)
            except Exception:
                log.exception("could not clear the triage record for %s", key)
            return False, "resolved"
        try:
            previous = self.store.last_triage(key)
        except Exception:
            log.exception("could not read the triage record for %s; triaging anyway", key)
            previous = None
        signature = incident_signature(incident)
        if previous is not None:
            last_at, last_signature = previous
            if last_signature == signature and now - last_at < self.repeat_window:
                minutes = int((now - last_at).total_seconds() // 60)
                return False, f"repeat of a group triaged {minutes} minute(s) ago"
        try:
            self.store.record_triage(key, signature, now)
        except Exception:
            log.exception("could not record the triage of %s", key)
        return True, "new or changed incident"
