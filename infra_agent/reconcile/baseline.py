"""Baseline acceptance.

Drift is only meaningful after a human has said "this is correct" once
(ADR 0001). `infra baseline accept` records the current observed estate as the
accepted baseline: always a local file under `data_dir/baseline/`, plus a
NetBox journal entry against the site when NetBox is configured, so the
acceptance is visible from both sides.

A baseline holds the parsed estate only -- no raw configuration, no secrets.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from infra_agent.config import Settings, get_settings
from infra_agent.reconcile.model import Estate
from infra_agent.reconcile.netbox import NetBoxLike

CURRENT = "current.json"


class Baseline(BaseModel):
    """One accepted snapshot set."""

    accepted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    accepted_by: str = "cli-user"
    note: str = ""
    fingerprint: str = ""
    counts: dict[str, int] = Field(default_factory=dict)
    sources: dict[str, str] = Field(default_factory=dict)
    netbox_journal_id: int | None = None
    estate: Estate

    def matches(self, estate: Estate) -> bool:
        return self.fingerprint == estate.fingerprint()

    def llm_view(self) -> dict[str, Any]:
        """Metadata only: the full estate is available through the inventory tools."""
        return {
            "accepted_at": self.accepted_at.isoformat(),
            "accepted_by": self.accepted_by,
            "note": self.note,
            "fingerprint": self.fingerprint,
            "counts": self.counts,
            "sources": self.sources,
            "netbox_journal_id": self.netbox_journal_id,
        }


class BaselineStore:
    """File-backed baseline history under `data_dir/baseline/`."""

    def __init__(self, root: Path):
        self.root = root

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> BaselineStore:
        return cls((settings or get_settings()).data_dir / "baseline")

    @property
    def current_path(self) -> Path:
        return self.root / CURRENT

    def accept(
        self,
        estate: Estate,
        accepted_by: str = "cli-user",
        note: str = "",
        client: NetBoxLike | None = None,
    ) -> Baseline:
        """Record `estate` as the accepted baseline and return it."""
        baseline = Baseline(
            accepted_by=accepted_by,
            note=note,
            fingerprint=estate.fingerprint(),
            counts=estate.counts(),
            sources=dict(estate.sources),
            estate=estate,
        )
        if client is not None:
            baseline.netbox_journal_id = self._journal(client, baseline)
        self.root.mkdir(parents=True, exist_ok=True)
        payload = baseline.model_dump_json(indent=1)
        stamp = baseline.accepted_at.strftime("%Y%m%dT%H%M%SZ")
        (self.root / f"accepted-{stamp}.json").write_text(payload)
        self.current_path.write_text(payload)
        return baseline

    def current(self) -> Baseline | None:
        if not self.current_path.exists():
            return None
        return Baseline.model_validate(json.loads(self.current_path.read_text()))

    def history(self, limit: int = 10) -> list[Baseline]:
        files = sorted(self.root.glob("accepted-*.json"), reverse=True)[:limit]
        return [Baseline.model_validate(json.loads(f.read_text())) for f in files]

    def _journal(self, client: NetBoxLike, baseline: Baseline) -> int | None:
        site = client.get("dcim.sites", slug=baseline.estate.site)
        if not site or not site.get("id"):
            return None
        counts = ", ".join(f"{k}={v}" for k, v in sorted(baseline.counts.items()))
        entry = client.journal(
            "dcim.site",
            int(site["id"]),
            comments=(
                f"Baseline accepted by {baseline.accepted_by} "
                f"at {baseline.accepted_at.isoformat()}.\n"
                f"Fingerprint {baseline.fingerprint[:16]}.\n{counts}\n{baseline.note}".strip()
            ),
        )
        value = entry.get("id") if isinstance(entry, dict) else None
        return int(value) if isinstance(value, (int, str)) and str(value).isdigit() else None
