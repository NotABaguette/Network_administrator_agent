"""Observed-state snapshot store.

Phase 0 ships a file-backed store (JSON under data/snapshots). The Postgres
JSONB store lands with Phase 1 behind the same interface.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from infra_agent.models.common import Snapshot


class Change(BaseModel):
    op: Literal["add", "remove", "change"]
    path: str
    old: Any = None
    new: Any = None


def diff_structures(old: Any, new: Any, path: str = "") -> list[Change]:
    """Structured diff of two JSON-like values. Lists of dicts with a 'name' or
    'id' key are matched by that key; other lists are compared positionally."""
    if isinstance(old, dict) and isinstance(new, dict):
        changes: list[Change] = []
        for key in sorted(set(old) | set(new), key=str):
            sub = f"{path}.{key}" if path else str(key)
            if key not in old:
                changes.append(Change(op="add", path=sub, new=new[key]))
            elif key not in new:
                changes.append(Change(op="remove", path=sub, old=old[key]))
            else:
                changes.extend(diff_structures(old[key], new[key], sub))
        return changes
    if isinstance(old, list) and isinstance(new, list):
        key = _list_key(old, new)
        if key is None:
            changes = []
            for i in range(max(len(old), len(new))):
                sub = f"{path}[{i}]"
                if i >= len(old):
                    changes.append(Change(op="add", path=sub, new=new[i]))
                elif i >= len(new):
                    changes.append(Change(op="remove", path=sub, old=old[i]))
                else:
                    changes.extend(diff_structures(old[i], new[i], sub))
            return changes
        old_map = {str(item[key]): item for item in old}
        new_map = {str(item[key]): item for item in new}
        return diff_structures(old_map, new_map, path)
    if old != new:
        return [Change(op="change", path=path, old=old, new=new)]
    return []


def _list_key(*lists: list[Any]) -> str | None:
    items = [i for lst in lists for i in lst]
    if not items or not all(isinstance(i, dict) for i in items):
        return None
    for candidate in ("name", "id", "mac", "ip"):
        if all(candidate in i for i in items):
            return candidate
    return None


class FileSnapshotStore:
    def __init__(self, root: Path):
        self.root = root

    def _dir(self, device: str, collector: str) -> Path:
        return self.root / device / collector

    def save(self, snapshot: Snapshot) -> Path:
        d = self._dir(snapshot.device, snapshot.collector)
        d.mkdir(parents=True, exist_ok=True)
        stamp = snapshot.taken_at.strftime("%Y%m%dT%H%M%S%fZ")
        path = d / f"{stamp}.json"
        path.write_text(snapshot.model_dump_json(indent=1))
        return path

    def history(self, device: str, collector: str, limit: int = 10) -> list[Snapshot]:
        d = self._dir(device, collector)
        if not d.exists():
            return []
        files = sorted(d.glob("*.json"), reverse=True)[:limit]
        return [Snapshot.model_validate(json.loads(f.read_text())) for f in files]

    def latest(self, device: str, collector: str) -> Snapshot | None:
        hist = self.history(device, collector, limit=1)
        return hist[0] if hist else None
