"""An in-memory NetBox stand-in.

`FakeNetBox` inherits `NetBoxBase`, so it runs the same `ensure()` upsert the
real client runs: tests that assert bootstrap idempotency are testing the
production code path, not a lookalike. It stores foreign keys as integer ids
exactly as NetBox does and resolves them when a filter asks for a natural key
(`device="sw-core-01"`), which is what the reconciler queries with.

It lives in the package rather than in `tests/` so the CLI can drive a dry-run
reconciliation without a NetBox instance.
"""

from __future__ import annotations

import copy
import itertools
from typing import Any

from infra_agent.reconcile.netbox import NetBoxBase, normalize_value

# field name -> (endpoint holding the referenced object, its natural key)
REFERENCES: dict[str, tuple[str, str]] = {
    "site": ("dcim.sites", "slug"),
    "device": ("dcim.devices", "name"),
    "device_type": ("dcim.device_types", "model"),
    "device_role": ("dcim.device_roles", "slug"),
    "role": ("dcim.device_roles", "slug"),
    "manufacturer": ("dcim.manufacturers", "slug"),
    "cluster": ("virtualization.clusters", "name"),
    "cluster_type": ("virtualization.cluster_types", "slug"),
    "type": ("virtualization.cluster_types", "slug"),
    "virtual_machine": ("virtualization.virtual_machines", "name"),
    "untagged_vlan": ("ipam.vlans", "vid"),
    "vlan": ("ipam.vlans", "vid"),
    "assigned_object_id": ("dcim.interfaces", "name"),
}


class FakeNetBox(NetBoxBase):
    def __init__(self, *, dry_run: bool = False):
        self.dry_run = dry_run
        self.store: dict[str, dict[int, dict[str, Any]]] = {}
        self.writes: list[tuple[str, str, int]] = []
        self._ids = itertools.count(1)

    # -- helpers ------------------------------------------------------------
    def _table(self, endpoint: str) -> dict[int, dict[str, Any]]:
        return self.store.setdefault(endpoint.replace("-", "_"), {})

    def _resolve(self, field: str, stored: Any) -> Any:
        """Turn a stored foreign key id into the natural key a filter would use."""
        target = REFERENCES.get(field)
        if target is None or not isinstance(stored, int) or isinstance(stored, bool):
            return None
        endpoint, natural = target
        referenced = self._table(endpoint).get(stored)
        return referenced.get(natural) if referenced else None

    def _matches(self, record: dict[str, Any], filters: dict[str, Any]) -> bool:
        for field, wanted in filters.items():
            stored = record.get(field)
            if normalize_value(field, stored) == normalize_value(field, wanted):
                continue
            resolved = self._resolve(field, stored)
            if resolved is not None and normalize_value(field, resolved) == normalize_value(
                field, wanted
            ):
                continue
            return False
        return True

    # -- primitives ---------------------------------------------------------
    def get(self, endpoint: str, **filters: Any) -> dict[str, Any] | None:
        found = self.all(endpoint, **filters)
        return found[0] if found else None

    def all(self, endpoint: str, **filters: Any) -> list[dict[str, Any]]:
        records = self._table(endpoint).values()
        return [copy.deepcopy(r) for r in records if not filters or self._matches(r, filters)]

    def create(self, endpoint: str, data: dict[str, Any]) -> dict[str, Any]:
        if self.dry_run:
            return dict(data)
        record = copy.deepcopy(data)
        record["id"] = next(self._ids)
        self._table(endpoint)[record["id"]] = record
        self.writes.append(("create", endpoint.replace("-", "_"), record["id"]))
        return copy.deepcopy(record)

    def update(self, endpoint: str, obj_id: int, data: dict[str, Any]) -> dict[str, Any]:
        if self.dry_run:
            return {"id": obj_id, **data}
        record = self._table(endpoint).get(obj_id)
        if record is None:
            raise LookupError(f"{endpoint} id={obj_id} not found")
        record.update(copy.deepcopy(data))
        self.writes.append(("update", endpoint.replace("-", "_"), obj_id))
        return copy.deepcopy(record)

    def delete(self, endpoint: str, obj_id: int) -> None:
        if self.dry_run:
            return
        if self._table(endpoint).pop(obj_id, None) is not None:
            self.writes.append(("delete", endpoint.replace("-", "_"), obj_id))

    # -- test conveniences --------------------------------------------------
    def count(self, endpoint: str) -> int:
        return len(self._table(endpoint))

    def reset_writes(self) -> None:
        self.writes.clear()

    def seed(self, endpoint: str, **fields: Any) -> dict[str, Any]:
        """Insert a record directly, bypassing the write log."""
        record = copy.deepcopy(fields)
        record["id"] = next(self._ids)
        self._table(endpoint)[record["id"]] = record
        return copy.deepcopy(record)
