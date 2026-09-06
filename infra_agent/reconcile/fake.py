"""An in-memory NetBox stand-in that enforces NetBox 4.3's rules.

`FakeNetBox` inherits `NetBoxBase`, so it runs the same `ensure()` upsert the
real client runs: tests that assert bootstrap idempotency are testing the
production code path, not a lookalike. It stores foreign keys as integer ids
exactly as NetBox does and resolves them when a filter asks for a natural key
(`device="sw-core-01"`), which is what the reconciler queries with.

A permissive fake is worse than no fake, because it makes payloads that NetBox
rejects or silently drops look correct. So the handful of 4.x rules this package
depends on are encoded here, each against the pinned release
(`netboxcommunity/netbox:v4.3-3.3.0`, source tag v4.3.3):

* `dcim/api/serializers_/device_components.py` `InterfaceSerializer.validate()`:
  an interface with no 802.1Q mode may not carry `untagged_vlan` or
  `tagged_vlans`, and an `access` interface may not carry `tagged_vlans`.
* `dcim/models/device_components.py` `BaseInterface.save()`: a VM interface with
  no mode has its `untagged_vlan` silently cleared instead (the VM serializer
  does not run that validation).
* `mac_address` is `read_only=True` on both interface serializers since 4.2; the
  writable field is `primary_mac_address`, a FK to a `dcim.mac_addresses` object
  that `BaseInterface.clean()` requires to be assigned to that same interface.
* `virtualization/api/serializers_/clusters.py`: a cluster is scoped with
  `scope_type`/`scope_id`; there is no writable `site`, and DRF drops it.
* NetBox filters MAC and IP addresses by `interface_id`/`vminterface_id`;
  `assigned_object_type` is a ContentType primary-key filter, so passing
  `"dcim.interface"` to it is a 400.

It lives in the package rather than in `tests/` so the CLI can drive a dry-run
reconciliation without a NetBox instance.
"""

from __future__ import annotations

import copy
import itertools
from typing import Any

from infra_agent.reconcile.netbox import NetBoxBase, NetBoxWriteError, normalize_value

# field name -> (endpoint holding the referenced object, its natural key)
REFERENCES: dict[str, tuple[str, str]] = {
    "site": ("dcim.sites", "slug"),
    "device": ("dcim.devices", "name"),
    "device_type": ("dcim.device_types", "model"),
    "device_role": ("dcim.device_roles", "slug"),
    "role": ("dcim.device_roles", "slug"),
    "manufacturer": ("dcim.manufacturers", "slug"),
    "platform": ("dcim.platforms", "slug"),
    "cluster": ("virtualization.clusters", "name"),
    "cluster_type": ("virtualization.cluster_types", "slug"),
    "type": ("virtualization.cluster_types", "slug"),
    "virtual_machine": ("virtualization.virtual_machines", "name"),
    "untagged_vlan": ("ipam.vlans", "vid"),
    "vlan": ("ipam.vlans", "vid"),
    "assigned_object_id": ("dcim.interfaces", "name"),
}

# endpoint -> the content type string NetBox stores for its objects
ASSIGNMENT_TYPES = {
    "dcim.interfaces": "dcim.interface",
    "virtualization.interfaces": "virtualization.vminterface",
}
# filter name -> the content type it implies (NetBox's own filterset shortcuts)
ASSIGNMENT_FILTERS = {
    "interface_id": "dcim.interface",
    "vminterface_id": "virtualization.vminterface",
}
# Endpoints whose `assigned_object_type` filter takes a ContentType pk, not a label.
_CONTENT_TYPE_PK_FILTERS = {"ipam.ip_addresses", "dcim.mac_addresses"}

_VALID_MODES = {"access", "tagged", "tagged-all", "q-in-q"}


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

    def _matches(self, endpoint: str, record: dict[str, Any], filters: dict[str, Any]) -> bool:
        for field, wanted in filters.items():
            if field == "assigned_object_type" and endpoint in _CONTENT_TYPE_PK_FILTERS:
                raise NetBoxWriteError(
                    f"{endpoint}: `assigned_object_type` filters on a ContentType primary key; "
                    f"filter by interface_id / vminterface_id instead"
                )
            if field in ASSIGNMENT_FILTERS:
                if record.get("assigned_object_type") != ASSIGNMENT_FILTERS[field]:
                    return False
                if record.get("assigned_object_id") != wanted:
                    return False
                continue
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

    # -- NetBox 4.3 semantics ------------------------------------------------
    def _mac_string(self, endpoint: str, record: dict[str, Any], value: Any) -> str:
        """`primary_mac_address` must point at a MAC assigned to this same object."""
        mac_id = value.get("id") if isinstance(value, dict) else value
        if not isinstance(mac_id, int):
            raise NetBoxWriteError("primary_mac_address must reference a dcim.mac_addresses id")
        mac = self._table("dcim.mac_addresses").get(mac_id)
        if mac is None:
            raise NetBoxWriteError(f"primary_mac_address {mac_id} does not exist")
        wanted_type = ASSIGNMENT_TYPES.get(endpoint.replace("-", "_"))
        if mac.get("assigned_object_type") != wanted_type or mac.get(
            "assigned_object_id"
        ) != record.get("id"):
            raise NetBoxWriteError(
                f"MAC address {mac.get('mac_address')} is not assigned to this interface"
            )
        return str(mac.get("mac_address") or "")

    def _apply_semantics(self, endpoint: str, record: dict[str, Any]) -> dict[str, Any]:
        endpoint = endpoint.replace("-", "_")
        if endpoint == "virtualization.clusters":
            # No writable `site` since 4.2: DRF drops the unknown key silently.
            record.pop("site", None)
        if endpoint in ASSIGNMENT_TYPES:
            record.pop("mac_address", None)  # read-only since 4.2
            mode = record.get("mode") or ""
            tagged = record.get("tagged_vlans") or []
            if endpoint == "dcim.interfaces":
                if not mode and record.get("untagged_vlan"):
                    raise NetBoxWriteError(
                        "{'untagged_vlan': 'Interface mode does not support untagged vlan'}"
                    )
                if not mode and tagged:
                    raise NetBoxWriteError(
                        "{'tagged_vlans': 'Interface mode does not support tagged vlans'}"
                    )
                if mode in ("access", "tagged-all") and tagged:
                    raise NetBoxWriteError(
                        "{'tagged_vlans': 'Interface mode does not support tagged vlans'}"
                    )
            elif not mode:
                # BaseInterface.save() clears it instead of raising, so the VLAN is lost.
                record["untagged_vlan"] = None
            if mode and mode not in _VALID_MODES:
                raise NetBoxWriteError(f"{{'mode': '\"{mode}\" is not a valid choice.'}}")
            if record.get("primary_mac_address") is not None:
                record["mac_address"] = self._mac_string(
                    endpoint, record, record["primary_mac_address"]
                )
        return record

    # -- primitives ---------------------------------------------------------
    def get(self, endpoint: str, **filters: Any) -> dict[str, Any] | None:
        found = self.all(endpoint, **filters)
        return found[0] if found else None

    def all(self, endpoint: str, **filters: Any) -> list[dict[str, Any]]:
        records = self._table(endpoint).values()
        key = endpoint.replace("-", "_")
        return [copy.deepcopy(r) for r in records if not filters or self._matches(key, r, filters)]

    def create(self, endpoint: str, data: dict[str, Any]) -> dict[str, Any]:
        if self.dry_run:
            return dict(data)
        record = copy.deepcopy(data)
        record["id"] = next(self._ids)
        self._apply_semantics(endpoint, record)
        self._table(endpoint)[record["id"]] = record
        self.writes.append(("create", endpoint.replace("-", "_"), record["id"]))
        return copy.deepcopy(record)

    def update(self, endpoint: str, obj_id: int, data: dict[str, Any]) -> dict[str, Any]:
        if self.dry_run:
            return {"id": obj_id, **data}
        record = self._table(endpoint).get(obj_id)
        if record is None:
            raise LookupError(f"{endpoint} id={obj_id} not found")
        merged = {**copy.deepcopy(record), **copy.deepcopy(data)}
        self._apply_semantics(endpoint, merged)
        record.clear()
        record.update(merged)
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
