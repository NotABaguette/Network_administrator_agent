"""Thin NetBox wrapper.

`pynetbox` is an optional dependency and is imported lazily inside methods, so
the core package and the test suite import without it. Everything the
reconciler needs is expressed in five primitives -- `get`, `all`, `create`,
`update`, `delete` -- plus the shared `ensure()` upsert that both the real
client and `FakeNetBox` inherit, so the tests exercise the production
idempotency logic rather than a lookalike.

Endpoints are written in pynetbox's `app.endpoint` form with underscores, e.g.
`dcim.devices`, `ipam.ip_addresses`, `virtualization.virtual_machines`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

from infra_agent.config import Settings, get_settings

EnsureStatus = Literal["created", "updated", "unchanged", "would-create", "would-update", "error"]

# Fields compared case-insensitively (NetBox normalises MAC address casing).
_CASE_INSENSITIVE = {"mac_address", "primary_mac_address", "slug"}

# NetBox's default read timeout. pynetbox builds a bare `requests.Session` and never
# passes `timeout=`, so without this a black-holed NetBox hangs a tool call for the
# whole OS TCP timeout, once per request.
DEFAULT_TIMEOUT = 10.0


class _Omit:
    """Marks a lookup key that must not be written back in the create payload."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "OMIT"

    def __bool__(self) -> bool:
        return False


OMIT = _Omit()


class NetBoxWriteError(RuntimeError):
    """NetBox rejected a write (HTTP 400). Mirrors `pynetbox.RequestError`."""


@dataclass
class EnsureResult:
    endpoint: str
    obj: dict[str, Any]
    status: EnsureStatus
    changed_fields: list[str] = field(default_factory=list)

    @property
    def id(self) -> int | None:
        value = self.obj.get("id")
        if isinstance(value, bool) or value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @property
    def changed(self) -> bool:
        return self.status not in ("unchanged", "error")


@runtime_checkable
class NetBoxLike(Protocol):
    """What the reconciler, the baseline and the drift comparison need."""

    def get(self, endpoint: str, **filters: Any) -> dict[str, Any] | None: ...

    def all(self, endpoint: str, **filters: Any) -> list[dict[str, Any]]: ...

    def create(self, endpoint: str, data: dict[str, Any]) -> dict[str, Any]: ...

    def update(self, endpoint: str, obj_id: int, data: dict[str, Any]) -> dict[str, Any]: ...

    def ensure(
        self,
        endpoint: str,
        key: dict[str, Any],
        defaults: dict[str, Any] | None = None,
        create: dict[str, Any] | None = None,
    ) -> EnsureResult: ...

    def journal(
        self, object_type: str, object_id: int, comments: str, kind: str = "info"
    ) -> dict[str, Any]: ...


def normalize_value(key: str, value: Any) -> Any:
    """Compare what NetBox returns (nested objects) with what we send (ids)."""
    if isinstance(value, dict):
        return value.get("id", value.get("value", value.get("slug")))
    if isinstance(value, (list, tuple)):
        return sorted(normalize_value(key, item) for item in value)  # type: ignore[type-var]
    if value is None:
        return ""
    if isinstance(value, str):
        text = value.strip()
        return text.lower() if key in _CASE_INSENSITIVE else text
    if isinstance(value, bool):
        return value
    return value


class NetBoxBase:
    """Shared upsert semantics for the real client and the in-memory fake."""

    dry_run: bool = False
    _preview_id: int = 0

    def _next_preview_id(self) -> int:
        """Negative placeholder id so a dry run can still walk into child objects."""
        self._preview_id -= 1
        return self._preview_id

    def get(self, endpoint: str, **filters: Any) -> dict[str, Any] | None:
        raise NotImplementedError

    def all(self, endpoint: str, **filters: Any) -> list[dict[str, Any]]:
        raise NotImplementedError

    def create(self, endpoint: str, data: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def update(self, endpoint: str, obj_id: int, data: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def delete(self, endpoint: str, obj_id: int) -> None:
        raise NotImplementedError

    def journal(
        self, object_type: str, object_id: int, comments: str, kind: str = "info"
    ) -> dict[str, Any]:
        return self.create(
            "extras.journal_entries",
            {
                "assigned_object_type": object_type,
                "assigned_object_id": object_id,
                "kind": kind,
                "comments": comments,
            },
        )

    def ensure(
        self,
        endpoint: str,
        key: dict[str, Any],
        defaults: dict[str, Any] | None = None,
        create: dict[str, Any] | None = None,
    ) -> EnsureResult:
        """Create the object if the key does not match, else patch changed fields only.

        `key` is a query filter and may use natural keys (`device="sw-core-01"`).
        `create` carries the write form of those same fields (`device=17`) and
        overrides them in the creation payload, because NetBox queries by name but
        writes by id; `OMIT` drops a key that is queryable but not writable (NetBox
        filters MAC addresses by `interface_id` but stores `assigned_object_id`).
        Running this twice with the same arguments never writes the second time,
        which is what makes `bootstrap` idempotent.
        """
        defaults = defaults or {}
        existing = self.get(endpoint, **key)
        if existing is None:
            payload = {
                name: value
                for name, value in {**key, **(create or {}), **defaults}.items()
                if not isinstance(value, _Omit)
            }
            if self.dry_run:
                preview = {"id": self._next_preview_id(), **payload}
                return EnsureResult(endpoint, preview, "would-create", sorted(payload))
            return EnsureResult(
                endpoint, self.create(endpoint, payload), "created", sorted(payload)
            )

        changed = [
            name
            for name, wanted in defaults.items()
            if normalize_value(name, existing.get(name)) != normalize_value(name, wanted)
        ]
        if not changed:
            return EnsureResult(endpoint, existing, "unchanged")
        patch = {name: defaults[name] for name in changed}
        if self.dry_run:
            return EnsureResult(endpoint, {**existing, **patch}, "would-update", sorted(changed))
        updated = self.update(endpoint, int(existing["id"]), patch)
        return EnsureResult(endpoint, updated, "updated", sorted(changed))


class NetBoxClient(NetBoxBase):
    """`pynetbox` wrapper. The import happens on first use, never at module import."""

    def __init__(
        self,
        url: str,
        token: str,
        *,
        dry_run: bool = False,
        threading: bool = False,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.url = url.rstrip("/")
        self._token = token
        self.dry_run = dry_run
        self.threading = threading
        self.timeout = timeout
        self._api: Any = None

    def __repr__(self) -> str:
        # Never let the API token reach a log line or a traceback.
        return f"NetBoxClient(url={self.url!r}, dry_run={self.dry_run})"

    @classmethod
    def from_settings(
        cls, settings: Settings | None = None, *, dry_run: bool = False
    ) -> NetBoxClient | None:
        """None when NetBox is not configured; every caller must handle that."""
        settings = settings or get_settings()
        if not settings.netbox_url or not settings.netbox_token:
            return None
        return cls(settings.netbox_url, settings.netbox_token, dry_run=dry_run)

    # -- plumbing -----------------------------------------------------------
    def api(self) -> Any:
        if self._api is None:
            import pynetbox  # lazy: optional dependency

            api = pynetbox.api(self.url, token=self._token, threading=self.threading)
            self._apply_timeout(api)
            self._api = api
        return self._api

    def _apply_timeout(self, api: Any) -> None:
        """Give every NetBox request a deadline.

        pynetbox never passes `timeout=`, so a NetBox whose SYNs are dropped would
        block an LLM-callable read for the OS TCP timeout on each of the dozen-odd
        requests a drift report makes.
        """
        try:
            import requests
        except ImportError:  # pragma: no cover - requests is a core dependency
            return
        timeout = self.timeout

        class _TimeoutSession(requests.Session):
            def request(self, *args: Any, **kwargs: Any) -> Any:
                kwargs.setdefault("timeout", timeout)
                return super().request(*args, **kwargs)

        session = _TimeoutSession()
        existing = getattr(api, "http_session", None)
        if existing is not None:
            session.headers.update(existing.headers)
            session.verify = existing.verify
        api.http_session = session

    def endpoint(self, name: str) -> Any:
        app, _, resource = name.partition(".")
        if not resource:
            raise ValueError(f"endpoint must be 'app.resource', got {name!r}")
        return getattr(getattr(self.api(), app), resource.replace("-", "_"))

    @staticmethod
    def _as_dict(record: Any) -> dict[str, Any]:
        if record is None:
            return {}
        if isinstance(record, dict):
            return record
        serialized = record.serialize() if hasattr(record, "serialize") else dict(record)
        serialized.setdefault("id", getattr(record, "id", None))
        return serialized

    # -- primitives ---------------------------------------------------------
    def get(self, endpoint: str, **filters: Any) -> dict[str, Any] | None:
        matches = self.endpoint(endpoint).filter(**filters)
        for record in matches:
            return self._as_dict(record)
        return None

    def all(self, endpoint: str, **filters: Any) -> list[dict[str, Any]]:
        source = self.endpoint(endpoint)
        records = source.filter(**filters) if filters else source.all()
        return [self._as_dict(r) for r in records]

    def create(self, endpoint: str, data: dict[str, Any]) -> dict[str, Any]:
        if self.dry_run:
            return dict(data)
        return self._as_dict(self.endpoint(endpoint).create(data))

    def update(self, endpoint: str, obj_id: int, data: dict[str, Any]) -> dict[str, Any]:
        if self.dry_run:
            return {"id": obj_id, **data}
        record = self.endpoint(endpoint).get(obj_id)
        if record is None:
            raise LookupError(f"{endpoint} id={obj_id} disappeared")
        record.update(data)
        return self._as_dict(record)

    def delete(self, endpoint: str, obj_id: int) -> None:
        if self.dry_run:
            return
        record = self.endpoint(endpoint).get(obj_id)
        if record is not None:
            record.delete()

    def ping(self) -> dict[str, Any]:
        """Cheap reachability/version check for `infra netbox` and the CLI."""
        return {"url": self.url, "version": str(self.api().version)}
