"""FortiOS executor: firewall objects over the REST API, rolled back by inverse ops.

The FortiGate 60F is the estate's single edge device and its own management
path, so this executor is deliberately narrow:

* Only the five CMDB object families the change engine proposes are reachable:
  addresses, services, policies, static routes and VIPs. Everything else is a
  refusal, not a generic passthrough.
* `_request` refuses any *endpoint* that smells of a revision, a configuration
  backup or restore, a reboot or an `execute`-style side effect
  (`forbidden_endpoint`). The guard is applied to the collection path and never
  to the object key appended to it, so an address named `backup-nas` stays
  manageable. Revision restore is the documented trap here: it reboots the 60F,
  and an API-token session does not create a revision to go back to, so
  rollback is always an inverse object operation built from the body the apply
  step captured (`docs/architecture.md`).
* Every captured body is scrubbed of `password` / `passwd` / `psk` / `secret` /
  `key` fields — matched as whole tokens, so `q_origin_key` is not one — and of
  FortiOS `ENC ...` blobs before it is stored in
  `StepResult.output`, which is a structure the engine persists and shows. A
  field that was changed but could not be captured makes the *rollback* fail
  loudly (`unrestorable_fields`) rather than silently writing a wrong value.

`dry_run` is where the tiering information comes from: it resolves every
address, service and interface a step references, blocks a delete whose object
is still referenced by a policy or held by an address or service group, and
warns when a policy touches a WAN interface so the engine can escalate the plan
to Tier 2.

TLS verification is off until the Phase 1 pinning work lands; that mirrors the
collector rather than inventing a second policy.
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import quote

from infra_agent.change.executors.base import (
    CheckResult,
    DryRunResult,
    ExecutionContext,
    Executor,
    StepResult,
    register,
)
from infra_agent.change.plan import ChangeStep
from infra_agent.models.common import Credential, SeedDevice

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 20.0

#: Words that make a path segment one this executor must never call. Revision
#: restore reboots the 60F; `execute` / `backup` / `restore` are side effects
#: with no inverse operation. The guard is applied to the endpoint (the
#: collection path), never to the object key appended to it: an address
#: legitimately named `backup-nas` or `factory-floor` has to stay manageable.
FORBIDDEN_WORD = re.compile(
    r"^(revision|revisions|backup|restore|reboot|shutdown|factory|reset|upgrade|format"
    r"|execute)$",
    re.IGNORECASE,
)
#: Whole segments that are refused on their own.
FORBIDDEN_SEGMENT = re.compile(r"^vpn\.ipsec$", re.IGNORECASE)
#: Whole endpoints that are refused because they hold credentials.
FORBIDDEN_ENDPOINT = re.compile(
    r"^(cmdb/system/admin|cmdb/system/api-user|cmdb/user/local)(/|$)", re.IGNORECASE
)


def forbidden_endpoint(endpoint: str) -> str | None:
    """The reason `endpoint` is refused, or None when it may be called.

    Only the endpoint is inspected — the collection path, without the object
    key. `config-revision` and `config/backup` are refused because a *segment*
    of the path says so; an address named `backup-nas` is not an endpoint and
    never reaches this function.
    """
    trimmed = str(endpoint or "").strip("/")
    for segment in trimmed.split("/"):
        if FORBIDDEN_SEGMENT.match(segment):
            return segment
        if any(FORBIDDEN_WORD.match(word) for word in re.split(r"[-_.]", segment)):
            return segment
    if FORBIDDEN_ENDPOINT.match(trimmed):
        return trimmed
    return None


#: Field-name tokens that may hold key material. Matched as whole tokens
#: (`-`, `_` and `.` are the separators FortiOS uses) so that `q_origin_key`,
#: which rides along on every nested table, and `ssl-client-rekey-count` are
#: not mistaken for secrets — flagging those made every step report redacted
#: fields and turned a harmless VIP update into an unrestorable one.
SECRET_TOKEN = re.compile(
    r"(?:^|[-_.])(password|passwd|passphrase|psk|psksecret|secret|key|keys|privatekey)(?:$|[-_.])",
    re.IGNORECASE,
)
#: Benign FortiOS fields whose name happens to contain a secret-shaped token.
SECRET_ALLOW = frozenset({"q_origin_key", "qoriginkey"})
#: FortiOS returns encrypted values as `ENC <base64>`; a value-side backstop.
ENC_VALUE = re.compile(r"^ENC\s+\S", re.IGNORECASE)


def is_secret_field(name: str) -> bool:
    """Whether a field name is one whose value must never be stored."""
    text = str(name)
    if text.lower() in SECRET_ALLOW:
        return False
    return bool(SECRET_TOKEN.search(text))


#: Interfaces that make a policy a Tier 2 change. `role` is the authoritative
#: FortiOS field; the name pattern is the last-resort hint for a 60F whose
#: roles were never set.
WAN_NAME_HINT = re.compile(r"^(wan|internet|isp|ppp|sdwan|virtual-wan-link)\d*$", re.IGNORECASE)

CREATE = "create"
UPDATE = "update"
DELETE = "delete"
MOVE = "move"
ENABLE = "enable"
DISABLE = "disable"
OPS = frozenset({CREATE, UPDATE, DELETE, MOVE, ENABLE, DISABLE})


@dataclass(frozen=True)
class ObjectSpec:
    """One CMDB object family and how it is addressed."""

    action: str
    path: str
    key: str
    label: str


OBJECTS: dict[str, ObjectSpec] = {
    spec.action: spec
    for spec in [
        ObjectSpec("fortigate.address", "cmdb/firewall/address", "name", "address"),
        ObjectSpec("fortigate.service", "cmdb/firewall.service/custom", "name", "service"),
        ObjectSpec("fortigate.policy", "cmdb/firewall/policy", "policyid", "policy"),
        ObjectSpec("fortigate.static_route", "cmdb/router/static", "seq-num", "static route"),
        ObjectSpec("fortigate.vip", "cmdb/firewall/vip", "name", "vip"),
    ]
}

ADDRGRP_PATH = "cmdb/firewall/addrgrp"
SERVICE_GROUP_PATH = "cmdb/firewall.service/group"
INTERFACE_PATH = "cmdb/system/interface"
ZONE_PATH = "cmdb/system/zone"
POLICY_PATH = OBJECTS["fortigate.policy"].path
ROUTE_MONITOR_PATH = "monitor/router/ipv4"
POLICY_MONITOR_PATH = "monitor/firewall/policy"

#: Address names FortiOS ships with; they always resolve.
BUILTIN_ADDRESSES = frozenset({"all", "none", "any"})
BUILTIN_SERVICES = frozenset({"ALL", "ALL_TCP", "ALL_UDP", "ALL_ICMP", "webproxy"})
BUILTIN_INTERFACES = frozenset({"any"})


# ---------------------------------------------------------------------------
# scrubbing
# ---------------------------------------------------------------------------
def scrub(value: Any, dropped: list[str] | None = None, prefix: str = "") -> Any:
    """`value` with every secret-shaped field removed, recursively.

    Names of the dropped fields are appended to `dropped` so the caller can say
    what it will not be able to restore, without ever holding the value.
    """
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            name = f"{prefix}{key}"
            if is_secret_field(key):
                if dropped is not None and name not in dropped:
                    dropped.append(name)
                continue
            if isinstance(item, str) and ENC_VALUE.match(item):
                if dropped is not None and name not in dropped:
                    dropped.append(name)
                continue
            out[key] = scrub(item, dropped, f"{name}.")
        return out
    if isinstance(value, list):
        return [scrub(item, dropped, prefix) for item in value]
    return value


def secret_fields(body: dict[str, Any]) -> list[str]:
    """Top-level field names in `body` that scrubbing would drop."""
    dropped: list[str] = []
    scrub(body, dropped)
    return dropped


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------
class FortiOSTransport(Protocol):
    """One authenticated REST call. Implementations never retry a write."""

    def request(
        self,
        device: SeedDevice,
        cred: Credential,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any: ...


class RequestsFortiOSTransport:
    """`requests` against `https://<mgmt_ip>/api/v2/`, one session per device."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout
        self._sessions: dict[str, Any] = {}
        self._lock = threading.Lock()

    def session(self, device: SeedDevice, cred: Credential) -> Any:
        import requests  # lazy: optional at import time

        with self._lock:
            session = self._sessions.get(device.name)
            if session is None:
                session = requests.Session()
                session.verify = False  # TLS pinning is a Phase 1 decision
                self._sessions[device.name] = session
            token = cred.token.get_secret_value() if cred.token else ""
            session.headers["Authorization"] = f"Bearer {token}"
            return session

    def request(
        self,
        device: SeedDevice,
        cred: Credential,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        if not cred.token:
            raise LookupError(f"no read-write API token for {device.name}")
        session = self.session(device, cred)
        base = f"https://{device.mgmt_ip}:{device.port or 443}/api/v2/"
        response = session.request(
            method.upper(), base + path, params=params, json=body, timeout=self.timeout
        )
        response.raise_for_status()
        if not (response.content or b"").strip():
            return {}
        return response.json()


def results_of(payload: Any) -> Any:
    """The `results` member of a FortiOS answer, or the answer itself."""
    if isinstance(payload, dict) and "results" in payload:
        return payload["results"]
    return payload


def _rows(payload: Any) -> list[dict[str, Any]]:
    body = results_of(payload)
    if isinstance(body, dict):
        return [body]
    if isinstance(body, list):
        return [row for row in body if isinstance(row, dict)]
    return []


def names_of(value: Any) -> list[str]:
    """`[{"name": "wan1"}]`, `["wan1"]` and `"wan1"` all mean the same thing."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        name = value.get("name")
        return [str(name)] if name else []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(names_of(item))
        return out
    return []


# ---------------------------------------------------------------------------
# check grammar
# ---------------------------------------------------------------------------
CHECK_POLICY = re.compile(
    r"^policy\s+(?P<id>\S+)\s+(?P<state>exists|absent|enabled|disabled)$", re.I
)
CHECK_ADDRESS = re.compile(r"^address\s+(?P<name>\S+)\s+(?P<state>exists|absent)$", re.I)
CHECK_ROUTE = re.compile(r"^route\s+to\s+(?P<cidr>\S+)\s+via\s+(?P<gw>\S+)$", re.I)
CHECK_SESSIONS = re.compile(
    r"^sessions\s+matching\s+policy\s+(?P<id>\S+)\s*>=\s*(?P<count>\d+)$", re.I
)

CHECK_GRAMMAR = (
    "policy <id> exists|absent|enabled|disabled",
    "address <name> exists|absent",
    "route to <cidr> via <gw>",
    "sessions matching policy <id> >= <n>",
)


@dataclass
class _Live:
    """Live FortiOS state fetched once per dry-run, then reused."""

    addresses: set[str] = field(default_factory=set)
    services: set[str] = field(default_factory=set)
    interfaces: dict[str, dict[str, Any]] = field(default_factory=dict)
    zones: dict[str, list[str]] = field(default_factory=dict)
    policies: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@register
class FortiGateExecutor(Executor):
    """Firewall object changes with inverse-operation rollback."""

    platform = "fortigate"

    def __init__(self, transport: FortiOSTransport | None = None) -> None:
        self.transport: FortiOSTransport = transport or RequestsFortiOSTransport()

    # -- contract ---------------------------------------------------------
    def supported_actions(self) -> set[str]:
        return set(OBJECTS)

    # -- plumbing ---------------------------------------------------------
    def _request(
        self,
        ctx: ExecutionContext,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        endpoint: str | None = None,
    ) -> Any:
        """One REST call, with the forbidden-endpoint guard in front of it.

        `endpoint` is the collection path the guard is applied to. It defaults
        to `path`, and callers that append a percent-encoded object key pass
        the collection explicitly so that an object *named* `backup-nas` is not
        mistaken for the configuration-backup endpoint.
        """
        reason = forbidden_endpoint(endpoint if endpoint is not None else path)
        if reason is not None:
            raise PermissionError(f"{reason!r} is not an endpoint this executor may call")
        if method.upper() != "GET" and ctx.dry_run:
            raise RuntimeError(f"{method} {path} attempted during a dry run")
        return self.transport.request(
            ctx.device, ctx.credential, method, path, params=params, body=body
        )

    def _object_request(
        self,
        ctx: ExecutionContext,
        method: str,
        spec: ObjectSpec,
        mkey: Any,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        """One REST call against a single object, guarded on its collection."""
        return self._request(
            ctx,
            method,
            self._object_path(spec, mkey),
            params=params,
            body=body,
            endpoint=spec.path,
        )

    def _object_path(self, spec: ObjectSpec, mkey: Any) -> str:
        return f"{spec.path}/{quote(str(mkey), safe='')}"

    def _get_object(
        self, ctx: ExecutionContext, spec: ObjectSpec, mkey: Any
    ) -> dict[str, Any] | None:
        """The object's full body, or None when it does not exist."""
        try:
            rows = _rows(self._object_request(ctx, "GET", spec, mkey))
        except PermissionError:
            raise
        except Exception as exc:  # noqa: BLE001 - "missing" and "unreachable" look alike
            if _is_not_found(exc):
                return None
            raise
        return rows[0] if rows else None

    def _collection(self, ctx: ExecutionContext, path: str) -> list[dict[str, Any]]:
        return _rows(self._request(ctx, "GET", path))

    @staticmethod
    def _mkey(spec: ObjectSpec, step: ChangeStep, op: str = UPDATE) -> Any:
        """The object's key, or None for a create that lets FortiOS assign one.

        A policy id and a static route's `seq-num` are server-assigned, so a
        create is allowed to omit the key; the POST answer carries the `mkey`
        the box chose and that is what the rollback deletes. Every other
        operation has to say which object it means.
        """
        params = step.params
        for candidate in ("mkey", spec.key, "name", "id"):
            if params.get(candidate) not in (None, ""):
                return params[candidate]
        body = params.get("body") or {}
        if isinstance(body, dict) and body.get(spec.key) not in (None, ""):
            return body[spec.key]
        if op == CREATE:
            return None
        raise ValueError(f"{step.action} needs a {spec.key!r} to identify the object")

    @staticmethod
    def _op(step: ChangeStep) -> str:
        op = str(step.params.get("op", UPDATE)).lower()
        if op not in OPS:
            raise ValueError(f"unknown FortiOS operation {op!r} (expected one of {sorted(OPS)})")
        return op

    @staticmethod
    def _body(step: ChangeStep) -> dict[str, Any]:
        body = step.params.get("body") or {}
        if not isinstance(body, dict):
            raise ValueError("params.body must be an object")
        return dict(body)

    def _spec(self, step: ChangeStep) -> ObjectSpec:
        spec = OBJECTS.get(step.action)
        if spec is None:
            raise ValueError(f"{step.action} is not a FortiOS action this executor implements")
        return spec

    # -- dry run ----------------------------------------------------------
    def _live(self, ctx: ExecutionContext) -> _Live:
        live = _Live()

        def load(what: str, path: str) -> list[dict[str, Any]]:
            try:
                return self._collection(ctx, path)
            except Exception as exc:  # noqa: BLE001 - a missing family is a warning
                live.errors.append(f"could not read {what}: {short_error(exc)}")
                return []

        live.addresses = {
            str(r.get("name")) for r in load("addresses", OBJECTS["fortigate.address"].path)
        }
        live.addresses |= {str(r.get("name")) for r in load("address groups", ADDRGRP_PATH)}
        live.addresses |= {str(r.get("name")) for r in load("VIPs", OBJECTS["fortigate.vip"].path)}
        live.services = {
            str(r.get("name")) for r in load("services", OBJECTS["fortigate.service"].path)
        }
        live.services |= {str(r.get("name")) for r in load("service groups", SERVICE_GROUP_PATH)}
        for row in load("interfaces", INTERFACE_PATH):
            live.interfaces[str(row.get("name"))] = row
        for row in load("zones", ZONE_PATH):
            members = [
                str(m.get("interface-name"))
                for m in row.get("interface") or []
                if isinstance(m, dict)
            ]
            live.zones[str(row.get("name"))] = members
        live.policies = load("policies", POLICY_PATH)
        return live

    def is_wan_interface(self, live: _Live, name: str, ctx: ExecutionContext | None = None) -> bool:
        """Whether a policy on this interface is edge-facing (and so Tier 2)."""
        extra = (ctx.extra if ctx else {}) or {}
        declared = {str(n) for n in extra.get("wan_interfaces") or []}
        if name in declared:
            return True
        row = live.interfaces.get(name)
        if row is not None:
            if str(row.get("role", "")).lower() == "wan":
                return True
            if row.get("sdwan-member") or row.get("fortilink"):
                return True
        if name in live.zones:
            return any(self.is_wan_interface(live, member, ctx) for member in live.zones[name])
        return bool(WAN_NAME_HINT.match(name))

    def _referencing_policies(self, live: _Live, spec: ObjectSpec, mkey: Any) -> list[str]:
        """Policy ids that still name this object."""
        name = str(mkey)
        hits: list[str] = []
        for policy in live.policies:
            fields = ("srcaddr", "dstaddr") if spec.action != "fortigate.service" else ("service",)
            if spec.action == "fortigate.vip":
                fields = ("dstaddr",)
            referenced = set()
            for f in fields:
                referenced.update(names_of(policy.get(f)))
            if name in referenced:
                hits.append(str(policy.get("policyid")))
        return hits

    def _referencing_groups(self, ctx: ExecutionContext, spec: ObjectSpec, mkey: Any) -> list[str]:
        """Group names that still hold this object.

        FortiOS rejects a delete for a group membership just as it does for a
        policy reference, so a plan that only checked policies would fail
        halfway through instead of at the dry run.
        """
        if spec.action == "fortigate.service":
            path, member_field = SERVICE_GROUP_PATH, "member"
        elif spec.action in ("fortigate.address", "fortigate.vip"):
            path, member_field = ADDRGRP_PATH, "member"
        else:
            return []
        name = str(mkey)
        try:
            groups = self._collection(ctx, path)
        except Exception:  # noqa: BLE001 - a missing group family blocks nothing
            return []
        return [
            str(group.get("name")) for group in groups if name in names_of(group.get(member_field))
        ]

    def _step_diff(
        self, ctx: ExecutionContext, live: _Live, step: ChangeStep
    ) -> tuple[dict[str, Any], list[str], list[str]]:
        """(diff entry, warnings, blockers) for one step. Never raises."""
        warnings: list[str] = []
        blockers: list[str] = []
        try:
            spec = self._spec(step)
            op = self._op(step)
            mkey = self._mkey(spec, step, op)
            body = self._body(step)
        except ValueError as exc:
            return {"action": step.action, "error": str(exc)}, warnings, [str(exc)]

        label = str(mkey) if mkey is not None else f"<new {spec.label}>"
        try:
            previous = self._get_object(ctx, spec, mkey) if mkey is not None else None
        except Exception as exc:  # noqa: BLE001
            detail = short_error(exc)
            return (
                {"action": step.action, "op": op, "object": label, "error": detail},
                warnings,
                [f"could not read {spec.label} {label}: {detail}"],
            )

        entry: dict[str, Any] = {
            "action": step.action,
            "op": op,
            "object": label,
            "path": spec.path,
            "before": scrub(previous) if previous else None,
        }

        if op == CREATE and previous is not None:
            blockers.append(f"{spec.label} {label} already exists")
        if op in (UPDATE, DELETE, MOVE, ENABLE, DISABLE) and previous is None:
            blockers.append(f"{spec.label} {label} does not exist")

        if op == DELETE:
            entry["after"] = None
            hits = self._referencing_policies(live, spec, mkey)
            if hits:
                blockers.append(
                    f"{spec.label} {label} is still referenced by "
                    f"{'policies' if len(hits) > 1 else 'policy'} {', '.join(sorted(hits))}"
                )
            groups = self._referencing_groups(ctx, spec, mkey)
            if groups:
                blockers.append(
                    f"{spec.label} {label} is still a member of {', '.join(sorted(groups))}"
                )
        elif op in (ENABLE, DISABLE):
            after = dict(scrub(previous) if previous else {})
            after["status"] = "enable" if op == ENABLE else "disable"
            entry["after"] = after
            entry["changed_fields"] = ["status"]
        elif op == MOVE:
            position = str(step.params.get("position", "")).lower()
            target = step.params.get("target")
            if position not in ("before", "after") or target in (None, ""):
                blockers.append("a move needs params.position (before|after) and params.target")
            entry["after"] = entry["before"]
            entry["move"] = {"position": position, "target": str(target)}
        else:
            merged = dict(previous or {})
            merged.update(body)
            entry["after"] = scrub(merged)
            entry["changed_fields"] = sorted(
                k for k in body if (previous or {}).get(k) != body.get(k)
            )
            blockers.extend(self._reference_blockers(live, spec, body))
            dropped = secret_fields(body)
            if dropped:
                warnings.append(
                    f"{spec.label} {label}: {', '.join(dropped)} will not be captured for rollback"
                )

        if spec.action == "fortigate.policy" and op != DELETE:
            # The interfaces that matter are the ones the policy will have once
            # the step lands, not only the ones the step names: an edit to a
            # single field on a WAN-facing rule is still an edge change.
            source = {**(previous or {}), **body}
            interfaces = names_of(source.get("srcintf")) + names_of(source.get("dstintf"))
            wan = sorted({i for i in interfaces if self.is_wan_interface(live, i, ctx)})
            if wan:
                entry["wan_interfaces"] = wan
                warnings.append(
                    f"policy {label} references WAN interface {', '.join(wan)}: "
                    "an edge change, tier accordingly"
                )
        return entry, warnings, blockers

    def _reference_blockers(self, live: _Live, spec: ObjectSpec, body: dict[str, Any]) -> list[str]:
        """Names a policy or VIP body points at that do not exist on the box."""
        blockers: list[str] = []
        if spec.action not in ("fortigate.policy", "fortigate.vip", "fortigate.static_route"):
            return blockers
        checks: list[tuple[str, set[str], frozenset[str], str]] = []
        if spec.action == "fortigate.policy":
            for f in ("srcaddr", "dstaddr"):
                checks.append((f, live.addresses, BUILTIN_ADDRESSES, "address"))
            checks.append(("service", live.services, BUILTIN_SERVICES, "service"))
            for f in ("srcintf", "dstintf"):
                checks.append(
                    (f, set(live.interfaces) | set(live.zones), BUILTIN_INTERFACES, "interface")
                )
        elif spec.action == "fortigate.vip":
            checks.append(
                ("extintf", set(live.interfaces) | set(live.zones), BUILTIN_INTERFACES, "interface")
            )
        else:
            checks.append(
                ("device", set(live.interfaces) | set(live.zones), BUILTIN_INTERFACES, "interface")
            )
        for field_name, known, builtins, label in checks:
            if field_name not in body or not known:
                continue
            for name in names_of(body[field_name]):
                if name not in known and name not in builtins:
                    blockers.append(f"{label} {name!r} referenced by {field_name} does not exist")
        return blockers

    def dry_run(self, ctx: ExecutionContext, steps: list[ChangeStep]) -> DryRunResult:
        try:
            live = self._live(ctx)
        except Exception as exc:  # noqa: BLE001 - a dead box is a blocker, not a crash
            return DryRunResult(ok=False, blockers=[f"FortiGate unreachable: {short_error(exc)}"])
        entries: list[dict[str, Any]] = []
        warnings = list(live.errors)
        blockers: list[str] = []
        probe = ExecutionContext(
            plan_id=ctx.plan_id,
            device=ctx.device,
            credential=ctx.credential,
            dry_run=True,
            frozen=ctx.frozen,
            extra=ctx.extra,
        )
        for step in steps:
            entry, step_warnings, step_blockers = self._step_diff(probe, live, step)
            entries.append(entry)
            warnings.extend(step_warnings)
            blockers.extend(step_blockers)
        return DryRunResult(
            ok=not blockers,
            diff={"platform": self.platform, "device": ctx.device.name, "steps": entries},
            warnings=warnings,
            blockers=blockers,
        )

    # -- checks -----------------------------------------------------------
    def _evaluate(self, ctx: ExecutionContext, check: str) -> CheckResult:
        text = " ".join(check.split())
        match = CHECK_POLICY.match(text)
        if match:
            policy = self._get_object(ctx, OBJECTS["fortigate.policy"], match["id"])
            state = match["state"].lower()
            if state in ("exists", "absent"):
                ok = (policy is not None) if state == "exists" else (policy is None)
                return CheckResult(
                    check=check, ok=ok, detail="present" if policy is not None else "absent"
                )
            status = str((policy or {}).get("status", "")).lower()
            if policy is None:
                return CheckResult(check=check, ok=False, detail="policy does not exist")
            ok = status == ("enable" if state == "enabled" else "disable")
            return CheckResult(check=check, ok=ok, detail=f"status={status or 'unknown'}")

        match = CHECK_ADDRESS.match(text)
        if match:
            address = self._get_object(ctx, OBJECTS["fortigate.address"], match["name"])
            ok = (address is not None) if match["state"].lower() == "exists" else (address is None)
            return CheckResult(
                check=check, ok=ok, detail="present" if address is not None else "absent"
            )

        match = CHECK_ROUTE.match(text)
        if match:
            rows = _rows(self._request(ctx, "GET", ROUTE_MONITOR_PATH))
            wanted_gw, wanted_dst = match["gw"], match["cidr"]
            for row in rows:
                dst = str(row.get("ip_mask") or row.get("dst") or "")
                gateway = str(row.get("gateway") or "")
                if dst == wanted_dst and gateway == wanted_gw:
                    return CheckResult(
                        check=check, ok=True, detail=f"via {gateway} on {row.get('interface', '?')}"
                    )
            return CheckResult(check=check, ok=False, detail="no matching route in the FIB")

        match = CHECK_SESSIONS.match(text)
        if match:
            wanted = int(match["count"])
            rows = _rows(self._request(ctx, "GET", POLICY_MONITOR_PATH))
            for row in rows:
                if str(row.get("policyid")) != match["id"]:
                    continue
                count = row.get("active_sessions")
                if count is None:
                    count = row.get("session_count", 0)
                count = int(count or 0)
                return CheckResult(
                    check=check, ok=count >= wanted, detail=f"{count} active sessions"
                )
            return CheckResult(check=check, ok=False, detail="policy has no session counters")

        return CheckResult(
            check=check,
            ok=False,
            detail=f"unknown check; this executor understands: {'; '.join(CHECK_GRAMMAR)}",
        )

    def _run_checks(self, ctx: ExecutionContext, checks: list[str]) -> list[CheckResult]:
        results: list[CheckResult] = []
        for check in checks:
            try:
                results.append(self._evaluate(ctx, check))
            except Exception as exc:  # noqa: BLE001 - a check never crashes the engine
                results.append(CheckResult(check=check, ok=False, detail=short_error(exc)))
        return results

    def pre_check(self, ctx: ExecutionContext, checks: list[str]) -> list[CheckResult]:
        return self._run_checks(ctx, checks)

    def post_check(self, ctx: ExecutionContext, checks: list[str]) -> list[CheckResult]:
        return self._run_checks(ctx, checks)

    # -- apply ------------------------------------------------------------
    def _policy_order(self, ctx: ExecutionContext) -> list[str]:
        return [str(p.get("policyid")) for p in self._collection(ctx, POLICY_PATH)]

    def _previous_position(self, ctx: ExecutionContext, mkey: Any) -> dict[str, Any] | None:
        order = self._policy_order(ctx)
        key = str(mkey)
        if key not in order:
            return None
        index = order.index(key)
        if index > 0:
            return {"position": "after", "target": order[index - 1]}
        if len(order) > 1:
            return {"position": "before", "target": order[1]}
        return None

    def _move(self, ctx: ExecutionContext, spec: ObjectSpec, mkey: Any, position: Any) -> None:
        """`PUT ?action=move&<before|after>=<target>`, refusing a vanished neighbour."""
        if not isinstance(position, dict):
            raise ValueError("no captured position to move the policy back to")
        target = str(position.get("target", ""))
        where = str(position.get("position", ""))
        if where not in ("before", "after") or not target:
            raise ValueError("the captured position is not a move this executor can issue")
        if target not in self._policy_order(ctx):
            raise ValueError(
                f"policy {target} is no longer in the table, so the original position "
                "cannot be restored; the rule is back but its order has to be checked by hand"
            )
        self._object_request(ctx, "PUT", spec, mkey, params={"action": "move", where: target})

    def _restore_position(
        self, ctx: ExecutionContext, spec: ObjectSpec, mkey: Any, result: StepResult
    ) -> dict[str, Any]:
        """Put a recreated policy back where it was. Raises if it cannot."""
        if spec.action != "fortigate.policy":
            return {}
        position = result.output.get("previous_position")
        if not position:
            return {"position_restored": "the policy was the only one; nothing to move back"}
        self._move(ctx, spec, mkey, position)
        return {"position_restored": f"{position['position']} {position['target']}"}

    def apply(self, ctx: ExecutionContext, step: ChangeStep) -> StepResult:
        started = datetime.now(UTC)
        try:
            if ctx.frozen:
                raise PermissionError("the platform is frozen (break-glass); no writes")
            if ctx.dry_run:
                raise RuntimeError("apply() called with a dry-run context")
            output = self._apply(ctx, step)
            return StepResult(
                step=step, ok=True, output=output, started_at=started, finished_at=datetime.now(UTC)
            )
        except Exception as exc:  # noqa: BLE001 - a failed step is a result, not a crash
            log.warning("fortigate step %s failed: %s", step.action, short_error(exc))
            return StepResult(
                step=step,
                ok=False,
                output={"action": step.action, "device": ctx.device.name},
                error=short_error(exc),
                started_at=started,
                finished_at=datetime.now(UTC),
            )

    def _apply(self, ctx: ExecutionContext, step: ChangeStep) -> dict[str, Any]:
        spec = self._spec(step)
        op = self._op(step)
        mkey = self._mkey(spec, step, op)
        body = self._body(step)
        previous = self._get_object(ctx, spec, mkey) if mkey is not None else None
        dropped: list[str] = []
        output: dict[str, Any] = {
            "action": step.action,
            "device": ctx.device.name,
            "op": op,
            "path": spec.path,
            "key": spec.key,
            "object": str(mkey) if mkey is not None else None,
            "existed": previous is not None,
            # local rollback material only: scrubbed, and never LLM-visible
            "previous": scrub(previous, dropped) if previous is not None else None,
            "redacted_fields": dropped,
        }

        if op == CREATE:
            if previous is not None:
                raise ValueError(f"{spec.label} {mkey} already exists")
            payload = dict(body)
            if mkey is not None:
                payload.setdefault(spec.key, mkey)
            answer = self._request(ctx, "POST", spec.path, body=payload)
            created = answer.get("mkey") if isinstance(answer, dict) else None
            if created in (None, "") and mkey is None:
                # Without a key there is no way to delete what was just made.
                raise ValueError(
                    f"FortiOS did not report the {spec.key!r} it assigned; "
                    "the object cannot be rolled back, so give the step an explicit key"
                )
            output["object"] = str(created if created not in (None, "") else mkey)
            output["rollback"] = DELETE
            return output

        if previous is None:
            raise ValueError(f"{spec.label} {mkey} does not exist")

        if op == DELETE:
            if spec.action == "fortigate.policy":
                # Policy evaluation is first-match, so recreating the rule at
                # the bottom of the table is not the same firewall. Where it
                # sat is captured before it goes.
                output["previous_position"] = self._previous_position(ctx, mkey)
            self._object_request(ctx, "DELETE", spec, mkey)
            output["rollback"] = CREATE
            if dropped:
                output["restore_incomplete"] = dropped
            return output

        if op == MOVE:
            position = str(step.params.get("position", "")).lower()
            target = step.params.get("target")
            if position not in ("before", "after") or target in (None, ""):
                raise ValueError("a move needs params.position (before|after) and params.target")
            output["previous_position"] = self._previous_position(ctx, mkey)
            self._object_request(
                ctx, "PUT", spec, mkey, params={"action": "move", position: str(target)}
            )
            output["moved"] = {"position": position, "target": str(target)}
            output["rollback"] = MOVE
            return output

        payload = body if op == UPDATE else {"status": "enable" if op == ENABLE else "disable"}
        if not payload:
            raise ValueError(f"{step.action} update needs params.body")
        restore = {k: previous[k] for k in payload if k in previous}
        restore_dropped: list[str] = []
        output["restore"] = scrub(restore, restore_dropped)
        unrestorable = [k for k in payload if k not in previous] + restore_dropped
        if unrestorable:
            output["restore_incomplete"] = sorted(set(unrestorable))
        output["changed_fields"] = sorted(k for k in payload if previous.get(k) != payload.get(k))
        self._object_request(ctx, "PUT", spec, mkey, body=payload)
        output["rollback"] = UPDATE
        return output

    # -- rollback ---------------------------------------------------------
    def rollback(self, ctx: ExecutionContext, applied: list[StepResult]) -> list[StepResult]:
        undone: list[StepResult] = []
        for result in reversed(applied):
            if not result.ok:
                continue
            undone.append(self._undo(ctx, result))
        return undone

    def _undo(self, ctx: ExecutionContext, result: StepResult) -> StepResult:
        started = datetime.now(UTC)
        output: dict[str, Any] = {
            "action": result.step.action,
            "device": ctx.device.name,
            "undo_of": result.output.get("op"),
            "object": result.output.get("object"),
        }
        try:
            spec = self._spec(result.step)
            op = str(result.output.get("op", ""))
            mkey = result.output.get("object")
            previous = result.output.get("previous")
            incomplete = result.output.get("restore_incomplete") or []
            if incomplete:
                # Recorded before the call, so a rollback that then fails for
                # another reason still says which fields it could not restore.
                output["unrestorable_fields"] = sorted(incomplete)

            if op == CREATE:
                self._object_request(ctx, "DELETE", spec, mkey)
                output["undo"] = "deleted the object that was created"
            elif op == DELETE:
                if not isinstance(previous, dict) or not previous:
                    raise ValueError("no captured body to recreate the object from")
                self._request(ctx, "POST", spec.path, body=previous)
                output["undo"] = "recreated the deleted object from its captured body"
                output.update(self._restore_position(ctx, spec, mkey, result))
            elif op == MOVE:
                position = result.output.get("previous_position")
                if not position:
                    output["undo"] = "the policy was already first and last; nothing to move back"
                else:
                    self._move(ctx, spec, mkey, position)
                    output["undo"] = f"moved back {position['position']} {position['target']}"
            elif op in (UPDATE, ENABLE, DISABLE):
                restore = result.output.get("restore")
                if not isinstance(restore, dict):
                    raise ValueError("no captured previous values to restore")
                if not restore:
                    # Every changed field was secret-bearing, so there is
                    # nothing safe to write back; `incomplete` says which.
                    if not incomplete:
                        raise ValueError("no captured previous values to restore")
                    output["undo"] = "nothing restorable was captured for this step"
                else:
                    self._object_request(ctx, "PUT", spec, mkey, body=restore)
                    output["undo"] = f"restored {', '.join(sorted(restore))}"
            else:
                raise ValueError(f"nothing to undo for op {op!r}")

            if incomplete:
                output["unrestorable_fields"] = sorted(incomplete)
                return StepResult(
                    step=result.step,
                    ok=False,
                    output=output,
                    error=(
                        "rollback left secret-bearing fields at their new value: "
                        f"{', '.join(sorted(incomplete))}"
                    ),
                    started_at=started,
                    finished_at=datetime.now(UTC),
                )
            return StepResult(
                step=result.step,
                ok=True,
                output=output,
                started_at=started,
                finished_at=datetime.now(UTC),
            )
        except Exception as exc:  # noqa: BLE001 - a failed rollback pages the owner
            return StepResult(
                step=result.step,
                ok=False,
                output=output,
                error=short_error(exc),
                started_at=started,
                finished_at=datetime.now(UTC),
            )


def _is_not_found(exc: Exception) -> bool:
    """Whether a transport error means "no such object" rather than "no answer"."""
    status = getattr(getattr(exc, "response", None), "status_code", None)
    if status == 404:
        return True
    text = str(exc).lower()
    return "404" in text or "resource not found" in text or "entry not found" in text


def short_error(exc: Exception) -> str:
    """A one-line, secret-free description of a failure."""
    return f"{type(exc).__name__}: {str(exc).strip()[:200]}"
