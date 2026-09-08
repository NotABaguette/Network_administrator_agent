"""FortiOS executor tests.

The fake is a small in-memory CMDB with *ordered* policies, so a move and its
inverse are observable, and every call the executor makes is recorded: the
tests assert on the endpoints it did NOT touch (revisions, backups, reboots)
as much as on the ones it did.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import pytest

from infra_agent.change.executors import fortigate as fg
from infra_agent.change.executors.base import ExecutionContext, StepResult, get_executor, load_all
from infra_agent.change.plan import ChangeStep
from infra_agent.models.common import Credential, DeviceKind, SeedDevice

FIXTURE = Path(__file__).parent / "fixtures" / "executors" / "fortigate_cmdb.json"

#: mkey field per collection, mirroring the FortiOS schema.
KEYS = {
    "cmdb/firewall/address": "name",
    "cmdb/firewall/addrgrp": "name",
    "cmdb/firewall.service/custom": "name",
    "cmdb/firewall.service/group": "name",
    "cmdb/firewall/policy": "policyid",
    "cmdb/firewall/vip": "name",
    "cmdb/router/static": "seq-num",
    "cmdb/system/interface": "name",
    "cmdb/system/zone": "name",
}
MONITOR = {"monitor/router/ipv4", "monitor/firewall/policy"}


class _Response:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class FortiError(Exception):
    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.response = _Response(status)


class FakeFortiOS:
    """An in-memory FortiOS CMDB behind the executor's transport protocol."""

    def __init__(self, data: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self.data = copy.deepcopy(data if data is not None else json.loads(FIXTURE.read_text()))
        self.calls: list[tuple[str, str, dict[str, Any] | None, dict[str, Any] | None]] = []
        self.fail_on: tuple[str, str] | None = None  # (method, path prefix)

    # -- helpers ----------------------------------------------------------
    def rows(self, collection: str) -> list[dict[str, Any]]:
        return self.data.setdefault(collection, [])

    def _split(self, path: str) -> tuple[str, str | None]:
        if path in MONITOR:
            return path, None
        for collection in sorted(KEYS, key=len, reverse=True):
            if path == collection:
                return collection, None
            if path.startswith(collection + "/"):
                return collection, unquote(path[len(collection) + 1 :])
        raise FortiError(f"unmapped endpoint {path}", 404)

    def _find(self, collection: str, mkey: Any) -> dict[str, Any] | None:
        key = KEYS.get(collection, "name")
        return next((r for r in self.rows(collection) if str(r.get(key)) == str(mkey)), None)

    # -- transport --------------------------------------------------------
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
        method = method.upper()
        self.calls.append((method, path, params, body))
        if self.fail_on and method == self.fail_on[0] and path.startswith(self.fail_on[1]):
            raise FortiError("simulated FortiOS failure", 500)
        collection, mkey = self._split(path)
        if method == "GET":
            if mkey is None:
                return {"results": copy.deepcopy(self.rows(collection))}
            row = self._find(collection, mkey)
            if row is None:
                raise FortiError(f"resource not found: {path}", 404)
            return {"results": [copy.deepcopy(row)]}
        if method == "POST":
            key = KEYS[collection]
            new = copy.deepcopy(body or {})
            if new.get(key) in (None, ""):
                existing = [int(r.get(key, 0)) for r in self.rows(collection)]
                new[key] = max(existing, default=0) + 1
            if self._find(collection, new.get(key)) is not None:
                raise FortiError("entry already exists", 500)
            self.rows(collection).append(new)
            return {"mkey": new.get(key), "status": "success"}
        if method == "PUT":
            row = self._find(collection, mkey)
            if row is None:
                raise FortiError(f"resource not found: {path}", 404)
            if (params or {}).get("action") == "move":
                self._move(collection, row, params or {})
                return {"status": "success"}
            row.update(copy.deepcopy(body or {}))
            return {"status": "success"}
        if method == "DELETE":
            row = self._find(collection, mkey)
            if row is None:
                raise FortiError(f"resource not found: {path}", 404)
            self.rows(collection).remove(row)
            return {"status": "success"}
        raise FortiError(f"unsupported method {method}", 405)

    def _move(self, collection: str, row: dict[str, Any], params: dict[str, Any]) -> None:
        rows = self.rows(collection)
        rows.remove(row)
        target = params.get("before") or params.get("after")
        anchor = self._find(collection, target)
        index = rows.index(anchor) if anchor in rows else len(rows)
        rows.insert(index if "before" in params else index + 1, row)

    # -- assertions helpers ----------------------------------------------
    def policy_order(self) -> list[str]:
        return [str(p["policyid"]) for p in self.rows("cmdb/firewall/policy")]

    def writes(self) -> list[tuple[str, str]]:
        return [(m, p) for m, p, _params, _body in self.calls if m != "GET"]


DEVICE = SeedDevice(
    name="fw-01",
    kind=DeviceKind.fortigate,
    mgmt_ip="10.10.0.1",
    credential_ref="fw-01-ro",
    rw_credential_ref="fw-01-rw",
)
RW = Credential(username="infra-rw", token="rw-token-value")


@pytest.fixture
def box() -> FakeFortiOS:
    return FakeFortiOS()


@pytest.fixture
def executor(box: FakeFortiOS) -> fg.FortiGateExecutor:
    return fg.FortiGateExecutor(transport=box)


@pytest.fixture
def ctx() -> ExecutionContext:
    return ExecutionContext(plan_id="plan-abc123", device=DEVICE, credential=RW)


def step(action: str, **params: Any) -> ChangeStep:
    return ChangeStep(
        description=f"{action} {params.get('op', '')}".strip(),
        platform="fortigate",
        action=action,
        params=params,
    )


def strings(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, default=str)


# ---------------------------------------------------------------------------
# registration and surface
# ---------------------------------------------------------------------------
def test_registered_under_the_fortigate_platform():
    load_all()
    assert isinstance(get_executor("fortigate"), fg.FortiGateExecutor)


def test_supported_actions_are_the_five_object_families(executor):
    assert executor.supported_actions() == {
        "fortigate.address",
        "fortigate.service",
        "fortigate.policy",
        "fortigate.static_route",
        "fortigate.vip",
    }


# ---------------------------------------------------------------------------
# address
# ---------------------------------------------------------------------------
def test_address_create_then_rollback_deletes_it(executor, ctx, box):
    created = step(
        "fortigate.address",
        op="create",
        name="srv-cache-01",
        body={"type": "ipmask", "subnet": "10.20.0.30 255.255.255.255"},
    )
    result = executor.apply(ctx, created)
    assert result.ok, result.error
    assert box._find("cmdb/firewall/address", "srv-cache-01") is not None
    assert result.output["existed"] is False
    assert result.output["rollback"] == "delete"

    undone = executor.rollback(ctx, [result])
    assert [u.ok for u in undone] == [True]
    assert box._find("cmdb/firewall/address", "srv-cache-01") is None


def test_address_update_captures_only_the_previous_values_it_changed(executor, ctx, box):
    result = executor.apply(
        ctx,
        step(
            "fortigate.address",
            op="update",
            name="srv-web-01",
            body={"subnet": "10.20.0.11 255.255.255.255", "comment": "moved"},
        ),
    )
    assert result.ok, result.error
    assert (
        box._find("cmdb/firewall/address", "srv-web-01")["subnet"] == "10.20.0.11 255.255.255.255"
    )
    assert result.output["restore"] == {
        "subnet": "10.20.0.10 255.255.255.255",
        "comment": "web",
    }
    assert result.output["changed_fields"] == ["comment", "subnet"]

    undone = executor.rollback(ctx, [result])
    assert undone[0].ok
    restored = box._find("cmdb/firewall/address", "srv-web-01")
    assert restored["subnet"] == "10.20.0.10 255.255.255.255"
    assert restored["comment"] == "web"


def test_address_delete_rollback_recreates_from_the_captured_body(executor, ctx, box):
    result = executor.apply(ctx, step("fortigate.address", op="delete", name="lab-host"))
    assert result.ok, result.error
    assert box._find("cmdb/firewall/address", "lab-host") is None
    assert result.output["previous"]["subnet"] == "10.99.0.5 255.255.255.255"

    undone = executor.rollback(ctx, [result])
    assert undone[0].ok
    assert box._find("cmdb/firewall/address", "lab-host")["subnet"] == "10.99.0.5 255.255.255.255"


def test_updating_an_absent_address_is_a_failed_step_not_a_crash(executor, ctx):
    result = executor.apply(
        ctx, step("fortigate.address", op="update", name="ghost", body={"comment": "x"})
    )
    assert result.ok is False
    assert "does not exist" in result.error


# ---------------------------------------------------------------------------
# service
# ---------------------------------------------------------------------------
def test_service_create_and_delete_round_trip(executor, ctx, box):
    created = executor.apply(
        ctx,
        step("fortigate.service", op="create", name="REDIS", body={"tcp-portrange": "6379"}),
    )
    assert created.ok, created.error
    assert box._find("cmdb/firewall.service/custom", "REDIS") is not None

    removed = executor.apply(ctx, step("fortigate.service", op="delete", name="REDIS"))
    assert removed.ok, removed.error
    assert box._find("cmdb/firewall.service/custom", "REDIS") is None

    undone = executor.rollback(ctx, [removed])
    assert undone[0].ok
    assert box._find("cmdb/firewall.service/custom", "REDIS")["tcp-portrange"] == "6379"


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------
def test_policy_create_uses_the_id_fortios_assigned(executor, ctx, box):
    result = executor.apply(
        ctx,
        step(
            "fortigate.policy",
            op="create",
            policyid="",
            body={
                "name": "lab-to-db",
                "srcintf": [{"name": "lab"}],
                "dstintf": [{"name": "internal"}],
                "srcaddr": [{"name": "lab-host"}],
                "dstaddr": [{"name": "srv-db-01"}],
                "service": [{"name": "PGSQL"}],
                "schedule": "always",
            },
        ),
    )
    assert result.ok is False  # no mkey given and none derivable
    result = executor.apply(
        ctx,
        step(
            "fortigate.policy",
            op="create",
            policyid=9,
            body={
                "name": "lab-to-db",
                "srcintf": [{"name": "lab"}],
                "dstintf": [{"name": "internal"}],
                "srcaddr": [{"name": "lab-host"}],
                "dstaddr": [{"name": "srv-db-01"}],
                "service": [{"name": "PGSQL"}],
                "schedule": "always",
            },
        ),
    )
    assert result.ok, result.error
    assert result.output["object"] == "9"
    assert executor.rollback(ctx, [result])[0].ok
    assert box._find("cmdb/firewall/policy", 9) is None


def test_policy_disable_and_enable_restore_the_previous_status(executor, ctx, box):
    disabled = executor.apply(ctx, step("fortigate.policy", op="disable", policyid=1))
    assert disabled.ok, disabled.error
    assert box._find("cmdb/firewall/policy", 1)["status"] == "disable"
    assert disabled.output["restore"] == {"status": "enable"}
    assert executor.rollback(ctx, [disabled])[0].ok
    assert box._find("cmdb/firewall/policy", 1)["status"] == "enable"

    enabled = executor.apply(ctx, step("fortigate.policy", op="enable", policyid=3))
    assert enabled.ok, enabled.error
    assert box._find("cmdb/firewall/policy", 3)["status"] == "enable"
    assert executor.rollback(ctx, [enabled])[0].ok
    assert box._find("cmdb/firewall/policy", 3)["status"] == "disable"


def test_policy_move_and_move_back(executor, ctx, box):
    assert box.policy_order() == ["1", "2", "3"]
    moved = executor.apply(
        ctx, step("fortigate.policy", op="move", policyid=3, position="before", target=1)
    )
    assert moved.ok, moved.error
    assert box.policy_order() == ["3", "1", "2"]
    assert moved.output["previous_position"] == {"position": "after", "target": "2"}

    assert executor.rollback(ctx, [moved])[0].ok
    assert box.policy_order() == ["1", "2", "3"]


def test_a_move_of_the_first_policy_rolls_back_before_the_old_second(executor, ctx, box):
    moved = executor.apply(
        ctx, step("fortigate.policy", op="move", policyid=1, position="after", target=3)
    )
    assert moved.ok, moved.error
    assert box.policy_order() == ["2", "3", "1"]
    assert moved.output["previous_position"] == {"position": "before", "target": "2"}
    assert executor.rollback(ctx, [moved])[0].ok
    assert box.policy_order() == ["1", "2", "3"]


def test_a_move_without_a_target_is_refused(executor, ctx):
    result = executor.apply(ctx, step("fortigate.policy", op="move", policyid=3, position="before"))
    assert result.ok is False
    assert "position" in result.error


# ---------------------------------------------------------------------------
# static route and vip
# ---------------------------------------------------------------------------
def test_static_route_create_and_rollback(executor, ctx, box):
    result = executor.apply(
        ctx,
        step(
            "fortigate.static_route",
            op="create",
            body={
                "seq-num": 7,
                "dst": "10.30.0.0 255.255.255.0",
                "gateway": "10.20.0.254",
                "device": "internal",
            },
        ),
    )
    assert result.ok, result.error
    assert box._find("cmdb/router/static", 7) is not None
    assert executor.rollback(ctx, [result])[0].ok
    assert box._find("cmdb/router/static", 7) is None


def test_vip_update_and_rollback(executor, ctx, box):
    result = executor.apply(
        ctx,
        step("fortigate.vip", op="update", name="vip-web", body={"mappedport": "8443"}),
    )
    assert result.ok, result.error
    assert box._find("cmdb/firewall/vip", "vip-web")["mappedport"] == "8443"
    assert executor.rollback(ctx, [result])[0].ok
    assert box._find("cmdb/firewall/vip", "vip-web")["mappedport"] == "443"


# ---------------------------------------------------------------------------
# dry run
# ---------------------------------------------------------------------------
def test_dry_run_produces_a_structured_before_after_diff(executor, ctx, box):
    result = executor.dry_run(
        ctx,
        [step("fortigate.address", op="update", name="srv-db-01", body={"comment": "primary"})],
    )
    assert result.ok, result.blockers
    entry = result.diff["steps"][0]
    assert entry["before"]["comment"] == "db"
    assert entry["after"]["comment"] == "primary"
    assert entry["changed_fields"] == ["comment"]
    assert box.writes() == []  # a dry run never writes


def test_dry_run_blocks_a_policy_referencing_an_unknown_address(executor, ctx):
    result = executor.dry_run(
        ctx,
        [
            step(
                "fortigate.policy",
                op="update",
                policyid=2,
                body={"dstaddr": [{"name": "srv-ghost"}]},
            )
        ],
    )
    assert result.ok is False
    assert any("srv-ghost" in b for b in result.blockers)


def test_dry_run_blocks_deleting_an_address_a_policy_still_references(executor, ctx):
    result = executor.dry_run(ctx, [step("fortigate.address", op="delete", name="srv-db-01")])
    assert result.ok is False
    assert any("still referenced by policy 2" in b for b in result.blockers)


def test_dry_run_allows_deleting_an_unreferenced_address(executor, ctx, box):
    box.rows("cmdb/firewall/policy").pop()  # policy 3 was the only user of lab-host
    result = executor.dry_run(ctx, [step("fortigate.address", op="delete", name="lab-host")])
    assert result.ok, result.blockers


def test_dry_run_warns_when_a_policy_touches_a_wan_interface(executor, ctx):
    result = executor.dry_run(
        ctx, [step("fortigate.policy", op="update", policyid=1, body={"nat": "disable"})]
    )
    assert result.ok, result.blockers
    assert any("WAN interface wan1" in w for w in result.warnings)
    assert result.diff["steps"][0]["wan_interfaces"] == ["wan1"]


def test_a_zone_holding_a_wan_member_counts_as_wan(executor, ctx, box):
    box.rows("cmdb/system/zone").append({"name": "edge", "interface": [{"interface-name": "wan1"}]})
    result = executor.dry_run(
        ctx,
        [
            step(
                "fortigate.policy",
                op="update",
                policyid=2,
                body={"dstintf": [{"name": "edge"}]},
            )
        ],
    )
    assert any("edge" in w for w in result.warnings)


def test_an_internal_only_policy_produces_no_wan_warning(executor, ctx):
    result = executor.dry_run(
        ctx, [step("fortigate.policy", op="update", policyid=2, body={"nat": "enable"})]
    )
    assert result.warnings == []


def test_dry_run_blocks_creating_an_object_that_exists(executor, ctx):
    result = executor.dry_run(
        ctx, [step("fortigate.address", op="create", name="srv-web-01", body={"subnet": "x"})]
    )
    assert result.ok is False
    assert any("already exists" in b for b in result.blockers)


def test_dry_run_reports_an_unreachable_firewall_as_a_blocker(executor, ctx, box):
    box.fail_on = ("GET", "cmdb")
    result = executor.dry_run(ctx, [step("fortigate.address", op="delete", name="lab-host")])
    assert result.ok is False
    assert result.blockers


def test_dry_run_of_an_unknown_action_is_a_blocker_not_a_crash(executor, ctx):
    result = executor.dry_run(ctx, [step("fortigate.wan", op="update", name="wan1")])
    assert result.ok is False
    assert any("not a FortiOS action" in b for b in result.blockers)


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("check", "expected"),
    [
        ("policy 1 exists", True),
        ("policy 99 exists", False),
        ("policy 99 absent", True),
        ("policy 1 enabled", True),
        ("policy 1 disabled", False),
        ("policy 3 disabled", True),
        ("address srv-web-01 exists", True),
        ("address nope exists", False),
        ("address nope absent", True),
        ("route to 0.0.0.0/0 via 203.0.113.1", True),
        ("route to 0.0.0.0/0 via 198.51.100.1", False),
        ("sessions matching policy 1 >= 10", True),
        ("sessions matching policy 2 >= 10", False),
    ],
)
def test_the_check_grammar(executor, ctx, check, expected):
    (result,) = executor.post_check(ctx, [check])
    assert result.ok is expected, result.detail


def test_an_unknown_check_fails_closed(executor, ctx):
    (result,) = executor.pre_check(ctx, ["the firewall feels fine"])
    assert result.ok is False
    assert "unknown check" in result.detail


def test_a_check_against_a_dead_box_fails_rather_than_raising(executor, ctx, box):
    box.fail_on = ("GET", "cmdb/firewall/policy")
    (result,) = executor.pre_check(ctx, ["policy 1 exists"])
    assert result.ok is False
    assert "FortiError" in result.detail


def test_sessions_check_on_a_policy_without_counters(executor, ctx, box):
    box.data["monitor/firewall/policy"] = []
    (result,) = executor.post_check(ctx, ["sessions matching policy 1 >= 1"])
    assert result.ok is False


# ---------------------------------------------------------------------------
# safety
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "path",
    [
        "monitor/system/config/revision",
        "monitor/system/config/backup",
        "monitor/system/config/restore",
        "monitor/system/os/reboot",
        "cmdb/system/admin/admin",
        "monitor/system/config-revision/file",
    ],
)
def test_forbidden_endpoints_are_refused_before_the_transport_sees_them(executor, ctx, box, path):
    with pytest.raises(PermissionError):
        executor._request(ctx, "GET", path)
    assert box.calls == []


def test_a_full_cycle_never_calls_a_revision_backup_or_reboot_endpoint(executor, ctx, box):
    applied = [
        executor.apply(
            ctx, step("fortigate.address", op="update", name="srv-web-01", body={"comment": "x"})
        ),
        executor.apply(ctx, step("fortigate.policy", op="disable", policyid=1)),
    ]
    executor.rollback(ctx, applied)
    for _method, path, _params, _body in box.calls:
        assert not fg.FORBIDDEN_PATH.search(path), path


def test_a_frozen_context_refuses_to_write(executor, box):
    frozen = ExecutionContext(plan_id="plan-abc123", device=DEVICE, credential=RW, frozen=True)
    result = executor.apply(frozen, step("fortigate.address", op="delete", name="lab-host"))
    assert result.ok is False
    assert "frozen" in result.error
    assert box.writes() == []


def test_apply_refuses_a_dry_run_context(executor, box):
    probe = ExecutionContext(plan_id="p", device=DEVICE, credential=RW, dry_run=True)
    result = executor.apply(probe, step("fortigate.address", op="delete", name="lab-host"))
    assert result.ok is False
    assert box.writes() == []


def test_rollback_runs_in_reverse_and_skips_failed_steps(executor, ctx, box):
    first = executor.apply(
        ctx, step("fortigate.address", op="update", name="srv-web-01", body={"comment": "one"})
    )
    failed = executor.apply(
        ctx, step("fortigate.address", op="update", name="ghost", body={"comment": "x"})
    )
    second = executor.apply(
        ctx, step("fortigate.address", op="update", name="srv-db-01", body={"comment": "two"})
    )
    undone = executor.rollback(ctx, [first, failed, second])
    assert [u.output["object"] for u in undone] == ["srv-db-01", "srv-web-01"]
    assert all(u.ok for u in undone)


def test_a_failed_rollback_is_reported_not_raised(executor, ctx, box):
    result = executor.apply(
        ctx, step("fortigate.address", op="update", name="srv-web-01", body={"comment": "x"})
    )
    box.fail_on = ("PUT", "cmdb/firewall/address")
    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok is False
    assert "FortiError" in undone.error


# ---------------------------------------------------------------------------
# secrets
# ---------------------------------------------------------------------------
SECRET_BEARING = {
    "name": "vip-legacy",
    "extip": "203.0.113.11",
    "extintf": "wan1",
    "mappedip": [{"range": "10.20.0.40"}],
    "psksecret": "ENC 0xdeadbeefcafe",
    "password": "hunter2",
    "ssl-certificate": "Fortinet_Factory",
    "monitor": [{"name": "http-probe", "auth-key": "ENC 0xfeed"}],
}


def test_the_captured_previous_body_never_carries_secret_fields(executor, ctx, box):
    box.rows("cmdb/firewall/vip").append(copy.deepcopy(SECRET_BEARING))
    result = executor.apply(ctx, step("fortigate.vip", op="delete", name="vip-legacy"))
    assert result.ok, result.error
    blob = strings(result.output)
    assert "hunter2" not in blob
    assert "0xdeadbeef" not in blob.lower()
    assert "0xfeed" not in blob
    assert result.output["previous"]["extip"] == "203.0.113.11"
    assert "psksecret" not in result.output["previous"]
    assert "password" not in result.output["previous"]
    assert set(result.output["redacted_fields"]) >= {"psksecret", "password"}


def test_no_credential_material_reaches_the_step_output(executor, ctx):
    result = executor.apply(
        ctx, step("fortigate.address", op="update", name="srv-web-01", body={"comment": "x"})
    )
    blob = strings(result.output)
    assert "rw-token-value" not in blob
    assert "infra-rw" not in blob


def test_rollback_fails_loudly_when_a_changed_field_could_not_be_captured(executor, ctx, box):
    box.rows("cmdb/firewall/vip").append(copy.deepcopy(SECRET_BEARING))
    result = executor.apply(
        ctx, step("fortigate.vip", op="update", name="vip-legacy", body={"psksecret": "new-one"})
    )
    assert result.ok, result.error
    assert result.output["restore_incomplete"] == ["psksecret"]
    assert "new-one" not in strings(result.output)

    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok is False
    assert undone.output["unrestorable_fields"] == ["psksecret"]


def test_scrub_drops_enc_blobs_wherever_they_appear():
    dropped: list[str] = []
    clean = fg.scrub({"a": "ENC 0x1234", "b": {"psk": "x", "ok": 1}}, dropped)
    assert clean == {"b": {"ok": 1}}
    assert sorted(dropped) == ["a", "b.psk"]


def test_names_of_accepts_every_fortios_spelling():
    assert fg.names_of([{"name": "wan1"}, {"name": "internal"}]) == ["wan1", "internal"]
    assert fg.names_of("wan1") == ["wan1"]
    assert fg.names_of(None) == []


def test_step_result_output_stays_json_serialisable(executor, ctx):
    result: StepResult = executor.apply(
        ctx, step("fortigate.address", op="delete", name="lab-host")
    )
    json.dumps(result.model_dump(mode="json"))


def test_dry_run_blocks_deleting_an_address_a_group_still_holds(executor, ctx, box):
    # only the address group references srv-web-01 once policy 2 is gone
    box.rows("cmdb/firewall/policy").remove(box._find("cmdb/firewall/policy", 2))
    result = executor.dry_run(ctx, [step("fortigate.address", op="delete", name="srv-web-01")])
    assert result.ok is False
    assert any("still a member of servers" in b for b in result.blockers)


def test_dry_run_blocks_deleting_a_service_a_group_still_holds(executor, ctx, box):
    box.rows("cmdb/firewall/policy").clear()
    result = executor.dry_run(ctx, [step("fortigate.service", op="delete", name="HTTPS")])
    assert result.ok is False
    assert any("still a member of web-stack" in b for b in result.blockers)


def test_an_unreferenced_object_is_not_blocked_by_the_group_check(executor, ctx, box):
    box.rows("cmdb/firewall/policy").clear()
    result = executor.dry_run(ctx, [step("fortigate.service", op="delete", name="PGSQL")])
    assert result.ok, result.blockers
