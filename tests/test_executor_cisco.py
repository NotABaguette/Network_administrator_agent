"""Cisco executor tests: the exact command sequences, and IOS vs IOS-XE parsing.

`FakeSession` is a scripted stand-in for one scrapli connection: it records
every line the executor sends (through the real `_assert_safe` guard, so the
refusals are exercised too) and answers `show` commands from recorded output.
Both flavours of that output are here, because classic IOS (2960 / 3560 / 3750)
and IOS-XE (3650 / 3850) do not print the same thing: the CDP `Device ID:`
separator, the extra err-disabled VLAN column, the wrapped VLAN port list and
the CPU row in the MAC table all differ.

The sequences are asserted literally. `configure terminal revert timer N` before
the change, `configure confirm` only after the post-checks pass, and
`configure revert now` when they do not, is the whole safety property; a change
to any of them should fail a test rather than pass review.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

import pytest

from infra_agent.change.executors.base import ExecutionContext, get_executor, load_all
from infra_agent.change.executors.cisco import (
    ARCHIVE_REMEDIATION,
    DEFAULT_REVERT_TIMER_MINUTES,
    CiscoError,
    CiscoExecutor,
    UnsupportedStep,
    _assert_safe,
    _config_lines,
    normalise_interface,
    parse_archive,
    parse_cdp_detail,
    parse_errdisabled,
    parse_interface_status,
    parse_mac_table,
    parse_running_interface,
    parse_vlan_brief,
)
from infra_agent.change.plan import ChangeStep
from infra_agent.models.common import Credential, DeviceKind, SeedDevice

# -- recorded output ----------------------------------------------------------
ARCHIVE_IOS = """The next archive file will be named flash:/archive/config-3
 Archive #  Name
   1        flash:/archive/config-1
   2        flash:/archive/config-2 <- Most Recent
"""

ARCHIVE_IOSXE = """The maximum archive configurations allowed is 10.
The next archive file will be named bootflash:archive/config-8
 Archive #  Name
   7        bootflash:archive/config-7 <- Most Recent
"""

ARCHIVE_OFF_IOS = "%Archive feature not enabled\n"

ARCHIVE_OFF_IOSXE = """ Archive #  Name
"""

VLAN_BRIEF_IOS = """VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi1/0/1, Gi1/0/2, Gi1/0/3
10   users                            active    Gi1/0/4
20   servers                          active    Gi1/0/5, Gi1/0/6
1002 fddi-default                     act/unsup
"""

# IOS-XE wraps the port column onto a continuation line.
VLAN_BRIEF_IOSXE = """VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi1/0/1, Gi1/0/2
20   servers                          active    Gi1/0/5, Gi1/0/6, Gi1/0/7,
                                                Gi1/0/8, Gi1/0/9
99   native                           active
"""

STATUS_IOS = """Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/5   to esx-01          connected    20         a-full a-1000 10/100/1000BaseTX
"""

STATUS_IOSXE = """Port         Name               Status       Vlan       Duplex  Speed Type
Gi1/0/5                         notconnect   20           auto   auto 10/100/1000BaseTX
"""

ERRDISABLED_IOS = """Port      Name               Status       Reason
Gi1/0/12  lab port           err-disabled link-flap
"""

# IOS-XE adds an Err-disabled Vlans column.
ERRDISABLED_IOSXE = """Port         Name               Status       Reason               Err-disabled Vlans
Gi1/0/12     lab port           err-disabled link-flap
"""

ERRDISABLED_NONE = "Port      Name               Status       Reason\n"

# Classic IOS prints `Device ID:esx-01.lan`, IOS-XE prints `Device ID: esx-01`.
CDP_IOS = """-------------------------
Device ID:esx-01.lan
Entry address(es):
  IP address: 10.0.0.21
Platform: VMware ESX,  Capabilities: Host
Interface: GigabitEthernet1/0/48,  Port ID (outgoing port): vmnic0
Holdtime : 143 sec
"""

CDP_IOSXE = """-------------------------
Device ID: esx-02
Entry address(es):
  IP address: 10.0.0.22
Platform: VMware ESX,  Capabilities: Host
Interface: GigabitEthernet1/0/48,  Port ID (outgoing port): vmnic1
Holdtime : 121 sec
"""

MAC_IOS = """          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  20    0050.5601.0203    DYNAMIC     Gi1/0/5
Total Mac Addresses for this criterion: 1
"""

# IOS-XE lists the CPU entry, which is not a host on the VLAN.
MAC_IOSXE = """          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 All    0100.0ccc.cccc    STATIC      CPU
  20    0050.5601.0203    DYNAMIC     Gi1/0/5
  20    0050.5601.0204    DYNAMIC     Gi1/0/6
Total Mac Addresses for this criterion: 2
"""

RUN_ACCESS_IOS = """Building configuration...

Current configuration : 132 bytes
!
interface GigabitEthernet1/0/5
 description to esx-01
 switchport access vlan 10
 switchport mode access
 spanning-tree portfast
end
"""

RUN_TRUNK_IOSXE = """Building configuration...

Current configuration : 231 bytes
!
interface GigabitEthernet1/0/48
 description uplink to sw-edge-02
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,20
 switchport trunk allowed vlan add 30
 switchport mode trunk
end
"""

RUN_SHUT_IOS = """Building configuration...

Current configuration : 88 bytes
!
interface GigabitEthernet1/0/12
 description lab port
 switchport mode access
 shutdown
end
"""

DEVICE = SeedDevice(
    name="sw-core-01",
    kind=DeviceKind.cisco_ios,
    mgmt_ip="10.0.0.11",
    credential_ref="sw-core-01",
    rw_credential_ref="sw-core-01-rw",
)
CREDENTIAL = Credential(username="svc-change", password="never-logged")


class FakeSession:
    """One scripted switch session. Records every line, answers the shows."""

    def __init__(
        self,
        responses: dict[str, str] | None = None,
        *,
        errors: tuple[str, ...] = (),
    ) -> None:
        self.sent: list[str] = []
        self.responses = dict(responses or {})
        self.errors = set(errors)

    def send(self, command: str) -> str:
        line = _assert_safe(command)  # the real guard, so a refusal is a test failure
        self.sent.append(line)
        if line in self.errors:
            raise CiscoError(f"{line!r} was rejected: % Invalid input")
        if line in self.responses:
            return self.responses[line]
        for key, value in self.responses.items():
            if line.startswith(key):
                return value
        return ""


def connect_to(*sessions: FakeSession):
    """A connect factory that hands out the given sessions in order."""
    queue = list(sessions)

    @contextmanager
    def connect(device: SeedDevice, credential: Credential):
        assert credential.password is not None
        yield queue.pop(0) if len(queue) > 1 else queue[0]

    return connect


def context(session: FakeSession, *, persist: bool = True, plan_id: str = "p1") -> ExecutionContext:
    return ExecutionContext(
        plan_id=plan_id,
        device=DEVICE,
        credential=CREDENTIAL,
        extra={"connect": connect_to(session), "persist": persist},
    )


def access_step(**params: Any) -> ChangeStep:
    body = {"device": "sw-core-01", "interface": "Gi1/0/5", "access_vlan": 20}
    body.update(params)
    return ChangeStep(
        description="move Gi1/0/5 to vlan 20",
        platform="cisco",
        action="switch.access_port_config",
        params=body,
    )


def base_responses(**extra: str) -> dict[str, str]:
    responses = {
        "show archive": ARCHIVE_IOS,
        "show vlan brief": VLAN_BRIEF_IOS,
        "show running-config interface Gi1/0/5": RUN_ACCESS_IOS,
        "show interfaces Gi1/0/5 status": STATUS_IOS,
        "show interfaces status err-disabled": ERRDISABLED_NONE,
        "show mac address-table vlan 20": MAC_IOS,
    }
    responses.update(extra)
    return responses


@pytest.fixture
def executor() -> CiscoExecutor:
    return CiscoExecutor()


# -- registration --------------------------------------------------------------
def test_the_executor_registers_itself_for_cisco():
    load_all()
    assert isinstance(get_executor("cisco"), CiscoExecutor)
    assert get_executor("cisco").supported_actions() == {
        "vlan.add",
        "vlan.remove",
        "switch.access_port_config",
        "switch.clear_errdisable",
        "switch.trunk_port_config",
    }


# -- the command guard ----------------------------------------------------------
@pytest.mark.parametrize(
    "command",
    [
        "reload in 5",
        "reload",
        "write erase",
        "erase startup-config",
        "configure replace flash:backup",
        "boot system flash:image.bin",
        "delete flash:config",
        "format flash:",
        "copy running-config startup-config",
        "username backdoor privilege 15 secret hunter2",
        "snmp-server community public ro",
        "interface Gi1/0/5\nreload",
    ],
)
def test_dangerous_commands_are_refused_before_they_are_sent(command):
    with pytest.raises(CiscoError):
        _assert_safe(command)


def test_the_revert_vocabulary_is_allowed_verbatim():
    for command in (
        "configure terminal revert timer 5",
        "configure terminal",
        "configure confirm",
        "configure revert now",
        "write memory",
        "interface Gi1/0/5",
    ):
        assert _assert_safe(command) == command


# -- rendering -------------------------------------------------------------------
def test_the_access_port_template_renders_only_what_was_asked():
    assert _config_lines(access_step(description="to esx-01", portfast=True, shutdown=False)) == [
        "interface Gi1/0/5",
        "description to esx-01",
        "switchport mode access",
        "switchport access vlan 20",
        "spanning-tree portfast",
        "no shutdown",
        "exit",
    ]
    assert _config_lines(access_step(access_vlan=None, description="lab")) == [
        "interface Gi1/0/5",
        "description lab",
        "exit",
    ]


def test_the_trunk_template_only_adds_and_removes():
    """A bare `switchport trunk allowed vlan <list>` replaces the whole
    membership, which on an uplink drops every VLAN the plan did not name."""
    lines = _config_lines(
        ChangeStep(
            description="carry vlan 30",
            platform="cisco",
            action="switch.trunk_port_config",
            params={
                "device": "sw-core-01",
                "interface": "Gi1/0/48",
                "add_vlans": "30,40",
                "remove_vlans": [10],
                "native_vlan": 99,
            },
        )
    )
    assert lines == [
        "interface Gi1/0/48",
        "switchport trunk allowed vlan add 30,40",
        "switchport trunk allowed vlan remove 10",
        "switchport trunk native vlan 99",
        "exit",
    ]
    assert not any(
        line.startswith("switchport trunk allowed vlan ")
        and not line.startswith(
            ("switchport trunk allowed vlan add", "switchport trunk allowed vlan remove")
        )
        for line in lines
    )


def test_vlan_and_errdisable_templates():
    assert _config_lines(
        ChangeStep(
            description="add",
            platform="cisco",
            action="vlan.add",
            params={"vlan": 20, "name": "servers"},
        )
    ) == ["vlan 20", "name servers", "exit"]
    assert _config_lines(
        ChangeStep(
            description="remove", platform="cisco", action="vlan.remove", params={"vlan": 20}
        )
    ) == ["no vlan 20"]
    assert _config_lines(
        ChangeStep(
            description="clear",
            platform="cisco",
            action="switch.clear_errdisable",
            params={"interface": "Gi1/0/12"},
        )
    ) == ["interface Gi1/0/12", "shutdown", "no shutdown", "exit"]


@pytest.mark.parametrize(
    "params",
    [
        {"interface": "Gi1/0/5; reload", "access_vlan": 20},
        {"interface": "Gi1/0/5", "access_vlan": 9999},
        {"interface": "Gi1/0/5", "access_vlan": 0},
        {"interface": "Gi1/0/5", "description": "line one\nline two"},
        {"interface": "Gi1/0/5"},
    ],
)
def test_bad_parameters_are_rejected_rather_than_rendered(params):
    with pytest.raises(UnsupportedStep):
        _config_lines(access_step(**{"access_vlan": None, **params}))


# -- dry run -----------------------------------------------------------------------
def test_dry_run_renders_the_exact_commands_and_a_structured_diff(executor):
    session = FakeSession(base_responses())

    result = executor.dry_run(context(session), [access_step()])

    assert result.ok is True and result.blockers == []
    assert result.diff["commands"] == [
        f"configure terminal revert timer {DEFAULT_REVERT_TIMER_MINUTES}",
        "interface Gi1/0/5",
        "switchport mode access",
        "switchport access vlan 20",
        "exit",
        "end",
        "configure confirm",
        "write memory",
    ]
    (change,) = result.diff["changes"]
    assert change["object"] == "interface Gi1/0/5"
    assert change["before"]["access_vlan"] == 10
    assert change["after"]["access_vlan"] == 20
    assert change["changed"] == ["access_vlan"]
    # Only structure: the raw `show running-config` text never leaves the process.
    assert "Building configuration" not in str(result.diff)


def test_dry_run_leaves_write_memory_out_when_the_plan_says_not_to_persist(executor):
    session = FakeSession(base_responses())

    result = executor.dry_run(context(session, persist=False), [access_step()])

    assert "write memory" not in result.diff["commands"]
    assert result.diff["persist"] is False


@pytest.mark.parametrize("output", [ARCHIVE_OFF_IOS, ARCHIVE_OFF_IOSXE])
def test_dry_run_blocks_with_the_exact_remediation_when_archive_is_off(executor, output):
    session = FakeSession(base_responses(**{"show archive": output}))

    result = executor.dry_run(context(session), [access_step()])

    assert result.ok is False
    assert result.blockers == [ARCHIVE_REMEDIATION]
    assert "archive\n   path flash:archive\n   maximum 10\n   write-memory" in ARCHIVE_REMEDIATION


def test_dry_run_warns_about_a_vlan_that_does_not_exist_yet(executor):
    session = FakeSession(base_responses())

    result = executor.dry_run(context(session), [access_step(access_vlan=77)])

    assert any("vlan 77 is not configured" in w for w in result.warnings)


def test_dry_run_warns_when_a_vlan_removal_still_has_members(executor):
    session = FakeSession(base_responses())
    step = ChangeStep(
        description="remove vlan 20",
        platform="cisco",
        action="vlan.remove",
        params={"device": "sw-core-01", "vlan": 20},
    )

    result = executor.dry_run(context(session), [step])

    assert any("still has 2 member port(s)" in w for w in result.warnings)
    (change,) = result.diff["changes"]
    assert change["before"]["exists"] is True and change["after"]["exists"] is False


def test_an_unreachable_switch_is_a_blocker_not_a_crash(executor):
    def explode(device, credential):
        raise OSError("connection refused")

    ctx = ExecutionContext(
        plan_id="p1", device=DEVICE, credential=CREDENTIAL, extra={"connect": explode}
    )

    result = executor.dry_run(ctx, [access_step()])

    assert result.ok is False
    assert "could not reach sw-core-01" in result.blockers[0]


# -- apply -------------------------------------------------------------------------
def test_apply_wraps_the_change_in_a_revert_timer(executor):
    session = FakeSession(base_responses())

    result = executor.apply(context(session), access_step())

    assert result.ok is True
    assert session.sent == [
        "show archive",
        "show running-config interface Gi1/0/5",
        "configure terminal revert timer 5",
        "interface Gi1/0/5",
        "switchport mode access",
        "switchport access vlan 20",
        "exit",
        "end",
        "show running-config interface Gi1/0/5",
    ]
    assert result.output["revert_timer_minutes"] == 5
    assert result.output["revert_armed"] is True
    assert result.output["before"]["access_vlan"] == 10
    assert "configure confirm" not in session.sent  # that is the post-check's job


def test_the_revert_timer_is_configurable_per_step(executor):
    session = FakeSession(base_responses())

    executor.apply(context(session), access_step(revert_timer_minutes=2))

    assert "configure terminal revert timer 2" in session.sent


def test_apply_refuses_when_the_archive_feature_was_turned_off_after_the_dry_run(executor):
    session = FakeSession(base_responses(**{"show archive": ARCHIVE_OFF_IOS}))

    result = executor.apply(context(session), access_step())

    assert result.ok is False
    assert "archive feature is not configured" in result.error
    assert "configure terminal revert timer 5" not in session.sent


def test_a_second_step_falls_back_to_plain_config_mode_when_the_timer_is_pending(executor):
    """Some IOS releases refuse to re-arm while a rollback is already scheduled.
    `configure revert now` still restores the checkpoint the first arm took, so
    the later steps are undone with it."""
    ctx = context(FakeSession(base_responses()))
    executor.apply(ctx, access_step())

    session = FakeSession(base_responses(), errors=("configure terminal revert timer 5",))
    second = ExecutionContext(
        plan_id="p1",
        device=DEVICE,
        credential=CREDENTIAL,
        extra={"connect": connect_to(session), "persist": True},
    )
    result = executor.apply(second, access_step(access_vlan=30))

    assert result.ok is True
    assert "configure terminal revert timer 5" in session.sent
    assert "configure terminal" in session.sent
    assert result.output["commands"][0] == "configure terminal"


def test_a_first_step_that_cannot_arm_the_timer_fails_instead_of_running_blind():
    executor = CiscoExecutor()
    session = FakeSession(base_responses(), errors=("configure terminal revert timer 5",))

    result = executor.apply(context(session), access_step())

    assert result.ok is False
    assert "interface Gi1/0/5" not in session.sent


def test_clear_errdisable_shuts_and_unshuts_inside_the_timer(executor):
    session = FakeSession(
        base_responses(**{"show running-config interface Gi1/0/12": RUN_SHUT_IOS})
    )
    step = ChangeStep(
        description="clear",
        platform="cisco",
        action="switch.clear_errdisable",
        params={"device": "sw-core-01", "interface": "Gi1/0/12"},
    )

    result = executor.apply(context(session), step)

    assert result.ok is True
    assert session.sent == [
        "show archive",
        "show running-config interface Gi1/0/12",
        "configure terminal revert timer 5",
        "interface Gi1/0/12",
        "shutdown",
        "no shutdown",
        "exit",
        "end",
        "show running-config interface Gi1/0/12",
    ]


# -- post-checks, confirm and revert -------------------------------------------------
def test_passing_post_checks_confirm_and_save(executor):
    session = FakeSession(base_responses())

    results = executor.post_check(context(session), ["interface Gi1/0/5 is up", "vlan 20 exists"])

    assert [r.ok for r in results] == [True, True, True, True]
    assert session.sent == [
        "show interfaces Gi1/0/5 status",
        "show vlan brief",
        "configure confirm",
        "write memory",
    ]
    assert results[-1].check == "advisory: write memory"


def test_no_post_checks_still_confirms(executor):
    """The plan may declare none; the revert timer would otherwise undo a good
    change, so `configure confirm` is not conditional on there being checks."""
    session = FakeSession(base_responses())

    results = executor.post_check(context(session), [])

    assert session.sent == ["configure confirm", "write memory"]
    assert [r.check for r in results] == ["configure confirm", "advisory: write memory"]


def test_a_failing_post_check_never_confirms(executor):
    session = FakeSession(base_responses(**{"show vlan brief": VLAN_BRIEF_IOSXE}))

    results = executor.post_check(context(session), ["vlan 10 exists"])

    assert [r.ok for r in results] == [False]
    assert "configure confirm" not in session.sent
    assert "write memory" not in session.sent


def test_a_confirm_that_fails_is_reported_as_a_failed_check(executor):
    session = FakeSession(base_responses(), errors=("configure confirm",))

    results = executor.post_check(context(session), [])

    assert results[-1].check == "configure confirm" and results[-1].ok is False
    assert "could not be committed" in results[-1].detail


def test_write_memory_failing_is_advisory_rather_than_a_rollback(executor):
    session = FakeSession(base_responses(), errors=("write memory",))

    results = executor.post_check(context(session), [])

    advisory = results[-1]
    assert advisory.check.startswith("advisory:") and advisory.ok is False
    assert "not saved to startup-config" in advisory.detail
    assert "configure confirm" in session.sent  # the change itself is committed


def test_persist_false_skips_write_memory(executor):
    session = FakeSession(base_responses())

    executor.post_check(context(session, persist=False), [])

    assert session.sent == ["configure confirm"]


def test_rollback_reverts_now_and_reports_the_steps_in_reverse(executor):
    apply_session = FakeSession(base_responses())
    ctx = context(apply_session)
    first = executor.apply(ctx, access_step())
    second = executor.apply(ctx, access_step(interface="Gi1/0/5", access_vlan=30))

    session = FakeSession(base_responses())
    rolled = executor.rollback(context(session), [first, second])

    assert session.sent == ["configure revert now"]
    assert all(r.ok for r in rolled)
    assert [r.output["reverted"] for r in rolled] == [True, True]
    assert [r.step.params["access_vlan"] for r in rolled] == [30, 20]


def test_a_rollback_that_cannot_reach_the_switch_reports_it(executor):
    session = FakeSession(base_responses(), errors=("configure revert now",))
    step_result = executor.apply(context(FakeSession(base_responses())), access_step())

    rolled = executor.rollback(context(session), [step_result])

    assert [r.ok for r in rolled] == [False]
    assert "was rejected" in rolled[0].error


# -- the check language ---------------------------------------------------------------
@pytest.mark.parametrize(
    ("check", "responses", "ok"),
    [
        ("interface Gi1/0/5 is up", {}, True),
        ("interface Gi1/0/5 is down", {}, False),
        ("interface Gi1/0/5 is up", {"show interfaces Gi1/0/5 status": STATUS_IOSXE}, False),
        ("interface Gi1/0/5 is down", {"show interfaces Gi1/0/5 status": STATUS_IOSXE}, True),
        ("vlan 20 exists", {}, True),
        ("vlan 77 exists", {}, False),
        ("vlan 77 does not exist", {}, True),
        ("no errdisable on Gi1/0/12", {}, True),
        (
            "no errdisable on Gi1/0/12",
            {"show interfaces status err-disabled": ERRDISABLED_IOS},
            False,
        ),
        (
            "no errdisable on Gi1/0/12",
            {"show interfaces status err-disabled": ERRDISABLED_IOSXE},
            False,
        ),
        ("mac count on vlan 20 >= 1", {}, True),
        ("mac count on vlan 20 >= 2", {}, False),
        ("mac count on vlan 20 >= 2", {"show mac address-table vlan 20": MAC_IOSXE}, True),
        ("mac count on vlan 20 == 1", {}, True),
        ("mac count on vlan 20 < 1", {}, False),
    ],
)
def test_the_check_language(executor, check, responses, ok):
    session = FakeSession(base_responses(**responses))

    (result,) = executor.pre_check(context(session), [check])

    assert result.ok is ok, result.detail


@pytest.mark.parametrize(
    ("output", "peer", "ok"),
    [
        (CDP_IOS, "esx-01", True),  # classic IOS: `Device ID:esx-01.lan`
        (CDP_IOS, "esx-02", False),
        (CDP_IOSXE, "esx-02", True),  # IOS-XE: `Device ID: esx-02`
        ("", "esx-01", False),
    ],
)
def test_the_cdp_check_reads_both_device_id_spellings(executor, output, peer, ok):
    session = FakeSession(base_responses(**{"show cdp neighbors Gi1/0/48 detail": output}))

    (result,) = executor.pre_check(context(session), [f"cdp neighbor on Gi1/0/48 is {peer}"])

    assert result.ok is ok, result.detail


def test_an_unknown_check_fails_closed(executor):
    """An unreadable post-check must never be what confirms a change."""
    session = FakeSession(base_responses())

    (result,) = executor.pre_check(context(session), ["everything looks fine"])

    assert result.ok is False
    assert "does not understand that check" in result.detail
    assert "configure confirm" not in session.sent


def test_a_check_whose_show_fails_is_a_failed_check_not_an_exception(executor):
    session = FakeSession(base_responses(), errors=("show vlan brief",))

    (result,) = executor.pre_check(context(session), ["vlan 20 exists"])

    assert result.ok is False and "CiscoError" in result.detail


def test_no_pre_checks_touches_nothing(executor):
    session = FakeSession(base_responses())

    assert executor.pre_check(context(session), []) == []
    assert session.sent == []


# -- parsers: IOS and IOS-XE -----------------------------------------------------------
@pytest.mark.parametrize(
    ("output", "expected"),
    [
        (ARCHIVE_IOS, True),
        (ARCHIVE_IOSXE, True),
        (ARCHIVE_OFF_IOS, False),
        (ARCHIVE_OFF_IOSXE, False),
        ("", False),
    ],
)
def test_parse_archive(output, expected):
    assert parse_archive(output) is expected


def test_parse_vlan_brief_reads_both_layouts():
    ios = parse_vlan_brief(VLAN_BRIEF_IOS)
    assert set(ios) == {1, 10, 20, 1002}
    assert ios[20] == {"name": "servers", "status": "active", "ports": ["Gi1/0/5", "Gi1/0/6"]}
    assert ios[1002]["ports"] == []

    xe = parse_vlan_brief(VLAN_BRIEF_IOSXE)
    # The wrapped continuation line belongs to VLAN 20, not to a VLAN of its own.
    assert xe[20]["ports"] == ["Gi1/0/5", "Gi1/0/6", "Gi1/0/7", "Gi1/0/8", "Gi1/0/9"]
    assert xe[99]["ports"] == []


def test_parse_interface_status_reads_both_layouts():
    assert parse_interface_status(STATUS_IOS)["gi1/0/5"] == {
        "interface": "Gi1/0/5",
        "name": "to esx-01",
        "status": "connected",
        "vlan": "20",
    }
    xe = parse_interface_status(STATUS_IOSXE)["gi1/0/5"]
    assert xe["status"] == "notconnect" and xe["name"] == ""


def test_parse_errdisabled_reads_both_layouts():
    assert parse_errdisabled(ERRDISABLED_IOS) == {"gi1/0/12": "link-flap"}
    assert parse_errdisabled(ERRDISABLED_IOSXE) == {"gi1/0/12": "link-flap"}
    assert parse_errdisabled(ERRDISABLED_NONE) == {}


def test_parse_cdp_detail_reads_both_device_id_spellings():
    assert parse_cdp_detail(CDP_IOS) == [
        {
            "device_id": "esx-01.lan",
            "local_interface": "GigabitEthernet1/0/48",
            "platform": "VMware ESX",
        }
    ]
    assert parse_cdp_detail(CDP_IOSXE)[0]["device_id"] == "esx-02"


def test_parse_mac_table_skips_the_cpu_row():
    assert parse_mac_table(MAC_IOS) == [
        {"vlan": "20", "mac": "0050.5601.0203", "type": "DYNAMIC", "port": "Gi1/0/5"}
    ]
    xe = parse_mac_table(MAC_IOSXE)
    assert [row["port"] for row in xe] == ["Gi1/0/5", "Gi1/0/6"]


def test_parse_running_interface_reads_access_and_trunk():
    access = parse_running_interface(RUN_ACCESS_IOS)
    assert access["interface"] == "GigabitEthernet1/0/5"
    assert access["mode"] == "access" and access["access_vlan"] == 10
    assert access["description"] == "to esx-01" and access["portfast"] is True
    assert access["shutdown"] is False

    trunk = parse_running_interface(RUN_TRUNK_IOSXE)
    assert trunk["mode"] == "trunk" and trunk["native_vlan"] == 99
    # The `add` line extends the list rather than replacing it.
    assert trunk["trunk_allowed_vlans"] == [10, 20, 30]

    assert parse_running_interface(RUN_SHUT_IOS)["shutdown"] is True


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("GigabitEthernet1/0/5", "gi1/0/5"),
        ("Gi1/0/5", "gi1/0/5"),
        ("gi1/0/5", "gi1/0/5"),
        ("TenGigabitEthernet1/1/1", "te1/1/1"),
        ("Te1/1/1", "te1/1/1"),
        ("Port-channel1", "po1"),
        ("Po1", "po1"),
        ("Vlan99", "vl99"),
    ],
)
def test_interface_names_normalise_across_platforms(name, expected):
    assert normalise_interface(name) == expected


# -- trunk dry run on IOS-XE -------------------------------------------------------------
def test_a_trunk_change_previews_the_new_allowed_list(executor):
    session = FakeSession(
        base_responses(
            **{
                "show vlan brief": VLAN_BRIEF_IOSXE,
                "show running-config interface Gi1/0/48": RUN_TRUNK_IOSXE,
                "show archive": ARCHIVE_IOSXE,
            }
        )
    )
    step = ChangeStep(
        description="carry vlan 40, drop vlan 10",
        platform="cisco",
        action="switch.trunk_port_config",
        params={
            "device": "sw-core-01",
            "interface": "Gi1/0/48",
            "add_vlans": [40],
            "remove_vlans": [10],
        },
    )

    result = executor.dry_run(context(session), [step])

    (change,) = result.diff["changes"]
    assert change["before"]["trunk_allowed_vlans"] == [10, 20, 30]
    assert change["after"]["trunk_allowed_vlans"] == [20, 30, 40]
    assert change["changed"] == ["trunk_allowed_vlans"]


# -- driven by the real change engine ------------------------------------------------------
def engine_for(session: FakeSession, tmp_path, **overrides: Any):
    """The real `ChangeEngine` driving the real `CiscoExecutor` over a fake session."""
    from infra_agent.change.engine import ChangeEngine
    from infra_agent.change.store import PlanStore
    from infra_agent.change.tiers import ImpactSummary, Tier0Guard
    from infra_agent.config import Settings
    from infra_agent.models.common import SeedInventory

    settings = Settings(
        data_dir=tmp_path / "data",
        secrets_dir=tmp_path / "secrets",
        seed_inventory=tmp_path / "seed.yaml",
        frozen=False,
        tier0_shadow_mode=False,
    )

    class Secrets:
        def available(self) -> bool:
            return True

        def read(self, name: str) -> dict[str, Any]:
            return {"sw-core-01-rw": {"username": "svc-change", "password": "never-logged"}}

    class Notifier:
        def __init__(self) -> None:
            self.messages: list[tuple[str, bool]] = []

        def send(self, text: str, *, critical: bool = False) -> None:
            self.messages.append((text, critical))

        def send_approval_request(self, plan, token: str) -> None:
            self.approval = (plan.id, token)

        def send_report(self, title: str, body: str) -> None:
            pass

    notifier = Notifier()
    store = PlanStore(settings.data_dir / "plans.db")
    executor = CiscoExecutor(connect=connect_to(session))
    engine = ChangeEngine(
        plan_store=store,
        secrets=Secrets(),
        inventory=lambda: SeedInventory(devices=[DEVICE]),
        settings=settings,
        notifier=notifier,
        guard=Tier0Guard(frozen=False, shadow_mode=False),
        impact=lambda target: type("Report", (), {"found": True, "summary": ImpactSummary()})(),
        heartbeat=type("Heartbeat", (), {"healthy": lambda self, now=None: (True, "fresh")})(),
        executor_factory=lambda platform: executor,
        **overrides,
    )
    return engine, store, notifier


def access_plan():
    from infra_agent.change.plan import ChangePlan

    return ChangePlan(
        title="move Gi1/0/5 to vlan 20",
        action="switch.access_port_config",
        targets=["sw-core-01:Gi1/0/5"],
        pre_checks=["vlan 20 exists"],
        post_checks=["interface Gi1/0/5 is up", "mac count on vlan 20 >= 1"],
        steps=[access_step()],
    )


def test_the_engine_drives_a_confirmed_change_end_to_end(tmp_path):
    from infra_agent.change.plan import ChangeState

    session = FakeSession(base_responses())
    engine, store, notifier = engine_for(session, tmp_path)
    plan = access_plan()
    store.save(plan)

    engine.dry_run(plan.id)
    token = engine.request_approval(plan.id)
    store.approve(plan.id, token, "owner", "cli")
    record = engine.execute(plan.id)

    assert record.outcome == "done"
    assert store.get(plan.id).state is ChangeState.done
    # The dry run reads, then the change is armed, applied and only then confirmed.
    assert session.sent == [
        "show archive",
        "show vlan brief",
        "show running-config interface Gi1/0/5",
        "show vlan brief",
        "show archive",
        "show running-config interface Gi1/0/5",
        "configure terminal revert timer 5",
        "interface Gi1/0/5",
        "switchport mode access",
        "switchport access vlan 20",
        "exit",
        "end",
        "show running-config interface Gi1/0/5",
        "show interfaces Gi1/0/5 status",
        "show mac address-table vlan 20",
        "configure confirm",
        "write memory",
    ]
    assert token not in str(record.llm_view())


def test_a_failed_post_check_reverts_now_through_the_engine(tmp_path):
    from infra_agent.change.plan import ChangeState

    # The port never comes up, so the post-check fails and the change must go.
    session = FakeSession(base_responses(**{"show interfaces Gi1/0/5 status": STATUS_IOSXE}))
    engine, store, notifier = engine_for(session, tmp_path)
    plan = access_plan()
    store.save(plan)

    engine.dry_run(plan.id)
    token = engine.request_approval(plan.id)
    store.approve(plan.id, token, "owner", "cli")
    record = engine.execute(plan.id)

    assert record.outcome == "rolled_back"
    assert store.get(plan.id).state is ChangeState.rolled_back
    assert "configure confirm" not in session.sent
    assert session.sent[-1] == "configure revert now"
    assert any(critical for _text, critical in notifier.messages)


def test_the_engine_refuses_a_plan_the_archive_feature_cannot_protect(tmp_path):
    from infra_agent.change.plan import ChangeState

    session = FakeSession(base_responses(**{"show archive": ARCHIVE_OFF_IOS}))
    engine, store, _ = engine_for(session, tmp_path)
    plan = access_plan()
    store.save(plan)

    result = engine.dry_run(plan.id)

    assert result.state is ChangeState.proposed
    assert any("path flash:archive" in b for b in result.diff["blockers"])
    assert "configure terminal revert timer 5" not in session.sent
