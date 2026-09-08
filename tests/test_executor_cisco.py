"""Cisco executor tests: the exact command sequences, and IOS vs IOS-XE parsing.

`FakeSession` is a scripted stand-in for one scrapli connection: it records
every line the executor sends (through the real `_assert_safe` guard, so the
refusals are exercised too) and answers `show` commands from recorded output.
Both flavours of that output are here, because classic IOS (2960 / 3560 / 3750)
and IOS-XE (3650 / 3850) do not print the same thing: the CDP `Device ID:`
separator, the extra err-disabled VLAN column, the wrapped VLAN port list and
the CPU row in the MAC table all differ.

The sequences are asserted literally. `configure terminal revert timer N` before
the change (armed once, never re-armed), `configure confirm` only in the commit
phase - after every device of the plan has passed - and `configure revert now`
when they do not, is the whole safety property; a change to any of them should
fail a test rather than pass review.

Two things a rollback is not allowed to do are also pinned here: report success
because the switch said nothing (the object is read back and compared with what
the step captured), and send `configure revert now` when no timer was ever armed
or when `configure confirm` already threw the checkpoint away - a committed
change is undone by the inverse configuration instead. VLAN work is refused
outright unless `show vtp status` says the switch is transparent or off, because
a VLAN in vlan.dat is not in the archive the revert timer restores.

`ScrapliSession` - the only code here that would talk to a real switch - has its
own tests: what a scrapli channel hands back (bytes, a `(raw, processed)` pair,
a string), which `%` lines are rejections and which are syslog noise from a vty
with `terminal monitor`, and how the read-write credential and the host-key
policy become driver arguments.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

import pytest

from infra_agent.change.executors.base import ExecutionContext, get_executor, load_all
from infra_agent.change.executors.cisco import (
    ARCHIVE_REMEDIATION,
    DEFAULT_REVERT_TIMER_MINUTES,
    VTP_UNKNOWN,
    CiscoError,
    CiscoExecutor,
    ScrapliSession,
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
    parse_vtp_status,
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

# `archive` with no `path`: the sentence is printed, the name is not a filesystem.
ARCHIVE_NO_PATH = "The next archive file will be named <no path configured>\n"

# Classic IOS (2960/3560/3750): one operating mode, VLANs in vlan.dat unless
# the switch is transparent.
VTP_TRANSPARENT_IOS = """VTP Version                     : 2
Configuration Revision          : 0
Maximum VLANs supported locally : 255
Number of existing VLANs        : 7
VTP Operating Mode              : Transparent
VTP Domain Name                 : lab
"""

VTP_SERVER_IOS = """VTP Version                     : 2
Configuration Revision          : 14
VTP Operating Mode              : Server
VTP Domain Name                 : CORE
"""

# VTPv3 (IOS-XE) prints a mode per feature.
VTP_SERVER_IOSXE = """VTP Version capable             : 1 to 3
VTP version running             : 3
VTP Domain Name                 : CORE
Device ID                       : aabb.cc00.1000

Feature VLAN:
--------------
VTP Operating Mode                : Primary Server
Number of existing VLANs          : 12
"""

VTP_OFF_IOSXE = """VTP Version capable             : 1 to 3
VTP Domain Name                 : CORE

Feature VLAN:
--------------
VTP Operating Mode                : Off
"""

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
        sequences: dict[str, list[str]] | None = None,
    ) -> None:
        self.sent: list[str] = []
        self.responses = dict(responses or {})
        self.errors = set(errors)
        #: Commands whose answer changes as the switch does: each send takes the
        #: next output, and the last one repeats.
        self.sequences = {k: list(v) for k, v in (sequences or {}).items()}

    def send(self, command: str) -> str:
        line = _assert_safe(command)  # the real guard, so a refusal is a test failure
        self.sent.append(line)
        if line in self.errors:
            raise CiscoError(f"{line!r} was rejected: % Invalid input")
        queued = self.sequences.get(line)
        if queued:
            return queued.pop(0) if len(queued) > 1 else queued[0]
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
        "show vtp status": VTP_TRANSPARENT_IOS,
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


def test_a_second_step_never_re_arms_the_revert_timer(executor):
    """Re-arming takes a *new* checkpoint - one that already contains step 1 -
    so `configure revert now` would then undo only the later steps. The timer is
    armed once per plan and per device; later steps enter plain config mode and
    are covered by the first checkpoint."""
    ctx = context(FakeSession(base_responses()))
    executor.apply(ctx, access_step())

    session = FakeSession(base_responses())
    second = ExecutionContext(
        plan_id="p1",
        device=DEVICE,
        credential=CREDENTIAL,
        extra={"connect": connect_to(session), "persist": True},
    )
    result = executor.apply(second, access_step(access_vlan=30))

    assert result.ok is True
    assert "configure terminal revert timer 5" not in session.sent
    assert result.output["commands"][0] == "configure terminal"


def test_the_revert_timer_outlives_the_other_devices_of_the_plan(executor):
    """The change is confirmed only once every device has passed, so the timer
    armed on the first switch has to survive the second switch's session."""
    session = FakeSession(base_responses())
    ctx = ExecutionContext(
        plan_id="p1",
        device=DEVICE,
        credential=CREDENTIAL,
        extra={
            "connect": connect_to(session),
            "persist": True,
            "plan_devices": 3,
            "plan_steps": 4,
        },
    )

    result = executor.apply(ctx, access_step())

    assert result.output["revert_timer_minutes"] == DEFAULT_REVERT_TIMER_MINUTES + 2 * 2 + 3
    assert f"configure terminal revert timer {DEFAULT_REVERT_TIMER_MINUTES + 7}" in session.sent


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


# -- post-checks verify; committing is its own phase ----------------------------------
def test_post_checks_only_verify(executor):
    """Confirming here would commit switch A before switch B of the same plan
    has been looked at, and a `configure confirm` cannot be taken back."""
    session = FakeSession(base_responses())

    results = executor.post_check(context(session), ["interface Gi1/0/5 is up", "vlan 20 exists"])

    assert [r.ok for r in results] == [True, True]
    assert session.sent == ["show interfaces Gi1/0/5 status", "show vlan brief"]
    assert "configure confirm" not in session.sent


def test_no_post_checks_opens_no_session(executor):
    session = FakeSession(base_responses())

    assert executor.post_check(context(session), []) == []
    assert session.sent == []


def test_a_failing_post_check_is_just_a_failed_check(executor):
    session = FakeSession(base_responses(**{"show vlan brief": VLAN_BRIEF_IOSXE}))

    results = executor.post_check(context(session), ["vlan 10 exists"])

    assert [r.ok for r in results] == [False]
    assert "configure confirm" not in session.sent
    assert "write memory" not in session.sent


def test_commit_confirms_and_saves(executor):
    session = FakeSession(base_responses())

    results = executor.commit(context(session))

    assert session.sent == ["configure confirm", "write memory"]
    assert [r.check for r in results] == ["configure confirm", "advisory: write memory"]
    assert all(r.ok for r in results)


def test_a_confirm_that_fails_is_reported_as_a_failed_check(executor):
    session = FakeSession(base_responses(), errors=("configure confirm",))

    results = executor.commit(context(session))

    assert results[-1].check == "configure confirm" and results[-1].ok is False
    assert "could not be committed" in results[-1].detail
    assert "write memory" not in session.sent


def test_write_memory_failing_is_advisory_rather_than_a_rollback(executor):
    session = FakeSession(base_responses(), errors=("write memory",))

    results = executor.commit(context(session))

    advisory = results[-1]
    assert advisory.check.startswith("advisory:") and advisory.ok is False
    assert "not saved to startup-config" in advisory.detail
    assert "configure confirm" in session.sent  # the change itself is committed


def test_persist_false_skips_write_memory(executor):
    session = FakeSession(base_responses())

    executor.commit(context(session, persist=False))

    assert session.sent == ["configure confirm"]


# -- rollback --------------------------------------------------------------------------
def test_rollback_reverts_now_and_verifies_every_step_in_reverse(executor):
    apply_session = FakeSession(base_responses())
    ctx = context(apply_session)
    first = executor.apply(ctx, access_step())
    second = executor.apply(ctx, access_step(interface="Gi1/0/5", access_vlan=30))

    session = FakeSession(base_responses())
    rolled = executor.rollback(context(session), [first, second])

    # One revert for the plan, then the switch is read back for each step.
    assert session.sent == [
        "configure revert now",
        "show running-config interface Gi1/0/5",
        "show running-config interface Gi1/0/5",
    ]
    assert all(r.ok for r in rolled)
    assert [r.output["reverted"] for r in rolled] == [True, True]
    assert [r.step.params["access_vlan"] for r in rolled] == [30, 20]


def test_a_revert_that_did_not_put_the_port_back_is_not_a_success(executor):
    """The audited failure: `configure revert now` prints nothing and the change
    is reported as rolled back, while the port is still in the new VLAN."""
    applied = executor.apply(context(FakeSession(base_responses())), access_step())
    moved = RUN_ACCESS_IOS.replace("switchport access vlan 10", "switchport access vlan 20")
    session = FakeSession(base_responses(**{"show running-config interface Gi1/0/5": moved}))

    (rolled,) = executor.rollback(context(session), [applied])

    assert rolled.ok is False
    assert rolled.output["reverted"] is False
    assert rolled.output["differs"] == ["access_vlan"]
    assert "did not return to the state" in rolled.error


@pytest.mark.parametrize(
    "answer",
    [
        "% No rollback confirmed change pending\n",
        "Rollback is not running\n",
    ],
)
def test_a_switch_with_nothing_to_revert_says_so(executor, answer):
    applied = executor.apply(context(FakeSession(base_responses())), access_step())
    session = FakeSession(base_responses(), sequences={"configure revert now": [answer]})

    (rolled,) = executor.rollback(context(session), [applied])

    assert rolled.ok is False
    assert "the rollback was refused" in rolled.error


def test_a_step_that_never_armed_the_timer_is_told_there_is_nothing_to_undo(executor):
    """The first step was refused, so nothing was configured. Sending
    `configure revert now` anyway either errors on a real switch or silently
    reverts something else."""
    session = FakeSession(base_responses(), errors=("configure terminal revert timer 5",))
    failed = executor.apply(context(session), access_step())
    assert failed.ok is False

    rollback_session = FakeSession(base_responses())
    (rolled,) = executor.rollback(context(rollback_session), [failed])

    assert rollback_session.sent == []
    assert rolled.ok is True
    assert rolled.output["reverted"] is False
    assert "nothing to undo" in rolled.output["reason"]


def test_a_committed_change_is_undone_with_the_inverse_configuration(executor):
    """After `configure confirm` there is no checkpoint left, so `configure
    revert now` would be a lie. The port is put back from what the step
    captured, and the result is verified."""
    applied = executor.apply(context(FakeSession(base_responses())), access_step())
    session = FakeSession(base_responses())
    ctx = ExecutionContext(
        plan_id="p1",
        device=DEVICE,
        credential=CREDENTIAL,
        extra={"connect": connect_to(session), "persist": True, "committed": True},
    )

    (rolled,) = executor.rollback(ctx, [applied])

    assert session.sent == [
        "configure terminal revert timer 5",
        "interface Gi1/0/5",
        "switchport access vlan 10",
        "switchport mode access",
        "exit",
        "end",
        "show running-config interface Gi1/0/5",
        "configure confirm",
        "write memory",
    ]
    assert rolled.ok is True and rolled.output["reverted"] is True


def test_a_committed_vlan_removal_is_re_created_from_the_captured_state(executor):
    """The VTP case the dry run refuses to walk into, and the reason vlan.* has
    an inverse at all: put VLAN 20 back, by name."""
    step = ChangeStep(
        description="remove vlan 20",
        platform="cisco",
        action="vlan.remove",
        params={"device": "sw-core-01", "vlan": 20},
    )
    gone = VLAN_BRIEF_IOS.replace(
        "20   servers                          active    Gi1/0/5, Gi1/0/6\n", ""
    )
    applied = executor.apply(
        context(
            FakeSession(base_responses(), sequences={"show vlan brief": [VLAN_BRIEF_IOS, gone]})
        ),
        step,
    )
    assert applied.output["before"] == {"exists": True, "name": "servers"}

    # The VLAN is back once the inverse configuration has been sent.
    session = FakeSession(base_responses())
    ctx = ExecutionContext(
        plan_id="p1",
        device=DEVICE,
        credential=CREDENTIAL,
        extra={"connect": connect_to(session), "persist": False, "committed": True},
    )

    (rolled,) = executor.rollback(ctx, [applied])

    assert session.sent == [
        "configure terminal revert timer 5",
        "vlan 20",
        "name servers",
        "exit",
        "end",
        "show vlan brief",
        "configure confirm",
    ]
    assert rolled.ok is True and rolled.output["reverted"] is True


def test_a_committed_errdisable_clear_has_nothing_to_undo(executor):
    step = ChangeStep(
        description="clear",
        platform="cisco",
        action="switch.clear_errdisable",
        params={"device": "sw-core-01", "interface": "Gi1/0/12"},
    )
    applied = executor.apply(
        context(
            FakeSession(base_responses(**{"show running-config interface Gi1/0/12": RUN_SHUT_IOS}))
        ),
        step,
    )
    session = FakeSession(base_responses())
    ctx = ExecutionContext(
        plan_id="p1",
        device=DEVICE,
        credential=CREDENTIAL,
        extra={"connect": connect_to(session), "committed": True},
    )

    (rolled,) = executor.rollback(ctx, [applied])

    assert session.sent == []
    assert rolled.ok is True and rolled.output["reverted"] is False
    assert "changes no configuration" in rolled.output["reason"]


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
    # Rendered the way IOS writes a VLAN list, not one number per VLAN.
    assert change["before"]["trunk_allowed_vlans"] == "10,20,30"
    assert change["after"]["trunk_allowed_vlans"] == "20,30,40"
    assert change["changed"] == ["trunk_allowed_vlans"]
    assert result.diff["commands"] == [
        f"configure terminal revert timer {DEFAULT_REVERT_TIMER_MINUTES}",
        "interface Gi1/0/48",
        "switchport trunk allowed vlan add 40",
        "switchport trunk allowed vlan remove 10",
        "exit",
        "end",
        "configure confirm",
        "write memory",
    ]


def test_a_trunk_that_allows_every_vlan_is_shown_as_all(executor):
    """`switchport trunk allowed vlan` missing means every VLAN. Showing the
    approver `after: [20]` for `add 20` would say the trunk is about to lose
    every other VLAN, which is the opposite of the truth."""
    all_vlans = RUN_TRUNK_IOSXE.replace(" switchport trunk allowed vlan 10,20\n", "").replace(
        " switchport trunk allowed vlan add 30\n", ""
    )
    session = FakeSession(
        base_responses(
            **{
                "show running-config interface Gi1/0/48": all_vlans,
                "show archive": ARCHIVE_IOSXE,
            }
        )
    )
    step = ChangeStep(
        description="carry vlan 20",
        platform="cisco",
        action="switch.trunk_port_config",
        params={"device": "sw-core-01", "interface": "Gi1/0/48", "add_vlans": [20]},
    )

    (change,) = executor.dry_run(context(session), [step]).diff["changes"]

    assert change["before"]["trunk_allowed_vlans"] == "all"
    assert change["after"]["trunk_allowed_vlans"] == "all"
    assert change["changed"] == []


def test_removing_a_vlan_from_a_trunk_that_allowed_everything_narrows_it(executor):
    all_vlans = RUN_TRUNK_IOSXE.replace(" switchport trunk allowed vlan 10,20\n", "").replace(
        " switchport trunk allowed vlan add 30\n", ""
    )
    session = FakeSession(
        base_responses(
            **{
                "show running-config interface Gi1/0/48": all_vlans,
                "show archive": ARCHIVE_IOSXE,
            }
        )
    )
    step = ChangeStep(
        description="stop carrying vlan 20",
        platform="cisco",
        action="switch.trunk_port_config",
        params={"device": "sw-core-01", "interface": "Gi1/0/48", "remove_vlans": [20]},
    )

    (change,) = executor.dry_run(context(session), [step]).diff["changes"]

    assert change["before"]["trunk_allowed_vlans"] == "all"
    assert change["after"]["trunk_allowed_vlans"] == "1-19,21-4094"


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
    # Reverted, and then read back: the rollback is only reported as done
    # because the port is measurably in the VLAN the step captured.
    assert session.sent[-2:] == [
        "configure revert now",
        "show running-config interface Gi1/0/5",
    ]
    assert [r.output["reverted"] for r in record.rollback_steps] == [True]
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


# -- VTP: a VLAN needs somewhere to roll back to ----------------------------------------
def vlan_step(action: str = "vlan.remove", **params: Any) -> ChangeStep:
    body: dict[str, Any] = {"device": "sw-core-01", "vlan": 20}
    body.update(params)
    return ChangeStep(description=f"{action} 20", platform="cisco", action=action, params=body)


@pytest.mark.parametrize(
    ("status", "mode"),
    [(VTP_SERVER_IOS, "server"), (VTP_SERVER_IOSXE, "server")],
)
def test_a_vlan_change_is_refused_on_a_vtp_server(executor, status, mode):
    """On a server or client the VLAN lives in vlan.dat, which the archive does
    not carry - so `configure revert now` cannot bring a deleted VLAN back - and
    `no vlan 20` propagates to every switch in the domain."""
    session = FakeSession(base_responses(**{"show vtp status": status}))

    result = executor.dry_run(context(session), [vlan_step()])

    assert result.ok is False
    (blocker,) = result.blockers
    assert f"VTP is in {mode} mode (domain CORE)" in blocker
    assert "vtp mode transparent" in blocker


def test_a_vlan_change_is_refused_when_the_switch_will_not_say(executor):
    session = FakeSession(base_responses(), errors=("show vtp status",))

    result = executor.dry_run(context(session), [vlan_step()])

    assert result.blockers == [VTP_UNKNOWN]


@pytest.mark.parametrize("status", [VTP_TRANSPARENT_IOS, VTP_OFF_IOSXE])
def test_a_vlan_change_passes_on_a_transparent_or_off_switch(executor, status):
    session = FakeSession(base_responses(**{"show vtp status": status}))

    result = executor.dry_run(context(session), [vlan_step()])

    assert result.ok is True and result.blockers == []


def test_an_access_port_change_does_not_care_about_vtp(executor):
    session = FakeSession(base_responses(**{"show vtp status": VTP_SERVER_IOS}))

    result = executor.dry_run(context(session), [access_step()])

    assert result.ok is True
    assert "show vtp status" not in session.sent


def test_apply_re_reads_the_vtp_mode_because_a_plan_may_sit_approved_for_hours(executor):
    session = FakeSession(base_responses(**{"show vtp status": VTP_SERVER_IOS}))

    result = executor.apply(context(session), vlan_step("vlan.add"))

    assert result.ok is False
    assert "VTP is in server mode" in result.error
    assert "configure terminal revert timer 5" not in session.sent


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        (VTP_TRANSPARENT_IOS, {"mode": "transparent", "domain": "lab"}),
        (VTP_SERVER_IOS, {"mode": "server", "domain": "CORE"}),
        (VTP_SERVER_IOSXE, {"mode": "server", "domain": "CORE"}),
        (VTP_OFF_IOSXE, {"mode": "off", "domain": "CORE"}),
        ("", {"mode": "", "domain": ""}),
    ],
)
def test_parse_vtp_status(output, expected):
    assert parse_vtp_status(output) == expected


def test_parse_archive_needs_a_real_filesystem_path():
    """`archive` without `path` prints the sentence and no destination: there is
    no checkpoint, so the revert timer has nothing to roll back to."""
    assert parse_archive(ARCHIVE_NO_PATH) is False
    assert parse_archive(ARCHIVE_IOS) is True
    assert parse_archive(ARCHIVE_IOSXE) is True


# -- the transport ------------------------------------------------------------------------
class FakeChannel:
    """scrapli's channel: whatever `send_input` returns, the wrapper copes."""

    def __init__(self, answers: dict[str, Any] | None = None) -> None:
        self.answers = dict(answers or {})
        self.sent: list[str] = []

    def send_input(self, command: str) -> Any:
        self.sent.append(command)
        return self.answers.get(command, ("raw", ""))


class FakeConnection:
    def __init__(self, channel: FakeChannel) -> None:
        self.channel = channel


@pytest.mark.parametrize(
    "answer",
    [
        ("raw bytes here", "VLAN Name\n20   servers    active"),
        b"VLAN Name\n20   servers    active",
        "VLAN Name\n20   servers    active",
    ],
)
def test_the_scrapli_wrapper_reads_bytes_tuples_and_strings(answer):
    channel = FakeChannel({"show vlan brief": answer})
    session = ScrapliSession(FakeConnection(channel))

    output = session.send("show vlan brief")

    assert "20   servers" in output
    assert channel.sent == ["show vlan brief"]


def test_the_scrapli_wrapper_refuses_a_command_outside_the_templates():
    session = ScrapliSession(FakeConnection(FakeChannel()))

    with pytest.raises(CiscoError, match="outside the action's command template"):
        session.send("reload in 5")


@pytest.mark.parametrize(
    "output",
    [
        "% Invalid input detected at '^' marker",
        "%Archive feature not enabled",
        "vlan 4000\n% VLAN not allowed in this mode",
    ],
)
def test_the_scrapli_wrapper_raises_on_a_rejected_command(output):
    channel = FakeChannel({"show archive": ("raw", output)})
    session = ScrapliSession(FakeConnection(channel))

    with pytest.raises(CiscoError, match="was rejected"):
        session.send("show archive")


@pytest.mark.parametrize(
    "noise",
    [
        "%SYS-5-CONFIG_I: Configured from console by svc-change on vty0",
        "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/5, changed state to up",
        "%ARCHIVE_DIFF-5-ARCHIVE_DIFF_APPLIED: applied",
    ],
)
def test_a_syslog_line_on_the_vty_is_not_a_rejected_command(noise):
    """A vty with `terminal monitor` prints log messages into the middle of a
    `show`. Reading one as a rejection would fail a post-check and roll a good
    change back."""
    body = f"{noise}\nVLAN Name\n20   servers    active"
    session = ScrapliSession(FakeConnection(FakeChannel({"show vlan brief": ("raw", body)})))

    assert "20   servers" in session.send("show vlan brief")


def test_the_session_silences_the_vty_and_carries_the_read_write_credential(monkeypatch):
    """The only place the read-write credential turns into a connection. It is
    handed over as the secret it is, and the host key policy comes from the
    operator's `INFRA_SSH_KNOWN_HOSTS`, not from a default."""
    import scrapli.driver.core as core

    from infra_agent.change.executors import cisco as cisco_module

    built: dict[str, Any] = {}
    channel = FakeChannel()

    class FakeDriver:
        def __init__(self, **kwargs: Any) -> None:
            built.update(kwargs)

        def __enter__(self):
            return FakeConnection(channel)

        def __exit__(self, *exc: Any) -> None:
            built["closed"] = True

    monkeypatch.setattr(core, "IOSXEDriver", FakeDriver)
    monkeypatch.setenv("INFRA_SSH_KNOWN_HOSTS", "/etc/infra/known_hosts")
    device = DEVICE.model_copy(update={"legacy_ssh": True, "port": 2222})

    with cisco_module.scrapli_session(device, CREDENTIAL) as session:
        assert isinstance(session, ScrapliSession)

    assert built["host"] == "10.0.0.11"
    assert built["port"] == 2222
    assert built["auth_username"] == "svc-change"
    assert built["auth_password"] == "never-logged"
    assert built["auth_strict_key"] is True
    assert built["ssh_known_hosts_file"] == "/etc/infra/known_hosts"
    assert built["ssh_config_file"] is True  # the old 2960s need legacy KEX
    assert built["closed"] is True
    # Log messages on the vty would land in the middle of a `show`.
    assert channel.sent == ["terminal length 0", "terminal no monitor"]


def test_an_unknown_host_key_is_only_ignored_when_nothing_pins_it(monkeypatch):
    import scrapli.driver.core as core

    from infra_agent.change.executors import cisco as cisco_module

    built: dict[str, Any] = {}

    class FakeDriver:
        def __init__(self, **kwargs: Any) -> None:
            built.update(kwargs)

        def __enter__(self):
            return FakeConnection(FakeChannel())

        def __exit__(self, *exc: Any) -> None:
            pass

    monkeypatch.setattr(core, "IOSXEDriver", FakeDriver)
    monkeypatch.delenv("INFRA_SSH_KNOWN_HOSTS", raising=False)

    with cisco_module.scrapli_session(DEVICE, CREDENTIAL):
        pass

    assert built["auth_strict_key"] is False
    assert "ssh_known_hosts_file" not in built
    assert "ssh_config_file" not in built


def test_a_switch_that_will_not_take_terminal_no_monitor_still_works(monkeypatch):
    import scrapli.driver.core as core

    from infra_agent.change.executors import cisco as cisco_module

    class RefusingChannel(FakeChannel):
        def send_input(self, command: str) -> Any:
            self.sent.append(command)
            if command == "terminal no monitor":
                return ("raw", "% Invalid input detected")
            return ("raw", "")

    channel = RefusingChannel()

    class FakeDriver:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def __enter__(self):
            return FakeConnection(channel)

        def __exit__(self, *exc: Any) -> None:
            pass

    monkeypatch.setattr(core, "IOSXEDriver", FakeDriver)

    with cisco_module.scrapli_session(DEVICE, CREDENTIAL) as session:
        assert session.send("show vlan brief") == ""


# -- two switches, one plan ----------------------------------------------------------------
EDGE = SeedDevice(
    name="sw-edge-02",
    kind=DeviceKind.cisco_iosxe,
    mgmt_ip="10.0.0.12",
    credential_ref="sw-edge-02",
    rw_credential_ref="sw-edge-02-rw",
)


def connect_by_device(sessions: dict[str, FakeSession]):
    @contextmanager
    def connect(device: SeedDevice, credential: Credential):
        assert credential.password is not None
        yield sessions[device.name]

    return connect


def two_switch_engine(sessions: dict[str, FakeSession], tmp_path):
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
            return {
                "sw-core-01-rw": {"username": "svc-change", "password": "never-logged"},
                "sw-edge-02-rw": {"username": "svc-change", "password": "never-logged"},
            }

    class Notifier:
        def __init__(self) -> None:
            self.messages: list[tuple[str, bool]] = []

        def send(self, text: str, *, critical: bool = False) -> None:
            self.messages.append((text, critical))

        def send_approval_request(self, plan, token: str, phrase: str | None = None) -> None:
            self.approval = (plan.id, token)

        def send_report(self, title: str, body: str) -> None:
            pass

    notifier = Notifier()
    store = PlanStore(settings.data_dir / "plans.db")
    executor = CiscoExecutor(connect=connect_by_device(sessions))
    engine = ChangeEngine(
        plan_store=store,
        secrets=Secrets(),
        inventory=lambda: SeedInventory(devices=[DEVICE, EDGE]),
        settings=settings,
        notifier=notifier,
        guard=Tier0Guard(frozen=False, shadow_mode=False),
        impact=lambda target: type("Report", (), {"found": True, "summary": ImpactSummary()})(),
        heartbeat=type("Heartbeat", (), {"healthy": lambda self, now=None: (True, "fresh")})(),
        executor_factory=lambda platform: executor,
    )
    return engine, store, notifier


def two_switch_plan():
    from infra_agent.change.plan import ChangePlan

    return ChangePlan(
        title="add vlan 20 on both switches",
        action="vlan.add",
        targets=["sw-core-01", "sw-edge-02"],
        post_checks=["vlan 20 exists"],
        steps=[
            ChangeStep(
                description="create vlan 20 on the core",
                platform="cisco",
                action="vlan.add",
                params={"device": "sw-core-01", "vlan": 20, "name": "servers"},
            ),
            ChangeStep(
                description="create vlan 20 on the edge",
                platform="cisco",
                action="vlan.add",
                params={"device": "sw-edge-02", "vlan": 20, "name": "servers"},
            ),
        ],
    )


def test_the_first_switch_is_not_committed_when_the_second_one_fails(tmp_path):
    """The audited failure: sw-core-01 confirmed and written to startup-config
    before sw-edge-02 was checked, then sent a `configure revert now` that has
    nothing left to revert - while the owner is told the change was undone."""
    without_vlan_20 = VLAN_BRIEF_IOS.replace(
        "20   servers                          active    Gi1/0/5, Gi1/0/6\n", ""
    )
    core = FakeSession(base_responses())
    edge = FakeSession(base_responses(**{"show vlan brief": without_vlan_20}))
    engine, store, notifier = two_switch_engine({"sw-core-01": core, "sw-edge-02": edge}, tmp_path)
    plan = two_switch_plan()
    store.save(plan)

    engine.dry_run(plan.id)
    token = engine.request_approval(plan.id)
    store.approve(plan.id, token, "owner", "cli")
    record = engine.execute(plan.id)

    assert record.outcome == "rolled_back"
    # Neither switch was confirmed, because the plan was never fully verified.
    assert "configure confirm" not in core.sent
    assert "write memory" not in core.sent
    assert "configure confirm" not in edge.sent
    assert core.sent.count("configure revert now") == 1
    assert edge.sent.count("configure revert now") == 1
    # The timer on the first switch had to outlive the second switch's session.
    assert "configure terminal revert timer 8" in core.sent
    assert any(critical for _text, critical in notifier.messages)


def test_both_switches_are_confirmed_only_after_both_passed(tmp_path):
    core = FakeSession(base_responses())
    edge = FakeSession(base_responses())
    engine, store, _ = two_switch_engine({"sw-core-01": core, "sw-edge-02": edge}, tmp_path)
    plan = two_switch_plan()
    store.save(plan)

    engine.dry_run(plan.id)
    token = engine.request_approval(plan.id)
    store.approve(plan.id, token, "owner", "cli")
    record = engine.execute(plan.id)

    assert record.outcome == "done"
    assert core.sent[-2:] == ["configure confirm", "write memory"]
    assert edge.sent[-2:] == ["configure confirm", "write memory"]
    # The core switch is verified before either switch is committed.
    assert core.sent.index("show vlan brief") < core.sent.index("configure confirm")
    assert [c.phase for c in record.checks if c.check == "configure confirm"] == [
        "commit",
        "commit",
    ]


def test_a_manual_rollback_after_a_confirmed_change_undoes_it_by_configuration(tmp_path):
    """`infra change rollback` on a plan that is already `done`. The revert
    timer is long gone, so sending `configure revert now` would be reported as a
    success while the port stayed where it was."""
    session = FakeSession(base_responses())
    engine, store, notifier = engine_for(session, tmp_path)
    plan = access_plan()
    store.save(plan)
    engine.dry_run(plan.id)
    token = engine.request_approval(plan.id)
    store.approve(plan.id, token, "owner", "cli")
    assert engine.execute(plan.id).outcome == "done"
    session.sent.clear()

    record = engine.rollback(plan.id)

    assert record.outcome == "rolled_back"
    assert "configure revert now" not in session.sent
    assert session.sent == [
        "configure terminal revert timer 5",
        "interface Gi1/0/5",
        "switchport access vlan 10",
        "switchport mode access",
        "exit",
        "end",
        "show running-config interface Gi1/0/5",
        "configure confirm",
        "write memory",
    ]
    assert [r.output["reverted"] for r in record.rollback_steps] == [True]
