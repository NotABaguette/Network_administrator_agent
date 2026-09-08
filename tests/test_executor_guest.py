"""Guest executor tests, Linux over SSH and Windows over WinRM.

The fake transport is a scripted shell keyed by the exact command, so the
tests assert on the command strings the dialects build as well as on the
behaviour: a guest command runs as root or SYSTEM, and the parameters can come
from the model, so "what exactly gets executed" is the thing worth pinning.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from infra_agent.change.executors import guest as gu
from infra_agent.change.executors.base import ExecutionContext, get_executor, load_all
from infra_agent.change.plan import ChangeStep
from infra_agent.models.common import Credential, DeviceKind, SeedDevice

LINUX = SeedDevice(
    name="app-01",
    kind=DeviceKind.guest_linux,
    mgmt_ip="10.20.0.10",
    credential_ref="app-01-ro",
    rw_credential_ref="app-01-rw",
)
WINDOWS = SeedDevice(
    name="win-01",
    kind=DeviceKind.guest_windows,
    mgmt_ip="10.20.0.11",
    credential_ref="win-01-ro",
    rw_credential_ref="win-01-rw",
)
NOT_A_GUEST = SeedDevice(
    name="sw-01", kind=DeviceKind.cisco_ios, mgmt_ip="10.10.0.11", credential_ref="sw-01"
)
RW = Credential(username="infra-rw", password="guest-password-value", ssh_key_path="/keys/rw.pem")

APT_SIMULATE = """Reading package lists...
Building dependency tree...
Calculating upgrade...
Inst libssl3 [3.0.11-1] (3.0.13-1 Debian:stable [amd64])
Inst curl [7.88.1-10] (7.88.1-11 Debian:stable [amd64])
Conf libssl3 (3.0.13-1 Debian:stable [amd64])
"""

DNF_CHECK_UPDATE = """Last metadata expiration check: 0:12:01 ago.

curl.x86_64                 7.76.1-27.el9      baseos
openssl-libs.x86_64         3.0.7-25.el9       baseos
"""

WINGET_UPGRADE = """Name              Id                     Version   Available Source
---------------------------------------------------------------------
Git                Git.Git                2.43.0    2.44.0    winget
7-Zip              7zip.7zip              23.01     24.05     winget
"""

WINGET_LIST = """Name              Id                     Version
------------------------------------------------
Git                Git.Git                2.44.0
7-Zip              7zip.7zip              24.05
"""


class FakeGuest:
    """A scripted guest shell. Commands not in the script answer rc=0, empty."""

    def __init__(self, name: str = "ssh", script: dict[str, Any] | None = None) -> None:
        self.name = name
        self.script: dict[str, Any] = dict(script or {})
        self.commands: list[str] = []

    def set(self, command: str, stdout: str = "", rc: int = 0, stderr: str = "") -> None:
        self.script[command] = (rc, stdout, stderr)

    def run(self, ctx: ExecutionContext, command: str, timeout: float) -> gu.CommandResult:
        self.commands.append(command)
        entry = self.script.get(command)
        if callable(entry):
            entry = entry()
        if isinstance(entry, Exception):
            raise entry
        rc, out, err = entry if entry is not None else (0, "", "")
        return gu.CommandResult(command=command, rc=rc, stdout=out, stderr=err)


def step(action: str, **params: Any) -> ChangeStep:
    return ChangeStep(description=action, platform="guest", action=action, params=params)


def strings(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, default=str)


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def linux_shell() -> FakeGuest:
    shell = FakeGuest("ssh")
    shell.set("systemctl show -p ActiveState --value -- nginx", "active\n")
    shell.set("cat /proc/uptime", "123456.78 987654.32\n")
    shell.set(
        "ss -H -ltn",
        "LISTEN 0      4096         0.0.0.0:22        0.0.0.0:*\n"
        "LISTEN 0      511          0.0.0.0:443       0.0.0.0:*\n",
    )
    return shell


@pytest.fixture
def windows_shell() -> FakeGuest:
    shell = FakeGuest("winrm")
    shell.set(
        "$s = Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue; "
        "if ($s) { $s.Status.ToString() } else { 'missing' }",
        "Running\n",
    )
    return shell


@pytest.fixture
def executor(linux_shell: FakeGuest, windows_shell: FakeGuest) -> gu.GuestExecutor:
    return gu.GuestExecutor(linux=linux_shell, windows=windows_shell, sleep=lambda _s: None)


@pytest.fixture
def ctx() -> ExecutionContext:
    return ExecutionContext(plan_id="plan-77", device=LINUX, credential=RW)


@pytest.fixture
def win_ctx() -> ExecutionContext:
    return ExecutionContext(plan_id="plan-77", device=WINDOWS, credential=RW)


# ---------------------------------------------------------------------------
# registration and dispatch
# ---------------------------------------------------------------------------
def test_registered_under_the_guest_platform():
    load_all()
    assert isinstance(get_executor("guest"), gu.GuestExecutor)


def test_supported_actions(executor):
    assert executor.supported_actions() == {
        "guest.service_restart",
        "guest.service_stop",
        "guest.service_start",
        "guest.package_update",
        "guest.reboot",
    }


def test_the_device_kind_picks_the_transport_and_the_dialect(executor):
    assert executor.transport(LINUX).name == "ssh"
    assert executor.transport(WINDOWS).name == "winrm"
    assert isinstance(executor.dialect(LINUX), gu.LinuxDialect)
    assert isinstance(executor.dialect(WINDOWS), gu.WindowsDialect)


def test_the_default_transports_are_the_real_ones():
    executor = gu.GuestExecutor()
    assert isinstance(executor.transport(LINUX), gu.SshGuestTransport)
    assert isinstance(executor.transport(WINDOWS), gu.WinRmGuestTransport)


def test_a_switch_is_not_a_guest(executor):
    with pytest.raises(gu.GuestError):
        executor.transport(NOT_A_GUEST)
    bad = ExecutionContext(plan_id="p", device=NOT_A_GUEST, credential=RW)
    assert executor.apply(bad, step("guest.service_restart", service="nginx")).ok is False


# ---------------------------------------------------------------------------
# quoting: the property that matters most here
# ---------------------------------------------------------------------------
def test_powershell_quoting_doubles_the_single_quote():
    assert gu.ps_quote("a'b") == "'a''b'"
    assert gu.ps_quote("plain") == "'plain'"


@pytest.mark.parametrize(
    "name",
    ["nginx; rm -rf /", "$(whoami)", "a`b`", "a\nb", "", "a|b", "a&b", "a>b", "'; shutdown --"],
)
def test_service_names_that_could_reach_a_shell_are_refused(executor, ctx, name):
    with pytest.raises(gu.GuestError):
        gu.checked(name, gu.SERVICE_NAME, "service name")
    result = executor.apply(ctx, step("guest.service_restart", service=name))
    assert result.ok is False
    assert "not a name" in result.error


def test_a_windows_service_name_with_spaces_is_allowed_and_quoted():
    dialect = gu.WindowsDialect()
    name = gu.checked("SQL Server (MSSQLSERVER)", gu.SERVICE_NAME, "service name")
    assert dialect.service_restart(name) == (
        "Restart-Service -Name 'SQL Server (MSSQLSERVER)' -Force"
    )


def test_no_command_the_linux_dialect_builds_carries_a_metacharacter_from_a_parameter():
    dialect = gu.LinuxDialect()
    name = "weird.name-1_a@b"
    for command in (
        dialect.service_restart(name),
        dialect.service_stop(name),
        dialect.service_start(name),
        dialect.service_state(name),
    ):
        assert name in command
        assert not re.search(r"[;&|><`$]", command)


# ---------------------------------------------------------------------------
# services
# ---------------------------------------------------------------------------
def test_service_restart_captures_the_previous_state_and_verifies(executor, ctx, linux_shell):
    result = executor.apply(ctx, step("guest.service_restart", service="nginx"))
    assert result.ok, result.error
    assert result.output["previous_state"] == "active"
    assert result.output["state"] == "active"
    assert "systemctl restart -- nginx" in linux_shell.commands


def test_a_service_that_does_not_come_back_fails_the_step(executor, ctx, linux_shell):
    states = iter(["active\n", "failed\n"])
    linux_shell.set("systemctl show -p ActiveState --value -- nginx", "")
    linux_shell.script["systemctl show -p ActiveState --value -- nginx"] = lambda: (
        0,
        next(states),
        "",
    )
    result = executor.apply(ctx, step("guest.service_restart", service="nginx"))
    assert result.ok is False
    assert "expected active" in result.error


def test_restarting_a_missing_service_is_refused(executor, ctx, linux_shell):
    linux_shell.set("systemctl show -p ActiveState --value -- ghost", "missing\n")
    result = executor.apply(ctx, step("guest.service_restart", service="ghost"))
    assert result.ok is False
    assert "no service named" in result.error


def test_service_restart_rollback_starts_a_service_that_had_been_running(
    executor, ctx, linux_shell
):
    result = executor.apply(ctx, step("guest.service_restart", service="nginx"))
    linux_shell.commands.clear()
    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok, undone.error
    assert linux_shell.commands == ["systemctl start -- nginx"]


def test_service_restart_rollback_stops_a_service_that_had_been_stopped(executor, ctx, linux_shell):
    linux_shell.set("systemctl show -p ActiveState --value -- worker", "inactive\n")
    result = executor.apply(ctx, step("guest.service_restart", service="worker"))
    assert result.ok is False  # a restart of an inactive unit must end active
    linux_shell.script["systemctl show -p ActiveState --value -- worker"] = iter
    states = iter(["inactive\n", "active\n"])
    linux_shell.script["systemctl show -p ActiveState --value -- worker"] = lambda: (
        0,
        next(states),
        "",
    )
    result = executor.apply(ctx, step("guest.service_restart", service="worker"))
    assert result.ok, result.error
    linux_shell.commands.clear()
    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok, undone.error
    assert linux_shell.commands == ["systemctl stop -- worker"]


def test_service_stop_and_its_rollback(executor, ctx, linux_shell):
    states = iter(["active\n", "inactive\n"])
    linux_shell.script["systemctl show -p ActiveState --value -- nginx"] = lambda: (
        0,
        next(states),
        "",
    )
    result = executor.apply(ctx, step("guest.service_stop", service="nginx"))
    assert result.ok, result.error
    assert "systemctl stop -- nginx" in linux_shell.commands
    linux_shell.commands.clear()
    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok, undone.error
    assert linux_shell.commands == ["systemctl start -- nginx"]


def test_service_start_and_its_rollback(executor, ctx, linux_shell):
    states = iter(["inactive\n", "active\n"])
    linux_shell.script["systemctl show -p ActiveState --value -- nginx"] = lambda: (
        0,
        next(states),
        "",
    )
    result = executor.apply(ctx, step("guest.service_start", service="nginx"))
    assert result.ok, result.error
    assert "systemctl start -- nginx" in linux_shell.commands
    linux_shell.commands.clear()
    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok
    assert linux_shell.commands == ["systemctl stop -- nginx"]


def test_a_failing_systemctl_becomes_a_failed_step(executor, ctx, linux_shell):
    linux_shell.set("systemctl restart -- nginx", "", rc=5, stderr="Job for nginx.service failed")
    result = executor.apply(ctx, step("guest.service_restart", service="nginx"))
    assert result.ok is False
    assert "exited 5" in result.error


def test_windows_service_restart_uses_powershell(executor, win_ctx, windows_shell):
    result = executor.apply(win_ctx, step("guest.service_restart", service="W3SVC"))
    assert result.ok, result.error
    assert result.output["previous_state"] == "Running"
    assert "Restart-Service -Name 'W3SVC' -Force" in windows_shell.commands
    (undone,) = executor.rollback(win_ctx, [result])
    assert undone.ok
    assert windows_shell.commands[-1] == "Start-Service -Name 'W3SVC'"


# ---------------------------------------------------------------------------
# package updates
# ---------------------------------------------------------------------------
def _apt_shell(linux_shell: FakeGuest) -> FakeGuest:
    linux_shell.set(gu.LinuxDialect().detect_manager(), "apt\n")
    linux_shell.set("apt-get --simulate --quiet upgrade", APT_SIMULATE)
    linux_shell.set(
        "dpkg-query -W -f='${Package} ${Version}\\n' -- libssl3 curl",
        "libssl3 3.0.11-1\ncurl 7.88.1-10\n",
    )
    return linux_shell


def test_package_update_dry_run_lists_the_pending_upgrades(executor, ctx, linux_shell):
    _apt_shell(linux_shell)
    result = executor.dry_run(ctx, [step("guest.package_update")])
    assert result.ok, result.blockers
    entry = result.diff["steps"][0]
    assert entry["manager"] == "apt"
    assert [p["name"] for p in entry["pending"]] == ["libssl3", "curl"]
    assert entry["pending"][0]["current"] == "3.0.11-1"
    assert entry["pending"][0]["available"] == "3.0.13-1"
    assert any("no automatic rollback" in w for w in result.warnings)
    # a dry run only simulates
    assert "DEBIAN_FRONTEND=noninteractive apt-get --yes --quiet upgrade" not in (
        linux_shell.commands
    )


def test_package_update_reports_what_changed(executor, ctx, linux_shell):
    _apt_shell(linux_shell)
    versions = iter(["libssl3 3.0.11-1\ncurl 7.88.1-10\n", "libssl3 3.0.13-1\ncurl 7.88.1-10\n"])
    linux_shell.script["dpkg-query -W -f='${Package} ${Version}\\n' -- libssl3 curl"] = lambda: (
        0,
        next(versions),
        "",
    )
    result = executor.apply(ctx, step("guest.package_update"))
    assert result.ok, result.error
    assert result.output["changed"] == [{"name": "libssl3", "from": "3.0.11-1", "to": "3.0.13-1"}]
    assert result.output["previous_versions"] == {"libssl3": "3.0.11-1", "curl": "7.88.1-10"}
    assert "DEBIAN_FRONTEND=noninteractive apt-get --yes --quiet upgrade" in linux_shell.commands


def test_a_package_update_cannot_be_rolled_back(executor, ctx, linux_shell):
    _apt_shell(linux_shell)
    versions = iter(["libssl3 3.0.11-1\ncurl 7.88.1-10\n", "libssl3 3.0.13-1\ncurl 7.88.1-10\n"])
    linux_shell.script["dpkg-query -W -f='${Package} ${Version}\\n' -- libssl3 curl"] = lambda: (
        0,
        next(versions),
        "",
    )
    result = executor.apply(ctx, step("guest.package_update"))
    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok is False
    assert "not rolled back automatically" in undone.error
    assert undone.output["previous_versions"]["libssl3"] == "3.0.11-1"


def test_an_upgrade_with_nothing_pending_needs_no_rollback(executor, ctx, linux_shell):
    linux_shell.set(gu.LinuxDialect().detect_manager(), "apt\n")
    linux_shell.set("apt-get --simulate --quiet upgrade", "Calculating upgrade...\n")
    result = executor.apply(ctx, step("guest.package_update"))
    assert result.ok, result.error
    assert result.output["changed"] == []
    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok
    assert "nothing to undo" in undone.output["undo"]


def test_dnf_check_update_exits_100_when_there_is_work(executor, ctx, linux_shell):
    linux_shell.set(gu.LinuxDialect().detect_manager(), "dnf\n")
    linux_shell.set("dnf --quiet check-update", DNF_CHECK_UPDATE, rc=100)
    linux_shell.set(
        "rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE}\\n' -- curl openssl-libs",
        "curl 7.76.1-26.el9\nopenssl-libs 3.0.7-24.el9\n",
    )
    result = executor.dry_run(ctx, [step("guest.package_update")])
    assert result.ok, result.blockers
    assert [p["name"] for p in result.diff["steps"][0]["pending"]] == ["curl", "openssl-libs"]


def test_a_guest_without_a_package_manager_is_a_blocker(executor, ctx, linux_shell):
    linux_shell.set(gu.LinuxDialect().detect_manager(), "unknown\n")
    result = executor.dry_run(ctx, [step("guest.package_update")])
    assert result.ok is False
    assert any("package manager" in b for b in result.blockers)


def test_winget_upgrades_are_parsed(executor, win_ctx, windows_shell):
    dialect = gu.WindowsDialect()
    windows_shell.set(dialect.detect_manager(), "winget\n")
    windows_shell.set("winget upgrade --accept-source-agreements", WINGET_UPGRADE)
    windows_shell.set("winget list --accept-source-agreements", WINGET_LIST)
    result = executor.dry_run(win_ctx, [step("guest.package_update")])
    assert result.ok, result.blockers
    pending = result.diff["steps"][0]["pending"]
    assert [p["name"] for p in pending] == ["Git.Git", "7zip.7zip"]
    assert pending[0]["available"] == "2.44.0"


# ---------------------------------------------------------------------------
# reboot
# ---------------------------------------------------------------------------
def test_reboot_without_a_confirmed_window_is_refused(executor, ctx, linux_shell):
    result = executor.apply(ctx, step("guest.reboot"))
    assert result.ok is False
    assert "window_confirmed" in result.error
    assert "shutdown -r +1" not in linux_shell.commands

    dry = executor.dry_run(ctx, [step("guest.reboot")])
    assert dry.ok is False
    assert any("Tier 2" in b for b in dry.blockers)


def test_reboot_with_a_confirmed_window_runs(executor, ctx, linux_shell):
    result = executor.apply(ctx, step("guest.reboot", window_confirmed=True))
    assert result.ok, result.error
    assert linux_shell.commands[-1] == "shutdown -r +1"
    assert result.output["previous_uptime_seconds"] == pytest.approx(123456.78)


def test_a_dropped_session_after_the_reboot_command_is_not_a_failure(executor, ctx, linux_shell):
    linux_shell.script["shutdown -r +1"] = ConnectionResetError("Socket is closed")
    result = executor.apply(ctx, step("guest.reboot", window_confirmed=True))
    assert result.ok, result.error
    assert "session dropped" in result.output["reboot"]


def test_a_permission_error_on_reboot_is_still_a_failure(executor, ctx, linux_shell):
    linux_shell.script["shutdown -r +1"] = gu.GuestError("Permission denied")
    result = executor.apply(ctx, step("guest.reboot", window_confirmed=True))
    assert result.ok is False
    assert "Permission denied" in result.error


def test_a_reboot_cannot_be_undone(executor, ctx):
    result = executor.apply(ctx, step("guest.reboot", window_confirmed=True))
    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok is False
    assert "cannot be undone" in undone.error


def test_windows_reboot_uses_restart_computer(executor, win_ctx, windows_shell):
    result = executor.apply(win_ctx, step("guest.reboot", window_confirmed=True))
    assert result.ok, result.error
    assert windows_shell.commands[-1] == "Restart-Computer -Force"


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("check", "expected"),
    [
        ("service nginx active", True),
        ("service nginx inactive", False),
        ("port 443 listening", True),
        ("port 8080 listening", False),
        ("uptime < 10m", False),
        ("uptime < 2d", True),
        ("uptime > 10m", True),
        ("uptime < 200000s", True),
    ],
)
def test_the_linux_check_grammar(executor, ctx, check, expected):
    (result,) = executor.post_check(ctx, [check])
    assert result.ok is expected, result.detail


def test_the_windows_check_grammar(executor, win_ctx, windows_shell):
    dialect = gu.WindowsDialect()
    windows_shell.set(dialect.uptime(), "300\n")
    windows_shell.set(dialect.listening(443), "listening\n")
    windows_shell.set(dialect.listening(8080), "no\n")
    results = executor.post_check(
        win_ctx,
        ["service W3SVC active", "port 443 listening", "port 8080 listening", "uptime < 10m"],
    )
    assert [r.ok for r in results] == [True, True, False, True]


def test_an_unknown_check_fails_closed(executor, ctx):
    (result,) = executor.pre_check(ctx, ["the guest feels fine"])
    assert result.ok is False
    assert "unknown check" in result.detail


def test_a_check_against_a_dead_guest_fails_rather_than_raising(executor, ctx, linux_shell):
    linux_shell.script["cat /proc/uptime"] = ConnectionRefusedError("no route to host")
    (result,) = executor.pre_check(ctx, ["uptime < 10m"])
    assert result.ok is False
    assert "ConnectionRefusedError" in result.detail


def test_a_guest_that_reports_no_uptime_fails_the_check(executor, ctx, linux_shell):
    linux_shell.set("cat /proc/uptime", "")
    (result,) = executor.post_check(ctx, ["uptime < 10m"])
    assert result.ok is False
    assert "no uptime" in result.detail


def test_a_check_with_an_unsafe_service_name_fails_rather_than_running(executor, ctx, linux_shell):
    (result,) = executor.pre_check(ctx, ["service nginx;reboot active"])
    assert result.ok is False
    assert not any("reboot" in c for c in linux_shell.commands)


# ---------------------------------------------------------------------------
# dry run and safety
# ---------------------------------------------------------------------------
def test_dry_run_reports_the_intended_commands(executor, ctx, linux_shell):
    result = executor.dry_run(ctx, [step("guest.service_restart", service="nginx")])
    assert result.ok, result.blockers
    entry = result.diff["steps"][0]
    assert entry["commands"] == ["systemctl restart -- nginx"]
    assert entry["before"] == {"state": "active"}
    assert entry["after"] == {"state": "active"}
    assert result.diff["dialect"] == "linux"
    assert "systemctl restart -- nginx" not in linux_shell.commands


def test_dry_run_blocks_a_missing_service(executor, ctx, linux_shell):
    linux_shell.set("systemctl show -p ActiveState --value -- ghost", "missing\n")
    result = executor.dry_run(ctx, [step("guest.service_restart", service="ghost")])
    assert result.ok is False
    assert any("no service named" in b for b in result.blockers)


def test_dry_run_of_an_unknown_action_is_a_blocker(executor, ctx):
    result = executor.dry_run(ctx, [step("guest.disk_grow", mount="/var")])
    assert result.ok is False
    assert any("not a guest action" in b for b in result.blockers)


def test_a_frozen_context_refuses_to_write(executor, linux_shell):
    frozen = ExecutionContext(plan_id="p", device=LINUX, credential=RW, frozen=True)
    result = executor.apply(frozen, step("guest.service_restart", service="nginx"))
    assert result.ok is False
    assert "frozen" in result.error
    assert linux_shell.commands == []


def test_apply_refuses_a_dry_run_context(executor, linux_shell):
    probe = ExecutionContext(plan_id="p", device=LINUX, credential=RW, dry_run=True)
    assert executor.apply(probe, step("guest.service_restart", service="nginx")).ok is False
    assert linux_shell.commands == []


def test_rollback_runs_in_reverse_and_skips_failed_steps(executor, ctx, linux_shell):
    first = executor.apply(ctx, step("guest.service_restart", service="nginx"))
    linux_shell.set("systemctl show -p ActiveState --value -- ghost", "missing\n")
    failed = executor.apply(ctx, step("guest.service_restart", service="ghost"))
    linux_shell.set("systemctl show -p ActiveState --value -- redis", "active\n")
    second = executor.apply(ctx, step("guest.service_restart", service="redis"))
    undone = executor.rollback(ctx, [first, failed, second])
    assert [u.output["service"] for u in undone] == ["redis", "nginx"]


def test_no_credential_material_reaches_any_output(executor, ctx, linux_shell):
    _apt_shell(linux_shell)
    results = [
        executor.apply(ctx, step("guest.service_restart", service="nginx")),
        executor.apply(ctx, step("guest.package_update")),
        executor.apply(ctx, step("guest.reboot", window_confirmed=True)),
    ]
    results.extend(executor.rollback(ctx, results))
    dry = executor.dry_run(ctx, [step("guest.service_stop", service="nginx")])
    blob = strings([r.model_dump(mode="json") for r in results]) + strings(
        dry.model_dump(mode="json")
    )
    assert "guest-password-value" not in blob
    assert "/keys/rw.pem" not in blob
    assert "infra-rw" not in blob


def test_the_recorded_commands_are_the_ones_that_ran(executor, ctx, linux_shell):
    result = executor.apply(ctx, step("guest.service_restart", service="nginx"))
    assert result.output["commands"] == ["systemctl restart -- nginx"]


def test_step_output_is_json_serialisable(executor, ctx, linux_shell):
    _apt_shell(linux_shell)
    result = executor.apply(ctx, step("guest.package_update"))
    json.dumps(result.model_dump(mode="json"))


# ---------------------------------------------------------------------------
# dialect parsers
# ---------------------------------------------------------------------------
def test_linux_parsers():
    dialect = gu.LinuxDialect()
    assert dialect.parse_service_state("active\n") == "active"
    assert dialect.parse_service_state("") == "unknown"
    assert dialect.parse_uptime("1234.5 999.0") == 1234.5
    assert dialect.parse_uptime("nonsense") is None
    assert dialect.parse_listening(22, "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*") is True
    assert dialect.parse_listening(23, "LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*") is False
    assert dialect.parse_versions("curl 7.88\nlibssl3 3.0\n") == {"curl": "7.88", "libssl3": "3.0"}


def test_windows_parsers():
    dialect = gu.WindowsDialect()
    assert dialect.parse_service_state("Running\r\n") == "Running"
    assert dialect.parse_uptime("300\n") == 300.0
    assert dialect.parse_listening(443, "listening") is True
    assert dialect.parse_versions(WINGET_LIST) == {"Git.Git": "2.44.0", "7zip.7zip": "24.05"}


def test_a_command_result_reports_the_failing_command_without_its_arguments():
    result = gu.CommandResult(command="systemctl restart -- nginx", rc=5, stderr="Job failed")
    with pytest.raises(gu.GuestError) as caught:
        result.check()
    assert "systemctl exited 5" in str(caught.value)


def test_a_restart_that_left_the_unit_failed_is_still_rolled_back(executor, ctx, linux_shell):
    """The unit was restarted; that it ended up 'failed' does not undo the restart."""
    states = iter(["active\n", "failed\n"])
    linux_shell.script["systemctl show -p ActiveState --value -- nginx"] = lambda: (
        0,
        next(states),
        "",
    )
    result = executor.apply(ctx, step("guest.service_restart", service="nginx"))
    assert result.ok is False
    assert executor.partially_applied(result) is True

    linux_shell.commands.clear()
    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok, undone.error
    assert linux_shell.commands == ["systemctl start -- nginx"]


def test_a_step_that_never_reached_the_service_is_skipped(executor, ctx, linux_shell):
    linux_shell.set("systemctl show -p ActiveState --value -- ghost", "missing\n")
    result = executor.apply(ctx, step("guest.service_restart", service="ghost"))
    assert result.ok is False
    assert executor.partially_applied(result) is False
    assert executor.rollback(ctx, [result]) == []
