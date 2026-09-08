"""The guest credential probe: identity, privilege and the warnings it raises.

The probe is what stands between the owner and a collector holding root on
every VM, so the tests are mostly about the warnings. Both transports are
replaced by a fake runner; nothing connects to anything.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from infra_agent.collectors.guest import (
    HOSTNAME_COMMAND,
    KERNEL_COMMAND,
    OS_RELEASE_COMMAND,
    SUDO_TEST_COMMAND,
    WHOAMI_COMMAND,
    CommandResult,
)
from infra_agent.models.common import Credential, DeviceKind, SeedDevice
from infra_agent.onboarding.accounts import (
    WINDOWS_READ_GROUPS,
    account_commands,
    sudoers_line,
)
from infra_agent.onboarding.probes import get_probe
from infra_agent.onboarding.probes.guest import (
    WHOAMI_NAME_COMMAND,
    WINDOWS_IDENTITY,
    GuestProbe,
    linux_result,
    windows_result,
)

FIXTURES = Path(__file__).parent / "fixtures" / "guest" / "linux"


class FakeRunner:
    def __init__(self, answers: dict[str, CommandResult | str]) -> None:
        self.answers = answers
        self.commands: list[str] = []
        self.closed = False

    def run(self, command: str) -> CommandResult:
        self.commands.append(command)
        answer = self.answers.get(command)
        if answer is None:
            return CommandResult(command=command, status=127, stderr="command not found")
        if isinstance(answer, CommandResult):
            return CommandResult(
                command=command, status=answer.status, stdout=answer.stdout, stderr=answer.stderr
            )
        return CommandResult(command=command, status=0, stdout=str(answer))

    def close(self) -> None:
        self.closed = True


def linux_device(name: str = "web-01") -> SeedDevice:
    return SeedDevice(
        name=name, kind=DeviceKind.guest_linux, mgmt_ip="10.20.0.11", credential_ref=name
    )


def windows_device(port: int | None = None) -> SeedDevice:
    return SeedDevice(
        name="app-win-01",
        kind=DeviceKind.guest_windows,
        mgmt_ip="10.20.0.21",
        credential_ref="app-win-01",
        port=port,
    )


def linux_answers(uid: str = "1001", sudo: bool = True) -> dict[str, CommandResult | str]:
    answers: dict[str, CommandResult | str] = {
        WHOAMI_COMMAND: f"{uid}\n",
        WHOAMI_NAME_COMMAND: "infra-ro\n" if uid != "0" else "root\n",
        HOSTNAME_COMMAND: "web-01\n",
        KERNEL_COMMAND: "Linux 5.15.0-91-generic x86_64\n",
        OS_RELEASE_COMMAND: (FIXTURES / "os-release.txt").read_text(),
    }
    answers[SUDO_TEST_COMMAND] = (
        ""
        if sudo
        else CommandResult(
            command=SUDO_TEST_COMMAND, status=1, stderr="sudo: a password is required"
        )
    )
    return answers


def probe_linux(answers: dict[str, CommandResult | str], device: SeedDevice | None = None):
    runner = FakeRunner(answers)
    probe = GuestProbe()
    probe.ssh_runner = lambda device, cred: runner  # type: ignore[method-assign]
    result = probe.probe(device or linux_device(), Credential(username="infra-ro"))
    return result, runner


# --------------------------------------------------------------------------
# registration
# --------------------------------------------------------------------------
def test_both_guest_kinds_resolve_to_the_guest_probe():
    assert isinstance(get_probe(DeviceKind.guest_linux), GuestProbe)
    assert isinstance(get_probe(DeviceKind.guest_windows), GuestProbe)


# --------------------------------------------------------------------------
# linux
# --------------------------------------------------------------------------
def test_an_unprivileged_account_with_sudo_is_what_the_collector_wants():
    result, runner = probe_linux(linux_answers())

    assert result.ok is True
    assert result.identity["hostname"] == "web-01"
    assert result.identity["os"] == "Ubuntu 22.04.4 LTS"
    assert result.identity["os_id"] == "ubuntu"
    assert result.identity["kernel"] == "Linux 5.15.0-91-generic"
    assert result.identity["user"] == "infra-ro"
    assert result.privilege == "user+sudo"
    assert result.read_only is True
    assert result.warnings == []
    assert runner.closed is True


def test_a_root_credential_is_accepted_but_warned_about():
    """A collector holding root on every VM is a standing risk nobody needs."""
    result, _runner = probe_linux(linux_answers(uid="0"))

    assert result.ok is True
    assert result.privilege == "root"
    assert result.read_only is False
    assert any("root" in warning for warning in result.warnings)
    assert any("infra onboard accounts web-01" in warning for warning in result.warnings)


def test_no_passwordless_sudo_warns_about_the_edges_the_graph_will_lose():
    result, _runner = probe_linux(linux_answers(sudo=False))

    assert result.privilege == "user"
    assert any("application layer of the graph" in w for w in result.warnings)


def test_an_account_that_cannot_run_a_command_is_a_failed_probe():
    answers = linux_answers()
    answers[WHOAMI_COMMAND] = CommandResult(
        command=WHOAMI_COMMAND, status=1, stderr="This account is currently not available."
    )
    result, _runner = probe_linux(answers)

    assert result.ok is False
    assert "cannot run commands" in str(result.error)


def test_an_unreadable_os_release_is_a_warning_not_a_failure():
    answers = linux_answers()
    answers.pop(OS_RELEASE_COMMAND)
    result, _runner = probe_linux(answers)

    assert result.ok is True
    assert any("os-release" in warning for warning in result.warnings)


def test_a_transport_failure_is_reported_without_the_credential():
    probe = GuestProbe()

    def explode(device, cred):
        raise OSError("[Errno 113] No route to host")

    probe.ssh_runner = explode  # type: ignore[method-assign]
    result = probe.probe(linux_device(), Credential(username="infra-ro", password="hunter2"))

    assert result.ok is False
    assert "No route to host" in str(result.error)
    assert "hunter2" not in str(result.error)
    assert "hunter2" not in json.dumps(result.model_dump(mode="json"))


def test_the_probe_only_runs_read_commands():
    _result, runner = probe_linux(linux_answers())
    assert set(runner.commands) == {
        WHOAMI_COMMAND,
        WHOAMI_NAME_COMMAND,
        HOSTNAME_COMMAND,
        KERNEL_COMMAND,
        OS_RELEASE_COMMAND,
        SUDO_TEST_COMMAND,
    }


# --------------------------------------------------------------------------
# windows
# --------------------------------------------------------------------------
def windows_answer(admin: bool = False) -> CommandResult:
    payload = {
        "User": "LAB\\infra-ro",
        "Admin": admin,
        "Hostname": "APP-WIN-01",
        "Os": "Microsoft Windows Server 2019 Standard",
        "Version": "10.0.17763",
    }
    return CommandResult(command=WINDOWS_IDENTITY, status=0, stdout=json.dumps(payload))


def test_a_windows_remote_management_user_is_what_the_collector_wants():
    result = windows_result(windows_device(), windows_answer())

    assert result.ok is True
    assert result.identity["hostname"] == "APP-WIN-01"
    assert result.identity["os"] == "Microsoft Windows Server 2019 Standard"
    assert result.privilege == "remote-management-user"
    assert result.read_only is True
    assert result.warnings == []


def test_a_windows_administrator_is_warned_about():
    result = windows_result(windows_device(), windows_answer(admin=True))

    assert result.privilege == "administrator"
    assert result.read_only is False
    assert any("local administrator" in warning for warning in result.warnings)


def test_clear_text_winrm_is_warned_about():
    result = windows_result(windows_device(port=5985), windows_answer())
    assert any("clear text" in warning for warning in result.warnings)


def test_a_winrm_failure_carries_the_status_and_not_the_credential():
    answer = CommandResult(
        command=WINDOWS_IDENTITY, status=5, stderr="Access is denied for user LAB\\infra-ro"
    )
    result = windows_result(windows_device(), answer)

    assert result.ok is False
    assert "WinRM returned 5" in str(result.error)


def test_a_windows_probe_that_returns_nothing_is_a_failure():
    result = windows_result(
        windows_device(), CommandResult(command=WINDOWS_IDENTITY, status=0, stdout="")
    )
    assert result.ok is False


def test_the_windows_probe_runs_one_fixed_read_only_script():
    runner = FakeRunner({WINDOWS_IDENTITY: windows_answer()})
    probe = GuestProbe()
    probe.winrm_runner = lambda device, cred: runner  # type: ignore[method-assign]

    result = probe.probe(windows_device(), Credential(username="LAB\\infra-ro"))

    assert result.ok is True
    assert runner.commands == [WINDOWS_IDENTITY]
    assert "Set-" not in WINDOWS_IDENTITY and "Remove-" not in WINDOWS_IDENTITY


def test_linux_result_is_a_pure_function_of_the_recorded_answers():
    """It is the piece the CLI shows the owner, so it is tested without a runner."""
    recorded = linux_answers()
    answers = {
        role: CommandResult(command=command, status=0, stdout=str(recorded[command]))
        for role, command in (
            ("uid", WHOAMI_COMMAND),
            ("user", WHOAMI_NAME_COMMAND),
            ("hostname", HOSTNAME_COMMAND),
            ("kernel", KERNEL_COMMAND),
            ("os_release", OS_RELEASE_COMMAND),
        )
    }
    answers["sudo"] = CommandResult(command=SUDO_TEST_COMMAND, status=0)
    result = linux_result(linux_device(), answers)

    assert result.privilege == "user+sudo"
    assert result.identity["uid"] == 1001


# --------------------------------------------------------------------------
# account templates
# --------------------------------------------------------------------------
def test_the_sudoers_allowlist_is_generated_from_the_collector_commands():
    """The file on the guest and the commands the collector elevates are one list."""
    from infra_agent.collectors.guest import SUDO_COMMANDS

    lines = "\n".join(sudoers_line("infra-ro"))

    for command in SUDO_COMMANDS:
        binary, _, arguments = command.partition(" ")
        assert arguments.replace("'", "") in lines, command
        assert f"/{binary} " in lines
    assert "infra-ro ALL=(root) NOPASSWD: INFRA_READ" in lines
    assert "ALL=(ALL)" not in lines and "NOPASSWD: ALL" not in lines
    # sudo matches the argv the shell already expanded, so the collector's
    # shell quoting must not survive into the sudoers file
    assert "'" not in lines
    assert "-name *.pem" in lines


def test_the_linux_guest_account_is_unprivileged_and_key_only():
    commands = "\n".join(account_commands(DeviceKind.guest_linux, "infra-ro", "pw", "10.10.10.50"))

    assert "useradd --system" in commands
    assert 'from="10.10.10.50"' in commands  # the key is pinned to mgmt-01
    assert "no-pty" in commands
    assert "visudo -cf /etc/sudoers.d/infra-agent" in commands
    assert "usermod -aG sudo" not in commands
    assert "NOPASSWD: ALL" not in commands


def test_the_windows_guest_account_is_group_membership_not_administrator():
    commands = "\n".join(
        account_commands(DeviceKind.guest_windows, "infra-ro", "pw", "10.10.10.50")
    )

    for group in WINDOWS_READ_GROUPS:
        assert f'Add-LocalGroupMember -Group "{group}"' in commands
    assert 'Add-LocalGroupMember -Group "Administrators"' not in commands
    assert "-Transport HTTPS" in commands
    assert "AllowUnencrypted -Value $false" in commands
    assert "LocalPort 5986" in commands
    assert "-RemoteAddress 10.10.10.50" in commands


@pytest.mark.parametrize("kind", [DeviceKind.guest_linux, DeviceKind.guest_windows])
def test_account_templates_never_grant_a_shell_login_or_a_wildcard(kind: DeviceKind):
    commands = "\n".join(account_commands(kind, "infra-ro", "s3cret", "10.10.10.50"))
    assert "ALL=(ALL:ALL) ALL" not in commands
    assert "Domain Admins" not in commands
