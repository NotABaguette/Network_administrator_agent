"""Guest collector tests.

Nothing here opens a socket. A fake command runner answers the collector's fixed
templates with the recorded output under `tests/fixtures/guest/`, so the parsers
are tested against what `ss`, `systemctl`, `dnf` and `openssl` really print,
including the edge cases the estate will actually hit: a guest with no `ss`, a
`dnf check-update` that exits 100 because updates are waiting, a certificate
with no subjectAltName, and an unprivileged account with no sudo.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
import yaml
from prometheus_client import REGISTRY

from infra_agent.collectors import guest as guest_module
from infra_agent.collectors.base import COLLECTORS, run_collector
from infra_agent.collectors.guest import (
    APT_UPGRADABLE_COMMAND,
    CERT_FIND_COMMAND,
    CERT_READ_TEMPLATE,
    CPU_COMMAND,
    DF_COMMAND,
    DNF_CHECK_COMMAND,
    DPKG_COMMAND,
    HOSTNAME_COMMAND,
    KERNEL_COMMAND,
    MEMINFO_COMMAND,
    NETSTAT_ESTABLISHED_COMMAND,
    NETSTAT_TCP_LISTEN_COMMAND,
    NETSTAT_UDP_LISTEN_COMMAND,
    OS_RELEASE_COMMAND,
    PS_CERTIFICATES,
    PS_COMPUTER_INFO,
    PS_ESTABLISHED,
    PS_HOTFIX,
    PS_LISTENERS,
    PS_LOGICAL_DISKS,
    PS_PENDING_UPDATES,
    PS_PROGRAMS,
    PS_SERVICES,
    PS_VOLUMES,
    RPM_COMMAND,
    SS_ESTABLISHED_COMMAND,
    SS_TCP_LISTEN_COMMAND,
    SS_UDP_LISTEN_COMMAND,
    SUDO_COMMANDS,
    SUDO_TEST_COMMAND,
    SYSTEMD_UNIT_FILES_COMMAND,
    SYSTEMD_UNITS_COMMAND,
    TLS_PROBE_TEMPLATE,
    TLS_PROBE_TIMEOUT_SECONDS,
    UPTIME_COMMAND,
    WHOAMI_COMMAND,
    CommandResult,
    GuestLinuxCollector,
    GuestWindowsCollector,
    WinRmRunner,
    collect_linux,
    collect_windows,
    expiring_certificates,
    parse_openssl_x509,
    sudo_refused,
    summarise_connections,
    tagged_service_names,
    tls_probe_targets,
)
from infra_agent.models.common import Credential, DeviceKind, SeedDevice

FIXTURES = Path(__file__).parent / "fixtures" / "guest"
RULES = Path(__file__).resolve().parents[1] / "infra_agent" / "monitoring" / "rules"
NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)


def linux_fixture(name: str) -> str:
    return (FIXTURES / "linux" / f"{name}.txt").read_text()


def windows_fixture(name: str) -> str:
    return (FIXTURES / "windows" / f"{name}.json").read_text()


# --------------------------------------------------------------------------
# the fake guests
# --------------------------------------------------------------------------
class FakeRunner:
    """Answers fixed command templates from recorded output.

    `answers` maps an exact command to a `CommandResult` or to the text of a
    successful one. Anything unanswered is `command not found`, which is what a
    minimal guest does and what the fallbacks have to survive.
    """

    def __init__(self, answers: dict[str, Any], *, missing_ok: bool = True) -> None:
        self.answers = answers
        self.missing_ok = missing_ok
        self.commands: list[str] = []
        self.closed = False

    def run(self, command: str) -> CommandResult:
        self.commands.append(command)
        answer = self.answers.get(command)
        if answer is None:
            for prefix, value in self.answers.items():
                if prefix.endswith("*") and command.startswith(prefix[:-1]):
                    answer = value
                    break
        if answer is None:
            if not self.missing_ok:
                raise AssertionError(f"unexpected command: {command}")
            return CommandResult(
                command=command, status=127, stderr=f"bash: {command.split()[0]}: command not found"
            )
        if isinstance(answer, CommandResult):
            return CommandResult(
                command=command,
                status=answer.status,
                stdout=answer.stdout,
                stderr=answer.stderr,
            )
        return CommandResult(command=command, status=0, stdout=str(answer))

    def close(self) -> None:
        self.closed = True


LETSENCRYPT_CERT = "/etc/letsencrypt/live/app.example.com/cert.pem"


def linux_answers(**overrides: Any) -> dict[str, Any]:
    """A healthy Debian-family guest: nginx, postgres, one expiring certificate."""
    cert_path = LETSENCRYPT_CERT
    answers: dict[str, Any] = {
        WHOAMI_COMMAND: "1001\n",
        OS_RELEASE_COMMAND: linux_fixture("os-release"),
        KERNEL_COMMAND: linux_fixture("uname"),
        HOSTNAME_COMMAND: linux_fixture("hostname"),
        UPTIME_COMMAND: linux_fixture("proc-uptime"),
        CPU_COMMAND: linux_fixture("nproc"),
        MEMINFO_COMMAND: linux_fixture("meminfo"),
        DPKG_COMMAND: linux_fixture("dpkg-query"),
        APT_UPGRADABLE_COMMAND: linux_fixture("apt-upgradable"),
        SYSTEMD_UNITS_COMMAND: linux_fixture("systemctl-units"),
        SYSTEMD_UNIT_FILES_COMMAND: linux_fixture("systemctl-unit-files"),
        f"sudo -n {SS_TCP_LISTEN_COMMAND}": linux_fixture("ss-tcp-listen"),
        f"sudo -n {SS_UDP_LISTEN_COMMAND}": linux_fixture("ss-udp-listen"),
        f"sudo -n {SS_ESTABLISHED_COMMAND}": linux_fixture("ss-established"),
        DF_COMMAND: linux_fixture("df"),
        f"sudo -n {CERT_FIND_COMMAND}": CommandResult(
            command=CERT_FIND_COMMAND, status=1, stdout=linux_fixture("find-certs")
        ),
        # Let's Encrypt keeps `live/` root-only, so this one answers only to sudo
        f"sudo -n {CERT_READ_TEMPLATE.format(path=cert_path)}": linux_fixture("openssl-cert"),
        # ... while /etc/nginx is world-readable and answers unprivileged
        CERT_READ_TEMPLATE.format(path="/etc/nginx/ssl/internal-ca-signed.crt"): (
            linux_fixture("openssl-cert-nosan")
        ),
        TLS_PROBE_TEMPLATE.format(
            host="127.0.0.1", port=443, timeout=TLS_PROBE_TIMEOUT_SECONDS
        ): linux_fixture("openssl-s-client"),
    }
    answers.update(overrides)
    return answers


def windows_answers(**overrides: Any) -> dict[str, Any]:
    answers: dict[str, Any] = {
        PS_COMPUTER_INFO: windows_fixture("computer-info"),
        PS_SERVICES: windows_fixture("services"),
        PS_LISTENERS: windows_fixture("listeners"),
        PS_ESTABLISHED: windows_fixture("established"),
        PS_VOLUMES: windows_fixture("volumes"),
        PS_PROGRAMS: windows_fixture("programs"),
        PS_CERTIFICATES: windows_fixture("certificates"),
        PS_HOTFIX: windows_fixture("hotfix"),
        PS_PENDING_UPDATES: windows_fixture("updates"),
    }
    answers.update(overrides)
    return answers


def linux_device(name: str = "web-01", tags: list[str] | None = None) -> SeedDevice:
    return SeedDevice(
        name=name,
        kind=DeviceKind.guest_linux,
        mgmt_ip="10.20.0.11",
        credential_ref=name,
        tags=tags
        if tags is not None
        else ["vm:web-01", "service:nginx", "service:postgresql", "service:redis"],
    )


def windows_device(name: str = "app-win-01") -> SeedDevice:
    return SeedDevice(
        name=name,
        kind=DeviceKind.guest_windows,
        mgmt_ip="10.20.0.21",
        credential_ref=name,
        tags=["vm:app-win-01", "service:MSSQLSERVER", "service:W3SVC"],
    )


@pytest.fixture
def linux_data() -> dict[str, Any]:
    return collect_linux(FakeRunner(linux_answers()), linux_device(), now=NOW)


@pytest.fixture
def windows_data() -> dict[str, Any]:
    return collect_windows(FakeRunner(windows_answers()), windows_device(), now=NOW)


# --------------------------------------------------------------------------
# registration
# --------------------------------------------------------------------------
def test_both_guest_kinds_are_registered_at_the_declared_interval():
    assert COLLECTORS[DeviceKind.guest_linux] is GuestLinuxCollector
    assert COLLECTORS[DeviceKind.guest_windows] is GuestWindowsCollector
    assert GuestLinuxCollector.name == GuestWindowsCollector.name == "guest"
    assert GuestLinuxCollector.interval_seconds == 900
    assert DeviceKind.guest_linux.platform == DeviceKind.guest_windows.platform == "guest"


def test_the_scheduler_imports_the_guest_collectors():
    """`infra collect` only runs collectors whose module got imported."""
    import inspect

    from infra_agent import scheduler

    assert "guest" in inspect.getsource(scheduler._load_collectors)


# --------------------------------------------------------------------------
# Linux
# --------------------------------------------------------------------------
def test_linux_identity_uptime_cpu_and_memory(linux_data):
    assert linux_data["os"]["id"] == "ubuntu"
    assert linux_data["os"]["version"] == "22.04"
    assert linux_data["os"]["pretty_name"] == "Ubuntu 22.04.4 LTS"
    assert linux_data["os"]["kernel"] == "Linux 5.15.0-91-generic"
    assert linux_data["os"]["arch"] == "x86_64"
    assert linux_data["os"]["hostname"] == "web-01"
    assert linux_data["uptime_seconds"] == pytest.approx(1044231.68)
    assert linux_data["cpu"] == {"count": 4}
    assert linux_data["memory"]["total_bytes"] == 8127252 * 1024
    assert linux_data["memory"]["available_bytes"] == 5218044 * 1024
    assert linux_data["errors"] == {}


def test_linux_packages_and_pending_updates(linux_data):
    names = {row["name"]: row["version"] for row in linux_data["packages"]}
    assert names["nginx"] == "1.18.0-6ubuntu14.4"
    assert names["openssl"] == "3.0.2-0ubuntu1.15"
    assert linux_data["updates"]["pending"] == 3
    assert linux_data["updates"]["source"] == APT_UPGRADABLE_COMMAND
    assert set(linux_data["updates"]["packages"]) == {"libssl3", "nginx", "openssl"}


def test_dnf_check_update_exits_100_when_updates_are_waiting():
    """Exit 100 is `there are updates`, not a failure. Treating it as one would
    report every RHEL-family guest's update count as unknown."""
    answers = linux_answers()
    answers.pop(APT_UPGRADABLE_COMMAND)
    answers.pop(DPKG_COMMAND)
    answers[RPM_COMMAND] = "nginx\t1.20.1-14.el9\nopenssl-libs\t3.0.7-26.el9\n"
    answers[DNF_CHECK_COMMAND] = CommandResult(
        command=DNF_CHECK_COMMAND, status=100, stdout=linux_fixture("dnf-check-update")
    )
    data = collect_linux(FakeRunner(answers), linux_device(), now=NOW)

    assert data["updates"]["pending"] == 3
    assert data["updates"]["source"] == DNF_CHECK_COMMAND
    # The `Obsoleting Packages` report below the list is a different question.
    assert data["updates"]["packages"] == ["kernel", "nginx", "openssl-libs"]
    assert "grub2-tools" not in data["updates"]["packages"]
    assert {row["name"] for row in data["packages"]} == {"nginx", "openssl-libs"}
    assert "updates" not in data["errors"]


def test_dnf_exit_1_is_a_real_failure_and_says_the_count_is_unknown():
    answers = linux_answers()
    answers.pop(APT_UPGRADABLE_COMMAND)
    answers[DNF_CHECK_COMMAND] = CommandResult(
        command=DNF_CHECK_COMMAND, status=1, stderr="Error: Failed to download metadata"
    )
    data = collect_linux(FakeRunner(answers), linux_device(), now=NOW)

    assert data["updates"]["pending"] is None
    assert any("pending updates are unknown" in w for w in data["warnings"])


def test_linux_services_and_the_tagged_ones(linux_data):
    units = {row["name"]: row for row in linux_data["services"]}
    assert units["nginx.service"]["active"] == "failed"
    assert units["nginx.service"]["enabled"] == "enabled"
    assert units["ssh.service"]["sub"] == "running"
    assert units["unattended-upgrades.service"]["active"] == "inactive"

    tagged = {row["service"]: row for row in linux_data["tagged_services"]}
    assert tagged["nginx"]["active"] is False  # the unit is loaded but failed
    assert tagged["nginx"]["unit"] == "nginx.service"
    # the tag is what an operator typed; the unit is the instance they meant
    assert tagged["postgresql"]["unit"] == "postgresql@14-main.service"
    assert tagged["postgresql"]["active"] is True
    assert tagged["redis"]["found"] is False  # tagged, but the unit is not there
    assert tagged["redis"]["active"] is False


def test_linux_listeners_carry_the_owning_process(linux_data):
    listeners = {(row["proto"], row["port"]): row for row in linux_data["listeners"]}
    assert listeners[("tcp", 443)]["process"] == "nginx"
    assert listeners[("tcp", 443)]["address"] == "0.0.0.0"
    assert listeners[("tcp", 5432)]["address"] == "127.0.0.1"
    assert listeners[("tcp", 5432)]["process"] == "postgres"
    assert listeners[("tcp", 9100)]["address"] == "::"
    assert listeners[("udp", 68)]["process"] == "dhclient"
    assert listeners[("tcp", 22)]["pid"] == 901


def test_established_connections_are_outbound_grouped_dependencies(linux_data):
    rows = {(row["remote_ip"], row["remote_port"]): row for row in linux_data["connections"]}
    # two sockets to the same database are one dependency
    assert rows[("10.20.0.31", 5432)]["connections"] == 2
    assert rows[("10.20.0.31", 5432)]["process"] == "gunicorn"
    assert rows[("10.20.0.31", 5432)]["local_port"] == 51234
    assert rows[("10.10.10.50", 8086)]["process"] == "telegraf"
    assert rows[("203.0.113.44", 443)]["process"] == "curl"
    # a socket whose local port is one we listen on is somebody talking to us
    assert ("10.10.10.50", 53318) not in rows


def test_inbound_connections_are_not_dependencies():
    listening = {443}
    rows = summarise_connections(
        [
            {"local_port": 443, "remote_ip": "10.0.0.9", "remote_port": 5111, "process": "nginx"},
            {"local_port": 40001, "remote_ip": "10.0.0.5", "remote_port": 636, "process": "sssd"},
        ],
        listening,
    )
    assert [row["remote_port"] for row in rows] == [636]


def test_linux_disks_are_real_filesystems_only(linux_data):
    mounts = {row["mount"]: row for row in linux_data["disks"]}
    assert set(mounts) == {"/", "/boot/efi", "/var/lib/postgresql"}
    assert mounts["/"]["total_bytes"] == 61118592 * 1024
    assert mounts["/"]["free_bytes"] == 9052160 * 1024
    assert mounts["/var/lib/postgresql"]["free_ratio"] == pytest.approx(0.0548, abs=0.001)
    assert "/run" not in mounts and "/dev" not in mounts


def test_linux_certificates_from_files_and_from_the_live_listener(linux_data):
    by_source = {row["source"]: row for row in linux_data["certificates"]}
    lets_encrypt = by_source["/etc/letsencrypt/live/app.example.com/cert.pem"]
    assert lets_encrypt["subject"] == "CN=app.example.com"
    assert lets_encrypt["issuer"] == "C=US, O=Let's Encrypt, CN=R3"
    assert lets_encrypt["not_after"] == "2026-11-01T12:00:00+00:00"
    assert lets_encrypt["sans"] == ["app.example.com", "www.app.example.com"]
    assert lets_encrypt["days_to_expiry"] == 56
    assert lets_encrypt["kind"] == "file"

    served = by_source["127.0.0.1:443"]
    assert served["kind"] == "listener"
    assert served["port"] == 443 and served["process"] == "nginx"


def test_a_world_readable_certificate_is_read_without_sudo():
    """The sudoers allowlist can only name the paths it knows about, so a
    certificate outside that glob must not be lost to a sudo refusal."""
    runner = FakeRunner(linux_answers())
    data = collect_linux(runner, linux_device(), now=NOW)

    reads = [c for c in runner.commands if "openssl x509" in c]
    nginx_read = CERT_READ_TEMPLATE.format(path="/etc/nginx/ssl/internal-ca-signed.crt")
    assert nginx_read in reads  # tried unprivileged first, and answered
    assert f"sudo -n {nginx_read}" not in reads  # so it never escalated
    assert f"sudo -n {CERT_READ_TEMPLATE.format(path=LETSENCRYPT_CERT)}" in reads
    assert {row["source"] for row in data["certificates"]} == {
        LETSENCRYPT_CERT,
        "/etc/nginx/ssl/internal-ca-signed.crt",
        "127.0.0.1:443",
    }


def test_a_certificate_without_a_san_is_still_recorded(linux_data):
    """A certificate with no subjectAltName is what browsers reject; the run
    must record it rather than treat the missing extension as a parse failure."""
    legacy = next(
        row
        for row in linux_data["certificates"]
        if row["source"].endswith("internal-ca-signed.crt")
    )
    assert legacy["sans"] == []
    assert legacy["subject"] == "C=GB, O=Example Ltd, CN=legacy.internal"
    assert legacy["not_after"] == "2026-09-20T09:30:00+00:00"
    assert legacy["days_to_expiry"] == 13


def test_openssl_output_without_any_extension_block():
    parsed = parse_openssl_x509(linux_fixture("openssl-cert-nosan"))
    assert parsed is not None and parsed["sans"] == []
    assert parse_openssl_x509("unable to load certificate") is None


def test_only_tls_worthy_ports_are_probed(linux_data):
    """Handshaking with sshd or postgres hangs for five seconds each."""
    runner = FakeRunner(linux_answers())
    collect_linux(runner, linux_device(), now=NOW)
    probes = [c for c in runner.commands if "s_client" in c]
    assert probes and all("127.0.0.1:443" in c for c in probes)
    assert not any(":22" in c or ":5432" in c for c in probes)


def test_a_guest_without_ss_falls_back_to_netstat():
    """Minimal images ship net-tools and no iproute2."""
    answers = linux_answers()
    for command in (SS_TCP_LISTEN_COMMAND, SS_UDP_LISTEN_COMMAND, SS_ESTABLISHED_COMMAND):
        answers.pop(f"sudo -n {command}")
    answers[f"sudo -n {NETSTAT_TCP_LISTEN_COMMAND}"] = linux_fixture("netstat-tcp-listen")
    answers[f"sudo -n {NETSTAT_UDP_LISTEN_COMMAND}"] = linux_fixture("netstat-udp-listen")
    answers[f"sudo -n {NETSTAT_ESTABLISHED_COMMAND}"] = linux_fixture("netstat-established")

    data = collect_linux(FakeRunner(answers), linux_device(), now=NOW)

    listeners = {(row["proto"], row["port"]): row for row in data["listeners"]}
    assert listeners[("tcp", 443)]["process"] == "nginx"
    assert listeners[("tcp", 5432)]["address"] == "127.0.0.1"
    assert listeners[("udp", 68)]["process"] == "dhclient"
    assert [(row["remote_ip"], row["remote_port"]) for row in data["connections"]] == [
        ("10.20.0.31", 5432)
    ]
    assert any("`ss`) is not installed" in w for w in data["warnings"])
    assert "listeners" not in data["errors"]


def test_neither_ss_nor_netstat_degrades_with_a_warning_not_an_exception():
    answers = linux_answers()
    for command in (SS_TCP_LISTEN_COMMAND, SS_UDP_LISTEN_COMMAND, SS_ESTABLISHED_COMMAND):
        answers.pop(f"sudo -n {command}")
    data = collect_linux(FakeRunner(answers), linux_device(), now=NOW)

    assert data["listeners"] == []
    assert data["connections"] == []
    assert any("neither" in w for w in data["warnings"])
    assert data["os"]["hostname"] == "web-01"  # the rest of the run survived


def test_without_passwordless_sudo_the_run_degrades_and_says_so():
    """The refusal is learned from the first elevated read and then remembered,
    so exactly one doomed `sudo -n` per binary is spent, not one per command."""
    answers = linux_answers()
    refused = CommandResult(command="", status=1, stderr="sudo: a password is required")
    for command in (SS_TCP_LISTEN_COMMAND, SS_UDP_LISTEN_COMMAND, SS_ESTABLISHED_COMMAND):
        answers[f"sudo -n {command}"] = refused
    answers[f"sudo -n {CERT_FIND_COMMAND}"] = refused
    answers[SS_TCP_LISTEN_COMMAND] = re.sub(
        r"\s+users:.*$", "", linux_fixture("ss-tcp-listen"), flags=re.M
    )
    answers[SS_UDP_LISTEN_COMMAND] = re.sub(
        r"\s+users:.*$", "", linux_fixture("ss-udp-listen"), flags=re.M
    )
    answers[SS_ESTABLISHED_COMMAND] = linux_fixture("ss-established")
    answers[CERT_FIND_COMMAND] = CommandResult(
        command=CERT_FIND_COMMAND, status=1, stdout=linux_fixture("find-certs")
    )
    runner = FakeRunner(answers)
    data = collect_linux(runner, linux_device(), now=NOW)

    elevated = [c for c in runner.commands if c.startswith("sudo -n ")]
    # one doomed attempt for `ss` and one for `find`, then both binaries are
    # remembered as denied; `openssl` is a third binary and is still tried
    assert elevated[:2] == [f"sudo -n {SS_TCP_LISTEN_COMMAND}", f"sudo -n {CERT_FIND_COMMAND}"]
    assert [c for c in elevated if "ss -" in c or " find " in c] == elevated[:2]
    listeners = {row["port"]: row for row in data["listeners"] if row["proto"] == "tcp"}
    assert listeners[443]["process"] is None
    assert data["listeners"] and data["certificates"]  # the run still happened
    assert any("no passwordless sudo" in w for w in data["warnings"])


def test_the_snapshot_records_whether_sudo_actually_worked(linux_data):
    """`privileged` says the account is root; `sudo` says an allowlisted read
    was really elevated, which is what the process names depend on."""
    assert linux_data["privileged"] is False
    assert linux_data["sudo"] is True


def test_sudo_availability_is_never_probed_with_a_command_the_allowlist_refuses():
    """`sudo -n true` is refused by the sudoers file this project generates, so
    probing with it would report "no sudo" on every correctly onboarded guest."""
    assert SUDO_TEST_COMMAND == f"sudo -n {SUDO_COMMANDS[0]}"
    assert "true" not in SUDO_TEST_COMMAND
    runner = FakeRunner(linux_answers())
    collect_linux(runner, linux_device(), now=NOW)
    assert "sudo -n true" not in runner.commands


@pytest.mark.parametrize(
    ("status", "stderr", "refused"),
    [
        (0, "", False),
        (1, "sudo: a password is required", True),
        (1, "Sorry, user infra-ro is not allowed to execute '/usr/bin/id' as root", True),
        (1, "sudo: no tty present and no askpass program specified", True),
        (127, "sudo: ss: command not found", False),  # sudo ran; the binary is gone
        (127, "bash: sudo: command not found", True),  # sudo itself is not installed
        (1, "find: '/etc/httpd': No such file or directory", False),  # the command failed
    ],
)
def test_sudo_refusal_is_told_apart_from_the_command_failing(status, stderr, refused):
    assert sudo_refused(CommandResult(command="x", status=status, stderr=stderr)) is refused


def test_a_binary_missing_from_the_allowlist_does_not_disable_sudo_for_the_others():
    """sudoers matches an absolute path, so a guest without `ss` refuses
    `sudo -n ss ...` while still permitting `sudo -n netstat ...`."""
    answers = linux_answers()
    for command in (SS_TCP_LISTEN_COMMAND, SS_UDP_LISTEN_COMMAND, SS_ESTABLISHED_COMMAND):
        answers.pop(f"sudo -n {command}")
        answers[f"sudo -n {command}"] = CommandResult(
            command=command, status=1, stderr="sudo: a password is required"
        )
    answers[f"sudo -n {NETSTAT_TCP_LISTEN_COMMAND}"] = linux_fixture("netstat-tcp-listen")
    answers[f"sudo -n {NETSTAT_UDP_LISTEN_COMMAND}"] = linux_fixture("netstat-udp-listen")
    answers[f"sudo -n {NETSTAT_ESTABLISHED_COMMAND}"] = linux_fixture("netstat-established")

    runner = FakeRunner(answers)
    data = collect_linux(runner, linux_device(), now=NOW)

    assert f"sudo -n {NETSTAT_TCP_LISTEN_COMMAND}" in runner.commands
    listeners = {row["port"]: row for row in data["listeners"] if row["proto"] == "tcp"}
    assert listeners[443]["process"] == "nginx"  # netstat still ran as root


def test_sudo_is_only_ever_used_for_the_allowlisted_read_commands():
    runner = FakeRunner(linux_answers())
    collect_linux(runner, linux_device(), now=NOW)
    elevated = [
        c.removeprefix("sudo -n ")
        for c in runner.commands
        if c.startswith("sudo -n ") and c != SUDO_TEST_COMMAND
    ]
    assert elevated
    cert_read_prefix = CERT_READ_TEMPLATE.split("{path}")[0]
    for command in elevated:
        assert command in SUDO_COMMANDS or command.startswith(cert_read_prefix), command


def test_the_collector_never_reads_key_material_or_password_hashes():
    runner = FakeRunner(linux_answers())
    data = collect_linux(runner, linux_device(), now=NOW)
    joined = " ".join(runner.commands)
    for forbidden in ("/etc/shadow", "id_rsa", "/root/", "krb5", "ccache", "-out "):
        assert forbidden not in joined
    # key material is excluded in the find itself, so it is never even opened
    assert "-not -name 'privkey*'" in CERT_FIND_COMMAND
    assert "-not -name '*.key'" in CERT_FIND_COMMAND
    assert all("PRIVATE KEY" not in str(row) for row in data["certificates"])


def test_a_broken_section_does_not_lose_the_run():
    answers = linux_answers()
    answers[DF_COMMAND] = CommandResult(command=DF_COMMAND, status=1, stderr="df: cannot read")
    data = collect_linux(FakeRunner(answers), linux_device(), now=NOW)

    assert data["disks"] == []
    assert "df -Pk" in data["errors"]["disks"]
    assert data["listeners"] and data["packages"]


def test_the_collector_closes_the_session_and_publishes(monkeypatch):
    runner = FakeRunner(linux_answers())
    collector = GuestLinuxCollector()
    monkeypatch.setattr(GuestLinuxCollector, "runner", lambda self, device, cred: runner)
    device = linux_device("web-metrics")

    data = collector.collect(device, Credential(username="infra-ro"))

    assert runner.closed is True
    assert data["os"]["id"] == "ubuntu"
    assert (
        REGISTRY.get_sample_value("infra_guest_pending_updates", {"device": "web-metrics"}) == 3.0
    )


# --------------------------------------------------------------------------
# Windows
# --------------------------------------------------------------------------
def test_windows_identity_and_capacity(windows_data):
    assert windows_data["os"]["name"] == "Microsoft Windows Server 2019 Standard"
    assert windows_data["os"]["hostname"] == "APP-WIN-01"
    assert windows_data["os"]["build"] == "17763"
    assert windows_data["cpu"] == {"count": 4}
    assert windows_data["memory"]["total_bytes"] == 17179869184
    assert windows_data["uptime_seconds"] == pytest.approx(7 * 86400 + 7 * 3600 + 45 * 60)
    assert windows_data["errors"] == {}


def test_windows_services_hotfixes_programs_and_volumes(windows_data):
    services = {row["name"]: row for row in windows_data["services"]}
    assert services["MSSQLSERVER"]["active"] == "active"
    assert services["W3SVC"]["active"] == "inactive"
    assert services["W3SVC"]["enabled"] == "Automatic"

    tagged = {row["service"]: row for row in windows_data["tagged_services"]}
    assert tagged["MSSQLSERVER"]["active"] is True
    assert tagged["W3SVC"]["active"] is False

    assert [row["id"] for row in windows_data["hotfixes"]] == ["KB5034768", "KB5032338"]
    assert windows_data["hotfixes"][0]["installed_at"].startswith("2026-02-03")
    assert windows_data["hotfixes"][1]["installed_at"].startswith("2026-01-11")

    programs = {row["name"]: row["version"] for row in windows_data["packages"]}
    assert programs["Microsoft SQL Server 2019"] == "15.0.2000.5"

    volumes = {row["mount"]: row for row in windows_data["disks"]}
    assert volumes["C:"]["free_bytes"] == 10307921510
    assert volumes["C:"]["free_ratio"] == pytest.approx(0.075, abs=0.001)


def test_windows_listeners_connections_certificates_and_updates(windows_data):
    listeners = {row["port"]: row for row in windows_data["listeners"]}
    assert listeners[1433]["process"] == "sqlservr"
    assert listeners[1433]["address"] == "127.0.0.1"
    assert listeners[3389]["process"] == "svchost"

    connections = {
        (row["remote_ip"], row["remote_port"]): row for row in windows_data["connections"]
    }
    assert connections[("10.20.0.31", 1433)]["connections"] == 2
    assert connections[("10.20.0.31", 1433)]["process"] == "w3wp"
    assert ("10.10.10.50", 51999) not in connections  # inbound to our own 443

    certs = {row["subject"]: row for row in windows_data["certificates"]}
    assert certs["CN=app-win-01.lab.local"]["not_after"] == "2026-09-20T09:30:00+00:00"
    assert certs["CN=app-win-01.lab.local"]["sans"] == ["app-win-01", "app-win-01.lab.local"]
    # whole days: a stored value that moved every run would make every guest
    # snapshot differ from the last one
    assert certs["CN=app-win-01.lab.local"]["days_to_expiry"] == 13
    assert certs["CN=win-legacy.lab.local"]["sans"] == []  # /Date(...)/ and no DnsNameList

    assert windows_data["updates"]["pending"] == 2


def test_a_windows_update_agent_that_refuses_says_unknown_rather_than_zero():
    """A remote WUA query is often blocked; reporting 0 pending would be a lie."""
    answers = windows_answers()
    answers[PS_PENDING_UPDATES] = CommandResult(
        command=PS_PENDING_UPDATES, status=1, stderr="0x80240044 access denied"
    )
    data = collect_windows(FakeRunner(answers), windows_device(), now=NOW)

    assert data["updates"] == {}
    assert "updates" in data["errors"]
    assert any("Windows Update agent" in w for w in data["warnings"])


# --------------------------------------------------------------------------
# metrics
# --------------------------------------------------------------------------
def test_gauges_are_published_per_guest(linux_data):
    GuestLinuxCollector().publish_metrics("web-gauges", linux_data)
    sample = REGISTRY.get_sample_value

    assert sample("infra_guest_pending_updates", {"device": "web-gauges"}) == 3.0
    assert sample("infra_guest_service_active", {"device": "web-gauges", "service": "nginx"}) == 0.0
    assert (
        sample("infra_guest_disk_free_bytes", {"device": "web-gauges", "mount": "/"})
        == 9052160 * 1024
    )
    assert (
        sample("infra_guest_disk_total_bytes", {"device": "web-gauges", "mount": "/"})
        == 61118592 * 1024
    )
    assert sample(
        "infra_guest_certificate_days_to_expiry",
        {"device": "web-gauges", "certificate": "/etc/letsencrypt/live/app.example.com/cert.pem"},
    ) == pytest.approx(56.0)


def test_a_filesystem_or_certificate_that_is_gone_loses_its_series(linux_data):
    """A renewed certificate and an unmounted volume must not keep their last
    reading, or the alert built on them can never resolve."""
    collector = GuestLinuxCollector()
    sample = REGISTRY.get_sample_value
    device = "web-sweep"
    collector.publish_metrics(device, linux_data)
    assert sample("infra_guest_disk_free_bytes", {"device": device, "mount": "/boot/efi"})

    smaller = {
        **linux_data,
        "disks": [row for row in linux_data["disks"] if row["mount"] == "/"],
        "certificates": [],
    }
    collector.publish_metrics(device, smaller)

    assert sample("infra_guest_disk_free_bytes", {"device": device, "mount": "/boot/efi"}) is None
    assert sample("infra_guest_disk_free_bytes", {"device": device, "mount": "/"})
    assert (
        sample(
            "infra_guest_certificate_days_to_expiry",
            {"device": device, "certificate": "127.0.0.1:443"},
        )
        is None
    )


def test_a_failed_section_keeps_its_series_instead_of_resolving_the_alert(linux_data):
    collector = GuestLinuxCollector()
    sample = REGISTRY.get_sample_value
    device = "web-section-error"
    collector.publish_metrics(device, linux_data)

    degraded = {**linux_data, "disks": [], "errors": {"disks": "RuntimeError: df -Pk exited 1"}}
    collector.publish_metrics(device, degraded)

    assert sample("infra_guest_disk_free_bytes", {"device": device, "mount": "/"}) == 9052160 * 1024


def test_run_collector_persists_a_guest_snapshot(tmp_path, monkeypatch):
    from infra_agent.store.snapshots import FileSnapshotStore

    runner = FakeRunner(linux_answers())
    monkeypatch.setattr(GuestLinuxCollector, "runner", lambda self, device, cred: runner)
    store = FileSnapshotStore(tmp_path / "snapshots")
    device = linux_device("web-store")

    result = run_collector(
        GuestLinuxCollector(), device, Credential(username="infra-ro"), store, None
    )

    assert result.snapshot.collector == "guest"
    assert store.latest("web-store", "guest").data["os"]["id"] == "ubuntu"
    assert result.config_commits == {}  # a guest has no config to back up


# --------------------------------------------------------------------------
# helpers used by the duty and by the graph
# --------------------------------------------------------------------------
def test_tagged_service_names_reads_the_seed_tags():
    assert tagged_service_names(["vm:web-01", "service:nginx", "auto:restart"]) == ["nginx"]
    assert tagged_service_names(["Service:Nginx", "service:"]) == ["Nginx"]
    assert tagged_service_names([]) == []


def test_expiring_certificates_recomputes_the_deadline_from_now(linux_data):
    """A guest whose collector has been down for a week must not look a week
    less urgent than it is."""
    later = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
    rows = expiring_certificates([("web-01", linux_data)], within_days=30, now=later)

    assert [row["source"] for row in rows] == ["/etc/nginx/ssl/internal-ca-signed.crt"]
    assert rows[0]["days_to_expiry"] == pytest.approx(3.9, abs=0.1)
    assert rows[0]["common_name"] == "legacy.internal"
    assert rows[0]["expired"] is False

    expired = expiring_certificates(
        [("web-01", linux_data)], within_days=30, now=datetime(2026, 12, 1, tzinfo=UTC)
    )
    assert {row["expired"] for row in expired} == {True}


def test_expiring_certificates_ignores_guests_with_none():
    assert expiring_certificates([("sw-core-01", {"vlans": []})], now=NOW) == []


# --------------------------------------------------------------------------
# alert rules
# --------------------------------------------------------------------------
def _metric_names_defined_in_code() -> set[str]:
    from prometheus_client import Counter

    from infra_agent.monitoring import metrics

    names = set()
    for value in vars(metrics).values():
        name = getattr(value, "_name", None)
        if isinstance(name, str) and name.startswith("infra_"):
            names.add(name)
            if isinstance(value, Counter):
                names.add(f"{name}_total")
    return names


def test_guest_rules_are_valid_and_reference_real_metrics():
    document = yaml.safe_load((RULES / "guest.yaml").read_text())
    (group,) = document["groups"]
    assert group["name"] == "infra-guest"

    defined = _metric_names_defined_in_code()
    alerts = {rule["alert"] for rule in group["rules"]}
    assert {
        "CertificateExpiringSoon",
        "CertificateExpiringCritical",
        "GuestServiceDown",
        "GuestDiskFull",
        "GuestUpdatesPending",
        "GuestUnreachable",
    } <= alerts

    for rule in group["rules"]:
        assert rule["labels"]["severity"] in {"info", "warning", "critical"}
        assert rule["annotations"]["summary"]
        referenced = set(re.findall(r"\binfra_[a-z0-9_]+", rule["expr"]))
        assert referenced, rule["alert"]
        assert referenced <= defined, (rule["alert"], referenced - defined)


def test_certificate_alerts_fire_at_thirty_and_seven_days():
    """The alert, the gauge and the daily digest share one threshold."""
    from infra_agent.agent.duties import CERT_EXPIRY_WARN_DAYS as duty_threshold
    from infra_agent.collectors.guest import CERT_EXPIRY_WARN_DAYS

    document = yaml.safe_load((RULES / "guest.yaml").read_text())
    rules = {rule["alert"]: rule for rule in document["groups"][0]["rules"]}
    assert duty_threshold == CERT_EXPIRY_WARN_DAYS == 30
    assert f"< {CERT_EXPIRY_WARN_DAYS}" in rules["CertificateExpiringSoon"]["expr"]
    assert "< 30" in rules["CertificateExpiringSoon"]["expr"]
    assert "< 7" in rules["CertificateExpiringCritical"]["expr"]
    assert "guest" in rules["GuestUnreachable"]["expr"]


def test_the_updates_alert_waits_thirty_days():
    document = yaml.safe_load((RULES / "guest.yaml").read_text())
    rules = {rule["alert"]: rule for rule in document["groups"][0]["rules"]}
    assert rules["GuestUpdatesPending"]["for"] == "30d"


# --------------------------------------------------------------------------
# the daily digest's certificate section
# --------------------------------------------------------------------------
def test_the_daily_digest_reports_expiring_guest_certificates(tmp_path, linux_data):
    """The duty reads the guest snapshots and recomputes the deadline itself."""
    from infra_agent.agent import duties as duties_module
    from infra_agent.agent.duties import Duties
    from infra_agent.config import Settings
    from infra_agent.models.common import SeedInventory, Snapshot
    from infra_agent.store.snapshots import FileSnapshotStore

    settings = Settings(data_dir=tmp_path / "data", seed_inventory=tmp_path / "seed.yaml")
    snapshots = FileSnapshotStore(tmp_path / "snapshots")
    snapshots.save(Snapshot(device="web-01", collector="guest", taken_at=NOW, data=linux_data))
    snapshots.save(
        Snapshot(device="sw-core-01", collector="cisco", taken_at=NOW, data={"vlans": []})
    )
    inventory = SeedInventory(
        devices=[
            linux_device("web-01"),
            SeedDevice(
                name="sw-core-01",
                kind=DeviceKind.cisco_ios,
                mgmt_ip="10.10.10.11",
                credential_ref="sw-core-01",
            ),
        ]
    )
    duties = Duties(
        settings=settings,
        snapshots=snapshots,
        inventory=lambda: inventory,
        now=lambda: datetime(2026, 9, 16, 12, 0, tzinfo=UTC),
    )

    rows = duties.certificate_expiry()

    # only the certificate inside 30 days, and the deadline is recomputed
    assert [row["common_name"] for row in rows] == ["legacy.internal"]
    assert rows[0]["device"] == "web-01"
    assert rows[0]["days_to_expiry"] == pytest.approx(3.9, abs=0.1)
    assert duties.digest_context()["certificate_expiry"] == rows
    assert "certificates about to expire" in duties_module.DIGEST_TASK


def test_paramiko_and_winrm_are_imported_lazily():
    """The core package must import on a box with no `devices` extra."""
    import ast

    tree = ast.parse(Path(guest_module.__file__).read_text())
    top_level = {
        alias.name.split(".")[0]
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in getattr(node, "names", [])
    }
    assert "paramiko" not in top_level and "winrm" not in top_level
    assert {"paramiko", "winrm"} <= {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }


# --------------------------------------------------------------------------
# the templates as the guest's login shell sees them
# --------------------------------------------------------------------------
#: Every fixed Linux template, replayed through a real shell. `exec_command`
#: hands the line to the account's login shell, so quoting is part of the
#: command and a fake runner keyed on the template string cannot see it break.
LINUX_TEMPLATES: dict[str, str] = {
    "os_release": OS_RELEASE_COMMAND,
    "kernel": KERNEL_COMMAND,
    "hostname": HOSTNAME_COMMAND,
    "uptime": UPTIME_COMMAND,
    "cpu": CPU_COMMAND,
    "meminfo": MEMINFO_COMMAND,
    "whoami": WHOAMI_COMMAND,
    "dpkg": DPKG_COMMAND,
    "rpm": RPM_COMMAND,
    "apt": APT_UPGRADABLE_COMMAND,
    "dnf": DNF_CHECK_COMMAND,
    "units": SYSTEMD_UNITS_COMMAND,
    "unit_files": SYSTEMD_UNIT_FILES_COMMAND,
    "ss_tcp": SS_TCP_LISTEN_COMMAND,
    "ss_udp": SS_UDP_LISTEN_COMMAND,
    "ss_established": SS_ESTABLISHED_COMMAND,
    "netstat_tcp": NETSTAT_TCP_LISTEN_COMMAND,
    "netstat_udp": NETSTAT_UDP_LISTEN_COMMAND,
    "netstat_established": NETSTAT_ESTABLISHED_COMMAND,
    "df": DF_COMMAND,
    "find": CERT_FIND_COMMAND,
    "openssl": CERT_READ_TEMPLATE.format(path="/etc/nginx/ssl/site.crt"),
    "tls_probe": TLS_PROBE_TEMPLATE.format(
        host="127.0.0.1", port=443, timeout=TLS_PROBE_TIMEOUT_SECONDS
    ),
    "sudo": SUDO_TEST_COMMAND,
}

SHELLS = [name for name in ("sh", "dash", "bash") if shutil.which(name)]


@pytest.fixture(scope="module")
def stub_bin(tmp_path_factory) -> Path:
    """A PATH of stubs that print the argv they were given, one per line."""
    directory = tmp_path_factory.mktemp("stub-bin")
    binaries = {command.split()[0] for command in LINUX_TEMPLATES.values()}
    binaries |= {"cat", "openssl", "sudo", "timeout", "ss", "netstat", "find"}
    for name in binaries:
        script = directory / name
        if name in ("sudo", "timeout"):
            # both exec the rest of the line, so the real argv still reaches the
            # binary under test
            body = '#!/bin/sh\nshift_to=0\nwhile [ "${1#-}" != "$1" ]; do shift; done\nexec "$@"\n'
        else:
            body = '#!/bin/sh\nfor a in "$@"; do printf "ARGV:%s\\n" "$a"; done\n'
        script.write_text(body)
        script.chmod(0o755)
    return directory


def shell_argv(shell: str, command: str, stub_bin: Path) -> tuple[int, list[str], str]:
    """Run one template through `shell -c` and report the argv it produced."""
    completed = subprocess.run(  # noqa: S603 - fixed argv, fixed PATH
        [shell, "-c", command],
        capture_output=True,
        text=True,
        env={"PATH": f"{stub_bin}:/usr/bin:/bin", "HOME": str(stub_bin)},
        check=False,
    )
    argv = [line[5:] for line in completed.stdout.splitlines() if line.startswith("ARGV:")]
    return completed.returncode, argv, completed.stderr


@pytest.mark.skipif(not SHELLS, reason="no POSIX shell to replay the templates through")
@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("name", sorted(LINUX_TEMPLATES))
def test_every_linux_template_survives_the_guests_login_shell(shell, name, stub_bin):
    """`dpkg-query -W -f=${binary:Package}` is a "Bad substitution" under dash
    and expands to `-f=tn` under bash: unquoted, the package list is garbage."""
    status, _argv, stderr = shell_argv(shell, LINUX_TEMPLATES[name], stub_bin)

    assert status == 0, f"{name}: exit {status}: {stderr}"
    assert "Bad substitution" not in stderr
    assert "not found" not in stderr


@pytest.mark.skipif(not SHELLS, reason="no POSIX shell to replay the templates through")
@pytest.mark.parametrize("shell", SHELLS)
def test_the_package_format_strings_reach_the_binary_intact(shell, stub_bin):
    _status, dpkg, _stderr = shell_argv(shell, DPKG_COMMAND, stub_bin)
    assert dpkg == ["-W", "-f=${binary:Package}\\t${Version}\\n"]

    _status, rpm, _stderr = shell_argv(shell, RPM_COMMAND, stub_bin)
    assert rpm == ["-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"]


@pytest.mark.skipif(not SHELLS, reason="no POSIX shell to replay the templates through")
@pytest.mark.parametrize("shell", SHELLS)
def test_the_certificate_find_reaches_find_as_the_sudoers_file_spells_it(shell, stub_bin):
    """The argv sudo matches is the one the shell produced, so the sudoers
    entry is generated by stripping exactly these quotes and backslashes."""
    from infra_agent.onboarding.accounts import sudoers_line

    _status, argv, _stderr = shell_argv(shell, CERT_FIND_COMMAND, stub_bin)

    assert argv[0] == "-L"
    assert "(" in argv and ")" in argv and "\\(" not in argv
    assert "*.pem" in argv  # the quotes stopped the shell globbing it
    assert " ".join(argv) in "\n".join(sudoers_line("infra-ro"))


# --------------------------------------------------------------------------
# certificates on disk
# --------------------------------------------------------------------------
def test_the_certificate_find_follows_certbots_symlinks(tmp_path):
    """certbot keeps `live/<domain>/cert.pem` as a symlink into `archive/`, and
    `-type f` alone does not match a symlink: without `-L` the flagship
    certificate-expiry case is never collected at all."""
    assert CERT_FIND_COMMAND.startswith("find -L ")
    live = tmp_path / "etc/letsencrypt/live/app.example.com"
    archive = tmp_path / "etc/letsencrypt/archive/app.example.com"
    archive.mkdir(parents=True)
    live.mkdir(parents=True)
    (tmp_path / "etc/nginx/ssl").mkdir(parents=True)
    (tmp_path / "etc/nginx/ssl/site.crt").write_text("x")
    for stem in ("cert", "chain", "fullchain", "privkey"):
        (archive / f"{stem}1.pem").write_text("x")
        (live / f"{stem}.pem").symlink_to(archive / f"{stem}1.pem")

    command = CERT_FIND_COMMAND.replace("/etc/", f"{tmp_path}/etc/")
    found = subprocess.run(  # noqa: S602 - the command is a module constant
        command, shell=True, capture_output=True, text=True, check=False
    ).stdout.split()

    assert f"{live}/cert.pem" in found
    assert f"{tmp_path}/etc/nginx/ssl/site.crt" in found
    # the private key is excluded in the find itself, and the intermediate and
    # the bundle would only duplicate the leaf or add a CA node
    assert not any(name in " ".join(found) for name in ("privkey", "chain.pem", "fullchain.pem"))


def test_certificate_expiry_is_stored_in_whole_days_so_a_rerun_is_not_a_change():
    """A stored value that moves every fifteen minutes makes every guest
    snapshot differ from the last one, and rebuilds the graph every cycle."""
    from infra_agent.store.snapshots import diff_structures

    # an hour past midday, so neither run sits exactly on a day boundary
    moment = NOW + timedelta(hours=1)
    first = collect_linux(FakeRunner(linux_answers()), linux_device(), now=moment)
    later = collect_linux(
        FakeRunner(linux_answers()), linux_device(), now=moment + timedelta(minutes=15)
    )

    assert all(isinstance(row["days_to_expiry"], int) for row in first["certificates"])
    assert diff_structures(first["certificates"], later["certificates"]) == []


# --------------------------------------------------------------------------
# TLS probing
# --------------------------------------------------------------------------
def test_every_https_listener_is_probed_not_only_the_well_known_ports():
    """A Node app on 3001 serves TLS as much as nginx on 443 does."""
    targets = tls_probe_targets(
        [
            {"proto": "tcp", "port": 3001, "address": "0.0.0.0", "process": "node"},
            {"proto": "tcp", "port": 8443, "address": "0.0.0.0", "process": "java"},
            {"proto": "tcp", "port": 22, "address": "0.0.0.0", "process": "sshd"},
            {"proto": "tcp", "port": 5432, "address": "127.0.0.1", "process": "postgres"},
            {"proto": "tcp", "port": 80, "address": "0.0.0.0", "process": "nginx"},
            {"proto": "udp", "port": 53, "address": "0.0.0.0", "process": "systemd-resolve"},
        ]
    )
    ports = [target["port"] for target in targets]

    assert 3001 in ports and 8443 in ports
    assert ports[0] == 8443  # a port that certainly speaks TLS is knocked on first
    for never in (22, 5432, 80, 53):
        assert never not in ports


def test_the_probe_never_makes_more_handshakes_than_the_cap():
    listeners = [
        {"proto": "tcp", "port": port, "address": "0.0.0.0", "process": "app"}
        for port in range(20000, 20100)
    ]
    assert len(tls_probe_targets(listeners)) == 20


def test_a_hostile_listener_address_cannot_reach_the_shell():
    """`ss` output is something the guest said, and it is interpolated into a
    shell pipeline: only a literal IP address is ever allowed through."""
    hostile = tls_probe_targets(
        [
            {
                "proto": "tcp",
                "port": 443,
                "address": "127.0.0.1;touch /tmp/pwned #",
                "process": "nginx",
            }
        ]
    )
    assert hostile[0]["host"] == "127.0.0.1"
    command = TLS_PROBE_TEMPLATE.format(host=hostile[0]["host"], port=443, timeout=3)
    assert "touch" not in command and ";" not in command

    scoped = tls_probe_targets(
        [{"proto": "tcp", "port": 443, "address": "fe80::1%eth0", "process": "nginx"}]
    )
    assert scoped[0]["host"] == "[fe80::1]"


# --------------------------------------------------------------------------
# a failed section is "unknown", never "down"
# --------------------------------------------------------------------------
def test_a_failed_service_list_reports_unknown_rather_than_every_service_down():
    """A transient systemctl or SSH failure must not page the owner for every
    tagged service on the guest, which is what publishing 0 would do."""
    answers = linux_answers()
    answers[SYSTEMD_UNITS_COMMAND] = CommandResult(
        command=SYSTEMD_UNITS_COMMAND, status=1, stderr="Failed to list units: Connection timed out"
    )
    data = collect_linux(FakeRunner(answers), linux_device(), now=NOW)

    assert "services" in data["errors"]
    assert data["tagged_services"]
    assert all(row["active"] is None and row["found"] is None for row in data["tagged_services"])
    assert any("reported as unknown" in warning for warning in data["warnings"])


def test_an_unknown_service_publishes_no_gauge_and_keeps_the_last_value(linux_data):
    collector = GuestLinuxCollector()
    sample = REGISTRY.get_sample_value
    device = "web-unknown-service"
    labels = {"device": device, "service": "postgresql"}

    collector.publish_metrics(device, linux_data)
    assert sample("infra_guest_service_active", labels) == 1.0

    degraded = {
        **linux_data,
        "services": [],
        "tagged_services": [
            {"service": row["service"], "unit": None, "found": None, "state": None, "active": None}
            for row in linux_data["tagged_services"]
        ],
        "errors": {"services": "RuntimeError: systemctl exited 1"},
    }
    collector.publish_metrics(device, degraded)

    # unchanged: GuestServiceDown must not fire because a section failed
    assert sample("infra_guest_service_active", labels) == 1.0


# --------------------------------------------------------------------------
# Windows disks
# --------------------------------------------------------------------------
def test_windows_disks_fall_back_to_win32_logicaldisk_when_get_volume_is_denied():
    """`Get-Volume` reads the Storage CIM classes, which are ACL'd to local
    administrators - and the account this project creates is deliberately not
    one. Without the fallback GuestDiskFull is dead on every Windows guest."""
    answers = windows_answers()
    answers[PS_VOLUMES] = CommandResult(
        command=PS_VOLUMES, status=1, stderr="Get-Volume : Access denied"
    )
    answers[PS_LOGICAL_DISKS] = windows_fixture("logical-disks")

    data = collect_windows(FakeRunner(answers), windows_device(), now=NOW)

    disks = {row["mount"]: row for row in data["disks"]}
    assert set(disks) == {"C:", "D:"}
    assert disks["C:"]["free_bytes"] == 10307921510
    assert disks["C:"]["label"] == "System"
    assert disks["C:"]["source"] == "Win32_LogicalDisk"
    assert "disks" not in data["errors"]


def test_windows_disks_that_answer_nowhere_are_an_error_with_a_warning():
    answers = windows_answers()
    answers[PS_VOLUMES] = CommandResult(command=PS_VOLUMES, status=1, stderr="Access denied")
    data = collect_windows(FakeRunner(answers), windows_device(), now=NOW)

    assert data["disks"] == []
    assert "Win32_LogicalDisk" in data["errors"]["disks"]
    assert any("free-space alerts are blind" in warning for warning in data["warnings"])


def test_the_winrm_session_is_given_the_command_timeout():
    """pywinrm defaults to 20 s, which cuts `Get-ComputerInfo` off."""
    captured: dict[str, Any] = {}

    class FakeSession:
        def __init__(self, endpoint: str, **kwargs: Any) -> None:
            captured["endpoint"] = endpoint
            captured.update(kwargs)

    with mock.patch.dict(sys.modules, {"winrm": types.SimpleNamespace(Session=FakeSession)}):
        WinRmRunner(windows_device(), Credential(username="infra-ro", password="pw"), timeout=45)

    assert captured["operation_timeout_sec"] == 45
    assert captured["read_timeout_sec"] > captured["operation_timeout_sec"]
    assert captured["endpoint"].startswith("https://10.20.0.21:5986/")
