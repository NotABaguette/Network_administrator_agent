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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
    UPTIME_COMMAND,
    WHOAMI_COMMAND,
    CommandResult,
    GuestLinuxCollector,
    GuestWindowsCollector,
    collect_linux,
    collect_windows,
    expiring_certificates,
    parse_openssl_x509,
    summarise_connections,
    tagged_service_names,
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
        SUDO_TEST_COMMAND: "",
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
        "timeout 5 openssl s_client -connect 127.0.0.1:443*": linux_fixture("openssl-s-client"),
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
    assert lets_encrypt["days_to_expiry"] == pytest.approx(56.0)
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
    assert legacy["days_to_expiry"] == pytest.approx(13.9, abs=0.1)


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
    answers = linux_answers()
    answers[SUDO_TEST_COMMAND] = CommandResult(
        command=SUDO_TEST_COMMAND, status=1, stderr="sudo: a password is required"
    )
    answers[SS_TCP_LISTEN_COMMAND] = re.sub(
        r"\s+users:.*$", "", linux_fixture("ss-tcp-listen"), flags=re.M
    )
    runner = FakeRunner(answers)
    data = collect_linux(runner, linux_device(), now=NOW)

    assert not any(c.startswith("sudo -n ") for c in runner.commands if c != SUDO_TEST_COMMAND)
    listeners = {row["port"]: row for row in data["listeners"] if row["proto"] == "tcp"}
    assert listeners[443]["process"] is None
    assert any("no passwordless sudo" in w for w in data["warnings"])


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
    assert certs["CN=app-win-01.lab.local"]["days_to_expiry"] == pytest.approx(13.9, abs=0.1)
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
