"""Guest collector: what the operating system inside a VM is actually running.

Two kinds, one shape. Linux is read over SSH (paramiko, key authentication
preferred); Windows over WinRM (pywinrm, NTLM or basic over HTTPS). Both return
the same top-level sections so everything downstream - the application layer in
`infra_agent/correlate/guest.py`, the certificate-expiry duty, the gauges - is
written once:

    os, uptime_seconds, cpu, memory, packages, updates, services, listeners,
    connections, disks, certificates, tagged_services, warnings, errors

Rules this collector is built around:

* **Fixed command templates.** Every command is a constant in this module. The
  only values interpolated into one are integers (a TCP port) and paths that
  came out of the collector's own `find` over a fixed list of directories.
  Nothing the model says, and nothing a device said, becomes a command.
* **Rows, never dumps.** `cat /etc/os-release` becomes `{"id": "ubuntu", ...}`;
  `ss -tlnpH` becomes listener rows. No raw text is stored, so nothing here can
  smuggle a configuration file past the redaction gateway.
* **Secrets are never collected.** No `/etc/shadow`, no private keys, no
  Kerberos tickets, no `*.key` / `privkey*` file is ever read - the certificate
  scan excludes them in the `find` itself and only ever asks `openssl x509` for
  the public fields (subject, issuer, notAfter, SANs).
* **Least privilege.** The account is unprivileged. Exactly the commands in
  `SUDO_COMMANDS` are run through `sudo -n`, which is the same list
  `infra_agent/onboarding/accounts.py` writes into the sudoers allowlist. When
  sudo is not available the run degrades (sockets without process names) with a
  warning instead of failing.
* **One bad section never loses the run, and never becomes a false alarm.**
  Each section is wrapped like the ESXi collector's: a failure lands in
  `errors[section]`, adds a warning, and the gauges of that section survive the
  stale-series sweep, because "not collected" is not "gone". The tagged
  services of a run whose `systemctl` failed are reported `active: None`, not
  `active: False` - "unknown" must never page as "down".
* **Stored values are stable between runs.** A snapshot is diffed against the
  previous one, so anything that moves every fifteen minutes would report a
  change every cycle: certificate expiry is therefore stored in whole days
  (`snapshot_days_to_expiry`), and only the digest, which is computed the
  moment it is read, works in fractions.

`paramiko` and `winrm` are imported lazily, so the package and the test suite
import without the `devices` extra.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import re
import shlex
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from infra_agent.collectors.base import Collector, register
from infra_agent.models.common import Credential, DeviceKind, SeedDevice
from infra_agent.monitoring import metrics

log = logging.getLogger(__name__)

#: Guests are cattle compared with the switches: 15 minutes is plenty, and a
#: shorter interval would put an SSH login per VM per minute on the estate.
GUEST_INTERVAL_SECONDS = 900

DEFAULT_SSH_PORT = 22
DEFAULT_WINRM_PORT = 5986
COMMAND_TIMEOUT_SECONDS = 60.0

#: Caps: a snapshot is written every run and diffed against the last one.
MAX_PACKAGES = 1500
MAX_UPDATES = 200
MAX_SERVICES = 400
MAX_LISTENERS = 200
MAX_CONNECTIONS = 100
MAX_CERTIFICATES = 40
#: At `TLS_PROBE_TIMEOUT_SECONDS` each this is a minute in the worst case, on a
#: collector that runs every fifteen.
MAX_TLS_PROBES = 20

#: A tag `service:nginx` on the seed device is what makes a unit worth a gauge
#: and worth alerting on; without it every guest would publish a hundred series.
SERVICE_TAG_PREFIX = "service:"

#: The daily digest's threshold, kept here with the parsing so both agree.
CERT_EXPIRY_WARN_DAYS = 30

# ---------------------------------------------------------------------------
# Linux command templates
# ---------------------------------------------------------------------------
OS_RELEASE_COMMAND = "cat /etc/os-release"
KERNEL_COMMAND = "uname -srm"
HOSTNAME_COMMAND = "uname -n"
UPTIME_COMMAND = "cat /proc/uptime"
CPU_COMMAND = "nproc"
MEMINFO_COMMAND = "cat /proc/meminfo"
WHOAMI_COMMAND = "id -u"

#: The format strings are single-quoted because `exec_command` hands the whole
#: line to the account's login shell: unquoted, `${binary:Package}` is a "Bad
#: substitution" under dash and expands to nothing under bash, and `\t` / `\n`
#: collapse to `t` / `n`. Either way the package inventory is empty or garbage.
DPKG_COMMAND = "dpkg-query -W -f='${binary:Package}\\t${Version}\\n'"
RPM_COMMAND = "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n'"

APT_UPGRADABLE_COMMAND = "apt list --upgradable"
#: `dnf check-update` answers 100 when updates are waiting and 0 when there are
#: none. Treating a non-zero exit as failure would report every patched host as
#: broken and every host with updates as unknown.
DNF_CHECK_COMMAND = "dnf --quiet check-update"
DNF_UPDATES_WAITING_STATUS = 100

SYSTEMD_UNITS_COMMAND = "systemctl list-units --type=service --all --no-legend --no-pager --plain"
SYSTEMD_UNIT_FILES_COMMAND = (
    "systemctl list-unit-files --type=service --no-legend --no-pager --plain"
)

SS_TCP_LISTEN_COMMAND = "ss -tlnpH"
SS_UDP_LISTEN_COMMAND = "ss -ulnpH"
SS_ESTABLISHED_COMMAND = "ss -tnpH state established"
NETSTAT_TCP_LISTEN_COMMAND = "netstat -tlnp"
NETSTAT_UDP_LISTEN_COMMAND = "netstat -ulnp"
NETSTAT_ESTABLISHED_COMMAND = "netstat -tnp"

#: `-P` is the POSIX one-line-per-filesystem format; `-k` pins the block size so
#: the parse does not depend on the guest's POSIXLY_CORRECT.
DF_COMMAND = "df -Pk"

#: /etc/ssl/certs is deliberately absent: it is the CA trust bundle, thousands
#: of files that say nothing about what this guest serves.
CERT_PATHS: tuple[str, ...] = (
    "/etc/letsencrypt/live",
    "/etc/nginx",
    "/etc/apache2",
    "/etc/httpd",
    "/etc/pki/tls/certs",
)
#: `-L` is load-bearing: certbot keeps `live/<domain>/cert.pem` as a *symlink*
#: into `archive/`, and plain `-type f` does not match a symlink - without it
#: the flagship certificate-expiry case (a Let's Encrypt certificate whose
#: renewal broke) is never collected at all. With `-L`, `find` tests the link
#: target, so `-type f` matches and the private keys are still excluded by name.
#: `chain.pem` is the intermediate CA and `fullchain.pem` starts with the same
#: leaf as `cert.pem`; both would only add a duplicate or a CA node.
CERT_FIND_COMMAND = (
    "find -L " + " ".join(CERT_PATHS) + " -maxdepth 3 -type f "
    r"\( -name '*.pem' -o -name '*.crt' -o -name '*.cer' \) "
    "-not -name 'privkey*' -not -name '*key.pem' -not -name '*.key' "
    "-not -name 'chain*.pem' -not -name 'fullchain*.pem'"
)
CERT_READ_TEMPLATE = "openssl x509 -noout -subject -issuer -enddate -ext subjectAltName -in {path}"
#: `{host}` is always a literal IP address (`_probe_host` validates it with
#: `ipaddress` and falls back to loopback), so nothing a guest printed can reach
#: the shell through this template.
TLS_PROBE_TEMPLATE = (
    "timeout {timeout} openssl s_client -connect {host}:{port} -servername localhost </dev/null "
    "2>/dev/null | openssl x509 -noout -subject -issuer -enddate -ext subjectAltName"
)
TLS_PROBE_TIMEOUT_SECONDS = 3

#: Every TCP listener is probed, because "every local HTTPS listener" includes
#: the Node app somebody put on 3001. The two lists below are only what is
#: *skipped*: ports and processes that certainly do not speak TLS and would
#: therefore cost `TLS_PROBE_TIMEOUT_SECONDS` of nothing each. Ports known to
#: serve TLS are probed first so that a guest with more listeners than
#: `MAX_TLS_PROBES` still gets its real certificates.
TLS_PORTS = frozenset({443, 465, 636, 993, 995, 5986, 6443, 8006, 8443, 9443, 10250})
TLS_PROCESSES = frozenset({"nginx", "httpd", "apache2", "haproxy", "traefik", "envoy", "postfix"})
#: nginx serves both; knocking on its plaintext port only produces a handshake
#: error and a few seconds of nothing.
PLAINTEXT_PORTS = frozenset({21, 23, 25, 80, 110, 143, 3000, 8000, 8080})
#: Protocols that are never TLS on these ports (or that start plaintext and
#: upgrade), so a handshake can only ever time out.
NON_TLS_PORTS = frozenset(
    {
        22,
        53,
        67,
        68,
        111,
        123,
        135,
        137,
        138,
        139,
        161,
        445,
        514,
        631,
        3306,
        3389,
        5432,
        6379,
        9100,
        9182,
        11211,
        27017,
    }
)
NON_TLS_PROCESSES = frozenset(
    {
        "sshd",
        "postgres",
        "mysqld",
        "mariadbd",
        "redis-server",
        "memcached",
        "mongod",
        "rpcbind",
        "rpc.statd",
        "chronyd",
        "ntpd",
        "named",
        "dnsmasq",
        "systemd-resolve",
        "dhclient",
        "cupsd",
        "node_exporter",
        "windows_exporter",
        "smbd",
        "nmbd",
    }
)

#: Exactly the commands the collector needs root for, and exactly what
#: `infra_agent/onboarding/accounts.py` puts in the sudoers allowlist:
#: process names on sockets, and the certificates under Let's Encrypt's
#: root-only `live/` directory.
SUDO_COMMANDS: tuple[str, ...] = (
    SS_TCP_LISTEN_COMMAND,
    SS_UDP_LISTEN_COMMAND,
    SS_ESTABLISHED_COMMAND,
    NETSTAT_TCP_LISTEN_COMMAND,
    NETSTAT_UDP_LISTEN_COMMAND,
    NETSTAT_ESTABLISHED_COMMAND,
    CERT_FIND_COMMAND,
    CERT_READ_TEMPLATE.format(path="/etc/letsencrypt/live/*/*.pem"),
)

#: How sudo availability is probed. It has to be one of the allowlisted
#: commands: the sudoers file `infra_agent/onboarding/accounts.py` generates
#: permits `SUDO_COMMANDS` and *nothing else*, so the obvious `sudo -n true`
#: answers "a password is required" on a correctly onboarded guest and would
#: make the collector (and the onboarding probe) conclude there is no sudo at
#: all - losing every process name and every Let's Encrypt certificate.
SUDO_TEST_COMMAND = f"sudo -n {SUDO_COMMANDS[0]}"

COMMAND_NOT_FOUND_STATUS = 127

#: sudo said no. Anything else - including the command itself failing, and
#: including `sudo: ss: command not found` - means sudo worked.
#: `sudo: unable to resolve host ...` is deliberately absent: sudo prints it and
#: then runs the command anyway.
_SUDO_REFUSED = re.compile(
    r"(a password is required|a terminal is required|no tty present|"
    r"not allowed to execute|may not run|is not in the sudoers|"
    r"authentication failure|no askpass program)",
    re.IGNORECASE,
)
#: `bash: sudo: command not found` / `sh: 1: sudo: not found` - sudo itself is
#: absent, which is a refusal. `sudo: ss: command not found` is not.
_SUDO_MISSING = re.compile(r"(?:^|[:\s])sudo:\s*(?:command\s+)?not found", re.IGNORECASE)


def sudo_refused(result: CommandResult) -> bool:
    """True when `sudo` itself rejected the command, not when the command failed."""
    stderr = result.stderr or ""
    if _SUDO_MISSING.search(stderr):
        return True
    if result.status == 0 or result.status == COMMAND_NOT_FOUND_STATUS:
        return False
    return bool(_SUDO_REFUSED.search(stderr))


# ---------------------------------------------------------------------------
# Windows command templates (PowerShell, one section each, JSON out)
# ---------------------------------------------------------------------------
PS_COMPUTER_INFO = (
    "Get-ComputerInfo -Property OsName,OsVersion,OsBuildNumber,OsArchitecture,CsName,"
    "CsDomain,CsNumberOfLogicalProcessors,CsTotalPhysicalMemory,OsLastBootUpTime "
    "| ConvertTo-Json -Compress -Depth 2"
)
PS_SERVICES = (
    "Get-Service | Select-Object Name,DisplayName,Status,StartType "
    "| ConvertTo-Json -Compress -Depth 2"
)
PS_LISTENERS = (
    "$p=@{}; Get-Process | ForEach-Object { $p[[int]$_.Id]=$_.ProcessName }; "
    "Get-NetTCPConnection -State Listen | ForEach-Object { [pscustomobject]@{"
    "LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort; ProcessId=[int]$_.OwningProcess; "
    "Process=$p[[int]$_.OwningProcess]} } | ConvertTo-Json -Compress -Depth 2"
)
PS_ESTABLISHED = (
    "$p=@{}; Get-Process | ForEach-Object { $p[[int]$_.Id]=$_.ProcessName }; "
    "Get-NetTCPConnection -State Established | ForEach-Object { [pscustomobject]@{"
    "LocalPort=$_.LocalPort; RemoteAddress=$_.RemoteAddress; RemotePort=$_.RemotePort; "
    "ProcessId=[int]$_.OwningProcess; Process=$p[[int]$_.OwningProcess]} } "
    "| ConvertTo-Json -Compress -Depth 2"
)
PS_HOTFIX = (
    "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 "
    "HotFixID,Description,InstalledOn | ConvertTo-Json -Compress -Depth 2"
)
PS_VOLUMES = (
    "Get-Volume | Where-Object DriveLetter | Select-Object DriveLetter,FileSystemLabel,"
    "FileSystem,Size,SizeRemaining,HealthStatus | ConvertTo-Json -Compress -Depth 2"
)
#: The Storage CIM classes (`root/Microsoft/Windows/Storage`) are ACL'd to the
#: local Administrators group, so `Get-Volume` answers "Access denied" for the
#: unprivileged account `infra onboard accounts` creates - which is exactly the
#: account this collector is meant to run as. `Win32_LogicalDisk` is readable by
#: standard users, so it is the fallback and `DriveType=3` keeps it to fixed
#: disks (no CD-ROMs, no mapped network drives).
PS_LOGICAL_DISKS = (
    'Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" '
    "| Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace "
    "| ConvertTo-Json -Compress -Depth 2"
)
PS_PROGRAMS = (
    r"Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',"
    r"'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' "
    "-ErrorAction SilentlyContinue | Where-Object DisplayName | "
    "Select-Object DisplayName,DisplayVersion,Publisher | Sort-Object DisplayName "
    "| ConvertTo-Json -Compress -Depth 2"
)
PS_CERTIFICATES = (
    r"Get-ChildItem Cert:\LocalMachine\My | Select-Object Subject,Issuer,NotAfter,Thumbprint,"
    "@{Name='DnsNameList';Expression={$_.DnsNameList.Unicode}} "
    "| ConvertTo-Json -Compress -Depth 3"
)
PS_PENDING_UPDATES = (
    "$s=New-Object -ComObject Microsoft.Update.Session; "
    '$r=$s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0"); '
    "$r.Updates | Select-Object Title | ConvertTo-Json -Compress -Depth 2"
)

WINDOWS_RUNNING_STATES = frozenset({"running", "4"})

#: Gauges that belong to one section. When that section failed this run its
#: absent rows mean "not collected", not "gone" (same contract as the ESXi
#: collector), so its series survive the sweep.
SECTION_GAUGES: tuple[tuple[str, tuple[Any, ...]], ...] = (
    ("updates", (metrics.GUEST_PENDING_UPDATES,)),
    ("services", (metrics.GUEST_SERVICE_ACTIVE,)),
    ("certificates", (metrics.GUEST_CERTIFICATE_DAYS_TO_EXPIRY,)),
    ("disks", (metrics.GUEST_DISK_FREE_BYTES, metrics.GUEST_DISK_TOTAL_BYTES)),
)

#: Label tuples published per guest, so a filesystem that is unmounted, a
#: certificate that is replaced and a service that is untagged lose their series.
_SERIES = metrics.DeviceSeries()


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CommandResult:
    """One command and what it answered. `stderr` never reaches a snapshot."""

    command: str
    status: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.status == 0

    @property
    def missing(self) -> bool:
        """The binary is not installed on this guest (`ss` on a minimal image)."""
        if self.status == COMMAND_NOT_FOUND_STATUS:
            return True
        return bool(re.search(r"(command not found|No such file or directory)", self.stderr))


class CommandRunner(Protocol):
    """Runs one fixed command template against one guest."""

    def run(self, command: str) -> CommandResult: ...

    def close(self) -> None: ...


class SshRunner:
    """paramiko over SSH. The key is the identity; a password is the fallback.

    Host keys are pinned when `INFRA_SSH_KNOWN_HOSTS` names a file, exactly as
    the read-only device transports do (`infra_agent/tools/observability_tools.py`).
    """

    def __init__(self, device: SeedDevice, cred: Credential, timeout: float | None = None) -> None:
        self.timeout = timeout or COMMAND_TIMEOUT_SECONDS
        self.client = self._connect(device, cred)

    @staticmethod
    def _connect(device: SeedDevice, cred: Credential) -> Any:
        import paramiko

        from infra_agent.tools.observability_tools import ssh_known_hosts

        client = paramiko.SSHClient()
        known_hosts = ssh_known_hosts()
        if known_hosts:
            client.load_host_keys(known_hosts)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict[str, Any] = {
            "hostname": device.mgmt_ip,
            "port": device.port or DEFAULT_SSH_PORT,
            "username": cred.username,
            "timeout": 20,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if cred.ssh_key_path:
            kwargs["key_filename"] = cred.ssh_key_path
            if cred.password:  # the password is the key's passphrase, not a login
                kwargs["passphrase"] = cred.password.get_secret_value()
        elif cred.password:
            kwargs["password"] = cred.password.get_secret_value()
        client.connect(**kwargs)
        return client

    def run(self, command: str) -> CommandResult:
        _stdin, stdout, stderr = self.client.exec_command(command, timeout=self.timeout)
        out = _text(stdout.read())
        err = _text(stderr.read())
        channel = getattr(stdout, "channel", None)
        status = channel.recv_exit_status() if channel is not None else 0
        return CommandResult(command=command, status=int(status), stdout=out, stderr=err)

    def close(self) -> None:
        try:
            self.client.close()
        except Exception as exc:  # noqa: BLE001 - teardown must never fail a run
            log.debug("closing the guest SSH session failed: %s", exc)


class WinRmRunner:
    """pywinrm over HTTPS. NTLM when the credential carries a domain user."""

    def __init__(self, device: SeedDevice, cred: Credential, timeout: float | None = None) -> None:
        self.timeout = timeout or COMMAND_TIMEOUT_SECONDS
        self.session = self._connect(device, cred, self.timeout)

    @staticmethod
    def _connect(device: SeedDevice, cred: Credential, timeout: float) -> Any:
        import winrm

        username = cred.username or ""
        transport = "ntlm" if ("\\" in username or "@" in username) else "basic"
        endpoint = f"https://{device.mgmt_ip}:{device.port or DEFAULT_WINRM_PORT}/wsman"
        # `Get-ComputerInfo` is slow; pywinrm's 20 s default cuts it off. The
        # read timeout must stay above the operation timeout or the HTTP read
        # gives up before WinRM has answered.
        operation_timeout = int(timeout)
        return winrm.Session(
            endpoint,
            auth=(username, cred.password.get_secret_value() if cred.password else ""),
            transport=transport,
            server_cert_validation="ignore",  # pinned with the executors
            operation_timeout_sec=operation_timeout,
            read_timeout_sec=operation_timeout + 10,
        )

    def run(self, command: str) -> CommandResult:
        response = self.session.run_ps(command)
        return CommandResult(
            command=command,
            status=int(getattr(response, "status_code", 0) or 0),
            stdout=_text(getattr(response, "std_out", "")),
            stderr=_text(getattr(response, "std_err", "")),
        )

    def close(self) -> None:  # pywinrm holds no session to close
        return None


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return "" if value is None else str(value)


# ---------------------------------------------------------------------------
# small pure helpers
# ---------------------------------------------------------------------------
def _int_or_none(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _float_or_none(value: Any) -> float | None:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def split_host_port(value: str) -> tuple[str, int | None]:
    """`0.0.0.0:443`, `[::]:443`, `*:111` and `127.0.0.1:5432` -> (host, port)."""
    text = value.strip()
    if not text:
        return "", None
    if text.startswith("["):
        host, _, port = text.partition("]")
        return host[1:], _int_or_none(port.lstrip(":"))
    host, _, port = text.rpartition(":")
    if not host:
        return text, None
    return host, _int_or_none(port)


def parse_os_release(text: str) -> dict[str, Any]:
    """`/etc/os-release` key=value lines, unquoted."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        fields[key.strip().lower()] = value.strip().strip('"').strip("'")
    return {
        "id": fields.get("id"),
        "name": fields.get("name"),
        "version": fields.get("version_id") or fields.get("version"),
        "pretty_name": fields.get("pretty_name"),
        "id_like": [part for part in (fields.get("id_like") or "").split() if part],
    }


def parse_meminfo(text: str) -> dict[str, Any]:
    """MemTotal / MemAvailable out of `/proc/meminfo`, in bytes."""
    values: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        amount = _int_or_none(rest.strip().split(" ")[0] if rest.strip() else None)
        if amount is not None:
            values[key.strip()] = amount * 1024  # /proc/meminfo is in kB
    return {
        "total_bytes": values.get("MemTotal"),
        "available_bytes": values.get("MemAvailable"),
        "swap_total_bytes": values.get("SwapTotal"),
    }


def parse_packages(text: str) -> list[dict[str, str]]:
    """`name<TAB>version` lines from dpkg-query or rpm."""
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        name, _, version = line.partition("\t")
        if not name.strip():
            continue
        rows.append({"name": name.strip(), "version": version.strip()})
    rows.sort(key=lambda row: row["name"])
    return rows


_APT_LINE = re.compile(
    r"^(?P<name>[^/\s]+)/(?P<origin>\S+)\s+(?P<candidate>\S+)\s+\S+"
    r"(?:\s+\[upgradable from:\s*(?P<installed>[^\]]+)\])?"
)


def parse_apt_upgradable(text: str) -> list[dict[str, str | None]]:
    """`apt list --upgradable` rows (the `Listing...` header is not one)."""
    rows: list[dict[str, str | None]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("Listing", "WARNING", "N:", "W:")):
            continue
        match = _APT_LINE.match(stripped)
        if not match:
            continue
        rows.append(
            {
                "name": match.group("name"),
                "installed": (match.group("installed") or "").strip() or None,
                "candidate": match.group("candidate"),
                "origin": match.group("origin"),
            }
        )
    return rows


def parse_dnf_check_update(text: str) -> list[dict[str, str | None]]:
    """`dnf check-update` rows: `name.arch  version  repo`.

    Everything after an `Obsoleting Packages` heading is a different report and
    is dropped, and so is any leading progress or metadata chatter.
    """
    rows: list[dict[str, str | None]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith("obsoleting packages"):
            break
        if stripped.startswith(("Last metadata", "Security:", "Loaded plugins")):
            continue
        parts = stripped.split()
        if len(parts) < 3 or "." not in parts[0]:
            continue
        name, _, arch = parts[0].rpartition(".")
        rows.append(
            {"name": name or parts[0], "arch": arch, "candidate": parts[1], "origin": parts[2]}
        )
    return rows


def parse_systemd_units(text: str) -> list[dict[str, Any]]:
    """`systemctl list-units --type=service` rows.

    A failed unit is printed with a leading bullet, which is decoration and not
    a column.
    """
    rows: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(("*", "●", "•")):
            line = line[1:].strip()
        if not line or line.lower().startswith(("legend:", "to show all")):
            continue
        parts = line.split(None, 4)
        if len(parts) < 4 or not parts[0].endswith(".service"):
            continue
        rows.append(
            {
                "name": parts[0],
                "load": parts[1],
                "active": parts[2],
                "sub": parts[3],
                "description": parts[4].strip() if len(parts) > 4 else None,
            }
        )
    return rows


def parse_unit_files(text: str) -> dict[str, str]:
    """`systemctl list-unit-files` -> {unit: enabled|disabled|static|masked}."""
    states: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(".service"):
            states[parts[0]] = parts[1]
    return states


_SS_PROCESS = re.compile(r'\(\("(?P<name>[^"]+)",pid=(?P<pid>\d+)')


def _ss_process(field: str) -> tuple[str | None, int | None]:
    match = _SS_PROCESS.search(field or "")
    if not match:
        return None, None
    return match.group("name"), _int_or_none(match.group("pid"))


def parse_ss_listeners(text: str, proto: str) -> list[dict[str, Any]]:
    """`ss -tlnpH` / `ss -ulnpH` rows: state, queues, local, peer, users."""
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        local, port = split_host_port(parts[3])
        if port is None:
            continue
        process, pid = _ss_process(parts[5] if len(parts) > 5 else "")
        rows.append(
            {
                "proto": proto,
                "address": local,
                "port": port,
                "process": process,
                "pid": pid,
                "state": parts[0].lower(),
            }
        )
    return rows


def parse_ss_established(text: str) -> list[dict[str, Any]]:
    """`ss -tnpH state established` rows: local and peer address, users."""
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 4:
            continue
        # With an explicit state filter `ss` drops the state column, so the
        # first field is a queue depth instead of `ESTAB`.
        offset = 0 if parts[0].isdigit() else 1
        if len(parts) < offset + 4:
            continue
        local_host, local_port = split_host_port(parts[offset + 2])
        remote_host, remote_port = split_host_port(parts[offset + 3])
        if local_port is None or remote_port is None:
            continue
        process, pid = _ss_process(parts[offset + 4] if len(parts) > offset + 4 else "")
        rows.append(
            {
                "local_address": local_host,
                "local_port": local_port,
                "remote_ip": remote_host,
                "remote_port": remote_port,
                "process": process,
                "pid": pid,
            }
        )
    return rows


_NETSTAT_PROCESS = re.compile(r"^(?P<pid>\d+)/(?P<name>.+)$")


def _netstat_process(field: str) -> tuple[str | None, int | None]:
    match = _NETSTAT_PROCESS.match((field or "").strip())
    if not match:
        return None, None
    # `812/nginx: master` -> nginx
    name = match.group("name").split(":")[0].strip()
    return name or None, _int_or_none(match.group("pid"))


def parse_netstat_listeners(text: str, proto: str) -> list[dict[str, Any]]:
    """`netstat -tlnp` / `-ulnp`, for guests without iproute2."""
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or not parts[0].startswith(("tcp", "udp")):
            continue
        address, port = split_host_port(parts[3])
        if port is None:
            continue
        has_state = parts[0].startswith("tcp")
        process_field = (
            parts[6]
            if has_state and len(parts) > 6
            else (parts[5] if not has_state and len(parts) > 5 else "")
        )
        process, pid = _netstat_process(process_field)
        rows.append(
            {
                "proto": proto,
                "address": address,
                "port": port,
                "process": process,
                "pid": pid,
                "state": "listen",
            }
        )
    return rows


def parse_netstat_established(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 6 or not parts[0].startswith("tcp") or parts[5] != "ESTABLISHED":
            continue
        local_host, local_port = split_host_port(parts[3])
        remote_host, remote_port = split_host_port(parts[4])
        if local_port is None or remote_port is None:
            continue
        process, pid = _netstat_process(parts[6] if len(parts) > 6 else "")
        rows.append(
            {
                "local_address": local_host,
                "local_port": local_port,
                "remote_ip": remote_host,
                "remote_port": remote_port,
                "process": process,
                "pid": pid,
            }
        )
    return rows


#: `df` lists the kernel's own filesystems too. A full `/run` is a node_exporter
#: alert, not a disk the owner can extend, and publishing a gauge per tmpfs
#: buries the two filesystems that matter.
PSEUDO_FILESYSTEMS = frozenset({"udev", "devtmpfs", "tmpfs", "none", "overlay", "shm"})
PSEUDO_MOUNT_PREFIXES = ("/dev", "/run", "/sys", "/proc", "/snap")


def _is_pseudo_mount(mount: str) -> bool:
    """`/run/user/1001` is one; `/development` is a directory somebody named."""
    return any(
        mount == prefix or mount.startswith(f"{prefix}/") for prefix in PSEUDO_MOUNT_PREFIXES
    )


def parse_df(text: str) -> list[dict[str, Any]]:
    """`df -Pk` rows in bytes; pseudo filesystems are not capacity."""
    rows: list[dict[str, Any]] = []
    for line in text.splitlines()[1:]:
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        total = _float_or_none(parts[1])
        used = _float_or_none(parts[2])
        free = _float_or_none(parts[3])
        if total is None or free is None or total <= 0:
            continue
        mount = parts[5].strip()
        if parts[0] in PSEUDO_FILESYSTEMS or _is_pseudo_mount(mount):
            continue
        rows.append(
            {
                "filesystem": parts[0],
                "mount": mount,
                "total_bytes": int(total * 1024),
                "used_bytes": int(used * 1024) if used is not None else None,
                "free_bytes": int(free * 1024),
                "free_ratio": round(free / total, 4),
            }
        )
    return rows


_SAN_ENTRY = re.compile(r"(?:DNS|IP Address|IP|email|URI):\s*([^,\s]+)")


def _normalise_dn(value: str) -> str:
    """`CN = app.example.com` and `/CN=app.example.com` both -> `CN=app.example.com`."""
    text = value.strip()
    if text.startswith("/"):
        text = ", ".join(part for part in text.split("/") if part)
    return re.sub(r"\s*=\s*", "=", text).strip()


def parse_not_after(value: str) -> datetime | None:
    """`Nov  1 12:00:00 2026 GMT` -> an aware datetime."""
    text = value.strip()
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return parsed.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_openssl_x509(text: str) -> dict[str, Any] | None:
    """subject / issuer / notAfter / SANs from `openssl x509 -noout ...`.

    A certificate without a subjectAltName extension prints no SAN block at all
    (or `No extensions in certificate`); that is a certificate with no SANs, not
    a parse failure - modern browsers reject it, so it is worth recording.
    """
    subject = issuer = not_after = None
    sans: list[str] = []
    in_san = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith("subject="):
            subject = _normalise_dn(line.split("=", 1)[1])
        elif lowered.startswith("issuer="):
            issuer = _normalise_dn(line.split("=", 1)[1])
        elif lowered.startswith("notafter="):
            not_after = line.split("=", 1)[1].strip()
        elif "subject alternative name" in lowered:
            in_san = True
        elif in_san:
            found = _SAN_ENTRY.findall(line)
            sans.extend(found)
            in_san = bool(found)
    if subject is None and not_after is None:
        return None
    expiry = parse_not_after(not_after or "")
    return {
        "subject": subject,
        "issuer": issuer,
        "not_after": expiry.isoformat() if expiry else None,
        "sans": sorted(dict.fromkeys(sans)),
    }


def _with_days(row: dict[str, Any], now: datetime) -> dict[str, Any]:
    expiry = parse_not_after(str(row.get("not_after") or ""))
    row["days_to_expiry"] = snapshot_days_to_expiry(expiry, now) if expiry else None
    return row


def days_to_expiry(not_after: datetime | None, now: datetime) -> float | None:
    """Fractional days, for a report that is computed at the moment it is read."""
    if not_after is None:
        return None
    return round((not_after - now).total_seconds() / 86400.0, 2)


def snapshot_days_to_expiry(not_after: datetime | None, now: datetime) -> int | None:
    """Whole days, for anything that is *stored*.

    A snapshot is diffed against the previous one, so a field that moves by
    fifteen minutes every run would report a change on every cycle and rebuild
    the topology graph each time. Whole days round that down to one change a
    day, which is also the resolution the alert thresholds (30 / 7) use.
    """
    if not_after is None:
        return None
    return math.floor((not_after - now).total_seconds() / 86400.0)


def common_name(subject: str | None) -> str | None:
    """`CN=app.example.com, O=Example` -> `app.example.com`."""
    if not subject:
        return None
    match = re.search(r"\bCN=([^,/]+)", subject)
    return match.group(1).strip() if match else subject.strip() or None


def expiring_certificates(
    guests: Iterable[tuple[str, Mapping[str, Any]]],
    within_days: int = CERT_EXPIRY_WARN_DAYS,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Certificates from guest snapshots that expire within `within_days`.

    `days_to_expiry` is recomputed against `now` rather than trusted from the
    snapshot: a guest whose collector has been failing for a week must not look
    a week less urgent than it is.
    """
    moment = now or datetime.now(UTC)
    rows: list[dict[str, Any]] = []
    for device, data in guests:
        for cert in (data or {}).get("certificates") or []:
            if not isinstance(cert, dict):
                continue
            expiry = parse_not_after(str(cert.get("not_after") or ""))
            remaining = days_to_expiry(expiry, moment)
            if remaining is None or remaining > within_days:
                continue
            rows.append(
                {
                    "device": device,
                    "subject": cert.get("subject"),
                    "common_name": common_name(cert.get("subject")),
                    "issuer": cert.get("issuer"),
                    "source": cert.get("source"),
                    "not_after": cert.get("not_after"),
                    "days_to_expiry": remaining,
                    "expired": remaining < 0,
                }
            )
    rows.sort(key=lambda row: (float(row["days_to_expiry"]), str(row["device"])))
    return rows


def tagged_service_names(tags: Sequence[str]) -> list[str]:
    """`service:nginx` tags on the seed device -> the services worth a gauge."""
    names = [
        tag.split(":", 1)[1].strip()
        for tag in tags
        if str(tag).lower().startswith(SERVICE_TAG_PREFIX) and ":" in str(tag)
    ]
    return sorted({name for name in names if name})


def summarise_connections(
    established: Sequence[Mapping[str, Any]],
    listening_ports: set[int],
    limit: int = MAX_CONNECTIONS,
) -> list[dict[str, Any]]:
    """Outbound established sockets, grouped by what they talk to.

    A connection whose local port is one this guest listens on is somebody
    talking *to* it, not a dependency *of* it. The rest are grouped by
    (remote ip, remote port, process): a web server with four hundred sockets to
    one database is one dependency, not four hundred rows.
    """
    groups: dict[tuple[str, int, str], dict[str, Any]] = {}
    for row in established:
        local_port = _int_or_none(row.get("local_port"))
        remote_port = _int_or_none(row.get("remote_port"))
        remote_ip = str(row.get("remote_ip") or "").strip()
        if local_port is None or remote_port is None or not remote_ip:
            continue
        if local_port in listening_ports:
            continue  # inbound: the peer is the client, not a dependency
        process = str(row.get("process") or "") or "unknown"
        key = (remote_ip, remote_port, process)
        group = groups.get(key)
        if group is None:
            group = {
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "process": row.get("process"),
                "pid": row.get("pid"),
                "connections": 0,
            }
            groups[key] = group
        group["connections"] = int(group["connections"]) + 1
        group["local_port"] = min(int(group["local_port"]), local_port)
    rows = sorted(
        groups.values(),
        key=lambda row: (str(row["remote_ip"]), int(row["remote_port"]), str(row["process"] or "")),
    )
    return rows[:limit]


def _tls_priority(port: int, process: str) -> int | None:
    """0 = certainly TLS, 1 = might be, None = never knock on it.

    Every TCP listener is a candidate - "every local HTTPS listener" has to
    include the Node app on 3001 - except the ports and processes that cannot
    be TLS, where a handshake could only ever burn the timeout.
    """
    if port in TLS_PORTS:
        return 0
    if port in NON_TLS_PORTS or process in NON_TLS_PROCESSES:
        return None
    if process in TLS_PROCESSES and port not in PLAINTEXT_PORTS:
        return 0
    if port in PLAINTEXT_PORTS:
        return None
    return 1


def tls_probe_targets(listeners: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The listeners worth a TLS handshake, deduplicated by port, TLS ports first."""
    seen: set[int] = set()
    candidates: list[tuple[int, int, dict[str, Any]]] = []
    for row in listeners:
        if str(row.get("proto")) != "tcp":
            continue
        port = _int_or_none(row.get("port"))
        process = str(row.get("process") or "").lower()
        if port is None or port in seen:
            continue
        priority = _tls_priority(port, process)
        if priority is None:
            continue
        seen.add(port)
        candidates.append(
            (
                priority,
                port,
                {"port": port, "process": row.get("process"), "host": _probe_host(row)},
            )
        )
    candidates.sort(key=lambda item: (item[0], item[1]))
    return [target for _priority, _port, target in candidates[:MAX_TLS_PROBES]]


def _probe_host(row: Mapping[str, Any]) -> str:
    """Where to knock: loopback for a wildcard bind, the bound address otherwise.

    The address came out of `ss`/`netstat`/`Get-NetTCPConnection`, i.e. from the
    guest, and it is interpolated into a shell pipeline - so it is validated as
    a literal IP address here and anything else becomes loopback. This is the
    module's "nothing a device said becomes a command" rule, enforced.
    """
    address = str(row.get("address") or "").strip()
    if address in ("", "*", "0.0.0.0", "::", "[::]", "127.0.0.1", "::1"):
        return "127.0.0.1"
    try:  # an IPv6 literal may carry a `%scope` suffix; the address is what matters
        parsed = ipaddress.ip_address(address.split("%")[0].strip("[]"))
    except ValueError:
        return "127.0.0.1"
    return f"[{parsed}]" if parsed.version == 6 else str(parsed)


#: A section that failed is a hole in the run, and a hole is not a fact: the
#: warning says so once, and the gauges of that section keep their last value
#: (`SECTION_GAUGES`) instead of publishing a zero nobody measured.
SECTION_WARNINGS: dict[str, str] = {
    "updates": "the pending-update count could not be read: it is unknown for this guest",
    "disks": "the disk list could not be read: free-space alerts are blind for this guest",
    "services": (
        "the service list could not be read: the tagged services are reported as unknown "
        "rather than down, so nothing pages on this run"
    ),
    "listeners": "the listening sockets could not be read: the application layer has no ports",
    "connections": "the established connections could not be read: dependencies are missing",
    "certificates": "the certificates could not be read: expiry is unknown for this guest",
    "packages": "the package list could not be read",
}


def section_warnings(errors: Mapping[str, str]) -> list[str]:
    return [
        SECTION_WARNINGS.get(key, f"the `{key}` section could not be collected")
        for key in sorted(errors)
    ]


NO_SUDO_WARNING = (
    "no passwordless sudo for `{binary}`: it runs unprivileged, so sockets are "
    "collected without the owning process and root-only certificates are missed. "
    "Run `infra onboard accounts <guest>` and install the sudoers allowlist."
)


def _section(errors: dict[str, str], key: str, fn: Callable[[], Any], default: Any) -> Any:
    """Run one collection section; a failure degrades to `default` plus an error."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - one bad section must not lose the run
        errors[key] = f"{type(exc).__name__}: {exc}"
        return default


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------
@dataclass
class LinuxSession:
    """A guest shell, the sudo decision it made, and what went wrong."""

    runner: CommandRunner
    now: datetime = field(default_factory=lambda: datetime.now(UTC))
    errors: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    _uid: int | None = None
    _sudo_denied: set[str] = field(default_factory=set)
    _sudo_used: bool = False

    def run(self, command: str, *, sudo: bool = False) -> CommandResult:
        """Run a fixed template, through `sudo -n` only when it is on the list.

        Availability is learned from the elevated commands themselves rather
        than from a separate `sudo -n true`: the sudoers file this project
        generates permits `SUDO_COMMANDS` and nothing else, so `true` is refused
        on a guest where sudo works perfectly and the whole run would silently
        drop to unprivileged.

        The refusal is remembered per binary, not globally: sudoers matches on
        the absolute path, so a guest without `ss` refuses `sudo -n ss ...`
        while still permitting `sudo -n netstat ...`.
        """
        if not sudo or self.is_root():
            return self.runner.run(command)
        if command not in SUDO_COMMANDS and not _is_templated_sudo_command(command):
            raise ValueError(f"refusing to sudo a command that is not on the allowlist: {command}")
        binary = command.split(" ", 1)[0]
        if binary in self._sudo_denied:
            return self.runner.run(command)
        result = self.runner.run(f"sudo -n {command}")
        if not sudo_refused(result):
            self._sudo_used = True
            return result
        self._sudo_denied.add(binary)
        self.warn(NO_SUDO_WARNING.format(binary=binary))
        return self.runner.run(command)

    def is_root(self) -> bool:
        if self._uid is None:
            result = self.runner.run(WHOAMI_COMMAND)
            self._uid = _int_or_none(result.stdout) if result.ok else -1
        return self._uid == 0

    @property
    def sudo_worked(self) -> bool:
        """True once an allowlisted command has actually been elevated."""
        return self._sudo_used or self.is_root()

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    def section(self, key: str, fn: Callable[[], Any], default: Any) -> Any:
        return _section(self.errors, key, fn, default)

    def first_ok(self, *commands: tuple[str, bool]) -> CommandResult | None:
        """The first command that exists on this guest, or None if none does."""
        last: CommandResult | None = None
        for command, sudo in commands:
            result = self.run(command, sudo=sudo)
            if result.ok or not result.missing:
                return result
            last = result
        return last


def _is_templated_sudo_command(command: str) -> bool:
    """`openssl x509 ... -in <path>` for a path the collector's own find returned."""
    prefix = CERT_READ_TEMPLATE.split("{path}")[0]
    return command.startswith(prefix)


def collect_linux(
    runner: CommandRunner, device: SeedDevice, now: datetime | None = None
) -> dict[str, Any]:
    """Every section of a Linux guest, from fixed commands, as rows."""
    session = LinuxSession(runner=runner, now=now or datetime.now(UTC))
    os_info = session.section("os", lambda: _linux_os(session), {})
    services = session.section("services", lambda: _linux_services(session), [])
    listeners = session.section("listeners", lambda: _linux_listeners(session), [])
    listening_ports = {int(row["port"]) for row in listeners if row.get("port") is not None}
    connections = session.section(
        "connections", lambda: _linux_connections(session, listening_ports), []
    )
    disks = session.section("disks", lambda: _linux_disks(session), [])
    packages = session.section("packages", lambda: _linux_packages(session), [])
    updates = session.section("updates", lambda: _linux_updates(session, os_info), {})
    certificates = session.section(
        "certificates", lambda: _linux_certificates(session, listeners), []
    )
    return {
        "os": os_info,
        "uptime_seconds": session.section("uptime", lambda: _linux_uptime(session), None),
        "cpu": session.section("cpu", lambda: _linux_cpu(session), {}),
        "memory": session.section("memory", lambda: _linux_memory(session), {}),
        "packages": packages[:MAX_PACKAGES],
        "updates": updates,
        "services": services[:MAX_SERVICES],
        "listeners": listeners[:MAX_LISTENERS],
        "connections": connections,
        "disks": disks,
        "certificates": certificates[:MAX_CERTIFICATES],
        "tagged_services": tagged_service_state(
            services,
            tagged_service_names(device.tags),
            known="services" not in session.errors,
        ),
        "privileged": session.is_root(),
        "sudo": session.sudo_worked,
        "warnings": list(session.warnings) + section_warnings(session.errors),
        "errors": dict(session.errors),
    }


def _linux_os(session: LinuxSession) -> dict[str, Any]:
    release = session.run(OS_RELEASE_COMMAND)
    info = parse_os_release(release.stdout) if release.ok else {}
    kernel = session.run(KERNEL_COMMAND)
    hostname = session.run(HOSTNAME_COMMAND)
    parts = kernel.stdout.split() if kernel.ok else []
    info["family"] = "linux"
    info["kernel"] = " ".join(parts[:2]) if len(parts) >= 2 else (kernel.stdout.strip() or None)
    info["arch"] = parts[2] if len(parts) > 2 else None
    info["hostname"] = hostname.stdout.strip() or None if hostname.ok else None
    return info


def _linux_uptime(session: LinuxSession) -> float | None:
    result = session.run(UPTIME_COMMAND)
    if not result.ok:
        return None
    return _float_or_none(result.stdout.split(" ")[0] if result.stdout.strip() else None)


def _linux_cpu(session: LinuxSession) -> dict[str, Any]:
    result = session.run(CPU_COMMAND)
    return {"count": _int_or_none(result.stdout) if result.ok else None}


def _linux_memory(session: LinuxSession) -> dict[str, Any]:
    result = session.run(MEMINFO_COMMAND)
    return parse_meminfo(result.stdout) if result.ok else {}


def _linux_packages(session: LinuxSession) -> list[dict[str, str]]:
    result = session.first_ok((DPKG_COMMAND, False), (RPM_COMMAND, False))
    if result is None or not result.ok:
        session.warn("neither dpkg-query nor rpm answered: the package list is empty")
        return []
    rows = parse_packages(result.stdout)
    if len(rows) > MAX_PACKAGES:
        session.warn(f"package list truncated to {MAX_PACKAGES} of {len(rows)}")
    return rows


def _linux_updates(session: LinuxSession, os_info: Mapping[str, Any]) -> dict[str, Any]:
    """Pending updates, tolerant of the exit codes both package managers use."""
    family = {str(os_info.get("id") or "").lower(), *(os_info.get("id_like") or [])}
    apt_first = bool(family & {"debian", "ubuntu"}) or not (
        family & {"rhel", "fedora", "centos", "rocky", "almalinux"}
    )
    order = (APT_UPGRADABLE_COMMAND, DNF_CHECK_COMMAND)
    if not apt_first:
        order = (DNF_CHECK_COMMAND, APT_UPGRADABLE_COMMAND)
    for command in order:
        result = session.run(command)
        if result.missing:
            continue
        if command == DNF_CHECK_COMMAND:
            if result.status not in (0, DNF_UPDATES_WAITING_STATUS):
                session.warn(f"`{command}` exited {result.status}: pending updates are unknown")
                continue
            rows = parse_dnf_check_update(result.stdout)
        else:
            if not result.ok:
                session.warn(f"`{command}` exited {result.status}: pending updates are unknown")
                continue
            rows = parse_apt_upgradable(result.stdout)
        return {
            "pending": len(rows),
            "source": command,
            "packages": [row["name"] for row in rows][:MAX_UPDATES],
        }
    session.warn("no package manager answered: the pending-update count is unknown")
    return {"pending": None, "source": None, "packages": []}


def _linux_services(session: LinuxSession) -> list[dict[str, Any]]:
    units = session.run(SYSTEMD_UNITS_COMMAND)
    if not units.ok:
        if units.missing:
            session.warn("systemd is not present: services were not collected")
            return []
        raise RuntimeError(f"`{SYSTEMD_UNITS_COMMAND}` exited {units.status}")
    rows = parse_systemd_units(units.stdout)
    files = session.run(SYSTEMD_UNIT_FILES_COMMAND)
    enabled = parse_unit_files(files.stdout) if files.ok else {}
    for row in rows:
        row["enabled"] = enabled.get(str(row["name"]))
    return rows


def _linux_listeners(session: LinuxSession) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for proto, ss_command, netstat_command in (
        ("tcp", SS_TCP_LISTEN_COMMAND, NETSTAT_TCP_LISTEN_COMMAND),
        ("udp", SS_UDP_LISTEN_COMMAND, NETSTAT_UDP_LISTEN_COMMAND),
    ):
        result = session.run(ss_command, sudo=True)
        if result.ok and result.stdout.strip():
            rows.extend(parse_ss_listeners(result.stdout, proto))
            continue
        if result.missing:
            session.warn("iproute2 (`ss`) is not installed: falling back to netstat")
        fallback = session.run(netstat_command, sudo=True)
        if fallback.ok:
            rows.extend(parse_netstat_listeners(fallback.stdout, proto))
        elif not result.ok:
            session.warn(f"neither `{ss_command}` nor `{netstat_command}` answered")
    rows.sort(key=lambda row: (str(row["proto"]), int(row["port"]), str(row["address"])))
    if len(rows) > MAX_LISTENERS:
        session.warn(f"listener list truncated to {MAX_LISTENERS} of {len(rows)}")
    return rows


def _linux_connections(session: LinuxSession, listening_ports: set[int]) -> list[dict[str, Any]]:
    result = session.run(SS_ESTABLISHED_COMMAND, sudo=True)
    if result.ok:
        rows = parse_ss_established(result.stdout)
    else:
        if result.missing:
            session.warn("iproute2 (`ss`) is not installed: falling back to netstat")
        fallback = session.run(NETSTAT_ESTABLISHED_COMMAND, sudo=True)
        if not fallback.ok:
            session.warn("established connections could not be read")
            return []
        rows = parse_netstat_established(fallback.stdout)
    return summarise_connections(rows, listening_ports)


def _linux_disks(session: LinuxSession) -> list[dict[str, Any]]:
    result = session.run(DF_COMMAND)
    if not result.ok:
        raise RuntimeError(f"`{DF_COMMAND}` exited {result.status}")
    return parse_df(result.stdout)


def _linux_certificates(
    session: LinuxSession, listeners: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """Certificates on disk and certificates actually served, public fields only."""
    rows: list[dict[str, Any]] = []
    found = session.run(CERT_FIND_COMMAND, sudo=True)
    # `find` exits non-zero when one of the fixed directories is absent, which is
    # the normal case (a guest has nginx or apache, not both); its stdout is
    # still the list of everything it did find.
    paths = [line.strip() for line in found.stdout.splitlines() if line.strip()]
    for path in paths[:MAX_CERTIFICATES]:
        if not _safe_cert_path(path):
            continue
        parsed = _read_certificate(session, path)
        if parsed is None:
            continue
        rows.append(_with_days({**parsed, "source": path, "kind": "file"}, session.now))
    for target in tls_probe_targets(listeners):
        command = TLS_PROBE_TEMPLATE.format(
            host=target["host"],
            port=int(target["port"]),
            timeout=TLS_PROBE_TIMEOUT_SECONDS,
        )
        result = session.run(command)
        parsed = parse_openssl_x509(result.stdout) if result.ok else None
        if parsed is None:
            continue
        rows.append(
            _with_days(
                {
                    **parsed,
                    "source": f"{target['host']}:{target['port']}",
                    "kind": "listener",
                    "port": int(target["port"]),
                    "process": target.get("process"),
                },
                session.now,
            )
        )
    return rows


def _read_certificate(session: LinuxSession, path: str) -> dict[str, Any] | None:
    """The public fields of one certificate, unprivileged first.

    Most certificates are world-readable (`/etc/nginx/ssl/...`) and only Let's
    Encrypt's `live/` directory needs root. The sudoers allowlist can only name
    the paths it knows about, so reading unprivileged first means a certificate
    outside that glob is still collected instead of being lost to a sudo refusal.
    """
    command = CERT_READ_TEMPLATE.format(path=shlex.quote(path))
    result = session.run(command)
    if not result.ok:
        result = session.run(command, sudo=True)
    return parse_openssl_x509(result.stdout) if result.ok else None


_CERT_PATH = re.compile(r"^/[A-Za-z0-9._/@+-]+$")


def _safe_cert_path(path: str) -> bool:
    """Only absolute paths under the configured directories are ever opened."""
    return bool(_CERT_PATH.match(path)) and path.startswith(tuple(CERT_PATHS))


def tagged_service_state(
    services: Sequence[Mapping[str, Any]], wanted: Sequence[str], *, known: bool = True
) -> list[dict[str, Any]]:
    """The state of exactly the services the guest is tagged with.

    The tag is what an operator typed, not a unit name: `service:postgresql`
    means the `postgresql@14-main.service` instance that guest actually runs.
    Exact names win, then the `.service` suffix, then the instance base before
    the `@`. A tag that still matches nothing is reported `found: false` and
    `active: false` - a service that was supposed to be there and is not is the
    alert, not a missing series.

    `known=False` says the service list itself could not be read this run
    (`systemctl` failed, the channel timed out). Then every row is `None`:
    "not collected" must never become "every tagged service is down", which
    would page the owner for the whole guest on one transient failure.
    """
    if not known:
        return [
            {
                "service": service,
                "unit": None,
                "found": None,
                "state": None,
                "active": None,
                "enabled": None,
            }
            for service in wanted
        ]
    by_name: dict[str, Mapping[str, Any]] = {}
    for row in services:
        name = str(row.get("name") or "")
        if not name:
            continue
        by_name[name.lower()] = row
        stem = name.lower().removesuffix(".service")
        by_name.setdefault(stem, row)
        by_name.setdefault(stem.split("@")[0], row)
    rows: list[dict[str, Any]] = []
    for service in wanted:
        row = by_name.get(service.lower()) or by_name.get(f"{service.lower()}.service")
        state = str((row or {}).get("active") or (row or {}).get("state") or "")
        rows.append(
            {
                "service": service,
                "unit": (row or {}).get("name"),
                "found": row is not None,
                "state": state or None,
                "active": _is_active(state),
                "enabled": (row or {}).get("enabled"),
            }
        )
    return rows


def _is_active(state: str) -> bool:
    return state.strip().lower() in {"active", "running"} or state.strip() in WINDOWS_RUNNING_STATES


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------
def _json_rows(result: CommandResult) -> list[dict[str, Any]]:
    """PowerShell's ConvertTo-Json emits an object for one row and a list for many."""
    if not result.ok or not result.stdout.strip():
        return []
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(payload, dict):
        return [payload]
    return [row for row in payload if isinstance(row, dict)]


def _json_object(result: CommandResult) -> dict[str, Any]:
    rows = _json_rows(result)
    return rows[0] if rows else {}


_PS_DATE = re.compile(r"^/Date\((?P<ms>-?\d+)")


def parse_windows_datetime(value: Any) -> datetime | None:
    """PowerShell serialises DateTime as ISO-8601 or as `/Date(ms)/`."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str) or not value.strip():
        return None
    match = _PS_DATE.match(value.strip())
    if match:
        return datetime.fromtimestamp(int(match.group("ms")) / 1000.0, tz=UTC)
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def collect_windows(
    runner: CommandRunner, device: SeedDevice, now: datetime | None = None
) -> dict[str, Any]:
    """Every section of a Windows guest, from fixed PowerShell templates."""
    moment = now or datetime.now(UTC)
    errors: dict[str, str] = {}
    warnings: list[str] = []

    def section(key: str, fn: Callable[[], Any], default: Any) -> Any:
        return _section(errors, key, fn, default)

    info = section("os", lambda: _windows_os(runner, moment), {})
    services = section("services", lambda: _windows_services(runner), [])
    listeners = section("listeners", lambda: _windows_listeners(runner), [])
    listening_ports = {int(row["port"]) for row in listeners if row.get("port") is not None}
    connections = section("connections", lambda: _windows_connections(runner, listening_ports), [])
    disks = section("disks", lambda: _windows_disks(runner), [])
    packages = section("packages", lambda: _windows_packages(runner), [])
    updates = section("updates", lambda: _windows_updates(runner), {})
    certificates = section("certificates", lambda: _windows_certificates(runner, moment), [])
    hotfixes = section("hotfixes", lambda: _windows_hotfixes(runner), [])
    if "updates" in errors:
        warnings.append(
            "the Windows Update agent could not be queried over WinRM; "
            "the pending-update count is unknown for this guest"
        )
    warnings.extend(section_warnings({k: v for k, v in errors.items() if k != "updates"}))
    return {
        "os": info.get("os", {}),
        "uptime_seconds": info.get("uptime_seconds"),
        "cpu": info.get("cpu", {}),
        "memory": info.get("memory", {}),
        "packages": packages[:MAX_PACKAGES],
        "updates": updates,
        "services": services[:MAX_SERVICES],
        "listeners": listeners[:MAX_LISTENERS],
        "connections": connections,
        "disks": disks,
        "certificates": certificates[:MAX_CERTIFICATES],
        "hotfixes": hotfixes,
        "tagged_services": tagged_service_state(
            services, tagged_service_names(device.tags), known="services" not in errors
        ),
        "warnings": warnings,
        "errors": errors,
    }


def _windows_os(runner: CommandRunner, now: datetime) -> dict[str, Any]:
    row = _json_object(runner.run(PS_COMPUTER_INFO))
    boot = parse_windows_datetime(row.get("OsLastBootUpTime"))
    memory = _int_or_none(row.get("CsTotalPhysicalMemory"))
    return {
        "os": {
            "family": "windows",
            "id": "windows",
            "name": row.get("OsName"),
            "version": row.get("OsVersion"),
            "build": row.get("OsBuildNumber"),
            "arch": row.get("OsArchitecture"),
            "hostname": row.get("CsName"),
            "domain": row.get("CsDomain"),
        },
        "uptime_seconds": round((now - boot).total_seconds(), 1) if boot else None,
        "cpu": {"count": _int_or_none(row.get("CsNumberOfLogicalProcessors"))},
        "memory": {"total_bytes": memory},
    }


def _windows_services(runner: CommandRunner) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in _json_rows(runner.run(PS_SERVICES)):
        state = str(row.get("Status") or "")
        rows.append(
            {
                "name": row.get("Name"),
                "description": row.get("DisplayName"),
                "load": "loaded",
                "active": "active" if _is_active(state) else "inactive",
                "sub": state.lower() or None,
                "state": state,
                "enabled": str(row.get("StartType") or "") or None,
            }
        )
    rows.sort(key=lambda row: str(row["name"]))
    return rows


def _windows_listeners(runner: CommandRunner) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in _json_rows(runner.run(PS_LISTENERS)):
        port = _int_or_none(row.get("LocalPort"))
        if port is None:
            continue
        rows.append(
            {
                "proto": "tcp",
                "address": str(row.get("LocalAddress") or ""),
                "port": port,
                "process": row.get("Process"),
                "pid": _int_or_none(row.get("ProcessId")),
                "state": "listen",
            }
        )
    rows.sort(key=lambda row: (int(row["port"]), str(row["address"])))
    return rows


def _windows_connections(runner: CommandRunner, listening_ports: set[int]) -> list[dict[str, Any]]:
    established = [
        {
            "local_port": _int_or_none(row.get("LocalPort")),
            "remote_ip": str(row.get("RemoteAddress") or ""),
            "remote_port": _int_or_none(row.get("RemotePort")),
            "process": row.get("Process"),
            "pid": _int_or_none(row.get("ProcessId")),
        }
        for row in _json_rows(runner.run(PS_ESTABLISHED))
    ]
    return summarise_connections(established, listening_ports)


def _windows_disks(runner: CommandRunner) -> list[dict[str, Any]]:
    """Fixed disks, from `Get-Volume` if the account may read it, else CIM."""
    primary = runner.run(PS_VOLUMES)
    rows = _volume_rows(_json_rows(primary))
    if rows:
        return rows
    fallback = runner.run(PS_LOGICAL_DISKS)
    rows = _logical_disk_rows(_json_rows(fallback))
    if rows or fallback.ok:
        return rows
    raise RuntimeError(
        f"neither `Get-Volume` (exit {primary.status}) nor `Win32_LogicalDisk` "
        f"(exit {fallback.status}) returned a disk"
    )


def _disk_row(
    mount: str, label: Any, filesystem: Any, total: float | None, free: float | None, **extra: Any
) -> dict[str, Any] | None:
    if not mount or total is None or free is None or total <= 0:
        return None
    return {
        "filesystem": filesystem,
        "mount": mount,
        "label": label,
        "total_bytes": int(total),
        "used_bytes": int(total - free),
        "free_bytes": int(free),
        "free_ratio": round(free / total, 4),
        **extra,
    }


def _volume_rows(payload: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any] | None] = []
    for row in payload:
        letter = str(row.get("DriveLetter") or "").strip()
        rows.append(
            _disk_row(
                f"{letter}:" if letter else "",
                row.get("FileSystemLabel"),
                row.get("FileSystem"),
                _float_or_none(row.get("Size")),
                _float_or_none(row.get("SizeRemaining")),
                health=row.get("HealthStatus"),
            )
        )
    return [row for row in rows if row is not None]


def _logical_disk_rows(payload: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows = [
        _disk_row(
            str(row.get("DeviceID") or "").strip(),
            row.get("VolumeName"),
            row.get("FileSystem"),
            _float_or_none(row.get("Size")),
            _float_or_none(row.get("FreeSpace")),
            source="Win32_LogicalDisk",
        )
        for row in payload
    ]
    return [row for row in rows if row is not None]


def _windows_packages(runner: CommandRunner) -> list[dict[str, Any]]:
    rows = [
        {
            "name": str(row.get("DisplayName") or "").strip(),
            "version": str(row.get("DisplayVersion") or "").strip(),
            "publisher": row.get("Publisher"),
        }
        for row in _json_rows(runner.run(PS_PROGRAMS))
    ]
    return sorted((row for row in rows if row["name"]), key=lambda row: row["name"])


def _windows_updates(runner: CommandRunner) -> dict[str, Any]:
    result = runner.run(PS_PENDING_UPDATES)
    if not result.ok:
        raise RuntimeError(f"the Windows Update search exited {result.status}")
    titles = [str(row.get("Title") or "") for row in _json_rows(result)]
    return {
        "pending": len(titles),
        "source": "Microsoft.Update.Session",
        "packages": [title for title in titles if title][:MAX_UPDATES],
    }


def _windows_hotfixes(runner: CommandRunner) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in _json_rows(runner.run(PS_HOTFIX)):
        installed = parse_windows_datetime(row.get("InstalledOn"))
        rows.append(
            {
                "id": row.get("HotFixID"),
                "description": row.get("Description"),
                "installed_at": installed.isoformat() if installed else None,
            }
        )
    return rows


def _windows_certificates(runner: CommandRunner, now: datetime) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in _json_rows(runner.run(PS_CERTIFICATES)):
        expiry = parse_windows_datetime(row.get("NotAfter"))
        names = row.get("DnsNameList")
        sans = (
            [str(n) for n in names] if isinstance(names, list) else ([str(names)] if names else [])
        )
        rows.append(
            {
                "subject": _normalise_dn(str(row.get("Subject") or "")),
                "issuer": _normalise_dn(str(row.get("Issuer") or "")),
                "not_after": expiry.isoformat() if expiry else None,
                "days_to_expiry": snapshot_days_to_expiry(expiry, now),
                "sans": sorted(dict.fromkeys(sans)),
                "source": f"Cert:\\LocalMachine\\My\\{row.get('Thumbprint')}",
                "kind": "store",
                "thumbprint": row.get("Thumbprint"),
            }
        )
    return rows


# ---------------------------------------------------------------------------
# collectors
# ---------------------------------------------------------------------------
class _GuestBase(Collector):
    """Shared metric publishing for both guest kinds."""

    name = "guest"
    interval_seconds = GUEST_INTERVAL_SECONDS

    def runner(self, device: SeedDevice, cred: Credential) -> CommandRunner:
        raise NotImplementedError

    def gather(
        self, runner: CommandRunner, device: SeedDevice, now: datetime | None = None
    ) -> dict[str, Any]:
        raise NotImplementedError

    def collect(self, device: SeedDevice, cred: Credential) -> dict[str, Any]:
        runner = self.runner(device, cred)
        try:
            data = self.gather(runner, device)
        finally:
            try:
                runner.close()
            except Exception as exc:  # noqa: BLE001 - never fail a run on teardown
                log.debug("closing the guest session for %s failed: %s", device.name, exc)
        self.publish_metrics(device.name, data)
        return data

    @staticmethod
    def spared_gauges(errors: Mapping[str, str]) -> list[Any]:
        spared: list[Any] = []
        for section, gauges in SECTION_GAUGES:
            if section in errors:
                spared.extend(gauges)
        return spared

    def publish_metrics(self, device_name: str, data: Mapping[str, Any]) -> None:
        """Set this run's gauges and drop the series of objects that are gone.

        A filesystem that is unmounted, a certificate that is renewed under a
        new subject and a service whose tag was removed all keep their last
        value forever otherwise, and the alert built on them can never resolve.
        """
        run = _SERIES.run(device_name)
        pending = (data.get("updates") or {}).get("pending")
        if pending is not None:
            run.set(metrics.GUEST_PENDING_UPDATES, float(pending), device=device_name)

        for row in data.get("tagged_services") or []:
            service = str(row.get("service") or "")
            active = row.get("active")
            # `active is None` means the service list could not be read this
            # run. Publishing 0 there would fire GuestServiceDown (critical)
            # for every tagged service on one transient systemctl failure; the
            # series is spared from the sweep instead and keeps its last value.
            if service and active is not None:
                run.set(
                    metrics.GUEST_SERVICE_ACTIVE,
                    1.0 if active else 0.0,
                    device=device_name,
                    service=service,
                )

        for row in data.get("disks") or []:
            mount = str(row.get("mount") or "")
            free = _float_or_none(row.get("free_bytes"))
            total = _float_or_none(row.get("total_bytes"))
            if not mount or free is None or total is None:
                continue
            run.set(metrics.GUEST_DISK_FREE_BYTES, free, device=device_name, mount=mount)
            run.set(metrics.GUEST_DISK_TOTAL_BYTES, total, device=device_name, mount=mount)

        for row in data.get("certificates") or []:
            days = _float_or_none(row.get("days_to_expiry"))
            source = str(row.get("source") or common_name(row.get("subject")) or "")
            if days is None or not source:
                continue
            run.set(
                metrics.GUEST_CERTIFICATE_DAYS_TO_EXPIRY,
                days,
                device=device_name,
                certificate=source,
            )

        run.sweep(skip=self.spared_gauges(data.get("errors") or {}))


@register
class GuestLinuxCollector(_GuestBase):
    """One Linux guest over SSH, read-only, with an unprivileged account."""

    kind = DeviceKind.guest_linux

    def runner(self, device: SeedDevice, cred: Credential) -> CommandRunner:
        return SshRunner(device, cred)

    def gather(
        self, runner: CommandRunner, device: SeedDevice, now: datetime | None = None
    ) -> dict[str, Any]:
        return collect_linux(runner, device, now)


@register
class GuestWindowsCollector(_GuestBase):
    """One Windows guest over WinRM, read-only PowerShell templates."""

    kind = DeviceKind.guest_windows

    def runner(self, device: SeedDevice, cred: Credential) -> CommandRunner:
        return WinRmRunner(device, cred)

    def gather(
        self, runner: CommandRunner, device: SeedDevice, now: datetime | None = None
    ) -> dict[str, Any]:
        return collect_windows(runner, device, now)


def stale_guest(device: str) -> None:
    """Forget a guest's series (used when a guest leaves the inventory)."""
    _SERIES.forget(device)


__all__ = [
    "CERT_EXPIRY_WARN_DAYS",
    "CERT_PATHS",
    "GUEST_INTERVAL_SECONDS",
    "SUDO_COMMANDS",
    "SUDO_TEST_COMMAND",
    "CommandResult",
    "CommandRunner",
    "GuestLinuxCollector",
    "GuestWindowsCollector",
    "SshRunner",
    "WinRmRunner",
    "collect_linux",
    "collect_windows",
    "expiring_certificates",
    "snapshot_days_to_expiry",
    "stale_guest",
    "sudo_refused",
    "tagged_service_names",
]
