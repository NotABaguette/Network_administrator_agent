"""Guest executor: services, packages and reboots inside a VM.

Two transports, chosen by `DeviceKind`: `guest_linux` goes over SSH
(paramiko), `guest_windows` over WinRM (pywinrm). Both share the executor's
logic through a :class:`Dialect`, which is the only place a command string is
built.

Nothing here interpolates a caller's string into a shell. Every parameter is
checked against a character allowlist first and then quoted — `shlex.quote` for
the POSIX shell, PowerShell single-quote doubling for WinRM — so the templates
below are the complete set of things this executor can run. That matters more
here than anywhere else in the estate: a guest command runs as root or
SYSTEM, and the model can propose the parameters.

Rollback is what the previous state says it should be:

* a service action restores the ActiveState / Status captured before it ran;
* a package update has no automatic rollback — the previous versions are
  recorded and the rollback fails loudly so the owner is paged rather than
  told a lie;
* a reboot cannot be undone.

`guest.reboot` is a Tier 2 action and refuses to run unless the plan carries
`params.window_confirmed`, so an executor-level mistake cannot reboot a
production guest outside its window even if the engine's own gate is wrong.
"""

from __future__ import annotations

import logging
import re
import shlex
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from infra_agent.change.executors.base import (
    CheckResult,
    DryRunResult,
    ExecutionContext,
    Executor,
    StepResult,
    register,
)
from infra_agent.change.plan import ChangeStep
from infra_agent.models.common import DeviceKind, SeedDevice

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 60.0
#: A distribution upgrade is slow; a service restart is not.
PACKAGE_TIMEOUT = 900.0
SERVICE_SETTLE_SECONDS = 2.0

ACTIONS = frozenset(
    {
        "guest.service_restart",
        "guest.service_stop",
        "guest.service_start",
        "guest.package_update",
        "guest.reboot",
    }
)

ACTIVE = "active"
INACTIVE = "inactive"

#: Service names. Windows allows spaces and parentheses ("SQL Server (X)");
#: neither dialect allows anything a shell or PowerShell would look at.
SERVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@()+-]{0,79}$")
#: Package names, including the `name.arch` spelling `dnf` reports.
PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$")

#: A dropped session right after a reboot command is the expected outcome, not
#: a failure; anything mentioning permissions is a real refusal.
_REFUSAL_HINT = re.compile(r"(permission|denied|not authorized|access is denied|sudo)", re.I)


class GuestError(RuntimeError):
    """A refusal or a guest-side failure, safe to show."""


def short_error(exc: Exception) -> str:
    return f"{type(exc).__name__}: {str(exc).strip()[:200]}"


@dataclass
class CommandResult:
    command: str
    rc: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.rc == 0

    def check(self, allow: tuple[int, ...] = (0,)) -> CommandResult:
        if self.rc not in allow:
            detail = (self.stderr or self.stdout).strip().splitlines()
            raise GuestError(
                f"{self.command.split()[0]} exited {self.rc}: "
                f"{detail[-1][:160] if detail else 'no output'}"
            )
        return self


# ---------------------------------------------------------------------------
# quoting
# ---------------------------------------------------------------------------
def sh_quote(value: Any) -> str:
    return shlex.quote(str(value))


def ps_quote(value: Any) -> str:
    """A PowerShell single-quoted literal; `'` is escaped by doubling it."""
    return "'" + str(value).replace("'", "''") + "'"


def checked(value: Any, pattern: re.Pattern[str], what: str) -> str:
    text = str(value or "").strip()
    if not pattern.match(text):
        raise GuestError(f"{what} {text!r} is not a name this executor will send to a guest")
    return text


# ---------------------------------------------------------------------------
# dialects: the only place a command string is built
# ---------------------------------------------------------------------------
@dataclass
class PendingPackage:
    name: str
    current: str | None = None
    available: str | None = None


class Dialect(Protocol):
    name: str
    active_value: str
    inactive_value: str

    def service_state(self, service: str) -> str: ...
    def parse_service_state(self, out: str) -> str: ...
    def service_restart(self, service: str) -> str: ...
    def service_stop(self, service: str) -> str: ...
    def service_start(self, service: str) -> str: ...
    def detect_manager(self) -> str: ...
    def pending_upgrades(self, manager: str) -> tuple[str, tuple[int, ...]]: ...
    def parse_pending(self, manager: str, out: str) -> list[PendingPackage]: ...
    def apply_upgrades(self, manager: str) -> str: ...
    def installed_versions(self, manager: str, packages: list[str]) -> str | None: ...
    def parse_versions(self, out: str) -> dict[str, str]: ...
    def reboot(self) -> str: ...
    def uptime(self) -> str: ...
    def parse_uptime(self, out: str) -> float | None: ...
    def listening(self, port: int) -> str: ...
    def parse_listening(self, port: int, out: str) -> bool: ...


APT_INST = re.compile(r"^Inst\s+(\S+)\s+\[([^\]]*)\]\s+\(([^\s)]+)")


@dataclass
class LinuxDialect:
    """systemd, apt/dnf and coreutils over a POSIX shell."""

    name: str = "linux"
    active_value: str = ACTIVE
    inactive_value: str = INACTIVE

    def service_state(self, service: str) -> str:
        return f"systemctl show -p ActiveState --value -- {sh_quote(service)}"

    def parse_service_state(self, out: str) -> str:
        return (out or "").strip().splitlines()[0].strip() if (out or "").strip() else "unknown"

    def service_restart(self, service: str) -> str:
        return f"systemctl restart -- {sh_quote(service)}"

    def service_stop(self, service: str) -> str:
        return f"systemctl stop -- {sh_quote(service)}"

    def service_start(self, service: str) -> str:
        return f"systemctl start -- {sh_quote(service)}"

    def detect_manager(self) -> str:
        # A fixed template with nothing interpolated into it.
        return (
            "if command -v apt-get >/dev/null 2>&1; then echo apt; "
            "elif command -v dnf >/dev/null 2>&1; then echo dnf; "
            "else echo unknown; fi"
        )

    def pending_upgrades(self, manager: str) -> tuple[str, tuple[int, ...]]:
        if manager == "apt":
            return "apt-get --simulate --quiet upgrade", (0,)
        # `dnf check-update` exits 100 when there is something to install.
        return "dnf --quiet check-update", (0, 100)

    def parse_pending(self, manager: str, out: str) -> list[PendingPackage]:
        rows: list[PendingPackage] = []
        if manager == "apt":
            for line in (out or "").splitlines():
                match = APT_INST.match(line.strip())
                if match:
                    rows.append(
                        PendingPackage(match.group(1), match.group(2) or None, match.group(3))
                    )
            return rows
        started = False
        for line in (out or "").splitlines():
            text = line.strip()
            if not text:
                started = True  # dnf prints a blank line before the table
                continue
            if text.lower().startswith(("last metadata", "obsoleting", "security:")):
                continue
            fields = text.split()
            if started and len(fields) >= 2 and PACKAGE_NAME.match(fields[0]):
                rows.append(PendingPackage(fields[0].rsplit(".", 1)[0], None, fields[1]))
        return rows

    def apply_upgrades(self, manager: str) -> str:
        if manager == "apt":
            return "DEBIAN_FRONTEND=noninteractive apt-get --yes --quiet upgrade"
        return "dnf --assumeyes --quiet upgrade"

    def installed_versions(self, manager: str, packages: list[str]) -> str | None:
        if not packages:
            return None
        names = " ".join(sh_quote(p) for p in packages)
        if manager == "apt":
            return f"dpkg-query -W -f='${{Package}} ${{Version}}\\n' -- {names}"
        return f"rpm -q --qf '%{{NAME}} %{{VERSION}}-%{{RELEASE}}\\n' -- {names}"

    def parse_versions(self, out: str) -> dict[str, str]:
        versions: dict[str, str] = {}
        for line in (out or "").splitlines():
            fields = line.split()
            if len(fields) >= 2:
                versions[fields[0]] = fields[1]
        return versions

    def reboot(self) -> str:
        # A one-minute delay so the command returns before the box goes down.
        return "shutdown -r +1"

    def uptime(self) -> str:
        return "cat /proc/uptime"

    def parse_uptime(self, out: str) -> float | None:
        try:
            return float((out or "").split()[0])
        except (IndexError, ValueError):
            return None

    def listening(self, port: int) -> str:
        return "ss -H -ltn"

    def parse_listening(self, port: int, out: str) -> bool:
        for line in (out or "").splitlines():
            for field_text in line.split():
                if ":" in field_text and field_text.rsplit(":", 1)[-1] == str(port):
                    return True
        return False


WINGET_ROW = re.compile(
    r"^(?P<name>.+?)\s{2,}(?P<id>\S+)\s{2,}(?P<version>\S+)\s{2,}(?P<available>\S+)"
)


@dataclass
class WindowsDialect:
    """PowerShell over WinRM. Every value is a single-quoted literal."""

    name: str = "windows"
    active_value: str = "Running"
    inactive_value: str = "Stopped"

    def service_state(self, service: str) -> str:
        return (
            f"$s = Get-Service -Name {ps_quote(service)} -ErrorAction SilentlyContinue; "
            "if ($s) { $s.Status.ToString() } else { 'missing' }"
        )

    def parse_service_state(self, out: str) -> str:
        return (out or "").strip().splitlines()[0].strip() if (out or "").strip() else "unknown"

    def service_restart(self, service: str) -> str:
        return f"Restart-Service -Name {ps_quote(service)} -Force"

    def service_stop(self, service: str) -> str:
        return f"Stop-Service -Name {ps_quote(service)} -Force"

    def service_start(self, service: str) -> str:
        return f"Start-Service -Name {ps_quote(service)}"

    def detect_manager(self) -> str:
        return (
            "if (Get-Command winget -ErrorAction SilentlyContinue) { 'winget' } else { 'unknown' }"
        )

    def pending_upgrades(self, manager: str) -> tuple[str, tuple[int, ...]]:
        return "winget upgrade --accept-source-agreements", (0,)

    def parse_pending(self, manager: str, out: str) -> list[PendingPackage]:
        rows: list[PendingPackage] = []
        started = False
        for line in (out or "").splitlines():
            if set(line.strip()) == {"-"} and line.strip():
                started = True
                continue
            if not started or not line.strip():
                continue
            match = WINGET_ROW.match(line.rstrip())
            if match:
                rows.append(
                    PendingPackage(
                        match.group("id"), match.group("version"), match.group("available")
                    )
                )
        return rows

    def apply_upgrades(self, manager: str) -> str:
        return (
            "winget upgrade --all --silent --accept-package-agreements --accept-source-agreements"
        )

    def installed_versions(self, manager: str, packages: list[str]) -> str | None:
        return "winget list --accept-source-agreements" if packages else None

    def parse_versions(self, out: str) -> dict[str, str]:
        versions: dict[str, str] = {}
        started = False
        for line in (out or "").splitlines():
            if set(line.strip()) == {"-"} and line.strip():
                started = True
                continue
            if not started or not line.strip():
                continue
            fields = re.split(r"\s{2,}", line.strip())
            if len(fields) >= 3:
                versions[fields[1]] = fields[2]
        return versions

    def reboot(self) -> str:
        return "Restart-Computer -Force"

    def uptime(self) -> str:
        return (
            "[int]((Get-Date) - (Get-CimInstance Win32_OperatingSystem)"
            ".LastBootUpTime).TotalSeconds"
        )

    def parse_uptime(self, out: str) -> float | None:
        try:
            return float((out or "").strip().splitlines()[0])
        except (IndexError, ValueError):
            return None

    def listening(self, port: int) -> str:
        return (
            f"if (Get-NetTCPConnection -State Listen -LocalPort {int(port)} "
            "-ErrorAction SilentlyContinue) { 'listening' } else { 'no' }"
        )

    def parse_listening(self, port: int, out: str) -> bool:
        return "listening" in (out or "").lower()


DIALECTS: dict[DeviceKind, Callable[[], Dialect]] = {
    DeviceKind.guest_linux: LinuxDialect,
    DeviceKind.guest_windows: WindowsDialect,
}


# ---------------------------------------------------------------------------
# transports
# ---------------------------------------------------------------------------
class GuestTransport(Protocol):
    name: str

    def run(self, ctx: ExecutionContext, command: str, timeout: float) -> CommandResult: ...


class SshGuestTransport:
    """paramiko against a Linux guest, with the read-write credential."""

    name = "ssh"

    def __init__(self, connect: Callable[[SeedDevice, Any], Any] | None = None) -> None:
        self._connect = connect

    def client(self, ctx: ExecutionContext) -> Any:
        if self._connect is not None:
            return self._connect(ctx.device, ctx.credential)
        import paramiko  # lazy: optional dependency

        from infra_agent.tools.observability_tools import ssh_known_hosts

        client = paramiko.SSHClient()
        known_hosts = ssh_known_hosts()
        if known_hosts:
            client.load_host_keys(known_hosts)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cred = ctx.credential
        client.connect(
            hostname=ctx.device.mgmt_ip,
            port=ctx.device.port or 22,
            username=cred.username,
            password=cred.password.get_secret_value() if cred.password else None,
            key_filename=cred.ssh_key_path,
            timeout=30,
            allow_agent=False,
            look_for_keys=False,
        )
        return client

    def run(self, ctx: ExecutionContext, command: str, timeout: float) -> CommandResult:
        client = self.client(ctx)
        try:
            _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            rc = getattr(getattr(stdout, "channel", None), "recv_exit_status", lambda: 0)()
        finally:
            try:
                client.close()
            except Exception:  # noqa: BLE001 - closing a dead session is not an error
                pass
        return CommandResult(command=command, rc=int(rc), stdout=out, stderr=err)


class WinRmGuestTransport:
    """pywinrm against a Windows guest; every command is PowerShell."""

    name = "winrm"

    def __init__(self, session: Callable[[SeedDevice, Any], Any] | None = None) -> None:
        self._session = session

    def session(self, ctx: ExecutionContext) -> Any:
        if self._session is not None:
            return self._session(ctx.device, ctx.credential)
        import winrm  # lazy: optional dependency

        cred = ctx.credential
        return winrm.Session(
            f"https://{ctx.device.mgmt_ip}:{ctx.device.port or 5986}/wsman",
            auth=(cred.username or "", cred.password.get_secret_value() if cred.password else ""),
            transport="ntlm",
            server_cert_validation="ignore",  # pinned in Phase 1, as the rest is
        )

    def run(self, ctx: ExecutionContext, command: str, timeout: float) -> CommandResult:
        response = self.session(ctx).run_ps(command)
        return CommandResult(
            command=command,
            rc=int(getattr(response, "status_code", 0)),
            stdout=_text(getattr(response, "std_out", "")),
            stderr=_text(getattr(response, "std_err", "")),
        )


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value or "")


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------
CHECK_SERVICE = re.compile(r"^service\s+(?P<name>.+?)\s+(?P<state>active|inactive)$", re.I)
CHECK_PORT = re.compile(r"^port\s+(?P<port>\d{1,5})\s+listening$", re.I)
CHECK_UPTIME = re.compile(
    r"^uptime\s*(?P<op>[<>])\s*(?P<amount>\d+(?:\.\d+)?)\s*(?P<unit>[smhd])?$", re.I
)
UNIT_SECONDS = {"s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}

CHECK_GRAMMAR = (
    "service <name> active|inactive",
    "port <n> listening",
    "uptime < 10m",
)

SERVICE_ACTIONS = {
    "guest.service_restart": "restart",
    "guest.service_stop": "stop",
    "guest.service_start": "start",
}


@dataclass
class _Ran:
    """Commands one step issued, for the diff and for the audit trail."""

    commands: list[str] = field(default_factory=list)

    def add(self, result: CommandResult) -> CommandResult:
        self.commands.append(result.command)
        return result


@register
class GuestExecutor(Executor):
    """Service, package and reboot changes inside a Linux or Windows guest."""

    platform = "guest"

    def __init__(
        self,
        linux: GuestTransport | None = None,
        windows: GuestTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._linux = linux
        self._windows = windows
        self.sleep = sleep

    # -- contract ---------------------------------------------------------
    def supported_actions(self) -> set[str]:
        return set(ACTIONS)

    def transport(self, device: SeedDevice) -> GuestTransport:
        if device.kind is DeviceKind.guest_windows:
            return self._windows or WinRmGuestTransport()
        if device.kind is DeviceKind.guest_linux:
            return self._linux or SshGuestTransport()
        raise GuestError(f"{device.kind.value} is not a guest this executor drives")

    def dialect(self, device: SeedDevice) -> Dialect:
        factory = DIALECTS.get(device.kind)
        if factory is None:
            raise GuestError(f"{device.kind.value} has no command dialect")
        return factory()

    # -- plumbing ---------------------------------------------------------
    def _run(
        self,
        ctx: ExecutionContext,
        command: str,
        timeout: float = DEFAULT_TIMEOUT,
        allow: tuple[int, ...] = (0,),
        ran: _Ran | None = None,
    ) -> CommandResult:
        result = self.transport(ctx.device).run(ctx, command, timeout)
        if ran is not None:
            ran.add(result)
        return result.check(allow)

    def _service_state(self, ctx: ExecutionContext, service: str) -> str:
        dialect = self.dialect(ctx.device)
        # `systemctl show` answers for an unknown unit too, so a non-zero exit
        # is tolerated here and the parsed value is what decides.
        result = self.transport(ctx.device).run(
            ctx, dialect.service_state(service), DEFAULT_TIMEOUT
        )
        return dialect.parse_service_state(result.stdout)

    def _is_active(self, device: SeedDevice, state: str) -> bool:
        return state.strip().lower() == self.dialect(device).active_value.lower()

    def _manager(self, ctx: ExecutionContext, step: ChangeStep, ran: _Ran | None = None) -> str:
        declared = step.params.get("manager")
        if declared:
            return str(declared).strip().lower()
        dialect = self.dialect(ctx.device)
        result = self._run(ctx, dialect.detect_manager(), ran=ran)
        manager = (result.stdout or "").strip().splitlines()
        manager = manager[-1].strip().lower() if manager else "unknown"
        if manager in ("unknown", ""):
            raise GuestError("no supported package manager (apt, dnf or winget) on this guest")
        return manager

    def _pending(
        self, ctx: ExecutionContext, manager: str, ran: _Ran | None = None
    ) -> list[PendingPackage]:
        dialect = self.dialect(ctx.device)
        command, allow = dialect.pending_upgrades(manager)
        result = self._run(ctx, command, timeout=PACKAGE_TIMEOUT, allow=allow, ran=ran)
        return dialect.parse_pending(manager, result.stdout)

    # -- dry run ----------------------------------------------------------
    def dry_run(self, ctx: ExecutionContext, steps: list[ChangeStep]) -> DryRunResult:
        entries: list[dict[str, Any]] = []
        warnings: list[str] = []
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
            entry, step_warnings, step_blockers = self._preview(probe, step)
            entries.append(entry)
            warnings.extend(step_warnings)
            blockers.extend(step_blockers)
        return DryRunResult(
            ok=not blockers,
            diff={
                "platform": self.platform,
                "device": ctx.device.name,
                "dialect": self.dialect(ctx.device).name if ctx.device.kind in DIALECTS else None,
                "steps": entries,
            },
            warnings=warnings,
            blockers=blockers,
        )

    def _preview(
        self, ctx: ExecutionContext, step: ChangeStep
    ) -> tuple[dict[str, Any], list[str], list[str]]:
        warnings: list[str] = []
        blockers: list[str] = []
        entry: dict[str, Any] = {"action": step.action}
        try:
            if step.action not in ACTIONS:
                raise GuestError(f"{step.action} is not a guest action this executor implements")
            dialect = self.dialect(ctx.device)

            if step.action in SERVICE_ACTIONS:
                service = checked(step.params.get("service"), SERVICE_NAME, "service name")
                verb = SERVICE_ACTIONS[step.action]
                state = self._service_state(ctx, service)
                wanted = dialect.inactive_value if verb == "stop" else dialect.active_value
                entry.update(
                    {
                        "operation": f"{verb} {service}",
                        "service": service,
                        "before": {"state": state},
                        "after": {"state": wanted},
                        "commands": [getattr(dialect, f"service_{verb}")(service)],
                    }
                )
                if state == "missing":
                    blockers.append(f"there is no service named {service!r} on {ctx.device.name}")
                elif verb == "start" and self._is_active(ctx.device, state):
                    warnings.append(f"{service} is already {state}")
                elif verb == "stop" and not self._is_active(ctx.device, state):
                    warnings.append(f"{service} is already {state}")
                return entry, warnings, blockers

            if step.action == "guest.package_update":
                manager = self._manager(ctx, step)
                pending = self._pending(ctx, manager)
                entry.update(
                    {
                        "operation": f"{manager} upgrade",
                        "manager": manager,
                        "pending": [vars(p) for p in pending],
                        "commands": [dialect.apply_upgrades(manager)],
                    }
                )
                if not pending:
                    warnings.append("nothing to upgrade on this guest")
                warnings.append("a package update has no automatic rollback")
                return entry, warnings, blockers

            # guest.reboot
            uptime = dialect.parse_uptime(
                self.transport(ctx.device).run(ctx, dialect.uptime(), DEFAULT_TIMEOUT).stdout
            )
            entry.update(
                {
                    "operation": "reboot",
                    "before": {"uptime_seconds": uptime},
                    "commands": [dialect.reboot()],
                }
            )
            if not step.params.get("window_confirmed"):
                blockers.append(
                    "guest.reboot is a Tier 2 action: it runs only with params.window_confirmed, "
                    "set when the plan's maintenance window and confirmation phrase are satisfied"
                )
            warnings.append("a reboot cannot be undone")
            return entry, warnings, blockers
        except Exception as exc:  # noqa: BLE001 - a preview failure is a blocker
            entry["error"] = short_error(exc)
            blockers.append(f"{step.action}: {short_error(exc)}")
            return entry, warnings, blockers

    # -- checks -----------------------------------------------------------
    def _evaluate(self, ctx: ExecutionContext, check: str) -> CheckResult:
        text = " ".join(check.split())
        dialect = self.dialect(ctx.device)

        match = CHECK_SERVICE.match(text)
        if match:
            service = checked(match["name"], SERVICE_NAME, "service name")
            state = self._service_state(ctx, service)
            active = self._is_active(ctx.device, state)
            wanted_active = match["state"].lower() == ACTIVE
            return CheckResult(check=check, ok=active is wanted_active, detail=f"state={state}")

        match = CHECK_PORT.match(text)
        if match:
            port = int(match["port"])
            result = self.transport(ctx.device).run(ctx, dialect.listening(port), DEFAULT_TIMEOUT)
            listening = dialect.parse_listening(port, result.stdout)
            return CheckResult(
                check=check, ok=listening, detail="listening" if listening else "not listening"
            )

        match = CHECK_UPTIME.match(text)
        if match:
            result = self.transport(ctx.device).run(ctx, dialect.uptime(), DEFAULT_TIMEOUT)
            uptime = dialect.parse_uptime(result.stdout)
            if uptime is None:
                return CheckResult(check=check, ok=False, detail="the guest reported no uptime")
            limit = float(match["amount"]) * UNIT_SECONDS[(match["unit"] or "s").lower()]
            ok = uptime < limit if match["op"] == "<" else uptime > limit
            return CheckResult(check=check, ok=ok, detail=f"up {uptime:.0f}s")

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
    def apply(self, ctx: ExecutionContext, step: ChangeStep) -> StepResult:
        started = datetime.now(UTC)
        ran = _Ran()
        output: dict[str, Any] = {"action": step.action, "device": ctx.device.name}
        try:
            if ctx.frozen:
                raise GuestError("the platform is frozen (break-glass); no writes")
            if ctx.dry_run:
                raise GuestError("apply() called with a dry-run context")
            if step.action not in ACTIONS:
                raise GuestError(f"{step.action} is not a guest action this executor implements")
            output["transport"] = self.transport(ctx.device).name
            self._apply(ctx, step, output, ran)
            output["commands"] = ran.commands
            return StepResult(
                step=step, ok=True, output=output, started_at=started, finished_at=datetime.now(UTC)
            )
        except Exception as exc:  # noqa: BLE001 - a failed step is a result, not a crash
            log.warning("guest step %s failed: %s", step.action, short_error(exc))
            output["commands"] = ran.commands
            return StepResult(
                step=step,
                ok=False,
                output=output,
                error=short_error(exc),
                started_at=started,
                finished_at=datetime.now(UTC),
            )

    def _apply(
        self, ctx: ExecutionContext, step: ChangeStep, output: dict[str, Any], ran: _Ran
    ) -> None:
        dialect = self.dialect(ctx.device)

        if step.action in SERVICE_ACTIONS:
            verb = SERVICE_ACTIONS[step.action]
            service = checked(step.params.get("service"), SERVICE_NAME, "service name")
            previous = self._service_state(ctx, service)
            if previous == "missing":
                raise GuestError(f"there is no service named {service!r} on {ctx.device.name}")
            output.update({"service": service, "previous_state": previous})
            self._run(ctx, getattr(dialect, f"service_{verb}")(service), ran=ran)
            self.sleep(SERVICE_SETTLE_SECONDS)
            state = self._service_state(ctx, service)
            output["state"] = state
            wanted_active = verb != "stop"
            if self._is_active(ctx.device, state) is not wanted_active:
                raise GuestError(
                    f"{service} is {state} after the {verb}, "
                    f"expected {'active' if wanted_active else 'inactive'}"
                )
            output["rollback"] = f"restore the previous state ({previous})"
            return

        if step.action == "guest.package_update":
            manager = self._manager(ctx, step, ran)
            pending = self._pending(ctx, manager, ran)
            names = [p.name for p in pending]
            before = self._versions(ctx, dialect, manager, names, ran)
            output.update(
                {
                    "manager": manager,
                    "pending": [vars(p) for p in pending],
                    "previous_versions": before,
                }
            )
            if not pending:
                output["changed"] = []
                output["rollback"] = "nothing was changed"
                return
            self._run(ctx, dialect.apply_upgrades(manager), timeout=PACKAGE_TIMEOUT, ran=ran)
            after = self._versions(ctx, dialect, manager, names, ran)
            output["changed"] = [
                {"name": name, "from": before.get(name), "to": after.get(name)}
                for name in names
                if before.get(name) != after.get(name)
            ]
            output["rollback"] = "none: package updates are not rolled back automatically"
            return

        # guest.reboot
        if not step.params.get("window_confirmed"):
            raise GuestError(
                "guest.reboot is a Tier 2 action: it runs only with params.window_confirmed"
            )
        output["previous_uptime_seconds"] = dialect.parse_uptime(
            self.transport(ctx.device).run(ctx, dialect.uptime(), DEFAULT_TIMEOUT).stdout
        )
        try:
            self._run(ctx, dialect.reboot(), ran=ran)
            output["reboot"] = "requested"
        except Exception as exc:  # noqa: BLE001 - a dropped session is the expected outcome
            if _REFUSAL_HINT.search(str(exc)):
                raise
            ran.commands.append(dialect.reboot())
            output["reboot"] = "requested; the session dropped, which a reboot is expected to do"
            output["session_note"] = short_error(exc)
        output["rollback"] = "none: a reboot cannot be undone"

    def _versions(
        self,
        ctx: ExecutionContext,
        dialect: Dialect,
        manager: str,
        names: list[str],
        ran: _Ran,
    ) -> dict[str, str]:
        """Installed versions of the packages an upgrade is about to touch."""
        safe = [checked(name, PACKAGE_NAME, "package name") for name in names]
        command = dialect.installed_versions(manager, safe)
        if not command:
            return {}
        # A package that is not installed makes the query exit non-zero; the
        # rows it did return are still what we want.
        result = self.transport(ctx.device).run(ctx, command, DEFAULT_TIMEOUT)
        ran.add(result)
        return {k: v for k, v in dialect.parse_versions(result.stdout).items() if k in set(safe)}

    # -- rollback ---------------------------------------------------------
    @staticmethod
    def partially_applied(result: StepResult) -> bool:
        """Whether a *failed* service step already changed the service.

        `systemctl restart` succeeding and the unit then landing in `failed` is
        a failed step whose service has still been restarted; leaving it there
        because the step reported an error is how a rollback becomes a lie. The
        commands the step recorded are the evidence that it acted.
        """
        return bool(
            result.step.action in SERVICE_ACTIONS
            and result.output.get("previous_state")
            and result.output.get("commands")
        )

    def rollback(self, ctx: ExecutionContext, applied: list[StepResult]) -> list[StepResult]:
        undone: list[StepResult] = []
        for result in reversed(applied):
            if not result.ok and not self.partially_applied(result):
                continue
            undone.append(self._undo(ctx, result))
        return undone

    def _undo(self, ctx: ExecutionContext, result: StepResult) -> StepResult:
        started = datetime.now(UTC)
        ran = _Ran()
        output: dict[str, Any] = {
            "action": result.step.action,
            "device": ctx.device.name,
            "undo_of": result.step.action,
        }
        error: str | None = None
        try:
            dialect = self.dialect(ctx.device)
            action = result.step.action

            if action in SERVICE_ACTIONS:
                service = str(result.output.get("service"))
                previous = str(result.output.get("previous_state", ""))
                output.update({"service": service, "restoring": previous})
                if self._is_active(ctx.device, previous):
                    self._run(ctx, dialect.service_start(service), ran=ran)
                    output["undo"] = f"started {service}, which was {previous} before"
                else:
                    self._run(ctx, dialect.service_stop(service), ran=ran)
                    output["undo"] = f"stopped {service}, which was {previous} before"
            elif action == "guest.package_update":
                output["previous_versions"] = result.output.get("previous_versions")
                output["changed"] = result.output.get("changed")
                if not result.output.get("changed"):
                    output["undo"] = "nothing was upgraded, so there is nothing to undo"
                else:
                    raise GuestError(
                        "package updates are not rolled back automatically; the previous "
                        "versions are recorded in this step's output for a manual downgrade"
                    )
            else:  # guest.reboot
                output["previous_uptime_seconds"] = result.output.get("previous_uptime_seconds")
                raise GuestError("a reboot cannot be undone")
        except Exception as exc:  # noqa: BLE001 - a failed rollback pages the owner
            error = short_error(exc)
        output["commands"] = ran.commands
        return StepResult(
            step=result.step,
            ok=error is None,
            output=output,
            error=error,
            started_at=started,
            finished_at=datetime.now(UTC),
        )
