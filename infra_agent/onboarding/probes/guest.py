"""Guest credential probe: who am I on this guest, and how much can I do?

The probe answers two questions before a credential is accepted, and changes
nothing on the guest:

* **identity** - hostname and operating system, so the owner can see they typed
  the address of the machine they meant;
* **privilege** - whether the account is root (Linux) or a local administrator
  (Windows). Both are a *warning*, not a failure: the guest collector is
  supposed to run as an unprivileged account with `sudo -n` for exactly the
  read commands in `infra_agent.collectors.guest.SUDO_COMMANDS`
  (`infra onboard accounts <guest>` prints the sudoers allowlist), and an
  administrator credential stored for a collector is a standing risk nobody
  needs to take.

The Linux side also reports whether that passwordless sudo actually works,
because without it the collector cannot see which process owns a socket and the
application layer of the graph loses its edges.

`paramiko` and `winrm` are imported lazily, so this module imports without the
`devices` extra.
"""

from __future__ import annotations

import json
from typing import Any

from infra_agent.collectors.guest import (
    HOSTNAME_COMMAND,
    KERNEL_COMMAND,
    OS_RELEASE_COMMAND,
    SUDO_TEST_COMMAND,
    WHOAMI_COMMAND,
    CommandResult,
    SshRunner,
    WinRmRunner,
    parse_os_release,
)
from infra_agent.models.common import Credential, DeviceKind, ProbeResult, SeedDevice
from infra_agent.onboarding.probes.base import Probe

WHOAMI_NAME_COMMAND = "id -un"

#: PowerShell that reports the identity and whether the session is elevated.
#: `Get-ComputerInfo` is the collector's own identity source, so onboarding and
#: collection agree on what this guest is called.
WINDOWS_IDENTITY = (
    "$id=[Security.Principal.WindowsIdentity]::GetCurrent(); "
    "$admin=(New-Object Security.Principal.WindowsPrincipal($id)).IsInRole("
    "[Security.Principal.WindowsBuiltInRole]::Administrator); "
    "$os=Get-CimInstance Win32_OperatingSystem; "
    "[pscustomobject]@{User=$id.Name; Admin=$admin; Hostname=$env:COMPUTERNAME; "
    "Os=$os.Caption; Version=$os.Version} | ConvertTo-Json -Compress"
)

ROOT_WARNING = (
    "this credential is {who}: the collector must not hold an administrative "
    "account. Create an unprivileged one with `infra onboard accounts {name}`."
)


class GuestProbe(Probe):
    """Identity and privilege of a guest credential, over SSH or WinRM."""

    def probe(self, device: SeedDevice, cred: Credential) -> ProbeResult:
        if device.kind is DeviceKind.guest_windows:
            return self._windows(device, cred)
        return self._linux(device, cred)

    # -- linux -------------------------------------------------------------
    def _linux(self, device: SeedDevice, cred: Credential) -> ProbeResult:
        try:
            runner = self.ssh_runner(device, cred)
        except ImportError as exc:  # pragma: no cover - the extra is installed in CI
            return ProbeResult(ok=False, error=f"paramiko not installed: {exc}")
        except Exception as exc:
            return self.failure(exc)
        try:
            return linux_result(device, self._collect_linux(runner))
        except Exception as exc:
            return self.failure(exc)
        finally:
            runner.close()

    @staticmethod
    def _collect_linux(runner: Any) -> dict[str, CommandResult]:
        return {
            "uid": runner.run(WHOAMI_COMMAND),
            "user": runner.run(WHOAMI_NAME_COMMAND),
            "hostname": runner.run(HOSTNAME_COMMAND),
            "kernel": runner.run(KERNEL_COMMAND),
            "os_release": runner.run(OS_RELEASE_COMMAND),
            "sudo": runner.run(SUDO_TEST_COMMAND),
        }

    def ssh_runner(self, device: SeedDevice, cred: Credential) -> Any:
        return SshRunner(device, cred)

    # -- windows -----------------------------------------------------------
    def _windows(self, device: SeedDevice, cred: Credential) -> ProbeResult:
        try:
            runner = self.winrm_runner(device, cred)
        except ImportError as exc:  # pragma: no cover - the extra is installed in CI
            return ProbeResult(ok=False, error=f"pywinrm not installed: {exc}")
        except Exception as exc:
            return self.failure(exc)
        try:
            return windows_result(device, runner.run(WINDOWS_IDENTITY))
        except Exception as exc:
            return self.failure(exc)
        finally:
            runner.close()

    def winrm_runner(self, device: SeedDevice, cred: Credential) -> Any:
        return WinRmRunner(device, cred)


def linux_result(device: SeedDevice, answers: dict[str, CommandResult]) -> ProbeResult:
    """Turn the probe's fixed commands into identity, privilege and warnings."""
    uid_result = answers["uid"]
    if not uid_result.ok:
        return ProbeResult(
            ok=False,
            error=f"`{WHOAMI_COMMAND}` exited {uid_result.status}: the account cannot run commands",
        )
    uid = _int(uid_result.stdout)
    user = answers["user"].stdout.strip() or None
    release = parse_os_release(answers["os_release"].stdout) if answers["os_release"].ok else {}
    kernel = answers["kernel"].stdout.split()
    identity = {
        "hostname": answers["hostname"].stdout.strip() or None,
        "os": release.get("pretty_name") or release.get("name"),
        "os_id": release.get("id"),
        "os_version": release.get("version"),
        "kernel": " ".join(kernel[:2]) if len(kernel) >= 2 else None,
        "user": user,
        "uid": uid,
    }
    sudo_ok = answers["sudo"].ok
    warnings: list[str] = []
    if uid == 0:
        warnings.append(ROOT_WARNING.format(who=f"root ({user or 'uid 0'})", name=device.name))
    elif not sudo_ok:
        warnings.append(
            "no passwordless sudo for the read commands: sockets will be collected "
            "without the owning process and the application layer of the graph will "
            f"have no edges for this guest. Run `infra onboard accounts {device.name}`."
        )
    if release.get("id") is None:
        warnings.append("/etc/os-release could not be read; the OS is unknown")
    return ProbeResult(
        ok=True,
        identity=identity,
        privilege="root" if uid == 0 else ("user+sudo" if sudo_ok else "user"),
        read_only=uid != 0,
        warnings=warnings,
    )


def windows_result(device: SeedDevice, answer: CommandResult) -> ProbeResult:
    """Identity and administrator membership from the WinRM probe."""
    if not answer.ok:
        detail = (answer.stderr or answer.stdout).strip()[:200]
        return ProbeResult(ok=False, error=f"WinRM returned {answer.status}: {detail}")
    payload = _json(answer.stdout)
    if not payload:
        return ProbeResult(ok=False, error="the WinRM identity probe returned nothing")
    admin = bool(payload.get("Admin"))
    identity = {
        "hostname": payload.get("Hostname"),
        "os": payload.get("Os"),
        "os_version": payload.get("Version"),
        "user": payload.get("User"),
    }
    warnings: list[str] = []
    if admin:
        warnings.append(
            ROOT_WARNING.format(
                who=f"a local administrator ({payload.get('User')})", name=device.name
            )
        )
    if (device.port or 5986) != 5986:
        warnings.append(
            f"WinRM on port {device.port}: only 5986 (HTTPS) is expected; "
            "5985 sends the credential in clear text"
        )
    return ProbeResult(
        ok=True,
        identity=identity,
        privilege="administrator" if admin else "remote-management-user",
        read_only=not admin,
        warnings=warnings,
    )


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _json(text: str) -> dict[str, Any]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {}
    if isinstance(payload, list):
        payload = payload[0] if payload else {}
    return payload if isinstance(payload, dict) else {}
