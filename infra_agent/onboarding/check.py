"""Prerequisites report."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Literal

from infra_agent.config import Settings
from infra_agent.models.common import DeviceKind, SeedInventory
from infra_agent.onboarding.secrets import SecretsStore

Status = Literal["ok", "warn", "fail", "pending"]


@dataclass
class CheckResult:
    name: str
    status: Status
    detail: str = ""
    remediation: str = ""


def _reachable(ip: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def run_checks(settings: Settings) -> list[CheckResult]:
    results: list[CheckResult] = []
    secrets = SecretsStore(settings.secrets_dir)
    if not secrets.available():
        results.append(
            CheckResult(
                "sops",
                "fail",
                "sops/age not usable",
                "install sops + age; run `infra onboard init`",
            )
        )
    else:
        results.append(CheckResult("sops", "ok"))
        platform = secrets.read("platform")
        for key in (
            "anthropic_api_key",
            "telegram_bot_token",
            "telegram_owner_id",
            "heartbeat_url",
        ):
            results.append(
                CheckResult(
                    f"platform.{key}",
                    "ok" if key in platform else "fail",
                    "" if key in platform else "missing",
                    "" if key in platform else "run `infra onboard init`",
                )
            )

    inv = SeedInventory.load(settings.seed_inventory)
    if not inv.devices:
        results.append(
            CheckResult("inventory", "fail", "no devices onboarded", "infra onboard add-device ...")
        )
        return results
    for kind in DeviceKind:
        if not inv.by_kind(kind):
            results.append(CheckResult(f"inventory.{kind.value}", "warn", "none onboarded"))

    for d in inv.devices:
        port = d.port or (22 if d.kind in (DeviceKind.cisco_ios, DeviceKind.cisco_iosxe) else 443)
        ok = _reachable(d.mgmt_ip, port)
        results.append(
            CheckResult(
                f"{d.name}.reachable",
                "ok" if ok else "fail",
                f"{d.mgmt_ip}:{port}",
                "" if ok else "check mgmt VLAN ACLs and the device's management interface",
            )
        )
        if secrets.available():
            has = secrets.has("devices", d.credential_ref)
            results.append(
                CheckResult(
                    f"{d.name}.credential",
                    "ok" if has else "fail",
                    "",
                    ""
                    if has
                    else f"infra onboard add-device {d.kind.value} {d.mgmt_ip} --name {d.name}",
                )
            )
        if d.probe is None:
            results.append(CheckResult(f"{d.name}.probe", "pending", "never probed"))
        elif not d.probe.ok:
            results.append(CheckResult(f"{d.name}.probe", "fail", d.probe.error or ""))
        else:
            status: Status = "ok"
            detail = d.probe.privilege
            remediation = ""
            if d.probe.read_only is False:
                status, remediation = "warn", f"infra onboard accounts {d.name}"
                detail += " (collector credential can write)"
            results.append(CheckResult(f"{d.name}.privilege", status, detail, remediation))
            for w in d.probe.warnings:
                results.append(CheckResult(f"{d.name}.warning", "warn", w))
        # Items a probe cannot see yet; Phase 1 collectors fill these in.
        for item, cmd in (
            ("ntp", "verify NTP sync on the device"),
            ("syslog", "point syslog at mgmt-01:514"),
        ):
            results.append(
                CheckResult(f"{d.name}.{item}", "pending", "verified by collector in Phase 1", cmd)
            )
        if d.kind is DeviceKind.esxi:
            results.append(
                CheckResult(
                    f"{d.name}.cdp",
                    "pending",
                    "verified by collector in Phase 1",
                    "esxcli network vswitch standard set -c both -v <vSwitch>",
                )
            )
    return results
