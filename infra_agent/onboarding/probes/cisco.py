from __future__ import annotations

import re

from infra_agent.models.common import Credential, DeviceKind, ProbeResult, SeedDevice
from infra_agent.onboarding.probes.base import Probe


class CiscoProbe(Probe):
    def probe(self, device: SeedDevice, cred: Credential) -> ProbeResult:
        try:
            from scrapli.driver.core import IOSXEDriver
        except ImportError as exc:  # pragma: no cover
            return ProbeResult(ok=False, error=f"scrapli not installed: {exc}")
        kwargs = {
            "host": device.mgmt_ip,
            "port": device.port or 22,
            "auth_username": cred.username,
            "auth_password": cred.password.get_secret_value() if cred.password else None,
            "auth_strict_key": False,
            "transport": "paramiko",
            "timeout_socket": 15,
            "timeout_transport": 15,
        }
        if device.legacy_ssh:
            kwargs["transport_options"] = {
                "paramiko": {
                    "disabled_algorithms": {},
                }
            }
        try:
            with IOSXEDriver(**kwargs) as conn:
                version = conn.send_command("show version").result
                privilege = conn.send_command("show privilege").result
        except Exception as exc:  # scrapli raises many transport-specific types
            return self.failure(exc)
        identity = parse_show_version(version)
        level = re.search(r"privilege level is (\d+)", privilege)
        priv = level.group(1) if level else "unknown"
        warnings = []
        if priv != "15":
            warnings.append("privilege < 15: `show running-config` backups will fail")
        if identity.get("os") == "IOS-XE" and device.kind is DeviceKind.cisco_ios:
            warnings.append("device runs IOS-XE; re-add with kind cisco_iosxe")
        if identity.get("os") == "IOS" and device.kind is DeviceKind.cisco_iosxe:
            warnings.append("device runs classic IOS; re-add with kind cisco_ios")
        return ProbeResult(
            ok=True,
            identity=identity,
            privilege=f"priv{priv}",
            read_only=None,  # IOS has no read-only concept; enforced by our allowlist
            warnings=warnings,
        )


def parse_show_version(text: str) -> dict[str, str | None]:
    hostname = re.search(r"^(\S+) uptime is", text, re.M)
    version = re.search(r"Version ([^,\s]+)", text)
    model = re.search(r"^[Mm]odel [Nn]umber\s*:\s*(\S+)", text, re.M) or re.search(
        r"^cisco (WS-\S+|C\d\S+)", text, re.M
    )
    serial = re.search(r"^[Ss]ystem [Ss]erial [Nn]umber\s*:\s*(\S+)", text, re.M)
    return {
        "hostname": hostname.group(1) if hostname else None,
        "version": version.group(1) if version else None,
        "model": model.group(1) if model else None,
        "serial": serial.group(1) if serial else None,
        "os": "IOS-XE" if "IOS-XE" in text or "IOS XE" in text else "IOS",
    }
