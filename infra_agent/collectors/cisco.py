"""Catalyst collector over SSH (scrapli) with TextFSM parsing (ntc-templates).

Works for classic IOS (2960, 3560, 3750) and IOS-XE (3650, 3850). Every
command here is on the read-only allowlist; `show running-config` goes to the
config git store only.
"""

from __future__ import annotations

from typing import Any

from infra_agent.collectors.base import Collector, register
from infra_agent.models.common import Credential, DeviceKind, SeedDevice

SHOW_COMMANDS = {
    "version": "show version",
    "inventory": "show inventory",
    "interfaces_status": "show interfaces status",
    "interfaces": "show interfaces",
    "ip_int_brief": "show ip interface brief",
    "vlans": "show vlan brief",
    "trunks": "show interfaces trunk",
    "cdp": "show cdp neighbors detail",
    "lldp": "show lldp neighbors detail",
    "mac_table": "show mac address-table",
    "arp": "show ip arp",
    "stp": "show spanning-tree",
    "etherchannel": "show etherchannel summary",
    "errdisable": "show interfaces status err-disabled",
    "power": "show power inline",
    "environment": "show environment all",
    "ntp": "show ntp status",
    "logging": "show logging | include Trap logging|Logging to",
}


def parse(platform: str, command: str, output: str) -> list[dict[str, Any]] | str:
    """TextFSM-parse with ntc-templates; fall back to raw text if no template matches."""
    try:
        from ntc_templates.parse import parse_output
    except ImportError:  # pragma: no cover
        return output
    try:
        return parse_output(platform=platform, command=command, data=output)
    except Exception:
        return output


class _CiscoBase(Collector):
    ntc_platform = "cisco_ios"
    interval_seconds = 300

    def _connect(self, device: SeedDevice, cred: Credential):
        from scrapli.driver.core import IOSXEDriver

        kwargs: dict[str, Any] = {
            "host": device.mgmt_ip,
            "port": device.port or 22,
            "auth_username": cred.username,
            "auth_password": cred.password.get_secret_value() if cred.password else None,
            "auth_strict_key": False,
            "transport": "paramiko",
            "timeout_socket": 20,
            "timeout_transport": 30,
            "timeout_ops": 60,
        }
        return IOSXEDriver(**kwargs)

    def collect(self, device: SeedDevice, cred: Credential) -> dict[str, Any]:
        data: dict[str, Any] = {"errors": {}}
        with self._connect(device, cred) as conn:
            for key, cmd in SHOW_COMMANDS.items():
                resp = conn.send_command(cmd)
                if resp.failed:
                    data["errors"][key] = resp.result[:200]
                    continue
                data[key] = parse(self.ntc_platform, cmd.split(" |")[0], resp.result)
        return data

    def configs(self, device: SeedDevice, cred: Credential) -> dict[str, str]:
        with self._connect(device, cred) as conn:
            running = conn.send_command("show running-config").result
        return {"running-config.txt": running}


@register
class CiscoIOSCollector(_CiscoBase):
    kind = DeviceKind.cisco_ios
    name = "cisco"
    ntc_platform = "cisco_ios"


@register
class CiscoIOSXECollector(_CiscoBase):
    kind = DeviceKind.cisco_iosxe
    name = "cisco"
    ntc_platform = "cisco_xe"
