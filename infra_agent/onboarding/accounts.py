"""Least-privilege account templates the owner pastes into each platform."""

from __future__ import annotations

import json

from infra_agent.models.common import DeviceKind


def account_commands(kind: DeviceKind, username: str, password: str, mgmt_ip: str) -> list[str]:
    if kind is DeviceKind.fortigate:
        return [
            "config system accprofile",
            f'    edit "{username}-profile"',
            "        set scope global",
            "        set secfabgrp read",
            "        set ftviewgrp read",
            "        set authgrp read",
            "        set sysgrp read",
            "        set netgrp read",
            "        set loggrp read",
            "        set fwgrp read",
            "        set vpngrp read",
            "        set utmgrp read",
            "        set wifi read",
            "    next",
            "end",
            "config system api-user",
            f'    edit "{username}"',
            f'        set accprofile "{username}-profile"',
            "        set vdom root",
            "        config trusthost",
            "            edit 1",
            f"                set ipv4-trusthost {mgmt_ip} 255.255.255.255",
            "            next",
            "        end",
            "    next",
            "end",
            f"execute api-user generate-key {username}",
            "# copy the printed key into `infra onboard add-device fortigate ... --token`",
        ]
    if kind in (DeviceKind.cisco_ios, DeviceKind.cisco_iosxe):
        return [
            "configure terminal",
            f" username {username} privilege 15 secret {password}",
            " ip ssh version 2",
            " archive",
            "  path flash:archive",
            "  maximum 10",
            "  write-memory",
            " exit",
            " ip access-list standard INFRA-MGMT",
            f"  permit host {mgmt_ip}",
            " line vty 0 15",
            "  access-class INFRA-MGMT in",
            "  transport input ssh",
            "end",
            "write memory",
            "# read-only is enforced by the platform's command allowlist; add AAA command",
            "# authorization if TACACS+ is available.",
        ]
    if kind is DeviceKind.esxi:
        return [
            f"esxcli system account add -i {username} -p '{password}' -c '{password}'",
            f"esxcli system permission set -i {username} -r ReadOnly",
            "esxcli network vswitch standard list | grep Name: | awk '{print $2}' | "
            "xargs -I{} esxcli network vswitch standard set -c both -v {}",
            f"esxcli system syslog config set --loghost=udp://{mgmt_ip}:514",
            "esxcli system syslog reload",
        ]
    if kind is DeviceKind.ilo:
        return [
            "# In the iLO web UI: Administration > User Administration > New",
            f"#   Login name: {username}",
            "#   Privileges: Login only (uncheck everything else)",
            "# or via Redfish from an admin account:",
            "curl -k -u admin -X POST https://<ilo>/redfish/v1/AccountService/Accounts "
            "-H 'Content-Type: application/json' -d '"
            + json.dumps(
                {
                    "UserName": username,
                    "Password": password,
                    "Oem": {
                        "Hpe": {
                            "LoginName": username,
                            "Privileges": {
                                "LoginPriv": True,
                                "RemoteConsolePriv": False,
                                "UserConfigPriv": False,
                                "VirtualMediaPriv": False,
                                "VirtualPowerAndResetPriv": False,
                                "iLOConfigPriv": False,
                            },
                        }
                    },
                }
            )
            + "'",
        ]
    raise LookupError(kind)
