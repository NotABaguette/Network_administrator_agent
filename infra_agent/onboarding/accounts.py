"""Least-privilege account templates the owner pastes into each platform."""

from __future__ import annotations

import json

from infra_agent.models.common import DeviceKind

#: The unprivileged Linux guest account's sudoers allowlist is generated from
#: the collector's own list, so the two can never drift apart: a command the
#: collector adds without adding it here simply loses its process names.
SUDOERS_ALIAS = "INFRA_READ"

#: Windows: WinRM read access is group membership, not a role. `Remote
#: Management Users` is what lets the account open a WinRM session at all;
#: `Performance Monitor Users` lets it read Get-NetTCPConnection and the
#: performance counters. Neither one is a local administrator.
WINDOWS_READ_GROUPS = ("Remote Management Users", "Performance Monitor Users")

#: sudoers matches on the absolute path, and distributions disagree about where
#: these live (`ss` is /usr/bin on Debian and /usr/sbin on RHEL). Every plausible
#: path is listed; a path that does not exist on the guest simply never matches.
BINARY_PATHS: dict[str, tuple[str, ...]] = {
    "ss": ("/usr/bin/ss", "/usr/sbin/ss"),
    "netstat": ("/usr/bin/netstat", "/bin/netstat"),
    "find": ("/usr/bin/find",),
    "openssl": ("/usr/bin/openssl",),
}


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
    if kind is DeviceKind.guest_linux:
        return _guest_linux_commands(username, password, mgmt_ip)
    if kind is DeviceKind.guest_windows:
        return _guest_windows_commands(username, password, mgmt_ip)
    raise LookupError(kind)


def sudoers_line(username: str) -> list[str]:
    """The sudoers allowlist for exactly the collector's read commands.

    Generated from `infra_agent.collectors.guest.SUDO_COMMANDS`, so the file on
    the guest and the commands the collector runs are the same list. Every entry
    is a read: `ss` and `netstat` only need root to name the process behind a
    socket, `find` and `openssl x509 -noout` only to read certificates under
    Let's Encrypt's root-only `live/` directory. `-noout` and the absence of
    `-out` mean the openssl entry cannot write a file.

    sudo matches the argument vector the shell already expanded, so the shell
    quoting in the collector's templates is stripped here: `-name '*.pem'`
    reaches sudo as `-name *.pem`, and a sudoers entry that kept the quotes
    would match nothing at all.
    """
    from infra_agent.collectors.guest import SUDO_COMMANDS

    commands: list[str] = []
    for command in SUDO_COMMANDS:
        binary, _, arguments = command.partition(" ")
        arguments = arguments.replace("'", "")
        for path in BINARY_PATHS.get(binary, (f"/usr/bin/{binary}",)):
            commands.append(f"{path} {arguments}".strip())
    return [
        f"Cmnd_Alias {SUDOERS_ALIAS} = " + ", \\\n    ".join(commands),
        f"{username} ALL=(root) NOPASSWD: {SUDOERS_ALIAS}",
        "Defaults!" + SUDOERS_ALIAS + " !requiretty",
    ]


def _guest_linux_commands(username: str, password: str, mgmt_ip: str) -> list[str]:
    """An unprivileged account, key authentication, and the read allowlist.

    The account exists to answer `ss`, `systemctl`, `df` and `openssl`, and
    nothing else: no SSH password (the collector authenticates with the key it
    was onboarded with) and sudo for nothing but the fixed read commands.
    `from=` pins the key to mgmt-01, so a stolen key is useless anywhere else.
    """
    sudoers = "/etc/sudoers.d/infra-agent"
    return [
        f"# Run as root on the guest. mgmt-01 is {mgmt_ip}.",
        "# the account needs a shell to run its read commands over SSH; the key",
        "# below is the only way in, because sshd keeps PasswordAuthentication no.",
        f"useradd --system --create-home --shell /bin/sh {username}",
        f"install -d -m 700 -o {username} -g {username} /home/{username}/.ssh",
        "# paste mgmt-01's public key, pinned to it and to nothing else:",
        f'echo \'from="{mgmt_ip}",no-agent-forwarding,no-port-forwarding,no-pty '
        f"ssh-ed25519 AAAA... infra-agent@mgmt-01' "
        f"> /home/{username}/.ssh/authorized_keys",
        f"chown {username}:{username} /home/{username}/.ssh/authorized_keys",
        f"chmod 600 /home/{username}/.ssh/authorized_keys",
        "# the read allowlist - exactly the commands the collector elevates:",
        f"cat > {sudoers} <<'EOF'",
        *sudoers_line(username),
        "EOF",
        f"chmod 440 {sudoers} && visudo -cf {sudoers}",
        "# break-glass console password only (SSH stays key-only); it is the one",
        "# `infra onboard accounts` stored for you:",
        f"echo '{username}:{password}' | chpasswd",
    ]


def _guest_windows_commands(username: str, password: str, mgmt_ip: str) -> list[str]:
    """A local account in the WinRM read groups, and HTTPS-only WinRM.

    Windows has no read-only role, so least privilege is group membership:
    `Remote Management Users` to open a session and `Performance Monitor Users`
    to read the counters and TCP connections. The account is deliberately not in
    `Administrators`, and the listener is HTTPS on 5986 only - 5985 puts the
    credential on the wire in clear text.
    """
    groups = "\n".join(
        f'Add-LocalGroupMember -Group "{group}" -Member "{username}"'
        for group in WINDOWS_READ_GROUPS
    )
    return [
        "# Run in an elevated PowerShell on the guest.",
        f'$pw = ConvertTo-SecureString "{password}" -AsPlainText -Force',
        f'New-LocalUser -Name "{username}" -Password $pw -PasswordNeverExpires '
        f'-Description "infra-agent read-only collector"',
        groups,
        "# HTTPS only: create the listener with the machine certificate and",
        "# refuse the clear-text one.",
        "$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME "
        "-CertStoreLocation Cert:\\LocalMachine\\My",
        "New-Item -Path WSMan:\\localhost\\Listener -Transport HTTPS -Address * "
        "-CertificateThumbPrint $cert.Thumbprint -Force",
        "Get-ChildItem WSMan:\\localhost\\Listener | Where-Object "
        "{ $_.Keys -contains 'Transport=HTTP' } | Remove-Item -Recurse",
        "Set-Item WSMan:\\localhost\\Service\\Auth\\Basic -Value $false",
        "Set-Item WSMan:\\localhost\\Service\\AllowUnencrypted -Value $false",
        f"New-NetFirewallRule -DisplayName 'WinRM HTTPS from mgmt-01' -Direction Inbound "
        f"-Protocol TCP -LocalPort 5986 -RemoteAddress {mgmt_ip} -Action Allow",
        "# grant the account WinRM session access without making it an admin:",
        "Set-PSSessionConfiguration -Name Microsoft.PowerShell -ShowSecurityDescriptorUI",
        f"#   add {username}: Read and Execute, nothing else.",
    ]
