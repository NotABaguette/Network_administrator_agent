# Onboarding

Discovery cannot start from nothing. Onboarding is the phase where the owner
supplies management IPs, credentials and API keys and the harness verifies
that every account has exactly the privileges the design assumes.

Principle: **secrets never enter the language model.** Claude Code guides the
owner and interprets results, but the credentials are typed into a local
prompt and written straight to SOPS-encrypted files.

## Commands

| Command | What it does |
|---|---|
| `infra onboard init` | Creates the age key (outside the repo), fills `.sops.yaml`, prompts for the Anthropic API key, Telegram bot token, owner Telegram user id and dead-man heartbeat URL, and writes `secrets/platform.enc.yaml`. |
| `infra onboard add-device <kind> <mgmt-ip> --name X` | Prompts locally for the credential, runs the **credential probe** for the platform (connects, records identity such as serial/hostname/version, verifies privilege level), writes the credential to `secrets/devices.enc.yaml` and the device to `inventory/seed.yaml`. |
| `infra onboard accounts <device>` | Prints the exact least-privilege account-creation commands for the device's platform with generated passwords already stored in SOPS, for the owner to paste. |
| `infra onboard scan <cidr>` | Probes a management CIDR for SSH/HTTPS/Redfish services to find devices the owner forgot. |
| `infra onboard check` | Prerequisites report: reachability, credential presence, probe results, privilege level, NTP/CDP/syslog status where a probe can see it, with remediation commands. |
| `infra onboard status` | Where onboarding stands; the same data the MCP tool `onboarding.status` exposes (redacted). |

## Probes

| Kind | Identity | Privilege check |
|---|---|---|
| `fortigate` | `GET /api/v2/monitor/system/status` (hostname, serial, version) | API user's access profile via `/api/v2/cmdb/system/accprofile/<name>`; read-only means every scope is `read` or `none` |
| `cisco_ios` / `cisco_iosxe` | `show version` (hostname, model, serial, IOS version) | `show privilege` |
| `esxi` | `content.about` (build, license product) | `HasPrivilegeOnEntity` on the host for `Host.Config.Settings`; read-only means false |
| `ilo` | `/redfish/v1/Systems/1` (model, serial, BIOS), `/redfish/v1/Managers/1` (iLO generation and firmware) | own account's privileges from `/redfish/v1/AccountService/Accounts`, or "unknown" on 403 |

Probe results are stored in `inventory/seed.yaml` next to the device and are
what Phase 1 collectors run from and what Phase 2 bootstraps NetBox with.
