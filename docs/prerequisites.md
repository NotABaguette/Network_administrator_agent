# Prerequisites checklist

Done once, by hand or via the exact commands `infra onboard accounts` prints.
`infra onboard check` verifies each item and prints remediation.

## Network
- [ ] Dedicated management VLAN; every device's management interface lives there.
- [ ] Management planes (SSH, HTTPS, Redfish, SNMP) ACL'd to mgmt-01 and a jump host.
- [ ] mgmt-01 has a static IP and DNS entry.
- [ ] NTP configured on every device and mgmt-01 (snapshots are time-correlated).
- [ ] Syslog on FortiGate, Cisco and ESXi pointed at mgmt-01 (Alloy, UDP/TCP 514).

## Per platform
### FortiGate
- [ ] REST API user `infra-ro` with a read-only access profile, trusted host = mgmt-01.
- [ ] REST API user `infra-rw` with a read-write profile, trusted host = mgmt-01 (used only by the change engine).
- [ ] SNMPv3 user (auth+priv) for mgmt-01.
- [ ] LLDP enabled on internal interfaces facing the switches.

### Cisco Catalyst
- [ ] Local user `infra-ro` privilege 15 (needed for `show running-config`); command allowlist is enforced by the platform, and by AAA command authorization where available.
- [ ] Local user `infra-rw` privilege 15 for the change engine.
- [ ] SSH v2 only; on old 2960s note the legacy KEX/ciphers in the seed inventory.
- [ ] `archive` configured (path to flash or mgmt-01 SCP) so `configure revert timer` works.
- [ ] CDP and LLDP enabled on ports facing hosts and the firewall.
- [ ] SNMPv3 user (auth+priv) for mgmt-01.

### ESXi
- [ ] Local role `infra-ro` (read-only + Global.Diagnostics) and user bound to it for collectors.
- [ ] Local admin user `infra-rw` for the change engine (only if the license permits API writes; otherwise SSH with a key).
- [ ] CDP mode `both` on every standard vSwitch (`esxcli network vswitch standard set -c both -v vSwitchN`).
- [ ] Syslog target set (`esxcli system syslog config set --loghost=udp://mgmt-01:514`).
- [ ] License type recorded per host (free vs licensed) in the seed inventory.
- [ ] For host-config backups: SSH enabled on the host (TSM-SSH service) and mgmt-01's public key in `/etc/ssh/keys-root/authorized_keys` (or the backup user's). The ESXi collector only opens SSH when the credential has `ssh_key_path`; without it the backup step is skipped and the run stays green.
- [ ] SSH host keys of every ESXi host and switch collected into a known_hosts file and exported as `INFRA_SSH_KNOWN_HOSTS` for the collectors and `device.show`; without it host keys are accepted on first use.

### HPE iLO
- [ ] Read-only iLO user `infra-ro` (Login privilege only) for Redfish.
- [ ] iLO generation recorded per host (iLO4 vs iLO5/6).
- [ ] Firmware current enough for Redfish 1.x.

## Platform
- [ ] age key generated and stored outside the repo; `.sops.yaml` recipient set (`infra onboard init`).
- [ ] Anthropic API key, Telegram bot token, owner Telegram user id, dead-man heartbeat URL stored (`infra onboard init`).
- [ ] Cold-standby copy of mgmt-01 scheduled to another host.
- [ ] Out-of-band mini-box planned (required before Tier 2 edge changes).
