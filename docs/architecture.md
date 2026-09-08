# Architecture

## The estate

Several HPE ProLiant DL hosts running standalone ESXi (no vCenter), many VMs,
a FortiGate 60F edge firewall with WAN uplinks, and Cisco Catalyst 3xxx /
2960 switches. One management VM (`mgmt-01`) runs this platform.

## Decisions that shape everything

| Decision | Choice | Consequence |
|---|---|---|
| Hypervisor | ESXi standalone | Each host is queried over its own API (`pyvmomi` to hostd). If a host has the free license the API rejects writes, so the executor uses SSH (`esxcli` / `vim-cmd`) for that host. |
| Autonomy | Automatic for low risk, approval for the rest | Three risk tiers computed per change from impact analysis. See `risk-tiers.md`. |
| Data policy | Cloud LLM may see metadata, never raw configs | One redaction gateway on all LLM egress. See `redaction-policy.md`. |
| Existing tools | None | Greenfield stack, deliberately small. |

## Components

```
                 ┌──────────────────────────────────────────────────────────┐
                 │                 mgmt-01 (Ubuntu LTS VM, Docker Compose)  │
   iLO/Redfish ──┤  Collectors ──► observed-state store (Postgres/JSONB)    │
   ESXi API/SSH ─┤   │  │  └─► /metrics (Prometheus scrapes collectors)     │
   FortiOS REST ─┤   │  └────► config git repo (configs, versioned, local)  │
   Cisco SSH/SNMP┤   │              │                                       │
   Guest agents ─┤   │        Reconciler ──► NetBox (source of truth)       │
                 │   └──────► Correlator ──► topology + dependency graph    │
                 │  Prometheus + Alertmanager + Loki + Alloy + Grafana      │
                 │        │ alerts (grouped)          │ PromQL / LogQL      │
                 │  ┌──────────── infra_agent tool layer ────────────┐      │
                 │  │ inventory  topology  metrics  logs  device.show│      │
                 │  │ change.propose/dry_run/status   runbook        │      │
                 │  └───────┬───────────────────────────┬────────────┘      │
                 │    MCP server (FastMCP)         agent service (SDK)      │
                 │    Claude Code / Desktop        triage, duties, Telegram │
                 │          ▲   redaction gateway (all LLM egress)  ▲       │
                 │   approvals: CLI + Telegram buttons (humans only)        │
                 └──────────────────────────────────────────────────────────┘
   external dead-man heartbeat ◄── agent + Alertmanager
   OOB mini-box: exporters + Alertmanager replica, alive if a host dies
```

### Source of truth: NetBox
NetBox holds the intended state: sites, racks, devices, interfaces, cables,
power, VLANs, prefixes, IPs, clusters, VMs, VM interfaces, services, tags,
journal. Discovery reconciles into it. The baseline is the first
human-accepted snapshot; drift is only meaningful after that acceptance.
NetBox and `pynetbox` versions are pinned.

### Collectors (`infra_agent/collectors/`)
One collector per system, read-only credentials, scheduled with APScheduler.
Each run writes a timestamped snapshot, emits a structured diff, exposes
`/metrics` (one poller per device, so no duplicate exporters), and commits raw
configs to the local config git repo.

| Collector | Transport | Notes |
|---|---|---|
| `ilo` | Redfish | Smart Array via OEM paths on iLO4, `SmartStorage` on iLO5+. iLO4 is slow and session-limited: poll every 5 minutes, reuse sessions. |
| `esxi` | pyvmomi (read-only role), SSH only for host-config backup | Standard vSwitches speak CDP only and default to listen-only; CDP mode `both` is a prerequisite. Host event log is collected to know who powered off a VM. |
| `fortigate` | FortiOS REST (read-only API user bound to mgmt-01's IP) + SNMPv3 | Policies parsed to rows. The 60F is small: one poller, 60 s minimum. Full config backup goes to git, never to the LLM. |
| `cisco` | scrapli + ntc-templates + SNMPv3 | Classic IOS and IOS-XE have different parsers and rollback support. `show run` needs priv-15, so the read account is priv-15 with a command allowlist enforced in code. |
| `guest` | SSH (Linux) / WinRM (Windows) with fixed read-only command templates; node/windows exporters deployed by Ansible | OS, packages and pending updates, services, listening sockets and established connections (application dependency edges), disks, TLS certificates with expiry. Onboarded like devices or seeded from ESXi VM annotations (`infra onboard seed-guests`). |

### Correlation and topology graph (`infra_agent/correlate/`)
A `networkx` graph persisted as JSON and rendered to `docs/topology/` as
Mermaid. Edges are derived from evidence with timestamps and confidence:
L1 via CDP/LLDP, L2 via MAC tables and VLANs, L3 via ARP/DHCP/prefixes/
policies, storage via VM → VMDK → datastore → logical drive → physical disks,
and the platform's own path (mgmt-01's host, uplinks, switch ports, the
firewall). `impact_analyze(object)` powers both "what breaks if X dies" and
the tier computation for every change.

### Monitoring and logs (`deploy/`)
Prometheus, Alertmanager, Grafana, Loki, and Grafana Alloy for syslog (Promtail
is end-of-life). `snmp_exporter` covers the switches, `blackbox_exporter`
probes WAN gateways and services, and the collectors expose everything else.
Every collector and the agent export freshness and error metrics; a stale
collector is itself an alert. Alertmanager groups and deduplicates before the
agent is called. The agent and Alertmanager ping an external dead-man
heartbeat so the owner is paged even when mgmt-01 or the WAN is gone.

### Config backups and change detection (`infra_agent/configstore/`)
Collectors commit Cisco running-configs, FortiOS full configs and ESXi
host-config bundles into a local git repo. A commit that does not match an
approved ChangePlan raises `UnapprovedConfigChange`.

### Redaction gateway (`infra_agent/redaction/`)
Every byte leaving to the Claude API passes through one function. See
`redaction-policy.md`.

### AI administrator layer
One typed tool layer (`infra_agent/tools/`), two front-ends:

1. **MCP server** (FastMCP) so Claude Code / Claude Desktop is the interactive
   admin console.
2. **Agent service** using the Anthropic Python SDK Tool Runner for unattended
   work: alert triage, scheduled duties, the Telegram bot. Model
   `claude-opus-5`, adaptive thinking, effort `high`, server-side fallbacks,
   prompt caching on the static system prefix. Per-run caps on tool calls and
   tokens, at most one Tier 0 action per triage run.

`change.approve` and `change.execute` are not LLM tools. Approval happens only
through the CLI or Telegram buttons, with a token minted for the human channel.

### Change engine (`infra_agent/change/`)
Every change is a `ChangePlan`: targets, intended diff, pre-checks, execution
steps, post-checks, rollback steps, computed tier. Rollback strategies:

- **Cisco:** `configure terminal revert timer N`, then `configure confirm` in a
  commit phase the engine runs only once *every* device of the plan has passed
  its post-checks (confirming one switch before another is checked cannot be
  undone). Never `reload in`. A rollback is verified by re-reading the object;
  a change that was already confirmed is undone by the inverse configuration
  built from the state the step captured. VLAN changes are refused unless the
  switch is VTP transparent or off, because a VLAN in vlan.dat is not in the
  archived running-config the revert timer restores.
- **FortiOS:** inverse object operations over REST. Never revision restore
  (it reboots the 60F, and API-token sessions do not create revisions).
- **ESXi:** host-config backup before host changes; VM snapshot before VM
  changes except disk extends; SSH path when the license blocks API writes.

### Communication with the owner
Primary channel is a Telegram bot: long polling only (no inbound port on the
firewall), only the owner's Telegram user id is accepted, Tier 1 proposals
arrive with Approve / Reject buttons, Tier 2 additionally requires typing a
confirmation phrase. Grouped alerts, a daily digest, weekly and monthly
reports, `/ask`, `/status`, `/freeze`, `/unfreeze`. Secondary channels:
Claude Code over the MCP server, Grafana, and the dead-man heartbeat service's
own notifications.

### Onboarding harness (`infra_agent/onboarding/`)
See `onboarding.md`. Credentials are prompted locally, probed for identity and
privilege, stored with SOPS, and never enter the LLM path.

### Stability and security foundations
Dedicated management VLAN with management planes ACL'd to mgmt-01 and a jump
host. Per-system least-privilege service accounts. SOPS + age secrets. Cold
standby copy of mgmt-01 on another host. External dead-man heartbeat and an
out-of-band mini-box, required before any Tier 2 change on the edge is
enabled. `INFRA_FROZEN=1` freezes all automation.

### Known gap: VM backups
Free-license ESXi has no VADP, so Veeam-class tools cannot back up VMs.
Options: licensed ESXi Essentials plus Veeam Community Edition; script-based
backups (ghettoVCB style) to an NFS target; agent-based backups inside the
important guests. The platform monitors whichever is chosen.
