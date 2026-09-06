# Roadmap

Ordered so the owner gets protection first (backups, monitoring, alerting),
then understanding (inventory, graph), then delegation (agent, changes).

| Phase | Deliverable |
|---|---|
| 0 Foundation + onboarding | Repo scaffold, platform stack, `infra onboard` harness, devices onboarded with verified least-privilege credentials, prerequisites report clean, break-glass flag, dead-man heartbeat, Telegram bot skeleton |
| 1 Collect, back up, watch | Collectors with `/metrics`, observed-state store, config git repo, snmp/blackbox targets, Alloy syslog, first alert rules, dashboards. Acceptance: test alert reaches the owner's phone; a manual config edit appears as a git commit within one cycle |
| 2 Source of truth + graph | NetBox bootstrap and reconciler, baseline acceptance, correlation (L1/L2/L3/storage/self-path), impact analysis, Mermaid topology. Acceptance: inventory matches a manual audit; lab-port cable pull attributed; seeded trunk VLAN mismatch reported |
| 3 AI layer, read-only | Redaction gateway with tests, read tool groups, FastMCP server, agent service with duties and advisory triage, Telegram bot. Acceptance: redaction corpus strips 100%; egress audit reviewed after a week; where-is / what-breaks questions answered correctly |
| 4 Change engine | ChangePlan, computed tiers, human-only approval channel, native executors with safe rollback, `UnapprovedConfigChange`. Tier 0 actions enabled one at a time after shadow mode. OOB box before any Tier 2 edge change. Acceptance: forced rollback on lab port and lab FortiGate object; unapproved edit flagged; approval token proven absent from every LLM-visible payload |
| 5 Guest and application layer | Guest collectors, node/windows exporters, application dependency edges, certificate-expiry duty |
| 6 Hardening and DR | Standby mgmt-01 failover rehearsed, DR runbook, restore test, backup solution monitored |

## Open items to confirm in Phase 0
- ESXi license type per host; whether Essentials is on the table for backups.
- Exact Catalyst models/IOS versions and iLO generation per host.
- Hardware for the OOB mini-box.
