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

## Status

Phases 0-6 are implemented. What remains is the part only the estate can
supply: the acceptance criteria above are exercises against real hardware, and
none of them counts until it has been run there. In particular Phase 6 ships
the mechanism (`infra dr export|verify|import|health`, `deploy/standby/`,
`deploy/oob/`) but a failover that has never been rehearsed is a document, not
a capability - see [`runbooks/restore-test.md`](runbooks/restore-test.md).

Tier 0 actions stay in shadow mode (`INFRA_TIER0_SHADOW_MODE=1`) and are
enabled one at a time, and no Tier 2 edge change may be enabled until the
out-of-band box is built and reporting
([`runbooks/oob-box.md`](runbooks/oob-box.md)).

Two Phase 6 pieces are deliberately edits to the main stack rather than files
that apply themselves, because the OOB box must not be able to change the
platform's own deployment:

* **Alertmanager clustering** - bring the stack up with
  `-f deploy/oob/main-stack.override.yml` (it publishes 9094 tcp+udp and sets
  the cluster flags). Without it the two Alertmanagers are two one-node
  clusters: duplicate pages, unshared silences.
* **The `oob-heartbeat` scrape job** - paste
  `deploy/oob/prometheus-job.snippet.yml` into
  `deploy/prometheus/prometheus.yml`. Until it exists, `OOBHeartbeatMissing`
  has no series and `OOBHeartbeatNeverSeen` (warning) says so.

## Open items to confirm in Phase 0
- ESXi license type per host; whether Essentials is on the table for backups.
- Exact Catalyst models/IOS versions and iLO generation per host.
- Hardware for the OOB mini-box: any x86 mini PC or a Pi 4+ with two NICs
  ([`runbooks/oob-box.md`](runbooks/oob-box.md) has the options and the cabling).
