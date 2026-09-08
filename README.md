# Network Administrator Agent

An AI-driven infrastructure administrator for a small bare-metal estate:
HPE ProLiant DL hosts running standalone ESXi, a FortiGate 60F edge firewall
with WAN uplinks, and Cisco Catalyst 3xxx / 2960 switches.

It keeps an accurate, always-current model of the whole estate (physical,
L2/L3, storage, hypervisor, VM, guest, application), monitors it, explains it,
and makes changes under a tiered autonomy model where anything risky needs a
human approval that the model itself cannot grant.

Read [`docs/architecture.md`](docs/architecture.md) first, then
[`docs/risk-tiers.md`](docs/risk-tiers.md) and
[`docs/redaction-policy.md`](docs/redaction-policy.md). The phased delivery
plan is in [`docs/roadmap.md`](docs/roadmap.md).

## Safety model in one paragraph

Collectors use read-only credentials. Every change is a `ChangePlan` whose
risk tier is computed from impact analysis, not looked up. Tier 0 actions run
automatically only for objects that opted in by tag and only inside cause
allowlists, cooldowns and retry caps. Tier 1 and 2 changes wait for a human
approval issued through the CLI or the Telegram bot; the approve tool is not
exposed to the language model and the approval token never appears in any
payload the model can read. Every byte sent to the Claude API goes through one
redaction gateway that strips secrets and refuses raw configs. One environment
flag (`INFRA_FROZEN=1`) freezes all automation and makes the agent read-only.

## Status

Phases 0-6 are implemented: collectors and the observed-state store, NetBox
reconciliation and the topology graph, the redaction gateway and the read-only
AI layer, the change engine with native executors and human-only approval, the
guest and application layer, and the platform's own disaster recovery. The
acceptance criteria in [`docs/roadmap.md`](docs/roadmap.md) are exercises
against real hardware and are the owner's to run.

## Getting started (Phase 0)

```bash
uv sync                     # install
uv run infra onboard init   # age key, SOPS, API keys, Telegram, heartbeat
uv run infra onboard add-device fortigate 10.0.0.1 --name fw-01
uv run infra onboard add-device cisco_ios 10.0.0.11 --name sw-core-01
uv run infra onboard add-device esxi 10.0.0.21 --name esx-01
uv run infra onboard add-device ilo 10.0.0.121 --name esx-01-ilo
uv run infra onboard check   # prerequisites report with remediation
docker compose -f deploy/docker-compose.yml up -d
```

Secrets are prompted locally and written straight into `secrets/*.enc.yaml`
(SOPS + age). They never pass through the language model.

## Layout

| Path | Purpose |
|---|---|
| `docs/` | Architecture, risk tiers, redaction policy, prerequisites, onboarding, ADRs, generated topology |
| `deploy/` | Docker Compose stack: Postgres, NetBox, Prometheus, Alertmanager, Loki, Alloy, Grafana, exporters, infra services |
| `infra_agent/` | The Python package: collectors, store, config git store, correlation, monitoring, redaction, change engine, tools, MCP server, agent service, onboarding harness |
| `inventory/` | `seed.yaml`: devices onboarded before NetBox exists (gitignored; example provided) |
| `secrets/` | SOPS-encrypted secrets only; plaintext is gitignored |
| `tests/` | Unit tests on recorded fixtures |

`deploy/standby/` is the cold standby on a second host and its failover and
failback scripts; `deploy/oob/` is the out-of-band mini-box that watches the
platform from outside it.

## Recovering the platform itself

The estate has backups because this platform watches them; the platform has
one because of [`infra_agent/dr/`](infra_agent/dr/).

```bash
infra dr health                                    # could this platform recover right now?
infra dr export --to ssh://infra@standby/srv/infra-dr
infra dr verify                                    # prove the newest bundle restores
infra dr import <bundle>                           # onto empty ground; leaves it FROZEN
```

A nightly duty ships a dated, checksummed bundle to a cold standby on a second
ESXi host and a weekly one verifies it. `deploy/.env` and the age private key
are deliberately not in the bundle; the manifest says why. The runbooks are
[`docs/runbooks/dr-mgmt-01.md`](docs/runbooks/dr-mgmt-01.md),
[`restore-test.md`](docs/runbooks/restore-test.md),
[`oob-box.md`](docs/runbooks/oob-box.md) and
[`freeze.md`](docs/runbooks/freeze.md).

## Development

```bash
uv sync --group dev
uv run pytest
uv run ruff check .
```

## License

Apache-2.0, see [LICENSE](LICENSE).
