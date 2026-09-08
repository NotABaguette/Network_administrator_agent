# Out-of-band monitoring box

**Tier:** building it is a Tier 1 change (new device on the management VLAN).
Losing it is a Tier 0 incident that blocks Tier 2 edge changes.

The platform lives on `mgmt-01`, which sits behind the FortiGate, on a VLAN the
FortiGate routes, on a host the FortiGate's management ACL protects. Every one
of those is a single point of failure that makes the platform blind to its own
outage. The out-of-band box is a second, tiny vantage point that does not
depend on any of them, and it is the precondition
[`docs/risk-tiers.md`](../risk-tiers.md) puts on enabling any Tier 2 change on
the edge: if a FortiGate change locks everyone out, this box is what tells you,
and the console cable next to it is what gets you back in.

## What it does

* Probes the ISP gateways, the FortiGate, every switch, every ESXi host, every
  iLO and `mgmt-01`'s `/healthz` — from outside the platform.
* Runs an Alertmanager clustered with the main one, so silences and
  de-duplication are shared while both are up, and so alerting survives when
  the main one is not.
* Sends a dead-man heartbeat **only while it can see the WAN itself**, so a
  site-wide outage results in the external service paging the owner rather than
  in a heartbeat that lies.

## What it deliberately does not do

No NetBox, no Loki, no agent, no LLM, and **no credentials to any device**. It
cannot log in to anything, so a stolen OOB box gives up a Telegram bot token
and a list of IP addresses. It is not a second platform; it is a witness.

## Hardware

Anything x86 with two network interfaces, or a Pi 4/5 with one plus a USB NIC:

| Option | Notes |
|---|---|
| x86 mini PC (Intel N100 / older i3 NUC), 8 GB RAM, 128 GB SSD | The comfortable choice. Two NICs on many models; otherwise one plus a USB 3 gigabit adapter. Runs the stack with room to spare. |
| Raspberry Pi 4 (4 GB) or Pi 5 | Fine. Use an SSD over USB, **not** an SD card: Prometheus writes constantly and SD cards fail silently after a year of it. `arm64` images exist for every container here. |
| An old laptop | Works, and has a built-in UPS. Disable lid-close suspend. |

Requirements, in order of how badly they bite when missed:

1. **Its own power feed**, ideally a different circuit or a small UPS from the
   rack's. A box that dies with the rack tells you nothing.
2. **Two network legs** (below).
3. Enough disk for 30 days of a handful of probe series — 20 GB is generous.

## Cabling

```
                    ┌──────────────────────────────┐
   management VLAN  │  eth0  10.0.0.9/24           │
   (access port) ───┤                              │
                    │   OOB box                    │
   WAN uplink or ───┤  eth1  DHCP from the ISP,    │
   LTE dongle       │        or the LTE dongle     │
                    └──────────────────────────────┘
```

**eth0 — the management VLAN.** An access port on a switch, in the management
VLAN, so the box can reach the device management planes. Add it to the
management-plane ACLs alongside `mgmt-01` and the jump host, ICMP and HTTPS
only. It never needs SSH or SNMP to anything.

**eth1 — a path out that does not cross the LAN.** Either a second port on the
ISP's handoff (many small ISPs give a /29, and one address of it can be the OOB
box), or an LTE dongle. This is the leg that makes the box able to say "the WAN
is down" rather than "I cannot see anything". If the only available path is
through the FortiGate, you get much less: the box can still see `mgmt-01` dying,
but it cannot distinguish a dark site from a dead firewall, and `WanDown`
becomes meaningless. Say so in the runbook rather than pretending.

**Default route** on eth1, and a static route for the management VLAN on eth0.
Do **not** let the box route between them — it is a monitoring device, not a
bypass around the firewall you spent all this effort protecting:

```bash
sysctl -w net.ipv4.ip_forward=0     # and in /etc/sysctl.d/
```

**A serial console cable** to the FortiGate, taped to the box. When a Tier 2
edge change locks everyone out, this is how you get in. It is not part of the
software, and it is the most valuable thing in this runbook.

## Install

```bash
git clone <this repo> /opt/infra-agent && cd /opt/infra-agent
cp deploy/oob/.env.example deploy/oob/.env
$EDITOR deploy/oob/.env                       # addresses, heartbeat URL, chat id
install -m 0600 /dev/null deploy/oob/telegram_token
$EDITOR deploy/oob/telegram_token             # the bot token, nothing else
$EDITOR deploy/oob/targets/*.json             # your real addresses
docker compose -f deploy/oob/docker-compose.yml up -d
```

Check it:

```bash
curl -s localhost:9090/api/v1/targets | jq '.data.activeTargets[].health'
curl -s localhost:9093/api/v2/status  | jq '.cluster'      # peers: 2 when clustered
curl -s localhost:9105/heartbeat.prom                      # wan_visible 1
```

### Two things to do on the main stack

1. **Publish Alertmanager's gossip port.** In `deploy/docker-compose.yml` the
   `alertmanager` service binds `127.0.0.1:9093` only; clustering needs 9094
   reachable from the OOB box, and `--cluster.advertise-address` set to
   `mgmt-01`'s management address. Without it the cluster silently stays at one
   node each and silences are not shared. Verify with
   `curl -s localhost:9093/api/v2/status | jq '.cluster.peers | length'` — it
   should say 2 on both sides.

2. **Scrape the OOB heartbeat**, so `OOBHeartbeatMissing` in
   `infra_agent/monitoring/rules/dr.yaml` has a series to alert on. Add to
   `deploy/prometheus/prometheus.yml`:

   ```yaml
     - job_name: oob-heartbeat
       metrics_path: /heartbeat.prom
       static_configs: [{ targets: ["10.0.0.9:9105"] }]
   ```

   This one job is the difference between "the OOB box is watching us" and "the
   OOB box has been off since June and nobody noticed". It is the classic
   monitoring failure: the watcher nobody watches.

## Alerts it raises

From `deploy/oob/rules.yaml`, all carrying `vantage="oob"`:

| Alert | Means |
|---|---|
| `MgmtVmDown` | mgmt-01's health endpoint is silent from outside. If the switches still answer, this is mgmt-01 alone. |
| `MgmtVmUnreachable` | mgmt-01 is not on the network at all. Look at its host first. |
| `PrimaryAlertmanagerDown` | The main notification path is gone; this box is now the only one that can page. |
| `WanDown` | Neither anycast resolver answers from the WAN leg. The site is dark. |
| `WanGatewayDownOOB` | One uplink is down. Both firing means no path out. |
| `FirewallDownOOB`, `SwitchDownOOB`, `EsxiHostDownOOB`, `IloDownOOB` | The named device is unreachable from a vantage that does not depend on the platform. |
| `OOBWanLegDown` | This box has lost its own second leg; the heartbeat has stopped on purpose. |

And from the main stack, about this box: `OOBHeartbeatMissing`.

## When it is down

The OOB box being down is not an outage — but it is a **blocker**. While
`OOBHeartbeatMissing` is firing:

* Do not enable or approve any Tier 2 change on the edge. The FortiGate
  executor's rollback assumes somebody is watching from outside, and a locked
  door with nobody outside it is a site visit.
* Tier 0 and Tier 1 are unaffected.
* Treat the dead-man heartbeat as the only external signal, and remember it now
  has one source instead of two.

Fixing it is a site visit or a power cycle. Nothing on it is precious: the
configuration is in this repository and the metrics are 30 days of probe
history nobody needs.
