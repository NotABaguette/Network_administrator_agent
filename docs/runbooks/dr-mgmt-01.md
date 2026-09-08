# Disaster recovery

**Tier:** every procedure here is Tier 2 or manual. Nothing in this runbook is
something the agent may do on its own, and most of it happens while the agent
is frozen or absent.

Five losses, in the order they are likely: mgmt-01, an ESXi host, the
FortiGate, the WAN, the out-of-band box. Each section says how you find out,
what you decide, what you do, how you know it worked, and — because this is a
platform that can act on its own — **what the agent can and cannot do while
frozen**.

## The one paragraph to read first

The platform's own backup is a nightly `infra dr export` bundle on the standby
(`deploy/standby/README.md`). It contains `data_dir` (snapshots, topology
graph, plan store, accepted baseline), the config git repository as a git
bundle, the SOPS-encrypted secrets, the seed inventory, `pg_dump` of the
`infra` and `netbox` databases, and the Grafana dashboards. It does **not**
contain `deploy/.env` or the age private key — both are recreated by hand from
the owner's password manager and offline copy, because a bundle travels over
the network and sits on a second machine, and one archive holding every
platform credential in plaintext is a worse risk than the inconvenience.

**Every `infra` command below runs inside the stack.** The platform's state is
the Docker named volume `infra-data` (`/app/data` in the containers), not
`./data` in the checkout: a host-side `infra dr export` would bundle an empty
directory and a host-side `infra dr import` would restore where nothing reads -
including the `FROZEN` marker, leaving a promoted platform *unfrozen*. Two
prefixes, used throughout this runbook:

```bash
# Read-only, against the running stack:
C="docker compose -f deploy/docker-compose.yml"
$C exec infra-agent infra dr health

# DR itself (pg_dump, ssh, rsync, age live in this image only):
DR="docker compose --profile dr -f deploy/docker-compose.yml \
      -f deploy/standby/dr.compose.yml run --rm dr infra"
$DR dr list                  # bundles in the local keep directory or the target
$DR dr verify                # prove the newest one restores
$DR dr export --to ssh://infra@standby/srv/infra-dr
$DR dr import /inbox/<bundle>   # onto empty ground; leaves the platform FROZEN
```

`INFRA_DR_CLI="uv run infra"` in the environment makes the scripts in
`deploy/standby/` use a host CLI instead, for an installation without compose;
then `INFRA_DATA_DIR` must point at the real state directory.

## What "frozen" means for the agent

`INFRA_FROZEN=1`, or `data_dir/FROZEN`, and the agent becomes read-only.
Details in [`freeze.md`](freeze.md). During any disaster below, assume frozen.

**Can, while frozen:** collect (read-only credentials), answer questions,
compute impact analysis, produce the digest, run `infra dr export`, run
`infra dr verify`, raise alerts, propose ChangePlans.

**Cannot, while frozen:** execute any ChangePlan of any tier, run Tier 0
actions, write to NetBox, restart a VM, touch a switch, a firewall or a host.
Approval still works — the plan is approved and waits — but execution refuses.

A restore always ends frozen. That is deliberate: an agent that comes up
against restored state and starts reconciling an estate whose primary may be
half alive is how you get two administrators fighting over one FortiGate.

---

## 1. Loss of mgmt-01

### Detection
* `MgmtVmDown` or `MgmtVmUnreachable` from the out-of-band box.
* The dead-man heartbeat stops and the external service pages the owner.
* Silence: no digest at 07:30, no Telegram messages at all.

The distinguishing question is whether the *host* is up. `EsxiHostDownOOB` for
`esx-01` firing at the same time means this is section 2, not section 1.

### Decision

| Situation | Do |
|---|---|
| VM is up, a container is unhealthy | Restart the stack. Not a disaster. |
| VM is down, host is up | Power it on from the host (`vim-cmd vmsvc/power.on`). |
| VM's disk is gone, host is up | Restore from bundle onto a new VM on the same host. |
| Host is gone | Fail over to the standby (section 2). |

Fail over when: the host is not coming back within the outage the owner can
tolerate, or the VM's storage is lost. Do **not** fail over because the
platform is merely slow — two live mgmt-01s is a worse incident than none, and
`deploy/standby/failover.sh` refuses while the primary answers on any of ICMP,
`/healthz` or SSH.

### Steps — restore onto a fresh VM

```bash
# 1. New VM on a working host: same OS, Docker, this repository at the same path.
# 2. The two things the bundle does not carry:
cp deploy/.env.example deploy/.env && $EDITOR deploy/.env   # from the password manager
install -m600 ~/keys.txt ~/.config/sops/age/keys.txt        # from the offline copy
# 3. The newest bundle from the standby, into the inbox this host mounts at /inbox:
sudo install -d -m 700 /srv/infra-dr
scp infra@standby:/srv/infra-dr/infra-dr-*.tar.gz* /srv/infra-dr/
DR="docker compose --profile dr -f deploy/docker-compose.yml \
      -f deploy/standby/dr.compose.yml run --rm dr infra"
$DR dr verify /inbox/infra-dr-mgmt-01-<stamp>.tar.gz     # never restore an unverified bundle
$DR dr import /inbox/infra-dr-mgmt-01-<stamp>.tar.gz     # into the infra-data volume
# 4. Everything up. The import left the platform FROZEN; it stays that way.
C="docker compose -f deploy/docker-compose.yml"
$C up -d
$C exec infra-agent test -f /app/data/FROZEN && echo "frozen, as it should be"
# 5. The databases. The dumps are staged inside the volume, which the postgres
#    container cannot see, so they go in over stdin:
$C exec -T infra-agent cat /app/data/dr-restore/postgres/netbox.dump |
  $C exec -T postgres pg_restore -U "${POSTGRES_USER:-infra}" -d netbox --clean --if-exists
$C exec -T infra-agent cat /app/data/dr-restore/postgres/infra.dump |
  $C exec -T postgres pg_restore -U "${POSTGRES_USER:-infra}" -d infra --clean --if-exists
```

### Steps — fail over to the standby

`deploy/standby/failover.sh --primary <old-ip>`; the README in that directory is
the long version. Then the address flip, which is the step people forget: the
management-plane ACLs on the switches, the hosts and the FortiGate allow
*mgmt-01's address*. A platform that comes up healthy on a new address collects
nothing and reports every device as unreachable.

### Verification

```bash
C="docker compose -f deploy/docker-compose.yml"
$C exec infra-agent infra dr health   # green except heartbeat if the agent is not up yet
$C exec infra-agent infra collect     # one read-only round
$C exec infra-agent infra graph build
$C exec infra-agent infra drift       # what changed while nobody watched - read this properly
$C exec infra-agent infra change list --state awaiting_approval   # plans mid-flight
```

Run these *through the stack*, not on the host: on the host they read an empty
`./data`, report a healthy platform with no devices, and prove nothing.

Look specifically for a plan in `executing` or `verifying`: a change that was
in flight when the platform died was **not rolled back**, because the thing that
would have rolled it back is what died. Check that device by hand against the
config git history before unfreezing.

Then `infra change unfreeze`, and tell the owner.

### What was lost

Up to 24 hours of snapshots and NetBox history. Snapshots regenerate within one
collector cycle. The config git history, the plan store and the accepted
baseline are in the bundle. Anything that happened between the last bundle and
the crash is gone from the platform's memory but is still on the devices — which
is why `infra drift` immediately after a restore is not optional.

---

## 2. Loss of an ESXi host

### Detection
`EsxiHostDownOOB`, `DeviceUnreachable`, every VM on it reported down, and its
`ilo` collector still working — an iLO that answers while the host does not
means the machine has power and the hypervisor is the problem.

### Decision
There is no vCenter and no HA: **nothing moves on its own**. Every VM on that
host is down until a human acts. First question: is `mgmt-01` on it? If yes,
this is also section 1 and the standby exists precisely for this.

### Steps
1. iLO first: power state, IML, health rollup. `infra graph impact esx-01`
   lists what is affected before you touch anything.
2. Power/POST failure → the host is a hardware job. Recover the VMs by
   re-registering them on another host from the shared datastore, or from
   backup if the storage was local.
3. PSOD or hung hypervisor → reset from iLO, then read `/var/core` and the IML.
4. If the storage is intact and the host is not: register the VMs on the
   surviving host (`vim-cmd solo/registervm /vmfs/volumes/<ds>/<vm>/<vm>.vmx`),
   power on in dependency order — domain controller or DNS first, then the
   database, then the rest.

### Verification
`infra collect`, then `infra graph build`, then check
`infra_esxi_vm_power_state` against `infra_esxi_vm_expected_on` — any VM that
is expected on and is off is still down. Re-check backups
(`infra_backup_last_success_timestamp_seconds`) for every VM you moved: a
ghettoVCB job pinned to the dead host's cron is not running any more.

### While frozen
The agent will report all of this and will not act on any of it. In particular
the Tier 0 "power on a VM tagged `auto:restart`" action does not run while
frozen — which is correct during a host failure, because powering VMs on in the
wrong order is worse than leaving them down.

---

## 3. Loss of the FortiGate

### Detection
`FirewallDownOOB` from the out-of-band box, everything behind it unreachable,
`WanGatewayDown` from the main stack — which by itself proves nothing, because
the main stack is behind the firewall it is reporting on.

### Decision
The 60F is the default gateway for every VLAN and the only path out. There is
no HA pair. This is an outage, not a degradation.

If a Tier 2 edge change was executing when it happened: the executor's
post-check has already failed and the FortiOS executor should have applied the
inverse object operations from the captured previous body
(`infra_agent/change/executors/base.py`). If the platform died mid-change, it
did not. Assume the change is half-applied.

### Steps
1. **Serial console.** The cable taped to the OOB box. This is the entire
   reason it is taped to the OOB box.
2. `get system status`, `diagnose hardware deviceinfo nic <wan>`, check for a
   crashed process or a failed boot.
3. Half-applied change → revert it by hand from the config git repository:
   `git -C data/configs log --oneline -- fw-01` and diff the last known-good
   commit. The raw config is in git and only in git; it never goes to the model.
4. Dead hardware → the cold spare, restored from the config backup in git.
   Reconfirm the API user is bound to mgmt-01's address before the collectors
   come back, or every FortiGate collection fails with 403.

### Verification
Console first, then from mgmt-01: `infra collect --device fw-01`, `infra drift`,
and confirm the management-plane ACLs still allow mgmt-01 and the OOB box.

### While frozen
Nothing about the firewall changes without a human. The agent will keep
collecting the moment the device answers, which is how you confirm the recovery.

---

## 4. Loss of the WAN

### Detection
`WanDown` from the OOB box's WAN leg — the only vantage that can tell "our
uplink is down" from "we are down". The dead-man heartbeat from both mgmt-01
and the OOB box stops, deliberately, and the external service pages the owner.

### Decision
Nothing inside the estate is broken. The estate is fine and unreachable. The
temptation is to change something; resist it. Almost every "fix" applied during
an ISP outage is discovered, two hours later, to have been the actual outage.

### Steps
1. Confirm from the OOB box: `docker logs infra-oob-heartbeat-1` shows the WAN
   check failing; `probe_success{job="blackbox-wan"}` is 0 for both gateways.
2. One gateway down, one up → the FortiGate should have failed over. If it did
   not, that is a firewall problem, not an ISP problem.
3. Both down → the ISP. Phone them. Note the time; the digest will want it.
4. If the LTE leg is up, the OOB box is still alerting and the owner still has
   a view. That is the entire value of the second leg.

### Verification
`probe_success{job="blackbox-wan"}` returns to 1, both heartbeats resume,
`infra dr export` catches up on the night it missed (`DRExportStale` clears).

### While frozen
The agent cannot reach the Claude API, so triage is unavailable and the digest
will not be written. Collection, alerting and the OOB box are unaffected —
they are all local. This is the case that most justifies the rule that the
platform must degrade to "loud and dumb" rather than to "silent".

---

## 5. Loss of the out-of-band box

### Detection
`OOBHeartbeatMissing` on the main stack — which only exists if the scrape job
in [`oob-box.md`](oob-box.md) was actually added. Also: no `vantage="oob"`
alerts have arrived in a suspiciously long time.

### Decision
Not an outage. A **blocker**: while it is down, no Tier 2 change on the edge may
be enabled or approved ([`docs/risk-tiers.md`](../risk-tiers.md)). A FortiGate
change with nobody watching from outside is a site visit waiting to happen.

### Steps
Power cycle it, or a site visit. Nothing on it is precious: the configuration
is in this repository, and its metrics are a month of probe history nobody
needs. If it will be down for a while, say so out loud to the owner, because
the platform's own opinion of its health no longer has a second source.

### Verification
```bash
curl -s <oob>:9105/heartbeat.prom                        # wan_visible 1, recent timestamp
curl -s <oob>:9093/api/v2/status | jq '.cluster.peers | length'   # 2
```
`OOBHeartbeatMissing` clears within two scrape intervals.

---

## Appendix A — the backup contracts the collector reads

### A1. ghettoVCB on an ESXi host

`infra_agent/collectors/backups.py` reads two things over SSH: the ghettoVCB
logs and the backup tree itself. Both have a layout, and the collector cannot
guess one it was never told about — so this is the layout, and the cron line
that produces it:

```sh
# In ghettoVCB.conf on the host:
VM_BACKUP_VOLUME=/vmfs/volumes/backup          # == INFRA_DR_BACKUP_ROOT
VM_BACKUP_ROTATION_COUNT=3

# In the host's crontab (/var/spool/cron/crontabs/root; re-add it after a
# reboot or an upgrade, ESXi does not persist crontab edits by itself):
0 2 * * * /vmfs/volumes/backup/ghettoVCB.sh \
    -f /vmfs/volumes/backup/vms.txt \
    -l /vmfs/volumes/backup/ghettoVCB-logs/ghettoVCB-$(date +\%F_\%H-\%M-\%S).log
```

| What | Where | Setting |
|---|---|---|
| Backup root | `/vmfs/volumes/backup` | `INFRA_DR_BACKUP_ROOT`, or the device tag `backup-root:<path>` |
| Restore points | `<root>/<vm>/<vm>-<YYYY-MM-DD_HH-MM-SS>/` | ghettoVCB's own layout under `VM_BACKUP_VOLUME` |
| Logs | `<root>/ghettoVCB-logs/ghettoVCB-*.log` | the `-l` argument above |
| Timezone | UTC | `INFRA_DR_BACKUP_TIMEZONE`, or the device tag `backup-tz:<zone>` |

Three details that cost a real backup each if they are wrong:

* **The `-l` path.** ghettoVCB's default is `/tmp`, which an ESXi host clears
  on reboot. The collector looks in `<root>/ghettoVCB-logs`, then `<root>`,
  then `/tmp`, and a `backup-logs:<path>` device tag overrides all three — but
  only the first survives a reboot, so use it.
* **The timezone.** ESXi is UTC out of the box and the collector reads log
  stamps and restore-point directory names in UTC unless told otherwise. A host
  somebody set to local time skews every `BackupMissing` threshold by its
  offset — up to twelve hours early or, worse, twelve hours blind. Either leave
  the host on UTC or tag it `backup-tz:Europe/Berlin`.
* **The VM list.** A VM tagged `backup:daily` that is not in `vms.txt` is the
  most likely backup failure on this estate, and it produces no log line at
  all. The collector publishes
  `infra_backup_last_success_timestamp_seconds{vm=...} = 0` for it, so
  `BackupMissing` fires on "never" exactly as it does on "not lately".

The collector also carries the `CONFIG - VM_BACKUP_VOLUME` and
`CONFIG - BACKUP_LOG_OUTPUT` lines out of the newest log into the snapshot
(`job.config`), which is the fastest way to see what the host thinks it is
doing versus what the settings say.

### A2. The agent-based backup contract

The platform monitors backups it does not take. For guests running restic,
borg, or a shell script, the contract is one file:

**`/var/lib/infra-backup/status.json` inside the guest**, written atomically
after every run (write to `status.json.tmp`, then `mv`):

```json
{
  "version": 1,
  "host": "web-01",
  "tool": "restic",
  "schedule": "daily",
  "status": "ok",
  "last_success": "2026-09-07T02:14:03Z",
  "last_attempt": "2026-09-07T02:14:03Z",
  "size_bytes": 51234567890,
  "snapshots": 42,
  "error": null
}
```

| Field | Meaning |
|---|---|
| `host` | The VM name as ESXi knows it. This is the join key; get it wrong and the VM looks unprotected. |
| `status` | `ok` or anything else. Anything else is a failure. |
| `last_success` | RFC 3339. The one field the alert is built on. |
| `size_bytes`, `snapshots` | Optional, for the digest. |
| `error` | Short, one line, **no credentials**. |

The collector reads an explicit allowlist of fields and drops everything else,
so a repository URL — which for restic and borg routinely carries a password —
cannot end up in a snapshot the model may later read. Do not put one in the
file anyway.

Getting the file to the platform, either way:

* **Push it to the shared backup target:** `<backup root>/agent-status/<vm>.json`,
  which the `backups` collector reads over SSH along with the ghettoVCB logs.
* **Or mount the directory on mgmt-01** and set
  `INFRA_DR_BACKUP_STATUS_DIR=/mnt/backup-status`.

Schedules come from the VM's annotation in ESXi, the same place `expect:off`
lives: tag a VM `backup:daily` or `backup:weekly` and it is alerted on; tag it
`backup:none`, or leave it untagged, and it is reported but never alerted on.
Guessing that every VM needs a nightly backup produces an alert nobody acts on,
which is the same as no alert at all.

## Appendix B — what is in a bundle

```
manifest.json         sha256 per file, versions, host, and why things are missing
data/                 snapshots, graph, plans.db, baseline, dr-state
configs.bundle        git bundle --all of the config repository
secrets/*.enc.yaml    SOPS-encrypted, copied verbatim
inventory/seed.yaml
postgres/infra.dump   pg_dump --format=custom
postgres/netbox.dump
grafana/*.json        dashboards, when Grafana answered
```

With `INFRA_DR_AGE_RECIPIENT` set the bundle is
`infra-dr-<host>-<stamp>.tar.gz.age`, encrypted to the same age recipient SOPS
uses, and the plaintext is not kept: an encrypted bundle is the bundle, on the
standby and on mgmt-01 both. `infra dr verify` and `infra dr import` decrypt it
transparently when the key is present, so nothing about the procedures above
changes - and the weekly verify proves the key still opens them, which is the
failure mode that quietly turns every bundle since a key rotation into noise.

### A bundle is credential-equivalent

Treat one exactly as you would treat a switch's `running-config` on a USB
stick, because that is what is in it:

* `configs.bundle` is the config git history — raw running-configs, which carry
  SNMP communities in cleartext, reversible Cisco type-7 keys, `username ...
  secret` lines and FortiOS `ENC` blobs. These configs never pass through the
  redaction gateway; that is deliberate (ADR 0004) and it is why the git
  repository lives on mgmt-01 and not on a hosted remote.
* `postgres/netbox.dump` carries NetBox API tokens (including the platform's
  own) and Django password hashes.
* `data/` carries the plan store — approval **token hashes**, never tokens —
  and the agent state database.

What the platform does about it: the bundle and its `.sha256` sidecar are
written `0600`, `data/dr` is `0700`, the push is `rsync --chmod=F600,D700` with
strict host-key checking, and the shipped copy is age-encrypted when a
recipient is configured. What you must do about it: keep the standby inbox
`0700`, do not copy a bundle to a laptop "to look at it", and treat a bundle
that arrives **without its `.sha256` sidecar as suspect** — the manifest hashes
every member, but only the sidecar covers the manifest itself, so a missing
sidecar is the one shape of tampering the per-file hashes cannot see.
`infra dr import` refuses a bundle whose sidecar is missing; `infra dr verify`
says so and carries on, because verifying a suspect bundle is exactly what you
want to be able to do.

Not included, on purpose:

| Missing | Why |
|---|---|
| `deploy/.env` | Every platform password in plaintext. A bundle travels and rests on a second machine; one stolen archive would be a full compromise. Recreate from `deploy/.env.example`. |
| The age private key | Same reason. Without it the encrypted secrets are opaque, which is what makes them safe to ship. Restore from the owner's offline copy. |
| Prometheus and Loki data | Observations, not the system of record, and larger than everything else combined. Rebuilt by scraping. The parts a human wrote — alert rules, dashboards — are in git and in `grafana/`. |
| The `FROZEN` marker | State of one installation, not of the estate. An import sets its own. |
