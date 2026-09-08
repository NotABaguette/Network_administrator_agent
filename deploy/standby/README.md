# Cold standby mgmt-01

A second copy of the platform on a **different ESXi host**, holding the same
compose stack, stopped. It receives a DR bundle every night and can be
promoted in minutes. It is deliberately cold, not warm: two live copies of an
agent that is allowed to reconfigure a FortiGate is a worse failure than
having no agent at all.

```
esx-01                              esx-02
├── mgmt-01          (running)      ├── mgmt-01-standby   (stopped)
│   docker compose up               │   docker compose down
│   nightly: infra dr export ───────┼──> /srv/infra-dr/infra-dr-*.tar.gz[.age]
└── ...                             └── ...
```

## Why cold

* **One writer.** The change engine, the Tier 0 loop and the Telegram approval
  channel all assume there is exactly one of them. A warm standby that starts
  triaging alerts while the primary is merely slow gives you two agents making
  changes with no coordination between them.
* **Nothing to keep in sync.** Postgres streaming replication, a shared volume
  or a clustered anything is a second system that can fail in its own ways, on
  an estate that has one administrator. A nightly file is boring, verifiable
  and restorable by hand at 3am.
* **The RPO is honest.** Up to 24 hours of snapshots and NetBox history, which
  is fine: snapshots are re-collected within five minutes of the standby coming
  up, and the estate's real configuration lives on the devices themselves. What
  is not re-collectible - the config git history, the plan store, the accepted
  baseline, the encrypted secrets - is exactly what the bundle carries.

## Where the state actually is

**The platform keeps everything it knows in the Docker named volume
`infra-data`**, mounted at `/app/data` in every service
(`deploy/docker-compose.yml`). It is not `./data` in the checkout. That single
fact shapes everything in this directory:

* a host-side `infra dr export` would bundle an empty `./data`: no plan store,
  no snapshots, no baseline, no config history - and could not reach the
  `postgres` service either, which publishes no host port;
* a host-side `infra dr import` would restore into a directory nothing reads,
  and would write the `FROZEN` marker where the agent never looks - so a
  promoted standby would come up **unfrozen, on stale state**, willing to
  change the estate. That is the two-administrators failure this whole
  directory exists to prevent.

So every `infra` command in these scripts runs *inside* the stack, through
`dr.compose.yml`:

```bash
docker compose --profile dr \
  -f deploy/docker-compose.yml -f deploy/standby/dr.compose.yml \
  run --rm dr infra dr export --to "$INFRA_DR_TARGET"
```

That container mounts the `infra-data` volume, joins the stack's network (so
`pg_dump` can reach `postgres`), and carries the four tools DR needs which the
main image deliberately does not: `pg_dump`, `ssh`, `rsync` and `age`
(`Dockerfile.dr`). `sync.sh`, `failover.sh` and `failback.sh` do this for you;
`INFRA_DR_CLI="uv run infra"` overrides it for an installation that does not
use compose.

## Build it

1. **A VM on the other host.** Same size as mgmt-01 (2 vCPU, 8 GB, 100 GB is
   enough for a small estate), same OS, Docker and Docker Compose installed.
   Annotate the VM `expect:off` so the platform knows it is meant to be down
   and `VirtualMachineDown` does not fire on it forever
   (`infra_agent/collectors/esxi.py`, `expected_power_state`).
2. **A checkout of this repository** at the same path as on the primary. The
   failover and failback scripts assume it (`REPO_ROOT`).
3. **`deploy/.env`, by hand.** It is deliberately *not* in the DR bundle: it
   holds the Postgres, NetBox and Grafana passwords in plaintext, and a bundle
   travels over the network and sits on a second machine. Recreate it from
   `deploy/.env.example` and the owner's password manager. Keep it identical to
   the primary's, or NetBox will not open the restored database.
4. **The age private key, by hand.** Same reason. `~/.config/sops/age/keys.txt`
   from the owner's offline copy. Without it every secret in the bundle is an
   opaque blob - and if `INFRA_DR_AGE_RECIPIENT` is set, so is the bundle.
5. **An inbox directory, 0700:**
   `sudo install -d -m 700 -o infra -g infra /srv/infra-dr`. A bundle is
   credential-equivalent (see "What is in a bundle" below); the directory mode
   is the last line of defence if the file mode is ever lost in a copy.
6. **A key for the sync**, on the primary:

   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/infra-dr -C infra-dr
   ```

   and on the standby, in `~infra/.ssh/authorized_keys`, restricted to writing
   into the inbox and nothing else:

   ```
   command="rrsync -wo /srv/infra-dr",restrict ssh-ed25519 AAAA... infra-dr
   ```

   `rrsync` ships with rsync (`/usr/share/doc/rsync/scripts/rrsync` or
   `/usr/bin/rrsync` on Debian). `-wo` is write-only into that one directory.
   **Do not** use a hand-written `command="rsync --server ..."`: the capability
   string in it is rsync-version specific and breaks the day either side is
   upgraded.

   With this key the primary can push bundles and do nothing else - no shell,
   no `ls`, no `rm`, not even `mkdir`. The platform knows
   (`INFRA_DR_SSH_RESTRICTED=1`, the default): it never tries a remote command,
   and retention on the standby is the standby's own cron, below. If the
   primary is compromised, the blast radius is one directory of files the
   attacker already had.

7. **Pin the standby's host key** on the primary - checking it is strict, so a
   missing entry is a failed push rather than a silent trust of whatever
   answered:

   ```bash
   ssh-keyscan -t ed25519 10.0.10.11 >> ~/.ssh/known_hosts
   # then compare the fingerprint with the standby's own:
   #   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   ```

8. **Point the primary at it:** in `deploy/.env` on the primary,

   ```
   INFRA_DR_TARGET=ssh://infra@10.0.10.11/srv/infra-dr
   INFRA_DR_RETENTION_DAYS=14
   INFRA_DR_SSH_KEY=/root/.ssh/infra-dr          # mounted into the DR container
   INFRA_DR_KNOWN_HOSTS=/root/.ssh/known_hosts
   INFRA_DR_INBOX=/srv/infra-dr                  # on the standby: the inbox
   INFRA_DR_AGE_RECIPIENT=age1...                # the recipient from .sops.yaml
   ```

9. **Retention on the standby**, in its own cron - the primary's key cannot
   delete anything:

   ```
   0 4 * * *  /opt/infra-agent/deploy/standby/prune.sh >> /var/log/infra-dr-prune.log 2>&1
   ```

   `prune.sh` never deletes the newest bundle, whatever the window says.

10. **Stop the stack** on the standby and leave it stopped:
    `docker compose -f deploy/docker-compose.yml down`.

## Run it

**From the host, with cron or a systemd timer:**

```bash
# on the primary
15 2 * * *  /opt/infra-agent/deploy/standby/sync.sh >> /var/log/infra-dr.log 2>&1
```

`sync.sh` runs the export in the DR container, prunes locally, and verifies
what it produced. It refuses early - before touching the network - if the push
key or the `known_hosts` entry is missing, because Docker would otherwise
bind-mount a *directory* over a missing key file and produce a failure nobody
enjoys reading at 2am.

**Or as the agent's own `dr-export` duty** (02:15 local, with a `dr-verify`
duty on Saturday morning), which is live as soon as `INFRA_DR_TARGET` is set.
The agent container has no `pg_dump`, no `ssh` and no `rsync` (they are in the
DR image, not the main one), so in that container the duty produces a bundle
without the database dumps and cannot push it. It does not lose the bundle
doing so: the export is pruned and recorded either way, `DRExportStale` stays
quiet, and `StandbyStale` - the true statement - is what fires. **On this
estate, use the cron entry above and let the duty be the backstop.**

Weekly, the `dr-verify` duty restores the newest bundle into a temporary
directory and checks every part of it. `DRVerifyFailed` means the backup is not
a backup. `StandbyStale` means bundles are being made but not landing.

## What is in a bundle

A bundle is **credential-equivalent**. `configs.bundle` is the config git
history, which holds raw running-configs: SNMP communities in cleartext,
reversible Cisco type-7 keys, FortiOS `ENC` blobs. `postgres/netbox.dump`
carries NetBox API tokens and Django password hashes. Treat one exactly as you
would treat a switch's `running-config` on a USB stick.

The platform's side of that: the bundle and its `.sha256` sidecar are written
`0600`, `data/dr` is `0700`, the push is `rsync --chmod=F600,D700` with strict
host-key checking, and with `INFRA_DR_AGE_RECIPIENT` set the bundle is
`age`-encrypted to the same recipient SOPS uses - the private half of which is
already required to be offline for any restore. The encrypted file *replaces*
the plaintext one rather than sitting beside it: keeping both would leave a
readable copy of every running-config on the volume for the whole retention
window. `infra dr verify` and `infra dr import` decrypt transparently when the
key is present, so the failover procedure does not change - and the weekly
verify then proves, every week, that the key still opens the bundles. That is
the failure this mechanism is most likely to have.

Your side of it: the inbox is `0700`, the standby is not a machine anybody else
logs in to, and a bundle that arrives without its sidecar is treated as
suspect - `infra dr import` refuses it.

## Fail over

```bash
# ON THE STANDBY
deploy/standby/failover.sh --primary 10.0.10.10
```

The pre-flight refuses while the primary answers ICMP, `/healthz` **or** SSH.
Each of those goes quiet on its own for reasons that have nothing to do with a
dead host, so all three have to be silent. If you have deliberately taken the
primary off the network, `--i-have-confirmed-the-primary-is-down` says so out
loud.

What it then does: check `deploy/.env` and the age key are present, verify the
newest bundle, `infra dr import --force` **into the volume**, start the stack,
wait for `/healthz`, and then confirm `/app/data/FROZEN` exists *inside the
running agent container*. If that last check fails it stops the stack rather
than leaving an unfrozen agent loose on the estate. `--force` moves whatever
the standby's volume already held into `data/pre-import/<stamp>/` - never
merges, never deletes.

Unfreezing is yours, and runs where the state is:

```bash
C="docker compose -f deploy/docker-compose.yml"
$C exec infra-agent infra dr health      # collectors, plan store, graph, secrets, DR
$C exec infra-agent infra collect        # one read-only round against the real devices
$C exec infra-agent infra drift          # what changed while nobody was watching
$C exec infra-agent infra change unfreeze
```

### The address flip

Write `deploy/standby/flip-address.sh` for your site; it is not in the
repository because it is the one part that is genuinely local. It takes one
argument, `promote` or `demote`, and does whichever of these you use:

* update the `mgmt-01` A record (a `nsupdate` call, or the FortiGate's internal
  DNS);
* take the primary's management IP on this VM - **only** once you are certain
  the primary is off the network, otherwise you have an address conflict on the
  management VLAN, which is the one VLAN you cannot afford to lose;
* update the FortiGate policy and the device management-plane ACLs that allow
  *mgmt-01's address* to reach the switches, the hosts and the iLOs. If you
  skip this the platform comes up healthy and collects nothing.

## Fail back

```bash
# ON THE STANDBY, while it is carrying the platform
deploy/standby/failback.sh --primary 10.0.10.10
```

Order matters and the script enforces it: freeze here, export from here,
verify and import there, start there, confirm the freeze there, flip the
address, stop here. The primary's pre-failback state is moved into
`data/pre-import/<stamp>/` inside its volume rather than deleted - it is
evidence about the outage, and the only copy of anything that happened between
the last bundle and the crash.

### The failback key

Failback is the only direction that needs a **standby → primary** key, and it
needs a real one: it runs `docker compose` on the primary over SSH. The nightly
push key does not work for this and must not be changed to; it is restricted on
purpose.

```bash
# on the standby
ssh-keygen -t ed25519 -f ~/.ssh/infra-failback -C infra-failback
ssh-keyscan -t ed25519 10.0.10.10 >> ~/.ssh/known_hosts   # check the fingerprint
# on the primary, in root's authorized_keys (or a user in the docker group):
#   ssh-ed25519 AAAA... infra-failback
```

Install it when you build the standby, not when you need it: at failback time
the primary is a machine somebody has just rebuilt and you will not want to be
copying keys around by hand. `INFRA_PRIMARY_SSH_USER` selects the account.

## Rehearsal

Twice a year, and after any change to this directory. Full procedure in
[`docs/runbooks/restore-test.md`](../../docs/runbooks/restore-test.md); the
short version is that a failover you have never performed is a document, not a
capability. Rehearse it with the primary deliberately powered off, not with
`--i-have-confirmed-the-primary-is-down`, so the pre-flight is exercised too.
