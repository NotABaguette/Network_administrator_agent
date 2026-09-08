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
│   nightly: infra dr export ───────┼──> /srv/infra-dr/infra-dr-*.tar.gz
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

## Build it

1. **A VM on the other host.** Same size as mgmt-01 (2 vCPU, 8 GB, 100 GB is
   enough for a small estate), same OS, Docker and Docker Compose installed.
   Annotate the VM `expect:off` so the platform knows it is meant to be down
   and `VirtualMachineDown` does not fire on it forever
   (`infra_agent/collectors/esxi.py`, `expected_power_state`).
2. **A checkout of this repository** at the same path as on the primary. The
   failover script assumes it (`REPO_ROOT`).
3. **`deploy/.env`, by hand.** It is deliberately *not* in the DR bundle: it
   holds the Postgres, NetBox and Grafana passwords in plaintext, and a bundle
   travels over the network and sits on a second machine. Recreate it from
   `deploy/.env.example` and the owner's password manager. Keep it identical to
   the primary's, or NetBox will not open the restored database.
4. **The age private key, by hand.** Same reason. `~/.config/sops/age/keys.txt`
   from the owner's offline copy. Without it every secret in the bundle is an
   opaque blob.
5. **An inbox directory:** `sudo install -d -o infra -g infra /srv/infra-dr`.
6. **A key for the sync.** On the primary, `ssh-keygen -t ed25519 -f
   ~/.ssh/infra-dr` and put the public half in the standby's
   `~infra/.ssh/authorized_keys`, restricted:

   ```
   command="rsync --server -logDtpre.iLsfxCIvu . /srv/infra-dr/",restrict ssh-ed25519 AAAA...
   ```

   The primary is the only machine that pushes; the standby never pulls and
   never logs in to the primary. If the primary is compromised, the blast
   radius is one directory on the standby.
7. **Point the primary at it:** in `deploy/.env` on the primary,

   ```
   INFRA_DR_TARGET=ssh://infra@10.0.10.11/srv/infra-dr
   INFRA_DR_RETENTION_DAYS=14
   ```

8. **Stop the stack** on the standby and leave it stopped:
   `docker compose -f deploy/docker-compose.yml down`.

## Run it

**From the host, with cron or a systemd timer — the recommended route:**

```bash
# on the primary
15 2 * * *  cd /opt/infra-agent && deploy/standby/sync.sh >> /var/log/infra-dr.log 2>&1
```

**Or as the agent's own `dr-export` duty** (02:15 local, with a `dr-verify`
duty on Saturday morning). The duty is live as soon as `INFRA_DR_TARGET` is
set, but the shipped image is missing three things it needs, because they exist
for this job alone (`deploy/Dockerfile` installs git, curl and sops):

| Missing | Needed for | Symptom if absent |
|---|---|---|
| `postgresql-client` | `pg_dump` of the `infra` and `netbox` databases | A bundle with `postgres` marked failed, and a message to the owner |
| `openssh-client`, `rsync` | pushing to the standby | `DRExportStale`, `StandbyStale`, and a nightly failure message |
| A mounted SSH key | key auth to the standby | The same, with `Permission denied (publickey)` |

Until the image carries them, run `sync.sh` from the host: it uses the host's
`ssh`, `rsync` and `pg_dump`, and produces exactly the bundle the duty would
have. Either way it lands in the same place and the same alerts watch it. None
of this fails quietly — an export that cannot ship pages the owner, which is
what `DRExportStale` and `StandbyStale` are for.

Weekly, the agent's `dr-verify` duty restores the newest bundle into a
temporary directory and checks every part of it. `DRVerifyFailed` means the
backup is not a backup. `StandbyStale` means bundles are being made but not
landing.

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

What it then does: verify the newest bundle, `infra dr import --force`, start
the stack, wait for `/healthz`, run `flip-address.sh promote` if you wrote one.
It leaves the platform **frozen**. `infra dr import` always does - a restored
agent must not start reconciling an estate whose primary may still be half
alive.

Unfreezing is yours:

```bash
infra dr health          # collectors, plan store, graph, secrets, DR
infra collect            # one read-only round against the real devices
infra drift              # what changed while nobody was watching
infra change unfreeze    # only when the three above look right
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
verify and import there, start there, flip the address, stop here. The
primary's pre-failback `data/` is moved aside rather than deleted - it is
evidence about the outage, and it is the only copy of anything that happened
between the last bundle and the crash.

## Rehearsal

Twice a year, and after any change to this directory. Full procedure in
[`docs/runbooks/restore-test.md`](../../docs/runbooks/restore-test.md); the
short version is that a failover you have never performed is a document, not a
capability. Rehearse it with the primary deliberately powered off, not with
`--i-have-confirmed-the-primary-is-down`, so the pre-flight is exercised too.
