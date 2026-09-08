# Quarterly restore test

**Tier:** the restore itself is isolated and harmless (a scratch VM, read-only
credentials). The one genuinely risky step — pointing collectors at a real
device from a second machine — is called out below and is Tier 1.

**Cadence:** quarterly, and after any change to `infra_agent/dr/`,
`deploy/standby/`, or the platform's own storage layout.

A backup nobody restored is a rumour. The weekly `dr-verify` duty proves a
bundle unpacks and its parts load; it does not prove that a human, on a bad
day, can turn that bundle back into a working platform. That is what this test
is for, and the deliverable is not a green tick — it is the list of things that
were not in the bundle and had to be found somewhere else.

Budget 90 minutes the first time, 30 once it is familiar.

## Before you start

Write down the start time. Do not tell the agent to freeze; the primary keeps
running normally throughout. Nothing here touches it.

**Every `infra` command in this runbook runs inside a stack**, because the
platform's state is the `infra-data` volume and not `./data` (see
`deploy/standby/README.md`, "Where the state actually is"). Run them on the
host and each one answers about an empty directory: the restore appears to work
and proves nothing, which is the worst possible outcome for this test. Two
prefixes, one for each machine:

```bash
C="docker compose -f deploy/docker-compose.yml"                    # the running stack
DR="docker compose --profile dr -f deploy/docker-compose.yml \
      -f deploy/standby/dr.compose.yml run --rm dr infra"          # DR tooling
```

## 1. Pick a bundle and verify it where it lives (5 min)

```bash
# on the primary
$DR dr list
$DR dr verify --json | tee /tmp/restore-test-verify.json
```

Use a bundle from the **standby**, not a fresh local one. The question is
whether what arrived over the wire is restorable, and a bundle that was never
transferred does not answer it.

```bash
sudo install -d -m 700 /srv/infra-dr-test        # on the scratch VM
scp infra@standby:/srv/infra-dr/infra-dr-*.tar.gz* /srv/infra-dr-test/
sha256sum -c /srv/infra-dr-test/infra-dr-*.sha256
```

A bundle that arrived **without its sidecar** is a finding, not an
inconvenience: the manifest hashes every member but only the sidecar covers the
manifest, so a missing one is the single shape of tampering the per-file hashes
cannot see. `infra dr import` refuses it.

**Record:** which checks passed, which components the manifest reports as
incomplete, and the bundle's age.

## 2. Build the scratch VM (15 min)

A throwaway VM on any host — 2 vCPU, 4 GB, 40 GB — with Docker and a clone of
this repository. **Give it no route to the management VLAN yet.** Until step 6
this machine must not be able to reach a single device: a second platform on
the management network is exactly the two-administrators failure the standby is
designed to avoid.

Annotate it `expect:off` so `VirtualMachineDown` does not fire on it, and
delete it when you are done.

## 3. Restore, and count what you had to fetch by hand (20 min)

On the scratch VM, with `INFRA_DR_INBOX=/srv/infra-dr-test` in `deploy/.env`
(that is what `dr.compose.yml` mounts at `/inbox`):

```bash
$DR dr verify /inbox/infra-dr-<stamp>.tar.gz
$DR dr import /inbox/infra-dr-<stamp>.tar.gz
```

The import refuses a non-empty `data_dir` and leaves the platform frozen. Both
are correct; do not `--force` past the first one on a scratch VM that should be
empty anyway — if it complains, you built the VM wrong. (`--force` would not
lose anything either: it moves what is there into `data/pre-import/<stamp>/`.
But on a scratch VM it means you restored on top of something.)

An age-encrypted bundle (`...tar.gz.age`) needs no different command — verify
and import decrypt it with the key from step 3. If they cannot, you have found
the most important possible failure of this test: **you have backups nobody can
read**. Stop and fix that before anything else.

Now the interesting part. The bundle deliberately excludes two things:

```bash
cp deploy/.env.example deploy/.env && $EDITOR deploy/.env
install -m600 <age key> ~/.config/sops/age/keys.txt
```

**Record honestly:** how long did it take to find the `.env` values and the age
key? If the answer is "I could not", you have just discovered the real gap, and
it is a much more valuable finding than a passing restore. Fix it by putting
both in the owner's password manager with a note pointing at this runbook.

## 4. Bring it up and prove the parts (15 min)

```bash
$C up -d postgres
# The dumps are staged inside the volume, which the postgres container cannot
# see, so they go in over stdin:
$C exec -T infra-agent cat /app/data/dr-restore/postgres/netbox.dump |
  $C exec -T postgres pg_restore -U "${POSTGRES_USER:-infra}" -d netbox --clean --if-exists
$C exec -T infra-agent cat /app/data/dr-restore/postgres/infra.dump |
  $C exec -T postgres pg_restore -U "${POSTGRES_USER:-infra}" -d infra --clean --if-exists
$C up -d

$C exec infra-agent test -f /app/data/FROZEN && echo "frozen, as a restore must be"
$C exec infra-agent infra dr health --json | tee /tmp/restore-test-health.json
```

Then prove each part by hand, because `dr health` is code and this test exists
to check the code:

```bash
$C exec infra-agent infra change list      # the plan store carries the real history
$C exec infra-agent infra baseline show    # the accepted baseline came back
$C exec infra-agent git -C /app/data/configs log --oneline | head   # real history
$C exec infra-agent infra graph build && $C exec infra-agent infra graph impact esx-01
sops -d secrets/devices.enc.yaml | head -3   # the age key really does open them
```

That last one is the step people skip, and it is the one that fails: an age key
that was rotated on the primary and never copied to the owner's offline store
turns every bundle since into an archive of noise.

## 5. Compare against the primary (10 min)

```bash
# on the scratch VM
$C exec infra-agent infra graph build
$C exec -T infra-agent infra graph impact fw-01 > /tmp/restored-impact.txt
# on the primary
$C exec -T infra-agent infra graph impact fw-01 > /tmp/primary-impact.txt
diff /tmp/primary-impact.txt /tmp/restored-impact.txt
```

Differences are expected and should all be explainable by the bundle's age.
A difference that is **not** explained by time is the finding: something is not
in the bundle that should be.

## 6. One read-only collection against one real device (10 min, Tier 1)

This is the only step that touches production. Give the scratch VM a route to
the management VLAN, or better, run it against **one** device by temporarily
allowing its address in that device's management ACL.

```bash
$C exec infra-agent infra collect --device sw-core-01   # read-only credential, one device
$C exec infra-agent infra drift --device sw-core-01
```

What you are proving: the restored *credentials* work. Everything up to here
proves files came back; only this proves they came back usable. Choose a switch,
not the FortiGate — a read-only Catalyst session is the least consequential
thing on the estate.

Remove the ACL entry afterwards. Write it down now so you do not forget.

## 7. Tear down and write it up (10 min)

```bash
$C down -v          # -v: the restored infra-data volume goes too. On the scratch
                    # VM only - never type this on the primary.
rm -rf /srv/infra-dr-test
# power off and delete the scratch VM; remove the temporary ACL entry
```

Record, in the repository or wherever the owner keeps this:

| | |
|---|---|
| Date, bundle, its age | |
| Wall-clock to a working platform | The number that matters on the bad day |
| Manual steps needed | `.env`, age key, anything else |
| What was missing from the bundle | The actual output of this test |
| What failed and what you changed | |

If the total is more than about two hours, the failover path
(`deploy/standby/failover.sh`) is the answer for a real outage and this restore
is the fallback — which is fine, as long as somebody has decided that on a
calm day rather than at 3am.

## Rehearse the failover too

Twice a year, do the harder version: power off the primary VM and run
`deploy/standby/failover.sh --primary <ip>` for real, without
`--i-have-confirmed-the-primary-is-down`, so the pre-flight refusal is exercised
as well. Then fail back. A failover you have never performed is a document, not
a capability.
