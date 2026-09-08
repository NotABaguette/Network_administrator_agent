# Break-glass: freeze and unfreeze

**Tier:** freezing is always allowed, by anyone, at any time, with no approval.
Unfreezing is a deliberate human act with a checklist.

Freezing is the one control that is meant to be pulled in a hurry and thought
about afterwards. If you are unsure whether to freeze, freeze. The cost of a
wrong freeze is a delayed change; the cost of a wrong hesitation is an
autonomous system making a bad situation worse while you read documentation.

## Pull the handle

Three ways, all equivalent in effect and available in different disasters:

```bash
# In the compose deployment, run it where the state is - data_dir is the
# infra-data volume, not ./data:
docker compose -f deploy/docker-compose.yml exec infra-agent infra change freeze
docker compose -f deploy/docker-compose.yml exec infra-agent test -f /app/data/FROZEN
```

```
/freeze                             # in the owner's Telegram chat
```

```bash
INFRA_FROZEN=1 docker compose -f deploy/docker-compose.yml up -d   # environment
```

Use Telegram from a phone. Use the CLI when you are already on the box. Use the
environment variable when you want the freeze to survive somebody clearing the
marker — that is the difference between the two mechanisms and it matters:

| Mechanism | Set by | Cleared by | Survives a restart |
|---|---|---|---|
| `data_dir/FROZEN` marker | `infra change freeze`, `/freeze`, `infra dr import` | `infra change unfreeze`, `/unfreeze` | Yes — the file is on the shared `infra-data` volume |
| `INFRA_FROZEN=1` | The environment / `deploy/.env` | Editing it out and restarting | Yes, and **cannot** be cleared by `unfreeze` |

The marker is re-read on every path that is about to act — a `stat` per triage
run — so a freeze takes effect within seconds, not at the next restart
(`infra_agent/agent/freeze.py`). `INFRA_FROZEN=1` in the environment keeps the
service frozen whether or not a marker exists, which is why the belt-and-braces
version of a serious freeze is both.

## What actually stops

Frozen, the agent is **read-only**. It keeps watching and keeps talking; it
stops touching things.

**Still runs:**

* every collector, with its read-only credentials;
* alerting, the Alertmanager webhook and Telegram notifications;
* triage — the agent still explains what it thinks is happening;
* the daily digest, weekly report and firmware inventory;
* impact analysis, drift, `infra graph`, all read tools;
* `infra dr export`, `infra dr verify`, `infra dr health` — a freeze often
  precedes a disaster, and a backup taken during one is the most valuable
  backup there is;
* the dead-man heartbeat. Freezing must never look like death.

**Refuses:**

* execution of any `ChangePlan`, of any tier, including one already approved;
* every Tier 0 automatic action, shadow-mode or not;
* NetBox writes (`infra netbox sync` exits 3; `--dry-run` still previews);
* anything an executor would do to a switch, a firewall, a host or a guest.

Approval itself still works, and that is on purpose: the owner can approve a
plan while frozen and it will sit in `approved` until the freeze lifts. The
approval channel is unaffected by the freeze because it is a human channel, and
the token still never appears in anything the model can read.

`infra_frozen` is 1 in Prometheus, and `PlatformFrozen` fires after 24 hours —
not to nag, but because the most common failure of a break-glass control is
that somebody pulled it in March and nobody noticed until June.

## When to freeze

* You are about to work on the estate by hand and do not want a Tier 0 action
  or an approved plan executing underneath you.
* A change went wrong and you are not yet sure what state anything is in.
* The platform is behaving in a way you do not understand. A system you cannot
  predict must not be a system that acts.
* Anything on this list has just happened: an unexplained config change, a
  device the collectors cannot reach that should be reachable, a plan that
  executed when you did not expect it, credentials you suspect are compromised.
* A restore or a failover. `infra dr import` freezes for you, and
  `deploy/standby/failover.sh` relies on it.

Freezing during an incident costs you nothing you needed.

## Lift it

Unfreezing is not the reverse of a keystroke; it is a decision that the estate
is in a state the platform should be allowed to act on. Work the list.

```bash
# 1. Do you know why it was frozen? If not, find out before going further.
docker compose -f deploy/docker-compose.yml logs infra-agent | grep -i freeze
infra change list --state awaiting_approval
infra change list --state executing        # anything stuck mid-flight?
```

A plan left in `executing` or `verifying` is the one that must be resolved by
hand before unfreezing. It means a change started and the platform stopped
before the post-check completed, so **it was not rolled back** — the thing that
would have rolled it back is the thing that stopped. Compare the device against
`data/configs` and finish or revert it yourself, then cancel the plan.

```bash
# 2. Is the estate as you expect?
infra collect
infra graph build
C="docker compose -f deploy/docker-compose.yml"
$C exec infra-agent infra drift      # exits 1 when there is drift; read every line
$C exec infra-agent infra dr health  # collectors, plan store, graph, secrets, DR

# 3. Only then:
infra change unfreeze          # or /unfreeze in Telegram
```

If `INFRA_FROZEN=1` is in the environment, `unfreeze` deletes the marker and
changes nothing: edit `deploy/.env` and restart. `/status` in Telegram reports
`frozen: yes/no` and is the quickest way to check which of the two is holding.

After a restore, unfreeze **last** — after `infra drift` has been read properly.
A restored platform's view of the estate is up to a day old, and drift is
exactly the list of what it does not know yet.

## What freezing does not do

It does not stop the estate. VMs keep running, the firewall keeps forwarding,
the switches keep switching. Freezing stops the *administrator*, not the
infrastructure — if the site is on fire, freezing the agent is a reasonable
first move and does nothing at all about the fire.

It does not lock other people out. A human with a console cable and the
credentials can still do anything; the freeze is a control on this platform's
autonomy, not an access control.

It does not revert anything. A change already made stays made. Freezing stops
the next one.
