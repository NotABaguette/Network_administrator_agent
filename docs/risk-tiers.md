# Risk tiers

Every change is a `ChangePlan`. Its tier is **computed**, never looked up:
the engine runs `impact_analyze` on the plan and takes the maximum of the
action's base tier and any escalation that applies.

## Escalations (any one of these forces Tier 2)

- The change touches mgmt-01's own path (its host, uplinks, switch ports, the firewall).
- The change touches a trunk, uplink, SVI, WAN interface, SD-WAN, HA, VPN or STP.
- A VLAN is removed while it still has members or an SVI.
- The target port feeds an iLO or the management VLAN.

## Tier 0: automatic

Conditions, all required:
- idempotent, reversible, single object, no topology effect;
- the object carries the matching opt-in tag (for example `auto:restart`);
- the cause is in the allowlist for that action;
- the cooldown for that object has elapsed and the retry cap is not exceeded;
- `INFRA_FROZEN` is not set.

Executed immediately with pre- and post-checks and reported afterwards. Each
Tier 0 action is introduced one at a time after a week in shadow mode
("would have done X").

| Action | Extra guard |
|---|---|
| Snapshot before a Tier 1 VM change | Only if datastore free space is above threshold and the change is not a disk extend (extends fail with snapshots present) |
| Power on a VM tagged `auto:restart` | Only if the ESXi event log shows no human power-off |
| Restart a guest service tagged `auto:restart` | Cooldown, retry cap |
| Clear err-disable on a tagged access port | Cause allowlist (for example `link-flap`); never BPDU guard or loop detection |
| Re-run discovery, collect a log bundle | none |
| Silence an alert | Always with a TTL |

## Tier 1: one human approval

Proposed with the structured diff and a rollback plan; executed after one
approval via CLI or Telegram button. Examples: add a VLAN, access-port
config, FortiGate address/service/policy edits, static routes, VM CPU/RAM/disk
changes, new VM from template, ESXi host settings.

## Tier 2: approval, maintenance window, confirmation phrase

Tier 1 plus a declared maintenance window and a typed confirmation phrase.
Never auto-suggested outside the window. The dead-man heartbeat must be
healthy before execution. Examples: anything on WAN, SD-WAN, HA, VPN; trunk
and uplink ports; STP; firmware; host reboot; RAID or storage rebuild;
anything on mgmt-01's own path.

## Approval channel

`change.approve` and `change.execute` are not exposed to the language model.
The approval token is minted server-side, bound to the change id and the
approver's identity, delivered only through the CLI or Telegram, and never
appears in any proposal text or tool result.

## Lifecycle

```
proposed → dry_run → awaiting_approval → approved → executing → verifying → done
                                                               └→ rolled_back
        any state → cancelled
```
A failed post-check rolls back automatically and pages.
