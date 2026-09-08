# Executors

An executor is what actually touches a device once a `ChangePlan` reaches
`approved`. There is one per platform, registered by `@register` in
`infra_agent/change/executors/` and found by `get_executor(platform)` after
`load_all()`. This runbook covers the three in this package — `fortigate`,
`esxi` and `guest`. The contract they implement is
`infra_agent/change/executors/base.py`; the Cisco executor and the change
engine that drives them are documented separately.

## How the engine drives an executor

```
dry_run(ctx, steps)  -> DryRunResult(ok, diff, warnings, blockers)
pre_check(ctx, ...)  -> [CheckResult]      any failure aborts before apply
apply(ctx, step)     -> StepResult         once per step, in order
post_check(ctx, ...) -> [CheckResult]      any failure triggers rollback
rollback(ctx, applied) -> [StepResult]     applied steps, in reverse
```

Rules every executor here obeys, so the engine does not have to special-case
them:

- **Nothing raises.** Every failure comes back as `StepResult(ok=False,
  error=...)` or a blocker, with a short one-line message.
- **A blocker is a refusal, a warning is information.** `dry_run` returns
  `ok=False` when a step must not run at all; warnings are what the engine
  tiers on (a policy touching a WAN interface, a change with no rollback).
- **`ctx.frozen` and `ctx.dry_run` refuse writes.** Belt and braces on top of
  the engine's own freeze gate; `apply()` on a frozen or dry-run context fails
  the step without touching the device.
- **An unknown check fails closed.** A check this executor cannot parse comes
  back `ok=False` with the grammar it does understand in `detail`, so a typo in
  a plan aborts the plan rather than silently passing.
- **`StepResult.output` is structured and secret-free.** It is what the engine
  persists and what a rollback reads. No credential, token, key path, `ENC`
  blob or `psksecret` ever reaches it. Nothing raw goes anywhere near a model:
  the engine shows `ChangePlan.llm_view()`.
- **A failed rollback is reported, not hidden.** Actions that genuinely cannot
  be undone (a disk extend, a removed snapshot, a package upgrade, a reboot)
  return `ok=False` from `rollback()` with the reason, which pages the owner
  through the `Notifier`.
- **A failed step that already changed something is still rolled back.** A step
  that reports `ok=False` is not always a no-op: an ESXi step can take its
  pre-change snapshot and then fail on the reconfigure, and `systemctl restart`
  can succeed with the unit landing in `failed`. `EsxiExecutor` and
  `GuestExecutor` expose `partially_applied(result)` and undo such a step even
  though it failed, so a pre-change snapshot is never orphaned and a restarted
  service is never left behind. A step that failed before touching the device
  is skipped.

Tiers below are the base tier from `infra_agent/change/tiers.py`; the engine
takes the **maximum** of that and any escalation `impact_analyze` reports, so a
Tier 1 action on mgmt-01's own path executes as Tier 2. Actions marked
*(default)* have no entry in `BASE_TIERS` and therefore fall to Tier 1; the two
worth revisiting there are `guest.reboot`, which this executor enforces as
Tier 2 itself, and `vm.power_off_graceful`.

---

## FortiOS — `infra_agent/change/executors/fortigate.py`

Platform `fortigate`. FortiOS REST API at `https://<mgmt_ip>/api/v2/` with the
read-write api-user token from `SeedDevice.rw_credential_ref`. TLS
verification is off until the Phase 1 pinning work lands, matching the
collector.

**Endpoints this executor will never call.** `_request` refuses any path
matching `revision`, `backup`, `restore`, `reboot`, `shutdown`, `factory`,
`reset`, `upgrade`, `format`, `execute`, `system/admin`, `system/api-user`,
`vpn.ipsec` or `user/local`, before the transport sees it. Revision restore is
the specific trap: it reboots the 60F, and an API-token session does not create
a revision to go back to. Rollback is therefore always an inverse object
operation.

**Secret handling.** Every captured body is scrubbed of fields matching
`password|passwd|psk|secret|key` and of `ENC ...` values; the dropped field
names are listed in `output["redacted_fields"]`. If a step *changed* such a
field, `output["restore_incomplete"]` records it and the rollback returns
`ok=False` with `unrestorable_fields` rather than writing a wrong value.

### Actions

All five take `params.op` — one of `create`, `update`, `delete`, `move`,
`enable`, `disable` — plus the object's key (`name`, or `policyid` /
`seq-num`) and `params.body` for creates and updates.

| Action | Tier | CMDB path | Ops |
|---|---|---|---|
| `fortigate.address` | 1 | `cmdb/firewall/address` | create, update, delete |
| `fortigate.service` | 1 | `cmdb/firewall.service/custom` | create, update, delete |
| `fortigate.policy` | 1 (2 on WAN) | `cmdb/firewall/policy` | create, update, delete, move, enable, disable |
| `fortigate.static_route` | 1 | `cmdb/router/static` | create, update, delete |
| `fortigate.vip` | 1 *(default)* | `cmdb/firewall/vip` | create, update, delete |

A `move` needs `params.position` (`before` / `after`) and `params.target`.

### Rollback

| What was applied | What rollback does |
|---|---|
| `create` | `DELETE` the object that was created |
| `update`, `enable`, `disable` | `PUT` the previous values of exactly the fields the step changed |
| `delete` | `POST` the captured previous body back |
| `move` | move the policy back to the neighbour it had (`output["previous_position"]`) |

### dry_run

- Resolves every name a policy or VIP references — `srcaddr`, `dstaddr`
  (addresses, address groups and VIPs), `service` (custom services and service
  groups), `srcintf` / `dstintf` / `extintf` / `device` (interfaces and zones) —
  and blocks on anything that does not exist.
- Blocks a `delete` whose object is still referenced by a policy, naming the
  policy ids, or still a member of an address or service group, naming the
  groups — FortiOS rejects both, and a plan that only checked policies would
  fail halfway through instead of at the dry run.
- Blocks a `create` of an object that already exists and any op on one that
  does not.
- Warns when a policy's effective interfaces (previous body merged with the
  step's body) include a WAN interface — `role: wan`, an SD-WAN member, a zone
  holding one, a name matching `wan|internet|isp|ppp|sdwan`, or a name listed in
  `ctx.extra["wan_interfaces"]` — so the engine escalates to Tier 2.
- Produces `{"platform", "device", "steps": [{action, op, object, before,
  after, changed_fields, wan_interfaces}]}`, scrubbed.

### Checks

| Check | Source |
|---|---|
| `policy <id> exists` / `absent` | `cmdb/firewall/policy/<id>` |
| `policy <id> enabled` / `disabled` | the object's `status` field |
| `address <name> exists` / `absent` | `cmdb/firewall/address/<name>` |
| `route to <cidr> via <gw>` | `monitor/router/ipv4`, matching `ip_mask` and `gateway` |
| `sessions matching policy <id> >= <n>` | `monitor/firewall/policy`, field `active_sessions` |

---

## ESXi — `infra_agent/change/executors/esxi.py`

Platform `esxi`. Two transports, chosen by `SeedDevice.license`:

| `license` | Transport | Notes |
|---|---|---|
| `licensed` | `PyvmomiTransport` | hostd's API with the read-write account |
| `free`, `Hypervisor…`, empty, unknown | `SshTransport` | `vim-cmd` / `esxcli` over SSH, key from `Credential.ssh_key_path` |

Only an explicit `licensed` takes the API path. Guessing "licensed" for an
unknown host would mean every write fails at the API and the plan stalls half
applied; the SSH path works on either licence.

**Pre-change snapshots.** Every VM-changing action *except* `vm.disk_extend`
and the two snapshot actions takes a snapshot named `infra-<plan_id>` before it
runs. Rollback reverts to it and restores the power state recorded in
`output["before"]`, and leaves the snapshot in place — it is the only evidence
of the state the VM was in. The successful path records the removal in
`output["cleanup"]` as a `vm.snapshot_remove` step for the engine to run once
the plan has verified.

**Disk extends never snapshot.** A snapshot present is exactly what corrupts a
disk extend, so taking one first would guarantee the refusal it is trying to
avoid. An extend on a VM with snapshots is a blocker.

**Free space.** A snapshot — including a pre-change one — is refused when the
VM's datastore has less than `params.min_free_gb` (default 20 GB) free, because
a full datastore stuns every VM on it.

**Host changes back the host up first.** `esxi.host_setting` captures the same
`backup_config` bundle the collector commits and records it as
`output["backup_ref"]` before it writes anything.

**Names.** Any VM, datastore or vSwitch name that reaches a shell must match
`^[A-Za-z0-9][A-Za-z0-9 ._@+-]{0,79}$` and is `shlex`-quoted on top of that.

### Actions

| Action | Tier | Params | Pre-change snapshot | Rollback |
|---|---|---|---|---|
| `vm.snapshot` | 0 | `vm`, `snapshot_name`, `description`, `min_free_gb` | n/a | remove the snapshot it created |
| `vm.snapshot_remove` | 1 *(default)* | `vm`, `snapshot_name` | n/a | **none** — a removed snapshot cannot be restored; the rollback fails and pages |
| `vm.power_on` | 0 | `vm` | yes | revert, then restore the recorded power state |
| `vm.power_off_graceful` | 1 *(default)* | `vm`, `timeout_seconds` (300), `force` | yes | revert, then power back on if it had been on |
| `vm.resize` | 1 | `vm`, `cpu`, `memory_mb` | yes | revert (restores the old CPU/memory) |
| `vm.disk_extend` | 1 | `vm`, `disk`, `size_gb` | **no** | **none** — a virtual disk cannot be shrunk |
| `vm.create_from_template` | 1 | `template`, `name`, `datastore` | n/a (nothing exists yet) | destroy the clone |
| `esxi.host_setting` | 1 | `key`, `value`, `vswitch` | n/a (host-config backup) | set the captured previous value back |
| `esxi.log_bundle` | 0 | — | n/a | nothing to undo |

`vm.power_off_graceful` asks the guest to shut down and polls until
`timeout_seconds`. If the guest is still up, or VMware Tools is not running in
the first place, it **refuses** — a hard power off happens only with
`params.force`, and the reason is recorded in the output.

`vm.resize` on a running VM needs the matching hot-add flag, and never removes
CPUs or memory from a running VM.

`esxi.host_setting` keys, normalised so a step and a check spell them alike:

| Key (and aliases) | What it sets |
|---|---|
| `syslog`, `Syslog.global.logHost` | remote syslog target (`esxcli system syslog config set` + reload, or the advanced option) |
| `ntp.servers`, `ntp` | NTP server list (a list value) |
| `cdp.mode`, `cdp` | link discovery on `params.vswitch` (default `vSwitch0`); must be one of `down`, `listen`, `advertise`, `both`, and anything but `both` is warned about because the topology graph needs both sides |
| `/Path/Like/This` or `Path.Like.This` | an advanced setting |

### Checks

| Check | Meaning |
|---|---|
| `vm <name> powered on` / `off` | `runtime.powerState` |
| `vm <name> tools running` | `toolsRunningStatus == guestToolsRunning` |
| `vm <name> has no snapshots` | the snapshot tree is empty; failing detail lists them |
| `datastore <name> free >= <GB>` | free space on that datastore |
| `host setting <key> == <value>` | the normalised key above; list values compare comma-separated |

### What each transport runs

`SshTransport` (free): `vim-cmd vmsvc/getallvms`, `power.getstate`,
`get.snapshotinfo`, `get.summary`, `get.config`, `get.guest`, `get.devices`,
`snapshot.create|remove|revert`, `power.on|shutdown|off`, `vmsvc/reload`,
`vmkfstools -X` / `-i`, `solo/registervm`, `esxcli --formatter=json …`, and
`vim-cmd hostsvc/firmware/backup_config`. A resize rewrites `numvcpus` /
`memSize` in the `.vmx` (delete the line, append the new one, both with integer
values) and reloads, because the free licence has no reconfigure API. A clone
copies the template's disk and `.vmx`, retitles it and registers it. Destroying
a VM refuses any directory that is not under `/vmfs/volumes/<datastore>/<vm>`.

`PyvmomiTransport` (licensed): `CreateSnapshot_Task`, `RemoveSnapshot_Task`,
`RevertToSnapshot_Task`, `PowerOnVM_Task`, `ShutdownGuest`, `PowerOffVM_Task`,
`ReconfigVM_Task` (config spec, and a `VirtualDeviceSpec` edit for a disk
extend), `CloneVM_Task`, `Destroy_Task`, `advancedOption.UpdateOptions`,
`dateTimeSystem.UpdateDateTimeConfig`, `networkSystem.UpdateVirtualSwitch`,
`firmwareSystem.BackupFirmwareConfiguration` and
`diagnosticManager.GenerateLogBundles_Task`. Tasks are polled to `success` or
`error` with a timeout; a task error becomes a short `EsxiError`. Note that
`CloneVM_Task` is a vCenter operation — on a standalone host that reports it
unsupported, the step fails with the host's own message and the SSH path is the
one to use.

---

## Guest — `infra_agent/change/executors/guest.py`

Platform `guest`, for both `guest_linux` (SSH, paramiko) and `guest_windows`
(WinRM, pywinrm). The two share the executor's logic through a `Dialect`, which
is the only place a command string is built.

**Command construction.** No caller string is ever interpolated into a shell.
Service names must match `^[A-Za-z0-9][A-Za-z0-9 ._@()+-]{0,79}$` (spaces and
parentheses for `SQL Server (MSSQLSERVER)`), package names
`^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$`, and the value is then quoted —
`shlex.quote` for the POSIX shell, PowerShell single-quote doubling for WinRM.
The templates in the two dialects are the complete set of things this executor
can run.

### Actions

| Action | Tier | Params | Rollback |
|---|---|---|---|
| `guest.service_restart` | 0 | `service` | restore the captured state: start it if it had been running, stop it if it had not |
| `guest.service_stop` | 1 *(default)* | `service` | same |
| `guest.service_start` | 1 *(default)* | `service` | same |
| `guest.package_update` | 1 *(default)* | `manager` (optional) | **none** — previous versions are recorded and the rollback fails so the owner is paged |
| `guest.reboot` | 2 (enforced here; *(default)* in `BASE_TIERS`) | `window_confirmed` | **none** — a reboot cannot be undone |

Service steps capture `ActiveState` (Linux) or `Status` (Windows) before
acting, verify the expected state afterwards, and fail the step if the service
did not reach it. A service that does not exist is a refusal, not a start.

`guest.package_update` detects `apt`, `dnf` or `winget` (or takes
`params.manager`), lists the pending upgrades — `apt-get --simulate --quiet
upgrade`, `dnf --quiet check-update` (exit 100 means "there is work"), `winget
upgrade` — records the installed versions of those packages, upgrades, and
reports `output["changed"]` as `{name, from, to}`. `dry_run` shows the pending
list without upgrading anything.

`guest.reboot` **refuses to run without `params.window_confirmed`**, which the
engine sets only when the plan's maintenance window and confirmation phrase are
satisfied. This is enforced in the executor as well as in the engine, so a
mistake in the engine's gate cannot reboot a production guest outside its
window. The command is `shutdown -r +1` / `Restart-Computer -Force`; if the
session drops right after it, that is the expected outcome and the step still
succeeds — unless the error mentions permissions, which is a real refusal.

### Checks

| Check | Linux | Windows |
|---|---|---|
| `service <name> active` / `inactive` | `systemctl show -p ActiveState --value` | `(Get-Service).Status` |
| `port <n> listening` | `ss -H -ltn` | `Get-NetTCPConnection -State Listen` |
| `uptime < 10m` (also `>`; units `s`, `m`, `h`, `d`) | `/proc/uptime` | `Win32_OperatingSystem.LastBootUpTime` |

---

## Testing an executor

Every transport is injected through the constructor, so nothing in the test
suite opens a socket:

```python
FortiGateExecutor(transport=FakeFortiOS())
EsxiExecutor(free=SshTransport(open_session=lambda d, c: FakeSession(...)))
EsxiExecutor(licensed=PyvmomiTransport(connect=..., vim=FakeVim))
GuestExecutor(linux=FakeGuest(), windows=FakeGuest())
```

`tests/test_executor_fortigate.py`, `tests/test_executor_esxi.py` and
`tests/test_executor_guest.py` cover apply and rollback for every action, every
blocker above, and the property that no credential or `ENC`/`psk` material
reaches any output. Recorded device output lives in
`tests/fixtures/executors/`.
