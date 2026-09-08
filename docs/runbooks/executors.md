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
  though it failed, so a pre-change snapshot is never orphaned, a half-copied
  clone directory is never left filling a datastore, and a restarted service is
  never left behind. A step that failed before touching the device is skipped.

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

**Endpoints this executor will never call.** `forbidden_endpoint` refuses any
endpoint with a segment whose words include `revision`, `backup`, `restore`,
`reboot`, `shutdown`, `factory`, `reset`, `upgrade`, `format` or `execute`, the
`vpn.ipsec` tree, and `cmdb/system/admin`, `cmdb/system/api-user` and
`cmdb/user/local`, before the transport sees it. Revision restore is the
specific trap: it reboots the 60F, and an API-token session does not create a
revision to go back to. Rollback is therefore always an inverse object
operation.

The guard is applied to the **endpoint** — the collection path — and never to
the percent-encoded object key appended to it (`_object_request` passes
`spec.path`). A firewall address called `backup-nas`, `factory-floor` or
`esxi-upgrade-host` is an ordinary object in an estate like this one, and it
stays readable, editable and checkable.

**Secret handling.** Every captured body is scrubbed of fields whose name
contains a whole `password`, `passwd`, `passphrase`, `psk`, `psksecret`,
`secret`, `key` or `privatekey` token — separated by `-`, `_` or `.`, with
`q_origin_key` explicitly allowed — and of `ENC ...` values; the dropped field
names are listed in `output["redacted_fields"]`. Whole tokens matter: FortiOS
puts `q_origin_key` on every nested table and `ssl-client-rekey-count` on a
VIP, and treating those as secrets made every step report redacted fields and
turned a harmless VIP edit into an unrestorable one. If a step *changed* a
genuinely secret field, `output["restore_incomplete"]` records it and the
rollback returns `ok=False` with `unrestorable_fields` rather than writing a
wrong value.

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

A `create` may omit the key — a `policyid` and a static route's `seq-num` are
server-assigned — and the executor takes the `mkey` from the POST answer, which
is what the rollback then deletes. If FortiOS reports no key the step fails
rather than leave an object nothing can remove. Every other operation must say
which object it means.

### Rollback

| What was applied | What rollback does |
|---|---|
| `create` | `DELETE` the object that was created |
| `update`, `enable`, `disable` | `PUT` the previous values of exactly the fields the step changed |
| `delete` | `POST` the captured previous body back, then — for a policy — move it back to the neighbour it had (`output["previous_position"]`, captured before the `DELETE`) |
| `move` | move the policy back to the neighbour it had (`output["previous_position"]`) |

Policy evaluation on the 60F is first-match, so a rule recreated at the bottom
of the table is not the rule that was deleted. If the neighbour it sat next to
is itself gone by the time the rollback runs, the rollback returns `ok=False`
saying the rule is back but its order needs a human — it does not quietly leave
it last.

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
| `free`, `Hypervisor…`, empty, unknown | `SshTransport` | `vim-cmd` / `esxcli` over SSH |

Only an explicit `licensed` takes the API path. Guessing "licensed" for an
unknown host would mean every write fails at the API and the plan stalls half
applied; the SSH path works on either licence.

**Credentials.** The SSH path authenticates with `Credential.ssh_key_path`
when there is one (offering `Credential.password` as its passphrase) and with
`Credential.password` when there is not — the same choice the collector's
`EsxiShowTransport` makes, because the ESXi root account this estate uses is a
password account. A read-write credential with neither is a `LookupError`
naming both, not a paramiko "no authentication methods available".

**Sessions.** Each of `dry_run`, `pre_check`, `apply`, `post_check` and
`rollback` opens **one** host session and closes it on the way out. hostd caps
concurrent sessions and an idle one lingers about half an hour, so a login per
read would eventually lock the platform out of its own host; on the SSH side it
is the difference between one login and a hundred.

**Pre-change snapshots.** Every VM-changing action *except* `vm.disk_extend`
and the two snapshot actions takes a snapshot named `infra-<plan_id>` before it
runs. It is left in place by every rollback — it is the only evidence of the
state the VM was in — and the successful path records its removal in
`output["cleanup"]` as a `vm.snapshot_remove` step for the engine to run once
the plan has verified.

**What a rollback actually does with it.** Only `vm.resize` reverts: the
snapshot is the one thing holding the old CPU and memory. The two power
actions roll back with the **inverse power operation** instead — a `vm.power_on`
is undone by shutting the guest down (gracefully if Tools is running, hard
after `timeout_seconds`), a `vm.power_off_graceful` by powering it back on.
Their pre-change snapshot was taken while the VM was running, so it is
crash-consistent: reverting to it to undo a clean shutdown boots the guest from
a crash image, and reverting to undo a power-on throws away everything the
guest wrote since it booted. The revert is kept as the fallback for when the
inverse operation itself fails, and `output["inverse_failed"]` says so.

**Refusals come before the snapshot.** A resize with nothing to change, a
resize a running VM cannot take, and a graceful power off of a VM with no
running Tools and no `params.force` are all refused before anything is
snapshotted, so a refusal never leaves an orphaned `infra-<plan_id>` behind.

**Disk extends never snapshot.** A snapshot present is exactly what corrupts a
disk extend, so taking one first would guarantee the refusal it is trying to
avoid. An extend on a VM with snapshots is a blocker.

**Free space.** A snapshot — including a pre-change one — is refused when the
VM's datastore has less than `params.min_free_gb` (default 20 GB) free, because
a full datastore stuns every VM on it.

**Host changes back the host up first.** `esxi.host_setting` captures the same
`backup_config` bundle the collector commits and records it as
`output["backup_ref"]` — `{kind, path, taken_at, plan_id, device}` — before it
writes anything.

*Known gap.* `backup_ref` is a reference to a bundle that stays **on the host**
(`/scratch/downloads/…` on the SSH path, hostd's download URL on the API path);
nothing in this package fetches it into the config git store, and
`collectors/esxi.py` rate-limits its own backup to an hour. If a host-setting
change locks the platform out of the host, the bundle may never have been
committed anywhere durable. Closing this needs a binary channel on the session
protocol (SFTP, or the collector's own download helper) and a write into the
config store, which `collectors/esxi.py` owns — see the executors package
notes.

**Names.** Any VM, datastore or vSwitch name that reaches a shell must match
`^[A-Za-z0-9][A-Za-z0-9 ._@+-]{0,79}$` and is `shlex`-quoted on top of that.

### Actions

| Action | Tier | Params | Pre-change snapshot | Rollback |
|---|---|---|---|---|
| `vm.snapshot` | 0 | `vm`, `snapshot_name`, `description`, `min_free_gb` | n/a | remove the snapshot it created |
| `vm.snapshot_remove` | 1 *(default)* | `vm`, `snapshot_name` | n/a | **none** — a removed snapshot cannot be restored; the rollback fails and pages |
| `vm.power_on` | 0 | `vm` | yes (evidence) | shut the guest down again; revert only if that fails |
| `vm.power_off_graceful` | 1 *(default)* | `vm`, `timeout_seconds` (300), `force` | yes (evidence) | power it back on; revert only if that fails |
| `vm.resize` | 1 | `vm`, `cpu`, `memory_mb` | yes | revert (restores the old CPU/memory) |
| `vm.disk_extend` | 1 | `vm`, `disk`, `size_gb` | **no** | **none** — a virtual disk cannot be shrunk |
| `vm.create_from_template` | 1 | `template`, `name`, `datastore` | n/a (nothing exists yet) | unregister the clone and delete **the directory this step created** |
| `esxi.host_setting` | 1 | `key`, `value`, `vswitch` | n/a (host-config backup) | set the captured previous value back |
| `esxi.log_bundle` | 0 | — | n/a | nothing to undo |

`vm.power_off_graceful` asks the guest to shut down and polls until
`timeout_seconds`. If the guest is still up, or VMware Tools is not running in
the first place, it **refuses** — a hard power off happens only with
`params.force`, and the reason is recorded in the output.

`vm.resize` on a running VM needs the matching hot-add flag on the **licensed**
path, and never removes CPUs or memory from a running VM. On the free licence a
running VM is refused outright, hot-add flags or not: that path resizes by
rewriting the `.vmx` and reloading, which needs the VM powered off (VMware KB
1026043), and `vmsvc/reload` does not hot-add. Power it off, or use a licensed
host.

`vm.create_from_template` refuses a name that already exists — in `dry_run`
*and* again in `apply`, because they are separate moments — creates its own
directory (a plain `mkdir` / `MakeDirectory`, so an existing one aborts before
a byte is copied), and records that directory in `output["created"]["dir"]`
before the copy starts. That record is what makes a clone that died half way
through the disk copy `partially_applied`, and it is the only thing the
rollback will delete.

`esxi.host_setting` keys, normalised so a step and a check spell them alike:

| Key (and aliases) | What it sets |
|---|---|
| `syslog`, `Syslog.global.logHost` | remote syslog target (`esxcli system syslog config set` + reload + `network firewall ruleset set -r syslog -e true`, or the advanced option and `EnableRuleset`). Without the ruleset the loghost is set, the check passes and nothing ever arrives |
| `ntp.servers`, `ntp` | NTP server list (a list value). An **empty** list is `esxcli system ntp set --reset` + `--enabled=0`, because a `set` with no flags is an error and that is exactly what a rollback to a host with no NTP would issue |
| `cdp.mode`, `cdp` | link discovery on `params.vswitch` (default `vSwitch0`); must be one of `down`, `listen`, `advertise`, `both`, and anything but `both` is warned about because the topology graph needs both sides |
| `/Path/Like/This` or `Path.Like.This` | an advanced setting |

CDP is read per host — `host_setting_get` answers with `{vswitch: mode}` for
every switch — so the executor captures the scalar for the vSwitch the step
names as `output["previous"]` (the whole map goes in `output["previous_all"]`
for the diff) and that scalar is what the rollback writes back. A step naming a
vSwitch the host does not have is a dry-run blocker. On the API path the write
reads the **live** `HostVirtualSwitchSpec` and changes only its link-discovery
config: `UpdateVirtualSwitch` replaces the whole spec, and a freshly built one
has neither `numPorts` nor the bridge's `nicDevice` — both required fields —
so it cannot even be serialised, and filling them in with empties would strip
vSwitch0's uplinks and isolate the host.

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
`vmsvc/unregister`, `vmkfstools -X` / `-i`, `solo/registervm`, `mkdir`, `cat`,
`rm -rf`, `esxcli --formatter=json …` and `vim-cmd hostsvc/firmware/backup_config`.

A resize rewrites `numvcpus` / `memSize` in the `.vmx` (delete the line, append
the new one, both with integer values) and reloads, because the free licence
has no reconfigure API — and it refuses a powered-on VM, since that rewrite
needs the VM off.

A clone reads the template's `.vmx`, `mkdir`s the target directory (plain, not
`-p`), copies the disk with `vmkfstools -i -d thin`, writes the patched `.vmx`
through a **quoted heredoc** and registers it. The patch happens in Python
(`patch_vmx`): it drops `displayName`, `uuid.*` and `vc.uuid`, re-points the
disk reference, and appends the new `displayName` and `uuid.action = "create"`
so hostd does not stop on the "I copied it" question. It is not a `sed`
script, because the disk basename is data and `.` in it is a regex
metacharacter.

Destroying a clone needs a recorded directory, refuses anything that is not
under `/vmfs/volumes/<datastore>/<vm>`, and skips the unregister when the clone
never got as far as being registered.

`PyvmomiTransport` (licensed): `CreateSnapshot_Task`, `RemoveSnapshot_Task`,
`RevertToSnapshot_Task`, `PowerOnVM_Task`, `ShutdownGuest`, `PowerOffVM_Task`,
`ReconfigVM_Task` (config spec, and a `VirtualDeviceSpec` edit for a disk
extend), `fileManager.MakeDirectory` / `CopyDatastoreFile_Task` /
`DeleteDatastoreFile_Task`, `virtualDiskManager.CopyVirtualDisk_Task`,
`vmFolder.RegisterVM_Task`, `UnregisterVM`, `advancedOption.UpdateOptions`,
`dateTimeSystem.UpdateDateTimeConfig`, `networkSystem.UpdateVirtualSwitch`,
`firewallSystem.EnableRuleset`, `firmwareSystem.BackupFirmwareConfiguration`
and `diagnosticManager.GenerateLogBundles_Task`. Tasks are polled to `success`
or `error` with a timeout; a task error becomes a short `EsxiError`.

**`CloneVM_Task` and `Destroy_Task` are never called.** `CloneVM_Task` is a
vCenter operation and standalone hostd answers it "the operation is not
supported on the object", so the licensed clone is the same copy-and-register
sequence the SSH path runs: `MakeDirectory` (the existence guard),
`CopyVirtualDisk_Task`, `CopyDatastoreFile_Task`, `RegisterVM_Task` on
`datacenter.vmFolder` with the host's resource pool, and a final
`ReconfigVM_Task` that sets the clone's name, adds `uuid.action = create` and
re-points its disk at the copy. `Destroy_Task` is avoided because it deletes
every file the VM references — including a template disk a clone whose backing
edit did not land still points at; the rollback unregisters and deletes only
the recorded directory.

---

## Guest — `infra_agent/change/executors/guest.py`

Platform `guest`, for both `guest_linux` (SSH, paramiko) and `guest_windows`
(WinRM, pywinrm). The two share the executor's logic through a `Dialect`, which
is the only place a command string is built.

**Timeouts.** Every command carries one. On WinRM that means constructing the
`winrm.Session` per call with `operation_timeout_sec` clamped to the command's
timeout (5–60 s) and `read_timeout_sec` ten seconds above it: pywinrm's
defaults are 20 s / 30 s and it *loops* on an operation timeout, so a hung
`winget upgrade --all` would otherwise never return.

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
| `guest.reboot` | 2 (enforced here; *(default)* in `BASE_TIERS`) | `window_confirmed`, `reboot_timeout_seconds` (600) | **none** — a reboot cannot be undone |

Service steps capture `ActiveState` (Linux) or `Status` (Windows) before
acting, verify the expected state afterwards, and fail the step if the service
did not reach it. A service that does not exist is a refusal, not a start —
which on Linux is why the state query asks for `LoadState` too: systemd reports
a unit that does not exist as `inactive`, so `ActiveState` alone cannot tell a
typo from a stopped service, and a typo would otherwise fail at `systemctl
restart` and then fail its own rollback.

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

**The step then waits for the guest to come back.** Issuing the command is not
the change: `shutdown -r +1` returns a minute before anything happens, and
`Restart-Computer` drops the session on its way down, so a post-check run at
that moment reads the still-running box (or a dead connection) and fails a
change that was perfectly fine. After the command the executor polls
`dialect.uptime()` on a fresh connection every 10 s — tolerating every
connection error, because that *is* the guest going down — until the reported
uptime is smaller than the one it recorded first, or `reboot_timeout_seconds`
(600 by default) elapses. `output["previous_uptime_seconds"]`,
`output["new_uptime_seconds"]` and `output["reboot_polls"]` record what
happened, and `output["reboot"]` reaches `completed` only when the box is back.
A guest that never returns fails the step, which is the one case worth paging
for.

### Checks

| Check | Linux | Windows |
|---|---|---|
| `service <name> active` / `inactive` | `systemctl show -p LoadState -p ActiveState` | `(Get-Service).Status` |
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

A fake that accepts anything tests nothing, so the ESXi fakes are deliberately
strict about the things the vendor API is strict about:

- `FakeVim` has **no** `vim.host.VirtualSwitch.Specification`, so building a
  fresh switch spec is an `AttributeError` rather than a passing test.
- The vSwitch in `fake_host` carries `numPorts` and `bridge.nicDevice`, and one
  test builds the live spec out of the **real** `pyVmomi` classes and runs
  `SoapAdapter.Serialize` over what the transport submitted — the check the
  audit's finding turned on. It skips when pyvmomi is not installed.
- `FakeVm.CloneVM_Task` raises what hostd raises, and `Destroy_Task` raises
  outright, so a regression to either shows up as a failing test.
- `FakeFileManager` refuses `MakeDirectory` over an existing directory, refuses
  a copy over an existing file, and refuses to delete a directory it does not
  know about, so the clone's guards are exercised rather than assumed.
