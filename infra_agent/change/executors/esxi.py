"""ESXi executor: two transports, one set of rules.

There is no vCenter, and some hosts run the free (Hypervisor) licence whose API
rejects writes. So the executor picks its transport from
`SeedDevice.license`:

* ``licensed``  -> :class:`PyvmomiTransport`, hostd's API with the read-write
  account.
* ``free`` or anything unknown -> :class:`SshTransport`, `vim-cmd` and `esxcli`
  over SSH with the key in ``Credential.ssh_key_path``. Unknown is treated as
  free on purpose: guessing "licensed" would mean every write fails at the API
  and the plan stalls half applied.

Both transports implement :class:`EsxiTransport`, so the safety rules live in
the executor and hold on either path:

* Every VM-changing action except ``vm.disk_extend`` and the snapshot actions
  themselves takes a pre-change snapshot named ``infra-<plan_id>`` first. The
  snapshot is not deleted by the rollback path; it is deleted by the cleanup
  the successful run records in ``StepResult.output["cleanup"]``.
* A ``vm.resize`` rolls back by reverting to that snapshot, because the
  snapshot is the only thing that holds the old CPU/memory. The two *power*
  actions do not: their pre-change snapshot is crash-consistent, and reverting
  to it would boot the guest from a crash image or throw away everything it
  wrote since it started. Their rollback is the inverse power operation, with
  the revert kept only for when that fails.
* ``vm.create_from_template`` copies into a directory it creates itself and
  records that directory before the first byte is written. The rollback
  deletes exactly that directory and nothing else — never one found by looking
  up whatever VM currently answers to the clone's name, and never through
  ``Destroy_Task``, which deletes every file the VM references.
* ``vm.disk_extend`` is refused outright when the VM has snapshots — an extend
  with a snapshot present corrupts the chain — and it never takes one itself,
  because that would guarantee the refusal it is trying to avoid.
* Host changes capture the same `backup_config` bundle the collector commits,
  and record it as ``StepResult.output["backup_ref"]``.
* A snapshot is refused when the datastore holding the VM is below the
  free-space threshold, because a full datastore stuns every VM on it.

Neither transport is a vCenter client. `CloneVM_Task` is a vCenter operation
that standalone hostd refuses, so the licensed clone is `MakeDirectory` +
`CopyVirtualDisk_Task` + `CopyDatastoreFile_Task` + `RegisterVM_Task` — the
same sequence the SSH path runs with `vmkfstools -i` and `solo/registervm`.

Both transports hold **one host session per executor call**: hostd caps
concurrent sessions and an idle one lingers for half an hour, and the SSH path
would otherwise log in once per `vim-cmd`. `dry_run`, `pre_check`, `apply`,
`post_check` and `rollback` each open a session and close it on the way out.

`pyVim`/`pyVmomi` and `paramiko` are imported lazily, and both transports take
their session factory as a constructor argument so the tests drive fakes.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from infra_agent.change.executors.base import (
    CheckResult,
    DryRunResult,
    ExecutionContext,
    Executor,
    StepResult,
    register,
)
from infra_agent.change.plan import ChangeStep
from infra_agent.models.common import Credential, SeedDevice

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120.0
#: A guest shutdown that has not finished by then needs a human decision.
DEFAULT_SHUTDOWN_TIMEOUT = 300.0
SHUTDOWN_POLL_SECONDS = 5.0
#: Free space below this on the VM's datastore turns a snapshot into an outage.
DEFAULT_MIN_FREE_GB = 20.0
GIB = 1024 * 1024 * 1024

POWERED_ON = "poweredOn"
POWERED_OFF = "poweredOff"

#: Actions that take a pre-change snapshot. Disk extends must not (snapshots
#: are exactly what breaks them) and the snapshot actions are the mechanism.
SNAPSHOT_BEFORE = frozenset({"vm.power_on", "vm.power_off_graceful", "vm.resize"})
#: Actions whose rollback is the inverse power operation, not a snapshot
#: revert: reverting a running VM to a crash-consistent snapshot loses guest
#: writes, and the honest undo of a power change is the other power change.
POWER_ACTIONS = frozenset({"vm.power_on", "vm.power_off_graceful"})

ACTIONS = frozenset(
    {
        "vm.snapshot",
        "vm.snapshot_remove",
        "vm.power_on",
        "vm.power_off_graceful",
        "vm.resize",
        "vm.disk_extend",
        "vm.create_from_template",
        "esxi.host_setting",
        "esxi.log_bundle",
    }
)

# Host-setting keys, normalised so a check and a step spell them the same way.
SYSLOG_KEY = "Syslog.global.logHost"
NTP_KEY = "ntp.servers"
CDP_KEY = "cdp.mode"
DEFAULT_VSWITCH = "vSwitch0"
#: CDP has to be `both` or neither side of the link learns anything.
CDP_MODES = frozenset({"down", "listen", "advertise", "both"})

SYSLOG_ALIASES = frozenset({"syslog", "loghost", "syslog.global.loghost"})
NTP_ALIASES = frozenset({"ntp", "ntp.server", "ntp.servers"})
CDP_ALIASES = frozenset({"cdp", "cdp.mode", "cdp.status"})

#: VM and datastore names that reach a shell. Everything else is refused
#: before a command is built, on top of the `shlex.quote` every value gets.
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@+-]{0,79}$")


class EsxiError(RuntimeError):
    """A refusal or a device-side failure, safe to show."""


def short_error(exc: Exception) -> str:
    return f"{type(exc).__name__}: {str(exc).strip()[:200]}"


# ---------------------------------------------------------------------------
# pure helpers (unit-tested directly)
# ---------------------------------------------------------------------------
def is_licensed(device: SeedDevice) -> bool:
    """Whether hostd will accept API writes for this host.

    Only an explicit ``licensed`` counts. `free`, `Hypervisor`, an empty value
    and a typo all take the SSH path, which works on either licence.
    """
    value = (device.license or "").strip().lower()
    if not value or "hypervisor" in value or value == "free":
        return False
    return value == "licensed"


def safe_name(value: Any, what: str) -> str:
    """A name that may be interpolated into a command, or a refusal."""
    text = str(value or "").strip()
    if not SAFE_NAME.match(text):
        raise EsxiError(f"{what} {text!r} is not a name this executor will send to a host")
    return text


def datastore_of(path: str | None) -> str | None:
    """`[datastore1] web-01/web-01.vmx` -> `datastore1`."""
    match = re.match(r"^\s*\[([^\]]+)\]", path or "")
    return match.group(1) if match else None


def host_path(path: str | None) -> str | None:
    """`[datastore1] web-01/web-01.vmx` -> `/vmfs/volumes/datastore1/web-01/web-01.vmx`."""
    match = re.match(r"^\s*\[([^\]]+)\]\s*(.*)$", path or "")
    if not match:
        return None
    return f"/vmfs/volumes/{match.group(1)}/{match.group(2).strip()}"


def normalise_setting_key(key: str) -> str:
    """The one spelling of a host setting that steps and checks share."""
    text = str(key or "").strip()
    lowered = text.lower()
    if lowered in SYSLOG_ALIASES:
        return SYSLOG_KEY
    if lowered in NTP_ALIASES:
        return NTP_KEY
    if lowered in CDP_ALIASES:
        return CDP_KEY
    if text.startswith("/"):
        return text.strip("/").replace("/", ".")
    return text


def advanced_path(key: str) -> str:
    """`UserVars.SuppressShellWarning` -> `/UserVars/SuppressShellWarning`."""
    return "/" + key.strip("/").replace(".", "/")


def parse_getallvms(text: str) -> list[dict[str, Any]]:
    """Rows of `vim-cmd vmsvc/getallvms`: id, name and the .vmx path."""
    rows: list[dict[str, Any]] = []
    for line in (text or "").splitlines():
        match = re.match(r"^\s*(\d+)\s+(.+?)\s+(\[[^\]]+\]\s*\S+\.vmx)(?:\s+(.*))?$", line)
        if not match:
            continue
        rows.append(
            {
                "vmid": match.group(1),
                "name": match.group(2).strip(),
                "vmx": match.group(3).strip(),
                "datastore": datastore_of(match.group(3)),
            }
        )
    return rows


def parse_power_state(text: str) -> str:
    """`Powered on` / `Powered off` / `Suspended` -> the API's spelling."""
    lowered = (text or "").lower()
    if "powered on" in lowered:
        return POWERED_ON
    if "powered off" in lowered:
        return POWERED_OFF
    if "suspended" in lowered:
        return "suspended"
    return "unknown"


def parse_snapshotinfo(text: str) -> list[dict[str, Any]]:
    """Snapshots of `vim-cmd vmsvc/get.snapshotinfo`, oldest first.

    ESXi spells it "Desciption"; both spellings are accepted so the parser does
    not depend on a typo staying put.
    """
    snapshots: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in (text or "").splitlines():
        name = re.match(r"^\s*[-|]*\s*Snapshot Name\s*:\s*(.*)$", line)
        if name:
            if current.get("name"):
                snapshots.append(current)
            current = {"name": name.group(1).strip()}
            continue
        desc = re.match(r"^\s*[-|]*\s*Snapshot Descr?iption\s*:\s*(.*)$", line)
        if desc and current:
            current["description"] = desc.group(1).strip()
            continue
        ident = re.match(r"^\s*[-|]*\s*Snapshot Id\s*:\s*(\d+)\s*$", line)
        if ident and current:
            current["id"] = ident.group(1)
    if current.get("name"):
        snapshots.append(current)
    return snapshots


def _scalar(text: str, field: str) -> str | None:
    match = re.search(rf"\b{re.escape(field)}\s*=\s*\"?([^\",\n]*)\"?\s*,?", text or "")
    return match.group(1).strip() if match else None


def parse_summary(text: str) -> dict[str, Any]:
    """CPU count and memory from `vim-cmd vmsvc/get.summary`."""
    cpu = _scalar(text, "numCpu")
    memory = _scalar(text, "memorySizeMB")
    return {
        "cpu": int(cpu) if cpu and cpu.isdigit() else None,
        "memory_mb": int(memory) if memory and memory.isdigit() else None,
    }


def parse_config(text: str) -> dict[str, Any]:
    """Hot-add flags from `vim-cmd vmsvc/get.config`."""
    return {
        "hot_add_cpu": _scalar(text, "cpuHotAddEnabled") == "true",
        "hot_add_memory": _scalar(text, "memoryHotAddEnabled") == "true",
    }


def parse_guest(text: str) -> dict[str, Any]:
    """Tools state from `vim-cmd vmsvc/get.guest`."""
    running = _scalar(text, "toolsRunningStatus")
    return {
        "tools_status": running,
        "tools_running": running == "guestToolsRunning",
        "guest_state": _scalar(text, "guestState"),
    }


#: A device block starts at its own type. Nested types carry a dotted suffix
#: (`VirtualDisk.FlatVer2BackingInfo`), which `\w+` does not match, so the
#: backing and its `fileName` stay inside the disk's block instead of starting
#: a new one.
_DEVICE_START = re.compile(r"\(vim\.vm\.device\.(\w+)\)")


def parse_devices(text: str) -> list[dict[str, Any]]:
    """Virtual disks from `vim-cmd vmsvc/get.devices`, label and capacity."""
    disks: list[dict[str, Any]] = []
    starts = list(_DEVICE_START.finditer(text or ""))
    for index, match in enumerate(starts):
        if match.group(1) != "VirtualDisk":
            continue
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        chunk = text[match.end() : end]
        label = _scalar(chunk, "label")
        capacity = _scalar(chunk, "capacityInKB")
        file_name = _scalar(chunk, "fileName")
        disks.append(
            {
                "label": label,
                "path": file_name,
                "size_gb": round(int(capacity) / (1024 * 1024), 3)
                if capacity and capacity.isdigit()
                else None,
            }
        )
    return disks


def parse_json(text: str, what: str) -> Any:
    try:
        return json.loads(text or "")
    except ValueError as exc:
        raise EsxiError(f"{what} did not return JSON") from exc


#: The heredoc delimiter a rewritten `.vmx` is written with. Quoted at the
#: shell, so nothing inside it is expanded.
VMX_HEREDOC = "INFRA_VMX_EOF"

#: `.vmx` lines a clone must not inherit: the template's name and its identity.
_VMX_DROP = re.compile(r"^\s*(displayName|uuid\.[A-Za-z]+|vc\.uuid)\s*=", re.IGNORECASE)


def patch_vmx(text: str, name: str, old_disk: str, new_disk: str) -> str:
    """A template's `.vmx` retitled for a clone, with its disk re-pointed.

    Done in Python rather than with a `sed` script: the disk basename is data,
    and `.` in it is a regex metacharacter that a `sed 's|...|...|'` would
    happily match against anything. `name` has already passed `SAFE_NAME`, so
    it holds no quote the file format could trip over.
    """
    lines: list[str] = []
    for line in (text or "").splitlines():
        if _VMX_DROP.match(line):
            continue
        if old_disk and old_disk in line and "fileName" in line:
            line = line.replace(old_disk, new_disk)
        lines.append(line.rstrip())
    lines.append(f'displayName = "{name}"')
    # Pre-answer hostd's "I moved it / I copied it" question: a copied .vmx
    # otherwise blocks on it at the first power on.
    lines.append('uuid.action = "create"')
    body = "\n".join(lines)
    if VMX_HEREDOC in body:
        raise EsxiError("the template .vmx contains this executor's heredoc marker")
    return body


def bundle_reference(command_output: str) -> dict[str, Any]:
    """The host-config bundle `backup_config` just wrote, as a reference.

    The bundle itself stays on the host: the executor records where it is and
    when, and the collector is what commits its contents to the config git
    store. The URL path is parsed by the collector's own helper so the two
    cannot drift.
    """
    from infra_agent.collectors.esxi import bundle_paths

    paths = bundle_paths(command_output)
    return {
        "kind": "esxi-host-config",
        "path": paths[-1],
        "taken_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# transports
# ---------------------------------------------------------------------------
class EsxiTransport(Protocol):
    """What the executor needs from a host, on either licence."""

    name: str

    def connection(self) -> AbstractContextManager[None]: ...
    def vm(self, ctx: ExecutionContext, name: str) -> dict[str, Any] | None: ...
    def power_state(self, ctx: ExecutionContext, vm: dict[str, Any]) -> str: ...
    def datastores(self, ctx: ExecutionContext) -> list[dict[str, Any]]: ...
    def host_setting_get(self, ctx: ExecutionContext, key: str) -> Any: ...
    def host_setting_set(
        self, ctx: ExecutionContext, key: str, value: Any, params: dict[str, Any]
    ) -> dict[str, Any]: ...
    def snapshot_create(
        self, ctx: ExecutionContext, vm: dict[str, Any], name: str, description: str
    ) -> dict[str, Any]: ...
    def snapshot_remove(
        self, ctx: ExecutionContext, vm: dict[str, Any], name: str
    ) -> dict[str, Any]: ...
    def snapshot_revert(
        self, ctx: ExecutionContext, vm: dict[str, Any], name: str
    ) -> dict[str, Any]: ...
    def power_on(self, ctx: ExecutionContext, vm: dict[str, Any]) -> dict[str, Any]: ...
    def shutdown_guest(self, ctx: ExecutionContext, vm: dict[str, Any]) -> dict[str, Any]: ...
    def power_off(self, ctx: ExecutionContext, vm: dict[str, Any]) -> dict[str, Any]: ...
    def reconfigure(
        self, ctx: ExecutionContext, vm: dict[str, Any], cpu: int | None, memory_mb: int | None
    ) -> dict[str, Any]: ...
    def disk_extend(
        self, ctx: ExecutionContext, vm: dict[str, Any], disk: dict[str, Any], size_gb: float
    ) -> dict[str, Any]: ...
    def clone_from_template(
        self,
        ctx: ExecutionContext,
        template: dict[str, Any],
        name: str,
        datastore: str | None,
        record: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]: ...
    def destroy_vm(self, ctx: ExecutionContext, vm: dict[str, Any]) -> dict[str, Any]: ...
    def backup_host_config(self, ctx: ExecutionContext) -> dict[str, Any]: ...
    def log_bundle(self, ctx: ExecutionContext) -> dict[str, Any]: ...


class SshSession(Protocol):
    """One shell on the host. `run` raises on a non-zero exit status."""

    def run(self, command: str, timeout: float) -> str: ...
    def close(self) -> None: ...


class ParamikoSession:
    """The real SSH session, opened with the read-write credential's key."""

    def __init__(self, device: SeedDevice, cred: Credential, timeout: float = 30.0) -> None:
        import paramiko  # lazy: optional dependency

        from infra_agent.tools.observability_tools import ssh_known_hosts

        client = paramiko.SSHClient()
        known_hosts = ssh_known_hosts()
        if known_hosts:
            client.load_host_keys(known_hosts)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict[str, Any] = {
            "hostname": device.mgmt_ip,
            "port": 22,  # device.port is the API port; ESXi SSH is always 22
            "username": cred.username,
            "timeout": timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }
        # Mirror the collector's `EsxiShowTransport`: the ESXi root account this
        # estate uses is a password account, and offering that password only as
        # a key passphrase meant every free-licence write failed with "no
        # authentication methods available".
        if cred.ssh_key_path:
            kwargs["key_filename"] = cred.ssh_key_path
            if cred.password:
                kwargs["passphrase"] = cred.password.get_secret_value()
        elif cred.password:
            kwargs["password"] = cred.password.get_secret_value()
        else:
            raise LookupError(
                f"the read-write credential for {device.name} has neither an ssh_key_path "
                "nor a password; a free-licence ESXi write needs one of them"
            )
        client.connect(**kwargs)
        self._client = client

    def run(self, command: str, timeout: float) -> str:
        _stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        status = getattr(getattr(stdout, "channel", None), "recv_exit_status", lambda: 0)()
        if status:
            raise EsxiError(f"command exited {status}: {err.strip()[:200]}")
        return out

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # noqa: BLE001 - closing a dead session is not an error
            pass


class SshTransport:
    """`vim-cmd` and `esxcli` over SSH. Works on the free licence and on any other."""

    name = "ssh"

    def __init__(
        self,
        open_session: Callable[[SeedDevice, Credential], SshSession] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.open_session = open_session or (lambda device, cred: ParamikoSession(device, cred))
        self.timeout = timeout
        self._session: SshSession | None = None
        self._depth = 0

    # -- plumbing ---------------------------------------------------------
    @contextmanager
    def connection(self) -> Iterator[None]:
        """One SSH session for everything inside the scope.

        A dry run plus pre-checks plus an apply plus post-checks used to be
        dozens of separate logins to the same host; the executor opens this
        once per call instead.
        """
        self._depth += 1
        try:
            yield
        finally:
            self._depth -= 1
            if self._depth == 0:
                self._close()

    def _close(self) -> None:
        session, self._session = self._session, None
        if session is not None:
            session.close()

    @contextmanager
    def _shell(self, ctx: ExecutionContext) -> Iterator[SshSession]:
        if self._depth > 0:
            if self._session is None:
                self._session = self.open_session(ctx.device, ctx.credential)
            yield self._session
            return
        session = self.open_session(ctx.device, ctx.credential)
        try:
            yield session
        finally:
            session.close()

    def run(self, ctx: ExecutionContext, command: str) -> str:
        with self._shell(ctx) as session:
            return session.run(command, self.timeout)

    def run_many(self, ctx: ExecutionContext, commands: list[str]) -> list[str]:
        """Several commands on one session, stopping at the first failure."""
        with self._shell(ctx) as session:
            return [session.run(command, self.timeout) for command in commands]

    # -- reads ------------------------------------------------------------
    def vm(self, ctx: ExecutionContext, name: str) -> dict[str, Any] | None:
        wanted = safe_name(name, "VM name")
        listing = parse_getallvms(self.run(ctx, "vim-cmd vmsvc/getallvms"))
        row = next((r for r in listing if r["name"] == wanted), None)
        if row is None:
            return None
        vmid = shlex.quote(str(row["vmid"]))
        outputs = self.run_many(
            ctx,
            [
                f"vim-cmd vmsvc/power.getstate {vmid}",
                f"vim-cmd vmsvc/get.snapshotinfo {vmid}",
                f"vim-cmd vmsvc/get.summary {vmid}",
                f"vim-cmd vmsvc/get.config {vmid}",
                f"vim-cmd vmsvc/get.guest {vmid}",
                f"vim-cmd vmsvc/get.devices {vmid}",
            ],
        )
        state, snapshots, summary, config, guest, devices = outputs
        row.update(parse_summary(summary))
        row.update(parse_config(config))
        row.update(parse_guest(guest))
        row["power_state"] = parse_power_state(state)
        row["snapshots"] = parse_snapshotinfo(snapshots)
        row["disks"] = parse_devices(devices)
        return row

    def power_state(self, ctx: ExecutionContext, vm: dict[str, Any]) -> str:
        """One `power.getstate`, for polling a shutdown without re-reading the VM."""
        vmid = shlex.quote(str(vm["vmid"]))
        return parse_power_state(self.run(ctx, f"vim-cmd vmsvc/power.getstate {vmid}"))

    def datastores(self, ctx: ExecutionContext) -> list[dict[str, Any]]:
        rows = parse_json(
            self.run(ctx, "esxcli --formatter=json storage filesystem list"), "filesystem list"
        )
        return [
            {
                "name": row.get("Volume Name"),
                "free_bytes": row.get("Free"),
                "capacity_bytes": row.get("Size"),
            }
            for row in rows or []
            if isinstance(row, dict)
        ]

    def host_setting_get(self, ctx: ExecutionContext, key: str) -> Any:
        key = normalise_setting_key(key)
        if key == SYSLOG_KEY:
            body = parse_json(
                self.run(ctx, "esxcli --formatter=json system syslog config get"), "syslog config"
            )
            return (body or {}).get("Remote Host")
        if key == NTP_KEY:
            body = parse_json(self.run(ctx, "esxcli --formatter=json system ntp get"), "ntp get")
            return list((body or {}).get("Server") or [])
        if key == CDP_KEY:
            rows = parse_json(
                self.run(ctx, "esxcli --formatter=json network vswitch standard list"),
                "vswitch list",
            )
            return {r.get("Name"): r.get("CDP Status") for r in rows or [] if isinstance(r, dict)}
        path = shlex.quote(advanced_path(key))
        rows = parse_json(
            self.run(ctx, f"esxcli --formatter=json system settings advanced list -o {path}"),
            "advanced settings",
        )
        row = (rows or [{}])[0] if isinstance(rows, list) else rows
        if not isinstance(row, dict):
            return None
        if str(row.get("Type", "")).lower() == "string":
            return row.get("String Value")
        return row.get("Int Value", row.get("String Value"))

    # -- writes -----------------------------------------------------------
    def host_setting_set(
        self, ctx: ExecutionContext, key: str, value: Any, params: dict[str, Any]
    ) -> dict[str, Any]:
        key = normalise_setting_key(key)
        if key == SYSLOG_KEY:
            target = shlex.quote(str(value or ""))
            # The firewall ruleset is the half everyone forgets: on a default
            # host the loghost is set, the check passes, and nothing ever
            # reaches the collector. Enabling it is idempotent.
            self.run_many(
                ctx,
                [
                    f"esxcli system syslog config set --loghost={target}",
                    "esxcli system syslog reload",
                    "esxcli network firewall ruleset set -r syslog -e true",
                ],
            )
            return {"key": key, "value": value, "firewall_ruleset": "syslog enabled"}
        if key == NTP_KEY:
            servers = [s for s in (value if isinstance(value, list) else [value]) if s]
            if not servers:
                # `esxcli system ntp set` with no flags is an error, so a
                # rollback to a host that had no NTP has to reset instead.
                self.run_many(
                    ctx,
                    ["esxcli system ntp set --reset", "esxcli system ntp set --enabled=0"],
                )
                return {"key": key, "value": [], "via": "reset"}
            flags = " ".join(f"--server={shlex.quote(str(s))}" for s in servers)
            self.run_many(
                ctx,
                [
                    f"esxcli system ntp set {flags}",
                    "esxcli system ntp set --enabled=1",
                ],
            )
            return {"key": key, "value": servers}
        if key == CDP_KEY:
            mode = str(value).lower()
            if mode not in CDP_MODES:
                raise EsxiError(f"CDP mode {value!r} is not one of {sorted(CDP_MODES)}")
            vswitch = shlex.quote(safe_name(params.get("vswitch", DEFAULT_VSWITCH), "vSwitch"))
            self.run(ctx, f"esxcli network vswitch standard set -v {vswitch} --cdp-status={mode}")
            return {"key": key, "value": mode, "vswitch": params.get("vswitch", DEFAULT_VSWITCH)}
        path = shlex.quote(advanced_path(key))
        flag = "-i" if isinstance(value, bool) or isinstance(value, int) else "-s"
        rendered = shlex.quote(str(int(value) if isinstance(value, bool) else value))
        self.run(ctx, f"esxcli system settings advanced set -o {path} {flag} {rendered}")
        return {"key": key, "value": value}

    def _snapshot_id(self, vm: dict[str, Any], name: str) -> str:
        for snapshot in vm.get("snapshots") or []:
            if snapshot.get("name") == name and snapshot.get("id"):
                return str(snapshot["id"])
        raise EsxiError(f"{vm.get('name')} has no snapshot named {name!r}")

    def snapshot_create(
        self, ctx: ExecutionContext, vm: dict[str, Any], name: str, description: str
    ) -> dict[str, Any]:
        vmid = shlex.quote(str(vm["vmid"]))
        # includeMemory=0 and quiesce=0: a memory snapshot of a busy VM on a
        # small datastore is exactly the outage this guard exists to avoid.
        self.run(
            ctx,
            f"vim-cmd vmsvc/snapshot.create {vmid} {shlex.quote(name)} "
            f"{shlex.quote(description)} 0 0",
        )
        return {"snapshot": name}

    def snapshot_remove(
        self, ctx: ExecutionContext, vm: dict[str, Any], name: str
    ) -> dict[str, Any]:
        vmid = shlex.quote(str(vm["vmid"]))
        snapshot_id = shlex.quote(self._snapshot_id(vm, name))
        self.run(ctx, f"vim-cmd vmsvc/snapshot.remove {vmid} {snapshot_id}")
        return {"snapshot": name}

    def snapshot_revert(
        self, ctx: ExecutionContext, vm: dict[str, Any], name: str
    ) -> dict[str, Any]:
        vmid = shlex.quote(str(vm["vmid"]))
        snapshot_id = shlex.quote(self._snapshot_id(vm, name))
        self.run(ctx, f"vim-cmd vmsvc/snapshot.revert {vmid} {snapshot_id} 0")
        return {"snapshot": name}

    def power_on(self, ctx: ExecutionContext, vm: dict[str, Any]) -> dict[str, Any]:
        self.run(ctx, f"vim-cmd vmsvc/power.on {shlex.quote(str(vm['vmid']))}")
        return {"power": "on"}

    def shutdown_guest(self, ctx: ExecutionContext, vm: dict[str, Any]) -> dict[str, Any]:
        self.run(ctx, f"vim-cmd vmsvc/power.shutdown {shlex.quote(str(vm['vmid']))}")
        return {"power": "guest shutdown requested"}

    def power_off(self, ctx: ExecutionContext, vm: dict[str, Any]) -> dict[str, Any]:
        self.run(ctx, f"vim-cmd vmsvc/power.off {shlex.quote(str(vm['vmid']))}")
        return {"power": "off"}

    def reconfigure(
        self, ctx: ExecutionContext, vm: dict[str, Any], cpu: int | None, memory_mb: int | None
    ) -> dict[str, Any]:
        """Rewrite the .vmx and reload it: the free licence has no reconfigure API.

        Only integers reach the file, and only through a delete-then-append of
        the whole line, so a malformed existing value cannot survive.

        A running VM is refused: hostd holds the .vmx open and `vmsvc/reload`
        does not hot-add, so the rewrite would either fail or quietly do
        nothing until the next power cycle (VMware KB 1026043). Hot-add lives
        on the API path only.
        """
        if vm.get("power_state") == POWERED_ON:
            raise EsxiError(
                f"{vm.get('name')} is powered on and this host has no reconfigure API: "
                "a .vmx rewrite needs the VM powered off, and hot-add is only "
                "available on the licensed (API) path"
            )
        vmx = host_path(vm.get("vmx"))
        if not vmx:
            raise EsxiError(f"no .vmx path for {vm.get('name')}")
        quoted_vmx = shlex.quote(vmx)
        commands: list[str] = []
        if cpu is not None:
            commands.append(f"sed -i '/^numvcpus[[:space:]]*=/d' {quoted_vmx}")
            commands.append(f"echo 'numvcpus = \"{int(cpu)}\"' >> {quoted_vmx}")
        if memory_mb is not None:
            commands.append(f"sed -i '/^memSize[[:space:]]*=/d' {quoted_vmx}")
            commands.append(f"echo 'memSize = \"{int(memory_mb)}\"' >> {quoted_vmx}")
        commands.append(f"vim-cmd vmsvc/reload {shlex.quote(str(vm['vmid']))}")
        self.run_many(ctx, commands)
        return {"cpu": cpu, "memory_mb": memory_mb, "via": "vmx rewrite + reload"}

    def disk_extend(
        self, ctx: ExecutionContext, vm: dict[str, Any], disk: dict[str, Any], size_gb: float
    ) -> dict[str, Any]:
        path = host_path(disk.get("path"))
        if not path:
            raise EsxiError(f"no datastore path for disk {disk.get('label')!r}")
        self.run(ctx, f"vmkfstools -X {int(size_gb)}G {shlex.quote(path)}")
        return {"disk": disk.get("label"), "size_gb": size_gb}

    def clone_from_template(
        self,
        ctx: ExecutionContext,
        template: dict[str, Any],
        name: str,
        datastore: str | None,
        record: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Copy the template's files, retitle them and register the result.

        Standalone ESXi has no clone API on the free licence, so this is the
        documented `vmkfstools -i` + `vim-cmd solo/registervm` path.

        The directory is created with a plain `mkdir`, not `mkdir -p`: if
        anything is already there the step stops before a single byte is
        written, because the rollback for this action deletes a directory and
        it must only ever delete one this step made. `record` is called with
        that directory the moment it exists, so a clone that dies half way
        through the disk copy still has something to clean up.
        """
        source_vmx = host_path(template.get("vmx"))
        if not source_vmx:
            raise EsxiError(f"no .vmx path for template {template.get('name')}")
        store = safe_name(datastore or template.get("datastore") or "", "datastore")
        target_dir = f"/vmfs/volumes/{store}/{name}"
        target_vmx = f"{target_dir}/{name}.vmx"
        target_vmdk = f"{target_dir}/{name}.vmdk"
        disks = template.get("disks") or []
        source_vmdk = host_path((disks[0] or {}).get("path")) if disks else None
        if not source_vmdk:
            raise EsxiError(f"template {template.get('name')} has no disk to copy")
        quoted_dir = shlex.quote(target_dir)
        quoted_vmx = shlex.quote(target_vmx)

        with self.connection():
            source_text = self.run(ctx, f"cat {shlex.quote(source_vmx)}")
            self.run(ctx, f"mkdir {quoted_dir}")
            if record is not None:
                record({"dir": target_dir})
            patched = patch_vmx(source_text, name, _vmdk_basename(source_vmdk), f"{name}.vmdk")
            outputs = self.run_many(
                ctx,
                [
                    f"vmkfstools -i {shlex.quote(source_vmdk)} -d thin {shlex.quote(target_vmdk)}",
                    # A quoted heredoc: the shell expands nothing inside it, so
                    # the .vmx is written verbatim without a sed script that
                    # would have to escape regex metacharacters.
                    f"cat > {quoted_vmx} <<'{VMX_HEREDOC}'\n{patched}\n{VMX_HEREDOC}",
                    f"vim-cmd solo/registervm {quoted_vmx}",
                ],
            )
        last = (outputs[-1] or "").strip()
        vmid = last.splitlines()[-1].strip() if last else None
        return {
            "name": name,
            "vmid": vmid,
            "vmx": f"[{store}] {name}/{name}.vmx",
            "dir": target_dir,
        }

    def destroy_vm(self, ctx: ExecutionContext, vm: dict[str, Any]) -> dict[str, Any]:
        """Unregister the clone and delete the directory *this plan created*.

        `dir` has to have been recorded by `clone_from_template`. Falling back
        to the directory of whatever VM happens to answer to that name is how a
        rollback deletes somebody else's VM folder.
        """
        directory = vm.get("dir")
        if not directory:
            raise EsxiError(
                "no directory was recorded for this clone, so there is nothing this "
                "rollback may safely delete; remove the clone by hand"
            )
        if not directory.startswith("/vmfs/volumes/") or directory.count("/") < 4:
            raise EsxiError(f"refusing to delete {directory!r}: not a VM directory on a datastore")
        commands = []
        vmid = vm.get("vmid")
        if vmid not in (None, ""):
            quoted = shlex.quote(str(vmid))
            commands += [
                f"vim-cmd vmsvc/power.off {quoted} || true",
                f"vim-cmd vmsvc/unregister {quoted}",
            ]
        commands.append(f"rm -rf {shlex.quote(directory)}")
        self.run_many(ctx, commands)
        return {"destroyed": vm.get("name"), "dir": directory}

    def backup_host_config(self, ctx: ExecutionContext) -> dict[str, Any]:
        from infra_agent.collectors.esxi import BACKUP_COMMAND

        return bundle_reference(self.run(ctx, BACKUP_COMMAND))

    def log_bundle(self, ctx: ExecutionContext) -> dict[str, Any]:
        output = self.run(ctx, "vm-support -w /scratch")
        match = re.search(r"(/\S+\.tgz)", output or "")
        return {"kind": "esxi-log-bundle", "path": match.group(1) if match else None}


def _vmdk_basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


class PyvmomiTransport:
    """hostd's API with the read-write account. Licensed hosts only.

    `connect` and `vim` are injected so the tests exercise this code without
    pyvmomi and without a host; in production both come from the lazy import.
    """

    name = "pyvmomi"

    def __init__(
        self,
        connect: Callable[[SeedDevice, Credential], Any] | None = None,
        vim: Any = None,
        sleep: Callable[[float], None] = time.sleep,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._connect = connect
        self._vim = vim
        self.sleep = sleep
        self.timeout = timeout
        self._si: Any = None
        self._content: Any = None
        self._depth = 0

    # -- plumbing ---------------------------------------------------------
    def vim(self) -> Any:
        if self._vim is None:
            from pyVmomi import vim  # lazy: optional dependency

            self._vim = vim
        return self._vim

    @contextmanager
    def connection(self) -> Iterator[None]:
        """One hostd session for everything inside the scope.

        hostd caps concurrent sessions and an idle one lingers for half an
        hour; a login per read would lock the platform out of its own host
        after a couple of plans. The session is disconnected on the way out.
        """
        self._depth += 1
        try:
            yield
        finally:
            self._depth -= 1
            if self._depth == 0:
                self._disconnect()

    def _disconnect(self) -> None:
        si, self._si, self._content = self._si, None, None
        if si is None:
            return
        try:
            from pyVim.connect import Disconnect  # lazy: optional dependency

            Disconnect(si)
        except Exception:  # noqa: BLE001 - closing a dead session is not an error
            pass

    def connect(self, ctx: ExecutionContext) -> Any:
        if self._si is not None:
            return self._si
        si = self._open(ctx)
        if self._depth > 0:
            self._si = si
        return si

    def _open(self, ctx: ExecutionContext) -> Any:
        if self._connect is not None:
            return self._connect(ctx.device, ctx.credential)
        import ssl

        from pyVim.connect import SmartConnect  # lazy: optional dependency

        cred = ctx.credential
        context = ssl._create_unverified_context()  # pinned in Phase 1, as the collector is
        return SmartConnect(
            host=ctx.device.mgmt_ip,
            port=ctx.device.port or 443,
            user=cred.username,
            pwd=cred.password.get_secret_value() if cred.password else "",
            sslContext=context,
            connectionPoolTimeout=int(self.timeout),
        )

    def content(self, ctx: ExecutionContext) -> Any:
        if self._content is not None:
            return self._content
        content = self.connect(ctx).RetrieveContent()
        if self._depth > 0:
            self._content = content
        return content

    def host(self, ctx: ExecutionContext) -> Any:
        from infra_agent.collectors.esxi import first_host

        return first_host(self.content(ctx))

    def datacenter(self, ctx: ExecutionContext) -> Any:
        """The single Datacenter of a standalone host."""
        for entity in (
            getattr(getattr(self.content(ctx), "rootFolder", None), "childEntity", None) or []
        ):
            if getattr(entity, "vmFolder", None) is not None:
                return entity
        raise EsxiError("this host exposes no datacenter to register a VM in")

    def wait(self, task: Any) -> Any:
        """Block until a task finishes; raise its error as an EsxiError."""
        deadline = time.monotonic() + self.timeout
        while True:
            info = getattr(task, "info", None)
            state = str(getattr(info, "state", "") or "")
            if state == "success":
                return getattr(info, "result", None)
            if state == "error":
                message = getattr(getattr(info, "error", None), "msg", None) or "task failed"
                raise EsxiError(str(message)[:200])
            if time.monotonic() > deadline:
                raise EsxiError("timed out waiting for the host task to finish")
            self.sleep(1.0)

    def _find_vm(self, ctx: ExecutionContext, name: str) -> Any:
        wanted = safe_name(name, "VM name")
        for candidate in getattr(self.host(ctx), "vm", None) or []:
            if getattr(candidate, "name", None) == wanted:
                return candidate
        return None

    # -- reads ------------------------------------------------------------
    def vm(self, ctx: ExecutionContext, name: str) -> dict[str, Any] | None:
        obj = self._find_vm(ctx, name)
        if obj is None:
            return None
        return self._row(obj)

    def power_state(self, ctx: ExecutionContext, vm: dict[str, Any]) -> str:
        """One property read, for polling a shutdown without re-reading the VM."""
        obj = vm.get("_ref") or self._find_vm(ctx, str(vm.get("name")))
        if obj is None:
            raise EsxiError(f"{vm.get('name')} is not registered on this host")
        return str(getattr(getattr(obj, "runtime", None), "powerState", "") or "unknown")

    def _row(self, obj: Any) -> dict[str, Any]:
        config = getattr(obj, "config", None)
        hardware = getattr(config, "hardware", None)
        guest = getattr(obj, "guest", None)
        runtime = getattr(obj, "runtime", None)
        tools = getattr(guest, "toolsRunningStatus", None)
        disks = []
        for device in getattr(hardware, "device", None) or []:
            capacity = getattr(device, "capacityInKB", None)
            label = getattr(getattr(device, "deviceInfo", None), "label", None)
            if capacity is None or not str(label or "").lower().startswith("hard disk"):
                continue
            disks.append(
                {
                    "label": label,
                    "path": getattr(getattr(device, "backing", None), "fileName", None),
                    "size_gb": round(int(capacity) / (1024 * 1024), 3),
                    "_key": getattr(device, "key", None),
                }
            )
        vmx = getattr(getattr(config, "files", None), "vmPathName", None)
        return {
            "name": getattr(obj, "name", None),
            "vmx": vmx,
            "datastore": datastore_of(vmx),
            "power_state": str(getattr(runtime, "powerState", "") or "unknown"),
            "cpu": getattr(hardware, "numCPU", None),
            "memory_mb": getattr(hardware, "memoryMB", None),
            "hot_add_cpu": bool(getattr(config, "cpuHotAddEnabled", False)),
            "hot_add_memory": bool(getattr(config, "memoryHotAddEnabled", False)),
            "tools_status": tools,
            "tools_running": tools == "guestToolsRunning",
            "guest_state": getattr(guest, "guestState", None),
            "snapshots": _snapshot_tree(
                getattr(getattr(obj, "snapshot", None), "rootSnapshotList", None)
            ),
            "disks": disks,
            "_ref": obj,
        }

    def datastores(self, ctx: ExecutionContext) -> list[dict[str, Any]]:
        rows = []
        for store in getattr(self.host(ctx), "datastore", None) or []:
            summary = getattr(store, "summary", None)
            rows.append(
                {
                    "name": getattr(summary, "name", None) or getattr(store, "name", None),
                    "free_bytes": getattr(summary, "freeSpace", None),
                    "capacity_bytes": getattr(summary, "capacity", None),
                }
            )
        return rows

    def host_setting_get(self, ctx: ExecutionContext, key: str) -> Any:
        key = normalise_setting_key(key)
        host = self.host(ctx)
        managers = getattr(host, "configManager", None)
        if key == NTP_KEY:
            config = getattr(getattr(managers, "dateTimeSystem", None), "dateTimeSystem", None)
            ntp = getattr(getattr(host, "config", None), "dateTimeInfo", None)
            servers = getattr(getattr(ntp, "ntpConfig", None), "server", None) or []
            del config
            return list(servers)
        if key == CDP_KEY:
            modes: dict[str, Any] = {}
            network = getattr(getattr(host, "config", None), "network", None)
            for switch in getattr(network, "vswitch", None) or []:
                discovery = getattr(getattr(switch, "spec", None), "bridge", None)
                protocol = getattr(discovery, "linkDiscoveryProtocolConfig", None)
                modes[getattr(switch, "name", None)] = getattr(protocol, "operation", None)
            return modes
        option_key = SYSLOG_KEY if key == SYSLOG_KEY else key
        options = getattr(managers, "advancedOption", None)
        for option in getattr(options, "setting", None) or []:
            if getattr(option, "key", None) == option_key:
                return getattr(option, "value", None)
        query = getattr(options, "QueryOptions", None)
        if query is not None:
            found = query(option_key) or []
            if found:
                return getattr(found[0], "value", None)
        return None

    # -- writes -----------------------------------------------------------
    def host_setting_set(
        self, ctx: ExecutionContext, key: str, value: Any, params: dict[str, Any]
    ) -> dict[str, Any]:
        key = normalise_setting_key(key)
        vim = self.vim()
        host = self.host(ctx)
        managers = getattr(host, "configManager", None)
        if key == NTP_KEY:
            servers = value if isinstance(value, list) else [value]
            spec = vim.host.DateTimeConfig(ntpConfig=vim.host.NtpConfig(server=list(servers)))
            managers.dateTimeSystem.UpdateDateTimeConfig(config=spec)
            return {"key": key, "value": list(servers)}
        if key == CDP_KEY:
            mode = str(value).lower()
            if mode not in CDP_MODES:
                raise EsxiError(f"CDP mode {value!r} is not one of {sorted(CDP_MODES)}")
            name = safe_name(params.get("vswitch", DEFAULT_VSWITCH), "vSwitch")
            # `UpdateVirtualSwitch` REPLACES the switch spec. A freshly built
            # Specification has neither `numPorts` nor the bridge's `nicDevice`
            # (both required fields), so it cannot even be serialised — and
            # supplying empty ones would strip vSwitch0's uplinks and isolate
            # the host. The live spec is read and only CDP is changed on it.
            spec = self._vswitch_spec(host, name)
            bridge = getattr(spec, "bridge", None)
            if bridge is None:
                raise EsxiError(
                    f"vSwitch {name} has no uplink bridge, so CDP has nothing to run on"
                )
            discovery = getattr(bridge, "linkDiscoveryProtocolConfig", None)
            if discovery is None:
                bridge.linkDiscoveryProtocolConfig = vim.host.LinkDiscoveryProtocolConfig(
                    protocol="cdp", operation=mode
                )
            else:
                discovery.protocol = "cdp"
                discovery.operation = mode
            managers.networkSystem.UpdateVirtualSwitch(vswitchName=name, spec=spec)
            return {"key": key, "value": mode, "vswitch": name}
        option_key = SYSLOG_KEY if key == SYSLOG_KEY else key
        managers.advancedOption.UpdateOptions(
            changedValue=[vim.option.OptionValue(key=option_key, value=value)]
        )
        applied: dict[str, Any] = {"key": key, "value": value}
        if key == SYSLOG_KEY:
            applied["firewall_ruleset"] = self._enable_syslog_ruleset(managers)
        return applied

    @staticmethod
    def _vswitch_spec(host: Any, name: str) -> Any:
        network = getattr(getattr(host, "config", None), "network", None)
        for switch in getattr(network, "vswitch", None) or []:
            if getattr(switch, "name", None) == name:
                spec = getattr(switch, "spec", None)
                if spec is None:
                    break
                return spec
        raise EsxiError(f"this host has no vSwitch named {name!r}")

    @staticmethod
    def _enable_syslog_ruleset(managers: Any) -> str:
        """Open the syslog ruleset, or say why it could not be opened.

        Without it the loghost is set, the check passes and nothing arrives.
        """
        firewall = getattr(managers, "firewallSystem", None)
        enable = getattr(firewall, "EnableRuleset", None)
        if enable is None:
            return "not available on this host; enable the syslog ruleset by hand"
        try:
            enable(id="syslog")
        except Exception as exc:  # noqa: BLE001 - the loghost itself is set either way
            return f"could not be enabled: {short_error(exc)}"
        return "syslog enabled"

    def _snapshot_ref(self, vm: dict[str, Any], name: str) -> Any:
        for snapshot in vm.get("snapshots") or []:
            if snapshot.get("name") == name and snapshot.get("_ref") is not None:
                return snapshot["_ref"]
        raise EsxiError(f"{vm.get('name')} has no snapshot named {name!r}")

    def snapshot_create(
        self, ctx: ExecutionContext, vm: dict[str, Any], name: str, description: str
    ) -> dict[str, Any]:
        self.wait(
            vm["_ref"].CreateSnapshot_Task(
                name=name, description=description, memory=False, quiesce=False
            )
        )
        return {"snapshot": name}

    def snapshot_remove(
        self, ctx: ExecutionContext, vm: dict[str, Any], name: str
    ) -> dict[str, Any]:
        self.wait(self._snapshot_ref(vm, name).RemoveSnapshot_Task(removeChildren=False))
        return {"snapshot": name}

    def snapshot_revert(
        self, ctx: ExecutionContext, vm: dict[str, Any], name: str
    ) -> dict[str, Any]:
        self.wait(self._snapshot_ref(vm, name).RevertToSnapshot_Task())
        return {"snapshot": name}

    def power_on(self, ctx: ExecutionContext, vm: dict[str, Any]) -> dict[str, Any]:
        self.wait(vm["_ref"].PowerOnVM_Task())
        return {"power": "on"}

    def shutdown_guest(self, ctx: ExecutionContext, vm: dict[str, Any]) -> dict[str, Any]:
        vm["_ref"].ShutdownGuest()  # fire and forget; the executor polls the state
        return {"power": "guest shutdown requested"}

    def power_off(self, ctx: ExecutionContext, vm: dict[str, Any]) -> dict[str, Any]:
        self.wait(vm["_ref"].PowerOffVM_Task())
        return {"power": "off"}

    def reconfigure(
        self, ctx: ExecutionContext, vm: dict[str, Any], cpu: int | None, memory_mb: int | None
    ) -> dict[str, Any]:
        vim = self.vim()
        spec = vim.vm.ConfigSpec()
        if cpu is not None:
            spec.numCPUs = int(cpu)
        if memory_mb is not None:
            spec.memoryMB = int(memory_mb)
        self.wait(vm["_ref"].ReconfigVM_Task(spec=spec))
        return {"cpu": cpu, "memory_mb": memory_mb, "via": "ReconfigVM_Task"}

    def disk_extend(
        self, ctx: ExecutionContext, vm: dict[str, Any], disk: dict[str, Any], size_gb: float
    ) -> dict[str, Any]:
        vim = self.vim()
        device = None
        for candidate in (
            getattr(getattr(vm["_ref"].config, "hardware", None), "device", None) or []
        ):
            if getattr(candidate, "key", None) == disk.get("_key"):
                device = candidate
                break
        if device is None:
            raise EsxiError(f"disk {disk.get('label')!r} is no longer on the VM")
        device.capacityInKB = int(size_gb * 1024 * 1024)
        change = vim.vm.device.VirtualDeviceSpec(operation="edit", device=device)
        self.wait(vm["_ref"].ReconfigVM_Task(spec=vim.vm.ConfigSpec(deviceChange=[change])))
        return {"disk": disk.get("label"), "size_gb": size_gb}

    def clone_from_template(
        self,
        ctx: ExecutionContext,
        template: dict[str, Any],
        name: str,
        datastore: str | None,
        record: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Copy, register and retitle — the standalone-host clone.

        `CloneVM_Task` is a vCenter operation: hostd answers it with "the
        operation is not supported on the object", and there is no vCenter in
        this estate, so it is never called. What a host *can* do is make a
        directory, copy a disk and a `.vmx` into it and register the result,
        which is the same sequence the SSH path runs.

        `MakeDirectory` is the existence guard: it fails if the directory is
        already there, before anything is copied. `record` is called with the
        directory the moment it exists so a half-finished clone still has
        something the rollback can remove.
        """
        vim = self.vim()
        source_vmx = template.get("vmx")
        disks = template.get("disks") or []
        source_vmdk = (disks[0] or {}).get("path") if disks else None
        if not source_vmx or not source_vmdk:
            raise EsxiError(f"template {template.get('name')} has no .vmx and disk to copy")
        store = safe_name(datastore or template.get("datastore") or "", "datastore")
        target_dir = f"[{store}] {name}"
        target_vmx = f"{target_dir}/{name}.vmx"
        target_vmdk = f"{target_dir}/{name}.vmdk"

        content = self.content(ctx)
        datacenter = self.datacenter(ctx)
        files = getattr(content, "fileManager", None)
        disk_manager = getattr(content, "virtualDiskManager", None)
        if files is None or disk_manager is None:
            raise EsxiError("this host exposes no fileManager/virtualDiskManager to clone with")

        files.MakeDirectory(name=target_dir, datacenter=datacenter, createParentDirectories=False)
        if record is not None:
            record({"dir": target_dir})
        # No destSpec: the copy keeps the template's disk format rather than
        # guessing an adapter type the source may not use.
        self.wait(
            disk_manager.CopyVirtualDisk_Task(
                sourceName=source_vmdk,
                sourceDatacenter=datacenter,
                destName=target_vmdk,
                destDatacenter=datacenter,
                force=False,
            )
        )
        self.wait(
            files.CopyDatastoreFile_Task(
                sourceName=source_vmx,
                sourceDatacenter=datacenter,
                destinationName=target_vmx,
                destinationDatacenter=datacenter,
                force=False,
            )
        )
        host = self.host(ctx)
        pool = getattr(getattr(host, "parent", None), "resourcePool", None)
        registered = self.wait(
            datacenter.vmFolder.RegisterVM_Task(
                path=target_vmx, name=name, asTemplate=False, pool=pool, host=host
            )
        )
        obj = registered or self._find_vm(ctx, name)
        if obj is None:
            raise EsxiError(f"{name} was registered but the host does not list it")
        # The copied .vmx still carries the template's displayName and points
        # at the template's disk, so both are corrected before anything can
        # power the clone on. `uuid.action` pre-answers the "I copied it"
        # question a copied .vmx otherwise blocks on.
        spec = vim.vm.ConfigSpec()
        spec.name = name
        spec.extraConfig = [vim.option.OptionValue(key="uuid.action", value="create")]
        change = self._disk_backing_change(vim, obj, target_vmdk)
        if change is not None:
            spec.deviceChange = [change]
        self.wait(obj.ReconfigVM_Task(spec=spec))
        return {
            "name": name,
            "from": template.get("name"),
            "vmx": target_vmx,
            "dir": target_dir,
            "via": "MakeDirectory + CopyVirtualDisk + RegisterVM",
        }

    @staticmethod
    def _disk_backing_change(vim: Any, obj: Any, path: str) -> Any:
        """Point the clone's first disk at the copy, not at the template's file."""
        for device in (
            getattr(getattr(getattr(obj, "config", None), "hardware", None), "device", None) or []
        ):
            backing = getattr(device, "backing", None)
            if getattr(device, "capacityInKB", None) is None or backing is None:
                continue
            if getattr(backing, "fileName", None) is None:
                continue
            backing.fileName = path
            return vim.vm.device.VirtualDeviceSpec(operation="edit", device=device)
        return None

    def destroy_vm(self, ctx: ExecutionContext, vm: dict[str, Any]) -> dict[str, Any]:
        """Unregister the clone and delete the directory *this plan created*.

        Never `Destroy_Task`: it deletes every file the VM references, and a
        clone whose backing edit did not land still references the template's
        own disk. Only the recorded directory goes.
        """
        directory = vm.get("dir")
        if not directory:
            raise EsxiError(
                "no directory was recorded for this clone, so there is nothing this "
                "rollback may safely delete; remove the clone by hand"
            )
        obj = vm.get("_ref") or self._find_vm(ctx, str(vm.get("name")))
        if obj is not None:
            if str(getattr(getattr(obj, "runtime", None), "powerState", "")) == POWERED_ON:
                self.wait(obj.PowerOffVM_Task())
            obj.UnregisterVM()
        files = getattr(self.content(ctx), "fileManager", None)
        if files is None:
            raise EsxiError("this host exposes no fileManager to delete the clone's files with")
        self.wait(files.DeleteDatastoreFile_Task(name=directory, datacenter=self.datacenter(ctx)))
        return {"destroyed": vm.get("name"), "dir": directory}

    def backup_host_config(self, ctx: ExecutionContext) -> dict[str, Any]:
        firmware = getattr(getattr(self.host(ctx), "configManager", None), "firmwareSystem", None)
        if firmware is None:
            raise EsxiError("this host exposes no firmwareSystem to back up from")
        url = firmware.BackupFirmwareConfiguration()
        return {
            "kind": "esxi-host-config",
            "path": str(url),
            "taken_at": datetime.now(UTC).isoformat(),
        }

    def log_bundle(self, ctx: ExecutionContext) -> dict[str, Any]:
        content = self.content(ctx)
        manager = getattr(content, "diagnosticManager", None)
        if manager is None:
            raise EsxiError("this host exposes no diagnosticManager")
        result = self.wait(manager.GenerateLogBundles_Task(includeDefault=True))
        paths = [getattr(item, "url", None) for item in result or []]
        return {"kind": "esxi-log-bundle", "path": paths[0] if paths else None}


def _snapshot_tree(nodes: Any, out: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Flatten pyvmomi's snapshot tree into rows the executor understands."""
    out = [] if out is None else out
    for node in nodes or []:
        out.append(
            {
                "name": getattr(node, "name", None),
                "id": getattr(node, "id", None),
                "description": getattr(node, "description", None),
                "_ref": getattr(node, "snapshot", None),
            }
        )
        _snapshot_tree(getattr(node, "childSnapshotList", None), out)
    return out


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------
CHECK_POWER = re.compile(r"^vm\s+(?P<vm>.+?)\s+powered\s+(?P<state>on|off)$", re.I)
CHECK_TOOLS = re.compile(r"^vm\s+(?P<vm>.+?)\s+tools\s+running$", re.I)
CHECK_NO_SNAPSHOTS = re.compile(r"^vm\s+(?P<vm>.+?)\s+has\s+no\s+snapshots$", re.I)
CHECK_DATASTORE = re.compile(
    r"^datastore\s+(?P<name>.+?)\s+free\s*>=\s*(?P<gb>\d+(?:\.\d+)?)\s*(?:gb)?$", re.I
)
CHECK_SETTING = re.compile(r"^host\s+setting\s+(?P<key>\S+)\s*==\s*(?P<value>.+)$", re.I)

CHECK_GRAMMAR = (
    "vm <name> powered on|off",
    "vm <name> tools running",
    "vm <name> has no snapshots",
    "datastore <name> free >= <GB>",
    "host setting <key> == <value>",
)


def public(row: dict[str, Any] | None) -> dict[str, Any]:
    """A transport row with its private handles removed, safe for `output`."""
    if not row:
        return {}
    clean: dict[str, Any] = {}
    for key, value in row.items():
        if key.startswith("_"):
            continue
        if isinstance(value, list):
            clean[key] = [public(v) if isinstance(v, dict) else v for v in value]
        elif isinstance(value, dict):
            clean[key] = public(value)
        else:
            clean[key] = value
    return clean


@dataclass
class _Plan:
    """What one step intends, resolved against live state."""

    action: str
    vm_name: str | None = None
    vm: dict[str, Any] | None = None
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    warnings: list[str] | None = None
    blockers: list[str] | None = None


@register
class EsxiExecutor(Executor):
    """VM and host changes on a standalone ESXi host, on either licence."""

    platform = "esxi"

    def __init__(
        self,
        licensed: EsxiTransport | None = None,
        free: EsxiTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._licensed = licensed
        self._free = free
        self.sleep = sleep
        self.monotonic = monotonic

    # -- contract ---------------------------------------------------------
    def supported_actions(self) -> set[str]:
        return set(ACTIONS)

    def transport(self, device: SeedDevice) -> EsxiTransport:
        """The transport for this licence, built once and reused.

        Memoised on purpose: a transport holds the host session, and a new one
        per call is a new login per call.
        """
        if is_licensed(device):
            if self._licensed is None:
                self._licensed = PyvmomiTransport()
            return self._licensed
        if self._free is None:
            self._free = SshTransport()
        return self._free

    def _session(self, device: SeedDevice) -> AbstractContextManager[None]:
        """One host session for the whole of a public call."""
        scope = getattr(self.transport(device), "connection", None)
        return scope() if callable(scope) else nullcontext()

    # -- shared step logic ------------------------------------------------
    def _vm(self, ctx: ExecutionContext, name: str) -> dict[str, Any]:
        row = self.transport(ctx.device).vm(ctx, name)
        if row is None:
            raise EsxiError(f"no VM named {name!r} on {ctx.device.name}")
        return row

    def _datastore_free_gb(self, ctx: ExecutionContext, name: str | None) -> float | None:
        if not name:
            return None
        for store in self.transport(ctx.device).datastores(ctx):
            if store.get("name") == name:
                free = store.get("free_bytes")
                return round(float(free) / GIB, 2) if free is not None else None
        return None

    def snapshot_name(self, ctx: ExecutionContext) -> str:
        return f"infra-{ctx.plan_id}"

    @staticmethod
    def _setting_before(
        transport: EsxiTransport, ctx: ExecutionContext, key: str, params: dict[str, Any]
    ) -> tuple[Any, Any]:
        """(the value a rollback restores, everything the host reported).

        CDP is read per host, not per vSwitch: `host_setting_get` answers with
        `{vswitch: mode}` for every switch. Handing that map back as *the* mode
        is how a rollback of `cdp.mode` used to fail every time, so the scalar
        for the vSwitch the step names is what gets captured.
        """
        current = transport.host_setting_get(ctx, key)
        if key == CDP_KEY and isinstance(current, dict):
            vswitch = str(params.get("vswitch", DEFAULT_VSWITCH))
            return current.get(vswitch), current
        return current, current

    def _snapshot_space_blocker(
        self, ctx: ExecutionContext, vm: dict[str, Any], minimum: float
    ) -> str | None:
        store = vm.get("datastore")
        free = self._datastore_free_gb(ctx, store)
        if free is None:
            return f"cannot read free space on datastore {store!r}; refusing to snapshot"
        if free < minimum:
            return (
                f"datastore {store} has {free} GB free, below the {minimum} GB "
                f"a snapshot of {vm.get('name')} needs"
            )
        return None

    @staticmethod
    def _min_free_gb(step: ChangeStep) -> float:
        try:
            return float(step.params.get("min_free_gb", DEFAULT_MIN_FREE_GB))
        except (TypeError, ValueError):
            return DEFAULT_MIN_FREE_GB

    @staticmethod
    def _disk(vm: dict[str, Any], label: Any) -> dict[str, Any]:
        disks = vm.get("disks") or []
        wanted = str(label) if label is not None else None
        for disk in disks:
            if wanted is None or disk.get("label") == wanted or disk.get("path") == wanted:
                return disk
        raise EsxiError(f"{vm.get('name')} has no disk {wanted!r}")

    # -- dry run ----------------------------------------------------------
    def dry_run(self, ctx: ExecutionContext, steps: list[ChangeStep]) -> DryRunResult:
        entries: list[dict[str, Any]] = []
        warnings: list[str] = []
        blockers: list[str] = []
        probe = ExecutionContext(
            plan_id=ctx.plan_id,
            device=ctx.device,
            credential=ctx.credential,
            dry_run=True,
            frozen=ctx.frozen,
            extra=ctx.extra,
        )
        with self._session(ctx.device):
            for step in steps:
                entry, step_warnings, step_blockers = self._preview(probe, step)
                entries.append(entry)
                warnings.extend(step_warnings)
                blockers.extend(step_blockers)
        return DryRunResult(
            ok=not blockers,
            diff={
                "platform": self.platform,
                "device": ctx.device.name,
                "transport": self.transport(ctx.device).name,
                "steps": entries,
            },
            warnings=warnings,
            blockers=blockers,
        )

    def _preview(
        self, ctx: ExecutionContext, step: ChangeStep
    ) -> tuple[dict[str, Any], list[str], list[str]]:
        """The exact intended operation for one step. Never raises."""
        warnings: list[str] = []
        blockers: list[str] = []
        entry: dict[str, Any] = {"action": step.action}
        try:
            if step.action not in ACTIONS:
                raise EsxiError(f"{step.action} is not an ESXi action this executor implements")
            if step.action == "esxi.log_bundle":
                entry["operation"] = "collect a support bundle; nothing is changed"
                return entry, warnings, blockers
            if step.action == "esxi.host_setting":
                return self._preview_host_setting(ctx, step, entry, warnings, blockers)
            return self._preview_vm(ctx, step, entry, warnings, blockers)
        except Exception as exc:  # noqa: BLE001 - a preview failure is a blocker
            entry["error"] = short_error(exc)
            blockers.append(f"{step.action}: {short_error(exc)}")
            return entry, warnings, blockers

    def _preview_host_setting(
        self,
        ctx: ExecutionContext,
        step: ChangeStep,
        entry: dict[str, Any],
        warnings: list[str],
        blockers: list[str],
    ) -> tuple[dict[str, Any], list[str], list[str]]:
        key = normalise_setting_key(step.params.get("key", ""))
        if not key:
            blockers.append("esxi.host_setting needs params.key")
            return entry, warnings, blockers
        value = step.params.get("value")
        transport = self.transport(ctx.device)
        current, everything = self._setting_before(transport, ctx, key, step.params)
        entry.update(
            {
                "operation": f"set host setting {key}",
                "key": key,
                "before": current,
                "after": value,
                "backup": "a host-config backup is taken before the change",
            }
        )
        if everything is not current:
            entry["before_all"] = everything
        if key == CDP_KEY:
            entry["vswitch"] = str(step.params.get("vswitch", DEFAULT_VSWITCH))
            if isinstance(everything, dict) and entry["vswitch"] not in everything:
                blockers.append(f"this host has no vSwitch named {entry['vswitch']!r}")
        if key == CDP_KEY and str(value).lower() not in CDP_MODES:
            blockers.append(f"CDP mode {value!r} is not one of {sorted(CDP_MODES)}")
        if key == CDP_KEY and str(value).lower() != "both":
            warnings.append("CDP has to be 'both' for the topology graph to see the switch side")
        if current == value:
            warnings.append(f"host setting {key} is already {value!r}")
        return entry, warnings, blockers

    def _preview_vm(
        self,
        ctx: ExecutionContext,
        step: ChangeStep,
        entry: dict[str, Any],
        warnings: list[str],
        blockers: list[str],
    ) -> tuple[dict[str, Any], list[str], list[str]]:
        name = step.params.get("vm") or step.params.get("name")
        if step.action == "vm.create_from_template":
            return self._preview_clone(ctx, step, entry, warnings, blockers)
        vm = self._vm(ctx, str(name))
        entry["vm"] = vm.get("name")
        entry["before"] = _vm_summary(vm)
        snapshots = [s.get("name") for s in vm.get("snapshots") or []]
        minimum = self._min_free_gb(step)

        if step.action == "vm.snapshot":
            snapshot = step.params.get("snapshot_name") or self.snapshot_name(ctx)
            entry["operation"] = f"create snapshot {snapshot!r}"
            entry["after"] = {"snapshots": snapshots + [snapshot]}
            space = self._snapshot_space_blocker(ctx, vm, minimum)
            if space:
                blockers.append(space)
            if snapshot in snapshots:
                blockers.append(f"{vm.get('name')} already has a snapshot named {snapshot!r}")
        elif step.action == "vm.snapshot_remove":
            snapshot = step.params.get("snapshot_name") or self.snapshot_name(ctx)
            entry["operation"] = f"remove snapshot {snapshot!r}"
            entry["after"] = {"snapshots": [s for s in snapshots if s != snapshot]}
            if snapshot not in snapshots:
                blockers.append(f"{vm.get('name')} has no snapshot named {snapshot!r}")
            warnings.append("removing a snapshot cannot be undone")
        elif step.action == "vm.power_on":
            entry["operation"] = "power on"
            entry["after"] = {"power_state": POWERED_ON}
            if vm.get("power_state") == POWERED_ON:
                warnings.append(f"{vm.get('name')} is already powered on")
            blockers.extend(self._pre_snapshot_blockers(ctx, vm, minimum))
        elif step.action == "vm.power_off_graceful":
            entry["operation"] = "guest shutdown"
            entry["after"] = {"power_state": POWERED_OFF}
            if not vm.get("tools_running") and not step.params.get("force"):
                blockers.append(
                    f"{vm.get('name')} has no running VMware Tools, so a guest shutdown "
                    "cannot be requested; params.force is required for a hard power off"
                )
            blockers.extend(self._pre_snapshot_blockers(ctx, vm, minimum))
        elif step.action == "vm.resize":
            cpu, memory = step.params.get("cpu"), step.params.get("memory_mb")
            if cpu is None and memory is None:
                blockers.append("vm.resize needs params.cpu and/or params.memory_mb")
            entry["operation"] = "reconfigure CPU/memory"
            entry["after"] = {
                "cpu": cpu if cpu is not None else vm.get("cpu"),
                "memory_mb": memory if memory is not None else vm.get("memory_mb"),
            }
            blockers.extend(self._resize_blockers(vm, cpu, memory, self.transport(ctx.device)))
            blockers.extend(self._pre_snapshot_blockers(ctx, vm, minimum))
        elif step.action == "vm.disk_extend":
            size = step.params.get("size_gb")
            disk = self._disk(vm, step.params.get("disk"))
            entry["operation"] = f"extend {disk.get('label')} to {size} GB"
            entry["after"] = {"disk": disk.get("label"), "size_gb": size}
            entry["no_snapshot"] = "a disk extend never takes a pre-change snapshot"
            if snapshots:
                blockers.append(
                    f"{vm.get('name')} has snapshots ({', '.join(str(s) for s in snapshots)}); "
                    "extending a disk with a snapshot present corrupts the chain — "
                    "consolidate first"
                )
            if size is None:
                blockers.append("vm.disk_extend needs params.size_gb")
            elif disk.get("size_gb") is not None and float(size) <= float(disk["size_gb"]):
                blockers.append(
                    f"{disk.get('label')} is already {disk['size_gb']} GB; a virtual disk "
                    "cannot be shrunk"
                )
            warnings.append(
                "a disk extend cannot be rolled back; the guest still has to grow the filesystem"
            )
        return entry, warnings, blockers

    def _pre_snapshot_blockers(
        self, ctx: ExecutionContext, vm: dict[str, Any], minimum: float
    ) -> list[str]:
        space = self._snapshot_space_blocker(ctx, vm, minimum)
        return [f"pre-change snapshot: {space}"] if space else []

    @staticmethod
    def _resize_blockers(
        vm: dict[str, Any], cpu: Any, memory: Any, transport: EsxiTransport | None = None
    ) -> list[str]:
        if vm.get("power_state") != POWERED_ON:
            return []
        if getattr(transport, "name", "") == "ssh":
            # The free licence resizes by rewriting the .vmx and reloading,
            # which needs the VM powered off (VMware KB 1026043); a reload
            # does not hot-add, so the hot-add flags mean nothing here.
            return [
                f"{vm.get('name')} is powered on and this host has no reconfigure API: "
                "power it off to resize, or use a licensed host for hot-add"
            ]
        blockers = []
        if cpu is not None and not vm.get("hot_add_cpu"):
            blockers.append(
                f"{vm.get('name')} is powered on and has no CPU hot-add; power it off to resize"
            )
        if memory is not None and not vm.get("hot_add_memory"):
            blockers.append(
                f"{vm.get('name')} is powered on and has no memory hot-add; power it off to resize"
            )
        if cpu is not None and vm.get("hot_add_cpu") and int(cpu) < int(vm.get("cpu") or 0):
            blockers.append("CPUs cannot be removed from a running VM")
        if (
            memory is not None
            and vm.get("hot_add_memory")
            and int(memory) < int(vm.get("memory_mb") or 0)
        ):
            blockers.append("memory cannot be removed from a running VM")
        return blockers

    def _preview_clone(
        self,
        ctx: ExecutionContext,
        step: ChangeStep,
        entry: dict[str, Any],
        warnings: list[str],
        blockers: list[str],
    ) -> tuple[dict[str, Any], list[str], list[str]]:
        template = str(step.params.get("template", ""))
        new_name = str(step.params.get("name", ""))
        transport = self.transport(ctx.device)
        entry["operation"] = f"clone {template!r} to {new_name!r}"
        entry["before"] = None
        entry["after"] = {"name": new_name, "from": template}
        if not template or not new_name:
            blockers.append("vm.create_from_template needs params.template and params.name")
            return entry, warnings, blockers
        source = transport.vm(ctx, template)
        if source is None:
            blockers.append(f"no template named {template!r} on {ctx.device.name}")
        elif source.get("power_state") == POWERED_ON:
            blockers.append(f"template {template!r} is powered on; clone from a powered-off VM")
        if transport.vm(ctx, new_name) is not None:
            blockers.append(f"a VM named {new_name!r} already exists")
        store = step.params.get("datastore") or (source or {}).get("datastore")
        free = self._datastore_free_gb(ctx, store)
        minimum = self._min_free_gb(step)
        if free is not None and free < minimum:
            blockers.append(f"datastore {store} has {free} GB free, below the {minimum} GB minimum")
        entry["datastore"] = store
        warnings.append("a new VM is not covered by any backup until it is added to one")
        return entry, warnings, blockers

    # -- checks -----------------------------------------------------------
    def _evaluate(self, ctx: ExecutionContext, check: str) -> CheckResult:
        text = " ".join(check.split())
        transport = self.transport(ctx.device)

        match = CHECK_POWER.match(text)
        if match:
            vm = transport.vm(ctx, match["vm"])
            if vm is None:
                return CheckResult(check=check, ok=False, detail="no such VM")
            wanted = POWERED_ON if match["state"].lower() == "on" else POWERED_OFF
            state = vm.get("power_state")
            return CheckResult(check=check, ok=state == wanted, detail=f"power_state={state}")

        match = CHECK_TOOLS.match(text)
        if match:
            vm = transport.vm(ctx, match["vm"])
            if vm is None:
                return CheckResult(check=check, ok=False, detail="no such VM")
            return CheckResult(
                check=check,
                ok=bool(vm.get("tools_running")),
                detail=f"tools={vm.get('tools_status')}",
            )

        match = CHECK_NO_SNAPSHOTS.match(text)
        if match:
            vm = transport.vm(ctx, match["vm"])
            if vm is None:
                return CheckResult(check=check, ok=False, detail="no such VM")
            names = [str(s.get("name")) for s in vm.get("snapshots") or []]
            return CheckResult(
                check=check, ok=not names, detail=", ".join(names) if names else "no snapshots"
            )

        match = CHECK_DATASTORE.match(text)
        if match:
            free = self._datastore_free_gb(ctx, match["name"])
            if free is None:
                return CheckResult(check=check, ok=False, detail="no such datastore")
            return CheckResult(check=check, ok=free >= float(match["gb"]), detail=f"{free} GB free")

        match = CHECK_SETTING.match(text)
        if match:
            key = normalise_setting_key(match["key"])
            current = transport.host_setting_get(ctx, key)
            wanted = match["value"].strip()
            return CheckResult(
                check=check,
                ok=_setting_equals(current, wanted),
                detail=f"{key}={_render_setting(current)}",
            )

        return CheckResult(
            check=check,
            ok=False,
            detail=f"unknown check; this executor understands: {'; '.join(CHECK_GRAMMAR)}",
        )

    def _run_checks(self, ctx: ExecutionContext, checks: list[str]) -> list[CheckResult]:
        results: list[CheckResult] = []
        with self._session(ctx.device):
            for check in checks:
                try:
                    results.append(self._evaluate(ctx, check))
                except Exception as exc:  # noqa: BLE001 - a check never crashes the engine
                    results.append(CheckResult(check=check, ok=False, detail=short_error(exc)))
        return results

    def pre_check(self, ctx: ExecutionContext, checks: list[str]) -> list[CheckResult]:
        return self._run_checks(ctx, checks)

    def post_check(self, ctx: ExecutionContext, checks: list[str]) -> list[CheckResult]:
        return self._run_checks(ctx, checks)

    # -- apply ------------------------------------------------------------
    def apply(self, ctx: ExecutionContext, step: ChangeStep) -> StepResult:
        started = datetime.now(UTC)
        output: dict[str, Any] = {
            "action": step.action,
            "device": ctx.device.name,
            "transport": self.transport(ctx.device).name,
        }
        try:
            if ctx.frozen:
                raise EsxiError("the platform is frozen (break-glass); no writes")
            if ctx.dry_run:
                raise EsxiError("apply() called with a dry-run context")
            if step.action not in ACTIONS:
                raise EsxiError(f"{step.action} is not an ESXi action this executor implements")
            with self._session(ctx.device):
                self._apply(ctx, step, output)
            return StepResult(
                step=step, ok=True, output=output, started_at=started, finished_at=datetime.now(UTC)
            )
        except Exception as exc:  # noqa: BLE001 - a failed step is a result, not a crash
            log.warning("esxi step %s failed: %s", step.action, short_error(exc))
            return StepResult(
                step=step,
                ok=False,
                output=output,
                error=short_error(exc),
                started_at=started,
                finished_at=datetime.now(UTC),
            )

    def _apply(self, ctx: ExecutionContext, step: ChangeStep, output: dict[str, Any]) -> None:
        transport = self.transport(ctx.device)
        action = step.action

        if action == "esxi.log_bundle":
            output.update(transport.log_bundle(ctx))
            output["rollback"] = "none: collecting a bundle changes nothing"
            return

        if action == "esxi.host_setting":
            key = normalise_setting_key(step.params.get("key", ""))
            if not key:
                raise EsxiError("esxi.host_setting needs params.key")
            value = step.params.get("value")
            # The backup comes first: a host setting that locks us out has to
            # be recoverable from the same bundle the collector commits.
            output["backup_ref"] = {
                **transport.backup_host_config(ctx),
                "plan_id": ctx.plan_id,
                "device": ctx.device.name,
            }
            output["key"] = key
            previous, everything = self._setting_before(transport, ctx, key, step.params)
            output["previous"] = previous
            if everything is not previous:
                output["previous_all"] = everything
            output["applied"] = transport.host_setting_set(ctx, key, value, step.params)
            output["rollback"] = "restore the previous value"
            return

        if action == "vm.create_from_template":
            template = self._vm(ctx, str(step.params.get("template", "")))
            new_name = safe_name(step.params.get("name"), "VM name")
            # The same refusal the preview makes, repeated here: a dry run and
            # an apply are separate moments, and a clone that lands on top of
            # an existing VM is a rollback that deletes somebody else's files.
            if transport.vm(ctx, new_name) is not None:
                raise EsxiError(f"a VM named {new_name!r} already exists on {ctx.device.name}")
            output["vm"] = new_name

            def record(what: dict[str, Any]) -> None:
                # Written before the copy, so a clone that dies half way still
                # tells the rollback exactly which directory it created.
                output["created"] = {**(output.get("created") or {}), **public(what)}

            record({"name": new_name, "from": template.get("name")})
            created = transport.clone_from_template(
                ctx, template, new_name, step.params.get("datastore"), record
            )
            record(created)
            output["rollback"] = "destroy the clone"
            return

        vm = self._vm(ctx, str(step.params.get("vm") or step.params.get("name") or ""))
        output["vm"] = vm.get("name")
        output["before"] = _vm_summary(vm)
        minimum = self._min_free_gb(step)

        if action == "vm.snapshot":
            snapshot = str(step.params.get("snapshot_name") or self.snapshot_name(ctx))
            space = self._snapshot_space_blocker(ctx, vm, minimum)
            if space:
                raise EsxiError(space)
            transport.snapshot_create(
                ctx, vm, snapshot, str(step.params.get("description", f"plan {ctx.plan_id}"))
            )
            output["snapshot"] = snapshot
            output["rollback"] = "remove the snapshot that was created"
            return

        if action == "vm.snapshot_remove":
            snapshot = str(step.params.get("snapshot_name") or self.snapshot_name(ctx))
            removed = next(
                (s for s in vm.get("snapshots") or [] if s.get("name") == snapshot), None
            )
            if removed is None:
                raise EsxiError(f"{vm.get('name')} has no snapshot named {snapshot!r}")
            transport.snapshot_remove(ctx, vm, snapshot)
            output["snapshot"] = snapshot
            output["removed"] = public(removed)
            output["rollback"] = "none: a removed snapshot cannot be restored"
            return

        if action == "vm.disk_extend":
            snapshots = [str(s.get("name")) for s in vm.get("snapshots") or []]
            if snapshots:
                raise EsxiError(
                    f"{vm.get('name')} has snapshots ({', '.join(snapshots)}); a disk extend "
                    "with a snapshot present corrupts the chain"
                )
            size = step.params.get("size_gb")
            if size is None:
                raise EsxiError("vm.disk_extend needs params.size_gb")
            disk = self._disk(vm, step.params.get("disk"))
            if disk.get("size_gb") is not None and float(size) <= float(disk["size_gb"]):
                raise EsxiError(
                    f"{disk.get('label')} is already {disk['size_gb']} GB; a virtual disk "
                    "cannot be shrunk"
                )
            output["disk"] = {"label": disk.get("label"), "size_gb": disk.get("size_gb")}
            transport.disk_extend(ctx, vm, disk, float(size))
            output["applied"] = {"disk": disk.get("label"), "size_gb": float(size)}
            output["rollback"] = "none: a virtual disk cannot be shrunk"
            return

        # Refusals that do not depend on the snapshot are made *before* it is
        # taken: a step that snapshots and then refuses has left an orphaned
        # infra-<plan_id> on the datastore for nothing.
        if action == "vm.resize":
            cpu, memory = step.params.get("cpu"), step.params.get("memory_mb")
            if cpu is None and memory is None:
                raise EsxiError("vm.resize needs params.cpu and/or params.memory_mb")
            refusals = self._resize_blockers(vm, cpu, memory, transport)
            if refusals:
                raise EsxiError(refusals[0])
        if (
            action == "vm.power_off_graceful"
            and not vm.get("tools_running")
            and not step.params.get("force")
        ):
            raise EsxiError(
                "VMware Tools is not running, so no guest shutdown can be requested; "
                "params.force is required for a hard power off"
            )

        # Everything that follows changes a running VM: snapshot it first.
        snapshot = self.snapshot_name(ctx)
        space = self._snapshot_space_blocker(ctx, vm, minimum)
        if space:
            raise EsxiError(f"pre-change snapshot: {space}")
        transport.snapshot_create(ctx, vm, snapshot, f"pre-change snapshot for plan {ctx.plan_id}")
        output["pre_snapshot"] = snapshot
        output["rollback"] = "revert to the pre-change snapshot and restore the power state"
        output["cleanup"] = {
            "action": "vm.snapshot_remove",
            "vm": vm.get("name"),
            "params": {"vm": vm.get("name"), "snapshot_name": snapshot},
            "why": "remove the pre-change snapshot once the plan has verified",
        }
        # Re-read so the snapshot the rollback needs carries its handle/id.
        vm = self._vm(ctx, str(vm.get("name")))

        if action == "vm.power_on":
            transport.power_on(ctx, vm)
            output["applied"] = {"power_state": POWERED_ON}
            return

        if action == "vm.power_off_graceful":
            output["applied"] = self._graceful_off(ctx, step, vm, transport)
            return

        if action == "vm.resize":
            cpu, memory = step.params.get("cpu"), step.params.get("memory_mb")
            if cpu is None and memory is None:
                raise EsxiError("vm.resize needs params.cpu and/or params.memory_mb")
            blockers = self._resize_blockers(vm, cpu, memory, transport)
            if blockers:
                raise EsxiError(blockers[0])
            transport.reconfigure(
                ctx,
                vm,
                int(cpu) if cpu is not None else None,
                int(memory) if memory is not None else None,
            )
            output["applied"] = {"cpu": cpu, "memory_mb": memory}
            return

        raise EsxiError(f"{action} reached apply without an implementation")  # pragma: no cover

    def _graceful_off(
        self,
        ctx: ExecutionContext,
        step: ChangeStep,
        vm: dict[str, Any],
        transport: EsxiTransport,
    ) -> dict[str, Any]:
        """Ask the guest to shut down, wait, and refuse a hard off without `force`."""
        timeout = float(step.params.get("timeout_seconds", DEFAULT_SHUTDOWN_TIMEOUT))
        if vm.get("tools_running"):
            transport.shutdown_guest(ctx, vm)
            deadline = self.monotonic() + timeout
            # One `power.getstate` per poll, not a whole VM read: the full read
            # is seven `vim-cmd` calls, sixty times over during a shutdown.
            while self.monotonic() < deadline:
                if transport.power_state(ctx, vm) == POWERED_OFF:
                    return {"power_state": POWERED_OFF, "via": "guest shutdown"}
                self.sleep(SHUTDOWN_POLL_SECONDS)
            reason = f"the guest did not shut down within {timeout:g}s"
        else:
            reason = "VMware Tools is not running, so no guest shutdown can be requested"
        if not step.params.get("force"):
            raise EsxiError(f"{reason}; params.force is required for a hard power off")
        transport.power_off(ctx, vm)
        return {
            "power_state": POWERED_OFF,
            "via": "hard power off (params.force)",
            "reason": reason,
        }

    # -- rollback ---------------------------------------------------------
    @staticmethod
    def partially_applied(result: StepResult) -> bool:
        """Whether a *failed* step left something behind that must be undone.

        A step that took its pre-change snapshot and then failed part-way — the
        vmx was rewritten but the reload failed, the power-on task errored — is
        not a no-op, and its snapshot is the only way back. Nor is a clone whose
        `vmkfstools -i` had already copied tens of gigabytes before the register
        failed: the directory it created is recorded before the copy starts, and
        that is what makes it recoverable instead of an orphan filling the
        datastore. The engine may hand such a step to `rollback` or not; either
        way it is handled here.
        """
        created = result.output.get("created") or {}
        return bool(result.output.get("pre_snapshot") or created.get("dir"))

    def rollback(self, ctx: ExecutionContext, applied: list[StepResult]) -> list[StepResult]:
        undone: list[StepResult] = []
        with self._session(ctx.device):
            for result in reversed(applied):
                if not result.ok and not self.partially_applied(result):
                    continue
                undone.append(self._undo(ctx, result))
        return undone

    def _undo(self, ctx: ExecutionContext, result: StepResult) -> StepResult:
        started = datetime.now(UTC)
        output: dict[str, Any] = {
            "action": result.step.action,
            "device": ctx.device.name,
            "undo_of": result.step.action,
            "vm": result.output.get("vm"),
        }
        error: str | None = None
        try:
            transport = self.transport(ctx.device)
            action = result.step.action

            if action == "esxi.log_bundle":
                output["undo"] = "nothing to undo: a support bundle changes nothing"
            elif action == "esxi.host_setting":
                key = result.output.get("key")
                previous = result.output.get("previous")
                output["backup_ref"] = result.output.get("backup_ref")
                if key is None:
                    raise EsxiError("no captured host setting to restore")
                if key == CDP_KEY and previous is None:
                    raise EsxiError(
                        "no previous CDP mode was captured for "
                        f"{result.step.params.get('vswitch', DEFAULT_VSWITCH)}; "
                        "set it back by hand rather than guessing a default"
                    )
                transport.host_setting_set(ctx, str(key), previous, result.step.params)
                output["undo"] = f"restored host setting {key}"
                output["restored"] = previous
            elif action == "vm.create_from_template":
                created = result.output.get("created") or {}
                name = created.get("name") or result.output.get("vm")
                directory = created.get("dir")
                if not directory:
                    raise EsxiError(
                        "no directory was recorded for this clone, so there is nothing "
                        "this rollback may safely delete"
                    )
                registered = transport.vm(ctx, str(name)) if name else None
                # Only ever the directory this step created: never one found by
                # looking up whatever VM currently answers to that name.
                target = {**(registered or {}), "name": name, "dir": directory}
                if created.get("vmid") and not target.get("vmid"):
                    target["vmid"] = created["vmid"]
                transport.destroy_vm(ctx, target)
                output["undo"] = f"destroyed the clone {name!r}"
                output["removed_directory"] = directory
            elif action == "vm.snapshot":
                snapshot = result.output.get("snapshot")
                vm = self._vm(ctx, str(result.output.get("vm")))
                transport.snapshot_remove(ctx, vm, str(snapshot))
                output["undo"] = f"removed the snapshot {snapshot!r} that was created"
            elif action == "vm.snapshot_remove":
                output["removed"] = result.output.get("removed")
                raise EsxiError(
                    f"a removed snapshot ({result.output.get('snapshot')!r}) cannot be restored; "
                    "restore the VM from a backup if its state is wrong"
                )
            elif action == "vm.disk_extend":
                output["disk"] = result.output.get("disk")
                raise EsxiError(
                    "a virtual disk cannot be shrunk; the extend stands and the guest "
                    "filesystem has to be reviewed by hand"
                )
            elif action in POWER_ACTIONS:
                output.update(self._undo_power(ctx, result, transport))
            else:
                output.update(self._revert_to_pre_snapshot(ctx, result, transport))
        except Exception as exc:  # noqa: BLE001 - a failed rollback pages the owner
            error = short_error(exc)
        return StepResult(
            step=result.step,
            ok=error is None,
            output=output,
            error=error,
            started_at=started,
            finished_at=datetime.now(UTC),
        )

    def _undo_power(
        self, ctx: ExecutionContext, result: StepResult, transport: EsxiTransport
    ) -> dict[str, Any]:
        """Undo a power step with the *inverse power operation*, not a revert.

        The pre-change snapshot of a running VM is crash-consistent. Reverting
        to it to undo a clean shutdown boots the guest from a crash image —
        journal replay, database recovery — and reverting to undo a power-on
        throws away everything the guest wrote since it booted. The honest
        inverse of "powered it on" is "shut it down", and of "shut it down" is
        "power it on". The snapshot stays as evidence, and the revert is only
        the fallback for when the inverse operation itself fails.
        """
        step = result.step
        wanted = (result.output.get("before") or {}).get("power_state")
        vm = self._vm(ctx, str(result.output.get("vm")))
        undo: dict[str, Any] = {"snapshot": result.output.get("pre_snapshot")}
        try:
            if wanted == POWERED_ON:
                if transport.power_state(ctx, vm) != POWERED_ON:
                    transport.power_on(ctx, vm)
                undo["undo"] = "powered the VM back on, which is where it was"
            elif wanted == POWERED_OFF:
                timeout = float(step.params.get("timeout_seconds", DEFAULT_SHUTDOWN_TIMEOUT))
                undo.update(self._power_off_for_rollback(ctx, vm, transport, timeout))
            else:
                raise EsxiError(f"no power state was recorded to go back to (was {wanted!r})")
        except EsxiError as exc:
            # The inverse failed; the snapshot is what is left.
            undo["inverse_failed"] = short_error(exc)
            undo.update(self._revert_to_pre_snapshot(ctx, result, transport))
            return undo
        undo["power_state"] = transport.power_state(ctx, vm)
        undo["snapshot_left_in_place"] = bool(result.output.get("pre_snapshot"))
        return undo

    def _power_off_for_rollback(
        self,
        ctx: ExecutionContext,
        vm: dict[str, Any],
        transport: EsxiTransport,
        timeout: float,
    ) -> dict[str, Any]:
        """Put a VM that had been off back to off: guest shutdown, then hard."""
        if transport.power_state(ctx, vm) != POWERED_ON:
            return {"undo": "the VM was already off, which is where it was"}
        if vm.get("tools_running"):
            transport.shutdown_guest(ctx, vm)
            deadline = self.monotonic() + timeout
            while self.monotonic() < deadline:
                if transport.power_state(ctx, vm) == POWERED_OFF:
                    return {"undo": "shut the guest down, which is where it was"}
                self.sleep(SHUTDOWN_POLL_SECONDS)
        transport.power_off(ctx, vm)
        return {
            "undo": "powered the VM off, which is where it was",
            "hard": "the guest did not stop in time, or has no running Tools",
        }

    def _revert_to_pre_snapshot(
        self, ctx: ExecutionContext, result: StepResult, transport: EsxiTransport
    ) -> dict[str, Any]:
        """Revert to `infra-<plan_id>` and put the power state back.

        The snapshot itself is left in place: it is the only evidence of the
        state the VM was in, and the cleanup step the successful path records
        is what removes one.
        """
        snapshot = result.output.get("pre_snapshot")
        if not snapshot:
            raise EsxiError("no pre-change snapshot was recorded for this step")
        vm = self._vm(ctx, str(result.output.get("vm")))
        transport.snapshot_revert(ctx, vm, str(snapshot))
        undo: dict[str, Any] = {"undo": f"reverted to {snapshot!r}", "snapshot": snapshot}
        wanted = (result.output.get("before") or {}).get("power_state")
        current = transport.vm(ctx, str(vm.get("name"))) or {}
        if wanted == POWERED_ON and current.get("power_state") != POWERED_ON:
            transport.power_on(ctx, current or vm)
            undo["power_state"] = POWERED_ON
        elif wanted == POWERED_OFF and current.get("power_state") == POWERED_ON:
            transport.power_off(ctx, current or vm)
            undo["power_state"] = POWERED_OFF
        else:
            undo["power_state"] = current.get("power_state")
        undo["snapshot_left_in_place"] = True
        return undo


def _vm_summary(vm: dict[str, Any]) -> dict[str, Any]:
    """The observable state a rollback and a diff care about. Secret-free."""
    return {
        "name": vm.get("name"),
        "power_state": vm.get("power_state"),
        "cpu": vm.get("cpu"),
        "memory_mb": vm.get("memory_mb"),
        "tools_running": vm.get("tools_running"),
        "datastore": vm.get("datastore"),
        "snapshots": [str(s.get("name")) for s in vm.get("snapshots") or []],
        "disks": [
            {"label": d.get("label"), "size_gb": d.get("size_gb")} for d in vm.get("disks") or []
        ],
    }


def _render_setting(value: Any) -> str:
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    if isinstance(value, dict):
        return ",".join(f"{k}={v}" for k, v in sorted(value.items()))
    return str(value)


def _setting_equals(current: Any, wanted: str) -> bool:
    """Compare a host setting to the check's text, list- and dict-aware."""
    wanted = wanted.strip().strip("'\"")
    if isinstance(current, list):
        return [str(v) for v in current] == [w.strip() for w in wanted.split(",") if w.strip()]
    if isinstance(current, dict):
        values = {str(v) for v in current.values()}
        return bool(values) and values == {wanted}
    if isinstance(current, bool):
        return str(current).lower() == wanted.lower() or str(int(current)) == wanted
    return str(current) == wanted
