"""Backup freshness per VM. The platform does not take the backups; it watches them.

`docs/architecture.md` calls this out as a known gap: free-license ESXi has no
VADP, so a Veeam-class tool cannot touch these VMs, and whatever the owner
chose instead - ghettoVCB to an NFS target, or restic/borg inside the important
guests - is a thing that fails silently at 2am for six weeks. This collector
turns "I think backups are running" into a timestamp per VM and an alert when
that timestamp stops moving.

Two sources, both read-only:

**ghettoVCB on the ESXi host.** Over SSH, when the credential carries a key
(the same gate as the host-config backup in the `esxi` collector: ESXi gives a
shell only to Administrator-role users, so a password alone is not an SSH
credential). Three commands: list the log directory, read the newest logs, and
`du` the backup tree for restore points and sizes.

**An agent inside a guest.** restic, borg, or anything else that can write a
file: the contract is a JSON document at ``/var/lib/infra-backup/status.json``
inside the guest, published either to ``<backup root>/agent-status/<vm>.json``
on the shared target or to a directory mounted on mgmt-01
(``INFRA_DR_BACKUP_STATUS_DIR``). The reader takes an explicit list of fields
and ignores everything else, so a repository URL with a password in it - which
is exactly what a restic config looks like - cannot be copied into a snapshot
that the model may later read. The full contract is in
``docs/runbooks/dr-mgmt-01.md``.

Schedules come from the VM's own annotation, the same place the `esxi`
collector reads `expect:off` from: a VM tagged ``backup:daily`` is expected to
have a backup less than 26 hours old, ``backup:weekly`` less than eight days,
``backup:none`` is not expected to have one at all. A VM with no tag is
reported but not alerted on, because guessing that every VM needs a nightly
backup produces an alert nobody can act on.

This collector is deliberately NOT in ``COLLECTORS``: that registry holds one
collector per :class:`DeviceKind` and ESXi already has one. It runs on its own
hourly job (`infra_agent.scheduler.run_backups_once`).
"""

from __future__ import annotations

import json
import logging
import posixpath
import re
import shlex
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from infra_agent.collectors.base import Collector
from infra_agent.config import Settings, get_settings
from infra_agent.models.common import Credential, DeviceKind, SeedDevice
from infra_agent.monitoring import metrics
from infra_agent.store.snapshots import FileSnapshotStore

log = logging.getLogger(__name__)

#: (command) -> stdout. Injectable, so every parser below is tested offline.
Runner = Callable[[str], str]

AGENT_STATUS_DIR = "agent-status"
LOCAL_STATUS_GLOB = "*.json"
#: Never read more than this many logs or status files in one run.
MAX_LOGS = 2
MAX_STATUS_FILES = 100
#: Backups older than this are not worth reporting a size for; the alert has
#: already fired and the number only makes the digest longer.
MAX_RESTORE_POINTS_PER_VM = 50

SCHEDULE_DAILY = "daily"
SCHEDULE_WEEKLY = "weekly"
SCHEDULE_NONE = "none"
SCHEDULE_UNSPECIFIED = "unspecified"
SCHEDULE_TAGS = {
    "backup:daily": SCHEDULE_DAILY,
    "backup:weekly": SCHEDULE_WEEKLY,
    "backup:none": SCHEDULE_NONE,
}

#: Fields copied out of a guest's status.json. Everything else - including any
#: repository URL, which is where restic keeps credentials - is dropped.
AGENT_FIELDS = ("tool", "status", "schedule", "snapshots", "error")

#: `2026-09-07 02:00:01 -- info: ...`
LOG_LINE = re.compile(r"^(?P<at>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+--\s+(?P<body>.*)$")
SUCCESS = re.compile(r"Successfully completed backup for (?P<vm>.+?)!")
FAILURE = re.compile(
    r"(?:Unable to backup|Failed to backup|ERROR: Unable to (?:backup|create snapshot) for)\s+"
    r"(?P<vm>[^\s!]+)"
)
INITIATE = re.compile(r"Initiate backup for (?P<vm>.+?)\s*$")
DURATION = re.compile(r"Backup Duration:\s+(?P<value>[0-9.]+)\s+(?P<unit>Minutes|Seconds)")
FINAL_STATUS = re.compile(r"Final status:\s*(?P<text>.+?)\s*#*\s*$")
#: ghettoVCB restore points are `<vm>-<YYYY-MM-DD_HH-MM-SS>`.
RESTORE_POINT = re.compile(r"^(?P<vm>.+)-(?P<stamp>\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})$")
LOG_NAME = re.compile(r"^ghettoVCB.*\.log$", re.IGNORECASE)


def parse_log_time(text: str) -> datetime | None:
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def parse_restore_point(name: str) -> tuple[str, datetime] | None:
    match = RESTORE_POINT.match(name)
    if match is None:
        return None
    try:
        when = datetime.strptime(match.group("stamp"), "%Y-%m-%d_%H-%M-%S").replace(tzinfo=UTC)
    except ValueError:
        return None
    return match.group("vm"), when


def parse_ghettovcb_log(text: str) -> dict[str, Any]:
    """One ghettoVCB run: per-VM outcome, duration and the run's final status.

    The log is the only place that distinguishes "no backup was attempted" from
    "a backup was attempted and failed", which is the difference between a
    misconfigured schedule and a full datastore.
    """
    vms: dict[str, dict[str, Any]] = {}
    started: datetime | None = None
    finished: datetime | None = None
    final_status: str | None = None
    current: str | None = None

    for raw in text.splitlines():
        match = LOG_LINE.match(raw.strip())
        if match is None:
            continue
        when = parse_log_time(match.group("at"))
        body = match.group("body")
        if when is not None:
            started = started or when
            finished = when

        initiate = INITIATE.search(body)
        if initiate:
            current = initiate.group("vm").strip()
            vms.setdefault(current, {"vm": current, "status": "started"})
            vms[current]["started_at"] = when
            continue

        success = SUCCESS.search(body)
        if success:
            name = success.group("vm").strip()
            row = vms.setdefault(name, {"vm": name})
            row.update({"status": "ok", "finished_at": when})
            current = name
            continue

        failure = FAILURE.search(body)
        if failure:
            name = failure.group("vm").strip()
            row = vms.setdefault(name, {"vm": name})
            row.update({"status": "failed", "finished_at": when, "error": body.strip()[:200]})
            current = name
            continue

        duration = DURATION.search(body)
        if duration and current:
            value = float(duration.group("value"))
            seconds = value * 60 if duration.group("unit") == "Minutes" else value
            vms[current]["duration_seconds"] = round(seconds, 1)
            continue

        final = FINAL_STATUS.search(body)
        if final:
            final_status = final.group("text").strip().rstrip("#").strip()

    return {
        "started_at": started,
        "finished_at": finished,
        "final_status": final_status,
        "vms": [vms[name] for name in sorted(vms)],
    }


def parse_du(text: str) -> list[dict[str, Any]]:
    """`du -sk <root>/*/*` output into restore points with sizes.

    Sizes are in kibibytes, which is what `du -sk` reports on ESXi's busybox as
    well as on GNU coreutils, so the same parser serves a lab and a host.
    """
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2 or not parts[0].isdigit():
            continue
        size_kb, path = int(parts[0]), parts[1].strip()
        parsed = parse_restore_point(posixpath.basename(path.rstrip("/")))
        if parsed is None:
            continue
        vm, when = parsed
        rows.append({"vm": vm, "at": when, "bytes": size_kb * 1024, "path": path})
    return rows


def parse_agent_status(text: str, *, name: str | None = None) -> dict[str, Any] | None:
    """One guest's `/var/lib/infra-backup/status.json`, field by allowed field.

    Anything not in :data:`AGENT_FIELDS` is dropped rather than copied, because
    a restic or borg status file naturally contains a repository URL and those
    carry passwords. The collector's output is a snapshot the model may read;
    an allowlist is the only shape of this function that is safe.
    """
    try:
        payload = json.loads(text)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    vm = str(payload.get("host") or payload.get("vm") or name or "").strip()
    if not vm:
        return None
    row: dict[str, Any] = {"vm": vm, "method": "agent"}
    for field in AGENT_FIELDS:
        value = payload.get(field)
        if isinstance(value, (str, int, float, bool)):
            row[field] = value
    row["last_success_at"] = _iso_or_none(payload.get("last_success"))
    row["last_attempt_at"] = _iso_or_none(payload.get("last_attempt"))
    size = payload.get("size_bytes")
    row["bytes"] = int(size) if isinstance(size, (int, float)) else None
    if row.get("status") is None:
        row["status"] = "ok" if row["last_success_at"] else "unknown"
    return row


def _iso_or_none(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def schedule_of(annotation: Any) -> str:
    """`backup:daily` / `backup:weekly` / `backup:none` out of a VM annotation."""
    text = f" {str(annotation or '').lower()} ".replace("\n", " ")
    for tag, schedule in SCHEDULE_TAGS.items():
        if tag in text:
            return schedule
    return SCHEDULE_UNSPECIFIED


def backup_root(device: SeedDevice, settings: Settings) -> str:
    """The device tag wins over the setting; a per-host NFS mount is normal."""
    for tag in device.tags:
        if tag.startswith("backup-root:"):
            value = tag.split(":", 1)[1].strip()
            if value:
                return value
    return settings.dr_backup_root


class BackupsCollector(Collector):
    """ghettoVCB and agent-based backup freshness for one ESXi host."""

    kind = DeviceKind.esxi
    name = "backups"
    interval_seconds = 3600

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        snapshots: FileSnapshotStore | None = None,
        runner_factory: Callable[[SeedDevice, Credential], Runner] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._snapshots = snapshots
        self._runner_factory = runner_factory
        self._now = now or (lambda: datetime.now(UTC))

    # -- plumbing -----------------------------------------------------------
    @property
    def snapshots(self) -> FileSnapshotStore:
        if self._snapshots is None:
            self._snapshots = FileSnapshotStore(self.settings.snapshot_dir)
        return self._snapshots

    def runner(self, device: SeedDevice, cred: Credential) -> Runner:
        if self._runner_factory is not None:
            return self._runner_factory(device, cred)
        return SshRunner(device, cred)

    def schedules(self, device: SeedDevice) -> dict[str, str]:
        """VM name -> backup schedule, from the newest `esxi` snapshot."""
        snapshot = self.snapshots.latest(device.name, "esxi")
        if snapshot is None:
            return {}
        vms = snapshot.data.get("vms")
        rows: dict[str, str] = {}
        for vm in vms if isinstance(vms, list) else []:
            if not isinstance(vm, dict):
                continue
            name = vm.get("name")
            if not name:
                continue
            if vm.get("template"):
                rows[str(name)] = SCHEDULE_NONE
                continue
            rows[str(name)] = schedule_of(vm.get("annotation"))
        return rows

    # -- collection ---------------------------------------------------------
    def collect(self, device: SeedDevice, cred: Credential) -> dict[str, Any]:
        root = backup_root(device, self.settings)
        data: dict[str, Any] = {
            "root": root,
            "checked_at": self._now(),
            "sources": [],
            "job": {},
            "vms": [],
            "errors": {},
        }
        rows: dict[str, dict[str, Any]] = {}

        local = self._local_agent_status()
        if local:
            data["sources"].append("agent-local")
            _merge(rows, local)

        if not cred.ssh_key_path and self._runner_factory is None:
            data["errors"]["ssh"] = (
                "no SSH key in the credential; ghettoVCB logs on the host cannot be read "
                "(agent status files, if any, still are)"
            )
        else:
            run = self.runner(device, cred)
            data["job"] = self._job(run, root, data["errors"])
            _merge(rows, self._from_logs(data["job"]))
            _merge(rows, self._from_datastore(run, root, data["errors"]))
            _merge(rows, self._remote_agent_status(run, root, data["errors"]))
            if data["job"] or rows:
                data["sources"].append("ghettovcb")

        schedules = self.schedules(device)
        for name, row in rows.items():
            row["schedule"] = schedules.get(name, SCHEDULE_UNSPECIFIED)
        data["vms"] = [rows[name] for name in sorted(rows)]
        data["expected"] = sorted(
            name
            for name, schedule in schedules.items()
            if schedule in (SCHEDULE_DAILY, SCHEDULE_WEEKLY)
        )
        data["unprotected"] = sorted(set(data["expected"]) - set(rows))
        self.publish_metrics(device.name, data)
        return data

    # -- ghettoVCB ----------------------------------------------------------
    def log_dir(self, root: str) -> str:
        return posixpath.join(root, "ghettoVCB-logs")

    def _job(self, run: Runner, root: str, errors: dict[str, str]) -> dict[str, Any]:
        directory = self.log_dir(root)
        try:
            listing = run(f"ls -1 {shlex.quote(directory)}")
        except Exception as exc:  # noqa: BLE001 - a missing log dir is a finding, not a crash
            errors["logs"] = f"{type(exc).__name__}: {exc}"
            return {}
        names = sorted(
            (line.strip() for line in listing.splitlines() if LOG_NAME.match(line.strip())),
            reverse=True,
        )[:MAX_LOGS]
        if not names:
            errors["logs"] = f"no ghettoVCB logs in {directory}"
            return {}
        runs: list[dict[str, Any]] = []
        for name in names:
            try:
                text = run(f"cat {shlex.quote(posixpath.join(directory, name))}")
            except Exception as exc:  # noqa: BLE001
                errors[f"log:{name}"] = f"{type(exc).__name__}: {exc}"
                continue
            parsed = parse_ghettovcb_log(text)
            parsed["log"] = name
            runs.append(parsed)
        if not runs:
            return {}
        newest = runs[0]
        failed = [vm["vm"] for vm in newest["vms"] if vm.get("status") == "failed"]
        return {
            "log": newest["log"],
            "started_at": newest["started_at"],
            "finished_at": newest["finished_at"],
            "final_status": newest["final_status"],
            "ok": not failed,
            "failed_vms": failed,
            "runs": runs,
        }

    @staticmethod
    def _from_logs(job: dict[str, Any]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for one in reversed(job.get("runs") or []):  # oldest first, so newest wins the merge
            for vm in one.get("vms") or []:
                row: dict[str, Any] = {
                    "vm": vm["vm"],
                    "method": "ghettovcb",
                    "status": vm.get("status"),
                    "duration_seconds": vm.get("duration_seconds"),
                    "error": vm.get("error"),
                }
                if vm.get("status") == "ok":
                    row["last_success_at"] = vm.get("finished_at")
                row["last_attempt_at"] = vm.get("finished_at") or vm.get("started_at")
                rows.append(row)
        return rows

    def _from_datastore(
        self, run: Runner, root: str, errors: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Restore points actually on disk: the ground truth behind the log."""
        try:
            output = run(f"du -sk {shlex.quote(root)}/*/* 2>/dev/null")
        except Exception as exc:  # noqa: BLE001
            errors["datastore"] = f"{type(exc).__name__}: {exc}"
            return []
        by_vm: dict[str, list[dict[str, Any]]] = {}
        for point in parse_du(output):
            by_vm.setdefault(point["vm"], []).append(point)
        rows = []
        for vm, points in by_vm.items():
            points.sort(key=lambda p: p["at"], reverse=True)
            newest = points[0]
            rows.append(
                {
                    "vm": vm,
                    "method": "ghettovcb",
                    "last_success_at": newest["at"],
                    "bytes": newest["bytes"],
                    "restore_points": min(len(points), MAX_RESTORE_POINTS_PER_VM),
                    "oldest_restore_point_at": points[-1]["at"],
                }
            )
        return rows

    # -- agent status -------------------------------------------------------
    def _remote_agent_status(
        self, run: Runner, root: str, errors: dict[str, str]
    ) -> list[dict[str, Any]]:
        directory = posixpath.join(root, AGENT_STATUS_DIR)
        try:
            listing = run(f"ls -1 {shlex.quote(directory)}")
        except Exception:  # noqa: BLE001 - no agent-status directory is the normal case
            return []
        rows = []
        for name in sorted(listing.split())[:MAX_STATUS_FILES]:
            if not name.endswith(".json"):
                continue
            try:
                text = run(f"cat {shlex.quote(posixpath.join(directory, name))}")
            except Exception as exc:  # noqa: BLE001
                errors[f"agent:{name}"] = f"{type(exc).__name__}: {exc}"
                continue
            row = parse_agent_status(text, name=Path(name).stem)
            if row is None:
                errors[f"agent:{name}"] = "not a status.json document"
                continue
            rows.append(row)
        return rows

    def _local_agent_status(self) -> list[dict[str, Any]]:
        directory = self.settings.dr_backup_status_dir
        if directory is None or not Path(directory).exists():
            return []
        rows = []
        for path in sorted(Path(directory).glob(LOCAL_STATUS_GLOB))[:MAX_STATUS_FILES]:
            try:
                row = parse_agent_status(path.read_text(errors="replace"), name=path.stem)
            except OSError:
                log.warning("could not read %s", path.name)
                continue
            if row is not None:
                rows.append(row)
        return rows

    # -- metrics ------------------------------------------------------------
    def publish_metrics(self, device_name: str, data: dict[str, Any]) -> None:
        job = data.get("job") or {}
        last_run = job.get("finished_at") or job.get("started_at")
        if isinstance(last_run, datetime):
            metrics.BACKUP_JOB_LAST_RUN.labels(device=device_name).set(last_run.timestamp())
        if job:
            metrics.BACKUP_JOB_OK.labels(device=device_name).set(1 if job.get("ok") else 0)
        for row in data.get("vms") or []:
            vm = row.get("vm")
            if not vm:
                continue
            success = row.get("last_success_at")
            if isinstance(success, datetime):
                metrics.BACKUP_LAST_SUCCESS.labels(
                    device=device_name, vm=vm, schedule=row.get("schedule") or SCHEDULE_UNSPECIFIED
                ).set(success.timestamp())
            if isinstance(row.get("bytes"), (int, float)):
                metrics.BACKUP_LAST_SIZE_BYTES.labels(device=device_name, vm=vm).set(
                    float(row["bytes"])
                )
            if isinstance(row.get("restore_points"), int):
                metrics.BACKUP_RESTORE_POINTS.labels(device=device_name, vm=vm).set(
                    row["restore_points"]
                )


def _merge(rows: dict[str, dict[str, Any]], new: list[dict[str, Any]]) -> None:
    """Later sources refine earlier ones; a None never overwrites a value."""
    for row in new:
        name = row.get("vm")
        if not name:
            continue
        target = rows.setdefault(str(name), {"vm": str(name)})
        for key, value in row.items():
            if value is not None:
                target[key] = value


class SshRunner:
    """Read-only SSH command runner for one ESXi host.

    Authenticated by the credential's key, exactly like the host-config backup
    in the `esxi` collector: the password is offered as the key's passphrase
    and never as a login password, so it is never replayed at a shell prompt.
    """

    def __init__(self, device: SeedDevice, cred: Credential, timeout: float = 60.0) -> None:
        self.device = device
        self._cred = cred
        self.timeout = timeout
        self._client: Any = None

    def _connect(self) -> Any:
        import paramiko  # lazy: optional dependency

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict[str, Any] = {
            "hostname": self.device.mgmt_ip,
            "port": 22,  # device.port is the API port; SSH is always 22 on ESXi
            "username": self._cred.username,
            "key_filename": self._cred.ssh_key_path,
            "timeout": 20,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if self._cred.password:
            kwargs["passphrase"] = self._cred.password.get_secret_value()
        client.connect(**kwargs)
        return client

    def __call__(self, command: str) -> str:
        if self._client is None:
            self._client = self._connect()
        _stdin, stdout, stderr = self._client.exec_command(command, timeout=self.timeout)
        out = stdout.read()
        status = getattr(getattr(stdout, "channel", None), "recv_exit_status", lambda: 0)()
        text = out.decode("utf-8", "replace") if isinstance(out, bytes) else str(out)
        if status:
            err = stderr.read()
            detail = err.decode("utf-8", "replace") if isinstance(err, bytes) else str(err)
            raise RuntimeError(f"exited {status}: {detail.strip()[:200]}")
        return text

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
