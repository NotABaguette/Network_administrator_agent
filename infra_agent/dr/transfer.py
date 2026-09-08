"""Shipping bundles to the standby, and pruning what is already there.

Everything that touches the network goes through an injectable `runner`, so
the tests exercise the real argument vectors without an SSH daemon. The
defaults are `rsync` with an `scp` fallback, both forced into batch mode:

* `-o BatchMode=yes` makes SSH fail instead of prompting, so a missing key is
  a loud nightly failure rather than a job hanging until the next one starts;
* no password ever appears in an argument vector, because key auth is the only
  authentication method the runbook allows.

Pruning never removes the newest bundle, whatever the retention window says. A
single stale backup is worth incomparably more than none, and the alert for
"the newest bundle is old" already exists (`DRExportStale`, `StandbyStale`).
"""

from __future__ import annotations

import logging
import re
import shlex
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from infra_agent.dr.errors import DRError
from infra_agent.dr.manifest import CHECKSUM_SUFFIX

log = logging.getLogger(__name__)

BUNDLE_PREFIX = "infra-dr"
BUNDLE_SUFFIX = ".tar.gz"
BUNDLE_GLOB = f"{BUNDLE_PREFIX}-*{BUNDLE_SUFFIX}"
#: infra-dr-<host>-<YYYYmmddTHHMMSSZ>.tar.gz
BUNDLE_RE = re.compile(
    rf"^{re.escape(BUNDLE_PREFIX)}-(?P<host>.+)-(?P<stamp>\d{{8}}T\d{{6}}Z){re.escape(BUNDLE_SUFFIX)}$"
)

SSH_BATCH = ("-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new")


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


#: (argv) -> CommandResult. Never raises for a non-zero exit; callers decide.
Runner = Callable[[Sequence[str]], CommandResult]


def subprocess_runner(argv: Sequence[str], timeout: float = 1800.0) -> CommandResult:
    try:
        proc = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        return CommandResult(tuple(argv), 127, "", str(exc))
    except subprocess.TimeoutExpired:
        return CommandResult(tuple(argv), 124, "", f"{argv[0]} timed out after {timeout:.0f}s")
    return CommandResult(tuple(argv), proc.returncode, proc.stdout or "", proc.stderr or "")


@dataclass(frozen=True)
class Target:
    """Where bundles go: a local directory or an SSH destination."""

    raw: str
    path: str
    host: str | None = None
    user: str | None = None

    @property
    def remote(self) -> bool:
        return self.host is not None

    @property
    def ssh_host(self) -> str:
        if self.host is None:
            raise DRError(f"{self.raw!r} is a local directory, not an SSH target")
        return f"{self.user}@{self.host}" if self.user else self.host

    @property
    def scp_destination(self) -> str:
        return f"{self.ssh_host}:{self.path.rstrip('/')}/"

    def local_path(self) -> Path:
        if self.remote:
            raise DRError(f"{self.raw!r} is an SSH target, not a local directory")
        return Path(self.path).expanduser()

    def describe(self) -> str:
        return f"{self.ssh_host}:{self.path}" if self.remote else self.path


def parse_target(raw: str | Path) -> Target:
    """`ssh://user@host/path`, `user@host:/path` or a local directory."""
    text = str(raw).strip()
    if not text:
        raise DRError("empty DR target")
    if text.startswith("ssh://"):
        parts = urlsplit(text)
        if not parts.hostname:
            raise DRError(f"{text!r} has no host")
        if not parts.path or parts.path == "/":
            raise DRError(f"{text!r} has no path; give the directory bundles land in")
        return Target(raw=text, path=parts.path, host=parts.hostname, user=parts.username)
    if text.startswith(("/", ".", "~")) or Path(text).is_absolute():
        return Target(raw=text, path=text)
    match = re.match(r"^(?:(?P<user>[^@/\s]+)@)?(?P<host>[^:/\s]+):(?P<path>.+)$", text)
    if match:
        return Target(
            raw=text,
            path=match.group("path"),
            host=match.group("host"),
            user=match.group("user"),
        )
    return Target(raw=text, path=text)


def bundle_time(name: str) -> datetime | None:
    """The export time encoded in a bundle's own name, or None if it is not ours."""
    match = BUNDLE_RE.match(Path(name).name)
    if match is None:
        return None
    try:
        return datetime.strptime(match.group("stamp"), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def local_bundles(directory: Path) -> list[Path]:
    """Our bundles in a directory, newest first."""
    if not directory.exists():
        return []
    named = [(bundle_time(p.name), p) for p in directory.glob(BUNDLE_GLOB) if p.is_file()]
    dated = [(when or _mtime(path), path) for when, path in named]
    return [path for _when, path in sorted(dated, key=lambda row: row[0], reverse=True)]


def newest_bundle(directory: Path) -> Path | None:
    found = local_bundles(directory)
    return found[0] if found else None


def _mtime(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)


def push(
    bundle: Path,
    target: Target,
    *,
    runner: Runner | None = None,
    extra_files: Sequence[Path] = (),
) -> CommandResult:
    """Copy the bundle (and its checksum sidecar) to the target.

    rsync first because it resumes a partial transfer over a flaky link; scp
    only when rsync is not installed on one of the two ends.
    """
    run = runner or subprocess_runner
    files = [str(bundle), *(str(p) for p in extra_files if p.exists())]
    if not target.remote:
        raise DRError("push() is for SSH targets; a local target is written in place")
    ssh = " ".join(["ssh", *SSH_BATCH])
    result = run(["rsync", "--archive", "--partial", "-e", ssh, *files, target.scp_destination])
    if result.ok:
        return result
    if result.returncode not in (12, 127):  # 127 no rsync locally, 12 protocol/no rsync remotely
        raise DRError(f"rsync to {target.describe()} failed: {_tail(result.stderr)}")
    log.info("rsync unavailable (exit %d); falling back to scp", result.returncode)
    fallback = run(["scp", "-B", *SSH_BATCH, *files, target.scp_destination])
    if not fallback.ok:
        raise DRError(f"scp to {target.describe()} failed: {_tail(fallback.stderr)}")
    return fallback


def ensure_remote_dir(target: Target, *, runner: Runner | None = None) -> None:
    run = runner or subprocess_runner
    result = run(["ssh", *SSH_BATCH, target.ssh_host, f"mkdir -p {shlex.quote(target.path)}"])
    if not result.ok:
        raise DRError(f"could not create {target.describe()}: {_tail(result.stderr)}")


def list_remote(target: Target, *, runner: Runner | None = None) -> list[str]:
    run = runner or subprocess_runner
    result = run(["ssh", *SSH_BATCH, target.ssh_host, f"ls -1 {shlex.quote(target.path)}"])
    if not result.ok:
        raise DRError(f"could not list {target.describe()}: {_tail(result.stderr)}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _prunable(names: Sequence[str], retention_days: int, now: datetime) -> list[str]:
    """Bundle names older than the window, newest one always kept."""
    dated = [(bundle_time(name), name) for name in names]
    ours = sorted(
        ((when, name) for when, name in dated if when is not None),
        key=lambda row: row[0],
        reverse=True,
    )
    cutoff = now - timedelta(days=retention_days)
    return sorted(name for when, name in ours[1:] if when < cutoff)


def prune_local(directory: Path, retention_days: int, *, now: datetime | None = None) -> list[str]:
    moment = now or datetime.now(UTC)
    names = [p.name for p in directory.glob(BUNDLE_GLOB)] if directory.exists() else []
    removed = []
    for name in _prunable(names, retention_days, moment):
        (directory / name).unlink(missing_ok=True)
        (directory / (name + CHECKSUM_SUFFIX)).unlink(missing_ok=True)
        removed.append(name)
    return removed


def prune_remote(
    target: Target,
    retention_days: int,
    *,
    runner: Runner | None = None,
    now: datetime | None = None,
) -> list[str]:
    """Delete expired bundles on the standby by name.

    Names are computed here and quoted individually rather than handing the
    remote shell a glob or `find -delete`: the standby directory is the only
    off-box copy of the platform, and one mistyped pattern there deletes all of
    it.
    """
    run = runner or subprocess_runner
    moment = now or datetime.now(UTC)
    expired = _prunable(list_remote(target, runner=run), retention_days, moment)
    if not expired:
        return []
    base = target.path.rstrip("/")
    quoted = " ".join(
        shlex.quote(f"{base}/{name}{suffix}")
        for name in expired
        for suffix in ("", CHECKSUM_SUFFIX)
    )
    result = run(["ssh", *SSH_BATCH, target.ssh_host, f"rm -f -- {quoted}"])
    if not result.ok:
        raise DRError(f"could not prune {target.describe()}: {_tail(result.stderr)}")
    return expired


def prune(
    target: Target,
    retention_days: int,
    *,
    runner: Runner | None = None,
    now: datetime | None = None,
) -> list[str]:
    if target.remote:
        return prune_remote(target, retention_days, runner=runner, now=now)
    return prune_local(target.local_path(), retention_days, now=now)


def _tail(text: str, limit: int = 300) -> str:
    cleaned = " ".join(text.split())
    return cleaned[-limit:] if len(cleaned) > limit else cleaned
