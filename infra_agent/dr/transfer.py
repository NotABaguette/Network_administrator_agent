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

The standby account is expected to be **restricted**: its `authorized_keys`
entry forces `rrsync -wo /srv/infra-dr`, so the key can write bundles into one
directory and do nothing else - no shell, no `mkdir`, no `ls`, no `rm`. That
shapes this module: with `INFRA_DR_SSH_RESTRICTED` (the default) the push is
one `rsync` invocation and nothing else, the inbox is created once by hand, and
retention on the standby is the standby's own cron (`deploy/standby/prune.sh`).
Host keys are pinned, not trusted on first use: `StrictHostKeyChecking=yes`
against `~/.ssh/known_hosts` or the file `INFRA_DR_SSH_KNOWN_HOSTS` names.
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

from infra_agent.dr.crypt import AGE_SUFFIX
from infra_agent.dr.errors import DRError
from infra_agent.dr.manifest import CHECKSUM_SUFFIX

log = logging.getLogger(__name__)

BUNDLE_PREFIX = "infra-dr"
BUNDLE_SUFFIX = ".tar.gz"
#: Matches the plain and the age-encrypted spelling, and nothing else in the
#: directory - a `.sha256` sidecar is not a bundle and must never be pruned as
#: if it were one.
BUNDLE_GLOB = f"{BUNDLE_PREFIX}-*{BUNDLE_SUFFIX}*"
#: infra-dr-<host>-<YYYYmmddTHHMMSSZ>.tar.gz[.age]
BUNDLE_RE = re.compile(
    rf"^{re.escape(BUNDLE_PREFIX)}-(?P<host>.+)-(?P<stamp>\d{{8}}T\d{{6}}Z)"
    rf"{re.escape(BUNDLE_SUFFIX)}(?P<enc>{re.escape(AGE_SUFFIX)})?$"
)


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


@dataclass(frozen=True)
class SshPolicy:
    """How this platform is allowed to talk to the standby.

    `restricted` is the default because the README's `authorized_keys` entry is
    a forced `rrsync` command: with it, *every* session runs rsync whatever the
    client asked for, so an `ssh host mkdir -p ...` does not create a directory,
    it starts an rsync server that reads EOF and exits non-zero. Code that
    assumes a shell there fails every single night, which is how a backup
    quietly stops existing.

    Host keys are pinned. `accept-new` on a management VLAN means the first
    nightly push trusts whatever answers at the standby's address.
    """

    known_hosts: Path | None = None
    restricted: bool = True

    @classmethod
    def from_settings(cls, settings: object | None) -> SshPolicy:
        if settings is None:
            return cls()
        known = getattr(settings, "dr_ssh_known_hosts", None)
        return cls(
            known_hosts=Path(known) if known else None,
            restricted=bool(getattr(settings, "dr_ssh_restricted", True)),
        )

    def options(self) -> list[str]:
        opts = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"]
        if self.known_hosts is not None:
            opts += ["-o", f"UserKnownHostsFile={self.known_hosts}"]
        return opts

    def ssh_command(self) -> str:
        """The `-e` argument for rsync: an ssh invocation with our options."""
        return " ".join(shlex.quote(part) for part in ["ssh", *self.options()])

    def require_shell(self, what: str) -> None:
        if self.restricted:
            raise DRError(
                f"{what} needs a shell on the standby, and the DR key is restricted to "
                "rsync (see deploy/standby/README.md). Set INFRA_DR_SSH_RESTRICTED=0 only "
                "if that account really has a shell."
            )


DEFAULT_POLICY = SshPolicy()


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
    """Our bundles in a directory, newest first. Sidecars are not bundles."""
    if not directory.exists():
        return []
    found = [
        path
        for path in directory.glob(BUNDLE_GLOB)
        if path.is_file() and BUNDLE_RE.match(path.name)
    ]
    dated = [(bundle_time(path.name) or _mtime(path), path) for path in found]
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
    policy: SshPolicy | None = None,
) -> CommandResult:
    """Copy the bundle (and its checksum sidecar) to the target.

    `--chmod=F600,D700` because the archive is credential-equivalent: it holds
    the raw device configs and the NetBox database (see
    `infra_agent/dr/crypt.py`). rsync would otherwise carry the sender's mode,
    and a world-readable bundle on the standby is a world-readable copy of
    every SNMP community on the estate.

    scp is the fallback for a standby without rsync - but only when the key is
    not restricted, because a forced `rrsync` command cannot run scp either.
    """
    run = runner or subprocess_runner
    rules = policy or DEFAULT_POLICY
    files = [str(bundle), *(str(p) for p in extra_files if p.exists())]
    if not target.remote:
        raise DRError("push() is for SSH targets; a local target is written in place")
    result = run(
        [
            "rsync",
            "--archive",
            "--partial",
            "--chmod=F600,D700",
            "-e",
            rules.ssh_command(),
            *files,
            target.scp_destination,
        ]
    )
    if result.ok:
        return result
    if rules.restricted or result.returncode not in (12, 127):
        # 127 no rsync locally, 12 protocol/no rsync remotely
        raise DRError(f"rsync to {target.describe()} failed: {_tail(result.stderr)}")
    log.info("rsync unavailable (exit %d); falling back to scp", result.returncode)
    fallback = run(["scp", "-B", *rules.options(), *files, target.scp_destination])
    if not fallback.ok:
        raise DRError(f"scp to {target.describe()} failed: {_tail(fallback.stderr)}")
    return fallback


def ensure_remote_dir(
    target: Target, *, runner: Runner | None = None, policy: SshPolicy | None = None
) -> None:
    """Create the inbox on the standby. Not available with a restricted key.

    With the shipped `authorized_keys` entry the inbox is created once, by
    hand, by whoever set the standby up - which is also the moment its mode is
    set to 0700.
    """
    rules = policy or DEFAULT_POLICY
    rules.require_shell("creating the remote directory")
    run = runner or subprocess_runner
    result = run(["ssh", *rules.options(), target.ssh_host, f"mkdir -p {shlex.quote(target.path)}"])
    if not result.ok:
        raise DRError(f"could not create {target.describe()}: {_tail(result.stderr)}")


def list_remote(
    target: Target, *, runner: Runner | None = None, policy: SshPolicy | None = None
) -> list[str]:
    rules = policy or DEFAULT_POLICY
    rules.require_shell("listing the standby inbox")
    run = runner or subprocess_runner
    result = run(["ssh", *rules.options(), target.ssh_host, f"ls -1 {shlex.quote(target.path)}"])
    if not result.ok:
        raise DRError(f"could not list {target.describe()}: {_tail(result.stderr)}")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _prunable(names: Sequence[str], retention_days: int, now: datetime) -> list[str]:
    """Bundle names older than the window; the newest export is always kept.

    "Newest" is a moment, not a file: an encrypted bundle and the plaintext it
    came from share a stamp, and keeping one while deleting the other would
    leave a standby holding a bundle nobody can read.
    """
    dated = [(bundle_time(name), name) for name in names if BUNDLE_RE.match(Path(name).name)]
    ours = [(when, name) for when, name in dated if when is not None]
    if not ours:
        return []
    newest = max(when for when, _name in ours)
    cutoff = now - timedelta(days=retention_days)
    return sorted(name for when, name in ours if when != newest and when < cutoff)


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
    policy: SshPolicy | None = None,
) -> list[str]:
    """Delete expired bundles on the standby by name.

    Names are computed here and quoted individually rather than handing the
    remote shell a glob or `find -delete`: the standby directory is the only
    off-box copy of the platform, and one mistyped pattern there deletes all of
    it.
    """
    rules = policy or DEFAULT_POLICY
    rules.require_shell("pruning the standby inbox")
    run = runner or subprocess_runner
    moment = now or datetime.now(UTC)
    expired = _prunable(list_remote(target, runner=run, policy=rules), retention_days, moment)
    if not expired:
        return []
    base = target.path.rstrip("/")
    quoted = " ".join(
        shlex.quote(f"{base}/{name}{suffix}")
        for name in expired
        for suffix in ("", CHECKSUM_SUFFIX)
    )
    result = run(["ssh", *rules.options(), target.ssh_host, f"rm -f -- {quoted}"])
    if not result.ok:
        raise DRError(f"could not prune {target.describe()}: {_tail(result.stderr)}")
    return expired


def prune(
    target: Target,
    retention_days: int,
    *,
    runner: Runner | None = None,
    now: datetime | None = None,
    policy: SshPolicy | None = None,
) -> list[str]:
    """Apply retention where we are allowed to.

    A restricted key cannot delete anything on the standby, by design, so the
    standby prunes its own inbox from cron (`deploy/standby/prune.sh`). Saying
    that out loud here beats a nightly `rm` that fails and looks like a broken
    backup.
    """
    rules = policy or DEFAULT_POLICY
    if target.remote:
        if rules.restricted:
            log.info(
                "the DR key is restricted to rsync; the standby prunes %s itself "
                "(deploy/standby/prune.sh)",
                target.describe(),
            )
            return []
        return prune_remote(target, retention_days, runner=runner, now=now, policy=rules)
    return prune_local(target.local_path(), retention_days, now=now)


def _tail(text: str, limit: int = 300) -> str:
    cleaned = " ".join(text.split())
    return cleaned[-limit:] if len(cleaned) > limit else cleaned
