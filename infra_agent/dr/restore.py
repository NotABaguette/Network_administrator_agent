"""`infra dr import`: put a bundle back where it came from.

Two rules make this safe to run on a machine somebody is panicking on:

1. **It refuses a non-empty `data_dir` unless `--force`.** Importing over a
   live installation would silently mix two estates' snapshots and two plan
   stores. Restores happen onto empty ground.
2. **It leaves the platform frozen.** The marker `data_dir/FROZEN` is written
   at the end of every import, so nothing automates against restored state
   until a human has looked at it and run `infra change unfreeze`. On a
   failover the restored agent must not start reconciling an estate whose
   primary may still be half alive - that is how you get two administrators.

Manifest integrity is not optional. `--force` overrides the empty-directory
refusal, never a checksum mismatch: a bundle that does not hash to its own
manifest is not a backup, and restoring it would be restoring an unknown. Nor
does `--force` mean "merge": the old `data_dir` is moved aside whole, because
files the bundle does not contain - a stale `plans.db-journal` from the last
crash, snapshots of an estate this is not - survive a merge and are read as if
they had been restored.

The freeze marker is written **before** the first file is restored and again
after the last one, whatever happened in between. A restore that stopped
half-way because the secrets mount is read-only must not leave a platform that
is restored enough to act and not frozen.

Postgres dumps and Grafana dashboards are staged rather than applied. Loading
them needs a running server, which on a cold standby comes up after this step;
the runbook (`docs/runbooks/dr-mgmt-01.md`) has the two `pg_restore` lines.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from infra_agent.config import Settings, get_settings
from infra_agent.dr import archive, crypt
from infra_agent.dr.errors import DRError
from infra_agent.dr.manifest import (
    CONFIG_BUNDLE,
    DATA_DIR,
    GRAFANA_DIR,
    INVENTORY_DIR,
    POSTGRES_DIR,
    SECRETS_DIR,
)
from infra_agent.dr.verify import GitRunner, VerifyReport, verify

log = logging.getLogger(__name__)

RESTORE_STAGING = "dr-restore"
FREEZE_MARKER = "FROZEN"
#: Where `--force` puts whatever was in data_dir before the restore.
PRE_IMPORT_DIR = "pre-import"

#: Checks that must pass before anything is written, whatever --force says.
INTEGRITY_CHECKS = ("checksum", "extract", "manifest", "files")


@dataclass
class ImportReport:
    bundle: str
    restored: list[str] = field(default_factory=list)
    staged: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    frozen: bool = False
    verification: VerifyReport | None = None

    def summary(self) -> dict[str, object]:
        return {
            "bundle": self.bundle,
            "restored": self.restored,
            "staged": self.staged,
            "skipped": self.skipped,
            "warnings": self.warnings,
            "frozen": self.frozen,
        }

    def headline(self) -> str:
        return (
            f"{self.bundle} restored: {len(self.restored)} components in place, "
            f"{len(self.staged)} staged for a human. "
            + ("The platform is FROZEN until you unfreeze it." if self.frozen else "")
        )


def data_dir_is_empty(data_dir: Path) -> bool:
    if not data_dir.exists():
        return True
    return not any(data_dir.iterdir())


def import_bundle(
    bundle: Path,
    settings: Settings | None = None,
    *,
    force: bool = False,
    git_runner: GitRunner | None = None,
    now: datetime | None = None,
    age_runner: Any = None,
) -> ImportReport:
    settings = settings or get_settings()
    bundle = Path(bundle)
    report = ImportReport(bundle=bundle.name)

    with tempfile.TemporaryDirectory(prefix="infra-dr-import-") as tmp:
        scratch = Path(tmp)
        # Verify the file as it arrived: for an encrypted bundle that is the
        # `.age` one, and its sidecar is the only thing covering the manifest.
        checked = verify(
            bundle,
            git_runner=git_runner,
            settings=settings,
            require_checksum=True,
            age_runner=age_runner,
        )
        report.verification = checked
        fatal = [c for c in checked.checks if c.name in INTEGRITY_CHECKS and not c.ok]
        if fatal:
            raise DRError(
                "refusing to import a bundle that does not match its own manifest: "
                + "; ".join(f"{c.name}: {c.detail}" for c in fatal)
            )
        report.warnings += [f"{c.name}: {c.detail}" for c in checked.failures()]

        plain, was_encrypted = crypt.ensure_plaintext(
            bundle, scratch / "plain", settings, runner=age_runner
        )
        if was_encrypted:
            report.warnings.append("bundle: decrypted with the age key before restoring")
        if _within(plain, settings.data_dir):
            # `infra dr import data/dr/<bundle> --force` would otherwise read
            # from a directory this function is about to empty.
            safe = scratch / "source"
            safe.mkdir(parents=True, exist_ok=True)
            plain = Path(shutil.copy2(plain, safe / plain.name))

        if not data_dir_is_empty(settings.data_dir) and not force:
            raise DRError(
                f"{settings.data_dir} is not empty. An import over a live installation mixes "
                "two estates; move it aside, or re-run with --force if you meant to "
                "overwrite it."
            )
        if force:
            moved = _move_aside(settings.data_dir, now or datetime.now(UTC))
            if moved is not None:
                report.warnings.append(
                    f"data: the previous installation was moved aside into "
                    f"{PRE_IMPORT_DIR}/{moved.name}, not deleted"
                )

        # Freeze first. Everything below can fail - a read-only secrets mount,
        # a full disk, a git that is not installed - and the one thing that
        # must be true afterwards either way is that nothing automates against
        # a half-restored platform.
        report.frozen = _freeze(settings)
        try:
            root = archive.extract(plain, scratch / "bundle")
            _step(report, "data", lambda: _restore_data(root, settings, report))
            _step(
                report,
                "config_repo",
                lambda: _restore_config_repo(root, settings, report, git_runner or _git),
            )
            _step(
                report,
                "secrets",
                lambda: _restore_secrets(root, settings, report, force=force),
            )
            _step(
                report,
                "inventory",
                lambda: _restore_inventory(root, settings, report, force=force),
            )
            _step(
                report,
                "postgres",
                lambda: _stage(
                    root / POSTGRES_DIR,
                    settings.data_dir / RESTORE_STAGING / "postgres",
                    report,
                ),
            )
            _step(
                report,
                "grafana",
                lambda: _stage(
                    root / GRAFANA_DIR, settings.data_dir / RESTORE_STAGING / "grafana", report
                ),
            )
        finally:
            report.frozen = _freeze(settings) or report.frozen
    return report


def _step(report: ImportReport, name: str, action: Callable[[], None]) -> None:
    """Run one restore step; an OS-level refusal is a warning, not an abort.

    The compose stack mounts `../secrets:/app/secrets:ro`, so restoring secrets
    inside the container raises `OSError: Read-only file system`. That is a
    thing for the operator to do by hand - it is not a reason to abandon a
    restore whose data, config history and inventory are already in place.
    """
    try:
        action()
    except OSError as exc:
        log.warning("restore step %s failed: %s", name, exc)
        report.warnings.append(f"{name}: {type(exc).__name__}: {exc.strerror or exc}")


def _within(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
    except (ValueError, OSError):
        return False
    return True


def _move_aside(data_dir: Path, now: datetime) -> Path | None:
    """Empty the data directory into `pre-import/<stamp>/`, keeping everything.

    Not a rename of `data_dir` itself: in the compose stack that path is the
    mount point of the `infra-data` volume, and renaming a mount point fails
    with EBUSY. Moving the contents works the same way in a container and on a
    bare host.

    Nothing is deleted. Whatever the platform accumulated since the bundle was
    made - the plan store, the snapshots, an old rollback journal - is the only
    record of the outage, and `pre-import/` is excluded from future exports so
    it cannot end up nested inside tomorrow's bundle.
    """
    if data_dir_is_empty(data_dir):
        return None
    destination = data_dir / PRE_IMPORT_DIR / now.strftime("%Y%m%dT%H%M%SZ")
    suffix = 1
    while destination.exists():
        suffix += 1
        destination = destination.with_name(f"{destination.name}-{suffix}")
    destination.mkdir(parents=True)
    for entry in sorted(data_dir.iterdir()):
        if entry.name == PRE_IMPORT_DIR:
            continue
        shutil.move(str(entry), str(destination / entry.name))
    log.warning("moved the previous contents of %s aside into %s", data_dir, destination)
    return destination


def _restore_data(root: Path, settings: Settings, report: ImportReport) -> None:
    source = root / DATA_DIR
    if not source.exists():
        report.warnings.append("data: the bundle carries no data directory")
        return
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        target = settings.data_dir / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        count += 1
    report.restored.append(f"data ({count} files into {settings.data_dir})")


def _restore_config_repo(
    root: Path, settings: Settings, report: ImportReport, runner: GitRunner
) -> None:
    source = root / CONFIG_BUNDLE
    repo = settings.config_repo
    if not source.exists():
        report.warnings.append("config_repo: no configs.bundle in the archive")
        return
    if (repo / ".git").exists():
        report.skipped.append(f"config_repo ({repo} already holds a repository)")
        return
    repo.parent.mkdir(parents=True, exist_ok=True)
    code, output = runner(["git", "clone", "--quiet", str(source), str(repo)])
    if code != 0:
        report.warnings.append(f"config_repo: clone failed: {_tail(output)}")
        return
    report.restored.append(f"config_repo (cloned into {repo})")


def _restore_secrets(root: Path, settings: Settings, report: ImportReport, *, force: bool) -> None:
    """Encrypted files only. The age key that opens them is not in the bundle."""
    source = root / SECRETS_DIR
    files = sorted(source.glob("*.enc.yaml")) if source.exists() else []
    if not files:
        report.warnings.append("secrets: no *.enc.yaml in the archive")
        return
    settings.secrets_dir.mkdir(parents=True, exist_ok=True)
    written, kept = 0, 0
    for path in files:
        target = settings.secrets_dir / path.name
        if target.exists() and not force:
            kept += 1
            continue
        shutil.copy2(path, target)
        written += 1
    if written:
        report.restored.append(f"secrets ({written} encrypted files into {settings.secrets_dir})")
    if kept:
        report.skipped.append(f"secrets ({kept} files already present; --force overwrites)")
    report.warnings.append(
        "secrets: restore ~/.config/sops/age/keys.txt from the owner's offline copy, "
        "or nothing here can be decrypted"
    )


def _restore_inventory(
    root: Path, settings: Settings, report: ImportReport, *, force: bool
) -> None:
    source = root / INVENTORY_DIR / "seed.yaml"
    if not source.exists():
        report.warnings.append("inventory: no seed.yaml in the archive")
        return
    target = settings.seed_inventory
    if target.exists() and not force:
        report.skipped.append(f"inventory ({target} already exists; --force overwrites)")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    report.restored.append(f"inventory ({target})")


def _stage(source: Path, dest: Path, report: ImportReport) -> None:
    files = sorted(p for p in source.rglob("*") if p.is_file()) if source.exists() else []
    if not files:
        return
    dest.mkdir(parents=True, exist_ok=True)
    for path in files:
        target = dest / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    report.staged.append(f"{source.name} ({len(files)} files in {dest})")


def _freeze(settings: Settings) -> bool:
    """Write the break-glass marker. A restored platform acts only when told to."""
    try:
        marker = settings.data_dir / FREEZE_MARKER
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("frozen by `infra dr import`; unfreeze once the restore is checked\n")
        return True
    except OSError:
        log.exception("could not write the freeze marker after an import")
        return False


Runner = Callable[[Sequence[str]], tuple[int, str]]


def _git(argv: Sequence[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(list(argv), capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        return 127, "git is not installed on this host"
    except subprocess.TimeoutExpired:
        return 124, "git timed out"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _tail(text: str, limit: int = 300) -> str:
    cleaned = " ".join(text.split())
    return cleaned[-limit:] if len(cleaned) > limit else cleaned
