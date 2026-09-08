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
manifest is not a backup, and restoring it would be restoring an unknown.

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
from pathlib import Path

from infra_agent.config import Settings, get_settings
from infra_agent.dr import archive
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
) -> ImportReport:
    settings = settings or get_settings()
    bundle = Path(bundle)
    report = ImportReport(bundle=bundle.name)

    checked = verify(bundle, git_runner=git_runner)
    report.verification = checked
    fatal = [c for c in checked.checks if c.name in INTEGRITY_CHECKS and not c.ok]
    if fatal:
        raise DRError(
            "refusing to import a bundle that does not match its own manifest: "
            + "; ".join(f"{c.name}: {c.detail}" for c in fatal)
        )
    report.warnings = [f"{c.name}: {c.detail}" for c in checked.failures()]

    if not data_dir_is_empty(settings.data_dir) and not force:
        raise DRError(
            f"{settings.data_dir} is not empty. An import over a live installation mixes two "
            "estates; move it aside, or re-run with --force if you meant to overwrite it."
        )

    with tempfile.TemporaryDirectory(prefix="infra-dr-import-") as tmp:
        root = archive.extract(bundle, Path(tmp) / "bundle")
        _restore_data(root, settings, report)
        _restore_config_repo(root, settings, report, git_runner or _git)
        _restore_secrets(root, settings, report, force=force)
        _restore_inventory(root, settings, report, force=force)
        _stage(root / POSTGRES_DIR, settings.data_dir / RESTORE_STAGING / "postgres", report)
        _stage(root / GRAFANA_DIR, settings.data_dir / RESTORE_STAGING / "grafana", report)

    report.frozen = _freeze(settings)
    return report


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
