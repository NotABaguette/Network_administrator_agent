"""`infra dr export`: everything needed to rebuild this platform, in one file.

The bundle is assembled in a staging directory, hashed into a manifest, tarred,
checksummed, and only then shipped. Nothing is deleted on the way, and a
component that fails is recorded rather than fatal: the export exists to be
there on the worst day of the year, so producing a partial bundle and saying
loudly which part is missing always beats producing nothing.

What is deliberately left out - `deploy/.env`, the age private key, the
Prometheus and Loki databases - and why, is in
:data:`infra_agent.dr.manifest.EXCLUSIONS` and travels inside every manifest.
"""

from __future__ import annotations

import logging
import platform
import shutil
import socket
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from infra_agent import __version__
from infra_agent.config import Settings, get_settings
from infra_agent.dr import archive, state, transfer
from infra_agent.dr.errors import DRError
from infra_agent.dr.manifest import (
    CHECKSUM_SUFFIX,
    CONFIG_BUNDLE,
    DATA_DIR,
    GRAFANA_DIR,
    INVENTORY_DIR,
    MANIFEST_NAME,
    POSTGRES_DIR,
    SECRETS_DIR,
    ComponentStatus,
    Manifest,
    exclusion_rows,
    file_entries,
    sha256_file,
)
from infra_agent.dr.sources import (
    GrafanaExporter,
    PgDumper,
    git_bundle,
    grafana_exporter,
    grafana_token,
    pg_dump_to_file,
)
from infra_agent.dr.transfer import BUNDLE_PREFIX, BUNDLE_SUFFIX, Runner, parse_target

log = logging.getLogger(__name__)

#: Names under data_dir that must not travel. `dr/` would nest every previous
#: bundle inside the new one and double the archive on every run.
DATA_EXCLUDE = {"FROZEN", "dr", "dr-restore"}


@dataclass
class ExportResult:
    bundle: Path
    checksum: Path
    manifest: Manifest
    components: list[ComponentStatus] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    pushed_to: str | None = None
    pruned: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when nothing this platform actually has failed to be exported.

        A component that is not configured at all - no Grafana, no Postgres -
        is reported, not counted as a failure: a nightly duty that pages the
        owner about a service they deliberately do not run is a duty they turn
        off, and then it is not there on the night it matters.
        """
        return not any(component.failed for component in self.components)

    def summary(self) -> dict[str, object]:
        """Secret-free description for the owner and for the digest."""
        return {
            "bundle": self.bundle.name,
            "bytes": self.bundle.stat().st_size if self.bundle.exists() else None,
            "created_at": self.manifest.created_at.isoformat(),
            "files": len(self.manifest.files),
            "components": {c.name: c.ok for c in self.components},
            "incomplete": [c.name for c in self.components if c.failed],
            "not_configured": [c.name for c in self.components if c.skipped],
            "pushed_to": self.pushed_to,
            "pruned": self.pruned,
            "warnings": self.warnings,
        }


def bundle_name(host: str, now: datetime) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in host) or "unknown"
    return f"{BUNDLE_PREFIX}-{safe}-{now.strftime('%Y%m%dT%H%M%SZ')}{BUNDLE_SUFFIX}"


def _copy_data_dir(data_dir: Path, dest: Path, config_repo: Path) -> ComponentStatus:
    """Everything under data_dir except the config repo, bundles and the marker.

    The config repo is exported as a git bundle instead of a file copy so its
    history survives; copying `.git` byte for byte would work too, but a bundle
    is verifiable on its own and a third of the size.
    """
    if not data_dir.exists():
        return ComponentStatus(name="data", ok=False, detail=f"{data_dir} does not exist")
    # Compare relative paths, not absolute ones: `data_dir` as configured and
    # `config_repo.resolve()` differ the moment either side crosses a symlink,
    # and then the repo is copied file by file into the bundle as well as being
    # exported as a git bundle.
    try:
        repo_rel: Path | None = config_repo.resolve().relative_to(data_dir.resolve())
    except ValueError:  # the repo lives outside data_dir; nothing to exclude
        repo_rel = None
    copied = 0
    for path in sorted(data_dir.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        rel = path.relative_to(data_dir)
        if rel.parts[0] in DATA_EXCLUDE:
            continue
        if repo_rel is not None and repo_rel in rel.parents:
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        copied += 1
    if copied == 0:
        return ComponentStatus(name="data", ok=False, detail=f"{data_dir} is empty")
    return ComponentStatus(name="data", ok=True, detail=f"{copied} files")


def _copy_secrets(secrets_dir: Path, dest: Path) -> ComponentStatus:
    """SOPS-encrypted files, copied verbatim. Plaintext is never read here."""
    files = sorted(secrets_dir.glob("*.enc.yaml")) if secrets_dir.exists() else []
    if not files:
        return ComponentStatus(name="secrets", ok=False, detail=f"no *.enc.yaml in {secrets_dir}")
    dest.mkdir(parents=True, exist_ok=True)
    for path in files:
        shutil.copy2(path, dest / path.name)
    return ComponentStatus(
        name="secrets", ok=True, detail=f"{len(files)} encrypted files (age key not included)"
    )


def _copy_inventory(seed: Path, dest: Path) -> ComponentStatus:
    if not seed.exists():
        return ComponentStatus(name="inventory", ok=False, detail=f"{seed} does not exist")
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy2(seed, dest / "seed.yaml")
    return ComponentStatus(name="inventory", ok=True, detail=seed.name)


def _config_repo(repo: Path, dest: Path) -> ComponentStatus:
    try:
        git_bundle(repo, dest)
    except DRError as exc:
        return ComponentStatus(name="config_repo", ok=False, detail=str(exc))
    return ComponentStatus(name="config_repo", ok=True, detail=CONFIG_BUNDLE)


def _postgres(settings: Settings, dest: Path, dumper: PgDumper) -> ComponentStatus:
    if not settings.postgres_dsn:
        return ComponentStatus(
            name="postgres",
            ok=False,
            skipped=True,
            detail="INFRA_POSTGRES_DSN is not set; nothing to dump",
        )
    dest.mkdir(parents=True, exist_ok=True)
    done: list[str] = []
    failed: list[str] = []
    for database in settings.dr_postgres_databases:
        try:
            dumper(settings.postgres_dsn, database, dest / f"{database}.dump")
            done.append(database)
        except DRError as exc:
            log.warning("pg_dump of %s failed: %s", database, exc)
            failed.append(f"{database} ({exc})")
    if failed:
        return ComponentStatus(
            name="postgres",
            ok=False,
            detail=f"dumped {', '.join(done) or 'nothing'}; failed: {'; '.join(failed)}",
        )
    return ComponentStatus(name="postgres", ok=True, detail=", ".join(done))


def _grafana(dest: Path, exporter: GrafanaExporter | None) -> ComponentStatus:
    if exporter is None:
        return ComponentStatus(
            name="grafana",
            ok=False,
            skipped=True,
            detail="INFRA_DR_GRAFANA_URL is not set; dashboards skipped",
        )
    try:
        dashboards = exporter()
    except DRError as exc:
        return ComponentStatus(name="grafana", ok=False, detail=str(exc))
    if not dashboards:
        return ComponentStatus(name="grafana", ok=True, detail="no dashboards to export")
    dest.mkdir(parents=True, exist_ok=True)
    import json

    for uid, body in sorted(dashboards.items()):
        safe = "".join(ch for ch in uid if ch.isalnum() or ch in "-_") or "dashboard"
        (dest / f"{safe}.json").write_text(json.dumps(body, indent=1, sort_keys=True))
    return ComponentStatus(name="grafana", ok=True, detail=f"{len(dashboards)} dashboards")


def build_bundle(
    settings: Settings | None = None,
    *,
    dest_dir: Path,
    now: datetime | None = None,
    host: str | None = None,
    pg_dumper: PgDumper | None = None,
    grafana: GrafanaExporter | None = None,
) -> ExportResult:
    """Assemble one bundle in `dest_dir`. No network beyond Postgres and Grafana."""
    settings = settings or get_settings()
    moment = now or datetime.now(UTC)
    hostname = host or socket.gethostname()
    dumper = pg_dumper or pg_dump_to_file
    dashboards = (
        grafana
        if grafana is not None
        else grafana_exporter(settings.dr_grafana_url, grafana_token(settings.secrets_dir))
    )
    name = bundle_name(hostname, moment)

    with tempfile.TemporaryDirectory(prefix="infra-dr-stage-") as tmp:
        stage = Path(tmp)
        components = [
            _copy_data_dir(settings.data_dir, stage / DATA_DIR, settings.config_repo),
            _config_repo(settings.config_repo, stage / CONFIG_BUNDLE),
            _copy_secrets(settings.secrets_dir, stage / SECRETS_DIR),
            _copy_inventory(settings.seed_inventory, stage / INVENTORY_DIR),
            _postgres(settings, stage / POSTGRES_DIR, dumper),
            _grafana(stage / GRAFANA_DIR, dashboards),
        ]
        manifest = Manifest(
            bundle=name,
            created_at=moment,
            host=hostname,
            tool_version=__version__,
            python_version=platform.python_version() or sys.version.split()[0],
            data_dir=str(settings.data_dir),
            config_repo=str(settings.config_repo),
            components=components,
            files=file_entries(stage),
            excluded=exclusion_rows(),
        )
        (stage / MANIFEST_NAME).write_text(manifest.model_dump_json(indent=1))
        dest_dir.mkdir(parents=True, exist_ok=True)
        bundle = archive.create(stage, dest_dir / name)

    checksum = bundle.with_name(bundle.name + CHECKSUM_SUFFIX)
    checksum.write_text(f"{sha256_file(bundle)}  {bundle.name}\n")
    warnings = [f"{c.name}: {c.detail}" for c in manifest.components if c.failed]
    for warning in warnings:
        log.warning("DR export incomplete - %s", warning)
    return ExportResult(
        bundle=bundle,
        checksum=checksum,
        manifest=manifest,
        components=manifest.components,
        warnings=warnings,
    )


def export_bundle(
    settings: Settings | None = None,
    *,
    to: str | Path | None = None,
    now: datetime | None = None,
    host: str | None = None,
    keep_dir: Path | None = None,
    pg_dumper: PgDumper | None = None,
    grafana: GrafanaExporter | None = None,
    runner: Runner | None = None,
    prune: bool = True,
) -> ExportResult:
    """Build a bundle and put it where `to` says: a directory or an SSH target.

    A remote target still gets a local copy in `data_dir/dr`, because the
    weekly verify has to read a bundle and the standby is deliberately a
    machine this one cannot log in to.
    """
    settings = settings or get_settings()
    moment = now or datetime.now(UTC)
    raw = to if to is not None else settings.dr_target
    if raw is None:
        raise DRError(
            "no DR target: pass --to, or set INFRA_DR_TARGET to a directory or ssh://user@host/path"
        )
    target = parse_target(raw)
    local_dir = target.local_path() if not target.remote else (keep_dir or settings.dr_dir)
    result = build_bundle(
        settings,
        dest_dir=local_dir,
        now=moment,
        host=host,
        pg_dumper=pg_dumper,
        grafana=grafana,
    )

    if target.remote:
        transfer.ensure_remote_dir(target, runner=runner)
        transfer.push(
            target=target, bundle=result.bundle, runner=runner, extra_files=[result.checksum]
        )
        result.pushed_to = target.describe()

    if prune:
        try:
            result.pruned = transfer.prune(
                target, settings.dr_retention_days, runner=runner, now=moment
            )
            if target.remote:
                result.pruned += transfer.prune_local(
                    local_dir, settings.dr_retention_days, now=moment
                )
        except DRError as exc:
            log.warning("retention pruning failed: %s", exc)
            result.warnings.append(f"pruning: {exc}")

    state.update(
        settings,
        last_export_at=moment,
        last_export_bundle=result.bundle.name,
        last_export_bytes=result.bundle.stat().st_size,
        last_export_ok=result.ok,
        last_export_error="; ".join(result.warnings) or None,
        **(
            {"last_push_at": moment, "last_push_target": result.pushed_to}
            if result.pushed_to
            else {}
        ),
    )
    return result
