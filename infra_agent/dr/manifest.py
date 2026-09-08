"""The bundle manifest: what a DR bundle contains and how to prove it is intact.

A bundle is a dated tarball whose members sit at the archive root::

    manifest.json
    data/...              snapshots, graph, plans.db, baseline, everything else
                          under data_dir except the config repo and the freeze marker
    configs.bundle        `git bundle create --all` of the config git repo
    secrets/*.enc.yaml    copied verbatim; already SOPS-encrypted
    inventory/seed.yaml
    postgres/<db>.dump    pg_dump custom format, one per configured database
    grafana/<uid>.json    dashboards, when Grafana answered

`deploy/.env` is deliberately absent - see :data:`EXCLUSIONS`.

The manifest carries a sha256 per file, so `infra dr verify` detects a member
that was edited, truncated, added or dropped after the export. A `.sha256`
sidecar next to the tarball covers the archive as a whole, including the
manifest itself; a tamperer who can rewrite both is a tamperer who can write
to the standby, which is the threat the runbook addresses with key auth and a
non-root account rather than with a checksum.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field

MANIFEST_NAME = "manifest.json"
MANIFEST_VERSION = 1
CHECKSUM_SUFFIX = ".sha256"

#: Bundle layout, as directory names inside the archive.
DATA_DIR = "data"
SECRETS_DIR = "secrets"
INVENTORY_DIR = "inventory"
POSTGRES_DIR = "postgres"
GRAFANA_DIR = "grafana"
CONFIG_BUNDLE = "configs.bundle"

#: Why some things are not in the bundle. Copied into every manifest so the
#: answer travels with the archive and cannot drift away from the code.
EXCLUSIONS: tuple[tuple[str, str], ...] = (
    (
        "deploy/.env",
        "It holds the Postgres, NetBox and Grafana passwords in plaintext. A DR "
        "bundle is copied to a standby host and may sit on a third machine on the "
        "way, so putting every platform credential in it unencrypted would make "
        "one stolen archive a full compromise. secrets/*.enc.yaml travel instead: "
        "they are SOPS-encrypted and useless without the age key. Recreate .env "
        "on the standby from deploy/.env.example plus the values in the owner's "
        "password manager.",
    ),
    (
        "the age private key",
        "The key that decrypts secrets/*.enc.yaml is not in the bundle either, for "
        "the same reason. It lives in the owner's offline copy "
        "(~/.config/sops/age/keys.txt) and must be restored by hand.",
    ),
    (
        "data/FROZEN",
        "The break-glass marker is state of one installation, not of the estate. "
        "An import sets its own freeze; carrying a stale one across would say "
        "nothing about the restored system.",
    ),
    (
        "Prometheus and Loki TSDB",
        "Metrics and logs are observations, not the system of record, and are far "
        "larger than everything else combined. They are rebuilt by scraping. Alert "
        "rules and dashboards - the parts a human wrote - are in git and in the "
        "grafana/ directory of the bundle.",
    ),
)


class FileEntry(BaseModel):
    """One member of the archive."""

    path: str
    sha256: str
    bytes: int


class ComponentStatus(BaseModel):
    """Whether one part of the export produced anything, and why not if not.

    `skipped` separates "this platform does not have one" from "this platform
    has one and it did not answer". Grafana that was never configured is not a
    broken backup; Grafana that timed out is.
    """

    name: str
    ok: bool
    detail: str = ""
    skipped: bool = False

    @property
    def failed(self) -> bool:
        return not self.ok and not self.skipped


class Manifest(BaseModel):
    manifest_version: int = MANIFEST_VERSION
    bundle: str
    created_at: datetime
    host: str
    tool_version: str
    python_version: str
    data_dir: str
    config_repo: str
    components: list[ComponentStatus] = Field(default_factory=list)
    files: list[FileEntry] = Field(default_factory=list)
    excluded: list[dict[str, str]] = Field(default_factory=list)

    def component(self, name: str) -> ComponentStatus | None:
        return next((c for c in self.components if c.name == name), None)

    def by_path(self) -> dict[str, FileEntry]:
        return {entry.path: entry for entry in self.files}

    def total_bytes(self) -> int:
        return sum(entry.bytes for entry in self.files)

    def paths_under(self, prefix: str) -> list[str]:
        marker = prefix.rstrip("/") + "/"
        return sorted(e.path for e in self.files if e.path.startswith(marker))


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(chunk):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def file_entries(root: Path) -> list[FileEntry]:
    """Every regular file under `root`, hashed, with archive-relative paths.

    Symlinks are skipped rather than followed: a bundle must not smuggle a file
    from outside the staging tree, and `infra dr verify` extracts with the
    tarfile data filter, which would reject them on the way back out anyway.
    """
    entries: list[FileEntry] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel == MANIFEST_NAME:
            continue
        entries.append(FileEntry(path=rel, sha256=sha256_file(path), bytes=path.stat().st_size))
    return entries


def exclusion_rows() -> list[dict[str, str]]:
    return [{"what": what, "why": why} for what, why in EXCLUSIONS]
