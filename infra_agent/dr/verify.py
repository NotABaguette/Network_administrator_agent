"""`infra dr verify`: prove a bundle would actually restore, without restoring it.

A backup nobody restored is a rumour. Verify unpacks the bundle into a
temporary directory and does the things a restore would do - hash every file
against the manifest, open the plan store, fsck the config repository, parse
the seed inventory and the topology graph, look at the Postgres dumps - then
throws the directory away. It touches nothing in `data_dir`, so it is safe to
run on the live primary, which is where the weekly duty runs it.

It is also the tamper check: a member that was edited after the export fails
its sha256 here, and so does a member that was added or removed.
"""

from __future__ import annotations

import json
import logging
import shutil
import sqlite3
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from infra_agent.dr import archive
from infra_agent.dr.errors import DRError
from infra_agent.dr.manifest import (
    CHECKSUM_SUFFIX,
    CONFIG_BUNDLE,
    DATA_DIR,
    INVENTORY_DIR,
    MANIFEST_NAME,
    POSTGRES_DIR,
    SECRETS_DIR,
    Manifest,
    sha256_file,
)
from infra_agent.dr.sources import looks_like_pg_dump

log = logging.getLogger(__name__)

#: (argv) -> (returncode, combined output). Injectable so the git checks are
#: exercised against a real repository in the tests and faked when git is not
#: the thing under test.
GitRunner = Callable[[Sequence[str]], tuple[int, str]]


def _git(argv: Sequence[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(list(argv), capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        return 127, "git is not installed on this host"
    except subprocess.TimeoutExpired:
        return 124, "git timed out"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


class CheckResult(BaseModel):
    name: str
    ok: bool
    detail: str = ""

    def line(self) -> str:
        return f"{'ok  ' if self.ok else 'FAIL'} {self.name}: {self.detail}"


class VerifyReport(BaseModel):
    bundle: str
    ok: bool = False
    checks: list[CheckResult] = Field(default_factory=list)
    created_at: datetime | None = None
    host: str | None = None
    tool_version: str | None = None
    incomplete_components: list[str] = Field(default_factory=list)

    def failures(self) -> list[CheckResult]:
        return [check for check in self.checks if not check.ok]

    def headline(self) -> str:
        bad = self.failures()
        if not bad:
            note = (
                f" (exported without {', '.join(self.incomplete_components)})"
                if self.incomplete_components
                else ""
            )
            return f"{self.bundle} verified: {len(self.checks)} checks passed{note}"
        return f"{self.bundle} FAILED verification: {', '.join(c.name for c in bad)}"

    def llm_view(self) -> dict[str, Any]:
        """Structured, secret-free: file names and outcomes, never file contents."""
        return {
            "bundle": self.bundle,
            "ok": self.ok,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "host": self.host,
            "checks": [c.model_dump() for c in self.checks],
            "incomplete_components": self.incomplete_components,
        }


def verify(
    bundle: Path,
    *,
    workdir: Path | None = None,
    git_runner: GitRunner | None = None,
    keep: bool = False,
) -> VerifyReport:
    """Verify one bundle. Never raises for a bad bundle; that is what the report is."""
    bundle = Path(bundle)
    report = VerifyReport(bundle=bundle.name)
    if not bundle.exists():
        report.checks.append(
            CheckResult(name="bundle", ok=False, detail=f"{bundle} does not exist")
        )
        return report

    scratch = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="infra-dr-verify-"))
    scratch.mkdir(parents=True, exist_ok=True)
    try:
        report.checks.append(_check_checksum(bundle))
        root = scratch / "bundle"
        try:
            archive.extract(bundle, root)
        except DRError as exc:
            report.checks.append(CheckResult(name="extract", ok=False, detail=str(exc)))
            return report
        report.checks.append(
            CheckResult(name="extract", ok=True, detail=f"unpacked into {root.name}")
        )

        manifest, manifest_check = _load_manifest(root)
        report.checks.append(manifest_check)
        if manifest is None:
            return report
        report.created_at = manifest.created_at
        report.host = manifest.host
        report.tool_version = manifest.tool_version
        report.incomplete_components = [c.name for c in manifest.components if not c.ok]

        report.checks.append(_check_files(root, manifest))
        report.checks.append(_check_plans_db(root))
        report.checks.append(_check_config_repo(root, scratch / "configs", git_runner or _git))
        report.checks.append(_check_inventory(root))
        report.checks.append(_check_graph(root))
        report.checks.append(_check_postgres(root, manifest))
        report.checks.append(_check_secrets(root, manifest))
        report.ok = all(check.ok for check in report.checks)
        return report
    finally:
        if not keep and workdir is None:
            shutil.rmtree(scratch, ignore_errors=True)


def _check_checksum(bundle: Path) -> CheckResult:
    sidecar = bundle.with_name(bundle.name + CHECKSUM_SUFFIX)
    if not sidecar.exists():
        return CheckResult(
            name="checksum",
            ok=True,
            detail="no .sha256 sidecar next to the bundle; per-file hashes still apply",
        )
    expected = sidecar.read_text().split()[0] if sidecar.read_text().split() else ""
    actual = sha256_file(bundle)
    if expected != actual:
        return CheckResult(
            name="checksum",
            ok=False,
            detail=f"sidecar says {expected[:12]}..., archive hashes to {actual[:12]}...",
        )
    return CheckResult(name="checksum", ok=True, detail=f"sha256 {actual[:12]}...")


def _load_manifest(root: Path) -> tuple[Manifest | None, CheckResult]:
    path = root / MANIFEST_NAME
    if not path.exists():
        return None, CheckResult(name="manifest", ok=False, detail="no manifest.json in the bundle")
    try:
        manifest = Manifest.model_validate_json(path.read_text())
    except Exception as exc:  # noqa: BLE001 - any parse failure is the same answer
        return None, CheckResult(
            name="manifest", ok=False, detail=f"unreadable manifest ({type(exc).__name__}: {exc})"
        )
    return manifest, CheckResult(
        name="manifest",
        ok=True,
        detail=(
            f"v{manifest.manifest_version} from {manifest.host} at "
            f"{manifest.created_at.isoformat()} (infra-agent {manifest.tool_version})"
        ),
    )


def _check_files(root: Path, manifest: Manifest) -> CheckResult:
    """Every file the manifest lists, hashed; and nothing the manifest does not list."""
    present = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.relative_to(root).as_posix() != MANIFEST_NAME
    }
    expected = manifest.by_path()
    missing = sorted(set(expected) - present)
    unexpected = sorted(present - set(expected))
    corrupt = []
    for name in sorted(present & set(expected)):
        if sha256_file(root / name) != expected[name].sha256:
            corrupt.append(name)
    problems = []
    if missing:
        problems.append(f"missing {_names(missing)}")
    if unexpected:
        problems.append(f"not in the manifest: {_names(unexpected)}")
    if corrupt:
        problems.append(f"checksum mismatch: {_names(corrupt)}")
    if problems:
        return CheckResult(name="files", ok=False, detail="; ".join(problems))
    return CheckResult(
        name="files",
        ok=True,
        detail=f"{len(expected)} files, {manifest.total_bytes()} bytes, all hashes match",
    )


def _names(values: list[str], limit: int = 5) -> str:
    head = ", ".join(values[:limit])
    return head if len(values) <= limit else f"{head} (+{len(values) - limit} more)"


def _check_plans_db(root: Path) -> CheckResult:
    path = root / DATA_DIR / "plans.db"
    if not path.exists():
        return CheckResult(
            name="plans_db",
            ok=True,
            detail="no plans.db in the bundle; nothing has been planned yet",
        )
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()
            if not integrity or integrity[0] != "ok":
                return CheckResult(
                    name="plans_db", ok=False, detail=f"integrity_check said {integrity!r}"
                )
            plans = conn.execute("SELECT count(*) FROM plans").fetchone()[0]
            approvals = conn.execute("SELECT count(*) FROM approvals").fetchone()[0]
        finally:
            conn.close()
    except sqlite3.Error as exc:
        return CheckResult(name="plans_db", ok=False, detail=f"sqlite refused it: {exc}")
    return CheckResult(
        name="plans_db", ok=True, detail=f"{plans} plans, {approvals} pending approval records"
    )


def _check_config_repo(root: Path, clone_dir: Path, runner: GitRunner) -> CheckResult:
    """`git bundle verify`, then a real clone and `git fsck`.

    Verifying the bundle alone would only prove it is a bundle; cloning proves
    the history is complete and reachable, which is what a restore needs.
    """
    path = root / CONFIG_BUNDLE
    if not path.exists():
        return CheckResult(name="config_repo", ok=False, detail=f"no {CONFIG_BUNDLE} in the bundle")
    code, output = runner(["git", "bundle", "verify", str(path)])
    if code != 0:
        return CheckResult(name="config_repo", ok=False, detail=_tail(output))
    code, output = runner(["git", "clone", "--quiet", str(path), str(clone_dir)])
    if code != 0:
        return CheckResult(name="config_repo", ok=False, detail=f"clone failed: {_tail(output)}")
    code, output = runner(["git", "-C", str(clone_dir), "fsck", "--no-progress"])
    if code != 0:
        return CheckResult(name="config_repo", ok=False, detail=f"fsck failed: {_tail(output)}")
    code, count = runner(["git", "-C", str(clone_dir), "rev-list", "--count", "--all"])
    commits = count.strip() if code == 0 else "?"
    return CheckResult(name="config_repo", ok=True, detail=f"clone + fsck clean, {commits} commits")


def _check_inventory(root: Path) -> CheckResult:
    path = root / INVENTORY_DIR / "seed.yaml"
    if not path.exists():
        return CheckResult(name="seed_inventory", ok=False, detail="no inventory/seed.yaml")
    try:
        from infra_agent.models.common import SeedInventory

        inventory = SeedInventory.load(path)
    except Exception as exc:  # noqa: BLE001 - a seed file that does not load is the finding
        return CheckResult(name="seed_inventory", ok=False, detail=f"{type(exc).__name__}: {exc}")
    kinds = sorted({device.kind.value for device in inventory.devices})
    return CheckResult(
        name="seed_inventory",
        ok=True,
        detail=f"{len(inventory.devices)} devices ({', '.join(kinds) or 'none'})",
    )


def _check_graph(root: Path) -> CheckResult:
    path = root / DATA_DIR / "graph" / "graph.json"
    if not path.exists():
        return CheckResult(
            name="graph",
            ok=True,
            detail="no graph.json in the bundle; `infra graph build` rebuilds it from snapshots",
        )
    try:
        from infra_agent.correlate.model import TopologyGraph

        summary = TopologyGraph.load(path).summary()
    except Exception as exc:  # noqa: BLE001
        return CheckResult(name="graph", ok=False, detail=f"{type(exc).__name__}: {exc}")
    nodes = summary.get("nodes") if isinstance(summary, dict) else None
    edges = summary.get("edges") if isinstance(summary, dict) else None
    return CheckResult(name="graph", ok=True, detail=f"loads: {nodes} nodes, {edges} edges")


def _check_postgres(root: Path, manifest: Manifest) -> CheckResult:
    component = manifest.component("postgres")
    dumps = sorted((root / POSTGRES_DIR).glob("*.dump")) if (root / POSTGRES_DIR).exists() else []
    if not dumps:
        detail = component.detail if component else "no postgres/ directory in the bundle"
        return CheckResult(name="postgres", ok=False, detail=f"no database dumps ({detail})")
    bad = [p.name for p in dumps if p.stat().st_size == 0 or not looks_like_pg_dump(p)]
    if bad:
        return CheckResult(name="postgres", ok=False, detail=f"not restorable dumps: {_names(bad)}")
    sizes = ", ".join(f"{p.stem} {p.stat().st_size}B" for p in dumps)
    return CheckResult(name="postgres", ok=True, detail=sizes)


def _check_secrets(root: Path, manifest: Manifest) -> CheckResult:
    """Presence and shape only.

    The age private key is deliberately not in the bundle, so verify cannot
    decrypt anything - and should not: it runs unattended on the primary. It
    checks that the files are there and still look SOPS-encrypted, and the
    quarterly restore test (docs/runbooks/restore-test.md) is where a human
    proves they decrypt with the offline key.
    """
    files = sorted((root / SECRETS_DIR).glob("*.enc.yaml")) if (root / SECRETS_DIR).exists() else []
    if not files:
        component = manifest.component("secrets")
        return CheckResult(
            name="secrets",
            ok=False,
            detail=component.detail if component else "no secrets/*.enc.yaml in the bundle",
        )
    plaintext = [p.name for p in files if "sops" not in p.read_text(errors="replace").lower()]
    if plaintext:
        return CheckResult(
            name="secrets",
            ok=False,
            detail=f"not SOPS-encrypted: {_names(plaintext)} - do not ship this bundle",
        )
    return CheckResult(
        name="secrets",
        ok=True,
        detail=f"{len(files)} encrypted files; decrypting needs the offline age key",
    )


def _tail(text: str, limit: int = 300) -> str:
    cleaned = " ".join(text.split())
    return cleaned[-limit:] if len(cleaned) > limit else cleaned


def read_manifest(bundle: Path) -> Manifest:
    """The manifest of a bundle without unpacking the rest of it."""
    blob = archive.read_member(Path(bundle), MANIFEST_NAME)
    try:
        return Manifest.model_validate(json.loads(blob))
    except Exception as exc:  # noqa: BLE001
        raise DRError(f"unreadable manifest: {type(exc).__name__}: {exc}") from exc


def verify_and_record(
    bundle: Path,
    settings: Any = None,
    *,
    now: datetime | None = None,
    git_runner: GitRunner | None = None,
) -> VerifyReport:
    """Verify a bundle and remember the outcome in `data_dir/dr-state.json`.

    The state file is what `infra_dr_last_verify_ok` and `infra dr health` read,
    so a verification that nobody recorded is a verification that never
    happened as far as the alerting is concerned.
    """
    from datetime import UTC

    from infra_agent.dr import state

    report = verify(bundle, git_runner=git_runner)
    failures = report.failures()
    state.update(
        settings,
        last_verify_at=now or datetime.now(UTC),
        last_verify_bundle=report.bundle,
        last_verify_ok=report.ok,
        last_verify_detail="; ".join(f"{c.name}: {c.detail}" for c in failures) or None,
    )
    return report
