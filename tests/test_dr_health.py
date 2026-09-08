"""`infra dr health`: can this platform still recover?

Every other health view in the repo answers "is the estate healthy". This one
answers "is the administrator healthy", from local state only, so it still
answers when Prometheus, NetBox and the Claude API are all gone - which is
exactly when it is worth asking. These tests hold it to two things: it notices
each way the platform can rot, and it never puts a secret in the report the
daily digest carries to the model.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from infra_agent.change.plan import ChangePlan, Tier
from infra_agent.change.store import PlanStore
from infra_agent.config import Settings
from infra_agent.configstore.git_store import ConfigGitStore
from infra_agent.dr import state as dr_state
from infra_agent.dr.health import HealthReport, health_report
from infra_agent.models.common import DeviceKind, SeedDevice, SeedInventory, Snapshot
from infra_agent.store.snapshots import FileSnapshotStore

NOW = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)

GRAPH = {
    "version": 1,
    "built_at": (NOW - timedelta(minutes=5)).isoformat(),
    "graph": {},
    "nodes": [{"id": "device:esx-01", "kind": "device", "label": "esx-01"}],
    "edges": [],
}


class FakeSecretsStore:
    """A SOPS store that works, without sops or an age key on the test box."""

    contents = {
        "devices": {"esx-01": {"password": "hunter2"}, "sw-core-01": {"password": "hunter2"}},
        "platform": {"anthropic_api_key": "sk-ant-secret", "heartbeat_url": "https://hc/x"},
    }

    def __init__(self, directory: Path, age_key_file: Path | None = None) -> None:
        self.dir = directory

    def available(self) -> bool:
        return True

    def read(self, name: str) -> dict[str, Any]:
        return dict(self.contents.get(name, {}))

    def keys(self, name: str) -> list[str]:
        return list(self.read(name))


class BrokenSecretsStore(FakeSecretsStore):
    """Decryption is broken. Nothing in the health report may need it."""

    def available(self) -> bool:
        return True

    def read(self, name: str) -> dict[str, Any]:
        raise RuntimeError("sops: failed to decrypt: no matching age key for sk-ant-secret")

    def keys(self, name: str) -> list[str]:
        raise RuntimeError("sops: failed to decrypt: no matching age key for sk-ant-secret")


class UnavailableSecretsStore(FakeSecretsStore):
    """No sops binary, or no age key: nothing on this host can be decrypted."""

    def available(self) -> bool:
        return False


@pytest.fixture
def healthy(tmp_path: Path, monkeypatch) -> Settings:
    settings = Settings(
        data_dir=tmp_path / "data",
        secrets_dir=tmp_path / "secrets",
        seed_inventory=tmp_path / "inventory" / "seed.yaml",
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
    for device, collector in (("esx-01", "esxi"), ("sw-core-01", "cisco")):
        store.save(
            Snapshot(
                device=device,
                collector=collector,
                taken_at=NOW - timedelta(minutes=4),
                data={"ok": True},
            )
        )

    settings.graph_dir.mkdir(parents=True, exist_ok=True)
    (settings.graph_dir / "graph.json").write_text(json.dumps(GRAPH))

    PlanStore(settings.data_dir / "plans.db").save(
        ChangePlan(title="t", action="a", targets=["sw-core-01"], tier=Tier.APPROVAL)
    )
    ConfigGitStore(settings.config_repo).write("sw-core-01", "running-config", "hostname x\n")
    settings.secrets_dir.mkdir(parents=True, exist_ok=True)
    # SOPS-shaped: the mapping keys stay in cleartext, every value is an ENC
    # blob, and the `sops` block is the metadata rather than a secret.
    (settings.secrets_dir / "devices.enc.yaml").write_text(
        "esx-01:\n    password: ENC[AES256_GCM,data:aa,type:str]\n"
        "sw-core-01:\n    password: ENC[AES256_GCM,data:bb,type:str]\n"
        "sops:\n    age: []\n"
    )
    (settings.secrets_dir / "platform.enc.yaml").write_text(
        "anthropic_api_key: ENC[AES256_GCM,data:cc,type:str]\n"
        "heartbeat_url: ENC[AES256_GCM,data:dd,type:str]\n"
        "sops:\n    age: []\n"
    )

    dr_state.save(
        dr_state.DRState(
            last_export_at=NOW - timedelta(hours=10),
            last_export_bundle="infra-dr-mgmt-01-20260908T021500Z.tar.gz",
            last_export_ok=True,
            last_push_at=NOW - timedelta(hours=10),
            last_push_target="infra@standby:/srv/infra-dr",
            last_verify_at=NOW - timedelta(days=2),
            last_verify_bundle="infra-dr-mgmt-01-20260906T021500Z.tar.gz",
            last_verify_ok=True,
        ),
        settings,
    )
    monkeypatch.setattr("infra_agent.onboarding.secrets.SecretsStore", FakeSecretsStore)
    return settings


def report(settings: Settings, **kwargs: Any) -> HealthReport:
    kwargs.setdefault("now", NOW)
    return health_report(settings, **kwargs)


# -- the happy path -----------------------------------------------------------


def test_a_healthy_platform_passes_every_check(healthy):
    result = report(healthy)

    assert result.ok, [check.line() for check in result.failures()]
    assert {check.name for check in result.checks} == {
        "collectors",
        "plan_store",
        "graph",
        "config_repo",
        "secrets",
        "heartbeat",
        "dr_export",
        "dr_verify",
    }
    assert result.headline().startswith("platform healthy")
    assert result.frozen is False


def test_it_needs_no_prometheus_no_netbox_and_no_network(healthy, monkeypatch):
    """The one health view that has to work during the outage it is describing."""

    def refuse(*_args: Any, **_kwargs: Any):
        raise AssertionError("dr health must not touch the network")

    monkeypatch.setattr("requests.get", refuse, raising=False)
    monkeypatch.setattr("requests.post", refuse, raising=False)

    assert report(healthy).ok


# -- the ways a platform rots -------------------------------------------------


def test_a_stale_collector_is_named(healthy):
    import shutil

    shutil.rmtree(healthy.snapshot_dir / "sw-core-01")
    FileSnapshotStore(healthy.snapshot_dir).save(
        Snapshot(
            device="sw-core-01",
            collector="cisco",
            taken_at=NOW - timedelta(hours=9),
            data={"ok": True},
        )
    )

    check = report(healthy).get("collectors")

    assert check is not None and not check.ok
    assert "sw-core-01" in check.detail


def test_a_device_that_has_never_been_collected_is_not_silently_healthy(healthy):
    """The failure mode this catches: a device onboarded months ago whose
    collector has never once succeeded, reported as "nothing wrong"."""
    inventory = SeedInventory.load(healthy.seed_inventory)
    inventory.upsert(
        SeedDevice(
            name="fw-01", kind=DeviceKind.fortigate, mgmt_ip="10.0.0.1", credential_ref="fw-01"
        )
    )
    inventory.save(healthy.seed_inventory)

    check = report(healthy).get("collectors")

    assert check is not None and not check.ok
    assert "fw-01 (never)" in check.detail


def test_an_empty_inventory_is_a_failure_not_a_clean_bill_of_health(healthy):
    SeedInventory().save(healthy.seed_inventory)

    check = report(healthy).get("collectors")

    assert check is not None and not check.ok
    assert "no devices" in check.detail


def test_a_corrupt_plan_store_is_caught(healthy):
    (healthy.data_dir / "plans.db").write_bytes(b"this is not a sqlite database")

    check = report(healthy).get("plan_store")

    assert check is not None and not check.ok


def test_no_plan_store_yet_is_not_a_failure(healthy):
    (healthy.data_dir / "plans.db").unlink()

    check = report(healthy).get("plan_store")

    assert check is not None and check.ok
    assert "created on first plan" in check.detail


def test_a_stale_graph_means_impact_analysis_is_answering_from_old_data(healthy):
    stale = dict(GRAPH, built_at=(NOW - timedelta(hours=30)).isoformat())
    (healthy.graph_dir / "graph.json").write_text(json.dumps(stale))

    check = report(healthy).get("graph")

    assert check is not None and not check.ok
    assert "30h ago" in check.detail


def test_a_missing_graph_says_how_to_get_one(healthy):
    (healthy.graph_dir / "graph.json").unlink()

    check = report(healthy).get("graph")

    assert check is not None and not check.ok
    assert "infra graph build" in check.detail


def test_a_config_repo_that_is_not_a_repo_is_caught(healthy):
    import shutil

    shutil.rmtree(healthy.config_repo)

    check = report(healthy).get("config_repo")

    assert check is not None and not check.ok
    assert "not a git repository" in check.detail


def test_a_healthy_config_repo_reports_its_commit_count(healthy):
    check = report(healthy).get("config_repo")

    assert check is not None and check.ok
    assert "fsck clean" in check.detail
    assert "2 commits" in check.detail  # init + one config write


def test_a_platform_that_cannot_open_its_own_secrets_is_the_whole_ballgame(healthy, monkeypatch):
    """Every device credential and the API key are behind this. If sops or the
    age key is gone, the platform is a museum piece with a nice graph."""
    monkeypatch.setattr("infra_agent.onboarding.secrets.SecretsStore", UnavailableSecretsStore)

    check = report(healthy).get("secrets")

    assert check is not None and not check.ok
    assert "age key" in check.detail


def test_a_plaintext_file_in_the_secrets_directory_is_a_finding(healthy):
    (healthy.secrets_dir / "devices.enc.yaml").write_text("esx-01:\n  password: hunter2\n")

    check = report(healthy).get("secrets")

    assert check is not None and not check.ok
    assert "not a SOPS document" in check.detail


def test_the_digest_never_decrypts_a_secret_just_to_count_them(healthy, monkeypatch):
    """`infra dr health` runs in the daily digest. Shelling out to `sops
    --decrypt` for every file would pull every device password and the
    Anthropic and Telegram keys into the agent process to produce the sentence
    "devices: 2 keys". SOPS leaves the mapping keys in cleartext; that is where
    the count comes from."""
    monkeypatch.setattr("infra_agent.onboarding.secrets.SecretsStore", BrokenSecretsStore)

    check = report(healthy).get("secrets")

    assert check is not None and check.ok, "counting keys must not need a decryption"
    assert "devices: 2 keys" in check.detail


def test_a_secrets_failure_never_quotes_what_failed_to_decrypt(healthy, monkeypatch):
    """The exception text carries the key material that could not be read.
    This report goes into the daily digest, which goes to the model."""
    monkeypatch.setattr("infra_agent.onboarding.secrets.SecretsStore", BrokenSecretsStore)

    result = report(healthy)

    assert "sk-ant-secret" not in json.dumps(result.llm_view())


def test_the_report_counts_secrets_but_never_names_their_values(healthy):
    result = report(healthy)

    body = json.dumps(result.llm_view())
    assert "hunter2" not in body
    assert "sk-ant-secret" not in body
    check = result.get("secrets")
    assert check is not None
    assert "devices: 2 keys" in check.detail
    assert "platform: 2 keys" in check.detail


# -- DR state -----------------------------------------------------------------


def test_a_stale_export_is_reported_with_the_bundle_that_is_too_old(healthy):
    dr_state.update(healthy, last_export_at=NOW - timedelta(hours=50))

    check = report(healthy).get("dr_export")

    assert check is not None and not check.ok
    assert "50h old" in check.detail


def test_never_having_exported_is_a_failure(healthy):
    healthy.dr_state_file.unlink()

    check = report(healthy).get("dr_export")

    assert check is not None and not check.ok
    assert "no DR export" in check.detail


def test_a_healthy_export_names_where_it_went(healthy):
    check = report(healthy).get("dr_export")

    assert check is not None and check.ok
    assert "infra@standby:/srv/infra-dr" in check.detail


def test_an_incomplete_export_is_not_reported_as_healthy(healthy):
    dr_state.update(
        healthy, last_export_ok=False, last_export_error="postgres: INFRA_POSTGRES_DSN is not set"
    )

    check = report(healthy).get("dr_export")

    assert check is not None and not check.ok
    assert "postgres" in check.detail


def test_a_failed_verification_is_reported_with_its_reason(healthy):
    dr_state.update(
        healthy, last_verify_ok=False, last_verify_detail="files: checksum mismatch: data/plans.db"
    )

    check = report(healthy).get("dr_verify")

    assert check is not None and not check.ok
    assert "checksum mismatch" in check.detail


def test_never_having_verified_says_why_that_matters(healthy):
    healthy.dr_state_file.unlink()

    check = report(healthy).get("dr_verify")

    assert check is not None and not check.ok
    assert "proves the backup" in check.detail


def test_a_verification_from_a_month_ago_is_stale(healthy):
    dr_state.update(healthy, last_verify_at=NOW - timedelta(days=30))

    check = report(healthy).get("dr_verify")

    assert check is not None and not check.ok
    assert "30 days ago" in check.detail


# -- heartbeat ----------------------------------------------------------------


def test_a_recent_heartbeat_passes(healthy):
    check = report(healthy, heartbeat_age=120.0).get("heartbeat")

    assert check is not None and check.ok
    assert check.age_seconds == 120.0


def test_an_old_heartbeat_fails(healthy):
    check = report(healthy, heartbeat_age=4000.0).get("heartbeat")

    assert check is not None and not check.ok
    assert "66m ago" in check.detail


def test_no_heartbeat_in_this_process_is_unknown_rather_than_broken(healthy):
    """The gauge lives in whichever process sends the ping. From the CLI it
    reads as never-sent, and reporting that as a failure would make
    `infra dr health` red on a perfectly healthy platform."""
    check = report(healthy).get("heartbeat")

    assert check is not None and check.ok
    assert "Prometheus" in check.detail


# -- freeze -------------------------------------------------------------------


def test_the_report_says_when_the_platform_is_frozen(healthy):
    (healthy.data_dir / "FROZEN").write_text("break glass\n")

    result = report(healthy)

    assert result.frozen is True
    assert result.llm_view()["frozen"] is True


def test_a_freeze_does_not_by_itself_make_the_platform_unhealthy(healthy):
    """Freezing is a control the owner pulled on purpose, not a fault."""
    (healthy.data_dir / "FROZEN").write_text("break glass\n")

    assert report(healthy).ok


# -- what the digest carries --------------------------------------------------


def test_the_llm_view_is_structured_and_carries_no_paths_to_key_material(healthy):
    view = report(healthy).llm_view()

    assert set(view) == {"generated_at", "ok", "frozen", "headline", "checks"}
    assert all(set(check) == {"name", "ok", "detail", "age_seconds"} for check in view["checks"])
    assert "keys.txt" not in json.dumps(view)


def test_the_digest_carries_the_report_and_survives_it_failing(healthy, monkeypatch):
    from infra_agent.agent.duties import Duties

    duties = Duties(settings=healthy, runner=object(), now=lambda: NOW)
    assert duties.platform_health()["ok"] is True

    def explode(*_args: Any, **_kwargs: Any):
        raise RuntimeError("the graph directory is on the missing volume")

    monkeypatch.setattr("infra_agent.dr.health.health_report", explode)
    answer = duties.platform_health()

    assert answer["available"] is False
    assert "RuntimeError" in answer["reason"]
