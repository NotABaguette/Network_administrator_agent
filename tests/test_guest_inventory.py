"""Guest discovery from the ESXi snapshots, and the files it generates.

`infra onboard seed-guests` is the only place a guest gets into the seed
inventory without somebody typing an address, so what it offers - and what it
refuses to offer - is worth pinning. The generated Ansible inventory and
Prometheus targets are asserted as data and as files, including the rule that no
credential is ever written into either.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from infra_agent.config import get_settings
from infra_agent.guest_inventory import (
    ANSIBLE_INVENTORY,
    NODE_EXPORTER_PORT,
    PROMETHEUS_TARGETS,
    WINDOWS_EXPORTER_PORT,
    annotation_tags,
    ansible_inventory,
    guest_candidates,
    guest_kind,
    prometheus_targets,
    seed_device_for,
    usable_address,
    write_all,
    write_ansible_inventory,
    write_prometheus_targets,
)
from infra_agent.models.common import DeviceKind, SeedDevice, SeedInventory, Snapshot
from infra_agent.onboarding.cli import app
from infra_agent.store.snapshots import FileSnapshotStore

NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)
DEPLOY = Path(__file__).resolve().parents[1] / "deploy"

ESXI_VMS: list[dict[str, Any]] = [
    {
        "name": "web-01",
        "power_state": "poweredOn",
        "guest_os": "Ubuntu Linux (64-bit)",
        "annotation": "Public web front end.\nguest:linux service:nginx auto:restart",
        "guest_ips": ["10.20.0.11", "fe80::250:56ff:feaa:2"],
    },
    {
        "name": "app-win-01",
        "power_state": "poweredOn",
        "guest_os": "Microsoft Windows Server 2019 (64-bit)",
        "annotation": "guest:windows service:MSSQLSERVER",
        "guest_ips": ["10.20.0.21"],
    },
    {
        # tagged, but VMware Tools has no address for it yet
        "name": "build-01",
        "power_state": "poweredOn",
        "annotation": "guest:linux",
        "guest_ips": ["169.254.3.4"],
    },
    {
        # not tagged: never offered, whatever it runs
        "name": "mgmt-01",
        "power_state": "poweredOn",
        "guest_os": "Ubuntu Linux (64-bit)",
        "annotation": "the platform itself",
        "guest_ips": ["10.10.10.50"],
    },
    {
        # the address is taken from the vNIC when guest_ips is empty
        "name": "db-01",
        "power_state": "poweredOn",
        "annotation": "guest:linux service:postgresql",
        "nics": [{"label": "Network adapter 1", "ips": ["10.20.0.31"]}],
    },
]


def estate(
    tmp_path: Path,
    devices: list[SeedDevice] | None = None,
    vms: list[dict[str, Any]] | None = None,
) -> tuple[Any, SeedInventory]:
    store = FileSnapshotStore(tmp_path / "snapshots")
    store.save(
        Snapshot(
            device="esx-01",
            collector="esxi",
            taken_at=NOW,
            data={"vms": ESXI_VMS if vms is None else vms},
        )
    )
    inventory = SeedInventory(
        devices=devices
        if devices is not None
        else [
            SeedDevice(
                name="esx-01",
                kind=DeviceKind.esxi,
                mgmt_ip="10.10.10.21",
                credential_ref="esx-01",
            )
        ]
    )
    return store, inventory


def guests_inventory() -> SeedInventory:
    return SeedInventory(
        devices=[
            SeedDevice(
                name="esx-01", kind=DeviceKind.esxi, mgmt_ip="10.10.10.21", credential_ref="esx-01"
            ),
            SeedDevice(
                name="web-01",
                kind=DeviceKind.guest_linux,
                mgmt_ip="10.20.0.11",
                credential_ref="web-01",
                tags=["service:nginx", "vm:web-01"],
            ),
            SeedDevice(
                name="app-win-01",
                kind=DeviceKind.guest_windows,
                mgmt_ip="10.20.0.21",
                credential_ref="app-win-01",
                tags=["service:MSSQLSERVER"],
            ),
        ]
    )


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------
def test_annotation_tags_and_kinds():
    tags = annotation_tags("Public web front end.\nguest:linux service:nginx auto:restart")
    assert tags == ["auto:restart", "guest:linux", "service:nginx"]
    assert guest_kind(tags) is DeviceKind.guest_linux
    assert guest_kind(annotation_tags("guest:windows")) is DeviceKind.guest_windows
    assert guest_kind(annotation_tags("just some notes")) is None
    # an explicit tag list (what a vCenter-managed estate would give us) works too
    assert guest_kind(annotation_tags(None, ["guest:windows"])) is DeviceKind.guest_windows


def test_usable_address_skips_what_a_collector_could_not_reach():
    assert usable_address(["169.254.3.4", "10.20.0.11"]) == "10.20.0.11"
    assert usable_address(["fe80::1", "10.20.0.11"]) == "10.20.0.11"
    assert usable_address(["127.0.0.1"]) is None
    assert usable_address([]) is None
    assert usable_address(["not-an-address"]) is None


def test_only_tagged_vms_with_an_address_are_offered(tmp_path: Path):
    store, inventory = estate(tmp_path)
    candidates = {row.vm: row for row in guest_candidates(store, inventory)}

    assert set(candidates) == {"web-01", "app-win-01", "build-01", "db-01"}
    assert "mgmt-01" not in candidates  # not tagged as a guest

    web = candidates["web-01"]
    assert web.kind is DeviceKind.guest_linux
    assert web.address == "10.20.0.11"
    assert web.host == "esx-01"
    assert web.tags == ["auto:restart", "service:nginx"]  # the guest: tag is consumed
    assert web.onboarded is False and web.reason == ""

    assert candidates["app-win-01"].kind is DeviceKind.guest_windows
    assert candidates["db-01"].address == "10.20.0.31"  # from the vNIC


def test_a_vm_without_a_usable_address_is_offered_with_the_reason(tmp_path: Path):
    """Silence would look like "there is no such VM"; the owner needs the why."""
    store, inventory = estate(tmp_path)
    build = next(row for row in guest_candidates(store, inventory) if row.vm == "build-01")

    assert build.address == ""
    assert "VMware Tools" in build.reason


def test_a_guest_already_in_the_inventory_is_marked_not_hidden(tmp_path: Path):
    store, inventory = estate(tmp_path)
    inventory.upsert(
        SeedDevice(
            name="web-01",
            kind=DeviceKind.guest_linux,
            mgmt_ip="10.20.0.11",
            credential_ref="web-01",
        )
    )
    web = next(row for row in guest_candidates(store, inventory) if row.vm == "web-01")

    assert web.onboarded is True
    assert web.reason == "already in the seed inventory"


def test_a_guest_onboarded_under_another_name_is_still_recognised(tmp_path: Path):
    store, inventory = estate(tmp_path)
    inventory.upsert(
        SeedDevice(
            name="web-01.lab",
            kind=DeviceKind.guest_linux,
            mgmt_ip="10.20.0.11",
            credential_ref="web-01.lab",
        )
    )
    web = next(row for row in guest_candidates(store, inventory) if row.vm == "web-01")
    assert web.onboarded is True


def test_nothing_is_offered_without_an_esxi_snapshot(tmp_path: Path):
    store = FileSnapshotStore(tmp_path / "snapshots")
    inventory = SeedInventory(
        devices=[
            SeedDevice(
                name="esx-01", kind=DeviceKind.esxi, mgmt_ip="10.10.10.21", credential_ref="esx-01"
            )
        ]
    )
    assert guest_candidates(store, inventory) == []


def test_the_seed_device_carries_the_tags_the_collector_reads(tmp_path: Path):
    store, inventory = estate(tmp_path)
    web = next(row for row in guest_candidates(store, inventory) if row.vm == "web-01")

    device = seed_device_for(web)
    assert device.name == "web-01"
    assert device.kind is DeviceKind.guest_linux
    assert device.mgmt_ip == "10.20.0.11"
    assert device.credential_ref == "web-01"
    assert device.tags == ["auto:restart", "host:esx-01", "service:nginx", "vm:web-01"]

    renamed = seed_device_for(web, "web-01.lab")
    assert renamed.name == "web-01.lab" and renamed.credential_ref == "web-01.lab"
    assert "vm:web-01" in renamed.tags  # still points at the VM it came from


# --------------------------------------------------------------------------
# generated files
# --------------------------------------------------------------------------
def test_the_ansible_inventory_groups_the_guests_by_kind():
    data = ansible_inventory(guests_inventory())
    groups = data["all"]["children"]

    assert set(groups) == {"guest_linux", "guest_windows"}
    assert groups["guest_linux"]["hosts"]["web-01"]["ansible_host"] == "10.20.0.11"
    assert groups["guest_linux"]["hosts"]["web-01"]["infra_tags"] == ["service:nginx", "vm:web-01"]
    assert groups["guest_linux"]["vars"]["exporter_port"] == NODE_EXPORTER_PORT
    assert groups["guest_windows"]["hosts"]["app-win-01"]["ansible_host"] == "10.20.0.21"
    assert groups["guest_windows"]["vars"]["ansible_connection"] == "winrm"
    assert groups["guest_windows"]["vars"]["ansible_port"] == 5986
    assert groups["guest_windows"]["vars"]["exporter_port"] == WINDOWS_EXPORTER_PORT
    # the ESXi host is not a guest
    assert "esx-01" not in json.dumps(data)


def test_the_generated_inventory_never_carries_a_credential(tmp_path: Path):
    """It is committed; the platform's secrets live in SOPS."""
    inventory = guests_inventory()
    inventory.devices[1].credential_ref = "web-01"
    path = write_ansible_inventory(inventory, tmp_path / "guests.yml")
    text = path.read_text()

    assert "generated by" in text.splitlines()[0]
    for forbidden in (
        "ansible_password",
        "ansible_ssh_pass",
        "ansible_winrm_password",
        "private_key",
        "credential_ref",
    ):
        assert forbidden not in text
    assert yaml.safe_load(text)["all"]["children"]["guest_linux"]["hosts"]["web-01"]


def test_the_prometheus_targets_point_at_the_right_exporter(tmp_path: Path):
    rows = prometheus_targets(guests_inventory())

    assert rows == [
        {
            "targets": [f"10.20.0.21:{WINDOWS_EXPORTER_PORT}"],
            "labels": {
                "device": "app-win-01",
                "platform": "guest",
                "os": "windows",
                "exporter": "windows_exporter",
            },
        },
        {
            "targets": [f"10.20.0.11:{NODE_EXPORTER_PORT}"],
            "labels": {
                "device": "web-01",
                "platform": "guest",
                "os": "linux",
                "exporter": "node_exporter",
            },
        },
    ]
    path = write_prometheus_targets(guests_inventory(), tmp_path / "guests.json")
    assert json.loads(path.read_text()) == rows


def test_write_all_writes_both_files_under_the_repository_root(tmp_path: Path):
    written = write_all(guests_inventory(), root=tmp_path)

    assert written == [tmp_path / ANSIBLE_INVENTORY, tmp_path / PROMETHEUS_TARGETS]
    assert all(path.exists() for path in written)
    assert yaml.safe_load((tmp_path / ANSIBLE_INVENTORY).read_text())["all"]


def test_an_estate_with_no_guests_writes_empty_files(tmp_path: Path):
    written = write_all(SeedInventory(), root=tmp_path)
    assert json.loads((tmp_path / PROMETHEUS_TARGETS).read_text()) == []
    groups = yaml.safe_load(written[0].read_text())["all"]["children"]
    assert groups["guest_linux"]["hosts"] == {}


# --------------------------------------------------------------------------
# deployment wiring
# --------------------------------------------------------------------------
def test_prometheus_scrapes_the_generated_target_file():
    config = yaml.safe_load((DEPLOY / "prometheus" / "prometheus.yml").read_text())
    jobs = {job["job_name"]: job for job in config["scrape_configs"]}

    assert "guests" in jobs
    files = jobs["guests"]["file_sd_configs"][0]["files"]
    assert files == [f"/etc/prometheus/targets/{PROMETHEUS_TARGETS.name}"]
    assert (DEPLOY / PROMETHEUS_TARGETS.relative_to("deploy")).exists()


def test_the_playbooks_install_the_exporters_the_targets_expect():
    root = Path(__file__).resolve().parents[1] / "ansible"
    linux = yaml.safe_load((root / "playbooks" / "node_exporter.yml").read_text())[0]
    windows = yaml.safe_load((root / "playbooks" / "windows_exporter.yml").read_text())[0]

    assert linux["hosts"] == "guest_linux"
    assert linux["vars"]["exporter_port"] == NODE_EXPORTER_PORT
    assert windows["hosts"] == "guest_windows"
    assert windows["vars"]["exporter_port"] == WINDOWS_EXPORTER_PORT
    # the generated inventory is what they run against
    assert "inventory/guests.yml" in (root / "README.md").read_text()
    assert (root / "inventory" / ANSIBLE_INVENTORY.name).exists()


def test_the_playbooks_carry_no_credentials():
    root = Path(__file__).resolve().parents[1] / "ansible"
    for path in sorted(root.rglob("*.yml")) + [root / "ansible.cfg"]:
        text = path.read_text()
        for forbidden in ("ansible_password", "ansible_ssh_pass", "BEGIN OPENSSH", "vault_"):
            assert forbidden not in text, path


# --------------------------------------------------------------------------
# the CLI
# --------------------------------------------------------------------------
@pytest.fixture
def cli_estate(tmp_path: Path, monkeypatch):
    store, inventory = estate(tmp_path)
    seed = tmp_path / "seed.yaml"
    inventory.save(seed)
    monkeypatch.setenv("INFRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INFRA_SEED_INVENTORY", str(seed))
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


def test_seed_guests_lists_the_candidates_and_stops(cli_estate: Path):
    result = CliRunner().invoke(app, ["seed-guests", "--dry-run"], catch_exceptions=False)

    assert result.exit_code == 0
    assert "web-01" in result.stdout and "app-win-01" in result.stdout
    assert "guest_linux" in result.stdout
    assert "mgmt-01" not in result.stdout
    # build-01 is listed even though it has no address, so the owner sees why
    assert "build-01" in result.stdout
    assert "ready" in result.stdout


class FakeSecrets:
    """Stands in for the SOPS store, which needs `sops` and an age key."""

    stored: dict[str, dict[str, Any]] = {}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def available(self) -> bool:
        return True

    def update(self, name: str, key: str, value: dict[str, Any]) -> None:
        FakeSecrets.stored[f"{name}/{key}"] = value


def test_add_device_records_the_ssh_key_a_guest_authenticates_with(cli_estate: Path, monkeypatch):
    """The guest account template disables password authentication, so a
    credential with no key path would be unusable the moment it is created."""
    monkeypatch.setattr("infra_agent.onboarding.cli.SecretsStore", FakeSecrets)
    monkeypatch.setattr("infra_agent.onboarding.cli.getpass", lambda prompt="": "")
    FakeSecrets.stored.clear()

    result = CliRunner().invoke(
        app,
        [
            "add-device",
            "guest_linux",
            "10.20.0.11",
            "--name",
            "web-01",
            "--ssh-key",
            "/home/infra/.ssh/infra-agent",
            "--tags",
            "vm:web-01,service:nginx",
            "--skip-probe",
        ],
        input="infra-ro\n",
        catch_exceptions=False,
    )

    assert result.exit_code == 0, result.stdout
    assert FakeSecrets.stored["devices/web-01"] == {
        "username": "infra-ro",
        "password": None,
        "token": None,
        "ssh_key_path": "/home/infra/.ssh/infra-agent",
    }
    device = SeedInventory.load(cli_estate / "seed.yaml").get("web-01")
    assert device is not None
    assert device.kind is DeviceKind.guest_linux
    assert device.tags == ["vm:web-01", "service:nginx"]


def test_seed_guests_says_what_to_do_when_nothing_is_tagged(tmp_path: Path, monkeypatch):
    seed = tmp_path / "seed.yaml"
    SeedInventory().save(seed)
    monkeypatch.setenv("INFRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INFRA_SEED_INVENTORY", str(seed))
    get_settings.cache_clear()
    try:
        result = CliRunner().invoke(app, ["seed-guests"], catch_exceptions=False)
        assert result.exit_code == 0
        assert "no candidates" in result.stdout
        assert "guest:linux" in result.stdout
    finally:
        get_settings.cache_clear()


def test_annotation_tags_keep_the_case_of_the_value_and_normalise_the_key():
    """`vm:Web-01` has to match a graph node id, and a Windows service really
    is called `MSSQLSERVER`; only the key is a keyword."""
    tags = annotation_tags("Guest:Windows VM:Web-01 Service:MSSQLSERVER auto:restart")

    assert tags == ["auto:restart", "guest:Windows", "service:MSSQLSERVER", "vm:Web-01"]
    assert guest_kind(tags) is DeviceKind.guest_windows


def test_a_mixed_case_guest_tag_is_not_copied_onto_the_seed_device(tmp_path: Path):
    store, inventory = estate(
        tmp_path,
        vms=[
            {
                "name": "Web-01",
                "power_state": "poweredOn",
                "annotation": "Guest:linux Service:Nginx",
                "guest_ips": ["10.20.0.77"],
            }
        ],
    )
    (candidate,) = guest_candidates(store, inventory)

    assert candidate.kind is DeviceKind.guest_linux
    assert candidate.tags == ["service:Nginx"]
    assert seed_device_for(candidate).tags == ["host:esx-01", "service:Nginx", "vm:Web-01"]


def test_the_windows_playbook_is_idempotent_and_pins_the_scraper():
    """A second run must not fail because Windows cleared C:\\Windows\\Temp, and
    the exporter port must not be open to the whole estate."""
    root = Path(__file__).resolve().parents[1] / "ansible"
    play = yaml.safe_load((root / "playbooks" / "windows_exporter.yml").read_text())[0]
    tasks = {task["name"]: task for task in play["tasks"]}

    install = tasks["Install windows_exporter"]
    assert "existing.exists" in install["when"]
    firewall = tasks["Allow the scrape from mgmt-01 only"]
    assert firewall["community.windows.win_firewall_rule"]["remoteip"] == "{{ prometheus_address }}"
    assert "default('any')" not in yaml.safe_dump(play)
    assert any(
        "assert" in str(task) and "prometheus_address" in str(task) for task in play["tasks"]
    )


def test_add_device_asks_for_the_api_password_even_with_an_ssh_key(cli_estate: Path, monkeypatch):
    """`--ssh-key` is what the ESXi host-config backup needs, but the ESXi
    collector still logs into hostd with the password: prompting for a key
    passphrase there would leave the API credential empty."""
    prompts: list[str] = []
    monkeypatch.setattr("infra_agent.onboarding.cli.SecretsStore", FakeSecrets)
    monkeypatch.setattr(
        "infra_agent.onboarding.cli.getpass",
        lambda prompt="": prompts.append(prompt) or "api-password",
    )
    FakeSecrets.stored.clear()

    result = CliRunner().invoke(
        app,
        [
            "add-device",
            "esxi",
            "10.10.10.21",
            "--name",
            "esx-01",
            "--ssh-key",
            "/home/infra/.ssh/infra-agent",
            "--skip-probe",
        ],
        input="infra-ro\n",
        catch_exceptions=False,
    )

    assert result.exit_code == 0, result.stdout
    assert prompts == ["password: "]
    assert FakeSecrets.stored["devices/esx-01"]["password"] == "api-password"
    assert FakeSecrets.stored["devices/esx-01"]["ssh_key_path"] == "/home/infra/.ssh/infra-agent"


def test_add_device_still_calls_it_a_passphrase_for_a_guest(cli_estate: Path, monkeypatch):
    prompts: list[str] = []
    monkeypatch.setattr("infra_agent.onboarding.cli.SecretsStore", FakeSecrets)
    monkeypatch.setattr(
        "infra_agent.onboarding.cli.getpass", lambda prompt="": prompts.append(prompt) or ""
    )
    FakeSecrets.stored.clear()

    result = CliRunner().invoke(
        app,
        [
            "add-device",
            "guest_linux",
            "10.20.0.11",
            "--name",
            "web-01",
            "--ssh-key",
            "/home/infra/.ssh/infra-agent",
            "--skip-probe",
        ],
        input="infra-ro\n",
        catch_exceptions=False,
    )

    assert result.exit_code == 0, result.stdout
    assert prompts == ["key passphrase (blank if the key has none): "]
