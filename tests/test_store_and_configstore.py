import subprocess

from infra_agent.configstore.git_store import ConfigGitStore
from infra_agent.models.common import DeviceKind, SeedDevice, SeedInventory, Snapshot
from infra_agent.store.snapshots import FileSnapshotStore, diff_structures


def test_diff_matches_lists_by_name():
    old = {"vlans": [{"name": "10", "ports": ["Gi1"]}, {"name": "20", "ports": []}]}
    new = {"vlans": [{"name": "20", "ports": ["Gi2"]}, {"name": "30", "ports": []}]}
    ops = {(c.op, c.path) for c in diff_structures(old, new)}
    assert ("remove", "vlans.10") in ops
    assert ("add", "vlans.30") in ops
    assert ("add", "vlans.20.ports[0]") in ops


def test_snapshot_store_roundtrip(tmp_path):
    store = FileSnapshotStore(tmp_path)
    assert store.latest("sw", "cisco") is None
    store.save(Snapshot(device="sw", collector="cisco", data={"a": 1}))
    store.save(Snapshot(device="sw", collector="cisco", data={"a": 2}))
    assert store.latest("sw", "cisco").data == {"a": 2}
    assert len(store.history("sw", "cisco")) == 2


def test_config_store_commits_only_on_change(tmp_path):
    cfg = ConfigGitStore(tmp_path / "configs")
    sha1 = cfg.write("sw-01", "running-config.txt", "hostname sw-01\n")
    assert sha1
    assert cfg.write("sw-01", "running-config.txt", "hostname sw-01\n") is None
    sha2 = cfg.write("sw-01", "running-config.txt", "hostname sw-01\nntp server 10.0.0.5\n")
    assert sha2 and sha2 != sha1
    assert len(cfg.history("sw-01")) == 2
    assert "ntp server" in cfg.diff("sw-01", "running-config.txt", sha1, sha2)
    log = subprocess.run(
        ["git", "-C", str(tmp_path / "configs"), "log", "--oneline"], capture_output=True, text=True
    ).stdout
    assert log.count("\n") == 3  # init + 2 changes


def test_seed_inventory_roundtrip(tmp_path):
    path = tmp_path / "seed.yaml"
    inv = SeedInventory.load(path)
    assert inv.devices == []
    inv.upsert(
        SeedDevice(
            name="fw-01",
            kind=DeviceKind.fortigate,
            mgmt_ip="10.0.0.1",
            credential_ref="fw-01",
            tags=["edge"],
        )
    )
    inv.upsert(
        SeedDevice(
            name="fw-01", kind=DeviceKind.fortigate, mgmt_ip="10.0.0.2", credential_ref="fw-01"
        )
    )
    inv.save(path)
    again = SeedInventory.load(path)
    assert len(again.devices) == 1
    assert again.get("fw-01").mgmt_ip == "10.0.0.2"
    assert again.by_kind(DeviceKind.esxi) == []
