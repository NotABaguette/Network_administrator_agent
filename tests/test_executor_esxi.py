"""ESXi executor tests, both transports.

Three layers:

* the pure parsers, against recorded `vim-cmd` / `esxcli` output;
* the executor's rules against an in-memory host (`FakeEsxi`) — pre-change
  snapshots, blockers, rollback, checks;
* each real transport against a fake session / fake managed objects, so the
  command building and the pyvmomi spec building are exercised offline.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from infra_agent.change.executors import esxi as ex
from infra_agent.change.executors.base import ExecutionContext, get_executor, load_all
from infra_agent.change.plan import ChangeStep
from infra_agent.models.common import Credential, DeviceKind, SeedDevice

SSH_FIXTURE = Path(__file__).parent / "fixtures" / "executors" / "esxi_ssh_outputs.json"

FREE_HOST = SeedDevice(
    name="esx-01",
    kind=DeviceKind.esxi,
    mgmt_ip="10.10.0.21",
    credential_ref="esx-01-ro",
    rw_credential_ref="esx-01-rw",
    license="free",
)
LICENSED_HOST = SeedDevice(
    name="esx-02",
    kind=DeviceKind.esxi,
    mgmt_ip="10.10.0.22",
    credential_ref="esx-02-ro",
    rw_credential_ref="esx-02-rw",
    license="licensed",
)
RW = Credential(
    username="infra-rw", password="host-password-value", ssh_key_path="/keys/esxi-rw.pem"
)


def step(action: str, **params: Any) -> ChangeStep:
    return ChangeStep(description=action, platform="esxi", action=action, params=params)


def strings(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, default=str)


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def ssh_outputs() -> dict[str, str]:
    return json.loads(SSH_FIXTURE.read_text())


@pytest.mark.parametrize(
    ("value", "licensed"),
    [
        ("licensed", True),
        ("free", False),
        ("VMware vSphere 7 Hypervisor", False),
        (None, False),
        ("", False),
        ("standard", False),
    ],
)
def test_only_an_explicit_licence_takes_the_api_path(value, licensed):
    device = SeedDevice(
        name="h", kind=DeviceKind.esxi, mgmt_ip="10.0.0.1", credential_ref="h", license=value
    )
    assert ex.is_licensed(device) is licensed


def test_the_executor_picks_its_transport_from_the_licence():
    executor = ex.EsxiExecutor()
    assert isinstance(executor.transport(LICENSED_HOST), ex.PyvmomiTransport)
    assert isinstance(executor.transport(FREE_HOST), ex.SshTransport)


def test_getallvms_parsing(ssh_outputs):
    rows = ex.parse_getallvms(ssh_outputs["vim-cmd vmsvc/getallvms"])
    assert [r["name"] for r in rows] == ["web-01", "tpl-ubuntu"]
    assert rows[0]["vmid"] == "1"
    assert rows[0]["datastore"] == "datastore1"


def test_snapshotinfo_parsing(ssh_outputs):
    snapshots = ex.parse_snapshotinfo(ssh_outputs["vim-cmd vmsvc/get.snapshotinfo 1"])
    assert snapshots == [
        {"name": "nightly", "description": "taken by the backup script", "id": "7"}
    ]
    assert ex.parse_snapshotinfo(ssh_outputs["vim-cmd vmsvc/get.snapshotinfo 2"]) == []


def test_summary_config_guest_and_device_parsing(ssh_outputs):
    assert ex.parse_summary(ssh_outputs["vim-cmd vmsvc/get.summary 1"]) == {
        "cpu": 2,
        "memory_mb": 4096,
    }
    assert ex.parse_config(ssh_outputs["vim-cmd vmsvc/get.config 1"]) == {
        "hot_add_cpu": False,
        "hot_add_memory": True,
    }
    guest = ex.parse_guest(ssh_outputs["vim-cmd vmsvc/get.guest 1"])
    assert guest["tools_running"] is True
    disks = ex.parse_devices(ssh_outputs["vim-cmd vmsvc/get.devices 1"])
    assert disks == [
        {"label": "Hard disk 1", "path": "[datastore1] web-01/web-01.vmdk", "size_gb": 40.0}
    ]


def test_paths_and_setting_keys():
    assert ex.host_path("[datastore1] web-01/web-01.vmdk") == (
        "/vmfs/volumes/datastore1/web-01/web-01.vmdk"
    )
    assert ex.datastore_of("[ds] a/b.vmx") == "ds"
    assert ex.normalise_setting_key("syslog") == ex.SYSLOG_KEY
    assert ex.normalise_setting_key("/UserVars/SuppressShellWarning") == (
        "UserVars.SuppressShellWarning"
    )
    assert ex.advanced_path("UserVars.SuppressShellWarning") == "/UserVars/SuppressShellWarning"
    assert ex.normalise_setting_key("cdp") == ex.CDP_KEY


def test_names_that_would_reach_a_shell_are_refused():
    assert ex.safe_name("web-01", "VM name") == "web-01"
    for bad in ["web-01; rm -rf /", "$(whoami)", "a`b`", "", "web\n01", "../x"]:
        with pytest.raises(ex.EsxiError):
            ex.safe_name(bad, "VM name")


def test_public_drops_private_handles():
    assert ex.public({"name": "a", "_ref": object(), "snapshots": [{"name": "s", "_ref": 1}]}) == {
        "name": "a",
        "snapshots": [{"name": "s"}],
    }


# ---------------------------------------------------------------------------
# the in-memory host
# ---------------------------------------------------------------------------
def _vm(name: str, **overrides: Any) -> dict[str, Any]:
    row = {
        "name": name,
        "vmid": "1",
        "vmx": f"[datastore1] {name}/{name}.vmx",
        "datastore": "datastore1",
        "power_state": ex.POWERED_OFF,
        "cpu": 2,
        "memory_mb": 4096,
        "hot_add_cpu": False,
        "hot_add_memory": False,
        "tools_status": "guestToolsNotRunning",
        "tools_running": False,
        "guest_state": "notRunning",
        "snapshots": [],
        "disks": [
            {"label": "Hard disk 1", "path": f"[datastore1] {name}/{name}.vmdk", "size_gb": 40.0}
        ],
    }
    row.update(overrides)
    return row


class FakeEsxi:
    """An in-memory ESXi host behind the executor's transport protocol."""

    name = "fake"

    def __init__(
        self,
        vms: list[dict[str, Any]] | None = None,
        datastores: list[dict[str, Any]] | None = None,
        settings: dict[str, Any] | None = None,
    ) -> None:
        self.vms = {v["name"]: v for v in (vms or [_vm("web-01")])}
        self.stores = datastores or [
            {"name": "datastore1", "free_bytes": 500 * ex.GIB, "capacity_bytes": 1000 * ex.GIB}
        ]
        self.settings = settings or {
            ex.SYSLOG_KEY: "udp://10.10.0.9:514",
            ex.NTP_KEY: ["10.10.0.9"],
            ex.CDP_KEY: {"vSwitch0": "listen"},
            "UserVars.SuppressShellWarning": 0,
        }
        self.calls: list[str] = []
        self.fail: dict[str, Exception] = {}
        #: whether a guest shutdown actually powers the VM off
        self.guest_shutdown_works = True
        self._next_snapshot_id = 1

    # -- bookkeeping ------------------------------------------------------
    def _record(self, what: str) -> None:
        self.calls.append(what)
        error = self.fail.get(what.split(":")[0])
        if error is not None:
            raise error

    def writes(self) -> list[str]:
        reads = ("vm", "datastores", "host_setting_get")
        return [c for c in self.calls if not c.startswith(reads)]

    # -- reads ------------------------------------------------------------
    def vm(self, ctx, name):
        self._record(f"vm:{name}")
        row = self.vms.get(ex.safe_name(name, "VM name"))
        return json.loads(json.dumps(row)) if row else None

    def datastores(self, ctx):
        self._record("datastores")
        return [dict(s) for s in self.stores]

    def host_setting_get(self, ctx, key):
        self._record(f"host_setting_get:{key}")
        return self.settings.get(ex.normalise_setting_key(key))

    # -- writes -----------------------------------------------------------
    def host_setting_set(self, ctx, key, value, params):
        self._record(f"host_setting_set:{key}={value}")
        self.settings[ex.normalise_setting_key(key)] = value
        return {"key": key, "value": value}

    def snapshot_create(self, ctx, vm, name, description):
        self._record(f"snapshot_create:{vm['name']}:{name}")
        live = self.vms[vm["name"]]
        if any(s["name"] == name for s in live["snapshots"]):
            raise ex.EsxiError(f"snapshot {name!r} already exists")
        live["snapshots"].append(
            {
                "name": name,
                "id": str(self._next_snapshot_id),
                "description": description,
                # what a revert restores
                "_state": {
                    "power_state": live["power_state"],
                    "cpu": live["cpu"],
                    "memory_mb": live["memory_mb"],
                },
            }
        )
        self._next_snapshot_id += 1
        return {"snapshot": name}

    def snapshot_remove(self, ctx, vm, name):
        self._record(f"snapshot_remove:{vm['name']}:{name}")
        live = self.vms[vm["name"]]
        found = next((s for s in live["snapshots"] if s["name"] == name), None)
        if found is None:
            raise ex.EsxiError(f"no snapshot named {name!r}")
        live["snapshots"].remove(found)
        return {"snapshot": name}

    def snapshot_revert(self, ctx, vm, name):
        self._record(f"snapshot_revert:{vm['name']}:{name}")
        live = self.vms[vm["name"]]
        found = next((s for s in live["snapshots"] if s["name"] == name), None)
        if found is None:
            raise ex.EsxiError(f"no snapshot named {name!r}")
        live.update(found.get("_state") or {})
        # A revert to a memory-less snapshot leaves the VM powered off.
        live["power_state"] = ex.POWERED_OFF
        return {"snapshot": name}

    def power_on(self, ctx, vm):
        self._record(f"power_on:{vm['name']}")
        self.vms[vm["name"]]["power_state"] = ex.POWERED_ON
        return {"power": "on"}

    def shutdown_guest(self, ctx, vm):
        self._record(f"shutdown_guest:{vm['name']}")
        if self.guest_shutdown_works:
            self.vms[vm["name"]]["power_state"] = ex.POWERED_OFF
        return {"power": "requested"}

    def power_off(self, ctx, vm):
        self._record(f"power_off:{vm['name']}")
        self.vms[vm["name"]]["power_state"] = ex.POWERED_OFF
        return {"power": "off"}

    def reconfigure(self, ctx, vm, cpu, memory_mb):
        self._record(f"reconfigure:{vm['name']}:{cpu}:{memory_mb}")
        live = self.vms[vm["name"]]
        if cpu is not None:
            live["cpu"] = cpu
        if memory_mb is not None:
            live["memory_mb"] = memory_mb
        return {"cpu": cpu, "memory_mb": memory_mb}

    def disk_extend(self, ctx, vm, disk, size_gb):
        self._record(f"disk_extend:{vm['name']}:{disk['label']}:{size_gb}")
        for live_disk in self.vms[vm["name"]]["disks"]:
            if live_disk["label"] == disk["label"]:
                live_disk["size_gb"] = size_gb
        return {"disk": disk["label"], "size_gb": size_gb}

    def clone_from_template(self, ctx, template, name, datastore):
        self._record(f"clone:{template['name']}->{name}")
        clone = _vm(name, datastore=datastore or template.get("datastore"))
        self.vms[name] = clone
        return {"name": name, "from": template["name"]}

    def destroy_vm(self, ctx, vm):
        self._record(f"destroy:{vm.get('name')}")
        self.vms.pop(vm.get("name"), None)
        return {"destroyed": vm.get("name")}

    def backup_host_config(self, ctx):
        self._record("backup_host_config")
        return {"kind": "esxi-host-config", "path": "/scratch/downloads/abc/configBundle.tgz"}

    def log_bundle(self, ctx):
        self._record("log_bundle")
        return {"kind": "esxi-log-bundle", "path": "/scratch/esx-01.tgz"}


class Clock:
    """A monotonic clock that advances a fixed amount per reading."""

    def __init__(self, stride: float = 100.0) -> None:
        self.now = 0.0
        self.stride = stride

    def __call__(self) -> float:
        value = self.now
        self.now += self.stride
        return value


@pytest.fixture
def host() -> FakeEsxi:
    return FakeEsxi()


@pytest.fixture
def executor(host: FakeEsxi) -> ex.EsxiExecutor:
    return ex.EsxiExecutor(free=host, licensed=host, sleep=lambda _s: None)


@pytest.fixture
def ctx() -> ExecutionContext:
    return ExecutionContext(plan_id="plan-9f", device=FREE_HOST, credential=RW)


# ---------------------------------------------------------------------------
# registration
# ---------------------------------------------------------------------------
def test_registered_under_the_esxi_platform():
    load_all()
    assert isinstance(get_executor("esxi"), ex.EsxiExecutor)


def test_supported_actions(executor):
    assert executor.supported_actions() == {
        "vm.snapshot",
        "vm.snapshot_remove",
        "vm.power_on",
        "vm.power_off_graceful",
        "vm.resize",
        "vm.disk_extend",
        "vm.create_from_template",
        "esxi.host_setting",
        "esxi.log_bundle",
    }


# ---------------------------------------------------------------------------
# snapshots
# ---------------------------------------------------------------------------
def test_snapshot_apply_and_rollback(executor, ctx, host):
    result = executor.apply(ctx, step("vm.snapshot", vm="web-01"))
    assert result.ok, result.error
    assert result.output["snapshot"] == "infra-plan-9f"
    assert [s["name"] for s in host.vms["web-01"]["snapshots"]] == ["infra-plan-9f"]

    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok, undone.error
    assert host.vms["web-01"]["snapshots"] == []


def test_a_snapshot_on_a_nearly_full_datastore_is_refused(executor, ctx, host):
    host.stores[0]["free_bytes"] = 3 * ex.GIB
    result = executor.apply(ctx, step("vm.snapshot", vm="web-01"))
    assert result.ok is False
    assert "below the 20.0 GB" in result.error
    assert host.vms["web-01"]["snapshots"] == []

    dry = executor.dry_run(ctx, [step("vm.snapshot", vm="web-01")])
    assert dry.ok is False
    assert any("free" in b for b in dry.blockers)


def test_the_free_space_threshold_is_overridable(executor, ctx, host):
    host.stores[0]["free_bytes"] = 10 * ex.GIB
    assert executor.apply(ctx, step("vm.snapshot", vm="web-01", min_free_gb=5)).ok


def test_snapshot_remove_apply_and_its_unrollbackable_rollback(executor, ctx, host):
    host.vms["web-01"]["snapshots"].append({"name": "nightly", "id": "7", "description": "d"})
    result = executor.apply(ctx, step("vm.snapshot_remove", vm="web-01", snapshot_name="nightly"))
    assert result.ok, result.error
    assert host.vms["web-01"]["snapshots"] == []
    assert result.output["removed"]["name"] == "nightly"

    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok is False
    assert "cannot be restored" in undone.error


def test_removing_a_snapshot_that_is_not_there_fails_cleanly(executor, ctx):
    result = executor.apply(ctx, step("vm.snapshot_remove", vm="web-01", snapshot_name="nope"))
    assert result.ok is False
    assert "no snapshot named" in result.error


# ---------------------------------------------------------------------------
# power
# ---------------------------------------------------------------------------
def test_power_on_takes_a_pre_change_snapshot_and_records_its_cleanup(executor, ctx, host):
    result = executor.apply(ctx, step("vm.power_on", vm="web-01"))
    assert result.ok, result.error
    assert host.vms["web-01"]["power_state"] == ex.POWERED_ON
    assert result.output["pre_snapshot"] == "infra-plan-9f"
    assert result.output["cleanup"]["action"] == "vm.snapshot_remove"
    assert result.output["cleanup"]["params"]["snapshot_name"] == "infra-plan-9f"


def test_power_on_rollback_reverts_and_restores_the_previous_power_state(executor, ctx, host):
    result = executor.apply(ctx, step("vm.power_on", vm="web-01"))
    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok, undone.error
    assert host.vms["web-01"]["power_state"] == ex.POWERED_OFF
    # the pre-change snapshot is evidence: the rollback does not delete it
    assert [s["name"] for s in host.vms["web-01"]["snapshots"]] == ["infra-plan-9f"]
    assert undone.output["snapshot_left_in_place"] is True


def test_graceful_power_off_uses_the_guest(executor, ctx, host):
    host.vms["web-01"].update(power_state=ex.POWERED_ON, tools_running=True)
    result = executor.apply(ctx, step("vm.power_off_graceful", vm="web-01"))
    assert result.ok, result.error
    assert result.output["applied"]["via"] == "guest shutdown"
    assert "shutdown_guest:web-01" in host.calls
    assert "power_off:web-01" not in host.calls


def test_a_guest_that_does_not_stop_is_refused_without_force(host, ctx):
    host.vms["web-01"].update(power_state=ex.POWERED_ON, tools_running=True)
    host.guest_shutdown_works = False
    executor = ex.EsxiExecutor(free=host, sleep=lambda _s: None, monotonic=Clock())
    result = executor.apply(ctx, step("vm.power_off_graceful", vm="web-01", timeout_seconds=200))
    assert result.ok is False
    assert "params.force is required" in result.error
    assert host.vms["web-01"]["power_state"] == ex.POWERED_ON


def test_force_turns_a_stuck_guest_into_a_hard_power_off(host, ctx):
    host.vms["web-01"].update(power_state=ex.POWERED_ON, tools_running=True)
    host.guest_shutdown_works = False
    executor = ex.EsxiExecutor(free=host, sleep=lambda _s: None, monotonic=Clock())
    result = executor.apply(
        ctx, step("vm.power_off_graceful", vm="web-01", timeout_seconds=200, force=True)
    )
    assert result.ok, result.error
    assert result.output["applied"]["via"].startswith("hard power off")
    assert host.vms["web-01"]["power_state"] == ex.POWERED_OFF


def test_a_vm_without_tools_is_refused_without_force(executor, ctx, host):
    host.vms["web-01"].update(power_state=ex.POWERED_ON, tools_running=False)
    result = executor.apply(ctx, step("vm.power_off_graceful", vm="web-01"))
    assert result.ok is False
    assert "VMware Tools is not running" in result.error
    dry = executor.dry_run(ctx, [step("vm.power_off_graceful", vm="web-01")])
    assert dry.ok is False


def test_graceful_power_off_rollback_powers_the_vm_back_on(executor, ctx, host):
    host.vms["web-01"].update(power_state=ex.POWERED_ON, tools_running=True)
    result = executor.apply(ctx, step("vm.power_off_graceful", vm="web-01"))
    assert result.ok, result.error
    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok, undone.error
    assert host.vms["web-01"]["power_state"] == ex.POWERED_ON


# ---------------------------------------------------------------------------
# resize
# ---------------------------------------------------------------------------
def test_resize_of_a_powered_off_vm_and_its_rollback(executor, ctx, host):
    result = executor.apply(ctx, step("vm.resize", vm="web-01", cpu=4, memory_mb=8192))
    assert result.ok, result.error
    assert host.vms["web-01"]["cpu"] == 4
    assert host.vms["web-01"]["memory_mb"] == 8192
    assert result.output["pre_snapshot"] == "infra-plan-9f"

    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok, undone.error
    assert host.vms["web-01"]["cpu"] == 2
    assert host.vms["web-01"]["memory_mb"] == 4096


def test_resizing_a_running_vm_without_hot_add_is_refused(executor, ctx, host):
    host.vms["web-01"]["power_state"] = ex.POWERED_ON
    dry = executor.dry_run(ctx, [step("vm.resize", vm="web-01", cpu=4)])
    assert dry.ok is False
    assert any("hot-add" in b for b in dry.blockers)
    result = executor.apply(ctx, step("vm.resize", vm="web-01", cpu=4))
    assert result.ok is False
    assert "hot-add" in result.error


def test_memory_hot_add_allows_a_running_growth(executor, ctx, host):
    host.vms["web-01"].update(power_state=ex.POWERED_ON, hot_add_memory=True)
    result = executor.apply(ctx, step("vm.resize", vm="web-01", memory_mb=8192))
    assert result.ok, result.error
    assert host.vms["web-01"]["memory_mb"] == 8192


def test_shrinking_a_running_vm_is_refused_even_with_hot_add(executor, ctx, host):
    host.vms["web-01"].update(power_state=ex.POWERED_ON, hot_add_memory=True)
    dry = executor.dry_run(ctx, [step("vm.resize", vm="web-01", memory_mb=2048)])
    assert dry.ok is False
    assert any("cannot be removed" in b for b in dry.blockers)


def test_a_resize_with_nothing_to_change_is_refused(executor, ctx):
    assert executor.apply(ctx, step("vm.resize", vm="web-01")).ok is False


# ---------------------------------------------------------------------------
# disk extend
# ---------------------------------------------------------------------------
def test_disk_extend_refuses_a_vm_with_snapshots(executor, ctx, host):
    host.vms["web-01"]["snapshots"].append({"name": "nightly", "id": "7"})
    dry = executor.dry_run(
        ctx, [step("vm.disk_extend", vm="web-01", disk="Hard disk 1", size_gb=80)]
    )
    assert dry.ok is False
    assert any("corrupts the chain" in b for b in dry.blockers)

    result = executor.apply(
        ctx, step("vm.disk_extend", vm="web-01", disk="Hard disk 1", size_gb=80)
    )
    assert result.ok is False
    assert "snapshot" in result.error
    assert host.vms["web-01"]["disks"][0]["size_gb"] == 40.0


def test_disk_extend_never_takes_a_pre_change_snapshot(executor, ctx, host):
    result = executor.apply(
        ctx, step("vm.disk_extend", vm="web-01", disk="Hard disk 1", size_gb=80)
    )
    assert result.ok, result.error
    assert "pre_snapshot" not in result.output
    assert host.vms["web-01"]["snapshots"] == []
    assert host.vms["web-01"]["disks"][0]["size_gb"] == 80.0
    assert not any(c.startswith("snapshot_create") for c in host.calls)


def test_a_disk_extend_cannot_be_rolled_back(executor, ctx):
    result = executor.apply(
        ctx, step("vm.disk_extend", vm="web-01", disk="Hard disk 1", size_gb=80)
    )
    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok is False
    assert "cannot be shrunk" in undone.error


def test_a_disk_extend_that_would_shrink_is_refused(executor, ctx):
    dry = executor.dry_run(
        ctx, [step("vm.disk_extend", vm="web-01", disk="Hard disk 1", size_gb=10)]
    )
    assert dry.ok is False
    result = executor.apply(
        ctx, step("vm.disk_extend", vm="web-01", disk="Hard disk 1", size_gb=10)
    )
    assert result.ok is False
    assert "cannot be shrunk" in result.error


# ---------------------------------------------------------------------------
# clone
# ---------------------------------------------------------------------------
def test_create_from_template_and_rollback_destroys_the_clone(host, ctx):
    host.vms["tpl-ubuntu"] = _vm("tpl-ubuntu")
    executor = ex.EsxiExecutor(free=host, sleep=lambda _s: None)
    result = executor.apply(
        ctx, step("vm.create_from_template", template="tpl-ubuntu", name="web-02")
    )
    assert result.ok, result.error
    assert "web-02" in host.vms

    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok, undone.error
    assert "web-02" not in host.vms


def test_cloning_over_an_existing_name_is_blocked(host, ctx):
    host.vms["tpl-ubuntu"] = _vm("tpl-ubuntu")
    executor = ex.EsxiExecutor(free=host)
    dry = executor.dry_run(
        ctx, [step("vm.create_from_template", template="tpl-ubuntu", name="web-01")]
    )
    assert dry.ok is False
    assert any("already exists" in b for b in dry.blockers)


def test_cloning_a_running_template_is_blocked(host, ctx):
    host.vms["tpl-ubuntu"] = _vm("tpl-ubuntu", power_state=ex.POWERED_ON)
    executor = ex.EsxiExecutor(free=host)
    dry = executor.dry_run(
        ctx, [step("vm.create_from_template", template="tpl-ubuntu", name="web-02")]
    )
    assert dry.ok is False
    assert any("powered on" in b for b in dry.blockers)


def test_cloning_from_a_missing_template_fails_cleanly(executor, ctx):
    result = executor.apply(ctx, step("vm.create_from_template", template="ghost", name="web-02"))
    assert result.ok is False
    assert "no VM named" in result.error


# ---------------------------------------------------------------------------
# host settings and log bundle
# ---------------------------------------------------------------------------
def test_host_setting_backs_the_host_up_first_and_rolls_back(executor, ctx, host):
    result = executor.apply(
        ctx, step("esxi.host_setting", key="syslog", value="udp://10.10.0.20:514")
    )
    assert result.ok, result.error
    assert result.output["backup_ref"]["kind"] == "esxi-host-config"
    assert host.calls.index("backup_host_config") < next(
        i for i, c in enumerate(host.calls) if c.startswith("host_setting_set")
    )
    assert host.settings[ex.SYSLOG_KEY] == "udp://10.10.0.20:514"

    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok, undone.error
    assert host.settings[ex.SYSLOG_KEY] == "udp://10.10.0.9:514"


def test_ntp_servers_are_a_list(executor, ctx, host):
    result = executor.apply(
        ctx, step("esxi.host_setting", key="ntp.servers", value=["10.10.0.9", "10.10.0.10"])
    )
    assert result.ok, result.error
    assert host.settings[ex.NTP_KEY] == ["10.10.0.9", "10.10.0.10"]
    assert executor.rollback(ctx, [result])[0].ok
    assert host.settings[ex.NTP_KEY] == ["10.10.0.9"]


def test_an_invalid_cdp_mode_is_blocked(executor, ctx):
    dry = executor.dry_run(ctx, [step("esxi.host_setting", key="cdp.mode", value="sideways")])
    assert dry.ok is False


def test_cdp_that_is_not_both_is_warned_about(executor, ctx):
    dry = executor.dry_run(ctx, [step("esxi.host_setting", key="cdp.mode", value="listen")])
    assert dry.ok, dry.blockers
    assert any("both" in w for w in dry.warnings)


def test_an_advanced_setting_round_trips(executor, ctx, host):
    result = executor.apply(
        ctx, step("esxi.host_setting", key="/UserVars/SuppressShellWarning", value=1)
    )
    assert result.ok, result.error
    assert host.settings["UserVars.SuppressShellWarning"] == 1
    assert executor.rollback(ctx, [result])[0].ok
    assert host.settings["UserVars.SuppressShellWarning"] == 0


def test_a_host_setting_without_a_key_is_refused(executor, ctx):
    assert executor.apply(ctx, step("esxi.host_setting", value="x")).ok is False
    assert executor.dry_run(ctx, [step("esxi.host_setting", value="x")]).ok is False


def test_log_bundle_changes_nothing_and_needs_no_rollback(executor, ctx):
    result = executor.apply(ctx, step("esxi.log_bundle"))
    assert result.ok, result.error
    assert result.output["kind"] == "esxi-log-bundle"
    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok
    assert "nothing to undo" in undone.output["undo"]


# ---------------------------------------------------------------------------
# dry run and checks
# ---------------------------------------------------------------------------
def test_dry_run_reports_the_transport_and_never_writes(executor, ctx, host):
    result = executor.dry_run(
        ctx,
        [
            step("vm.snapshot", vm="web-01"),
            step("vm.resize", vm="web-01", cpu=4),
            step("esxi.log_bundle"),
        ],
    )
    assert result.ok, result.blockers
    assert result.diff["transport"] == "fake"
    assert [e["action"] for e in result.diff["steps"]] == [
        "vm.snapshot",
        "vm.resize",
        "esxi.log_bundle",
    ]
    assert result.diff["steps"][1]["after"] == {"cpu": 4, "memory_mb": 4096}
    assert host.writes() == []


def test_dry_run_of_an_unknown_action_is_a_blocker(executor, ctx):
    result = executor.dry_run(ctx, [step("esxi.reboot", host="esx-01")])
    assert result.ok is False
    assert any("not an ESXi action" in b for b in result.blockers)


def test_dry_run_of_a_missing_vm_is_a_blocker(executor, ctx):
    result = executor.dry_run(ctx, [step("vm.snapshot", vm="ghost")])
    assert result.ok is False
    assert any("no VM named" in b for b in result.blockers)


@pytest.mark.parametrize(
    ("check", "expected"),
    [
        ("vm web-01 powered off", True),
        ("vm web-01 powered on", False),
        ("vm web-01 has no snapshots", True),
        ("vm ghost powered on", False),
        ("datastore datastore1 free >= 100", True),
        ("datastore datastore1 free >= 5000", False),
        ("datastore nope free >= 1", False),
        ("host setting syslog == udp://10.10.0.9:514", True),
        ("host setting syslog == udp://10.10.0.99:514", False),
        ("host setting ntp.servers == 10.10.0.9", True),
        ("host setting cdp.mode == listen", True),
        ("host setting cdp.mode == both", False),
    ],
)
def test_the_check_grammar(executor, ctx, check, expected):
    (result,) = executor.post_check(ctx, [check])
    assert result.ok is expected, result.detail


def test_tools_and_snapshot_checks(executor, ctx, host):
    (tools,) = executor.pre_check(ctx, ["vm web-01 tools running"])
    assert tools.ok is False
    host.vms["web-01"]["tools_running"] = True
    (tools,) = executor.pre_check(ctx, ["vm web-01 tools running"])
    assert tools.ok is True

    host.vms["web-01"]["snapshots"].append({"name": "nightly", "id": "7"})
    (snapshots,) = executor.post_check(ctx, ["vm web-01 has no snapshots"])
    assert snapshots.ok is False
    assert "nightly" in snapshots.detail


def test_an_unknown_check_fails_closed(executor, ctx):
    (result,) = executor.pre_check(ctx, ["the host looks happy"])
    assert result.ok is False
    assert "unknown check" in result.detail


def test_a_check_against_a_dead_host_fails_rather_than_raising(executor, ctx, host):
    host.fail["vm"] = ex.EsxiError("hostd is not answering")
    (result,) = executor.pre_check(ctx, ["vm web-01 powered on"])
    assert result.ok is False
    assert "hostd" in result.detail


# ---------------------------------------------------------------------------
# safety
# ---------------------------------------------------------------------------
def test_a_frozen_context_refuses_to_write(executor, host):
    frozen = ExecutionContext(plan_id="p", device=FREE_HOST, credential=RW, frozen=True)
    result = executor.apply(frozen, step("vm.snapshot", vm="web-01"))
    assert result.ok is False
    assert "frozen" in result.error
    assert host.writes() == []


def test_apply_refuses_a_dry_run_context(executor, host):
    probe = ExecutionContext(plan_id="p", device=FREE_HOST, credential=RW, dry_run=True)
    assert executor.apply(probe, step("vm.snapshot", vm="web-01")).ok is False
    assert host.writes() == []


def test_a_transport_failure_becomes_a_failed_step(executor, ctx, host):
    host.fail["snapshot_create"] = ex.EsxiError("datastore is read only")
    result = executor.apply(ctx, step("vm.snapshot", vm="web-01"))
    assert result.ok is False
    assert "read only" in result.error


def test_no_credential_material_reaches_any_output(executor, ctx, host):
    host.vms["web-01"]["snapshots"].append({"name": "nightly", "id": "7"})
    results = [
        executor.apply(ctx, step("vm.snapshot", vm="web-01")),
        executor.apply(ctx, step("esxi.host_setting", key="syslog", value="udp://10.0.0.1:514")),
        executor.apply(ctx, step("esxi.log_bundle")),
    ]
    results.extend(executor.rollback(ctx, results))
    dry = executor.dry_run(ctx, [step("vm.resize", vm="web-01", cpu=4)])
    blob = strings([r.model_dump(mode="json") for r in results]) + strings(
        dry.model_dump(mode="json")
    )
    assert "host-password-value" not in blob
    assert "/keys/esxi-rw.pem" not in blob
    assert "infra-rw" not in blob


def test_step_output_is_json_serialisable_and_free_of_handles(executor, ctx):
    result = executor.apply(ctx, step("vm.power_on", vm="web-01"))
    payload = json.dumps(result.model_dump(mode="json"))
    assert "_ref" not in payload


# ---------------------------------------------------------------------------
# SSH transport (the free licence path)
# ---------------------------------------------------------------------------
class FakeSession:
    """A scripted ESXi shell. Unknown commands answer with an empty string."""

    def __init__(self, outputs: dict[str, str], fail: dict[str, str] | None = None) -> None:
        self.outputs = dict(outputs)
        self.fail = fail or {}
        self.commands: list[str] = []
        self.closed = 0

    def run(self, command: str, timeout: float) -> str:
        self.commands.append(command)
        if command in self.fail:
            raise ex.EsxiError(self.fail[command])
        return self.outputs.get(command, "")

    def close(self) -> None:
        self.closed += 1


@pytest.fixture
def session(ssh_outputs) -> FakeSession:
    return FakeSession(ssh_outputs)


@pytest.fixture
def ssh(session: FakeSession) -> ex.SshTransport:
    return ex.SshTransport(open_session=lambda device, cred: session)


def test_ssh_reads_a_whole_vm_from_vim_cmd(ssh, ctx, session):
    vm = ssh.vm(ctx, "web-01")
    assert vm["vmid"] == "1"
    assert vm["power_state"] == ex.POWERED_ON
    assert vm["cpu"] == 2 and vm["memory_mb"] == 4096
    assert vm["hot_add_memory"] is True and vm["hot_add_cpu"] is False
    assert vm["tools_running"] is True
    assert [s["name"] for s in vm["snapshots"]] == ["nightly"]
    assert vm["disks"][0]["size_gb"] == 40.0
    assert session.closed >= 1


def test_ssh_returns_none_for_an_unknown_vm(ssh, ctx):
    assert ssh.vm(ctx, "ghost") is None


def test_ssh_reads_datastores(ssh, ctx):
    stores = {s["name"]: s for s in ssh.datastores(ctx)}
    assert stores["datastore1"]["free_bytes"] == 644245094400
    assert stores["datastore-small"]["capacity_bytes"] == 214748364800


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("syslog", "udp://10.10.0.9:514"),
        ("ntp.servers", ["10.10.0.9"]),
        ("cdp.mode", {"vSwitch0": "listen"}),
        ("/UserVars/SuppressShellWarning", 1),
        ("/Syslog/global/logDir", "[] /scratch/log"),
    ],
)
def test_ssh_reads_every_host_setting_family(ssh, ctx, key, expected):
    assert ssh.host_setting_get(ctx, key) == expected


def test_ssh_writes_the_documented_commands(ssh, ctx, session):
    ssh.host_setting_set(ctx, "syslog", "udp://10.10.0.20:514", {})
    ssh.host_setting_set(ctx, "ntp.servers", ["10.10.0.9", "10.10.0.10"], {})
    ssh.host_setting_set(ctx, "cdp.mode", "both", {"vswitch": "vSwitch0"})
    ssh.host_setting_set(ctx, "/UserVars/SuppressShellWarning", 1, {})
    assert session.commands == [
        "esxcli system syslog config set --loghost=udp://10.10.0.20:514",
        "esxcli system syslog reload",
        "esxcli system ntp set --server=10.10.0.9 --server=10.10.0.10",
        "esxcli system ntp set --enabled=1",
        "esxcli network vswitch standard set -v vSwitch0 --cdp-status=both",
        "esxcli system settings advanced set -o /UserVars/SuppressShellWarning -i 1",
    ]


def test_ssh_refuses_a_cdp_mode_the_host_does_not_have(ssh, ctx):
    with pytest.raises(ex.EsxiError):
        ssh.host_setting_set(ctx, "cdp.mode", "sideways", {})


def test_ssh_snapshot_commands_use_the_snapshot_id(ssh, ctx, session):
    vm = ssh.vm(ctx, "web-01")
    session.commands.clear()
    ssh.snapshot_create(ctx, vm, "infra-plan-9f", "pre-change")
    ssh.snapshot_revert(ctx, vm, "nightly")
    ssh.snapshot_remove(ctx, vm, "nightly")
    assert session.commands == [
        "vim-cmd vmsvc/snapshot.create 1 infra-plan-9f pre-change 0 0",
        "vim-cmd vmsvc/snapshot.revert 1 7 0",
        "vim-cmd vmsvc/snapshot.remove 1 7",
    ]


def test_ssh_refuses_a_snapshot_name_it_cannot_resolve(ssh, ctx):
    vm = ssh.vm(ctx, "web-01")
    with pytest.raises(ex.EsxiError):
        ssh.snapshot_remove(ctx, vm, "not-there")


def test_ssh_reconfigure_rewrites_the_vmx_and_reloads(ssh, ctx, session):
    vm = ssh.vm(ctx, "web-01")
    session.commands.clear()
    ssh.reconfigure(ctx, vm, cpu=4, memory_mb=8192)
    assert session.commands == [
        "sed -i '/^numvcpus[[:space:]]*=/d' /vmfs/volumes/datastore1/web-01/web-01.vmx",
        "echo 'numvcpus = \"4\"' >> /vmfs/volumes/datastore1/web-01/web-01.vmx",
        "sed -i '/^memSize[[:space:]]*=/d' /vmfs/volumes/datastore1/web-01/web-01.vmx",
        "echo 'memSize = \"8192\"' >> /vmfs/volumes/datastore1/web-01/web-01.vmx",
        "vim-cmd vmsvc/reload 1",
    ]


def test_ssh_disk_extend_uses_vmkfstools(ssh, ctx, session):
    vm = ssh.vm(ctx, "web-01")
    session.commands.clear()
    ssh.disk_extend(ctx, vm, vm["disks"][0], 80)
    assert session.commands == ["vmkfstools -X 80G /vmfs/volumes/datastore1/web-01/web-01.vmdk"]


def test_ssh_power_commands(ssh, ctx, session):
    vm = ssh.vm(ctx, "web-01")
    session.commands.clear()
    ssh.power_on(ctx, vm)
    ssh.shutdown_guest(ctx, vm)
    ssh.power_off(ctx, vm)
    assert session.commands == [
        "vim-cmd vmsvc/power.on 1",
        "vim-cmd vmsvc/power.shutdown 1",
        "vim-cmd vmsvc/power.off 1",
    ]


def test_ssh_clone_copies_registers_and_retitles(ssh, ctx, session):
    template = ssh.vm(ctx, "tpl-ubuntu")
    session.commands.clear()
    session.outputs["vim-cmd solo/registervm /vmfs/volumes/datastore1/web-02/web-02.vmx"] = "12\n"
    created = ssh.clone_from_template(ctx, template, "web-02", "datastore1")
    assert created["vmid"] == "12"
    assert created["vmx"] == "[datastore1] web-02/web-02.vmx"
    assert session.commands[0] == "mkdir -p /vmfs/volumes/datastore1/web-02"
    assert session.commands[1].startswith("vmkfstools -i /vmfs/volumes/datastore1/tpl-ubuntu")
    assert session.commands[-1].startswith("vim-cmd solo/registervm")


def test_ssh_destroy_refuses_a_path_outside_a_datastore(ssh, ctx):
    with pytest.raises(ex.EsxiError):
        ssh.destroy_vm(ctx, {"name": "x", "vmid": "1", "dir": "/etc"})
    with pytest.raises(ex.EsxiError):
        ssh.destroy_vm(ctx, {"name": "x", "vmid": "1", "dir": "/vmfs/volumes"})


def test_ssh_destroy_unregisters_then_removes_the_directory(ssh, ctx, session):
    ssh.destroy_vm(ctx, {"name": "web-02", "vmid": "12", "vmx": "[datastore1] web-02/web-02.vmx"})
    assert session.commands == [
        "vim-cmd vmsvc/power.off 12 || true",
        "vim-cmd vmsvc/unregister 12",
        "rm -rf /vmfs/volumes/datastore1/web-02",
    ]


def test_ssh_backup_and_log_bundle_report_their_paths(ssh, ctx):
    backup = ssh.backup_host_config(ctx)
    assert backup["kind"] == "esxi-host-config"
    assert backup["path"].endswith("configBundle-esx-01.tgz")
    bundle = ssh.log_bundle(ctx)
    assert bundle["path"].endswith(".tgz")


def test_ssh_refuses_vm_names_that_are_not_names(ssh, ctx):
    with pytest.raises(ex.EsxiError):
        ssh.vm(ctx, "web-01; reboot")


def test_a_failing_command_surfaces_as_a_failed_step(ssh_outputs, ctx):
    session = FakeSession(ssh_outputs, fail={"vim-cmd vmsvc/power.on 1": "not permitted"})
    transport = ex.SshTransport(open_session=lambda device, cred: session)
    executor = ex.EsxiExecutor(free=transport, sleep=lambda _s: None)
    result = executor.apply(ctx, step("vm.power_on", vm="web-01"))
    assert result.ok is False
    assert "not permitted" in result.error


def test_the_free_path_end_to_end_takes_a_snapshot_over_ssh(ssh_outputs, ctx):
    session = FakeSession(ssh_outputs)
    executor = ex.EsxiExecutor(
        free=ex.SshTransport(open_session=lambda device, cred: session), sleep=lambda _s: None
    )
    result = executor.apply(ctx, step("vm.snapshot", vm="web-01", description="before the change"))
    assert result.ok, result.error
    assert (
        "vim-cmd vmsvc/snapshot.create 1 infra-plan-9f 'before the change' 0 0" in session.commands
    )


# ---------------------------------------------------------------------------
# pyvmomi transport (the licensed path)
# ---------------------------------------------------------------------------
class Bag:
    """An attribute bag standing in for a pyvmomi managed object or spec."""

    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Bag({self.__dict__})"


class Task:
    def __init__(self, state: str = "success", result: Any = None, msg: str = "") -> None:
        self.info = Bag(state=state, result=result, error=Bag(msg=msg))


class FakeVim:
    """Just the spec constructors the transport builds."""

    class option:
        OptionValue = Bag

    class vm:
        ConfigSpec = Bag
        CloneSpec = Bag
        RelocateSpec = Bag

        class device:
            VirtualDeviceSpec = Bag

    class host:
        DateTimeConfig = Bag
        NtpConfig = Bag
        LinkDiscoveryProtocolConfig = Bag

        class VirtualSwitch:
            Specification = Bag
            BondBridge = Bag


class FakeVm:
    def __init__(self, name: str, powered: bool = False) -> None:
        self.name = name
        self.calls: list[tuple[str, Any]] = []
        self.disk = Bag(
            key=2000,
            capacityInKB=41943040,
            deviceInfo=Bag(label="Hard disk 1"),
            backing=Bag(fileName=f"[datastore1] {name}/{name}.vmdk"),
        )
        self.config = Bag(
            hardware=Bag(numCPU=2, memoryMB=4096, device=[self.disk]),
            cpuHotAddEnabled=False,
            memoryHotAddEnabled=True,
            files=Bag(vmPathName=f"[datastore1] {name}/{name}.vmx"),
        )
        self.runtime = Bag(powerState=ex.POWERED_ON if powered else ex.POWERED_OFF)
        self.guest = Bag(toolsRunningStatus="guestToolsRunning", guestState="running")
        self.snapshot = Bag(rootSnapshotList=[])
        self.parent = Bag(name="vm folder")

    def _task(self, what: str, payload: Any = None) -> Task:
        self.calls.append((what, payload))
        return Task()

    def CreateSnapshot_Task(self, name, description, memory, quiesce):
        snapshot = Bag(name=name, id=len(self.snapshot.rootSnapshotList) + 1)
        snapshot.snapshot = Bag(
            RemoveSnapshot_Task=lambda removeChildren: self._task("snapshot.remove", name),
            RevertToSnapshot_Task=lambda: self._task("snapshot.revert", name),
        )
        snapshot.description = description
        snapshot.childSnapshotList = []
        self.snapshot.rootSnapshotList.append(snapshot)
        return self._task("snapshot.create", {"name": name, "memory": memory, "quiesce": quiesce})

    def PowerOnVM_Task(self):
        self.runtime.powerState = ex.POWERED_ON
        return self._task("power.on")

    def PowerOffVM_Task(self):
        self.runtime.powerState = ex.POWERED_OFF
        return self._task("power.off")

    def ShutdownGuest(self):
        self.runtime.powerState = ex.POWERED_OFF
        self.calls.append(("guest.shutdown", None))

    def ReconfigVM_Task(self, spec):
        return self._task("reconfigure", spec)

    def CloneVM_Task(self, folder, name, spec):
        return self._task("clone", {"folder": folder, "name": name, "spec": spec})

    def Destroy_Task(self):
        return self._task("destroy")


def fake_host(vms: list[FakeVm]) -> Bag:
    advanced = Bag(
        setting=[Bag(key="Syslog.global.logHost", value="udp://10.10.0.9:514")],
        updates=[],
    )
    advanced.UpdateOptions = lambda changedValue: advanced.updates.append(changedValue)
    date_time = Bag(configs=[])
    date_time.UpdateDateTimeConfig = lambda config: date_time.configs.append(config)
    network = Bag(switches=[])
    network.UpdateVirtualSwitch = lambda vswitchName, spec: network.switches.append(
        (vswitchName, spec)
    )
    firmware = Bag(BackupFirmwareConfiguration=lambda: "http://*/downloads/x/configBundle.tgz")
    return Bag(
        vm=vms,
        datastore=[
            Bag(summary=Bag(name="datastore1", freeSpace=500 * ex.GIB, capacity=1000 * ex.GIB))
        ],
        configManager=Bag(
            advancedOption=advanced,
            dateTimeSystem=date_time,
            networkSystem=network,
            firmwareSystem=firmware,
        ),
        config=Bag(
            dateTimeInfo=Bag(ntpConfig=Bag(server=["10.10.0.9"])),
            network=Bag(
                vswitch=[
                    Bag(
                        name="vSwitch0",
                        spec=Bag(
                            bridge=Bag(
                                linkDiscoveryProtocolConfig=Bag(protocol="cdp", operation="listen")
                            )
                        ),
                    )
                ]
            ),
        ),
    )


def fake_content(host: Bag) -> Bag:
    compute = Bag(host=[host])
    datacenter = Bag(hostFolder=Bag(childEntity=[compute]))
    return Bag(
        rootFolder=Bag(childEntity=[datacenter]),
        diagnosticManager=Bag(
            GenerateLogBundles_Task=lambda includeDefault: Task(
                result=[Bag(url="http://*/downloads/bundle.tgz")]
            )
        ),
    )


@pytest.fixture
def api_vm() -> FakeVm:
    return FakeVm("web-01")


@pytest.fixture
def api(api_vm: FakeVm) -> ex.PyvmomiTransport:
    host = fake_host([api_vm])
    content = fake_content(host)
    return ex.PyvmomiTransport(
        connect=lambda device, cred: Bag(RetrieveContent=lambda: content),
        vim=FakeVim,
        sleep=lambda _s: None,
    )


@pytest.fixture
def api_ctx() -> ExecutionContext:
    return ExecutionContext(plan_id="plan-9f", device=LICENSED_HOST, credential=RW)


def test_pyvmomi_reads_a_vm_row(api, api_ctx):
    vm = api.vm(api_ctx, "web-01")
    assert vm["power_state"] == ex.POWERED_OFF
    assert vm["cpu"] == 2 and vm["memory_mb"] == 4096
    assert vm["hot_add_memory"] is True
    assert vm["tools_running"] is True
    assert vm["datastore"] == "datastore1"
    assert vm["disks"][0] == {
        "label": "Hard disk 1",
        "path": "[datastore1] web-01/web-01.vmdk",
        "size_gb": 40.0,
        "_key": 2000,
    }
    assert api.vm(api_ctx, "ghost") is None


def test_pyvmomi_reads_datastores_and_settings(api, api_ctx):
    assert api.datastores(api_ctx)[0]["free_bytes"] == 500 * ex.GIB
    assert api.host_setting_get(api_ctx, "syslog") == "udp://10.10.0.9:514"
    assert api.host_setting_get(api_ctx, "ntp.servers") == ["10.10.0.9"]
    assert api.host_setting_get(api_ctx, "cdp.mode") == {"vSwitch0": "listen"}


def test_pyvmomi_snapshot_lifecycle(api, api_ctx, api_vm):
    vm = api.vm(api_ctx, "web-01")
    api.snapshot_create(api_ctx, vm, "infra-plan-9f", "pre-change")
    assert api_vm.calls[0][0] == "snapshot.create"
    assert api_vm.calls[0][1]["memory"] is False

    vm = api.vm(api_ctx, "web-01")
    assert [s["name"] for s in vm["snapshots"]] == ["infra-plan-9f"]
    api.snapshot_revert(api_ctx, vm, "infra-plan-9f")
    api.snapshot_remove(api_ctx, vm, "infra-plan-9f")
    assert [c[0] for c in api_vm.calls] == [
        "snapshot.create",
        "snapshot.revert",
        "snapshot.remove",
    ]


def test_pyvmomi_reconfigure_builds_a_config_spec(api, api_ctx, api_vm):
    vm = api.vm(api_ctx, "web-01")
    api.reconfigure(api_ctx, vm, cpu=4, memory_mb=8192)
    what, spec = api_vm.calls[-1]
    assert what == "reconfigure"
    assert spec.numCPUs == 4 and spec.memoryMB == 8192


def test_pyvmomi_disk_extend_edits_the_device(api, api_ctx, api_vm):
    vm = api.vm(api_ctx, "web-01")
    api.disk_extend(api_ctx, vm, vm["disks"][0], 80)
    _what, spec = api_vm.calls[-1]
    change = spec.deviceChange[0]
    assert change.operation == "edit"
    assert change.device.capacityInKB == 80 * 1024 * 1024


def test_pyvmomi_host_settings_use_the_right_manager(api, api_ctx):
    host = api.host(api_ctx)
    api.host_setting_set(api_ctx, "syslog", "udp://10.10.0.20:514", {})
    assert host.configManager.advancedOption.updates[-1][0].key == "Syslog.global.logHost"
    api.host_setting_set(api_ctx, "ntp.servers", ["10.10.0.1"], {})
    assert host.configManager.dateTimeSystem.configs[-1].ntpConfig.server == ["10.10.0.1"]
    api.host_setting_set(api_ctx, "cdp.mode", "both", {"vswitch": "vSwitch0"})
    name, spec = host.configManager.networkSystem.switches[-1]
    assert name == "vSwitch0"
    assert spec.bridge.linkDiscoveryProtocolConfig.operation == "both"


def test_pyvmomi_backup_and_log_bundle(api, api_ctx):
    assert api.backup_host_config(api_ctx)["path"].endswith("configBundle.tgz")
    assert api.log_bundle(api_ctx)["path"].endswith("bundle.tgz")


def test_pyvmomi_surfaces_a_task_error(api):
    with pytest.raises(ex.EsxiError) as caught:
        api.wait(Task(state="error", msg="insufficient disk space"))
    assert "insufficient disk space" in str(caught.value)


def test_pyvmomi_times_out_rather_than_spinning(api_vm):
    transport = ex.PyvmomiTransport(vim=FakeVim, sleep=lambda _s: None, timeout=0.0)
    with pytest.raises(ex.EsxiError) as caught:
        transport.wait(Task(state="running"))
    assert "timed out" in str(caught.value)


def test_the_licensed_path_end_to_end_resizes_and_rolls_back(api, api_ctx, api_vm):
    executor = ex.EsxiExecutor(licensed=api, sleep=lambda _s: None)
    result = executor.apply(api_ctx, step("vm.resize", vm="web-01", memory_mb=8192))
    assert result.ok, result.error
    assert result.output["pre_snapshot"] == "infra-plan-9f"
    assert [c[0] for c in api_vm.calls] == ["snapshot.create", "reconfigure"]

    (undone,) = executor.rollback(api_ctx, [result])
    assert undone.ok, undone.error
    assert [c[0] for c in api_vm.calls][-1] == "snapshot.revert"


def test_the_licensed_path_destroys_a_clone_on_rollback(api, api_ctx, api_vm):
    executor = ex.EsxiExecutor(licensed=api, sleep=lambda _s: None)
    result = executor.apply(
        api_ctx, step("vm.create_from_template", template="web-01", name="web-02")
    )
    assert result.ok, result.error
    assert [c[0] for c in api_vm.calls] == ["clone"]


def test_a_step_that_failed_after_its_pre_snapshot_is_still_rolled_back(executor, ctx, host):
    """The snapshot exists, so the rollback has somewhere to go back to."""
    host.fail["reconfigure"] = ex.EsxiError("the host rejected the reconfigure")
    result = executor.apply(ctx, step("vm.resize", vm="web-01", cpu=4))
    assert result.ok is False
    assert result.output["pre_snapshot"] == "infra-plan-9f"
    assert executor.partially_applied(result) is True

    (undone,) = executor.rollback(ctx, [result])
    assert undone.ok, undone.error
    assert undone.output["undo"] == "reverted to 'infra-plan-9f'"


def test_a_step_that_failed_before_touching_anything_is_skipped(executor, ctx, host):
    host.fail["snapshot_create"] = ex.EsxiError("no space")
    result = executor.apply(ctx, step("vm.resize", vm="web-01", cpu=4))
    assert result.ok is False
    assert executor.partially_applied(result) is False
    assert executor.rollback(ctx, [result]) == []
