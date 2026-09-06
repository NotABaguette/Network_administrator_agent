"""Reconciliation, baseline and drift, entirely offline.

The synthetic snapshots below have the shape the collectors produce: TextFSM
rows for Cisco, FortiOS REST rows for the FortiGate, and parsed hosts / VMs /
portgroups for ESXi and iLO. `FakeNetBox` stands in for NetBox and runs the
same `ensure()` upsert the real client runs.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from infra_agent.config import Settings
from infra_agent.models.common import DeviceKind, SeedDevice, SeedInventory, Snapshot
from infra_agent.reconcile import service
from infra_agent.reconcile.baseline import BaselineStore
from infra_agent.reconcile.bootstrap import bootstrap, slugify, sync
from infra_agent.reconcile.drift import Severity, compare, intended_from_netbox
from infra_agent.reconcile.fake import FakeNetBox
from infra_agent.reconcile.model import normalize_ifname, normalize_mac, to_cidr
from infra_agent.reconcile.netbox import NetBoxClient
from infra_agent.reconcile.observed import parse_vlan_list
from infra_agent.redaction.gateway import RedactionGateway
from infra_agent.store.snapshots import FileSnapshotStore

SEED_DEVICES = [
    SeedDevice(
        name="fw-01",
        kind=DeviceKind.fortigate,
        mgmt_ip="10.0.10.1",
        credential_ref="fw-01",
        tags=["edge", "mgmt-path"],
    ),
    SeedDevice(
        name="sw-core-01",
        kind=DeviceKind.cisco_ios,
        mgmt_ip="10.0.10.2",
        credential_ref="sw-core-01",
        tags=["core", "mgmt-path"],
    ),
    SeedDevice(
        name="esx-01",
        kind=DeviceKind.esxi,
        mgmt_ip="10.0.10.21",
        credential_ref="esx-01",
        tags=["hypervisor"],
        license="free",
    ),
    SeedDevice(
        name="esx-01-ilo",
        kind=DeviceKind.ilo,
        mgmt_ip="10.0.0.121",
        credential_ref="esx-01-ilo",
        tags=["oob"],
    ),
]


def cisco_data() -> dict[str, Any]:
    return {
        "version": [
            {
                "hostname": "sw-core-01",
                "version": "15.2(7)E3",
                "hardware": ["WS-C2960X-48TS-L"],
                "serial": ["FOC1234A5BC"],
                "mac_address": ["aabb.cc00.0100"],
            }
        ],
        "inventory": [
            {
                "name": "1",
                "descr": "WS-C2960X-48TS-L",
                "pid": "WS-C2960X-48TS-L",
                "sn": "FOC1234A5BC",
            }
        ],
        "interfaces": [
            {
                "interface": "GigabitEthernet1/0/1",
                "link_status": "up",
                "protocol_status": "up",
                "address": "aabb.cc00.0101",
                "description": "esx-01 vmnic0",
                "mtu": "1500",
            },
            {
                "interface": "GigabitEthernet1/0/2",
                "link_status": "up",
                "address": "aabb.cc00.0102",
                "description": "fw-01 internal",
                "mtu": "1500",
            },
            {
                "interface": "GigabitEthernet1/0/24",
                "link_status": "down",
                "address": "aabb.cc00.0118",
                "description": "spare",
                "mtu": "1500",
            },
            {
                "interface": "Vlan10",
                "link_status": "up",
                "address": "aabb.cc00.0100",
                "description": "management",
                "ip_address": "10.0.10.2/24",
                "mtu": "1500",
            },
        ],
        "interfaces_status": [
            {
                "port": "Gi1/0/1",
                "name": "esx-01 vmnic0",
                "status": "connected",
                "vlan": "trunk",
                "type": "10/100/1000BaseTX",
            },
            {
                "port": "Gi1/0/2",
                "name": "fw-01 internal",
                "status": "connected",
                "vlan": "trunk",
                "type": "10/100/1000BaseTX",
            },
            {
                "port": "Gi1/0/24",
                "name": "spare",
                "status": "notconnect",
                "vlan": "20",
                "type": "10/100/1000BaseTX",
            },
        ],
        "ip_int_brief": [
            {"interface": "Vlan10", "ip_address": "10.0.10.2", "status": "up", "proto": "up"}
        ],
        "vlans": [
            {"vlan_id": "1", "vlan_name": "default", "status": "active", "interfaces": []},
            {
                "vlan_id": "10",
                "vlan_name": "mgmt",
                "status": "active",
                "interfaces": ["Gi1/0/1", "Gi1/0/2"],
            },
            {
                "vlan_id": "20",
                "vlan_name": "servers",
                "status": "active",
                "interfaces": ["Gi1/0/24"],
            },
            {"vlan_id": "30", "vlan_name": "voice", "status": "active", "interfaces": []},
        ],
        "trunks": [
            {
                "interface": "Gi1/0/1",
                "mode": "on",
                "native_vlan": "1",
                "vlans_allowed": "10,20,30",
            },
            {
                "interface": "Gi1/0/2",
                "mode": "on",
                "native_vlan": "1",
                "vlans_allowed": "10,20,30",
            },
        ],
        "mac_table": [
            {
                "vlan": "20",
                "destination_address": "0050.5601.aabb",
                "type": "DYNAMIC",
                "destination_port": ["Gi1/0/1"],
            },
            {
                "vlan": "10",
                "destination_address": "aabb.cc00.0201",
                "type": "DYNAMIC",
                "destination_port": ["Gi1/0/2"],
            },
        ],
        "arp": [
            {
                "ip_address": "10.0.10.1",
                "mac_address": "aabb.cc00.0201",
                "interface": "Vlan10",
                "type": "ARPA",
            }
        ],
        "errors": {},
    }


def fortigate_data() -> dict[str, Any]:
    return {
        "system": {"hostname": "fw-01", "version": "v7.4.4", "serial": "FGT60FTK20001234"},
        "interfaces": [
            {
                "name": "wan1",
                "type": "physical",
                "ip": "203.0.113.10 255.255.255.248",
                "role": "wan",
                "status": "up",
                "alias": "ISP-A",
            },
            {
                "name": "internal",
                "type": "physical",
                "ip": "0.0.0.0 0.0.0.0",
                "role": "lan",
                "status": "up",
                "alias": "trunk to sw-core-01",
            },
            {
                "name": "mgmt-vl10",
                "type": "vlan",
                "vlanid": 10,
                "interface": "internal",
                "ip": "10.0.10.1 255.255.255.0",
                "role": "lan",
                "status": "up",
                "alias": "mgmt",
            },
            {
                "name": "srv-vl20",
                "type": "vlan",
                "vlanid": 20,
                "interface": "internal",
                "ip": "10.0.20.1 255.255.255.0",
                "role": "lan",
                "status": "up",
                "alias": "servers",
            },
        ],
        "interface_stats": {
            "wan1": {"mac": "aa:bb:cc:00:02:00", "speed": 1000},
            "internal": {"mac": "aa:bb:cc:00:02:01", "speed": 1000},
        },
        "arp": [{"ip": "10.0.20.55", "mac": "00:50:56:01:aa:bb", "interface": "srv-vl20"}],
        "dhcp_leases": [
            {
                "ip": "10.0.20.55",
                "mac": "00:50:56:01:aa:bb",
                "hostname": "app-01",
                "interface": "srv-vl20",
                "expire_time": 3600,
            }
        ],
        "policies": [
            {
                "id": 1,
                "name": "servers-out",
                "action": "accept",
                "srcintf": ["srv-vl20"],
                "dstintf": ["wan1"],
            }
        ],
        "errors": {},
    }


def esxi_data() -> dict[str, Any]:
    return {
        "host": {
            "name": "esx-01.lab.local",
            "model": "ProLiant DL360 Gen9",
            "vendor": "HPE",
            "version": "7.0.3",
            "build": "21930508",
            "license": "VMware vSphere 7 Hypervisor (free)",
        },
        "portgroups": [
            {"name": "Management Network", "vlan": 10, "vswitch": "vSwitch0"},
            {"name": "Servers", "vlan": 20, "vswitch": "vSwitch0"},
        ],
        "pnics": [
            {
                "device": "vmnic0",
                "mac": "aa:bb:cc:00:03:00",
                "speed": 1000,
                "link": "up",
                "driver": "ntg3",
                "uplink": True,
            },
            {
                "device": "vmnic1",
                "mac": "aa:bb:cc:00:03:01",
                "speed": 1000,
                "link": "down",
                "driver": "ntg3",
            },
        ],
        "vmknics": [
            {
                "device": "vmk0",
                "ip": "10.0.10.21",
                "netmask": "255.255.255.0",
                "mac": "aa:bb:cc:00:03:10",
                "portgroup": "Management Network",
                "management": True,
            }
        ],
        "vms": [
            {
                "name": "app-01",
                "power_state": "poweredOn",
                "num_cpu": 4,
                "memory_mb": 8192,
                "disk_gb": 80,
                "guest_os": "Ubuntu Linux (64-bit)",
                "nics": [
                    {
                        "name": "Network adapter 1",
                        "mac": "00:50:56:01:aa:bb",
                        "portgroup": "Servers",
                        "connected": True,
                        "ip": "10.0.20.55",
                    }
                ],
            },
            {
                "name": "mgmt-01",
                "power_state": "poweredOn",
                "num_cpu": 2,
                "memory_mb": 4096,
                "disk_gb": 120,
                "guest_os": "Ubuntu Linux (64-bit)",
                "nics": [
                    {
                        "name": "Network adapter 1",
                        "mac": "00:50:56:01:cc:dd",
                        "portgroup": "Management Network",
                        "connected": True,
                        "ip": "10.0.10.30",
                    }
                ],
            },
        ],
        "errors": {},
    }


def ilo_data() -> dict[str, Any]:
    return {
        "system": {
            "model": "ProLiant DL360 Gen9",
            "serial": "CZ12345678",
            "bios": "P89 v2.76",
            "ilo_firmware": "2.82",
            "ilo_generation": "iLO4",
        },
        "power": {"state": "On"},
        "errors": {},
    }


SNAPSHOTS = {
    "sw-core-01": ("cisco", cisco_data),
    "fw-01": ("fortigate", fortigate_data),
    "esx-01": ("esxi", esxi_data),
    "esx-01-ilo": ("ilo", ilo_data),
}


def write_estate(tmp_path: Path, overrides: dict[str, Any] | None = None) -> Settings:
    """Write seed.yaml plus one snapshot per device and return matching Settings."""
    overrides = overrides or {}
    data_dir = tmp_path / "data"
    seed_path = tmp_path / "inventory" / "seed.yaml"
    inventory = SeedInventory(devices=copy.deepcopy(SEED_DEVICES))
    inventory.save(seed_path)

    store = FileSnapshotStore(data_dir / "snapshots")
    for device, (collector, factory) in SNAPSHOTS.items():
        data = overrides.get(device, factory())
        if data is None:
            continue
        store.save(Snapshot(device=device, collector=collector, data=data))
    return Settings(data_dir=data_dir, seed_inventory=seed_path, netbox_url=None, netbox_token=None)


def observed(tmp_path: Path, overrides: dict[str, Any] | None = None):
    settings = write_estate(tmp_path, overrides)
    return service.observed_estate(settings)


def bootstrapped(tmp_path: Path) -> tuple[FakeNetBox, Any]:
    estate = observed(tmp_path)
    client = FakeNetBox()
    bootstrap(estate, client)
    return client, estate


# --------------------------------------------------------------------------- parsing
def test_normalizers():
    assert normalize_mac("aabb.cc00.0101") == "aa:bb:cc:00:01:01"
    assert normalize_mac("AA-BB-CC-00-01-01") == "aa:bb:cc:00:01:01"
    assert normalize_mac("nope") is None
    assert normalize_ifname("Gi1/0/1") == "GigabitEthernet1/0/1"
    assert normalize_ifname("GigabitEthernet1/0/1") == "GigabitEthernet1/0/1"
    assert normalize_ifname("Po1") == "Port-channel1"
    assert normalize_ifname("vmnic0") == "vmnic0"
    assert to_cidr("10.0.10.1 255.255.255.0") == "10.0.10.1/24"
    assert to_cidr("10.0.10.1", "255.255.255.128") == "10.0.10.1/25"
    assert to_cidr("0.0.0.0 0.0.0.0") is None
    assert parse_vlan_list("10,20,30-32") == [10, 20, 30, 31, 32]
    assert parse_vlan_list("1-4094", known={10, 20}) == [10, 20]
    assert parse_vlan_list("1-4094") == []


def test_observed_estate_parses_every_collector(tmp_path):
    estate = observed(tmp_path)

    assert [d.name for d in estate.devices] == ["esx-01", "fw-01", "sw-core-01"]
    switch = estate.device("sw-core-01")
    assert switch.model == "WS-C2960X-48TS-L"
    assert switch.serial == "FOC1234A5BC"
    assert switch.role == "core-switch"

    uplink = switch.interface("Gi1/0/1")
    assert uplink.name == "GigabitEthernet1/0/1"
    assert uplink.mac == "aa:bb:cc:00:01:01"
    assert uplink.mode == "tagged"
    assert uplink.tagged_vlans == [10, 20, 30]
    assert uplink.is_sensitive()

    access = switch.interface("Gi1/0/24")
    # notconnect is a dark link, not a shut port: NetBox's `enabled` is the admin state.
    assert (access.mode, access.untagged_vlan, access.enabled) == ("access", 20, True)

    svi = switch.interface("Vlan10")
    assert svi.addresses == ["10.0.10.2/24"], "the /32 from `show ip int brief` must not duplicate"

    firewall = estate.device("fw-01")
    assert firewall.model == "FortiGate-60F"
    assert firewall.interface("wan1").role == "wan"
    assert firewall.interface("srv-vl20").untagged_vlan == 20
    assert firewall.interface("srv-vl20").parent == "internal"

    host = estate.device("esx-01")
    assert host.serial == "CZ12345678", "the iLO serial folds into its ESXi host"
    assert host.interface("iLO").role == "oob"
    assert host.interface("vmk0").addresses == ["10.0.10.21/24"]

    assert [c.name for c in estate.clusters] == ["esx-01"]
    assert [vm.name for vm in estate.virtual_machines] == ["app-01", "mgmt-01"]
    app = estate.vm("app-01")
    assert (app.vcpus, app.memory_mb, app.disk_gb, app.status) == (4.0, 8192, 80.0, "active")
    assert app.interfaces[0].vlan == 20

    assert {v.vid for v in estate.vlans} == {1, 10, 20, 30}
    assert estate.vlan(20).name == "servers", "the switch VLAN database names a VLAN"
    assert estate.vlan(10).devices == ["esx-01", "fw-01", "sw-core-01"]
    assert {p.prefix for p in estate.prefixes} >= {"10.0.10.0/24", "10.0.20.0/24"}
    assert estate.warnings == []


def test_estate_holds_no_raw_config(tmp_path, gateway):
    estate = observed(tmp_path)
    gateway.refuse_raw_config(estate.model_dump(mode="json"))


def test_missing_snapshot_becomes_a_warning(tmp_path):
    estate = observed(tmp_path, overrides={"sw-core-01": None})
    assert estate.device("sw-core-01") is None
    assert any("sw-core-01" in w for w in estate.warnings)


def test_unlinked_ilo_becomes_its_own_device(tmp_path):
    settings = write_estate(tmp_path)
    inventory = SeedInventory.load(settings.seed_inventory)
    inventory.devices = [d for d in inventory.devices if d.kind is not DeviceKind.esxi]
    inventory.save(settings.seed_inventory)
    estate = service.observed_estate(settings)
    assert estate.device("esx-01-ilo").serial == "CZ12345678"
    assert any("esx-01-ilo" in w for w in estate.warnings)


# --------------------------------------------------------------------------- bootstrap
def test_bootstrap_creates_the_estate(tmp_path):
    client, _ = bootstrapped(tmp_path)

    assert client.count("dcim.sites") == 1
    assert {d["name"] for d in client.all("dcim.devices")} == {"fw-01", "sw-core-01", "esx-01"}
    assert {r["slug"] for r in client.all("dcim.device_roles")} == {
        "firewall",
        "core-switch",
        "hypervisor",
    }
    assert {t["model"] for t in client.all("dcim.device_types")} >= {"WS-C2960X-48TS-L"}
    assert {v["vid"] for v in client.all("ipam.vlans")} == {1, 10, 20, 30}
    assert {c["name"] for c in client.all("virtualization.clusters")} == {"esx-01"}
    assert {v["name"] for v in client.all("virtualization.virtual_machines")} == {
        "app-01",
        "mgmt-01",
    }

    uplink = client.get("dcim.interfaces", device="sw-core-01", name="GigabitEthernet1/0/1")
    assert uplink["mac_address"] == "aa:bb:cc:00:01:01"
    assert uplink["mode"] == "tagged"
    assert len(uplink["tagged_vlans"]) == 3

    switch = client.get("dcim.devices", name="sw-core-01")
    mgmt_ip = client.get("ipam.ip_addresses", address="10.0.10.2/24")
    assert switch["primary_ip4"] == mgmt_ip["id"]
    assert client.get(
        "virtualization.interfaces", virtual_machine="app-01", name="Network adapter 1"
    )


def test_bootstrap_is_idempotent(tmp_path):
    estate = observed(tmp_path)
    client = FakeNetBox()

    first = bootstrap(estate, client)
    assert first.created > 0
    # A device is created before its addresses exist, so its primary IP is a patch.
    assert {a.object for a in first.actions if a.status == "updated"} == {
        "esx-01 primary_ip4",
        "fw-01 primary_ip4",
        "sw-core-01 primary_ip4",
    }

    before = client.count("dcim.interfaces")
    client.reset_writes()
    second = bootstrap(estate, client)

    assert second.created == 0
    assert second.updated == 0
    assert second.unchanged == len(second.actions)
    assert client.writes == [], "a second bootstrap must not write to NetBox at all"
    assert client.count("dcim.interfaces") == before


def test_bootstrap_patches_only_the_field_that_changed(tmp_path):
    estate = observed(tmp_path)
    client = FakeNetBox()
    bootstrap(estate, client)

    estate.device("sw-core-01").serial = "FOC9999ZZZ"
    client.reset_writes()
    report = bootstrap(estate, client)

    assert report.created == 0
    assert report.updated == 1
    assert [a.fields for a in report.actions if a.status == "updated"] == [["serial"]]
    assert client.get("dcim.devices", name="sw-core-01")["serial"] == "FOC9999ZZZ"


def test_dry_run_writes_nothing(tmp_path):
    estate = observed(tmp_path)
    client = FakeNetBox(dry_run=True)
    report = bootstrap(estate, client)

    assert report.dry_run is True
    assert report.created > 0
    assert client.writes == []
    assert client.count("dcim.devices") == 0
    assert "would create" in report.summary_line()


def test_sync_limits_itself_to_the_named_devices(tmp_path):
    estate = observed(tmp_path)
    client = FakeNetBox()
    report = sync(estate, client, devices=["sw-core-01", "nope-01"])

    assert report.devices == ["sw-core-01"]
    assert {d["name"] for d in client.all("dcim.devices")} == {"sw-core-01"}
    assert client.count("virtualization.virtual_machines") == 0
    assert any("nope-01" in w for w in report.warnings)


def test_slugify():
    assert slugify("VMware ESXi (standalone)") == "vmware-esxi-standalone"
    assert slugify("WS-C2960X-48TS-L") == "ws-c2960x-48ts-l"


def test_netbox_client_is_none_without_configuration():
    assert NetBoxClient.from_settings(Settings(netbox_url=None, netbox_token=None)) is None
    client = NetBoxClient.from_settings(
        Settings(netbox_url="http://netbox:8080/", netbox_token="t")
    )
    assert client is not None and client.url == "http://netbox:8080"
    with pytest.raises(ValueError):
        client.endpoint("devices")


# --------------------------------------------------------------------------- drift
def test_no_drift_immediately_after_bootstrap(tmp_path):
    client, estate = bootstrapped(tmp_path)
    report = compare(estate, intended_from_netbox(client, estate.site))
    assert report.items == [], [i.summary for i in report.items]
    assert report.clean
    assert "no drift" in report.headline()


def test_drift_detects_changed_vlan_new_vm_and_removed_interface(tmp_path):
    client, _ = bootstrapped(tmp_path)

    cisco = cisco_data()
    for vlan in cisco["vlans"]:
        if vlan["vlan_id"] == "20":
            vlan["vlan_name"] = "srv-prod"
    cisco["interfaces"] = [i for i in cisco["interfaces"] if "1/0/24" not in i["interface"]]
    cisco["interfaces_status"] = [
        i for i in cisco["interfaces_status"] if "1/0/24" not in i["port"]
    ]

    esxi = esxi_data()
    esxi["vms"].append(
        {
            "name": "build-01",
            "power_state": "poweredOn",
            "num_cpu": 8,
            "memory_mb": 16384,
            "disk_gb": 200,
            "guest_os": "Debian GNU/Linux 12 (64-bit)",
            "nics": [
                {
                    "name": "Network adapter 1",
                    "mac": "00:50:56:01:ee:ff",
                    "portgroup": "Servers",
                    "connected": True,
                }
            ],
        }
    )

    after = observed(tmp_path / "after", overrides={"sw-core-01": cisco, "esx-01": esxi})
    report = compare(after, intended_from_netbox(client, after.site))

    vlan_item = next(i for i in report.items if i.object == "vlan20" and i.change == "changed")
    assert vlan_item.field == "name"
    assert (vlan_item.observed, vlan_item.intended) == ("srv-prod", "servers")
    assert vlan_item.device == "sw-core-01"
    assert vlan_item.severity is Severity.medium
    assert "VLAN 20 name is srv-prod" in vlan_item.summary

    vm_item = next(i for i in report.items if i.object == "build-01")
    assert (vm_item.change, vm_item.object_type, vm_item.device) == ("added", "vm", "esx-01")
    assert "not in netbox" in vm_item.summary

    iface_item = next(i for i in report.items if i.object == "sw-core-01:GigabitEthernet1/0/24")
    assert (iface_item.change, iface_item.object_type) == ("removed", "interface")
    assert iface_item.severity is Severity.medium
    assert iface_item.device == "sw-core-01"

    assert report.by_device()["sw-core-01"]
    assert set(report.by_type()) >= {"vlan", "vm", "interface"}
    assert report.counts()["changed"] >= 1
    assert not report.clean


def test_drift_escalates_a_trunk_and_a_missing_device(tmp_path):
    client, _ = bootstrapped(tmp_path)

    cisco = cisco_data()
    for trunk in cisco["trunks"]:
        if trunk["interface"] == "Gi1/0/1":
            trunk["vlans_allowed"] = "10,20"
    after = observed(tmp_path / "after", overrides={"sw-core-01": cisco, "fw-01": None})
    report = compare(after, intended_from_netbox(client, after.site))

    trunk_item = next(
        i
        for i in report.items
        if i.object == "sw-core-01:GigabitEthernet1/0/1" and i.field == "tagged_vlans"
    )
    assert trunk_item.severity is Severity.high, "trunk VLAN membership drift is high severity"

    missing = next(i for i in report.items if i.object == "fw-01" and i.object_type == "device")
    assert (missing.change, missing.severity) == ("removed", Severity.high)
    assert report.worst is Severity.high


def test_drift_notices_an_address_that_moved_ports(tmp_path):
    client, _ = bootstrapped(tmp_path)

    fortigate = fortigate_data()
    for interface in fortigate["interfaces"]:
        if interface["name"] == "srv-vl20":
            interface["name"] = "srv-vl20-new"
    after = observed(tmp_path / "after", overrides={"fw-01": fortigate})
    report = compare(after, intended_from_netbox(client, after.site))

    moved = next(i for i in report.items if i.object == "10.0.20.1/24" and i.change == "changed")
    assert moved.field == "assignment"
    assert moved.observed == "fw-01:srv-vl20-new"
    assert moved.intended == "fw-01:srv-vl20"
    assert moved.severity is Severity.medium


def test_drift_can_be_limited_to_one_device(tmp_path):
    client, _ = bootstrapped(tmp_path)
    esxi = esxi_data()
    esxi["vms"][0]["memory_mb"] = 16384
    cisco = cisco_data()
    cisco["interfaces"] = [i for i in cisco["interfaces"] if "1/0/24" not in i["interface"]]
    cisco["interfaces_status"] = [
        i for i in cisco["interfaces_status"] if "1/0/24" not in i["port"]
    ]

    after = observed(tmp_path / "after", overrides={"esx-01": esxi, "sw-core-01": cisco})
    everything = compare(after, intended_from_netbox(client, after.site))
    just_host = compare(after, intended_from_netbox(client, after.site), devices=["esx-01"])

    assert {i.device for i in just_host.items} == {"esx-01"}
    assert len(just_host.items) < len(everything.items)
    assert just_host.devices == ["esx-01"]


def test_drift_report_is_structured_and_free_of_raw_config(tmp_path, gateway):
    client, _ = bootstrapped(tmp_path)
    esxi = esxi_data()
    esxi["vms"][0]["num_cpu"] = 8
    after = observed(tmp_path / "after", overrides={"esx-01": esxi})
    report = compare(after, intended_from_netbox(client, after.site))

    view = report.llm_view()
    gateway.refuse_raw_config(view)
    safe = gateway.egress(view, tool="inventory.drift_report")
    assert safe["by_device"]["esx-01"][0]["object"] == "app-01"
    assert all(isinstance(item["summary"], str) for item in safe["by_device"]["esx-01"])
    assert RedactionGateway.looks_like_raw_config(str(view)) is False


# --------------------------------------------------------------------------- baseline
def test_baseline_accept_records_and_reloads(tmp_path):
    settings = write_estate(tmp_path)
    estate = service.observed_estate(settings)
    client = FakeNetBox()
    bootstrap(estate, client)

    baseline = service.accept_baseline(
        accepted_by="owner", note="post-audit", settings=settings, estate=estate, client=client
    )
    assert baseline.fingerprint == estate.fingerprint()
    assert baseline.counts["devices"] == 3
    assert baseline.netbox_journal_id is not None

    entry = client.all("extras.journal_entries")[0]
    assert entry["assigned_object_type"] == "dcim.site"
    assert "Baseline accepted by owner" in entry["comments"]

    store = BaselineStore.from_settings(settings)
    reloaded = store.current()
    assert reloaded is not None
    assert reloaded.matches(estate)
    assert reloaded.accepted_by == "owner"
    assert len(store.history()) == 1
    assert "fingerprint" in reloaded.llm_view()


def test_baseline_fingerprint_reacts_to_change(tmp_path):
    settings = write_estate(tmp_path)
    estate = service.observed_estate(settings)
    baseline = service.accept_baseline(settings=settings, estate=estate, client=None)
    assert baseline.netbox_journal_id is None

    esxi = esxi_data()
    esxi["vms"][0]["memory_mb"] = 16384
    changed = service.observed_estate(write_estate(tmp_path / "after", {"esx-01": esxi}))
    assert not baseline.matches(changed)


def test_baseline_is_absent_before_acceptance(tmp_path):
    settings = write_estate(tmp_path)
    assert BaselineStore.from_settings(settings).current() is None


# --------------------------------------------------------------------------- service wiring
def test_drift_falls_back_to_the_baseline_without_netbox(tmp_path):
    settings = write_estate(tmp_path)
    estate = service.observed_estate(settings)
    service.accept_baseline(settings=settings, estate=estate)

    esxi = esxi_data()
    esxi["vms"] = [vm for vm in esxi["vms"] if vm["name"] != "mgmt-01"]
    later = service.observed_estate(write_estate(tmp_path / "after", {"esx-01": esxi}))

    report = service.drift_report(settings=settings, observed=later)
    assert report.source == "baseline"
    removed = next(i for i in report.items if i.object == "mgmt-01")
    assert removed.change == "removed"
    assert removed.severity is Severity.medium


def test_drift_without_netbox_or_baseline_explains_itself(tmp_path):
    settings = write_estate(tmp_path)
    report = service.drift_report(settings=settings)
    assert report.source == "none"
    assert report.clean
    assert any("baseline" in w for w in report.warnings)


def test_intended_estate_prefers_netbox_but_warns_without_a_baseline(tmp_path):
    settings = write_estate(tmp_path)
    client, estate = bootstrapped(tmp_path)
    intended, source, warnings = service.intended_estate(settings, client)

    assert source == "netbox"
    assert {d.name for d in intended.devices} == {"fw-01", "sw-core-01", "esx-01"}
    assert any("baseline" in w for w in warnings)


# --------------------------------------------------------------------------- pynetbox wrapper
class _Record:
    """The slice of a pynetbox Record that NetBoxClient touches."""

    def __init__(self, **fields):
        self.fields = fields

    def serialize(self):
        return dict(self.fields)

    @property
    def id(self):
        return self.fields.get("id")

    def update(self, data):
        self.fields.update(data)
        return True

    def delete(self):
        self.fields["deleted"] = True


class _Endpoint:
    def __init__(self, records=()):
        self.records = list(records)

    def filter(self, **filters):
        return [r for r in self.records if all(r.fields.get(k) == v for k, v in filters.items())]

    def all(self):
        return list(self.records)

    def create(self, data):
        record = _Record(id=len(self.records) + 1, **data)
        self.records.append(record)
        return record

    def get(self, obj_id):
        return next((r for r in self.records if r.fields.get("id") == obj_id), None)


@pytest.fixture
def pynetbox_stub(monkeypatch):
    """Install a stand-in `pynetbox` so the real client's translation layer is exercised."""
    import sys
    import types

    devices = _Endpoint([_Record(id=1, name="sw-core-01", serial="OLD")])
    device_types = _Endpoint()
    api = types.SimpleNamespace(
        dcim=types.SimpleNamespace(devices=devices, device_types=device_types),
        version="4.1",
    )
    module = types.ModuleType("pynetbox")
    module.api = lambda url, token=None, threading=False: api
    monkeypatch.setitem(sys.modules, "pynetbox", module)
    return devices, device_types


def test_netbox_client_translates_to_pynetbox(pynetbox_stub):
    devices, device_types = pynetbox_stub
    client = NetBoxClient("https://netbox.example/", "token")

    assert client.get("dcim.devices", name="sw-core-01")["serial"] == "OLD"
    assert client.get("dcim.devices", name="missing") is None
    assert [d["name"] for d in client.all("dcim.devices")] == ["sw-core-01"]
    assert client.ping() == {"url": "https://netbox.example", "version": "4.1"}
    assert client.endpoint("dcim.device-types") is device_types, "dashes become underscores"

    patched = client.ensure("dcim.devices", {"name": "sw-core-01"}, {"serial": "NEW"})
    assert (patched.status, patched.changed_fields) == ("updated", ["serial"])
    assert devices.records[0].fields["serial"] == "NEW"
    again = client.ensure("dcim.devices", {"name": "sw-core-01"}, {"serial": "NEW"})
    assert again.status == "unchanged"

    made = client.ensure("dcim.device_types", {"model": "C9200"}, {"slug": "c9200"})
    assert made.status == "created"
    assert made.obj["model"] == "C9200"
    assert made.id == 1


def test_netbox_client_dry_run_reads_but_never_writes(pynetbox_stub):
    devices, _ = pynetbox_stub
    client = NetBoxClient("https://netbox.example", "token", dry_run=True)

    result = client.ensure("dcim.devices", {"name": "sw-core-01"}, {"serial": "NEW"})
    assert result.status == "would-update"
    assert devices.records[0].fields["serial"] == "OLD", "a dry run must not write"

    preview = client.ensure("dcim.devices", {"name": "new-01"}, {"serial": "S"})
    assert preview.status == "would-create"
    assert preview.id is not None and preview.id < 0, "a placeholder id lets the preview recurse"
    assert len(devices.records) == 1


def test_ensure_comparison_normalises_nested_objects_and_mac_case():
    from infra_agent.reconcile.netbox import normalize_value

    assert normalize_value("device", {"id": 7, "name": "sw"}) == 7
    assert normalize_value("mac_address", "AA:BB:CC:00:01:01") == "aa:bb:cc:00:01:01"
    assert normalize_value("serial", None) == normalize_value("serial", "")
    assert normalize_value("tagged_vlans", [{"id": 3}, {"id": 1}]) == [1, 3]


def test_fake_netbox_resolves_natural_keys_through_ids():
    client = FakeNetBox()
    site = client.create("dcim.sites", {"slug": "hq", "name": "HQ"})
    device = client.create("dcim.devices", {"name": "sw-core-01", "site": site["id"]})
    client.create("dcim.interfaces", {"device": device["id"], "name": "Gi1/0/1"})

    assert client.get("dcim.devices", site="hq")["name"] == "sw-core-01"
    assert client.get("dcim.interfaces", device="sw-core-01", name="Gi1/0/1") is not None
    assert client.get("dcim.interfaces", device="fw-01", name="Gi1/0/1") is None


def test_sync_writes_only_the_prefixes_its_devices_configure(tmp_path):
    estate = observed(tmp_path)
    client = FakeNetBox()
    sync(estate, client, devices=["sw-core-01"])
    assert {p["prefix"] for p in client.all("ipam.prefixes")} == {"10.0.10.0/24"}
