"""ESXi collector tests.

Everything runs against a fake pyvmomi object tree and a fake paramiko client;
nothing here touches a host, a network or the pyvmomi library itself (the one
test that does builds a real `EventFilterSpec` and skips when the optional
`devices` extra is not installed).
"""

from __future__ import annotations

import base64
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace as ns

import pytest
import yaml
from prometheus_client import REGISTRY

from infra_agent.collectors.base import COLLECTORS, Collector
from infra_agent.collectors.esxi import (
    BACKUP_COMMAND,
    BACKUP_FILENAME,
    EVENT_TYPE_IDS,
    EsxiCollector,
    bundle_paths,
    datastore_from_path,
    first_host,
    is_free_license,
    ratio,
    snapshot_rows,
    vmkernel_services,
)
from infra_agent.models.common import Credential, DeviceKind, SeedDevice

NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)
RULES = Path(__file__).resolve().parents[1] / "infra_agent" / "monitoring" / "rules"


def event(type_name: str, **attrs):
    """A stand-in for `vim.event.<type_name>`; the collector keys off the class name."""
    return type(type_name, (ns,), {})(**attrs)


def device_of(cls_name: str, **attrs):
    return type(cls_name, (ns,), {})(**attrs)


# --------------------------------------------------------------------------
# the fake host
# --------------------------------------------------------------------------
def build_host():
    pnic0 = ns(
        device="vmnic0",
        key="key-vim.host.PhysicalNic-vmnic0",
        mac="38:63:bb:3f:5a:10",
        driver="ntg3",
        pci="0000:02:00.0",
        linkSpeed=ns(speedMb=1000, duplex=True),
        autoNegotiateSupported=True,
    )
    pnic1 = ns(
        device="vmnic1",
        key="key-vim.host.PhysicalNic-vmnic1",
        mac="38:63:bb:3f:5a:11",
        driver="ntg3",
        pci="0000:02:00.1",
        linkSpeed=None,
        autoNegotiateSupported=True,
    )
    security = ns(allowPromiscuous=False, forgedTransmits=False, macChanges=False)
    vswitch0 = ns(
        name="vSwitch0",
        pnic=[pnic0.key, pnic1.key],
        mtu=1500,
        numPorts=1536,
        numPortsAvailable=1480,
        spec=ns(
            numPorts=1536,
            mtu=1500,
            bridge=ns(
                nicDevice=["vmnic0", "vmnic1"],
                linkDiscoveryProtocolConfig=ns(protocol="cdp", operation="both"),
            ),
            policy=ns(security=security),
        ),
    )
    vswitch1 = ns(
        name="vSwitch1",
        pnic=[],
        mtu=9000,
        numPorts=1024,
        numPortsAvailable=1024,
        spec=ns(
            numPorts=1024,
            mtu=9000,
            bridge=ns(
                nicDevice=[],
                linkDiscoveryProtocolConfig=ns(protocol="cdp", operation="listen"),
            ),
            policy=ns(security=security),
        ),
    )
    portgroups = [
        ns(
            key="key-vim.host.PortGroup-Management Network",
            port=[ns(), ns()],
            spec=ns(
                name="Management Network",
                vlanId=10,
                vswitchName="vSwitch0",
                policy=ns(
                    security=ns(allowPromiscuous=None, forgedTransmits=None, macChanges=None)
                ),
            ),
        ),
        ns(
            key="key-vim.host.PortGroup-VM Servers",
            port=[ns()],
            spec=ns(
                name="VM Servers",
                vlanId=20,
                vswitchName="vSwitch0",
                policy=ns(
                    security=ns(allowPromiscuous=None, forgedTransmits=None, macChanges=None)
                ),
            ),
        ),
    ]
    vmk0 = ns(
        device="vmk0",
        key="key-vim.host.VirtualNic-vmk0",
        portgroup="Management Network",
        spec=ns(
            ip=ns(ipAddress="10.0.0.21", subnetMask="255.255.255.0", dhcp=False),
            mac="38:63:bb:3f:5a:10",
            mtu=1500,
            netStackInstanceKey="defaultTcpipStack",
        ),
    )
    vmk1 = ns(
        device="vmk1",
        key="key-vim.host.VirtualNic-vmk1",
        portgroup="Storage",
        spec=ns(
            ip=ns(ipAddress="10.10.0.21", subnetMask="255.255.255.0", dhcp=False),
            mac="00:50:56:6a:00:01",
            mtu=9000,
            netStackInstanceKey="defaultTcpipStack",
        ),
    )
    net_config = [
        ns(
            nicType="management",
            selectedVnic=["management.key-vim.host.VirtualNic-vmk0"],
            candidateVnic=[vmk0, vmk1],
        ),
        ns(
            nicType="vmotion",
            selectedVnic=[],
            candidateVnic=[vmk0, vmk1],
        ),
        ns(
            nicType="vSphereProvisioning",
            selectedVnic=["vSphereProvisioning.key-vim.host.VirtualNic-vmk1"],
            candidateVnic=[vmk0, vmk1],
        ),
    ]
    datastores = [
        ns(
            summary=ns(
                name="datastore1",
                type="VMFS",
                url="ds:///vmfs/volumes/5f0a/",
                accessible=True,
                maintenanceMode="normal",
                capacity=1_199_495_774_208,
                freeSpace=119_949_577_420,
                uncommitted=40_000_000_000,
            ),
            info=ns(
                vmfs=ns(
                    uuid="5f0a1b2c-3d4e5f60-7a8b-38 63bb3f5a10",
                    version="6.82",
                    ssd=False,
                    local=True,
                    extent=[ns(diskName="naa.600508b1001c1e1f2a3b4c5d6e7f8090")],
                )
            ),
        ),
        ns(
            summary=ns(
                name="nfs-backup",
                type="NFS",
                url="ds:///vmfs/volumes/abcd/",
                accessible=True,
                maintenanceMode="normal",
                capacity=8_000_000_000_000,
                freeSpace=2_000_000_000_000,
                uncommitted=None,
            ),
            info=ns(nas=ns(type="NFS", remoteHost="10.10.0.9", remotePath="/export/backup")),
        ),
    ]
    disk = device_of(
        "VirtualDisk",
        key=2000,
        deviceInfo=ns(label="Hard disk 1"),
        capacityInKB=41_943_040,
        backing=ns(
            fileName="[datastore1] web-01/web-01.vmdk",
            diskMode="persistent",
            thinProvisioned=True,
            uuid="6000C296-1234-5678-9abc-def012345678",
        ),
    )
    vnic = device_of(
        "VirtualVmxnet3",
        key=4000,
        deviceInfo=ns(label="Network adapter 1"),
        macAddress="00:50:56:aa:bb:01",
        addressType="assigned",
        backing=ns(deviceName="VM Servers"),
        connectable=ns(connected=True, startConnected=True),
    )
    web = ns(
        summary=ns(
            config=ns(
                name="web-01",
                uuid="4210a1b2-c3d4-e5f6-0718-293a4b5c6d7e",
                instanceUuid="5010a1b2-c3d4-e5f6-0718-293a4b5c6d7e",
                vmPathName="[datastore1] web-01/web-01.vmx",
                template=False,
                annotation="public web",
                numCpu=4,
                memorySizeMB=8192,
                guestFullName="Ubuntu Linux (64-bit)",
            ),
            runtime=ns(
                powerState="poweredOn",
                connectionState="connected",
                bootTime=NOW - timedelta(days=30),
            ),
            quickStats=ns(
                overallCpuUsage=440,
                guestMemoryUsage=3200,
                hostMemoryUsage=8400,
                uptimeSeconds=2_592_000,
            ),
            storage=ns(
                committed=45_000_000_000, uncommitted=3_000_000_000, unshared=45_000_000_000
            ),
        ),
        guest=ns(
            guestState="running",
            hostName="web-01.lab.local",
            ipAddress="10.0.20.31",
            toolsStatus="toolsOk",
            toolsRunningStatus="guestToolsRunning",
            toolsVersion="12325",
            toolsVersionStatus2="guestToolsCurrent",
            net=[
                ns(
                    network="VM Servers",
                    macAddress="00:50:56:aa:bb:01",
                    connected=True,
                    ipAddress=["10.0.20.31", "fe80::250:56ff:feaa:bb01"],
                    ipConfig=None,
                )
            ],
            disk=[ns(diskPath="/", capacity=40_000_000_000, freeSpace=18_000_000_000)],
        ),
        config=ns(hardware=ns(device=[disk, vnic])),
        snapshot=ns(
            rootSnapshotList=[
                ns(
                    id=1,
                    name="pre-patch",
                    description="before the June rollup",
                    createTime=NOW - timedelta(days=9),
                    state="poweredOn",
                    quiesced=False,
                    childSnapshotList=[
                        ns(
                            id=2,
                            name="post-patch",
                            description="",
                            createTime=NOW - timedelta(days=2),
                            state="poweredOn",
                            quiesced=False,
                            childSnapshotList=[],
                        )
                    ],
                )
            ]
        ),
    )
    db = ns(
        summary=ns(
            config=ns(
                name="db-01",
                uuid="4210ffff-c3d4-e5f6-0718-293a4b5c6d7f",
                instanceUuid="5010ffff-c3d4-e5f6-0718-293a4b5c6d7f",
                vmPathName="[datastore1] db-01/db-01.vmx",
                template=False,
                annotation=None,
                numCpu=8,
                memorySizeMB=32768,
                guestFullName="Microsoft Windows Server 2022 (64-bit)",
            ),
            runtime=ns(powerState="poweredOff", connectionState="connected", bootTime=None),
            quickStats=ns(
                overallCpuUsage=0, guestMemoryUsage=0, hostMemoryUsage=0, uptimeSeconds=0
            ),
            storage=ns(committed=210_000_000_000, uncommitted=0, unshared=210_000_000_000),
        ),
        guest=ns(
            guestState="notRunning",
            hostName=None,
            ipAddress=None,
            toolsStatus="toolsNotRunning",
            toolsRunningStatus="guestToolsNotRunning",
            toolsVersion="12325",
            toolsVersionStatus2="guestToolsCurrent",
            net=[],
            disk=[],
        ),
        config=ns(hardware=ns(device=[])),
        snapshot=None,
    )
    host = ns(
        name="esx-01.lab.local",
        summary=ns(
            hardware=ns(
                vendor="HPE",
                model="ProLiant DL380 Gen9",
                uuid="31313131-3131-4331-5A33-343231414230",
                cpuModel="Intel(R) Xeon(R) CPU E5-2650 v4 @ 2.20GHz ",
                numCpuPkgs=2,
                numCpuCores=24,
                numCpuThreads=48,
                cpuMhz=2200,
                memorySize=137_438_953_472,
                numNics=4,
                numHBAs=2,
                otherIdentifyingInfo=[
                    ns(identifierType=ns(key="ServiceTag"), identifierValue="CZ3421AB01"),
                    ns(identifierType=ns(key="AssetTag"), identifierValue="rack12-u14"),
                ],
            ),
            runtime=ns(
                powerState="poweredOn",
                connectionState="connected",
                inMaintenanceMode=False,
                bootTime=NOW - timedelta(days=120),
            ),
            quickStats=ns(overallCpuUsage=13_200, overallMemoryUsage=98_304, uptime=10_368_000),
        ),
        hardware=ns(biosInfo=ns(biosVersion="P89", releaseDate=datetime(2019, 10, 21, tzinfo=UTC))),
        config=ns(
            network=ns(
                pnic=[pnic0, pnic1],
                vswitch=[vswitch0, vswitch1],
                portgroup=portgroups,
                vnic=[vmk0, vmk1],
            ),
            virtualNicManagerInfo=ns(netConfig=net_config),
        ),
        datastore=datastores,
        vm=[web, db],
    )
    return host


def build_content(host=None, events=None, license_name="VMware vSphere 7 Hypervisor"):
    host = host or build_host()
    queried: list = []

    class EventManager:
        def QueryEvents(self, spec):  # noqa: N802 - pyvmomi spelling
            queried.append(spec)
            return events if events is not None else []

    content = ns(
        about=ns(
            fullName="VMware ESXi 7.0.3 build-21930508",
            name="VMware ESXi",
            version="7.0.3",
            build="21930508",
            apiVersion="7.0.3.0",
            osType="vmnix-x86",
            licenseProductName="VMware ESX Server",
            licenseProductVersion="7.0",
        ),
        rootFolder=ns(childEntity=[ns(hostFolder=ns(childEntity=[ns(host=[host])]))]),
        licenseManager=ns(licenses=[ns(name=license_name, editionKey="esxBasic", total=0, used=1)]),
        eventManager=EventManager(),
    )
    content.queried_specs = queried
    return content


@pytest.fixture
def collector(monkeypatch):
    """A collector whose event filter is a plain dict, so pyVmomi is not needed."""
    monkeypatch.setattr(
        EsxiCollector,
        "event_filter_spec",
        staticmethod(lambda since, type_ids: {"since": since, "types": type_ids}),
    )
    return EsxiCollector()


@pytest.fixture
def data(collector):
    return collector.collect_from_content(build_content(), now=NOW)


# --------------------------------------------------------------------------
# pure helpers
# --------------------------------------------------------------------------
def test_datastore_from_path():
    assert datastore_from_path("[datastore1] web-01/web-01.vmdk") == "datastore1"
    assert datastore_from_path("[nfs-backup] db/db.vmx") == "nfs-backup"
    assert datastore_from_path("no-brackets.vmdk") is None
    assert datastore_from_path(None) is None


def test_free_license_is_detected_by_the_word_hypervisor():
    assert is_free_license("VMware vSphere 7 Hypervisor") is True
    assert is_free_license(None, "VMware vSphere 6 Hypervisor (free)") is True
    assert is_free_license("VMware vSphere 7 Enterprise Plus") is False
    assert is_free_license(None, None) is False


def test_ratio_survives_missing_and_zero_denominators():
    assert ratio(50, 200) == 0.25
    assert ratio(1, 0) is None
    assert ratio(None, 10) is None


def test_bundle_paths_prefers_scratch():
    output = "Bundle can be downloaded at : http://*/downloads/52f3a1-9c8b/configBundle-esx-01.tgz"
    assert bundle_paths(output) == [
        "/scratch/downloads/52f3a1-9c8b/configBundle-esx-01.tgz",
        "/downloads/52f3a1-9c8b/configBundle-esx-01.tgz",
    ]
    with pytest.raises(ValueError):
        bundle_paths("Unable to create the bundle")


def test_first_host_raises_when_the_inventory_is_empty():
    with pytest.raises(LookupError):
        first_host(ns(rootFolder=ns(childEntity=[])))


def test_vmkernel_services_matches_the_prefixed_selection_keys():
    vmk0 = ns(device="vmk0", key="key-vim.host.VirtualNic-vmk0")
    vmk1 = ns(device="vmk1", key="key-vim.host.VirtualNic-vmk1")
    config = [
        ns(
            nicType="management",
            selectedVnic=["management.key-vim.host.VirtualNic-vmk0"],
            candidateVnic=[vmk0, vmk1],
        ),
        ns(nicType="vmotion", selectedVnic=[], candidateVnic=[vmk0, vmk1]),
    ]
    assert vmkernel_services(config) == {"vmk0": ["management"]}
    assert vmkernel_services(None) == {}


def test_snapshot_rows_flattens_the_tree_with_ages():
    rows = snapshot_rows(
        [
            ns(
                id=1,
                name="root",
                description="",
                createTime=NOW - timedelta(days=3),
                state="poweredOn",
                quiesced=False,
                childSnapshotList=[
                    ns(
                        id=2,
                        name="child",
                        description="",
                        createTime=NOW - timedelta(hours=6),
                        state="poweredOn",
                        quiesced=True,
                        childSnapshotList=None,
                    )
                ],
            )
        ],
        NOW,
    )
    assert [(r["name"], r["depth"]) for r in rows] == [("root", 0), ("child", 1)]
    assert rows[0]["age_seconds"] == pytest.approx(3 * 86400)
    assert rows[1]["age_seconds"] == pytest.approx(6 * 3600)


# --------------------------------------------------------------------------
# registration and contract
# --------------------------------------------------------------------------
def test_collector_is_registered_for_the_esxi_kind():
    assert COLLECTORS[DeviceKind.esxi] is EsxiCollector
    assert issubclass(EsxiCollector, Collector)
    assert EsxiCollector.name == "esxi"
    assert EsxiCollector.interval_seconds == 300


def test_scheduler_imports_the_esxi_collector():
    from infra_agent import scheduler

    scheduler._load_collectors()
    assert DeviceKind.esxi in COLLECTORS


# --------------------------------------------------------------------------
# collection
# --------------------------------------------------------------------------
def test_host_hardware_and_usage(data):
    host = data["host"]
    assert host["model"] == "ProLiant DL380 Gen9"
    assert host["service_tag"] == "CZ3421AB01"
    assert host["cpu_model"] == "Intel(R) Xeon(R) CPU E5-2650 v4 @ 2.20GHz"
    assert host["cpu_cores"] == 24
    assert host["cpu_capacity_mhz"] == 24 * 2200
    assert host["cpu_usage_ratio"] == pytest.approx(0.25)
    assert host["memory_usage_ratio"] == pytest.approx(0.75, abs=0.01)
    assert host["bios_version"] == "P89"
    assert host["in_maintenance_mode"] is False


def test_version_and_free_license_warning(data):
    assert data["version"]["build"] == "21930508"
    assert data["version"]["version"] == "7.0.3"
    assert data["license"]["free"] is True
    assert data["license"]["names"] == ["VMware vSphere 7 Hypervisor"]
    assert any("free licence" in w and "SSH" in w for w in data["warnings"])


def test_licensed_host_has_no_free_license_warning(collector):
    data = collector.collect_from_content(
        build_content(license_name="VMware vSphere 7 Enterprise Plus"), now=NOW
    )
    assert data["license"]["free"] is False
    assert not any("free licence" in w for w in data["warnings"])


def test_license_key_is_never_collected(data):
    assert "licenseKey" not in json.dumps(data)
    assert set(data["license"]["details"][0]) == {"name", "edition", "total", "used"}


def test_pnics(data):
    up, down = data["pnics"]
    assert (up["name"], up["mac"], up["driver"]) == ("vmnic0", "38:63:bb:3f:5a:10", "ntg3")
    assert up["link"] is True and up["speed_mb"] == 1000
    assert down["link"] is False and down["speed_mb"] is None


def test_vswitches_and_the_cdp_warning(data):
    good, bad = data["vswitches"]
    assert good["name"] == "vSwitch0"
    assert good["uplinks"] == ["vmnic0", "vmnic1"]
    assert good["mtu"] == 1500
    assert good["cdp_mode"] == "both" and good["cdp_ok"] is True
    assert good["warnings"] == []

    assert bad["cdp_mode"] == "listen" and bad["cdp_ok"] is False
    assert any("link discovery is 'listen'" in w for w in bad["warnings"])
    assert any("no uplink attached" in w for w in bad["warnings"])
    assert any("vswitch vSwitch1" in w for w in data["warnings"])


def test_portgroups_and_vmkernel_ports(data):
    assert [(p["name"], p["vlan"], p["vswitch"]) for p in data["portgroups"]] == [
        ("Management Network", 10, "vSwitch0"),
        ("VM Servers", 20, "vSwitch0"),
    ]
    vmk0, vmk1 = data["vmkernel"]
    assert vmk0["name"] == "vmk0"
    assert vmk0["ip"] == "10.0.0.21"
    assert vmk0["portgroup"] == "Management Network"
    assert vmk0["services"] == ["management"]
    assert vmk1["mtu"] == 9000
    assert vmk1["services"] == ["vSphereProvisioning"]


def test_datastores_carry_their_backing(data):
    vmfs, nfs = data["datastores"]
    assert vmfs["type"] == "VMFS"
    assert vmfs["capacity_bytes"] == 1_199_495_774_208
    assert vmfs["free_ratio"] == pytest.approx(0.1, abs=0.001)
    assert vmfs["backing"]["kind"] == "vmfs"
    assert vmfs["backing"]["devices"] == ["naa.600508b1001c1e1f2a3b4c5d6e7f8090"]
    assert nfs["backing"] == {
        "kind": "nas",
        "type": "NFS",
        "remote_host": "10.10.0.9",
        "remote_path": "/export/backup",
    }


def test_vm_rows(data):
    web, db = data["vms"]
    assert web["name"] == "web-01"
    assert web["uuid"] == "4210a1b2-c3d4-e5f6-0718-293a4b5c6d7e"
    assert web["power_state"] == "poweredOn"
    assert (web["cpu"], web["memory_mb"]) == (4, 8192)
    assert web["guest_os"] == "Ubuntu Linux (64-bit)"
    assert web["guest_hostname"] == "web-01.lab.local"
    assert "10.0.20.31" in web["guest_ips"]
    assert web["tools"]["status"] == "toolsOk"
    assert web["datastore"] == "datastore1"
    assert web["usage"]["cpu_mhz"] == 440

    assert db["power_state"] == "poweredOff"
    assert db["guest_ips"] == []
    assert db["snapshots"] == [] and db["snapshot_count"] == 0


def test_vm_disks_and_nics(data):
    web = data["vms"][0]
    (disk,) = web["disks"]
    assert disk["label"] == "Hard disk 1"
    assert disk["capacity_bytes"] == 41_943_040 * 1024
    assert disk["file"] == "[datastore1] web-01/web-01.vmdk"
    assert disk["datastore"] == "datastore1"
    assert disk["thin_provisioned"] is True

    (nic,) = web["nics"]
    assert nic["mac"] == "00:50:56:aa:bb:01"
    assert nic["portgroup"] == "VM Servers"
    assert nic["connected"] is True
    assert nic["type"] == "VirtualVmxnet3"


def test_vm_snapshots_have_ages(data):
    web = data["vms"][0]
    assert [s["name"] for s in web["snapshots"]] == ["pre-patch", "post-patch"]
    assert web["snapshot_count"] == 2
    assert web["oldest_snapshot_age_seconds"] == pytest.approx(9 * 86400)


def test_events_are_filtered_to_the_last_24h_and_carry_the_user(collector):
    events = [
        event(
            "VmPoweredOffEvent",
            key=41,
            createdTime=NOW - timedelta(hours=2),
            userName="lab\\bob",
            vm=ns(name="db-01"),
            host=ns(name="esx-01.lab.local"),
            fullFormattedMessage="db-01 on esx-01.lab.local is powered off",
        ),
        event(
            "VmReconfiguredEvent",
            key=42,
            createdTime=NOW - timedelta(hours=1),
            userName="root",
            vm=ns(name="web-01"),
            host=ns(name="esx-01.lab.local"),
            fullFormattedMessage="Reconfigured web-01 on esx-01.lab.local",
        ),
        event(
            "UserLoginSessionEvent",  # not a power/config event
            key=43,
            createdTime=NOW - timedelta(minutes=5),
            userName="root",
            fullFormattedMessage="User root@10.0.0.5 logged in",
        ),
    ]
    content = build_content(events=events)
    data = collector.collect_from_content(content, now=NOW)

    assert [e["type"] for e in data["events"]] == ["VmPoweredOffEvent", "VmReconfiguredEvent"]
    power_off = data["events"][0]
    assert power_off["user"] == "lab\\bob"
    assert power_off["vm"] == "db-01"
    assert power_off["at"] == (NOW - timedelta(hours=2)).isoformat()

    (spec,) = content.queried_specs
    assert spec["since"] == NOW - timedelta(hours=24)
    assert "VmPoweredOffEvent" in spec["types"]


def test_event_query_falls_back_when_the_type_filter_is_rejected(collector):
    calls: list = []

    class PickyEventManager:
        def QueryEvents(self, spec):  # noqa: N802 - pyvmomi spelling
            calls.append(spec)
            if spec["types"]:
                raise RuntimeError("InvalidArgument: eventTypeId")
            return [
                event(
                    "VmPoweredOnEvent",
                    key=1,
                    createdTime=NOW,
                    userName="root",
                    vm=ns(name="web-01"),
                    host=ns(name="esx-01.lab.local"),
                    fullFormattedMessage="web-01 powered on",
                )
            ]

    content = build_content()
    content.eventManager = PickyEventManager()
    data = collector.collect_from_content(content, now=NOW)

    assert len(calls) == 2 and calls[1]["types"] is None
    assert [e["type"] for e in data["events"]] == ["VmPoweredOnEvent"]
    assert "events" not in data["errors"]


def test_event_filter_spec_builds_a_real_pyvmomi_spec():
    pytest.importorskip("pyVmomi")
    spec = EsxiCollector.event_filter_spec(NOW, ["VmPoweredOffEvent"])
    assert list(spec.eventTypeId) == ["VmPoweredOffEvent"]
    assert spec.time.beginTime == NOW


def test_every_declared_event_type_is_a_power_or_config_event():
    assert "VmPoweredOffEvent" in EVENT_TYPE_IDS
    assert "UserLoginSessionEvent" not in EVENT_TYPE_IDS


# --------------------------------------------------------------------------
# degradation
# --------------------------------------------------------------------------
def test_one_broken_section_does_not_lose_the_run(collector):
    host = build_host()

    class Exploding(list):
        def __iter__(self):
            raise RuntimeError("hostd is busy")

    host.datastore = Exploding([object()])
    data = collector.collect_from_content(build_content(host=host), now=NOW)

    assert data["datastores"] == []
    assert "hostd is busy" in data["errors"]["datastores"]
    assert data["vms"] and data["pnics"]  # the rest still landed


# --------------------------------------------------------------------------
# metrics
# --------------------------------------------------------------------------
def test_metrics_are_published(collector, data):
    collector.publish_metrics("esx-01", data)
    sample = REGISTRY.get_sample_value

    assert sample("infra_esxi_host_cpu_usage_ratio", {"device": "esx-01"}) == pytest.approx(0.25)
    assert sample("infra_esxi_host_memory_usage_ratio", {"device": "esx-01"}) == pytest.approx(
        0.75, abs=0.01
    )
    assert sample(
        "infra_esxi_datastore_free_bytes", {"device": "esx-01", "datastore": "datastore1"}
    ) == pytest.approx(119_949_577_420)
    assert sample(
        "infra_esxi_datastore_capacity_bytes", {"device": "esx-01", "datastore": "datastore1"}
    ) == pytest.approx(1_199_495_774_208)
    assert sample("infra_esxi_vm_power_state", {"device": "esx-01", "vm": "web-01"}) == 1
    assert sample("infra_esxi_vm_power_state", {"device": "esx-01", "vm": "db-01"}) == 0
    assert sample(
        "infra_esxi_vm_snapshot_age_seconds", {"device": "esx-01", "vm": "web-01"}
    ) == pytest.approx(9 * 86400)
    assert sample("infra_esxi_vm_snapshot_count", {"device": "esx-01", "vm": "db-01"}) == 0
    assert sample("infra_esxi_pnic_link_up", {"device": "esx-01", "pnic": "vmnic0"}) == 1
    assert sample("infra_esxi_pnic_link_up", {"device": "esx-01", "pnic": "vmnic1"}) == 0


def test_collect_connects_disconnects_and_publishes(monkeypatch, collector):
    content = build_content()
    closed: list[bool] = []
    monkeypatch.setattr(
        EsxiCollector, "_connect", lambda self, device, cred: ns(RetrieveContent=lambda: content)
    )
    monkeypatch.setattr(EsxiCollector, "_disconnect", lambda self, si: closed.append(True))

    device = SeedDevice(
        name="esx-metrics", kind=DeviceKind.esxi, mgmt_ip="10.0.0.21", credential_ref="esx-01"
    )
    data = collector.collect(device, Credential(username="infra-ro"))

    assert closed == [True]
    assert data["host"]["model"] == "ProLiant DL380 Gen9"
    assert (
        REGISTRY.get_sample_value(
            "infra_esxi_vm_power_state", {"device": "esx-metrics", "vm": "web-01"}
        )
        == 1
    )


# --------------------------------------------------------------------------
# host-config backup over SSH
# --------------------------------------------------------------------------
BUNDLE = b"\x1f\x8b\x08\x00fake-tgz-bytes\x00\x00"
BACKUP_OUTPUT = (
    "Bundle can be downloaded at : http://*/downloads/52f3a1-9c8b/configBundle-esx-01.tgz\n"
)


class FakeStream:
    def __init__(self, payload: bytes, status: int = 0):
        self._payload = payload
        self.channel = ns(recv_exit_status=lambda: status)

    def read(self) -> bytes:
        return self._payload


class FakeSftpFile:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeSftp:
    def __init__(self, files: dict[str, bytes]):
        self.files = files
        self.opened: list[str] = []
        self.closed = False

    def open(self, path, mode="r"):
        self.opened.append(path)
        if path not in self.files:
            raise OSError(2, "No such file")
        return FakeSftpFile(self.files[path])

    def close(self):
        self.closed = True


class FakeSSH:
    def __init__(self, output: str, files: dict[str, bytes], status: int = 0):
        self.output = output
        self.status = status
        self.sftp = FakeSftp(files)
        self.commands: list[str] = []
        self.closed = False

    def exec_command(self, command, timeout=None):
        self.commands.append(command)
        return None, FakeStream(self.output.encode(), self.status), FakeStream(b"", self.status)

    def open_sftp(self):
        return self.sftp

    def close(self):
        self.closed = True


def _device():
    return SeedDevice(
        name="esx-01", kind=DeviceKind.esxi, mgmt_ip="10.0.0.21", credential_ref="esx-01"
    )


def test_configs_backs_up_the_host_config_as_base64(monkeypatch, collector):
    ssh = FakeSSH(BACKUP_OUTPUT, {"/scratch/downloads/52f3a1-9c8b/configBundle-esx-01.tgz": BUNDLE})
    monkeypatch.setattr(EsxiCollector, "_ssh_client", lambda self, device, cred: ssh)

    configs = collector.configs(_device(), Credential(username="root", password="s3cret"))

    assert list(configs) == [BACKUP_FILENAME]
    assert base64.b64decode(configs[BACKUP_FILENAME]) == BUNDLE
    assert ssh.commands == [BACKUP_COMMAND]
    assert ssh.closed and ssh.sftp.closed
    # line-wrapped so the git store still produces a readable diff
    assert configs[BACKUP_FILENAME].endswith("\n")


def test_configs_falls_back_to_the_url_path(monkeypatch, collector):
    ssh = FakeSSH(BACKUP_OUTPUT, {"/downloads/52f3a1-9c8b/configBundle-esx-01.tgz": BUNDLE})
    monkeypatch.setattr(EsxiCollector, "_ssh_client", lambda self, device, cred: ssh)

    configs = collector.configs(_device(), Credential(username="root", password="s3cret"))

    assert base64.b64decode(configs[BACKUP_FILENAME]) == BUNDLE
    assert ssh.sftp.opened == [
        "/scratch/downloads/52f3a1-9c8b/configBundle-esx-01.tgz",
        "/downloads/52f3a1-9c8b/configBundle-esx-01.tgz",
    ]


def test_configs_needs_an_ssh_credential(monkeypatch, collector):
    def explode(self, device, cred):
        raise AssertionError("must not connect without an SSH credential")

    monkeypatch.setattr(EsxiCollector, "_ssh_client", explode)
    assert collector.configs(_device(), Credential(username="infra-ro")) == {}
    assert collector.configs(_device(), Credential()) == {}


def test_configs_uses_the_key_when_there_is_one(monkeypatch, collector):
    ssh = FakeSSH(BACKUP_OUTPUT, {"/scratch/downloads/52f3a1-9c8b/configBundle-esx-01.tgz": BUNDLE})
    monkeypatch.setattr(EsxiCollector, "_ssh_client", lambda self, device, cred: ssh)
    cred = Credential(username="root", ssh_key_path="/home/infra/.ssh/esxi")
    assert collector.configs(_device(), cred)


def test_configs_reports_a_failed_backup_command(monkeypatch, collector):
    ssh = FakeSSH("Permission denied", {}, status=1)
    monkeypatch.setattr(EsxiCollector, "_ssh_client", lambda self, device, cred: ssh)
    with pytest.raises(RuntimeError, match="exited 1"):
        collector.configs(_device(), Credential(username="root", password="s3cret"))
    assert ssh.closed


def test_configs_reports_a_missing_bundle(monkeypatch, collector):
    ssh = FakeSSH(BACKUP_OUTPUT, {})
    monkeypatch.setattr(EsxiCollector, "_ssh_client", lambda self, device, cred: ssh)
    with pytest.raises(FileNotFoundError):
        collector.configs(_device(), Credential(username="root", password="s3cret"))


# --------------------------------------------------------------------------
# redaction invariants
# --------------------------------------------------------------------------
def test_collected_state_carries_no_raw_config_and_passes_the_gateway(gateway, data):
    gateway.refuse_raw_config(data)
    assert gateway.egress(data, tool="test.esxi") is not None


def test_the_backup_bundle_is_not_part_of_the_observed_state(data):
    assert BACKUP_FILENAME not in json.dumps(data)
    assert "configBundle" not in json.dumps(data)


def test_the_credential_password_never_reaches_the_snapshot(monkeypatch, collector):
    content = build_content()
    monkeypatch.setattr(
        EsxiCollector, "_connect", lambda self, device, cred: ns(RetrieveContent=lambda: content)
    )
    monkeypatch.setattr(EsxiCollector, "_disconnect", lambda self, si: None)
    data = collector.collect(_device(), Credential(username="infra-ro", password="hunter2"))
    assert "hunter2" not in json.dumps(data)


# --------------------------------------------------------------------------
# alert rules
# --------------------------------------------------------------------------
def _metric_names_defined_in_code() -> set[str]:
    from infra_agent.monitoring import metrics

    names = set()
    for value in vars(metrics).values():
        name = getattr(value, "_name", None)
        if isinstance(name, str) and name.startswith("infra_"):
            names.add(name)
    return names


def test_virtualization_rules_are_valid_and_reference_real_metrics():
    document = yaml.safe_load((RULES / "virtualization.yaml").read_text())
    (group,) = document["groups"]
    assert group["name"] == "infra-virtualization"

    defined = _metric_names_defined_in_code()
    alerts = {rule["alert"] for rule in group["rules"]}
    assert {"DatastoreLowSpace", "VirtualMachineDown", "EsxiHostCpuSaturated"} <= alerts

    for rule in group["rules"]:
        assert rule["labels"]["severity"] in {"info", "warning", "critical"}
        assert rule["annotations"]["summary"]
        referenced = set(re.findall(r"\binfra_[a-z0-9_]+", rule["expr"]))
        assert referenced, rule["alert"]
        assert referenced <= defined, (rule["alert"], referenced - defined)


# --------------------------------------------------------------------------
# the base collector contract, end to end
# --------------------------------------------------------------------------
def test_run_collector_persists_a_snapshot_and_commits_the_bundle(monkeypatch, collector, tmp_path):
    from infra_agent.collectors.base import run_collector
    from infra_agent.configstore.git_store import ConfigGitStore
    from infra_agent.store.snapshots import FileSnapshotStore

    content = build_content()
    ssh = FakeSSH(BACKUP_OUTPUT, {"/scratch/downloads/52f3a1-9c8b/configBundle-esx-01.tgz": BUNDLE})
    monkeypatch.setattr(
        EsxiCollector, "_connect", lambda self, device, cred: ns(RetrieveContent=lambda: content)
    )
    monkeypatch.setattr(EsxiCollector, "_disconnect", lambda self, si: None)
    monkeypatch.setattr(EsxiCollector, "_ssh_client", lambda self, device, cred: ssh)

    store = FileSnapshotStore(tmp_path / "snapshots")
    configs = ConfigGitStore(tmp_path / "configs")
    device = _device()
    cred = Credential(username="root", password="s3cret")

    first = run_collector(collector, device, cred, store, configs)
    assert first.changes == []  # nothing to diff against yet
    assert BACKUP_FILENAME in first.config_commits
    assert store.latest("esx-01", "esxi").data["vms"][0]["name"] == "web-01"

    # A VM powered off between runs is one structured change, and an unchanged
    # bundle produces no second commit.
    host = content.rootFolder.childEntity[0].hostFolder.childEntity[0].host[0]
    host.vm[0].summary.runtime.powerState = "poweredOff"
    second = run_collector(collector, device, cred, store, configs)

    assert second.config_commits == {}
    changed = [c for c in second.changes if c.path.endswith("power_state")]
    assert [(c.old, c.new) for c in changed] == [("poweredOn", "poweredOff")]
    assert configs.latest("esx-01", BACKUP_FILENAME).startswith("H4sI")
