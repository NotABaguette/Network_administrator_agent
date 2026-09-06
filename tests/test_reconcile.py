"""Reconciliation, baseline and drift, entirely offline.

The Cisco snapshot below is not hand-written: `CISCO_PARSED` is what
`ntc_templates.parse_output()` returns for the recorded `show` output in
`CISCO_SHOW_OUTPUT` (empty fields dropped), and
`test_cisco_fixture_is_what_ntc_templates_really_emits` re-derives it whenever
the optional `devices` extra is installed, so the fixture cannot drift away from
the key names the collector actually stores. The FortiOS, ESXi and iLO snapshots
have the shape those collectors produce.

`FakeNetBox` stands in for NetBox and enforces the NetBox 4.3 rules the
reconciler depends on, so "bootstrap is idempotent" means idempotent against the
pinned release rather than against a permissive stub.
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
from infra_agent.reconcile.bootstrap import bootstrap, disk_mb, slugify, sync
from infra_agent.reconcile.drift import Severity, compare, intended_from_netbox
from infra_agent.reconcile.fake import FakeNetBox
from infra_agent.reconcile.model import normalize_ifname, normalize_mac, to_cidr
from infra_agent.reconcile.netbox import NetBoxClient, NetBoxWriteError
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

# --------------------------------------------------------------------------- cisco fixture
# Recorded Catalyst output, one entry per snapshot key in `collectors/cisco.py`.
CISCO_SHOW_OUTPUT: dict[str, tuple[str, str]] = {
    "version": (
        "show version",
        """Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2020 by Cisco Systems, Inc.

ROM: Bootstrap program is C2960X boot loader

sw-core-01 uptime is 41 weeks, 2 days, 3 hours, 17 minutes
System returned to ROM by power-on
System restarted at 09:12:44 UTC Mon Nov 20 2023
System image file is "flash:/c2960x-universalk9-mz.152-7.E3.bin"
Last reload reason: power-on

cisco WS-C2960X-48TS-L (APM86XXX) processor (revision D0) with 524288K bytes of memory.
Processor board ID FOC1234A5BC
The password-recovery mechanism is enabled.

512K bytes of flash-simulated non-volatile configuration memory.
Base ethernet MAC Address       : AA:BB:CC:00:01:00
Model number                    : WS-C2960X-48TS-L
System serial number            : FOC1234A5BC
Version ID                      : V03

Configuration register is 0xF
""",
    ),
    "inventory": (
        "show inventory",
        """NAME: "1", DESCR: "WS-C2960X-48TS-L"
PID: WS-C2960X-48TS-L  , VID: V03  , SN: FOC1234A5BC
""",
    ),
    "interfaces": (
        "show interfaces",
        """GigabitEthernet1/0/1 is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is aabb.cc00.0101 (bia aabb.cc00.0101)
  Description: esx-01 vmnic0
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX
GigabitEthernet1/0/2 is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is aabb.cc00.0102 (bia aabb.cc00.0102)
  Description: fw-01 internal
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX
GigabitEthernet1/0/24 is down, line protocol is down (notconnect)
  Hardware is Gigabit Ethernet, address is aabb.cc00.0118 (bia aabb.cc00.0118)
  Description: spare
  MTU 1500 bytes, BW 10000 Kbit/sec, DLY 1000 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Auto-duplex, Auto-speed, media type is 10/100/1000BaseTX
Vlan10 is up, line protocol is up
  Hardware is EtherSVI, address is aabb.cc00.0100 (bia aabb.cc00.0100)
  Description: management
  Internet address is 10.0.10.2/24
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
""",
    ),
    "interfaces_status": (
        "show interfaces status",
        """
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   esx-01 vmnic0      connected    trunk        full   1000 10/100/1000BaseTX
Gi1/0/2   fw-01 internal     connected    trunk        full   1000 10/100/1000BaseTX
Gi1/0/24  spare              notconnect   20           auto   auto 10/100/1000BaseTX
""",
    ),
    "ip_int_brief": (
        "show ip interface brief",
        """Interface              IP-Address      OK? Method Status                Protocol
Vlan10                 10.0.10.2       YES NVRAM  up                    up
GigabitEthernet1/0/1   unassigned      YES unset  up                    up
""",
    ),
    "vlans": (
        "show vlan brief",
        """
VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active
10   mgmt                             active    Gi1/0/1, Gi1/0/2
20   servers                          active    Gi1/0/24
30   voice                            active
""",
    ),
    "switchport": (
        "show interfaces switchport",
        """Name: Gi1/0/1
Switchport: Enabled
Administrative Mode: trunk
Operational Mode: trunk
Administrative Trunking Encapsulation: dot1q
Operational Trunking Encapsulation: dot1q
Negotiation of Trunking: On
Access Mode VLAN: 1 (default)
Trunking Native Mode VLAN: 1 (default)
Voice VLAN: none
Operational private-vlan: none
Trunking VLANs Enabled: 10,20,30
Pruning VLANs Enabled: 2-1001
Capture Mode Disabled
Capture VLANs Allowed: ALL

Protected: false
Unknown unicast blocked: disabled
Unknown multicast blocked: disabled
Appliance trust: none

Name: Gi1/0/2
Switchport: Enabled
Administrative Mode: trunk
Operational Mode: trunk
Administrative Trunking Encapsulation: dot1q
Operational Trunking Encapsulation: dot1q
Negotiation of Trunking: On
Access Mode VLAN: 1 (default)
Trunking Native Mode VLAN: 1 (default)
Voice VLAN: none
Operational private-vlan: none
Trunking VLANs Enabled: 10,20,30
Pruning VLANs Enabled: 2-1001
Capture Mode Disabled
Capture VLANs Allowed: ALL

Protected: false
Unknown unicast blocked: disabled
Unknown multicast blocked: disabled
Appliance trust: none

Name: Gi1/0/24
Switchport: Enabled
Administrative Mode: static access
Operational Mode: static access
Administrative Trunking Encapsulation: dot1q
Operational Trunking Encapsulation: native
Negotiation of Trunking: Off
Access Mode VLAN: 20 (servers)
Trunking Native Mode VLAN: 1 (default)
Voice VLAN: none
Operational private-vlan: none
Trunking VLANs Enabled: ALL
Pruning VLANs Enabled: 2-1001
Capture Mode Disabled
Capture VLANs Allowed: ALL

Protected: false
Unknown unicast blocked: disabled
Unknown multicast blocked: disabled
Appliance trust: none
""",
    ),
    "mac_table": (
        "show mac address-table",
        """          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  20    0050.5601.aabb    DYNAMIC     Gi1/0/1
  10    aabb.cc00.0201    DYNAMIC     Gi1/0/2
Total Mac Addresses for this criterion: 2
""",
    ),
    "arp": (
        "show ip arp",
        """Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.0.10.1              12   aabb.cc00.0201  ARPA   Vlan10
""",
    ),
}

# `ntc_templates.parse_output(platform="cisco_ios", ...)` over the output above.
# Note the key names: VLAN_ID (never VLAN) on `interfaces status` and the MAC
# table, and IP_ADDRESS plus a separate PREFIX_LENGTH on `show interfaces`.
CISCO_PARSED: dict[str, list[dict[str, Any]]] = {
    "version": [
        {
            "software_image": "C2960X-UNIVERSALK9-M",
            "version": "15.2(7)E3",
            "release": "fc2",
            "rommon": "Bootstrap",
            "hostname": "sw-core-01",
            "uptime": "41 weeks, 2 days, 3 hours, 17 minutes",
            "uptime_weeks": "41",
            "uptime_days": "2",
            "uptime_hours": "3",
            "uptime_minutes": "17",
            "reload_reason": "power-on",
            "running_image": "/c2960x-universalk9-mz.152-7.E3.bin",
            "hardware": ["WS-C2960X-48TS-L"],
            "serial": ["FOC1234A5BC"],
            "config_register": "0xF",
            "mac_address": ["AA:BB:CC:00:01:00"],
            "restarted": "09:12:44 UTC Mon Nov 20 2023",
        }
    ],
    "inventory": [
        {
            "name": "1",
            "descr": "WS-C2960X-48TS-L",
            "pid": "WS-C2960X-48TS-L",
            "vid": "V03  ",
            "sn": "FOC1234A5BC",
        }
    ],
    "interfaces": [
        {
            "interface": "GigabitEthernet1/0/1",
            "link_status": "up",
            "protocol_status": "up (connected)",
            "hardware_type": "Gigabit Ethernet",
            "mac_address": "aabb.cc00.0101",
            "bia": "aabb.cc00.0101",
            "description": "esx-01 vmnic0",
            "mtu": "1500",
            "duplex": "Full-duplex",
            "speed": "1000Mb/s",
            "media_type": "10/100/1000BaseTX",
            "bandwidth": "1000000 Kbit",
            "delay": "10 usec",
            "encapsulation": "ARPA",
        },
        {
            "interface": "GigabitEthernet1/0/2",
            "link_status": "up",
            "protocol_status": "up (connected)",
            "hardware_type": "Gigabit Ethernet",
            "mac_address": "aabb.cc00.0102",
            "bia": "aabb.cc00.0102",
            "description": "fw-01 internal",
            "mtu": "1500",
            "duplex": "Full-duplex",
            "speed": "1000Mb/s",
            "media_type": "10/100/1000BaseTX",
            "bandwidth": "1000000 Kbit",
            "delay": "10 usec",
            "encapsulation": "ARPA",
        },
        {
            "interface": "GigabitEthernet1/0/24",
            "link_status": "down",
            "protocol_status": "down (notconnect)",
            "hardware_type": "Gigabit Ethernet",
            "mac_address": "aabb.cc00.0118",
            "bia": "aabb.cc00.0118",
            "description": "spare",
            "mtu": "1500",
            "duplex": "Auto-duplex",
            "speed": "Auto-speed",
            "media_type": "10/100/1000BaseTX",
            "bandwidth": "10000 Kbit",
            "delay": "1000 usec",
            "encapsulation": "ARPA",
        },
        {
            "interface": "Vlan10",
            "link_status": "up",
            "protocol_status": "up",
            "hardware_type": "EtherSVI",
            "mac_address": "aabb.cc00.0100",
            "bia": "aabb.cc00.0100",
            "description": "management",
            "ip_address": "10.0.10.2",
            "prefix_length": "24",
            "mtu": "1500",
            "bandwidth": "1000000 Kbit",
            "delay": "10 usec",
            "encapsulation": "ARPA",
        },
    ],
    "interfaces_status": [
        {
            "port": "Gi1/0/1",
            "name": "esx-01 vmnic0",
            "status": "connected",
            "vlan_id": "trunk",
            "duplex": "full",
            "speed": "1000",
            "type": "10/100/1000BaseTX",
        },
        {
            "port": "Gi1/0/2",
            "name": "fw-01 internal",
            "status": "connected",
            "vlan_id": "trunk",
            "duplex": "full",
            "speed": "1000",
            "type": "10/100/1000BaseTX",
        },
        {
            "port": "Gi1/0/24",
            "name": "spare",
            "status": "notconnect",
            "vlan_id": "20",
            "duplex": "auto",
            "speed": "auto",
            "type": "10/100/1000BaseTX",
        },
    ],
    "ip_int_brief": [
        {"interface": "Vlan10", "ip_address": "10.0.10.2", "status": "up", "proto": "up"},
        {
            "interface": "GigabitEthernet1/0/1",
            "ip_address": "unassigned",
            "status": "up",
            "proto": "up",
        },
    ],
    "vlans": [
        {"vlan_id": "1", "vlan_name": "default", "status": "active"},
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
        {"vlan_id": "30", "vlan_name": "voice", "status": "active"},
    ],
    "switchport": [
        {
            "interface": "Gi1/0/1",
            "switchport": "Enabled",
            "switchport_negotiation": "On",
            "mode": "trunk",
            "admin_mode": "trunk",
            "access_vlan": "1",
            "native_vlan": "1",
            "voice_vlan": "none",
            "trunking_vlans": ["10", "20", "30"],
        },
        {
            "interface": "Gi1/0/2",
            "switchport": "Enabled",
            "switchport_negotiation": "On",
            "mode": "trunk",
            "admin_mode": "trunk",
            "access_vlan": "1",
            "native_vlan": "1",
            "voice_vlan": "none",
            "trunking_vlans": ["10", "20", "30"],
        },
        {
            "interface": "Gi1/0/24",
            "switchport": "Enabled",
            "switchport_negotiation": "Off",
            "mode": "static access",
            "admin_mode": "static access",
            "access_vlan": "20",
            "native_vlan": "1",
            "voice_vlan": "none",
            "trunking_vlans": ["ALL"],
        },
    ],
    "mac_table": [
        {
            "destination_address": "0050.5601.aabb",
            "type": "DYNAMIC",
            "vlan_id": "20",
            "destination_port": ["Gi1/0/1"],
        },
        {
            "destination_address": "aabb.cc00.0201",
            "type": "DYNAMIC",
            "vlan_id": "10",
            "destination_port": ["Gi1/0/2"],
        },
    ],
    "arp": [
        {
            "protocol": "Internet",
            "ip_address": "10.0.10.1",
            "age": "12",
            "mac_address": "aabb.cc00.0201",
            "type": "ARPA",
            "interface": "Vlan10",
        }
    ],
}


def cisco_data() -> dict[str, Any]:
    return {**copy.deepcopy(CISCO_PARSED), "errors": {}}


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
    report = bootstrap(estate, client)
    assert report.failed == 0, report.warnings
    return client, estate


def without_port(data: dict[str, Any], port: str) -> dict[str, Any]:
    """Drop a switch port from every `show` command that mentions it."""
    data["interfaces"] = [i for i in data["interfaces"] if port not in i["interface"]]
    data["interfaces_status"] = [i for i in data["interfaces_status"] if port not in i["port"]]
    data["switchport"] = [i for i in data["switchport"] if port not in i["interface"]]
    return data


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
    assert to_cidr("10.0.10.2", "24") == "10.0.10.2/24", "ntc-templates gives a prefix length"
    assert to_cidr("0.0.0.0 0.0.0.0") is None
    assert parse_vlan_list("10,20,30-32") == [10, 20, 30, 31, 32]
    assert parse_vlan_list("1-4094", known={10, 20}) == [10, 20]
    assert parse_vlan_list("1-4094") == []
    assert parse_vlan_list(["10", "20", "30"]) == [10, 20, 30]
    assert parse_vlan_list(["ALL"]) == []


def test_cisco_fixture_is_what_ntc_templates_really_emits():
    """The fixture is generated, not imagined: re-derive it from the recorded output.

    ntc-templates is in the optional `devices` extra, so this is skipped when the
    core-only environment runs the suite -- but wherever the collector can parse,
    the fixture has to match it key for key.
    """
    parse = pytest.importorskip("ntc_templates.parse")

    for key, (command, output) in CISCO_SHOW_OUTPUT.items():
        rows = parse.parse_output(platform="cisco_ios", command=command, data=output)
        pruned = [{k: v for k, v in row.items() if v not in ("", [], None)} for row in rows]
        assert pruned == CISCO_PARSED[key], f"the {key} fixture no longer matches ntc-templates"


def test_ntc_templates_has_no_cisco_trunk_template():
    """Why trunk membership comes from `show interfaces switchport`.

    `show interfaces trunk` falls through to the generic `show interfaces`
    template, which matches nothing, so the collector stores an empty list and
    `tagged_vlans` could never be populated from it.
    """
    parse = pytest.importorskip("ntc_templates.parse")

    trunk_output = """Port        Mode         Encapsulation  Status        Native vlan
Gi1/0/1     on           802.1q         trunking      1

Port        Vlans allowed on trunk
Gi1/0/1     10,20,30
"""
    assert (
        parse.parse_output(platform="cisco_ios", command="show interfaces trunk", data=trunk_output)
        == []
    )


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
    assert uplink.tagged_vlans == [10, 20, 30], "trunk membership comes from `switchport`"
    assert uplink.is_sensitive()

    access = switch.interface("Gi1/0/24")
    # notconnect is a dark link, not a shut port: NetBox's `enabled` is the admin state.
    assert (access.mode, access.untagged_vlan, access.enabled) == ("access", 20, True)
    assert access.link_up is False

    svi = switch.interface("Vlan10")
    assert svi.addresses == ["10.0.10.2/24"], "IP_ADDRESS + PREFIX_LENGTH, not a bare /32"
    assert svi.mode == "routed"

    firewall = estate.device("fw-01")
    assert firewall.model == "FortiGate-60F"
    assert firewall.interface("wan1").role == "wan"
    assert firewall.interface("srv-vl20").untagged_vlan == 20
    assert firewall.interface("srv-vl20").parent == "internal"

    host = estate.device("esx-01")
    assert host.serial == "CZ12345678", "the iLO serial folds into its ESXi host"
    assert host.interface("iLO").role == "oob"
    assert host.interface("vmk0").addresses == ["10.0.10.21/24"]
    assert estate.ilo_links == {"esx-01-ilo": "esx-01"}

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


def test_mac_table_entries_keep_their_vlan(tmp_path):
    estate = observed(tmp_path)
    entry = next(
        e
        for e in estate.mac_entries
        if e.mac == "00:50:56:01:aa:bb" and e.source == "cisco-mac-table"
    )
    assert (entry.device, entry.port, entry.vlan) == (
        "sw-core-01",
        "GigabitEthernet1/0/1",
        20,
    )


def test_a_pulled_cable_is_not_an_administrative_shutdown(tmp_path):
    estate = observed(tmp_path)
    host = estate.device("esx-01")
    down = host.interface("vmnic1")
    assert down.enabled is True, "ESXi reports link, not admin state"
    assert down.link_up is False


def test_unparsed_snapshot_keys_become_warnings(tmp_path):
    """An IOS-XE switch whose output ntc-templates cannot parse must say so.

    `collectors/cisco.py` keeps the raw text when no template matches; the estate
    drops it (no raw output ever reaches the model) but must not pretend the
    switch simply has no interfaces.
    """
    # Exactly what the collector stores for a platform ntc-templates does not know.
    raw = {key: text for key, (_, text) in CISCO_SHOW_OUTPUT.items()}
    raw["errors"] = {}
    estate = observed(tmp_path, overrides={"sw-core-01": raw})

    warnings = " ".join(estate.warnings)
    assert "`interfaces` was not parsed by ntc-templates" in warnings
    assert "no interfaces were parsed" in warnings
    assert estate.device("sw-core-01").interfaces == []
    assert RedactionGateway.looks_like_raw_config(str(estate.model_dump(mode="json"))) is False


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
    assert estate.ilo_links == {}
    assert any("esx-01-ilo" in w for w in estate.warnings)


# --------------------------------------------------------------------------- NetBox semantics
def test_fake_netbox_refuses_a_vlan_without_a_mode():
    """NetBox 4.3 `InterfaceSerializer.validate()`, reproduced."""
    client = FakeNetBox()
    with pytest.raises(NetBoxWriteError, match="untagged vlan"):
        client.create(
            "dcim.interfaces", {"device": 1, "name": "Vlan10", "mode": "", "untagged_vlan": 7}
        )
    with pytest.raises(NetBoxWriteError, match="tagged vlans"):
        client.create(
            "dcim.interfaces",
            {"device": 1, "name": "Gi1/0/1", "mode": "access", "tagged_vlans": [7]},
        )


def test_fake_netbox_drops_a_vm_vlan_without_a_mode():
    """A VM interface is not validated but `BaseInterface.save()` clears the VLAN."""
    client = FakeNetBox()
    nic = client.create(
        "virtualization.interfaces", {"virtual_machine": 1, "name": "nic0", "untagged_vlan": 7}
    )
    assert nic["untagged_vlan"] is None


def test_fake_netbox_treats_mac_address_as_read_only():
    client = FakeNetBox()
    iface = client.create(
        "dcim.interfaces", {"device": 1, "name": "Gi1/0/1", "mac_address": "aa:bb:cc:00:01:01"}
    )
    assert "mac_address" not in iface, "NetBox >= 4.2 makes mac_address read-only"

    mac = client.create(
        "dcim.mac_addresses",
        {
            "mac_address": "aa:bb:cc:00:01:01",
            "assigned_object_type": "dcim.interface",
            "assigned_object_id": iface["id"],
        },
    )
    updated = client.update("dcim.interfaces", iface["id"], {"primary_mac_address": mac["id"]})
    assert updated["mac_address"] == "aa:bb:cc:00:01:01"

    other = client.create("dcim.interfaces", {"device": 1, "name": "Gi1/0/2"})
    with pytest.raises(NetBoxWriteError, match="not assigned to this interface"):
        client.update("dcim.interfaces", other["id"], {"primary_mac_address": mac["id"]})


def test_fake_netbox_drops_a_cluster_site():
    client = FakeNetBox()
    cluster = client.create("virtualization.clusters", {"name": "esx-01", "site": 1, "type": 2})
    assert "site" not in cluster, "clusters carry scope_type/scope_id since NetBox 4.2"


def test_fake_netbox_rejects_a_content_type_filter():
    client = FakeNetBox()
    client.create(
        "ipam.ip_addresses",
        {
            "address": "10.0.10.2/24",
            "assigned_object_type": "dcim.interface",
            "assigned_object_id": 1,
        },
    )
    assert client.get("ipam.ip_addresses", address="10.0.10.2/24", interface_id=1) is not None
    assert client.get("ipam.ip_addresses", address="10.0.10.2/24", interface_id=2) is None
    with pytest.raises(NetBoxWriteError, match="interface_id"):
        client.all("ipam.ip_addresses", assigned_object_type="dcim.interface")


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


def test_bootstrap_stores_macs_as_netbox_objects(tmp_path):
    """`interfaces (with MACs)` means a dcim.mac_addresses object, not a string field."""
    client, _ = bootstrapped(tmp_path)

    uplink = client.get("dcim.interfaces", device="sw-core-01", name="GigabitEthernet1/0/1")
    mac = client.get("dcim.mac_addresses", mac_address="aa:bb:cc:00:01:01")
    assert mac["assigned_object_type"] == "dcim.interface"
    assert mac["assigned_object_id"] == uplink["id"]
    assert uplink["primary_mac_address"] == mac["id"]

    nic = client.get("virtualization.interfaces", virtual_machine="app-01")
    vm_mac = client.get("dcim.mac_addresses", mac_address="00:50:56:01:aa:bb")
    assert vm_mac["assigned_object_type"] == "virtualization.vminterface"
    assert nic["primary_mac_address"] == vm_mac["id"]

    # The interface is findable the way `inventory.where_is_mac` looks for it.
    found = client.all("dcim.interfaces", mac_address="aa:bb:cc:00:01:01")
    assert [i["name"] for i in found] == ["GigabitEthernet1/0/1"]


def test_bootstrap_records_vlans_only_where_netbox_allows_them(tmp_path):
    client, _ = bootstrapped(tmp_path)

    svi = client.get("dcim.interfaces", device="sw-core-01", name="Vlan10")
    assert (svi["mode"], svi["untagged_vlan"]) == ("", None), "a routed SVI has no 802.1Q mode"

    vmk = client.get("dcim.interfaces", device="esx-01", name="vmk0")
    assert (vmk["mode"], vmk["untagged_vlan"]) == ("", None)
    assert vmk["mgmt_only"] is True

    access = client.get("dcim.interfaces", device="sw-core-01", name="GigabitEthernet1/0/24")
    vlan20 = client.get("ipam.vlans", vid=20)
    assert (access["mode"], access["untagged_vlan"]) == ("access", vlan20["id"])

    nic = client.get("virtualization.interfaces", virtual_machine="app-01")
    assert nic["mode"] == "access", "a VM NIC needs a mode or NetBox drops its VLAN"
    assert nic["untagged_vlan"] == vlan20["id"]


def test_bootstrap_writes_vm_disk_in_megabytes(tmp_path):
    client, _ = bootstrapped(tmp_path)
    vm = client.get("virtualization.virtual_machines", name="app-01")
    assert vm["disk"] == 81920, "NetBox has stored disk in MB since 4.1"
    assert vm["memory"] == 8192
    assert disk_mb(80.0) == 81920

    intended = intended_from_netbox(client, "hq")
    assert intended.vm("app-01").disk_gb == 80.0, "and it reads back as GB"


def test_bootstrap_scopes_the_cluster_to_the_site(tmp_path):
    client, _ = bootstrapped(tmp_path)
    site = client.get("dcim.sites", slug="hq")
    cluster = client.get("virtualization.clusters", name="esx-01")
    assert (cluster["scope_type"], cluster["scope_id"]) == ("dcim.site", site["id"])
    assert intended_from_netbox(client, "hq").cluster("esx-01") is not None
    assert intended_from_netbox(client, "elsewhere").clusters == []


def test_bootstrap_leaves_curated_fields_alone(tmp_path):
    """`comments` belongs to the owner, and an unknown serial must not blank a known one."""
    estate = observed(tmp_path)
    client = FakeNetBox()
    bootstrap(estate, client)

    for endpoint in ("dcim.devices", "virtualization.virtual_machines"):
        assert all("comments" not in row for row in client.all(endpoint))
    device = client.get("dcim.devices", name="fw-01")
    platform = client.get("dcim.platforms", name="FortiOS v7.4.4")
    assert device["platform"] == platform["id"], "the OS goes in `platform`, not `comments`"
    assert intended_from_netbox(client, "hq").vm("app-01").guest_os == "Ubuntu Linux (64-bit)"

    client.update("dcim.devices", device["id"], {"comments": "owner note: RMA pending"})
    estate.device("fw-01").serial = None
    report = bootstrap(estate, client)

    assert report.updated == 0
    assert client.get("dcim.devices", name="fw-01")["serial"] == "FGT60FTK20001234"
    assert client.get("dcim.devices", name="fw-01")["comments"] == "owner note: RMA pending"


def test_bootstrap_is_idempotent(tmp_path):
    estate = observed(tmp_path)
    client = FakeNetBox()

    first = bootstrap(estate, client)
    assert first.created > 0
    assert first.failed == 0, first.warnings
    # An object is created before the things it points at exist, so a device's
    # primary IP and an interface's MAC are patched in afterwards -- once.
    updated = {a.object for a in first.actions if a.status == "updated"}
    assert {"esx-01 primary_ip4", "fw-01 primary_ip4", "sw-core-01 primary_ip4"} <= updated
    assert all(o.endswith(("primary_ip4", "primary MAC", "parent")) for o in updated)

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


def test_a_rejected_object_does_not_abort_the_run(tmp_path):
    """One 400 must not leave NetBox with a site, one device and no VMs."""

    class _Picky(FakeNetBox):
        def create(self, endpoint: str, data: dict[str, Any]) -> dict[str, Any]:
            if endpoint == "dcim.devices" and data.get("name") == "sw-core-01":
                raise NetBoxWriteError("{'name': 'device name is reserved'}")
            return super().create(endpoint, data)

    estate = observed(tmp_path)
    client = _Picky()
    report = bootstrap(estate, client)

    assert report.failed == 1
    assert any("sw-core-01" in w and "rejected" in w for w in report.warnings)
    assert "rejected 1" in report.summary_line()
    assert {d["name"] for d in client.all("dcim.devices")} == {"fw-01", "esx-01"}
    assert {v["name"] for v in client.all("virtualization.virtual_machines")} == {
        "app-01",
        "mgmt-01",
    }


def test_bootstrap_hangs_a_vlan_subinterface_off_its_parent(tmp_path):
    client, _ = bootstrapped(tmp_path)
    parent = client.get("dcim.interfaces", device="fw-01", name="internal")
    child = client.get("dcim.interfaces", device="fw-01", name="srv-vl20")
    assert child["parent"] == parent["id"]


def test_an_address_is_not_stolen_from_another_object(tmp_path):
    """A VIP that NetBox already assigns elsewhere must not flip on every sync."""
    estate = observed(tmp_path)
    client = FakeNetBox()
    other = client.create("dcim.interfaces", {"device": 99, "name": "ha-vip"})
    client.create(
        "ipam.ip_addresses",
        {
            "address": "10.0.20.1/24",
            "assigned_object_type": "dcim.interface",
            "assigned_object_id": other["id"],
        },
    )

    report = bootstrap(estate, client)

    held = client.get("ipam.ip_addresses", address="10.0.20.1/24")
    assert held["assigned_object_id"] == other["id"]
    assert any("10.0.20.1/24" in w for w in report.warnings)
    assert bootstrap(estate, client).updated == 0, "and it stays put on the next run"


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
    without_port(cisco, "1/0/24")

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
    for port in cisco["switchport"]:
        if port["interface"] == "Gi1/0/1":
            port["trunking_vlans"] = ["10", "20"]
    after = observed(tmp_path / "after", overrides={"sw-core-01": cisco, "fw-01": None})
    report = compare(after, intended_from_netbox(client, after.site))

    trunk_item = next(
        i
        for i in report.items
        if i.object == "sw-core-01:GigabitEthernet1/0/1" and i.field == "tagged_vlans"
    )
    assert trunk_item.severity is Severity.high, "trunk VLAN membership drift is high severity"
    assert (trunk_item.observed, trunk_item.intended) == ([10, 20], [10, 20, 30])

    missing = next(i for i in report.items if i.object == "fw-01" and i.object_type == "device")
    assert (missing.change, missing.severity) == ("removed", Severity.high)
    assert report.worst is Severity.high


def test_drift_ignores_vlans_on_interfaces_netbox_cannot_hold_them_on(tmp_path):
    """The SVI knows it is VLAN 10; NetBox is not allowed to say so. Not drift."""
    client, estate = bootstrapped(tmp_path)
    intended = intended_from_netbox(client, estate.site)

    svi = estate.device("sw-core-01").interface("Vlan10")
    assert (svi.mode, svi.untagged_vlan) == ("routed", 10)
    assert intended.device("sw-core-01").interface("Vlan10").untagged_vlan is None
    assert compare(estate, intended).clean


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
    cisco = without_port(cisco_data(), "1/0/24")

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


def test_baseline_fingerprint_ignores_transient_observations(tmp_path):
    """An ARP entry ageing out or a cable being replugged is not a new baseline."""
    settings = write_estate(tmp_path)
    estate = service.observed_estate(settings)
    baseline = service.accept_baseline(settings=settings, estate=estate, client=None)

    cisco = cisco_data()
    cisco["mac_table"] = []
    cisco["arp"] = []
    esxi = esxi_data()
    esxi["pnics"][0]["link"] = "down"
    later = service.observed_estate(
        write_estate(tmp_path / "after", {"sw-core-01": cisco, "esx-01": esxi})
    )

    assert later.mac_entries != estate.mac_entries
    assert baseline.matches(later)


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


class _DeadNetBox(FakeNetBox):
    """A NetBox whose SYNs are dropped: every read raises, nothing hangs."""

    def all(self, endpoint: str, **filters: Any) -> list[dict[str, Any]]:
        raise ConnectionError("HTTPConnectionPool(host='netbox', port=8080): connection refused")


def test_drift_degrades_to_the_baseline_when_netbox_is_down(tmp_path):
    settings = write_estate(tmp_path)
    estate = service.observed_estate(settings)
    service.accept_baseline(settings=settings, estate=estate)

    esxi = esxi_data()
    esxi["vms"][0]["num_cpu"] = 8
    later = service.observed_estate(write_estate(tmp_path / "after", {"esx-01": esxi}))

    report = service.drift_report(settings=settings, client=_DeadNetBox(), observed=later)
    assert report.source == "baseline"
    assert any("NetBox is unreachable" in w for w in report.warnings)
    assert next(i for i in report.items if i.field == "vcpus").observed == 8.0


def test_drift_says_so_when_netbox_is_down_and_there_is_no_baseline(tmp_path):
    settings = write_estate(tmp_path)
    report = service.drift_report(settings=settings, client=_DeadNetBox())
    assert report.source == "none"
    assert any("NetBox is unreachable" in w for w in report.warnings)


def test_drift_flags_a_device_nobody_has_heard_of(tmp_path):
    settings = write_estate(tmp_path)
    estate = service.observed_estate(settings)
    service.accept_baseline(settings=settings, estate=estate)

    report = service.drift_report(device="sw-core-99", settings=settings)
    assert report.clean
    assert any("sw-core-99" in w for w in report.warnings)
    assert not any("sw-core-01" in w for w in service.drift_report("sw-core-01", settings).warnings)


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

    import requests

    devices = _Endpoint([_Record(id=1, name="sw-core-01", serial="OLD")])
    device_types = _Endpoint()
    api = types.SimpleNamespace(
        dcim=types.SimpleNamespace(devices=devices, device_types=device_types),
        version="4.3",
        http_session=requests.Session(),
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
    assert client.ping() == {"url": "https://netbox.example", "version": "4.3"}
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


def test_netbox_client_gives_every_request_a_deadline(pynetbox_stub, monkeypatch):
    """pynetbox never passes `timeout=`, so a black-holed NetBox would hang a tool call."""
    import requests

    seen: dict[str, Any] = {}

    def fake_request(self, method, url, **kwargs):
        seen.update({"method": method, "url": url, **kwargs})
        return "response"

    monkeypatch.setattr(requests.Session, "request", fake_request)
    client = NetBoxClient("https://netbox.example", "token", timeout=3.5)
    session = client.api().http_session

    session.get("https://netbox.example/api/dcim/devices/")
    assert seen["timeout"] == 3.5


def test_ensure_omits_a_lookup_key_that_is_not_writable(pynetbox_stub):
    from infra_agent.reconcile.netbox import OMIT

    client = NetBoxClient("https://netbox.example", "token")
    made = client.ensure(
        "dcim.device_types",
        {"model": "C9200", "manufacturer_id": 4},
        {"slug": "c9200"},
        create={"manufacturer_id": OMIT, "manufacturer": 4},
    )
    assert "manufacturer_id" not in made.obj
    assert made.obj["manufacturer"] == 4


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
