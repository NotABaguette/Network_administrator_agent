"""The read-only inventory tools, answered from snapshots with no network access."""

from __future__ import annotations

import pytest

from infra_agent.config import get_settings
from infra_agent.redaction.gateway import RedactionGateway
from infra_agent.tools import inventory_tools
from infra_agent.tools.registry import REGISTRY, llm_tools, load_all
from tests.test_reconcile import _DeadNetBox, esxi_data, write_estate

INVENTORY_TOOLS = {
    "inventory.get_device",
    "inventory.find_vm",
    "inventory.list_vlans",
    "inventory.where_is_mac",
    "inventory.where_is_ip",
    "inventory.drift_report",
    "inventory.list_devices",
}


@pytest.fixture
def estate_env(tmp_path, monkeypatch):
    """Point the settings-driven tools at a synthetic snapshot tree."""
    settings = write_estate(tmp_path)
    monkeypatch.setenv("INFRA_DATA_DIR", str(settings.data_dir))
    monkeypatch.setenv("INFRA_SEED_INVENTORY", str(settings.seed_inventory))
    monkeypatch.delenv("INFRA_NETBOX_URL", raising=False)
    monkeypatch.delenv("INFRA_NETBOX_TOKEN", raising=False)
    get_settings.cache_clear()
    yield settings
    get_settings.cache_clear()


# --------------------------------------------------------------------------- registration
def test_inventory_tools_are_registered_and_readable_by_the_model():
    load_all()
    callable_names = {spec.name for spec in llm_tools()}
    assert INVENTORY_TOOLS <= callable_names
    for name in INVENTORY_TOOLS:
        spec = REGISTRY[name]
        assert spec.group == "inventory"
        assert spec.tier is None, "read-only tools carry no change tier"
        assert spec.parallel_safe
        assert spec.description


# --------------------------------------------------------------------------- devices
def test_list_devices_and_filter_by_kind(estate_env):
    everything = inventory_tools.list_devices()
    assert everything["count"] == 4
    assert {d["name"] for d in everything["devices"]} == {
        "fw-01",
        "sw-core-01",
        "esx-01",
        "esx-01-ilo",
    }

    switches = inventory_tools.list_devices(kind="cisco_ios")
    assert [d["name"] for d in switches["devices"]] == ["sw-core-01"]
    assert switches["devices"][0]["model"] == "WS-C2960X-48TS-L"

    hypervisors = inventory_tools.list_devices(kind="esxi")
    assert hypervisors["devices"][0]["vm_count"] == 2
    assert inventory_tools.list_devices(kind="nonsense")["count"] == 0


def test_get_device_returns_interfaces_vlans_and_provenance(estate_env):
    device = inventory_tools.get_device("sw-core-01")

    assert device["found"] is True
    assert device["serial"] == "FOC1234A5BC"
    assert device["vlans"] == [1, 10, 20, 30], "native VLAN 1 on the trunks counts too"
    assert device["interface_count"] == 4
    uplink = next(i for i in device["interfaces"] if i["name"] == "GigabitEthernet1/0/1")
    assert uplink["mode"] == "tagged"
    assert uplink["mac"] == "aa:bb:cc:00:01:01"
    assert "cisco" in device["snapshots"]
    assert device["netbox"] is None, "NetBox is not configured in this fixture"


def test_get_device_for_a_hypervisor_lists_its_vms(estate_env):
    host = inventory_tools.get_device("esx-01")
    assert host["serial"] == "CZ12345678"
    assert sorted(host["virtual_machines"]) == ["app-01", "mgmt-01"]


def test_an_onboarded_ilo_is_still_listed_after_being_folded_into_its_host(estate_env):
    """`apply_ilo` folds the iLO into esx-01; the seed name must still answer."""
    ilos = inventory_tools.list_devices(kind="ilo")
    assert [d["name"] for d in ilos["devices"]] == ["esx-01-ilo"]
    entry = ilos["devices"][0]
    assert entry["folded_into"] == "esx-01"
    assert entry["serial"] == "CZ12345678"
    assert entry["primary_ip"] == "10.0.0.121"

    resolved = inventory_tools.get_device("esx-01-ilo")
    assert resolved["found"] is True
    assert resolved["name"] == "esx-01"
    assert resolved["resolved_from"] == "esx-01-ilo"
    assert "iLO of esx-01" in resolved["note"]


def test_get_device_is_helpful_when_the_name_is_wrong(estate_env):
    answer = inventory_tools.get_device("sw-core-99")
    assert answer["found"] is False
    assert "sw-core-01" in answer["known_devices"]
    assert "esx-01-ilo" in answer["known_devices"], "the folded iLO is a name worth suggesting"


# --------------------------------------------------------------------------- VMs and VLANs
def test_find_vm_by_name_mac_and_ip(estate_env):
    by_name = inventory_tools.find_vm("app")
    assert [vm["name"] for vm in by_name["vms"]] == ["app-01"]
    assert by_name["vms"][0]["matched_on"] == ["name"]
    assert by_name["vms"][0]["memory_mb"] == 8192

    by_mac = inventory_tools.find_vm("00:50:56:01:cc:dd")
    assert [vm["name"] for vm in by_mac["vms"]] == ["mgmt-01"]

    by_ip = inventory_tools.find_vm("10.0.20.55")
    assert [vm["name"] for vm in by_ip["vms"]] == ["app-01"]

    assert inventory_tools.find_vm("no-such-vm")["count"] == 0


def test_list_vlans_joins_devices_ports_and_prefixes(estate_env):
    vlans = inventory_tools.list_vlans()
    assert [v["vid"] for v in vlans["vlans"]] == [1, 10, 20, 30]

    servers = next(v for v in vlans["vlans"] if v["vid"] == 20)
    assert servers["name"] == "servers"
    assert servers["prefixes"] == ["10.0.20.0/24"]
    assert "sw-core-01:GigabitEthernet1/0/24" in servers["members"]
    assert servers["vm_count"] == 1
    assert set(servers["devices"]) == {"esx-01", "fw-01", "sw-core-01"}


# --------------------------------------------------------------------------- location
def test_where_is_mac_joins_cisco_fortigate_and_esxi(estate_env):
    answer = inventory_tools.where_is_mac("0050.5601.aabb")
    assert answer["found"] is True
    assert answer["mac"] == "00:50:56:01:aa:bb"

    learned = next(p for p in answer["switch_ports"] if p["source"] == "cisco-mac-table")
    assert (learned["device"], learned["port"], learned["vlan"]) == (
        "sw-core-01",
        "GigabitEthernet1/0/1",
        20,
    )

    firewall = {p["source"] for p in answer["switch_ports"]}
    assert {"fortigate-arp", "fortigate-dhcp"} <= firewall

    vnic = answer["vm_interfaces"][0]
    assert (vnic["vm"], vnic["portgroup"], vnic["vlan"]) == ("app-01", "Servers", 20)

    leases = [ip for ip in answer["ip_addresses"] if ip["source"] == "fortigate-dhcp"]
    assert leases[0]["hostname"] == "app-01"

    assert "sw-core-01 GigabitEthernet1/0/1" in answer["summary"]
    assert "VM app-01" in answer["summary"]


def test_where_is_mac_finds_a_device_interface(estate_env):
    answer = inventory_tools.where_is_mac("aa:bb:cc:00:02:00")
    assert answer["device_interfaces"] == [
        {"device": "fw-01", "interface": "wan1", "addresses": ["203.0.113.10/29"]}
    ]


def test_where_is_mac_rejects_nonsense(estate_env):
    answer = inventory_tools.where_is_mac("not-a-mac")
    assert answer["found"] is False
    assert answer["error"] == "not a MAC address"


def test_where_is_unknown_mac(estate_env):
    answer = inventory_tools.where_is_mac("02:00:00:00:00:99")
    assert answer["found"] is False
    assert "not known here" in answer["summary"]


def test_where_is_ip_chases_arp_dhcp_and_the_switch_port(estate_env):
    answer = inventory_tools.where_is_ip("10.0.20.55")
    assert answer["found"] is True
    assert answer["macs"] == ["00:50:56:01:aa:bb"]

    sources = {b["source"] for b in answer["bindings"]}
    assert {"fortigate-arp", "fortigate-dhcp", "vm"} <= sources
    lease = next(b for b in answer["bindings"] if b["source"] == "fortigate-dhcp")
    assert (lease["device"], lease["interface"], lease["hostname"]) == (
        "fw-01",
        "srv-vl20",
        "app-01",
    )

    assert {
        "device": "sw-core-01",
        "port": "GigabitEthernet1/0/1",
        "vlan": 20,
        "source": "cisco-mac-table",
    } in answer["switch_ports"]
    assert answer["virtual_machines"][0]["vm"] == "app-01"
    assert answer["prefix"] == {
        "prefix": "10.0.20.0/24",
        "vlan": 20,
        "description": "servers",
    }
    assert "reachable through sw-core-01" in answer["summary"]


def test_where_is_ip_finds_a_switch_svi(estate_env):
    answer = inventory_tools.where_is_ip("10.0.10.2")
    binding = next(b for b in answer["bindings"] if b["source"] == "interface")
    assert (binding["device"], binding["interface"]) == ("sw-core-01", "Vlan10")


def test_where_is_ip_rejects_nonsense(estate_env):
    assert inventory_tools.where_is_ip("banana")["error"] == "not an IP address"


def test_find_port_reports_learned_macs(estate_env):
    answer = inventory_tools.find_port("sw-core-01:Gi1/0/1")
    assert answer["found"] is True
    assert answer["sensitive"] is True
    assert answer["interface"]["tagged_vlans"] == [10, 20, 30]
    assert {m["mac"] for m in answer["learned_macs"]} == {"00:50:56:01:aa:bb"}
    assert inventory_tools.find_port("nonsense")["found"] is False


# --------------------------------------------------------------------------- drift + safety
def test_drift_tool_explains_itself_before_a_baseline(estate_env):
    report = inventory_tools.drift_report()
    assert report["source"] == "none"
    assert any("baseline" in w for w in report["warnings"])


def test_drift_tool_reports_against_the_accepted_baseline(estate_env, tmp_path):
    from infra_agent.reconcile import service

    service.accept_baseline(settings=estate_env, accepted_by="owner")

    esxi = esxi_data()
    esxi["vms"][0]["num_cpu"] = 8
    write_estate(tmp_path, {"esx-01": esxi})  # newer snapshot in the same tree

    report = inventory_tools.drift_report()
    assert report["source"] == "baseline"
    item = report["by_device"]["esx-01"][0]
    assert (item["object"], item["field"]) == ("app-01", "vcpus")
    assert item["observed"] == 8.0 and item["intended"] == 4.0

    assert inventory_tools.drift_report(device="fw-01")["by_device"] == {}


def test_drift_tool_degrades_instead_of_raising_when_netbox_is_down(estate_env, monkeypatch):
    """A read tool that raises out of the agent loop is worse than a partial answer."""
    from infra_agent.reconcile import service

    service.accept_baseline(settings=estate_env, accepted_by="owner")
    monkeypatch.setattr(service, "netbox_client", lambda *a, **k: _DeadNetBox())

    report = inventory_tools.drift_report()
    assert report["source"] == "baseline"
    assert any("NetBox is unreachable" in w for w in report["warnings"])

    located = inventory_tools.where_is_mac("0050.5601.aabb")
    assert located["found"] is True, "the snapshot answer survives NetBox being down"
    assert located["netbox_interfaces"] == []


def test_where_is_mac_enriches_from_netbox(estate_env, monkeypatch):
    """The MAC is findable in NetBox only because bootstrap stores it as an object."""
    from infra_agent.reconcile import bootstrap, service
    from infra_agent.reconcile.fake import FakeNetBox

    client = FakeNetBox()
    bootstrap(service.observed_estate(estate_env), client)
    monkeypatch.setattr(service, "netbox_client", lambda *a, **k: client)

    answer = inventory_tools.where_is_mac("aa:bb:cc:00:01:01")
    assert [i["name"] for i in answer["netbox_interfaces"]] == ["GigabitEthernet1/0/1"]

    vm_nic = inventory_tools.where_is_mac("00:50:56:01:aa:bb")
    assert any("Network adapter 1" == i["name"] for i in vm_nic["netbox_interfaces"])


def test_every_inventory_answer_survives_the_redaction_gateway(estate_env, tmp_path):
    gateway = RedactionGateway(audit_log=tmp_path / "audit.jsonl")
    payloads = [
        inventory_tools.list_devices(),
        inventory_tools.get_device("sw-core-01"),
        inventory_tools.find_vm("app"),
        inventory_tools.list_vlans(),
        inventory_tools.where_is_mac("0050.5601.aabb"),
        inventory_tools.where_is_ip("10.0.20.55"),
        inventory_tools.drift_report(),
    ]
    for payload in payloads:
        gateway.refuse_raw_config(payload)
        gateway.egress(payload, tool="inventory.test")
    assert (tmp_path / "audit.jsonl").read_text().count("\n") == len(payloads)


def test_inventory_answers_never_carry_approval_material(estate_env):
    blob = repr(
        [
            inventory_tools.get_device("sw-core-01"),
            inventory_tools.drift_report(),
            inventory_tools.where_is_ip("10.0.20.55"),
        ]
    ).lower()
    for forbidden in (
        "approval",
        "confirmation_phrase",
        "token_sha256",
        "password",
        "api_key",
        "secret",
    ):
        assert forbidden not in blob
