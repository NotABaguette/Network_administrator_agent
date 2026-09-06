"""Correlation, impact analysis and topology rendering, on a synthetic estate.

`tests/fixtures/estate/` holds recorded snapshots for two Catalyst switches, a
FortiGate 60F, two standalone ESXi hosts with four VMs and the iLO behind each
host, plus the seeded faults: a trunk VLAN mismatch, portgroups on VLANs the
uplink feeding their host does not carry, a duplicate IP and a disconnected
vNIC. Everything runs offline.

The Catalyst snapshots are *not* written by hand: `tests/fixtures/estate/cli/`
holds the recorded `show` output and `regenerate_cisco.py` replays it through
ntc-templates exactly as the collector does, so the fixture is the shape the
pinned parser really emits (`vlan_id`, `neighbor_name`, `mgmt_address`, and an
empty `trunks` section because no `show interfaces trunk` template exists).
"""

from __future__ import annotations

import importlib.util
import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from infra_agent.change.plan import Tier
from infra_agent.change.tiers import compute_tier
from infra_agent.config import Settings, get_settings
from infra_agent.correlate import model as correlate_model
from infra_agent.correlate import service
from infra_agent.correlate.builder import (
    MAC_HALF_LIFE_HOURS,
    MAC_MAX_AGE_HOURS,
    MIN_MAC_CONFIDENCE,
    GraphBuilder,
)
from infra_agent.correlate.checks import run_checks
from infra_agent.correlate.impact import (
    DependencyIndex,
    default_action,
    impact_analyze,
    impact_summary,
)
from infra_agent.correlate.mermaid import (
    GENERATED_MARK,
    render_physical,
    render_storage,
    render_vlan,
    write_docs,
)
from infra_agent.correlate.model import EdgeKind, NodeKind, TopologyGraph
from infra_agent.correlate.parsing import (
    compact_vlan_list,
    expand_vlan_list,
    naa_key,
    normalize_ifname,
    normalize_mac,
    parse_ip_mask,
    parse_trunk_text,
)
from infra_agent.models.common import DeviceKind, SeedDevice, SeedInventory, Snapshot
from infra_agent.redaction.gateway import RedactionGateway
from infra_agent.store.snapshots import FileSnapshotStore
from infra_agent.tools import topology_tools
from infra_agent.tools.registry import llm_tools, load_all

ESTATE = Path(__file__).parent / "fixtures" / "estate"
NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)

CORE_TO_ESX01 = "interface:sw-core-01:GigabitEthernet1/0/1"
ACC_TO_ESX01 = "interface:sw-acc-01:GigabitEthernet1/0/1"
CORE_TO_ESX02 = "interface:sw-core-01:GigabitEthernet1/0/3"
CORE_TO_ILO = "interface:sw-core-01:GigabitEthernet1/0/10"
CORE_TO_FW = "interface:sw-core-01:GigabitEthernet1/0/23"
CORE_TO_FW_B = "interface:sw-core-01:GigabitEthernet1/0/22"
CORE_TO_ACC = "interface:sw-core-01:GigabitEthernet1/0/24"
ACC_TO_CORE = "interface:sw-acc-01:GigabitEthernet1/0/24"
ACCESS_PORT = "interface:sw-core-01:GigabitEthernet1/0/5"
AP_PORT = "interface:sw-acc-01:GigabitEthernet1/0/5"
FW_MEMBER = "interface:fw-01:internal3"
FW_MEMBER_B = "interface:fw-01:internal4"
FW_SPARE = "interface:fw-01:internal5"
MGMT_VNIC = "vnic:mgmt-01:Network adapter 1"
DB_VNIC = "vnic:db-01:Network adapter 1"
APP_VNIC = "vnic:app-01:Network adapter 1"


@pytest.fixture(scope="module")
def estate_settings() -> Settings:
    return Settings(
        data_dir=Path("/nonexistent-for-tests"),
        seed_inventory=ESTATE / "inventory.yaml",
    )


@pytest.fixture(scope="module")
def graph(estate_settings: Settings) -> TopologyGraph:
    store = FileSnapshotStore(ESTATE / "snapshots")
    inventory = SeedInventory.load(ESTATE / "inventory.yaml")
    return GraphBuilder(store, inventory, settings=estate_settings, now=NOW).build()


def build_estate(
    inventory: SeedInventory | None = None,
    *,
    settings: Settings | None = None,
    **kwargs: Any,
) -> TopologyGraph:
    """The estate graph, optionally with a re-ordered inventory or a tweak."""
    return GraphBuilder(
        FileSnapshotStore(ESTATE / "snapshots"),
        inventory if inventory is not None else SeedInventory.load(ESTATE / "inventory.yaml"),
        settings=settings
        or Settings(
            data_dir=Path("/nonexistent-for-tests"), seed_inventory=ESTATE / "inventory.yaml"
        ),
        now=NOW,
        **kwargs,
    ).build()


def switch_graph(tmp_path: Path, data: dict[str, Any], name: str = "sw-test-01") -> TopologyGraph:
    """One Catalyst, one snapshot: for parser-shape regressions."""
    store = FileSnapshotStore(tmp_path / "snapshots")
    store.save(Snapshot(device=name, collector="cisco", taken_at=NOW, data=data))
    inventory = SeedInventory(
        devices=[
            SeedDevice(
                name=name, kind=DeviceKind.cisco_ios, mgmt_ip="10.0.0.9", credential_ref=name
            )
        ]
    )
    settings = Settings(data_dir=tmp_path, seed_inventory=tmp_path / "no-inventory.yaml")
    return GraphBuilder(store, inventory, settings=settings, now=NOW).build()


@pytest.fixture
def persisted(tmp_path, monkeypatch, graph: TopologyGraph):
    """The tool layer and the CLI read the persisted graph, not the snapshots."""
    monkeypatch.setenv("INFRA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("INFRA_SEED_INVENTORY", str(ESTATE / "inventory.yaml"))
    monkeypatch.setenv("INFRA_TOPOLOGY_DOCS_DIR", str(tmp_path / "docs" / "topology"))
    get_settings.cache_clear()
    service.clear_cache()
    service.persist(graph)
    yield tmp_path
    get_settings.cache_clear()
    service.clear_cache()


# --- parsing ---------------------------------------------------------------


def test_interface_names_are_canonicalised():
    assert normalize_ifname("Gi1/0/1") == "GigabitEthernet1/0/1"
    assert normalize_ifname("GigabitEthernet1/0/1") == "GigabitEthernet1/0/1"
    assert normalize_ifname("Te1/1/1") == "TenGigabitEthernet1/1/1"
    assert normalize_ifname("Po1") == "Port-channel1"
    assert normalize_ifname("Vlan10") == "Vlan10"
    assert normalize_ifname("internal.20") == "internal.20"  # FortiOS names pass through
    assert normalize_ifname("vmnic0") == "vmnic0"
    assert normalize_ifname(None) == ""


def test_macs_vlans_prefixes_and_volume_ids_normalise():
    assert normalize_mac("0050.56aa.0001") == "00:50:56:aa:00:01"
    assert normalize_mac("00-50-56-AA-00-01") == "00:50:56:aa:00:01"
    assert normalize_mac("not a mac") == ""
    assert expand_vlan_list("1-3,10,20") == {1, 2, 3, 10, 20}
    assert compact_vlan_list({1, 2, 3, 10, 20}) == "1-3,10,20"
    assert parse_ip_mask("10.20.0.1 255.255.255.0") == ("10.20.0.1", "10.20.0.0/24")
    assert parse_ip_mask("10.10.10.2/24") == ("10.10.10.2", "10.10.10.0/24")
    assert parse_ip_mask("0.0.0.0 0.0.0.0") is None
    assert naa_key("naa.600508b1001c000000000000000000a1") == naa_key(
        "600508B1001C000000000000000000A1"
    )


def test_raw_show_interfaces_trunk_output_is_parsed():
    """No ntc template exists for this command, so the text is parsed here."""
    rows = parse_trunk_text(
        "Port        Mode             Encapsulation  Status        Native vlan\n"
        "Gi1/0/1     on               802.1q         trunking      99\n"
        "\n"
        "Port        Vlans allowed on trunk\n"
        "Gi1/0/1     10,20-22\n"
        "            30\n"
        "\n"
        "Port        Vlans allowed and active in management domain\n"
        "Gi1/0/1     10,20\n"
        "\n"
        "Port        Vlans in spanning tree forwarding state and not pruned\n"
        "Gi1/0/1     10\n"
    )
    assert rows == [
        {
            "port": "GigabitEthernet1/0/1",
            "mode": "on",
            "encapsulation": "802.1q",
            "status": "trunking",
            "native_vlan": "99",
            "vlans_allowed": "10,20-22,30",  # the wrapped continuation line is kept
            "vlans_allowed_active": "10,20",
            "vlans_forwarding": "10",
        }
    ]
    assert parse_trunk_text([]) == []
    assert parse_trunk_text("") == []


# --- the shape the pinned parser really emits ------------------------------


def _regenerator():
    spec = importlib.util.spec_from_file_location(
        "estate_regenerate", ESTATE / "regenerate_cisco.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_cisco_fixtures_match_the_pinned_parser():
    """The Catalyst fixtures are what ntc-templates produces, not invented keys.

    The collector parses every `show` command with ntc-templates, so a fixture
    written by hand can pass while production yields an empty graph. Replaying
    the recorded CLI output through the installed parser makes a key rename in
    a templates upgrade fail here instead of silently in the field.
    """
    pytest.importorskip("ntc_templates", reason="the devices extra is not installed")
    regenerate = _regenerator()
    for device, stamps in regenerate.DEVICES.items():
        for stamp in stamps:
            committed = json.loads(
                (ESTATE / "snapshots" / device / "cisco" / f"{stamp}.json").read_text()
            )
            assert committed["data"] == regenerate.build(device, stamp, "")["data"], (
                f"{device}/{stamp}.json is stale: "
                "run `uv run python tests/fixtures/estate/regenerate_cisco.py`"
            )


def test_the_pinned_parser_emits_the_keys_the_builder_reads():
    """Pin the facts the L2 derivation depends on (verified against 9.2.0)."""
    parse = pytest.importorskip("ntc_templates.parse", reason="the devices extra is not installed")
    cli = ESTATE / "cli" / "sw-core-01"
    status = parse.parse_output(
        platform="cisco_ios",
        command="show interfaces status",
        data=(cli / "show_interfaces_status.txt").read_text(),
    )
    assert "vlan_id" in status[0] and "vlan" not in status[0]  # renamed in ntc-templates 5
    assert status[0]["vlan_id"] == "trunk"

    cdp = parse.parse_output(
        platform="cisco_ios",
        command="show cdp neighbors detail",
        data=(cli / "show_cdp_neighbors_detail.txt").read_text(),
    )
    assert {"neighbor_name", "mgmt_address", "local_interface", "neighbor_interface"} <= set(cdp[0])

    # and there is still no template for `show interfaces trunk`
    assert (
        parse.parse_output(
            platform="cisco_ios",
            command="show interfaces trunk",
            data=(cli / "show_interfaces_trunk.txt").read_text(),
        )
        == []
    )


def test_trunk_ports_and_their_vlans_survive_the_real_snapshot_shape(graph: TopologyGraph):
    """`show interfaces status` says `trunk`; `show spanning-tree` says which VLANs."""
    core = graph.node(CORE_TO_ESX01)
    assert core["mode"] == "trunk"
    assert core["vlan_source"] == "show spanning-tree"
    assert expand_vlan_list(core["allowed_vlans"]) == {10, 20}
    assert graph.edge(CORE_TO_ESX01, "vlan:10", EdgeKind.trunk_vlan)["confidence"] == 0.9

    to_firewall = graph.node(CORE_TO_FW)
    assert expand_vlan_list(to_firewall["allowed_vlans"]) == {1, 10, 20, 30}
    assert len(graph.edges_of_kind(EdgeKind.trunk_vlan)) > 0

    # an access port is not turned into a trunk by the spanning-tree fallback
    assert graph.node(ACCESS_PORT)["mode"] == "access"
    assert graph.node(ACCESS_PORT)["access_vlan"] == 20
    assert graph.node(ACCESS_PORT).get("allowed_vlans") is None


def test_a_trunk_away_from_the_management_path_still_forces_tier_2(estate_settings):
    """The escalation must come from the trunk itself, not from luck.

    Every trunk in the fixture happens to be on the platform's own path; with
    the management VM absent nothing is, and a port action on the trunk to the
    access switch must still compute as Tier 2 (docs/risk-tiers.md).
    """
    settings = estate_settings.model_copy(update={"mgmt_vm_name": "no-such-vm"})
    graph = build_estate(settings=settings)
    assert graph.mgmt_path_nodes() == []
    summary = impact_summary(CORE_TO_ACC, graph)
    assert summary.touches_mgmt_path is False
    assert summary.feeds_ilo_or_mgmt_vlan is False
    assert summary.touches_trunk_or_uplink is True  # the trunk alone must escalate
    tier, reasons = compute_tier("switch.access_port_config", summary)
    assert tier is Tier.WINDOW
    assert [r for r in reasons if "trunk" in r]


def test_trunk_vlans_from_raw_show_interfaces_trunk_text(tmp_path: Path):
    """An IOS-XE box stores raw text for every command; the trunk block is read."""
    graph = switch_graph(
        tmp_path,
        {
            "interfaces_status": [
                {"port": "Gi1/0/1", "name": "uplink", "status": "connected", "vlan_id": "trunk"}
            ],
            "trunks": (ESTATE / "cli" / "sw-core-01" / "show_interfaces_trunk.txt").read_text(),
            "vlans": [{"vlan_id": "10", "vlan_name": "mgmt", "interfaces": []}],
        },
    )
    port = "interface:sw-test-01:GigabitEthernet1/0/1"
    assert graph.node(port)["mode"] == "trunk"
    assert graph.node(port)["vlan_source"] == "show interfaces trunk"
    assert expand_vlan_list(graph.node(port)["allowed_vlans"]) == {10, 20}
    assert graph.edge(port, "vlan:10", EdgeKind.trunk_vlan) is not None
    assert impact_summary(port, graph).touches_trunk_or_uplink is True


def test_trunk_vlans_from_show_interfaces_switchport_rows(tmp_path: Path):
    """The ntc-supported command a collector can add without a new template."""
    graph = switch_graph(
        tmp_path,
        {
            "interfaces_status": [
                {"port": "Gi1/0/2", "name": "uplink", "status": "connected", "vlan_id": "trunk"}
            ],
            "switchport": [
                {
                    "interface": "GigabitEthernet1/0/2",
                    "mode": "trunk",
                    "admin_mode": "trunk",
                    "access_vlan": "1",
                    "native_vlan": "1",
                    "trunking_vlans": ["10,20", "30"],
                }
            ],
        },
    )
    port = "interface:sw-test-01:GigabitEthernet1/0/2"
    assert graph.node(port)["vlan_source"] == "show interfaces switchport"
    assert expand_vlan_list(graph.node(port)["allowed_vlans"]) == {10, 20, 30}


def test_a_switch_whose_output_no_template_matched_is_reported(tmp_path: Path):
    """Silence is the dangerous failure: say the graph is incomplete."""
    graph = switch_graph(
        tmp_path,
        {
            "interfaces_status": "Port      Name   Status   Vlan\nGi1/0/1  up  connected  trunk",
            "cdp": "Device ID: somebody",
            "mac_table": [],
        },
    )
    assert graph.nodes_of_kind(NodeKind.interface) == []
    gaps = [f for f in run_checks(graph) if f.kind == "collector_parse_gap"]
    assert {g.evidence["section"] for g in gaps} >= {"interfaces_status", "cdp"}
    assert all(g.objects == ["device:sw-test-01"] for g in gaps)
    assert all("raw text" in g.detail for g in gaps if g.evidence["section"] == "cdp")


def test_a_trunk_with_no_vlan_source_is_reported(tmp_path: Path):
    graph = switch_graph(
        tmp_path,
        {
            "interfaces_status": [
                {"port": "Gi1/0/1", "name": "uplink", "status": "connected", "vlan_id": "trunk"}
            ],
            "trunks": [],
        },
    )
    gaps = [f for f in run_checks(graph) if f.kind == "collector_parse_gap"]
    assert any("no source lists the VLANs it carries" in g.detail for g in gaps)


# --- graph shape -----------------------------------------------------------


def test_every_node_kind_the_estate_contains_is_built(graph: TopologyGraph):
    expected = {
        NodeKind.device,
        NodeKind.interface,
        NodeKind.vlan,
        NodeKind.vswitch,
        NodeKind.portgroup,
        NodeKind.vm,
        NodeKind.vnic,
        NodeKind.datastore,
        NodeKind.logical_drive,
        NodeKind.physical_drive,
        NodeKind.prefix,
        NodeKind.ip,
        NodeKind.fw_policy,
        NodeKind.wan_link,
    }
    for kind in expected:
        assert graph.nodes_of_kind(kind), f"no {kind} nodes were built"
    assert graph.node("device:sw-core-01")["role"] == "switch"
    assert graph.node("device:fw-01")["role"] == "firewall"
    assert graph.node("device:esx-01")["role"] == "host"
    assert graph.node("device:esx-01-ilo")["role"] == "bmc"


def test_every_edge_carries_evidence(graph: TopologyGraph):
    for source, target, _key, data in graph.g.edges(keys=True, data=True):
        where = f"{source} -> {target}"
        assert data.get("kind"), where
        assert data.get("collector"), where
        assert data.get("observed_at"), where
        assert 0.0 <= float(data["confidence"]) <= 1.0, where


# --- L1 --------------------------------------------------------------------


def test_l1_edges_come_from_cdp_and_lldp_with_confirmation_confidence(graph: TopologyGraph):
    # CDP from the switch and CDP from the ESXi host agree: both sides confirmed.
    edge = graph.edge(CORE_TO_ESX01, "interface:esx-01:vmnic0", EdgeKind.l1_neighbor)
    assert edge is not None
    assert edge["confirmed_both_sides"] is True
    assert edge["confidence"] == pytest.approx(0.99)
    assert graph.edge("interface:esx-01:vmnic0", CORE_TO_ESX01, EdgeKind.l1_neighbor) is not None

    # FortiGate LLDP and Catalyst LLDP agree on the firewall trunk. On a 60F the
    # cable lands on a hardware-switch *member* port, not on `internal` itself.
    assert graph.edge(CORE_TO_FW, FW_MEMBER, EdgeKind.l1_neighbor) is not None
    assert graph.edge(FW_MEMBER, "interface:fw-01:internal", EdgeKind.switch_member_of) is not None

    # Only the switch sees the iLO, so the link is kept at a lower confidence.
    ilo_edge = graph.edge(CORE_TO_ILO, "interface:esx-01-ilo:iLO-Port-1", EdgeKind.l1_neighbor)
    assert ilo_edge is not None
    assert ilo_edge["confirmed_both_sides"] is False
    assert ilo_edge["confidence"] == pytest.approx(0.9)

    # switch to switch
    assert graph.edge(CORE_TO_ACC, ACC_TO_CORE, EdgeKind.l1_neighbor) is not None


# --- L2 --------------------------------------------------------------------


def test_l2_chain_from_vnic_mac_to_switch_port_to_vlan_to_firewall(graph: TopologyGraph):
    # vNIC MAC learned on the switch port
    seen = graph.edge(MGMT_VNIC, CORE_TO_ESX01, EdgeKind.mac_seen_on)
    assert seen is not None
    assert seen["mac"] == "00:50:56:aa:00:01"
    assert seen["vlan"] == 10
    assert seen["stale"] is False

    # the port is a trunk that allows the VLAN
    assert graph.edge(CORE_TO_ESX01, "vlan:10", EdgeKind.trunk_vlan) is not None
    # the portgroup tags the same VLAN, on the vSwitch whose uplink that port is
    assert graph.edge("portgroup:esx-01:Management", "vlan:10", EdgeKind.portgroup_vlan) is not None
    assert graph.edge(MGMT_VNIC, "portgroup:esx-01:Management", EdgeKind.attached_to) is not None
    assert (
        graph.edge("vswitch:esx-01:vSwitch0", "interface:esx-01:vmnic0", EdgeKind.uplink_of)
        is not None
    )
    # and the FortiGate VLAN interface terminates it
    assert graph.edge("interface:fw-01:internal.10", "vlan:10", EdgeKind.svi_for) is not None
    assert (
        graph.edge(
            "interface:fw-01:internal.10", "interface:fw-01:internal", EdgeKind.subinterface_of
        )
        is not None
    )


def test_mac_aging_keeps_the_last_sighting_with_a_decaying_confidence(graph: TopologyGraph):
    """db-01 aged out of the current MAC table but was there four hours ago."""
    stale = graph.edge(DB_VNIC, CORE_TO_ESX02, EdgeKind.mac_seen_on)
    assert stale is not None
    assert stale["stale"] is True
    # four hours at a four hour half life halves the fresh confidence
    assert stale["confidence"] == pytest.approx(0.95 * 0.5, abs=0.01)
    assert stale["observed_at"].startswith("2026-09-06T08:00")

    fresh = graph.edge(APP_VNIC, CORE_TO_ESX02, EdgeKind.mac_seen_on)
    assert fresh["stale"] is False
    assert fresh["confidence"] == pytest.approx(0.95)


def test_the_mac_window_is_an_age_and_not_a_snapshot_count():
    """Twelve snapshots at the collector's 300 s interval is one hour, which is
    not the four-hour half life the decay curve is written for."""
    assert MAC_MAX_AGE_HOURS >= 4 * MAC_HALF_LIFE_HOURS
    builder = GraphBuilder(
        FileSnapshotStore(ESTATE / "snapshots"),
        SeedInventory.load(ESTATE / "inventory.yaml"),
        settings=Settings(data_dir=Path("/nonexistent-for-tests")),
        now=NOW,
    )
    # the whole curve, floor included, fits inside the window
    assert builder._mac_confidence(MAC_MAX_AGE_HOURS, fresh=False) == MIN_MAC_CONFIDENCE
    assert builder._mac_confidence(1.0, fresh=False) > MIN_MAC_CONFIDENCE

    tight = build_estate(mac_max_age_hours=1.0)
    assert tight.edge(DB_VNIC, CORE_TO_ESX02, EdgeKind.mac_seen_on) is None
    assert tight.edge(APP_VNIC, CORE_TO_ESX02, EdgeKind.mac_seen_on) is not None


# --- L3 --------------------------------------------------------------------


def test_l3_edges_from_guest_ips_arp_dhcp_prefixes_and_policies(graph: TopologyGraph):
    # a guest IP reported by the hypervisor
    assert graph.edge("vnic:web-01:Network adapter 1", "ip:10.20.0.11", EdgeKind.has_ip) is not None
    # a lease the firewall handed out, which nothing else in the estate reports
    lease = graph.edge(APP_VNIC, "ip:10.20.0.12", EdgeKind.has_ip)
    assert lease is not None
    assert lease["collector"] == "fortigate"
    assert "dhcp lease" in lease["note"]
    # containment in the prefix the FortiGate VLAN interface serves
    assert graph.edge("ip:10.20.0.11", "prefix:10.20.0.0/24", EdgeKind.in_prefix) is not None
    assert (
        graph.edge("interface:fw-01:internal.20", "prefix:10.20.0.0/24", EdgeKind.gateway_for)
        is not None
    )
    # the SVI on the core switch is a second gateway for the management prefix
    assert (
        graph.edge("interface:sw-core-01:Vlan10", "prefix:10.10.10.0/24", EdgeKind.gateway_for)
        is not None
    )
    # policies point at the addresses they reference, resolved through the object table
    assert graph.edge("fw_policy:fw-01:1", "prefix:10.20.0.0/24", EdgeKind.references) is not None
    assert graph.edge("fw_policy:fw-01:2", "ip:10.20.0.11", EdgeKind.references) is not None
    assert graph.edge("fw_policy:fw-01:1", "interface:fw-01:wan1", EdgeKind.references) is not None
    assert (
        graph.edge("interface:fw-01:wan1", "wan_link:fw-01:wan1", EdgeKind.wan_uplink) is not None
    )


def test_the_lease_is_the_only_source_of_that_address():
    """Guard the test above: it must not be satisfied by an explicit vNIC `ips`."""
    snapshot = json.loads(
        (ESTATE / "snapshots" / "esx-02" / "esxi" / "20260906T120000000000Z.json").read_text()
    )
    for vm in snapshot["data"]["vms"]:
        for nic in vm.get("vnics", []):
            assert "10.20.0.12" not in (nic.get("ips") or [])
        assert "10.20.0.12" not in (vm.get("guest_ips") or [])


def test_arp_and_dhcp_addresses_do_not_depend_on_the_inventory_order(graph: TopologyGraph):
    """`inventory/seed.yaml` is in whatever order `infra onboard add-device` ran.

    ARP tables and DHCP leases are read from the switches and the firewall but
    belong to VMs on the hosts, so joining them at ingest time silently drops
    half of L3 whenever the hosts happen to be listed first.
    """
    devices = SeedInventory.load(ESTATE / "inventory.yaml").devices
    hosts_first = SeedInventory(
        devices=[d for d in devices if d.kind in (DeviceKind.esxi, DeviceKind.ilo)]
        + [d for d in devices if d.kind not in (DeviceKind.esxi, DeviceKind.ilo)]
    )
    assert [d.name for d in hosts_first.devices] != [d.name for d in devices]

    reordered = build_estate(hosts_first)
    assert reordered.edge(APP_VNIC, "ip:10.20.0.12", EdgeKind.has_ip) is not None
    assert reordered.edge("ip:10.20.0.12", "prefix:10.20.0.0/24", EdgeKind.in_prefix) is not None
    assert set(reordered.g.nodes) == set(graph.g.nodes)
    assert reordered.summary()["edges_by_kind"] == graph.summary()["edges_by_kind"]


# --- storage ---------------------------------------------------------------


def test_storage_chain_from_vm_to_physical_drives(graph: TopologyGraph):
    stored = graph.edge("vm:mgmt-01", "datastore:esx-01:ds-esx01-local", EdgeKind.stored_on)
    assert stored is not None
    assert "mgmt-01.vmdk" in stored["vmdk"]
    backed = graph.edge(
        "datastore:esx-01:ds-esx01-local", "logical_drive:esx-01-ilo:1", EdgeKind.backed_by
    )
    assert backed is not None
    assert backed["volume_id"] == naa_key("600508B1001C000000000000000000A1")
    assert (
        graph.edge("logical_drive:esx-01-ilo:1", "physical_drive:esx-01-ilo:1I:1:1", EdgeKind.spans)
        is not None
    )
    assert graph.edge("device:esx-01-ilo", "device:esx-01", EdgeKind.manages) is not None


# --- the platform's own path ----------------------------------------------


def test_mgmt_path_is_marked_from_the_vm_to_the_firewall(graph: TopologyGraph):
    assert graph.g.graph["mgmt_vm"] == "vm:mgmt-01"
    assert graph.g.graph["mgmt_vlans"] == [10]
    marked = set(graph.mgmt_path_nodes())
    for node in (
        "vm:mgmt-01",
        MGMT_VNIC,
        "portgroup:esx-01:Management",
        "vswitch:esx-01:vSwitch0",
        "interface:esx-01:vmnic0",
        "interface:esx-01:vmnic1",
        "device:esx-01",
        CORE_TO_ESX01,
        ACC_TO_ESX01,
        "device:sw-core-01",
        "device:sw-acc-01",
        CORE_TO_FW,
        "interface:fw-01:internal",
        "device:fw-01",
        "wan_link:fw-01:wan1",
    ):
        assert node in marked, f"{node} should be on the platform's path"
    for node in ("vm:db-01", "vm:web-01", "device:esx-02", CORE_TO_ESX02, "vlan:10"):
        assert node not in marked, f"{node} should not be on the platform's path"


def test_every_redundant_route_to_the_firewall_is_on_the_path(graph: TopologyGraph):
    """Two trunks to the firewall: marking one of them is worse than useless.

    The second link is the redundancy that keeps the platform reachable, so a
    change on it is exactly as dangerous as one on the first.
    """
    marked = set(graph.mgmt_path_nodes())
    assert {CORE_TO_FW, FW_MEMBER} <= marked
    assert {CORE_TO_FW_B, FW_MEMBER_B} <= marked, "the parallel core/firewall link is unmarked"
    assert impact_summary(CORE_TO_FW_B, graph).touches_mgmt_path is True
    assert impact_summary(FW_MEMBER_B, graph).touches_mgmt_path is True
    # the unused hardware-switch ports are not dragged onto the path with them
    assert FW_SPARE not in marked
    assert "interface:fw-01:internal1" not in marked


def test_the_path_does_not_transit_hosts_ilos_or_discovered_neighbours(graph: TopologyGraph):
    """Only switches and firewalls forward for the platform."""
    marked = set(graph.mgmt_path_nodes())
    assert "device:esx-01-ilo" not in marked
    assert "device:ap-hallway-01" not in marked
    assert "interface:esx-01-ilo:iLO-Port-1" not in marked
    assert AP_PORT not in marked


def test_the_fortigate_hardware_switch_is_wired_through_its_member_ports(graph: TopologyGraph):
    """On a 60F the LLDP neighbour is the member port and the gateways are on
    the parent; without that edge a change on the member port looks harmless."""
    for member in (FW_MEMBER, FW_MEMBER_B):
        assert graph.edge(member, "interface:fw-01:internal", EdgeKind.switch_member_of) is not None
        assert graph.node(member)["uplink"] is True
        assert impact_summary(member, graph).touches_trunk_or_uplink is True

    report = impact_analyze(FW_MEMBER, graph)
    affected = {a.id for a in report.affected}
    assert "interface:fw-01:internal" in affected
    assert {"interface:fw-01:internal.10", "interface:fw-01:internal.20"} <= affected
    assert graph.node("interface:fw-01:internal")["hardware_switch"] is True

    # both members are wired, so losing one only costs redundancy
    assert report.loses_connectivity == []
    assert "interface:fw-01:internal" in {a.id for a in report.loses_redundancy}


# --- consistency checks ----------------------------------------------------


def test_seeded_faults_are_reported_as_findings(graph: TopologyGraph):
    findings = run_checks(graph)
    by_kind: dict[str, list] = {}
    for finding in findings:
        by_kind.setdefault(finding.kind, []).append(finding)
    assert set(by_kind) == {
        "trunk_vlan_mismatch",
        "portgroup_vlan_not_carried",
        "duplicate_ip",
        "vm_disconnected_vnic",
    }

    (mismatch,) = by_kind["trunk_vlan_mismatch"]
    assert set(mismatch.objects) == {CORE_TO_ACC, ACC_TO_CORE}
    assert mismatch.evidence["allowed_only_on"][CORE_TO_ACC] == [30]
    assert mismatch.evidence["allowed_only_on"][ACC_TO_CORE] == []

    orphan = next(f for f in by_kind["portgroup_vlan_not_carried"] if "Lab" in f.title)
    assert orphan.objects[0] == "portgroup:esx-02:Lab"
    assert orphan.evidence["vlan"] == 40
    assert orphan.severity == "critical"  # app-01 is stranded on it

    (duplicate,) = by_kind["duplicate_ip"]
    assert duplicate.objects[0] == "ip:10.20.0.13"
    assert set(duplicate.evidence["owners"]) == {"app-01", "db-01"}

    (disconnected,) = by_kind["vm_disconnected_vnic"]
    assert "vm:app-01" in disconnected.objects


def test_a_healthy_trunk_pair_is_not_reported(graph: TopologyGraph):
    findings = [f for f in run_checks(graph) if f.kind == "trunk_vlan_mismatch"]
    assert len(findings) == 1  # only the seeded pair, not every L1 link


def test_the_portgroup_vlan_check_follows_the_uplink_that_feeds_the_host(graph: TopologyGraph):
    """Estate-wide is the wrong question.

    VLAN 30 is trunked between the core and the firewall and the FortiGate has
    a gateway on it, so an estate-wide check calls it carried — but neither
    uplink feeding esx-01 allows it, so a VM on that portgroup is isolated.
    """
    findings = {
        f.objects[0]: f for f in run_checks(graph) if f.kind == "portgroup_vlan_not_carried"
    }
    assert graph.edge("interface:fw-01:internal.30", "vlan:30", EdgeKind.svi_for) is not None
    assert 30 in expand_vlan_list(graph.node(CORE_TO_FW)["allowed_vlans"])

    dmz = findings["portgroup:esx-01:DMZ"]
    assert dmz.evidence["vlan"] == 30
    assert dmz.evidence["host"] == "esx-01"
    assert set(dmz.evidence["uplinks_without_the_vlan"]) == {
        "interface:esx-01:vmnic0",
        "interface:esx-01:vmnic1",
    }
    assert dmz.evidence["uplinks_without_the_vlan"]["interface:esx-01:vmnic0"] == CORE_TO_ESX01
    assert dmz.evidence["uplinks_with_the_vlan"] == {}
    assert CORE_TO_ESX01 in dmz.objects
    assert dmz.severity == "warning"  # nothing is attached to it yet

    # VLANs both uplinks carry are not reported
    assert "portgroup:esx-01:Management" not in findings
    assert "portgroup:esx-01:Servers" not in findings


def test_a_single_uplink_host_reports_the_port_that_is_missing_the_vlan(graph: TopologyGraph):
    findings = run_checks(graph)
    lab = next(f for f in findings if f.objects and f.objects[0] == "portgroup:esx-02:Lab")
    assert lab.evidence["uplinks_with_the_vlan"] == {}
    assert lab.evidence["uplinks_without_the_vlan"] == {"interface:esx-02:vmnic0": CORE_TO_ESX02}
    assert "app-01" in lab.detail


def test_a_vlan_carried_on_one_uplink_only_is_still_reported():
    """One good uplink and one bad one black-holes the traffic that takes it."""
    evidence = correlate_model.Evidence(collector="test", device="sw-a")
    g = TopologyGraph(built_at=NOW)
    for device, role in (("sw-a", "switch"), ("sw-b", "switch"), ("esx-9", "host")):
        g.add_node(f"device:{device}", NodeKind.device, label=device, role=role)
    g.add_node("vlan:70", NodeKind.vlan, label="VLAN 70", vlan_id=70)
    for device, port, allowed in (("sw-a", "Gi1/0/1", "10,70"), ("sw-b", "Gi1/0/1", "10")):
        node = g.add_node(
            f"interface:{device}:{port}",
            NodeKind.interface,
            label=f"{device} {port}",
            device=device,
            mode="trunk",
            allowed_vlans=allowed,
        )
        g.add_edge(f"device:{device}", node, EdgeKind.has_interface, evidence)
    g.add_edge("interface:sw-a:Gi1/0/1", "vlan:70", EdgeKind.trunk_vlan, evidence)
    g.add_node("vswitch:esx-9:vSwitch0", NodeKind.vswitch, label="esx-9 vSwitch0", device="esx-9")
    g.add_node(
        "portgroup:esx-9:Lab", NodeKind.portgroup, label="esx-9 Lab", device="esx-9", vlan=70
    )
    g.add_edge("portgroup:esx-9:Lab", "vswitch:esx-9:vSwitch0", EdgeKind.portgroup_on, evidence)
    for index, peer in enumerate(("sw-a", "sw-b")):
        pnic = g.add_node(
            f"interface:esx-9:vmnic{index}",
            NodeKind.interface,
            label=f"esx-9 vmnic{index}",
            device="esx-9",
            pnic=True,
        )
        g.add_edge("device:esx-9", pnic, EdgeKind.has_interface, evidence)
        g.add_edge("vswitch:esx-9:vSwitch0", pnic, EdgeKind.uplink_of, evidence)
        g.add_edge(pnic, f"interface:{peer}:Gi1/0/1", EdgeKind.l1_neighbor, evidence)

    (finding,) = [f for f in run_checks(g) if f.kind == "portgroup_vlan_not_carried"]
    assert finding.evidence["uplinks_with_the_vlan"] == {
        "interface:esx-9:vmnic0": "interface:sw-a:Gi1/0/1"
    }
    assert finding.evidence["uplinks_without_the_vlan"] == {
        "interface:esx-9:vmnic1": "interface:sw-b:Gi1/0/1"
    }
    assert "sw-b Gi1/0/1" in finding.detail


# --- impact analysis -------------------------------------------------------


def test_impact_on_the_port_feeding_mgmt_01_touches_the_platform_path(graph: TopologyGraph):
    report = impact_analyze(CORE_TO_ESX01, graph)
    assert report.found
    assert report.summary.touches_mgmt_path is True
    assert report.summary.touches_trunk_or_uplink is True
    assert report.summary.feeds_ilo_or_mgmt_vlan is True

    # esx-01 has a second uplink, so nothing loses connectivity, but mgmt-01 and
    # everything between it and the network lose their redundancy.
    degraded = {a.id for a in report.loses_redundancy}
    assert "vm:mgmt-01" in degraded
    assert "vswitch:esx-01:vSwitch0" in degraded
    assert {a.id for a in report.loses_connectivity} == {"interface:esx-01:vmnic0"}
    assert any("mgmt path" in line for line in report.describe())

    # the tier engine escalates on that summary alone
    tier, reasons = compute_tier("switch.access_port_config", report.summary)
    assert tier is Tier.WINDOW
    assert any("management path" in reason for reason in reasons)


def test_impact_on_a_single_uplink_takes_its_vms_offline(graph: TopologyGraph):
    report = impact_analyze(CORE_TO_ESX02, graph)
    offline = {a.id for a in report.loses_connectivity}
    assert {"vm:app-01", "vm:db-01", "vswitch:esx-02:vSwitch0"} <= offline
    assert "interface:esx-02:vmnic0" in offline
    # esx-02 hosts nothing of the platform's own
    assert report.summary.touches_mgmt_path is False
    # it still carries the management VLAN, which is its own escalation
    assert report.summary.feeds_ilo_or_mgmt_vlan is True
    assert compute_tier("switch.trunk_port_config", report.summary)[0] is Tier.WINDOW


def test_impact_on_a_plain_access_port_stays_local(graph: TopologyGraph):
    summary = impact_summary(ACCESS_PORT, graph)
    assert summary.affected_objects == []
    assert summary.touches_mgmt_path is False
    assert summary.touches_trunk_or_uplink is False
    assert summary.feeds_ilo_or_mgmt_vlan is False
    assert compute_tier("switch.access_port_config", summary)[0] is Tier.APPROVAL


def test_a_port_feeding_an_ilo_escalates(graph: TopologyGraph):
    summary = impact_summary(CORE_TO_ILO, graph)
    assert summary.feeds_ilo_or_mgmt_vlan is True
    assert compute_tier("switch.access_port_config", summary)[0] is Tier.WINDOW


def test_impact_on_a_wan_link_is_flagged(graph: TopologyGraph):
    assert impact_summary("interface:fw-01:wan1", graph).touches_wan_ha_vpn_stp is True
    assert impact_summary("wan_link:fw-01:wan2", graph).touches_wan_ha_vpn_stp is True


def test_ordinary_port_descriptions_do_not_masquerade_as_wan_ha_or_stp(graph: TopologyGraph):
    """`ha` inside `chassis`, `shared` or `Hallway` must not force a window.

    Over-escalation is the safe direction only until it is routine: a Tier 2
    change asks for a maintenance window and a confirmation phrase, and an
    owner who is asked for one on every access port stops reading them.
    """
    assert graph.node(FW_SPARE)["alias"] == "shared storage nas"
    assert impact_summary(FW_SPARE, graph).touches_wan_ha_vpn_stp is False
    assert graph.node(AP_PORT)["description"] == "Hallway AP"
    assert impact_summary(AP_PORT, graph).touches_wan_ha_vpn_stp is False
    assert compute_tier("switch.access_port_config", impact_summary(AP_PORT, graph))[0] is (
        Tier.APPROVAL
    )


@pytest.mark.parametrize(
    ("description", "flagged"),
    [
        ("chassis link", False),
        ("shared storage", False),
        ("Hallway AP", False),
        ("channel 3", False),
        ("uplink to the ISP", True),
        ("wan1 backup", True),
        ("ipsec to branch", True),
        ("stp root guard edge", True),
    ],
)
def test_wan_hints_are_matched_as_whole_tokens(tmp_path: Path, description: str, flagged: bool):
    graph = switch_graph(
        tmp_path,
        {
            "interfaces_status": [
                {"port": "Gi1/0/9", "name": description, "status": "connected", "vlan_id": "20"}
            ]
        },
    )
    port = "interface:sw-test-01:GigabitEthernet1/0/9"
    assert graph.node(port)["description"] == description
    assert impact_summary(port, graph).touches_wan_ha_vpn_stp is flagged


def test_spanning_tree_relevance_comes_from_the_stp_section(graph: TopologyGraph):
    """STP is a fact in `show spanning-tree`, not a word in a description."""
    root_port = graph.node(ACC_TO_CORE)
    assert root_port["stp_roles"] == ["Root"]
    assert root_port["stp_significant"] is True
    assert impact_summary(ACC_TO_CORE, graph).touches_wan_ha_vpn_stp is True
    # a designated edge port is not an STP-significant port
    assert graph.node(AP_PORT)["stp_roles"] == ["Desg"]
    assert graph.node(AP_PORT)["stp_edge_port"] is True
    assert graph.node(AP_PORT)["stp_significant"] is False


def test_impact_on_a_vlan_knows_it_has_members(graph: TopologyGraph):
    summary = impact_summary("vlan:20", graph)
    assert summary.vlan_has_members_or_svi is True
    assert compute_tier("vlan.remove", summary)[0] is Tier.WINDOW


def test_raid5_survives_one_drive_but_the_datastore_is_degraded(graph: TopologyGraph):
    report = impact_analyze("physical_drive:esx-02-ilo:1I:1:3", graph)
    assert report.loses_connectivity == []
    degraded = {a.id for a in report.loses_redundancy}
    assert "logical_drive:esx-02-ilo:1" in degraded
    assert "datastore:esx-02:ds-esx02-local" in degraded
    assert {"vm:app-01", "vm:db-01"} <= degraded


def test_losing_a_mirror_leg_and_its_partner_takes_the_datastore_down(graph: TopologyGraph):
    """RAID 1 tolerates one drive; the logical drive itself does not."""
    report = impact_analyze("logical_drive:esx-01-ilo:1", graph)
    offline = {a.id for a in report.loses_connectivity}
    assert "datastore:esx-01:ds-esx01-local" in offline
    assert "vm:mgmt-01" in offline
    assert report.summary.touches_mgmt_path is True


def test_impact_on_an_unknown_object_is_reported_not_raised(graph: TopologyGraph):
    report = impact_analyze("interface:nope:Gi9/9/9", graph)
    assert report.found is False
    assert report.summary.affected_objects == []


def test_dependency_index_is_reusable_across_queries(graph: TopologyGraph):
    index = DependencyIndex(graph)
    first = impact_analyze(CORE_TO_ESX02, graph, index=index)
    second = impact_analyze(CORE_TO_ESX02, graph, index=index)
    assert first.summary.affected_objects == second.summary.affected_objects


# --- queries ---------------------------------------------------------------


def test_neighbors_and_paths(graph: TopologyGraph):
    neighbours = {n["id"] for n in graph.neighbors(CORE_TO_ESX01)}
    assert {"device:sw-core-01", "interface:esx-01:vmnic0", "vlan:10", MGMT_VNIC} <= neighbours

    path = graph.path("vm:mgmt-01", "device:fw-01")
    assert path[0] == "vm:mgmt-01"
    assert path[-1] == "device:fw-01"
    detail = graph.path_detail("vm:mgmt-01", "device:fw-01")
    assert detail["found"] is True
    assert all(hop["edges"] for hop in detail["hops"])
    assert graph.path("vm:mgmt-01", "vm:mgmt-01") == ["vm:mgmt-01"]


def test_loose_references_resolve(graph: TopologyGraph):
    assert graph.resolve("sw-core-01") == "device:sw-core-01"
    assert graph.resolve("mgmt-01") == "vm:mgmt-01"
    assert graph.resolve("20") == "vlan:20"
    assert graph.resolve("device:sw-core-01") == "device:sw-core-01"
    assert graph.resolve("no-such-thing") is None


# --- persistence -----------------------------------------------------------


def test_graph_survives_a_json_round_trip(graph: TopologyGraph, tmp_path: Path):
    path = graph.save(tmp_path / "graph" / "graph.json")
    reloaded = TopologyGraph.load(path)
    assert reloaded.summary() == graph.summary()
    assert reloaded.mgmt_path_nodes() == graph.mgmt_path_nodes()
    assert reloaded.g.graph["mgmt_vm"] == "vm:mgmt-01"
    assert (
        reloaded.edge(CORE_TO_ESX01, "interface:esx-01:vmnic0", EdgeKind.l1_neighbor)["confidence"]
        == 0.99
    )
    assert impact_analyze(CORE_TO_ESX01, reloaded).summary.touches_mgmt_path is True


def test_build_and_persist_writes_graph_and_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("INFRA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("INFRA_SEED_INVENTORY", str(ESTATE / "inventory.yaml"))
    get_settings.cache_clear()
    service.clear_cache()
    try:
        shutil.copytree(ESTATE / "snapshots", tmp_path / "data" / "snapshots")
        built, findings, path = service.build_and_persist()
        assert path.exists()
        assert service.findings_path().exists()
        assert findings
        assert service.load_graph().summary()["nodes"] == built.summary()["nodes"]
        assert {f.kind for f in service.load_findings()} == {f.kind for f in findings}
    finally:
        get_settings.cache_clear()
        service.clear_cache()


def test_graph_and_findings_are_written_atomically(graph: TopologyGraph, tmp_path, monkeypatch):
    """The MCP server reads graph.json while `infra graph build` rewrites it."""
    path = tmp_path / "graph" / "graph.json"
    graph.save(path)
    intact = path.read_text()

    def boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(correlate_model.os, "replace", boom)
    with pytest.raises(OSError):
        graph.save(path)
    assert path.read_text() == intact  # a reader never sees a half-written file
    assert list(path.parent.iterdir()) == [path]  # and no temp file is left behind


def test_an_on_demand_rebuild_is_persisted(tmp_path, monkeypatch):
    """Otherwise every topology.* call walks every snapshot again."""
    monkeypatch.setenv("INFRA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("INFRA_SEED_INVENTORY", str(ESTATE / "inventory.yaml"))
    get_settings.cache_clear()
    service.clear_cache()
    try:
        shutil.copytree(ESTATE / "snapshots", tmp_path / "data" / "snapshots")
        assert not service.graph_path().exists()
        rebuilt = service.load_graph()
        assert service.graph_path().exists()
        assert service.findings_path().exists()
        assert service.load_graph().summary()["nodes"] == rebuilt.summary()["nodes"]
    finally:
        get_settings.cache_clear()
        service.clear_cache()


def test_a_graph_nobody_rebuilt_reports_itself_stale(graph: TopologyGraph):
    """Nothing rebuilds on a schedule yet, so every answer carries its age."""
    fresh = service.freshness(graph, now=NOW + timedelta(minutes=5))
    assert fresh["stale"] is False
    assert fresh["age_seconds"] == pytest.approx(300)
    assert fresh["built_at"].startswith("2026-09-06T12:00")
    assert service.freshness(graph, now=NOW + timedelta(days=1))["stale"] is True


def test_builder_tolerates_an_estate_with_no_snapshots_yet(tmp_path, estate_settings):
    inventory = SeedInventory.load(ESTATE / "inventory.yaml")
    empty = GraphBuilder(
        FileSnapshotStore(tmp_path / "empty"), inventory, settings=estate_settings, now=NOW
    ).build()
    assert len(empty.nodes_of_kind(NodeKind.device)) == len(inventory.devices)
    assert empty.g.number_of_edges() == 0
    assert empty.mgmt_path_nodes() == []
    # and says so, instead of presenting an empty estate as a healthy one
    gaps = [f for f in run_checks(empty) if f.kind == "collector_parse_gap"]
    assert len(gaps) == len(inventory.devices)
    assert all("no snapshot" in f.detail for f in gaps)


def test_the_healthy_estate_has_no_parse_gaps(graph: TopologyGraph):
    assert graph.g.graph["parse_gaps"] == []


# --- mermaid ---------------------------------------------------------------


def test_physical_diagram_shows_devices_and_evidence(graph: TopologyGraph):
    text = render_physical(graph)
    assert text.startswith("graph LR")
    assert "sw-core-01 (switch)" in text
    assert "fw-01 (firewall)" in text
    assert "cdp 0.99" in text
    assert "classDef mgmt" in text


def test_vlan_diagram_shows_the_l2_story(graph: TopologyGraph):
    text = render_vlan(graph, 10)
    assert "VLAN 10 (mgmt)" in text
    assert "trunk" in text and "gateway" in text
    assert "mgmt-01" in text
    assert "not in the graph" in render_vlan(graph, 4000)


def test_storage_diagram_walks_the_chain(graph: TopologyGraph):
    text = render_storage(graph)
    assert "esx-01 ds-esx01-local" in text
    assert "esx-01-ilo LD1" in text
    assert "esx-01-ilo disk 1I:1:1" in text


def test_write_docs_emits_generated_headers(graph: TopologyGraph, tmp_path: Path):
    written = write_docs(graph, tmp_path / "topology", run_checks(graph))
    names = {p.name for p in written}
    assert {"physical.md", "storage.md", "index.md", "vlan-0010.md"} <= names
    for path in written:
        text = path.read_text()
        assert text.startswith(GENERATED_MARK)
        assert "graph built at 2026-09-06T12:00:00+00:00" in text
    assert "```mermaid" in (tmp_path / "topology" / "physical.md").read_text()
    assert "trunk between" in (tmp_path / "topology" / "index.md").read_text()


# --- tool layer ------------------------------------------------------------


def test_topology_tools_are_registered_and_model_callable():
    load_all()
    names = {spec.name for spec in llm_tools()}
    assert {
        "topology.neighbors",
        "topology.path",
        "topology.impact_analyze",
        "topology.findings",
        "topology.render",
    } <= names


def test_tools_answer_from_the_persisted_graph(persisted):
    assert topology_tools.summary()["nodes"] > 50
    assert topology_tools.summary()["graph"]["stale"] in (True, False)

    neighbours = topology_tools.neighbors("sw-core-01")
    assert neighbours["found"] is True
    assert neighbours["object_id"] == "device:sw-core-01"
    assert any(n["id"] == CORE_TO_ESX01 for n in neighbours["neighbors"])
    assert all("confidence" in n["edge"] for n in neighbours["neighbors"])

    route = topology_tools.path("mgmt-01", "fw-01")
    assert route["found"] is True
    assert route["nodes"][0]["id"] == "vm:mgmt-01"

    impact = topology_tools.impact_analyze(CORE_TO_ESX01)
    assert impact["summary"]["touches_mgmt_path"] is True
    assert any("mgmt-01" in line for line in impact["description"])

    reported = topology_tools.findings()
    kinds = {f["kind"] for f in reported["findings"]}
    assert "trunk_vlan_mismatch" in kinds
    assert "portgroup_vlan_not_carried" in kinds

    # every answer says how old the graph behind it is
    for answer in (neighbours, route, impact, reported, topology_tools.summary()):
        assert set(answer["graph"]) == {"built_at", "age_seconds", "stale"}
        assert answer["graph"]["built_at"].startswith("2026-09-06T12:00")

    assert topology_tools.render().startswith("graph LR")
    assert "VLAN 20" in topology_tools.render("vlan", vlan=20)
    with pytest.raises(ValueError):
        topology_tools.render("nonsense")


def test_tools_report_unknown_objects_without_raising(persisted):
    answer = topology_tools.neighbors("no-such-device")
    assert answer["found"] is False
    assert "hint" in answer
    assert "graph" in answer
    assert topology_tools.path("no-such-device", "fw-01")["found"] is False


def test_the_illustrative_tier_uses_an_action_that_fits_the_object(graph: TopologyGraph):
    """`switch.access_port_config` is meaningless for a datastore or a VM."""
    assert default_action(graph, CORE_TO_ESX01) == "switch.trunk_port_config"
    assert default_action(graph, ACCESS_PORT) == "switch.access_port_config"
    assert default_action(graph, "interface:fw-01:wan1") == "fortigate.wan"
    assert default_action(graph, FW_MEMBER) == "fortigate.policy"
    assert default_action(graph, "interface:esx-01:vmnic0") == "esxi.host_setting"
    assert default_action(graph, "vm:mgmt-01") == "vm.resize"
    assert default_action(graph, "datastore:esx-01:ds-esx01-local") == "storage.rebuild"
    assert default_action(graph, "vlan:20") == "vlan.remove"
    assert default_action(graph, "device:esx-01") == "esxi.host_setting"
    assert default_action(graph, "device:sw-core-01") == "firmware.update"
    assert default_action(graph, "nothing-like-this") == "switch.access_port_config"


def test_tool_output_survives_the_redaction_gateway(persisted, tmp_path):
    """Nothing the topology tools return may look like a raw device config."""
    gateway = RedactionGateway(audit_log=tmp_path / "egress.jsonl")
    for payload, name in (
        (topology_tools.neighbors("sw-core-01"), "topology.neighbors"),
        (topology_tools.impact_analyze(CORE_TO_ESX01), "topology.impact_analyze"),
        (topology_tools.findings(), "topology.findings"),
        (topology_tools.render(), "topology.render"),
        (topology_tools.render("storage"), "topology.render"),
    ):
        gateway.egress(payload, tool=name)
    assert (tmp_path / "egress.jsonl").read_text().count("\n") == 5


# --- cli -------------------------------------------------------------------


def test_graph_cli_builds_renders_and_explains(tmp_path, monkeypatch):
    monkeypatch.setenv("INFRA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("INFRA_SEED_INVENTORY", str(ESTATE / "inventory.yaml"))
    monkeypatch.setenv("INFRA_TOPOLOGY_DOCS_DIR", str(tmp_path / "topology"))
    get_settings.cache_clear()
    service.clear_cache()
    shutil.copytree(ESTATE / "snapshots", tmp_path / "data" / "snapshots")
    from infra_agent.cli import app

    runner = CliRunner()
    try:
        built = runner.invoke(app, ["graph", "build"])
        assert built.exit_code == 0, built.output
        assert (tmp_path / "data" / "graph" / "graph.json").exists()
        assert "trunk" in built.output

        rendered = runner.invoke(app, ["graph", "render"])
        assert rendered.exit_code == 0, rendered.output
        assert (tmp_path / "topology" / "physical.md").exists()

        printed = runner.invoke(app, ["graph", "render", "--diagram", "storage"])
        assert printed.exit_code == 0
        assert "graph LR" in printed.output

        impact = runner.invoke(app, ["graph", "impact", CORE_TO_ESX01])
        assert impact.exit_code == 0, impact.output
        assert "touches_mgmt_path" in impact.output
        assert "switch.trunk_port_config" in impact.output.replace("\n", "")

        # the illustrative action follows the object, and can be overridden
        storage = runner.invoke(app, ["graph", "impact", "datastore:esx-01:ds-esx01-local"])
        assert storage.exit_code == 0, storage.output
        assert "storage.rebuild" in storage.output.replace("\n", "")
        chosen = runner.invoke(app, ["graph", "impact", ACCESS_PORT, "--action", "vlan.add"])
        assert chosen.exit_code == 0, chosen.output
        assert "vlan.add" in chosen.output.replace("\n", "")

        missing = runner.invoke(app, ["graph", "impact", "interface:nope:Gi9/9/9"])
        assert missing.exit_code == 1
    finally:
        get_settings.cache_clear()
        service.clear_cache()
