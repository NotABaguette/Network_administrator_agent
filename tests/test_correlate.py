"""Correlation, impact analysis and topology rendering, on a synthetic estate.

`tests/fixtures/estate/` holds recorded snapshots for two Catalyst switches, a
FortiGate, two standalone ESXi hosts with four VMs and the iLO behind each
host, plus three seeded faults: a trunk VLAN mismatch, a portgroup on a VLAN no
switch carries, a duplicate IP and a disconnected vNIC. Everything runs
offline.
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from infra_agent.change.plan import Tier
from infra_agent.change.tiers import compute_tier
from infra_agent.config import Settings, get_settings
from infra_agent.correlate import service
from infra_agent.correlate.builder import GraphBuilder
from infra_agent.correlate.checks import run_checks
from infra_agent.correlate.impact import DependencyIndex, impact_analyze, impact_summary
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
)
from infra_agent.models.common import SeedInventory
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
CORE_TO_ACC = "interface:sw-core-01:GigabitEthernet1/0/24"
ACC_TO_CORE = "interface:sw-acc-01:GigabitEthernet1/0/24"
ACCESS_PORT = "interface:sw-core-01:GigabitEthernet1/0/5"
MGMT_VNIC = "vnic:mgmt-01:Network adapter 1"
DB_VNIC = "vnic:db-01:Network adapter 1"


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

    # FortiGate LLDP and Catalyst LLDP agree on the firewall trunk.
    assert graph.edge(CORE_TO_FW, "interface:fw-01:internal", EdgeKind.l1_neighbor) is not None

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

    fresh = graph.edge("vnic:app-01:Network adapter 1", CORE_TO_ESX02, EdgeKind.mac_seen_on)
    assert fresh["stale"] is False
    assert fresh["confidence"] == pytest.approx(0.95)


# --- L3 --------------------------------------------------------------------


def test_l3_edges_from_guest_ips_arp_dhcp_prefixes_and_policies(graph: TopologyGraph):
    # a guest IP reported by the hypervisor
    assert graph.edge("vnic:web-01:Network adapter 1", "ip:10.20.0.11", EdgeKind.has_ip) is not None
    # a lease the firewall handed out
    assert graph.edge("vnic:app-01:Network adapter 1", "ip:10.20.0.12", EdgeKind.has_ip) is not None
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


# --- consistency checks ----------------------------------------------------


def test_seeded_faults_are_reported_as_findings(graph: TopologyGraph):
    findings = run_checks(graph)
    by_kind = {f.kind: f for f in findings}
    assert set(by_kind) == {
        "trunk_vlan_mismatch",
        "portgroup_vlan_not_carried",
        "duplicate_ip",
        "vm_disconnected_vnic",
    }

    mismatch = by_kind["trunk_vlan_mismatch"]
    assert set(mismatch.objects) == {CORE_TO_ACC, ACC_TO_CORE}
    assert mismatch.evidence["allowed_only_on"][CORE_TO_ACC] == [30]
    assert mismatch.evidence["allowed_only_on"][ACC_TO_CORE] == []

    orphan = by_kind["portgroup_vlan_not_carried"]
    assert orphan.objects[0] == "portgroup:esx-02:Lab"
    assert orphan.evidence["vlan"] == 40

    duplicate = by_kind["duplicate_ip"]
    assert duplicate.objects[0] == "ip:10.20.0.13"
    assert set(duplicate.evidence["owners"]) == {"app-01", "db-01"}

    disconnected = by_kind["vm_disconnected_vnic"]
    assert "vm:app-01" in disconnected.objects


def test_a_healthy_trunk_pair_is_not_reported(graph: TopologyGraph):
    findings = [f for f in run_checks(graph) if f.kind == "trunk_vlan_mismatch"]
    assert len(findings) == 1  # only the seeded pair, not every L1 link


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


def test_builder_tolerates_an_estate_with_no_snapshots_yet(tmp_path, estate_settings):
    inventory = SeedInventory.load(ESTATE / "inventory.yaml")
    empty = GraphBuilder(
        FileSnapshotStore(tmp_path / "empty"), inventory, settings=estate_settings, now=NOW
    ).build()
    assert len(empty.nodes_of_kind(NodeKind.device)) == len(inventory.devices)
    assert empty.g.number_of_edges() == 0
    assert empty.mgmt_path_nodes() == []


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

    kinds = {f["kind"] for f in topology_tools.findings()}
    assert "trunk_vlan_mismatch" in kinds

    assert topology_tools.render().startswith("graph LR")
    assert "VLAN 20" in topology_tools.render("vlan", vlan=20)
    with pytest.raises(ValueError):
        topology_tools.render("nonsense")


def test_tools_report_unknown_objects_without_raising(persisted):
    answer = topology_tools.neighbors("no-such-device")
    assert answer["found"] is False
    assert "hint" in answer
    assert topology_tools.path("no-such-device", "fw-01")["found"] is False


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

        missing = runner.invoke(app, ["graph", "impact", "interface:nope:Gi9/9/9"])
        assert missing.exit_code == 1
    finally:
        get_settings.cache_clear()
        service.clear_cache()
