"""The application layer of the graph: services, ports, certificates, dependencies.

A small offline estate: one ESXi host with three VMs, guest snapshots for two of
them (`web-01` generated from the recorded command output, `db-01` written by
hand as the other end of the dependency) and one Windows guest. Everything the
tests assert is derived from those snapshots - nothing here talks to anything.
"""

from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from infra_agent.config import Settings
from infra_agent.correlate.builder import GraphBuilder
from infra_agent.correlate.checks import run_checks
from infra_agent.correlate.guest import (
    external_network,
    is_routable_peer,
    resolve_owner,
    service_name_for,
)
from infra_agent.correlate.impact import DependencyIndex, default_action, impact_analyze
from infra_agent.correlate.mermaid import _safe, render, render_applications, write_docs
from infra_agent.correlate.model import EdgeKind, Evidence, NodeKind, TopologyGraph
from infra_agent.models.common import DeviceKind, SeedDevice, SeedInventory, Snapshot
from infra_agent.store.snapshots import FileSnapshotStore

FIXTURES = Path(__file__).parent / "fixtures" / "guest"
NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)

WEB = "vm:web-01"
DB = "vm:db-01"
WIN = "vm:app-win-01"
NGINX = "service:web-01:nginx"
POSTGRES = "service:db-01:postgresql@14-main"
GUNICORN = "service:db-01:gunicorn"
PG_LISTENER = "listener:db-01:tcp/5432"
APP_LISTENER = "listener:db-01:tcp/8080"
HTTPS_LISTENER = "listener:web-01:tcp/443"


def snapshot_data(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / "snapshots" / f"{name}.json").read_text())


def regenerator() -> Any:
    spec = importlib.util.spec_from_file_location("guest_regenerate", FIXTURES / "regenerate.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ESXI_SNAPSHOT: dict[str, Any] = {
    "host": {"name": "esx-01.lab.local", "version": "8.0.2", "model": "ProLiant DL360 Gen9"},
    "vswitches": [{"name": "vSwitch0", "uplinks": ["vmnic0"], "mtu": 1500}],
    "portgroups": [{"name": "Servers", "vswitch": "vSwitch0", "vlan": 20}],
    "datastores": [{"name": "ds-esx01-local", "type": "VMFS", "capacity_gb": 900, "free_gb": 420}],
    "vms": [
        {
            "name": "mgmt-01",
            "power_state": "poweredOn",
            "tags": ["role:platform"],
            "guest_ips": ["10.10.10.50"],
            "vnics": [
                {
                    "label": "Network adapter 1",
                    "mac": "00:50:56:aa:00:01",
                    "portgroup": "Servers",
                    "connected": True,
                    "ips": ["10.10.10.50"],
                }
            ],
            "disks": [{"label": "Hard disk 1", "datastore": "ds-esx01-local", "size_gb": 80}],
        },
        {
            "name": "web-01",
            "power_state": "poweredOn",
            "annotation": "guest:linux service:nginx",
            "guest_ips": ["10.20.0.11"],
            "vnics": [
                {
                    "label": "Network adapter 1",
                    "mac": "00:50:56:aa:00:02",
                    "portgroup": "Servers",
                    "connected": True,
                    "ips": ["10.20.0.11"],
                }
            ],
            "disks": [{"label": "Hard disk 1", "datastore": "ds-esx01-local", "size_gb": 60}],
        },
        {
            "name": "db-01",
            "power_state": "poweredOn",
            "annotation": "guest:linux",
            "guest_ips": ["10.20.0.31"],
            "vnics": [
                {
                    "label": "Network adapter 1",
                    "mac": "00:50:56:aa:00:03",
                    "portgroup": "Servers",
                    "connected": True,
                    "ips": ["10.20.0.31"],
                }
            ],
            "disks": [{"label": "Hard disk 1", "datastore": "ds-esx01-local", "size_gb": 200}],
        },
        {
            "name": "app-win-01",
            "power_state": "poweredOn",
            "annotation": "guest:windows",
            "guest_ips": ["10.20.0.21"],
            "vnics": [
                {
                    "label": "Network adapter 1",
                    "mac": "00:50:56:aa:00:04",
                    "portgroup": "Servers",
                    "connected": True,
                    "ips": ["10.20.0.21"],
                }
            ],
            "disks": [{"label": "Hard disk 1", "datastore": "ds-esx01-local", "size_gb": 120}],
        },
    ],
    "errors": {},
}

GUESTS: list[tuple[str, DeviceKind, str, list[str]]] = [
    ("web-01", DeviceKind.guest_linux, "10.20.0.11", ["vm:web-01", "service:nginx"]),
    ("db-01", DeviceKind.guest_linux, "10.20.0.31", ["service:postgresql"]),
    ("app-win-01", DeviceKind.guest_windows, "10.20.0.21", ["service:MSSQLSERVER"]),
]


def build_estate(tmp_path: Path, *, guests: list[str] | None = None) -> TopologyGraph:
    """The estate graph with the named guests onboarded (all of them by default)."""
    wanted = {name for name, *_ in GUESTS} if guests is None else set(guests)
    store = FileSnapshotStore(tmp_path / "snapshots")
    store.save(Snapshot(device="esx-01", collector="esxi", taken_at=NOW, data=ESXI_SNAPSHOT))
    devices = [
        SeedDevice(
            name="esx-01",
            kind=DeviceKind.esxi,
            mgmt_ip="10.10.10.21",
            credential_ref="esx-01",
            license="free",
        )
    ]
    for name, kind, ip, tags in GUESTS:
        if name not in wanted:
            continue
        store.save(Snapshot(device=name, collector="guest", taken_at=NOW, data=snapshot_data(name)))
        devices.append(SeedDevice(name=name, kind=kind, mgmt_ip=ip, credential_ref=name, tags=tags))
    settings = Settings(data_dir=tmp_path, seed_inventory=tmp_path / "no-inventory.yaml")
    return GraphBuilder(store, SeedInventory(devices=devices), settings=settings, now=NOW).build()


@pytest.fixture(scope="module")
def graph(tmp_path_factory) -> TopologyGraph:
    return build_estate(tmp_path_factory.mktemp("estate"))


# --------------------------------------------------------------------------
# the fixture is what the collector really produces
# --------------------------------------------------------------------------
def test_the_web_guest_snapshot_matches_the_collector():
    """A graph built from an invented snapshot shape proves nothing."""
    regenerate = regenerator()
    committed = snapshot_data("web-01")
    assert committed == regenerate.build("web-01", now=NOW), (
        "tests/fixtures/guest/snapshots/web-01.json is stale: "
        "run `uv run python tests/fixtures/guest/regenerate.py`"
    )


# --------------------------------------------------------------------------
# who the guest is
# --------------------------------------------------------------------------
def test_a_guest_is_joined_to_its_vm(graph: TopologyGraph):
    """The SSH endpoint and the VM the hypervisor knows are one object."""
    assert graph.has(WEB) and graph.has("device:web-01")
    edge = graph.edge("device:web-01", WEB, EdgeKind.guest_of)
    assert edge is not None and "seed tag vm:web-01" in str(edge["note"])
    assert graph.node(WEB)["guest_device"] == "web-01"
    assert graph.node("device:web-01")["role"] == "guest"
    assert graph.node("device:web-01")["os"] == "Ubuntu 22.04.4 LTS"


def test_a_guest_with_no_vm_tag_is_matched_by_name_and_by_address(graph: TopologyGraph):
    # db-01 carries no vm: tag; the VM has the same name.
    assert graph.edge("device:db-01", DB, EdgeKind.guest_of) is not None
    assert "the VM has the same name" in str(graph.edge("device:db-01", DB, EdgeKind.guest_of))


def test_resolve_owner_falls_back_to_the_hostname_then_the_address_then_itself():
    empty = TopologyGraph()
    empty.add_node("vm:renamed", NodeKind.vm, label="renamed")
    empty.add_node("ip:10.20.0.99", NodeKind.ip, label="10.20.0.99", address="10.20.0.99")
    empty.add_node("vm:by-address", NodeKind.vm, label="by-address")
    empty.g.nodes["ip:10.20.0.99"]["owner_vm"] = "by-address"
    empty.add_node("device:orphan", NodeKind.device, label="orphan")

    device = SeedDevice(
        name="orphan", kind=DeviceKind.guest_linux, mgmt_ip="10.20.0.99", credential_ref="orphan"
    )
    node, how, _confidence = resolve_owner(empty, device, {"os": {"hostname": "renamed.lab"}})
    assert node == "vm:renamed" and "calls itself" in how

    node, how, _confidence = resolve_owner(empty, device, {"os": {}})
    assert node == "vm:by-address" and "belongs to it" in how

    device = device.model_copy(update={"mgmt_ip": "10.99.99.99"})
    node, how, _confidence = resolve_owner(empty, device, {})
    assert node == "device:orphan" and how == "no VM matched this guest"


# --------------------------------------------------------------------------
# services, listeners, certificates
# --------------------------------------------------------------------------
def test_services_and_listeners_hang_off_the_vm(graph: TopologyGraph):
    assert graph.node(NGINX)["kind"] == NodeKind.service
    assert graph.node(NGINX)["tagged"] is True
    assert graph.node(NGINX)["active"] is False  # the unit is loaded but failed
    assert graph.edge(WEB, NGINX, EdgeKind.runs_service) is not None
    assert graph.edge(NGINX, HTTPS_LISTENER, EdgeKind.listens_on) is not None

    listener = graph.node(HTTPS_LISTENER)
    assert listener["port"] == 443 and listener["proto"] == "tcp"
    assert listener["process"] == "nginx" and listener["address"] == "0.0.0.0"

    # The tag `service:postgresql`, the unit `postgresql@14-main.service` and
    # the `postgres` process that owns 5432 are one application, one node.
    unit = "service:web-01:postgresql@14-main"
    assert graph.has(unit)
    assert graph.node(unit)["tag"] == "postgresql"
    assert graph.edge(unit, "listener:web-01:tcp/5432", EdgeKind.listens_on) is not None
    assert not graph.has("service:web-01:postgres")


def test_a_unit_name_is_matched_from_the_process_name():
    services = [{"name": "postgresql@14-main.service"}, {"name": "nginx.service"}]
    assert service_name_for("nginx", services) == "nginx"
    assert service_name_for("postgres", services) == "postgresql@14-main"
    assert service_name_for("postgresql", services) == "postgresql@14-main"
    assert service_name_for("gunicorn", services) == "gunicorn"  # kept as the process
    assert service_name_for(None, services) is None


def test_certificates_become_nodes_with_their_expiry(graph: TopologyGraph):
    node = "certificate:web-01:CN=app.example.com"
    assert graph.has(node)
    data = graph.node(node)
    assert data["not_after"] == "2026-11-01T12:00:00+00:00"
    assert data["days_to_expiry"] == pytest.approx(56.0)
    assert data["sans"] == ["app.example.com", "www.app.example.com"]
    # found on disk *and* served by the listener: one certificate, both sources
    assert data["sources"] == ["/etc/letsencrypt/live/app.example.com/cert.pem", "127.0.0.1:443"]
    assert graph.edge(WEB, node, EdgeKind.has_certificate) is not None
    assert graph.edge(HTTPS_LISTENER, node, EdgeKind.has_certificate) is not None

    legacy = "certificate:web-01:C=GB, O=Example Ltd, CN=legacy.internal"
    assert graph.node(legacy)["sans"] == []


def test_the_windows_guest_lands_in_the_same_shape(graph: TopologyGraph):
    assert graph.edge("device:app-win-01", WIN, EdgeKind.guest_of) is not None
    assert graph.has("service:app-win-01:MSSQLSERVER")
    assert graph.node("service:app-win-01:MSSQLSERVER")["active"] is True
    assert graph.has("listener:app-win-01:tcp/443")
    assert graph.has("certificate:app-win-01:CN=app-win-01.lab.local")


# --------------------------------------------------------------------------
# dependencies
# --------------------------------------------------------------------------
def test_a_connection_to_a_known_listener_becomes_a_dependency_edge(graph: TopologyGraph):
    """web-01's nginx proxies to db-01:8080, and that is the edge."""
    edge = graph.edge(NGINX, APP_LISTENER, EdgeKind.connects_to)
    assert edge is not None
    assert edge["remote_ip"] == "10.20.0.31" and edge["remote_port"] == 8080
    assert edge["process"] == "nginx"


def test_a_connection_from_a_process_with_no_service_hangs_off_the_vm(graph: TopologyGraph):
    """gunicorn on web-01 owns no port and matches no unit, so the dependent is
    the guest itself rather than an invented service."""
    edge = graph.edge(WEB, PG_LISTENER, EdgeKind.connects_to)
    assert edge is not None and edge["process"] == "gunicorn"
    assert edge["connections"] == 2  # two sockets, one dependency
    assert not graph.has("service:web-01:gunicorn")


def test_a_connection_to_a_known_object_whose_port_was_never_collected(graph: TopologyGraph):
    """mgmt-01 has no guest snapshot, so the dependency lands on the VM."""
    edge = graph.edge(WEB, "vm:mgmt-01", EdgeKind.connects_to)
    assert edge is not None and edge["remote_port"] == 8086
    assert "no guest snapshot lists that port" in str(edge["note"])


def test_unknown_remotes_are_grouped_into_external_endpoints(graph: TopologyGraph):
    node = "external_endpoint:203.0.113.0/24"
    assert graph.has(node)
    assert graph.node(node)["ports"] == [443]
    assert graph.node(node)["addresses"] == ["203.0.113.44"]
    assert graph.edge(WEB, node, EdgeKind.connects_to) is not None
    # the Windows guest's own external peer is a different /24
    assert graph.has("external_endpoint:198.51.100.0/24")
    assert len(graph.nodes_of_kind(NodeKind.external_endpoint)) == 2


def test_the_windows_guest_depends_on_the_database(graph: TopologyGraph):
    assert graph.edge(WIN, PG_LISTENER, EdgeKind.connects_to) is not None


def test_dependencies_do_not_depend_on_the_inventory_order(tmp_path: Path):
    """db-01 is ingested after web-01, so the first pass cannot see its ports."""
    graph = build_estate(tmp_path, guests=["web-01", "db-01"])
    assert graph.edge(NGINX, APP_LISTENER, EdgeKind.connects_to) is not None
    # ... and the external endpoint the first pass would have invented is gone
    assert not graph.has("external_endpoint:10.20.0.0/24")


def test_a_guest_whose_peer_is_not_onboarded_keeps_the_dependency_at_the_vm(tmp_path: Path):
    graph = build_estate(tmp_path, guests=["web-01"])
    assert graph.edge(WEB, DB, EdgeKind.connects_to) is not None
    assert not graph.has(PG_LISTENER)


def test_loopback_and_link_local_peers_are_not_dependencies():
    assert is_routable_peer("10.20.0.31") is True
    assert is_routable_peer("127.0.0.1") is False
    assert is_routable_peer("169.254.1.1") is False
    assert is_routable_peer("not-an-ip") is False
    assert external_network("203.0.113.44") == "203.0.113.0/24"
    assert external_network("2001:db8::5") == "2001:db8::/64"
    assert external_network("nope") is None


# --------------------------------------------------------------------------
# impact
# --------------------------------------------------------------------------
def test_impact_of_a_listener_names_the_applications_that_lose_it(graph: TopologyGraph):
    report = impact_analyze(APP_LISTENER, graph)

    assert report.found and report.kind == NodeKind.listener
    services = {row.id: row for row in report.affected_services}
    assert services[NGINX].effect == "loses_dependency"
    assert "db-01 tcp/8080" in services[NGINX].reason
    assert any("loses a dependency" in line for line in report.describe())
    # the port dying does not take the database VM with it
    assert DB not in [obj.id for obj in report.loses_connectivity]


def test_impact_of_a_guest_takes_its_services_down_and_names_its_consumers(graph: TopologyGraph):
    report = impact_analyze(DB, graph)

    failed = {obj.id for obj in report.loses_connectivity}
    assert {POSTGRES, GUNICORN, PG_LISTENER, APP_LISTENER} <= failed
    effects = {row.id: row.effect for row in report.affected_services}
    assert effects[POSTGRES] == "down" and effects[GUNICORN] == "down"
    assert effects[NGINX] == "loses_dependency"
    assert effects[WEB] == "loses_dependency"
    assert effects[WIN] == "loses_dependency"


def test_impact_of_the_host_reaches_the_applications(graph: TopologyGraph):
    """The whole point: a host reboot is answered in applications, not just VMs."""
    report = impact_analyze("device:esx-01", graph)

    down = {row.id for row in report.affected_services if row.effect == "down"}
    assert {NGINX, POSTGRES, GUNICORN} <= down


def test_an_outbound_dependency_is_not_a_hard_dependency(graph: TopologyGraph):
    """mgmt-01 scrapes everything; if that were a dependency every guest change
    would touch the platform's own path and compute as Tier 2."""
    index = DependencyIndex(graph)
    assert (WEB, "upstream") not in index.dependents.get(PG_LISTENER, set())
    report = impact_analyze(PG_LISTENER, graph)
    assert WEB not in {obj.id for obj in report.loses_connectivity}
    assert report.summary.touches_mgmt_path is False


def test_a_service_change_defaults_to_the_tier_zero_restart_action(graph: TopologyGraph):
    assert default_action(graph, NGINX) == "guest.service_restart"
    assert default_action(graph, HTTPS_LISTENER) == "guest.service_restart"


def test_the_graph_survives_a_round_trip_with_the_new_kinds(graph: TopologyGraph, tmp_path: Path):
    path = graph.save(tmp_path / "graph.json")
    reloaded = TopologyGraph.load(path)

    assert reloaded.node(NGINX) == graph.node(NGINX)
    assert reloaded.edge(NGINX, APP_LISTENER, EdgeKind.connects_to) is not None
    summary = reloaded.summary()
    assert summary["nodes_by_kind"]["service"] >= 4
    assert summary["nodes_by_kind"]["listener"] >= 8
    assert summary["edges_by_kind"]["connects_to"] >= 4


def test_the_application_layer_does_not_disturb_the_other_checks(graph: TopologyGraph):
    """A guest device is not a switch with no ports."""
    kinds = {finding.kind for finding in run_checks(graph)}
    assert "collector_parse_gap" not in kinds


# --------------------------------------------------------------------------
# mermaid
# --------------------------------------------------------------------------
def test_the_applications_diagram_draws_guests_ports_and_dependencies(graph: TopologyGraph):
    diagram = render_applications(graph)

    assert diagram.startswith("graph LR")
    assert 'subgraph n_vm_web_01["web-01"]' in diagram
    assert '"tcp/443 nginx"' in diagram
    assert '"nginx"' in diagram
    assert '-->|"8080"|' in diagram
    assert "203.0.113.0/24 (external)" in diagram
    assert "classDef external" in diagram
    assert "tls" in diagram  # the certificate the listener presents
    assert render(graph, "applications") == diagram


def test_the_diagram_shows_the_certificate_nobody_serves_but_everybody_forgets(
    graph: TopologyGraph,
):
    """The expiring one is on disk, not on a port; drawing only served
    certificates would hide exactly the certificate that breaks something."""
    diagram = render_applications(graph)

    legacy = _safe("certificate:web-01:C=GB, O=Example Ltd, CN=legacy.internal")
    assert "CN=legacy.internal (14d)" in diagram
    assert "classDef expiring" in diagram
    styled = [
        line
        for line in diagram.splitlines()
        if line.strip().startswith("class ") and line.rstrip().endswith("expiring;")
    ]
    assert styled and legacy in styled[0]
    # ... and the healthy one, which a port does serve, is drawn without the alarm
    served = _safe("certificate:web-01:CN=app.example.com")
    assert f"{served}[/" in diagram
    assert served not in styled[0]


def test_the_windows_kernel_is_not_an_application(graph: TopologyGraph):
    """`System` owns 443 on a Windows box; it is not a service anybody restarts."""
    assert not graph.has("service:app-win-01:System")
    assert graph.has("listener:app-win-01:tcp/443")
    assert graph.edge(WIN, "listener:app-win-01:tcp/443", EdgeKind.listens_on) is not None


def test_a_dependency_on_an_uncollected_port_of_a_collected_guest_draws_once(tmp_path: Path):
    """The target is a subgraph; declaring it as a node too is a broken diagram."""
    graph = build_estate(tmp_path, guests=["web-01", "db-01"])
    # db-01 answers on 5432 and 8080; nothing lists 8086, and mgmt-01 is the
    # peer there, so aim a dependency at db-01 on a port nobody collected.
    graph.add_edge(
        NGINX,
        DB,
        EdgeKind.connects_to,
        Evidence(collector="guest", device="web-01"),
        remote_port=9999,
    )
    diagram = render_applications(graph)

    declarations = [
        line for line in diagram.splitlines() if line.strip().startswith(f"{_safe(DB)}[")
    ]
    assert declarations == []
    assert f'subgraph {_safe(DB)}["db-01"]' in diagram
    assert f'{_safe(NGINX)} -->|"9999"| {_safe(DB)}' in diagram


def test_an_estate_with_no_guests_renders_an_empty_applications_diagram():
    assert "No guest snapshots" in render_applications(TopologyGraph())


def test_write_docs_adds_the_applications_page(graph: TopologyGraph, tmp_path: Path):
    written = write_docs(graph, tmp_path / "topology")
    names = {path.name for path in written}

    assert "applications.md" in names
    index = (tmp_path / "topology" / "index.md").read_text()
    assert "[applications.md](applications.md)" in index
    assert "```mermaid" in (tmp_path / "topology" / "applications.md").read_text()


def test_write_docs_skips_the_page_when_no_guest_was_collected(tmp_path: Path):
    written = write_docs(TopologyGraph(), tmp_path / "topology")
    assert "applications.md" not in {path.name for path in written}
    assert "applications.md" not in (tmp_path / "topology" / "index.md").read_text()
