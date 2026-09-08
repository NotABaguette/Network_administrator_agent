"""The application layer of the graph, built from guest snapshots.

The network layers answer "what is plugged into what". This one answers the
question the owner actually asks during an outage: *which applications stop
working if this VM, this port or this switch dies?*

Nodes (all derived from parsed rows in `infra_agent/collectors/guest.py`):

* `service:<guest>:<name>` - something the guest runs: a unit it was tagged
  with, or the process that owns a listening socket.
* `listener:<guest>:<proto>/<port>` - a port that answers, with the process.
* `certificate:<guest>:<subject>` - a certificate the guest serves or stores,
  with its expiry.
* `external_endpoint:<network>` - everything outside the estate a guest talks
  to, grouped by /24 (or /64), so a busy web server does not add a node per
  address it ever contacted.

Edges:

    device --guest_of--> vm                (the SSH/WinRM endpoint *is* that VM)
    vm     --runs_service--> service
    service --listens_on--> listener
    service|vm --connects_to--> listener|device|external_endpoint

`connects_to` is the dependency edge: an established outbound connection whose
remote address belongs to something the graph already knows becomes an edge to
that object's listener (or to the object itself when the port was never
collected), and everything else becomes an external endpoint. Direction is
dependent -> provider, like the rest of the graph.

Two things this module deliberately does *not* do:

* It does not make an outbound connection a hard dependency in the tier engine.
  Prometheus on mgmt-01 connects to every exporter in the estate; if that were
  a dependency, every guest port change would touch the platform's own path and
  compute as Tier 2, and Tier 2 would stop meaning anything. Consumers are
  reported by `impact_analyze` as *affected services* instead
  (`infra_agent/correlate/impact.py`).
* It does not trust the guest to say which VM it is. The mapping is resolved
  from the seed tag, the VM name, the guest's hostname and finally its IP.

The builder calls `ingest_guest` once per guest device. Because a guest can be
ingested before the guest it talks to, the whole application layer is rebuilt
from every guest seen so far on each call; the passes are idempotent.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable, Mapping, Sequence
from typing import TYPE_CHECKING, Any

from infra_agent.correlate.model import (
    EdgeKind,
    Evidence,
    NodeKind,
    TopologyGraph,
    certificate_id,
    device_id,
    external_endpoint_id,
    ip_id,
    listener_id,
    service_id,
    vm_id,
)
from infra_agent.correlate.parsing import short_hostname
from infra_agent.models.common import SeedDevice, Snapshot

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to type checkers
    from infra_agent.correlate.builder import GraphBuilder

log = logging.getLogger(__name__)

#: Where the guest layer parks the snapshots it has been handed, on the builder.
_STATE_ATTR = "_guest_layer"

#: A tag on the seed device that names the VM the guest runs in.
VM_TAG_PREFIX = "vm:"

#: Remote addresses that are never a dependency on somebody else.
_SKIP_REMOTE_KINDS = ("loopback", "link_local", "unspecified", "multicast")

#: How many ports an external endpoint node lists before it just counts them.
MAX_EXTERNAL_PORTS = 12

#: Process names that own a socket without being an application: the Windows
#: kernel answers on 445 and on every port an HTTP.sys service registers.
NOT_A_SERVICE = frozenset({"system", "idle", "kernel_task", "-"})

CONFIDENCE_TAG = 1.0
CONFIDENCE_NAME = 0.95
CONFIDENCE_ADDRESS = 0.9
CONFIDENCE_SNAPSHOT = 0.95


# ---------------------------------------------------------------------------
# small pure helpers
# ---------------------------------------------------------------------------
def external_network(address: str) -> str | None:
    """The /24 (or /64) an address belongs to, or None if it is not an address."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    prefix = 24 if parsed.version == 4 else 64
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def is_routable_peer(address: str) -> bool:
    """Loopback, link-local and multicast peers are not dependencies."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (
        parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_unspecified
    )


def service_name_for(name: str | None, services: Sequence[Mapping[str, Any]]) -> str | None:
    """The canonical service name for a process or a tag.

    `nginx` is `nginx.service` and `postgres` is `postgresql@14-main.service`:
    the unit name is a hint, not a key, so the join is best-effort - exact stem,
    then the instance base before the `@`, then a unit whose base begins with
    the name. Its only job is that the same application on the same guest always
    lands on the same node, whether it was reached through a tag, a listening
    socket or an outbound connection. Nothing matched keeps the name as given.
    """
    if not name:
        return None
    lowered = name.strip().lower()
    if not lowered or lowered in NOT_A_SERVICE:
        return None
    stems = [str(row.get("name") or "").removesuffix(".service") for row in services]
    for stem in stems:
        if stem.lower() == lowered:
            return stem
    for stem in stems:
        if stem.lower().split("@")[0] == lowered:
            return stem
    for stem in sorted(stems):
        if stem.lower().split("@")[0].startswith(lowered):
            return stem
    return name.strip()


def _rows(value: Any) -> list[dict[str, Any]]:
    return [row for row in (value or []) if isinstance(row, dict)]


def _label_of(graph: TopologyGraph, node: str) -> str:
    return str(graph.node(node).get("label", node)) if node in graph else node


# ---------------------------------------------------------------------------
# who the guest is
# ---------------------------------------------------------------------------
def resolve_owner(
    graph: TopologyGraph, device: SeedDevice, data: Mapping[str, Any]
) -> tuple[str, str, float]:
    """The graph node this guest *is*: (node id, how it was matched, confidence).

    A guest is onboarded as a device with its own credential, but in the graph
    it is usually a VM that the ESXi collector already found. Matching them is
    what turns "web-01 the SSH endpoint" and "web-01 the VM on esx-01" into one
    object, so an impact analysis on the ESXi host reaches the applications.
    """
    for tag in device.tags:
        if str(tag).lower().startswith(VM_TAG_PREFIX):
            candidate = vm_id(str(tag).split(":", 1)[1].strip())
            if candidate in graph:
                return candidate, f"seed tag {tag}", CONFIDENCE_TAG
    if vm_id(device.name) in graph:
        return vm_id(device.name), "the VM has the same name", CONFIDENCE_NAME
    hostname = short_hostname(str((data.get("os") or {}).get("hostname") or ""))
    if hostname:
        for node in graph.nodes_of_kind(NodeKind.vm):
            if str(graph.node(node).get("label", "")).lower() == hostname.lower():
                return node, f"the guest calls itself {hostname}", CONFIDENCE_NAME
    owner = _owner_of_address(graph, device.mgmt_ip)
    if owner is not None:
        return owner, f"{device.mgmt_ip} belongs to it", CONFIDENCE_ADDRESS
    return device_id(device.name), "no VM matched this guest", CONFIDENCE_ADDRESS


def _owner_of_address(graph: TopologyGraph, address: str) -> str | None:
    """The vm or device node that owns an IP, from the L3 layer."""
    node = ip_id(address)
    if node not in graph:
        return None
    data = graph.node(node)
    owner_vm = data.get("owner_vm")
    if owner_vm and vm_id(str(owner_vm)) in graph:
        return vm_id(str(owner_vm))
    owner_device = data.get("owner_device")
    if owner_device and device_id(str(owner_device)) in graph:
        return device_id(str(owner_device))
    for source, _edge in graph.in_edges(node, EdgeKind.has_ip):
        holder = graph.node(source)
        if holder.get("vm") and vm_id(str(holder["vm"])) in graph:
            return vm_id(str(holder["vm"]))
        if holder.get("device") and device_id(str(holder["device"])) in graph:
            return device_id(str(holder["device"]))
    return None


# ---------------------------------------------------------------------------
# the hook the builder calls
# ---------------------------------------------------------------------------
def ingest_guest(builder: GraphBuilder, device: SeedDevice, snapshot: Snapshot) -> None:
    """Add one guest's applications to the graph and re-resolve the layer.

    This is the whole hook `infra_agent/correlate/builder.py` calls. The layer
    is rebuilt from every guest handed over so far, because guest A's dependency
    on guest B's port can only be resolved once B has been ingested, and the
    seed inventory is in whatever order `infra onboard` wrote it.
    """
    seen: list[tuple[SeedDevice, Snapshot]] = getattr(builder, _STATE_ATTR, [])
    seen = [entry for entry in seen if entry[0].name != device.name]
    seen.append((device, snapshot))
    setattr(builder, _STATE_ATTR, seen)
    build_application_layer(builder, seen)


def build_application_layer(
    builder: GraphBuilder, guests: Sequence[tuple[SeedDevice, Snapshot]]
) -> None:
    """(Re)build services, listeners, certificates and dependencies for `guests`."""
    graph = builder.graph
    _clear_resolved_dependencies(graph)
    owners: dict[str, str] = {}
    for device, snapshot in guests:
        try:
            owners[device.name] = _ingest_one(builder, device, snapshot)
        except Exception:  # a bad guest snapshot must not lose the whole graph
            log.exception("failed to ingest the guest snapshot for %s", device.name)
    index = _address_index(graph, guests, owners)
    for device, snapshot in guests:
        owner = owners.get(device.name)
        if owner is None:
            continue
        try:
            _resolve_dependencies(builder, device, snapshot, owner, index)
        except Exception:
            log.exception("failed to resolve the dependencies of %s", device.name)


def _clear_resolved_dependencies(graph: TopologyGraph) -> None:
    """Drop what a previous pass resolved, so re-running cannot leave a ghost.

    Guest A ingested before guest B has no way to know B's ports yet, so the
    first pass records A -> external endpoint; once B arrives the same edge has
    to become A -> B's listener rather than sit next to it.
    """
    for source, target, key in list(graph.g.edges(keys=True)):
        if key == str(EdgeKind.connects_to):
            graph.g.remove_edge(source, target, key=key)
    for node in [
        n
        for n, data in graph.g.nodes(data=True)
        if data.get("kind") == str(NodeKind.external_endpoint)
    ]:
        graph.g.remove_node(node)


def _ingest_one(builder: GraphBuilder, device: SeedDevice, snapshot: Snapshot) -> str:
    """Nodes and edges that need only this guest. Returns the owner node."""
    graph = builder.graph
    data = snapshot.data
    evidence = builder._evidence("guest", device.name, snapshot, confidence=CONFIDENCE_SNAPSHOT)
    owner, how, confidence = resolve_owner(graph, device, data)
    label = _label_of(graph, owner)

    guest_node = device_id(device.name)
    if guest_node in graph:
        os_info = data.get("os") or {}
        graph.add_node(
            guest_node,
            NodeKind.device,
            role="guest",
            os=os_info.get("pretty_name") or os_info.get("name"),
            os_version=os_info.get("version"),
            hostname=os_info.get("hostname"),
        )
        if owner != guest_node:
            graph.add_edge(
                guest_node,
                owner,
                EdgeKind.guest_of,
                evidence.model_copy(update={"confidence": confidence, "note": how}),
            )
    if owner in graph:
        graph.add_node(owner, graph.node(owner).get("kind", NodeKind.vm), guest_device=device.name)

    services = _rows(data.get("services"))
    listeners = _rows(data.get("listeners"))
    service_nodes: dict[str, str] = {}

    for row in _rows(data.get("tagged_services")):
        tag = str(row.get("service") or "")
        if not tag:
            continue
        # The unit the collector resolved is the canonical name, so the tagged
        # service and the process that owns its port are one node.
        name = str(row.get("unit") or "").removesuffix(".service") or tag
        service_nodes[name.lower()] = _service_node(
            graph, owner, label, name, evidence, tagged=True, row=row, tag=tag
        )

    for row in listeners:
        port = row.get("port")
        proto = str(row.get("proto") or "tcp")
        if port is None:
            continue
        listener_node = graph.add_node(
            listener_id(label, proto, int(port)),
            NodeKind.listener,
            label=f"{label} {proto}/{port}",
            guest=label,
            proto=proto,
            port=int(port),
            address=row.get("address"),
            process=row.get("process"),
        )
        name = service_name_for(row.get("process"), services)
        if name:
            key = name.lower()
            node = service_nodes.get(key) or _service_node(
                graph, owner, label, name, evidence, tagged=False, row=_unit_row(name, services)
            )
            service_nodes[key] = node
            graph.add_edge(node, listener_node, EdgeKind.listens_on, evidence)
        else:
            # A port whose owner we could not read (no sudo) still exists.
            graph.add_edge(owner, listener_node, EdgeKind.listens_on, evidence)

    _ingest_certificates(graph, owner, label, data, evidence)
    return owner


def _unit_row(name: str, services: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
    for row in services:
        if str(row.get("name") or "").removesuffix(".service").lower() == name.lower():
            return row
    return {}


def _service_node(
    graph: TopologyGraph,
    owner: str,
    label: str,
    name: str,
    evidence: Evidence,
    *,
    tagged: bool,
    row: Mapping[str, Any],
    tag: str | None = None,
) -> str:
    active = row.get("active")
    node = graph.add_node(
        service_id(label, name),
        NodeKind.service,
        label=f"{label} {name}",
        guest=label,
        service=name,
        tag=tag,
        unit=row.get("unit") or row.get("name"),
        tagged=tagged or None,
        state=row.get("state") or (active if isinstance(active, str) else None),
        active=active if isinstance(active, bool) else _active_from_state(active),
    )
    graph.add_edge(owner, node, EdgeKind.runs_service, evidence)
    return node


def _active_from_state(value: Any) -> bool | None:
    if not isinstance(value, str) or not value:
        return None
    return value.strip().lower() in {"active", "running"}


def _ingest_certificates(
    graph: TopologyGraph,
    owner: str,
    label: str,
    data: Mapping[str, Any],
    evidence: Evidence,
) -> None:
    """One node per certificate, joined to the port that serves it.

    A certificate found on disk and the same certificate served by a listener
    are one object: they share a subject, so they share a node and the graph
    says both where it lives and what presents it.
    """
    for row in _rows(data.get("certificates")):
        subject = str(row.get("subject") or "").strip()
        if not subject:
            continue
        node = graph.add_node(
            certificate_id(label, subject),
            NodeKind.certificate,
            label=subject,
            guest=label,
            subject=subject,
            issuer=row.get("issuer"),
            not_after=row.get("not_after"),
            days_to_expiry=row.get("days_to_expiry"),
            sans=list(row.get("sans") or []),
        )
        sources = list(graph.node(node).get("sources") or [])
        source = str(row.get("source") or "")
        if source and source not in sources:
            sources.append(source)
        graph.add_node(node, NodeKind.certificate, sources=sorted(sources))
        graph.add_edge(owner, node, EdgeKind.has_certificate, evidence)
        port = row.get("port")
        if port is None:
            continue
        listener_node = listener_id(label, "tcp", int(port))
        if listener_node in graph:
            graph.add_edge(listener_node, node, EdgeKind.has_certificate, evidence)


# ---------------------------------------------------------------------------
# dependencies
# ---------------------------------------------------------------------------
def _address_index(
    graph: TopologyGraph,
    guests: Sequence[tuple[SeedDevice, Snapshot]],
    owners: Mapping[str, str],
) -> dict[str, str]:
    """address -> the node that answers on it.

    Built from the L3 layer the other collectors produced (guest IPs, ARP, DHCP
    leases, VMkernel and interface addresses) plus each guest's own management
    address, so a dependency resolves even when nothing else in the estate has
    seen that VM's traffic yet.
    """
    index: dict[str, str] = {}
    for node in graph.nodes_of_kind(NodeKind.ip):
        address = str(graph.node(node).get("address") or "")
        owner = _owner_of_address(graph, address) if address else None
        if address and owner is not None:
            index.setdefault(address, owner)
    for device, _snapshot in guests:
        owner = owners.get(device.name)
        if owner is not None:
            index[device.mgmt_ip] = owner
    return index


def _resolve_dependencies(
    builder: GraphBuilder,
    device: SeedDevice,
    snapshot: Snapshot,
    owner: str,
    index: Mapping[str, str],
) -> None:
    graph = builder.graph
    label = _label_of(graph, owner)
    evidence = builder._evidence("guest", device.name, snapshot, confidence=CONFIDENCE_SNAPSHOT)
    services = _rows(snapshot.data.get("services"))
    externals: dict[str, dict[str, Any]] = {}

    for row in _rows(snapshot.data.get("connections")):
        remote_ip = str(row.get("remote_ip") or "")
        remote_port = row.get("remote_port")
        if not remote_ip or remote_port is None or not is_routable_peer(remote_ip):
            continue
        source = _dependency_source(graph, owner, label, row, services)
        target, note = _dependency_target(graph, index, remote_ip, int(remote_port))
        if target is None:
            _record_external(externals, remote_ip, int(remote_port))
            continue
        if target == source or target == owner:
            continue  # a guest talking to itself is not a dependency
        graph.add_edge(
            source,
            target,
            EdgeKind.connects_to,
            evidence.model_copy(update={"note": note}),
            process=row.get("process"),
            remote_ip=remote_ip,
            remote_port=int(remote_port),
            connections=row.get("connections"),
        )

    for network, info in sorted(externals.items()):
        node = graph.add_node(
            external_endpoint_id(network),
            NodeKind.external_endpoint,
            label=f"{network} (external)",
            network=network,
            addresses=sorted(info["addresses"])[:MAX_EXTERNAL_PORTS],
            ports=sorted(info["ports"])[:MAX_EXTERNAL_PORTS],
        )
        graph.add_edge(
            owner,
            node,
            EdgeKind.connects_to,
            evidence.model_copy(update={"note": "outbound to an address outside the estate"}),
            ports=sorted(info["ports"])[:MAX_EXTERNAL_PORTS],
        )


def _dependency_source(
    graph: TopologyGraph,
    owner: str,
    label: str,
    row: Mapping[str, Any],
    services: Sequence[Mapping[str, Any]],
) -> str:
    """(vm, process) -> the service node when there is one, else the guest."""
    name = service_name_for(row.get("process"), services)
    if not name:
        return owner
    node = service_id(label, name)
    return node if node in graph else owner


def _dependency_target(
    graph: TopologyGraph, index: Mapping[str, str], remote_ip: str, remote_port: int
) -> tuple[str | None, str]:
    """The listener the connection lands on, the object that owns it, or None."""
    owner = index.get(remote_ip)
    if owner is None:
        return None, ""
    label = _label_of(graph, owner)
    for proto in ("tcp", "udp"):
        candidate = listener_id(label, proto, remote_port)
        if candidate in graph:
            return candidate, f"established connection to {remote_ip}:{remote_port}"
    return owner, (
        f"established connection to {remote_ip}:{remote_port}; "
        "no guest snapshot lists that port, so the dependency is on the object itself"
    )


def _record_external(
    externals: dict[str, dict[str, Any]], remote_ip: str, remote_port: int
) -> None:
    network = external_network(remote_ip)
    if network is None:
        return
    info = externals.setdefault(network, {"addresses": set(), "ports": set()})
    info["addresses"].add(remote_ip)
    info["ports"].add(remote_port)


# ---------------------------------------------------------------------------
# read helpers used by the tools and the duty
# ---------------------------------------------------------------------------
def services_of(graph: TopologyGraph, node: str) -> list[str]:
    """Service nodes a vm or device runs."""
    return sorted(target for target, _e in graph.out_edges(node, EdgeKind.runs_service))


def consumers_of(graph: TopologyGraph, node: str) -> list[str]:
    """Everything that has an established dependency on this object."""
    return sorted(source for source, _e in graph.in_edges(node, EdgeKind.connects_to))


def expiring_certificate_nodes(
    graph: TopologyGraph, within_days: float = 30.0
) -> list[dict[str, Any]]:
    """Certificate nodes whose recorded expiry is inside `within_days`."""
    rows: list[dict[str, Any]] = []
    for node in graph.nodes_of_kind(NodeKind.certificate):
        data = graph.node(node)
        days = data.get("days_to_expiry")
        if isinstance(days, (int, float)) and days <= within_days:
            rows.append({"id": node, **{k: data[k] for k in ("guest", "subject", "not_after")}})
    return sorted(rows, key=lambda row: str(row["id"]))


def guest_nodes(graph: TopologyGraph) -> Iterable[str]:
    """Every vm or device a guest snapshot was attached to."""
    return sorted(n for n, d in graph.g.nodes(data=True) if d.get("guest_device"))
