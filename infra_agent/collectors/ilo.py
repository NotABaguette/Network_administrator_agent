"""HPE iLO collector over Redfish (read-only account).

Plain `requests` against `/redfish/v1` rather than the `redfish` library: the
surface used here is small, the shape differences between generations have to
be handled explicitly anyway, and a `requests.Session` makes the one thing that
really matters easy — **one login per run**. iLO4 counts every Basic-auth
request as a session and runs out of them, so the collector opens a Redfish
session once, reuses the `X-Auth-Token` for every GET, and deletes the session
at the end. Basic auth is only the fallback when session login is refused.

Generation differences the code absorbs:

* iLO4 puts its extensions under `Oem/Hp`, iLO5 and iLO6 under `Oem/Hpe`.
* Smart Array lives under `Systems/1/SmartStorage/...` on both. The array
  controller links its drives as `Links/PhysicalDrives` (whose URL segment is
  `DiskDrives`), and iLO4 repeats the same link in a legacy lowercase `links`
  block with a `/rest/v1` `href`. iLO5/6 also publish the standard
  `Systems/1/Storage` collection, used when SmartStorage yields no drives.
* iLO4 collections carry the same members twice, as Redfish `Members` and as
  RIS `links.Member`; they are de-duplicated so nothing is fetched or stored
  twice on the slowest, session-limited box in the estate (ADR 0004).
* iLO4 firmware is a single `Current` document, iLO5+ a proper
  `UpdateService/FirmwareInventory` collection.
* iLO4 spells fan readings `FanName`/`CurrentReading`/`Units`, iLO5+
  `Name`/`Reading`/`ReadingUnits`.

Every endpoint is fetched independently: a device that does not publish one
records the reason in `data["errors"]` and the rest of the run still lands.

`interval_seconds` is 300 because iLO4 is slow and session-limited. The
scheduler currently runs every collector at the shortest interval of all of
them, so that declaration is nominal until it grows one job per collector
kind; keep the endpoint count per run low regardless.
"""

from __future__ import annotations

import logging
import re
import warnings
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any, Protocol

import requests
from pydantic import SecretStr

from infra_agent.collectors.base import Collector, register
from infra_agent.models.common import Credential, DeviceKind, SeedDevice
from infra_agent.monitoring import metrics

log = logging.getLogger(__name__)

MIB = 1024 * 1024

ROOT_PATH = "/redfish/v1/"
SYSTEM_PATH = "/redfish/v1/Systems/1"
MANAGER_PATH = "/redfish/v1/Managers/1"
CHASSIS_PATH = "/redfish/v1/Chassis/1"
THERMAL_PATH = "/redfish/v1/Chassis/1/Thermal"
POWER_PATH = "/redfish/v1/Chassis/1/Power"
PROCESSORS_PATH = "/redfish/v1/Systems/1/Processors/"
MEMORY_PATH = "/redfish/v1/Systems/1/Memory/"
ETHERNET_PATH = "/redfish/v1/Systems/1/EthernetInterfaces/"
SMART_STORAGE_PATH = "/redfish/v1/Systems/1/SmartStorage/"
LOG_SERVICES_PATH = "/redfish/v1/Systems/1/LogServices/"
FIRMWARE_PATHS = (
    "/redfish/v1/UpdateService/FirmwareInventory/",  # iLO5 / iLO6
    "/redfish/v1/Systems/1/FirmwareInventory/",  # iLO4
)
SESSIONS_PATH = "/redfish/v1/SessionService/Sessions"

#: The IML is long-lived; only the tail is interesting and each entry may be a
#: separate GET on a box that is slow to begin with.
IML_MAX_ENTRIES = 25

#: Anything not in here is treated as a fault worth surfacing.
BENIGN_SEVERITIES = {"ok", "informational", "info", "normal"}

HEALTH_VALUES: dict[str, float] = {
    "ok": metrics.HEALTH_OK,
    "enabled": metrics.HEALTH_OK,
    "good": metrics.HEALTH_OK,
    "goodinuse": metrics.HEALTH_OK,
    "redundant": metrics.HEALTH_OK,
    "ready": metrics.HEALTH_OK,
    "warning": metrics.HEALTH_WARNING,
    "degraded": metrics.HEALTH_WARNING,
    "notredundant": metrics.HEALTH_WARNING,
    "other": metrics.HEALTH_WARNING,
    "critical": metrics.HEALTH_CRITICAL,
    "failed": metrics.HEALTH_CRITICAL,
    "fault": metrics.HEALTH_CRITICAL,
}


#: Gauges that belong to one collection section. When that section failed this
#: run its rows mean "not collected", not "gone", so its series survive the
#: sweep that clears the objects which really disappeared.
SECTION_GAUGES: tuple[tuple[tuple[str, ...], tuple[Any, ...]], ...] = (
    (("system",), (metrics.ILO_HEALTH_ROLLUP,)),
    (
        ("thermal",),
        (
            metrics.ILO_TEMPERATURE_CELSIUS,
            metrics.ILO_TEMPERATURE_CRITICAL_CELSIUS,
            metrics.ILO_FAN_PERCENT,
            metrics.ILO_FAN_HEALTH,
        ),
    ),
    (
        ("power",),
        (metrics.ILO_PSU_HEALTH, metrics.ILO_PSU_OUTPUT_WATTS, metrics.ILO_POWER_CONSUMED_WATTS),
    ),
    (
        # both storage trees: SmartStorage keys and the standard Storage keys
        (
            "smart_storage",
            "storage",
            "array_controllers",
            "disk_drives",
            "logical_drives",
            "drives",
            "volumes",
        ),
        (
            metrics.ILO_DRIVE_HEALTH,
            metrics.ILO_LOGICAL_DRIVE_HEALTH,
            metrics.ILO_CONTROLLER_HEALTH,
        ),
    ),
)

#: Label tuples published per device, so a drive pulled for RMA loses its series.
_SERIES = metrics.DeviceSeries()


class RedfishError(RuntimeError):
    """One Redfish GET failed. Callers degrade instead of losing the run."""


@contextmanager
def quiet_tls_warnings() -> Iterator[None]:
    """Silence urllib3's InsecureRequestWarning for one request.

    Certificate pinning needs a fingerprint recorded per device at onboarding,
    which does not exist yet, so `verify=False` is still the transport default.
    A global `urllib3.disable_warnings()` would hide that everywhere in the
    process; scoping it here keeps the warning meaningful for anything else
    while not printing one line per GET on every poll.
    """
    with warnings.catch_warnings():
        try:
            from urllib3.exceptions import InsecureRequestWarning

            warnings.simplefilter("ignore", InsecureRequestWarning)
        except ImportError:  # pragma: no cover - urllib3 ships with requests
            pass
        yield


class RedfishClient(Protocol):
    """What the collector needs from a transport (a fake satisfies this in tests)."""

    def get(self, path: str) -> dict[str, Any]: ...

    def close(self) -> None: ...


class RedfishSession:
    """One authenticated Redfish session, reused for every GET of a run."""

    def __init__(
        self,
        base_url: str,
        username: str | None,
        password: SecretStr | None,
        *,
        verify: bool = False,
        timeout: int = 20,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._username = username or ""
        self._password = password
        self._http = requests.Session()
        self._http.verify = verify  # certificate pinning lands with the executors
        self._session_uri: str | None = None

    def _secret(self) -> str:
        return self._password.get_secret_value() if self._password else ""

    def open(self) -> RedfishSession:
        """Log in once. Falls back to Basic auth when SessionService refuses."""
        try:
            with quiet_tls_warnings():
                response = self._http.post(
                    f"{self.base_url}{SESSIONS_PATH}",
                    json={"UserName": self._username, "Password": self._secret()},
                    timeout=self.timeout,
                )
            token = response.headers.get("X-Auth-Token")
            if response.status_code in (200, 201) and token:
                self._http.headers["X-Auth-Token"] = token
                self._session_uri = response.headers.get("Location")
                return self
            log.debug("redfish session login refused (%s); using basic auth", response.status_code)
        except requests.RequestException as exc:
            log.debug("redfish session login failed (%s); using basic auth", exc)
        self._http.auth = (self._username, self._secret())
        return self

    def url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{self.base_url}{path if path.startswith('/') else '/' + path}"

    def get(self, path: str) -> dict[str, Any]:
        try:
            with quiet_tls_warnings():
                response = self._http.get(self.url(path), timeout=self.timeout)
            response.raise_for_status()
            body = response.json()
        except requests.RequestException as exc:
            raise RedfishError(f"GET {path}: {type(exc).__name__}") from exc
        except ValueError as exc:
            raise RedfishError(f"GET {path}: response was not JSON") from exc
        if not isinstance(body, dict):
            raise RedfishError(f"GET {path}: expected an object")
        return body

    def close(self) -> None:
        if self._session_uri:
            try:
                with quiet_tls_warnings():
                    self._http.delete(self.url(self._session_uri), timeout=self.timeout)
            except requests.RequestException as exc:
                log.debug("could not delete the redfish session: %s", exc)
            self._session_uri = None
        self._http.close()


# --------------------------------------------------------------------------
# shape helpers (unit-tested directly)
# --------------------------------------------------------------------------
def _nav(doc: Any, *keys: str) -> Any:
    current = doc
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _ref(node: Any) -> str | None:
    """The `@odata.id` (or legacy `href`) of a Redfish link."""
    if isinstance(node, dict):
        value = node.get("@odata.id") or node.get("href")
        return value if isinstance(value, str) else None
    return None


def redfish_path(reference: str | None) -> str | None:
    """A link in the spelling this collector fetches.

    iLO4 publishes the same resource under two roots: the Redfish `@odata.id`
    (`/redfish/v1/...`) and the legacy RIS `href` (`/rest/v1/...`). Both are
    served by the same firmware, so a legacy href is rewritten rather than
    fetched as if it were a second resource.
    """
    if not reference:
        return None
    if reference.startswith("/rest/v1/"):
        return "/redfish/v1/" + reference[len("/rest/v1/") :]
    return reference


def reference_key(reference: str | None) -> str | None:
    """Identity of a link, independent of spelling and of the trailing slash."""
    path = redfish_path(reference)
    return path.rstrip("/") if path else None


def path_id(reference: str | None) -> str | None:
    """Last segment of a link: `.../DiskDrives/1/` -> `1`, the drive's `Id`."""
    key = reference_key(reference)
    if not key:
        return None
    return key.rsplit("/", 1)[-1] or None


def linked(doc: Any, *names: str) -> str | None:
    """Resolve a named link wherever this generation keeps it.

    iLO5/6 use `Links/<Name>` with an `@odata.id`, iLO4 carries both that and a
    lowercase `links/<Name>` with a `/rest/v1` `href`, and a few resources hang
    the collection straight off the document.
    """
    for name in names:
        for node in (_nav(doc, "Links", name), _nav(doc, "links", name), _nav(doc, name)):
            reference = redfish_path(_ref(node))
            if reference:
                return reference
    return None


def oem(doc: Any) -> dict[str, Any]:
    """The HPE OEM block, whichever spelling this generation uses."""
    block = _nav(doc, "Oem") or {}
    for vendor in ("Hpe", "Hp"):
        if isinstance(block.get(vendor), dict):
            return block[vendor]
    return {}


def oem_vendor(doc: Any) -> str | None:
    block = _nav(doc, "Oem") or {}
    for vendor in ("Hpe", "Hp"):
        if isinstance(block.get(vendor), dict):
            return vendor
    return None


def ilo_generation(manager: dict[str, Any], system: dict[str, Any]) -> str:
    """`iLO4`, `iLO5`, `iLO6`... from the manager, OEM spelling as the fallback."""
    for candidate in (manager.get("Model"), manager.get("FirmwareVersion"), manager.get("Name")):
        match = re.search(r"iLO\s*(\d+)", str(candidate or ""), re.I)
        if match:
            return f"iLO{match.group(1)}"
    return "iLO5" if oem_vendor(system) == "Hpe" else "iLO4"


def health_value(health: Any) -> float | None:
    """1 OK, 0.5 warning/degraded, 0 critical/failed; None when not reported."""
    if health is None:
        return None
    return HEALTH_VALUES.get(str(health).strip().replace(" ", "").lower())


def status_row(status: Any) -> dict[str, Any]:
    block = status if isinstance(status, dict) else {}
    rollup = block.get("HealthRollup") or block.get("HealthRollUp")
    return {
        "health": block.get("Health") or rollup,
        "rollup": rollup,
        "state": block.get("State"),
    }


#: One member of a collection: either the expanded document or a link to fetch.
Member = tuple[dict[str, Any] | None, str | None]


def collection_members(doc: Any) -> list[Member]:
    """Ordered members of a Redfish collection, de-duplicated across spellings.

    iLO uses `Members`, older firmware `Items` or `links.Member`, and it
    inlines some collections instead of linking to them (log entries are
    `Items` on iLO4 and expanded `Members` on iLO5). A real iLO4 collection
    carries the same members *twice*, once as Redfish `Members` and once as RIS
    `links.Member`; without de-duplication every DIMM, CPU, NIC, drive and IML
    entry would be fetched twice over `/rest/v1` and stored twice.

    Members keep document order (the IML cap wants the recent tail), the first
    spelling wins, and an expanded member always beats a bare link to itself.
    """
    order: list[str] = []
    best: dict[str, Member] = {}
    groups = (
        _nav(doc, "Members"),
        _nav(doc, "Items"),
        _nav(doc, "links", "Member"),
        _nav(doc, "Links", "Member"),
    )
    for group in groups:
        if not isinstance(group, list):
            continue
        for entry in group:
            if not isinstance(entry, dict):
                continue
            payload = {k: v for k, v in entry.items() if not k.startswith("@") and k != "href"}
            reference = _ref(entry)
            candidate: Member = (entry, None) if payload else (None, redfish_path(reference))
            if candidate == (None, None):
                continue
            key = reference_key(reference) or f"#{payload.get('Id') or repr(payload)[:200]}"
            if key not in best:
                order.append(key)
                best[key] = candidate
            elif payload and best[key][0] is None:
                best[key] = candidate  # an expanded member replaces the link to it
    return [best[key] for key in order]


def collection_entries(doc: Any) -> tuple[list[dict[str, Any]], list[str]]:
    """`collection_members` split into expanded members and links still to fetch."""
    members = collection_members(doc)
    inline = [entry for entry, _ in members if entry is not None]
    links = [reference for entry, reference in members if entry is None and reference]
    return inline, links


def version_string(value: Any) -> str | None:
    """Firmware is a bare string on some resources and `{Current: {VersionString}}` on others."""
    if isinstance(value, str):
        return value or None
    return _nav(value, "Current", "VersionString")


def processor_row(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": doc.get("Id"),
        "socket": doc.get("Socket") or doc.get("Name"),
        "model": (doc.get("Model") or "").strip() or None,
        "manufacturer": doc.get("Manufacturer"),
        "cores": doc.get("TotalCores"),
        "threads": doc.get("TotalThreads"),
        "max_speed_mhz": doc.get("MaxSpeedMHz"),
        "architecture": doc.get("ProcessorArchitecture"),
        "status": status_row(doc.get("Status")),
    }


def dimm_row(doc: dict[str, Any]) -> dict[str, Any]:
    size_mb = doc.get("CapacityMiB")
    if size_mb is None:
        size_mb = doc.get("SizeMB")
    dimm_status = doc.get("DIMMStatus")
    status = status_row(doc.get("Status"))
    if status["health"] is None and dimm_status:
        status["health"] = dimm_status
    present = str(dimm_status or "").lower() not in {"notpresent", "absent"} and bool(size_mb)
    return {
        "id": doc.get("Id"),
        "locator": doc.get("DeviceLocator") or doc.get("SocketLocator") or doc.get("Name"),
        "size_mb": size_mb,
        "type": doc.get("MemoryDeviceType") or doc.get("DIMMType"),
        "technology": doc.get("BaseModuleType") or doc.get("DIMMTechnology"),
        "speed_mhz": (
            doc.get("OperatingSpeedMhz")
            or doc.get("MaximumFrequencyMHz")
            or doc.get("DIMMFrequencyMHz")
        ),
        "rank": doc.get("RankCount") or doc.get("Rank"),
        "manufacturer": (doc.get("Manufacturer") or "").strip() or None,
        "part_number": (doc.get("PartNumber") or "").strip() or None,
        "present": present,
        "status": status,
    }


def nic_row(doc: dict[str, Any]) -> dict[str, Any]:
    mac = doc.get("MACAddress") or doc.get("MacAddress") or doc.get("PermanentMACAddress")
    return {
        "id": doc.get("Id"),
        "name": doc.get("Name"),
        "mac": (mac or "").lower() or None,
        "permanent_mac": (doc.get("PermanentMACAddress") or "").lower() or None,
        "speed_mbps": doc.get("SpeedMbps"),
        "full_duplex": doc.get("FullDuplex"),
        "autosense": doc.get("Autosense"),
        "link_status": doc.get("LinkStatus") or _nav(doc, "Status", "State"),
        "ipv4": [entry.get("Address") for entry in doc.get("IPv4Addresses") or []],
        "status": status_row(doc.get("Status")),
    }


def psu_row(doc: dict[str, Any]) -> dict[str, Any]:
    bay = _nav(oem(doc), "BayNumber")
    identifier = doc.get("MemberId") or bay or doc.get("Name")
    return {
        # Both supplies are called "HpeServerPowerSupply", so the bay is what
        # makes a label unique enough to alert on.
        "label": f"PSU {bay}" if bay is not None else str(identifier),
        "id": str(identifier) if identifier is not None else None,
        "name": doc.get("Name"),
        "bay": bay,
        "model": (doc.get("Model") or "").strip() or None,
        "serial": (doc.get("SerialNumber") or "").strip() or None,
        "firmware": version_string(doc.get("FirmwareVersion")),
        "type": doc.get("PowerSupplyType"),
        "capacity_watts": doc.get("PowerCapacityWatts"),
        "output_watts": doc.get("LastPowerOutputWatts"),
        "line_input_voltage": doc.get("LineInputVoltage"),
        "status": status_row(doc.get("Status")),
    }


def fan_row(doc: dict[str, Any]) -> dict[str, Any]:
    reading = doc.get("Reading")
    if reading is None:
        reading = doc.get("CurrentReading")
    return {
        "name": doc.get("Name") or doc.get("FanName"),
        "id": doc.get("MemberId") or doc.get("Id"),
        "reading": reading,
        "units": doc.get("ReadingUnits") or doc.get("Units"),
        "location": doc.get("PhysicalContext") or _nav(oem(doc), "Location"),
        "status": status_row(doc.get("Status")),
    }


def temperature_row(doc: dict[str, Any]) -> dict[str, Any]:
    reading = doc.get("ReadingCelsius")
    if reading is None:
        reading = doc.get("CurrentReading")
    return {
        "name": doc.get("Name"),
        "id": doc.get("MemberId") or doc.get("Id") or doc.get("SensorNumber"),
        "celsius": reading,
        "upper_critical": doc.get("UpperThresholdCritical"),
        "upper_fatal": doc.get("UpperThresholdFatal"),
        "physical_context": doc.get("PhysicalContext"),
        "status": status_row(doc.get("Status")),
    }


def firmware_rows(document: dict[str, Any], members: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalise the iLO4 `Current` map and the iLO5+ collection into one list."""
    rows: list[dict[str, Any]] = []
    current = document.get("Current")
    if isinstance(current, dict):
        for component, entries in current.items():
            listed = entries if isinstance(entries, list) else [entries]
            for entry in listed:
                if not isinstance(entry, dict):
                    continue
                rows.append(
                    {
                        "component": component,
                        "name": entry.get("Name") or component,
                        "version": entry.get("VersionString") or entry.get("Version"),
                        "location": entry.get("Location"),
                        "updateable": None,
                    }
                )
    for entry in members:
        rows.append(
            {
                "component": _nav(oem(entry), "DeviceClass") or entry.get("Id"),
                "name": entry.get("Name"),
                "version": entry.get("Version") or entry.get("VersionString"),
                "location": entry.get("Location") or _nav(oem(entry), "DeviceContext"),
                "updateable": entry.get("Updateable"),
            }
        )
    return rows


def health_rollup(system: dict[str, Any]) -> dict[str, str]:
    """Per-subsystem health from the OEM aggregate block plus the overall rollup."""
    rollup: dict[str, str] = {}
    aggregate = oem(system).get("AggregateHealthStatus")
    if isinstance(aggregate, dict):
        for subsystem, value in aggregate.items():
            if isinstance(value, dict):
                health = _nav(value, "Status", "Health") or _nav(value, "Status", "HealthRollup")
                if health:
                    rollup[subsystem] = str(health)
            elif isinstance(value, str) and health_value(value) is not None:
                rollup[subsystem] = value
    overall = _nav(system, "Status", "HealthRollup") or _nav(system, "Status", "Health")
    if overall:
        rollup["System"] = str(overall)
    return rollup


def logical_drive_row(doc: dict[str, Any]) -> dict[str, Any]:
    capacity = doc.get("CapacityBytes")
    if capacity is None and doc.get("CapacityMiB") is not None:
        capacity = doc["CapacityMiB"] * MIB
    return {
        "id": doc.get("Id"),
        "name": doc.get("LogicalDriveName") or doc.get("Name"),
        "raid": doc.get("Raid") or doc.get("RAIDType"),
        "capacity_bytes": capacity,
        "volume_uid": doc.get("VolumeUniqueIdentifier"),
        "media_type": doc.get("MediaType"),
        "stripe_size_bytes": doc.get("StripeSizeBytes") or doc.get("OptimumIOSizeBytes"),
        "status": status_row(doc.get("Status")),
        "data_drives": [],
    }


def physical_drive_row(doc: dict[str, Any]) -> dict[str, Any]:
    capacity = doc.get("CapacityBytes")
    if capacity is None and doc.get("CapacityMiB") is not None:
        capacity = doc["CapacityMiB"] * MIB
    location = (
        doc.get("Location")
        or _nav(doc, "PhysicalLocation", "PartLocation", "ServiceLabel")
        or doc.get("Name")
    )
    return {
        "id": doc.get("Id"),
        "location": location,
        "model": (doc.get("Model") or "").strip() or None,
        "serial": (doc.get("SerialNumber") or "").strip() or None,
        "capacity_bytes": capacity,
        "media_type": doc.get("MediaType"),
        "interface": doc.get("InterfaceType") or doc.get("Protocol"),
        "speed_rpm": doc.get("RotationalSpeedRpm") or doc.get("RotationSpeedRPM"),
        "firmware": version_string(doc.get("FirmwareVersion")) or doc.get("Revision"),
        "power_on_hours": doc.get("PowerOnHours"),
        "ssd_endurance_percent": doc.get("SSDEnduranceUtilizationPercentage"),
        "life_left_percent": doc.get("PredictedMediaLifeLeftPercent"),
        "failure_predicted": doc.get("FailurePredicted"),
        "status": status_row(doc.get("Status")),
    }


def iml_row(doc: dict[str, Any]) -> dict[str, Any]:
    block = oem(doc)
    severity = doc.get("Severity")
    repaired = block.get("Repaired")
    return {
        "id": doc.get("Id"),
        "created": doc.get("Created"),
        "updated": doc.get("Updated"),
        "severity": severity,
        "message": doc.get("Message"),
        "entry_type": doc.get("EntryType"),
        "class": block.get("Class"),
        "code": block.get("Code"),
        "count": block.get("Count"),
        "categories": block.get("Categories"),
        "repaired": repaired,
        "recommended_action": block.get("RecommendedAction"),
        "active": str(severity or "").lower() not in BENIGN_SEVERITIES and not repaired,
    }


@register
class IloCollector(Collector):
    """Read-only hardware inventory and health of one HPE ProLiant through iLO."""

    kind = DeviceKind.ilo
    name = "ilo"
    #: iLO4 is slow and session-limited (ADR 0004): five minutes, one poller.
    interval_seconds = 300

    # -- transport ---------------------------------------------------------
    def _client(self, device: SeedDevice, cred: Credential) -> RedfishClient:
        base = f"https://{device.mgmt_ip}:{device.port or 443}"
        return RedfishSession(base, cred.username, cred.password).open()

    def collect(self, device: SeedDevice, cred: Credential) -> dict[str, Any]:
        client = self._client(device, cred)
        try:
            data = self.collect_from(client)
        finally:
            try:
                client.close()
            except Exception as exc:  # noqa: BLE001 - never fail a run on teardown
                log.debug("ilo session teardown failed for %s: %s", device.name, exc)
        self.publish_metrics(device.name, data)
        return data

    # -- fetch helpers -----------------------------------------------------
    @staticmethod
    def _fetch(
        client: RedfishClient, errors: dict[str, str], key: str, path: str
    ) -> dict[str, Any] | None:
        try:
            return client.get(path)
        except RedfishError as exc:
            errors[key] = str(exc)
            return None

    def _materialise(
        self,
        client: RedfishClient,
        members: list[Member],
        key: str,
        errors: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Documents for a list of members, fetching only the ones that are links."""
        rows: list[dict[str, Any]] = []
        for inline, reference in members:
            if inline is not None:
                rows.append(inline)
            elif reference:
                document = self._fetch(client, errors, f"{key}[{reference}]", reference)
                if document is not None:
                    rows.append(document)
        return rows

    def _expand(
        self,
        client: RedfishClient,
        collection: dict[str, Any] | None,
        key: str,
        errors: dict[str, str],
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Members of a collection, fetching the ones that are only linked.

        `limit` caps the *combined* list and keeps its tail, so an inline log
        (iLO4 `Items`, iLO5 expanded `Members`) is bounded exactly like a
        linked one and nothing beyond the cap is fetched.
        """
        members = collection_members(collection or {})
        if limit is not None and len(members) > limit:
            members = members[-limit:]  # the tail is the recent end of a log
        return self._materialise(client, members, key, errors)

    def _fetch_collection(
        self,
        client: RedfishClient,
        errors: dict[str, str],
        key: str,
        path: str,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        collection = self._fetch(client, errors, key, path)
        if collection is None:
            return []
        return self._expand(client, collection, key, errors, limit=limit)

    # -- collection --------------------------------------------------------
    def collect_from(self, client: RedfishClient) -> dict[str, Any]:
        """Everything below works off a `RedfishClient`, so recorded fixtures drive it."""
        errors: dict[str, str] = {}
        root = self._fetch(client, errors, "root", ROOT_PATH) or {}
        system = self._fetch(client, errors, "system", SYSTEM_PATH) or {}
        manager = self._fetch(client, errors, "manager", MANAGER_PATH) or {}
        chassis = self._fetch(client, errors, "chassis", CHASSIS_PATH) or {}
        thermal = self._fetch(client, errors, "thermal", THERMAL_PATH) or {}
        power = self._fetch(client, errors, "power", POWER_PATH) or {}

        generation = ilo_generation(manager, system)
        processors = self._fetch_collection(
            client,
            errors,
            "processors",
            _ref(system.get("Processors")) or PROCESSORS_PATH,
        )
        dimms = self._fetch_collection(
            client, errors, "memory", _ref(system.get("Memory")) or MEMORY_PATH
        )
        nics = self._fetch_collection(
            client,
            errors,
            "nics",
            _ref(system.get("EthernetInterfaces")) or ETHERNET_PATH,
        )
        power_control = power.get("PowerControl") or []
        first_control = (
            power_control[0] if isinstance(power_control, list) and power_control else {}
        )
        iml = self.collect_iml(client, system, errors)

        return {
            "redfish_version": root.get("RedfishVersion"),
            "generation": generation,
            "ilo": {
                "model": manager.get("Model"),
                "firmware": manager.get("FirmwareVersion"),
                "uuid": manager.get("UUID"),
                "license": _nav(oem(manager), "License", "LicenseType"),
                "status": status_row(manager.get("Status")),
            },
            "system": self.system_row(system, chassis),
            "processors": [processor_row(p) for p in processors],
            "memory": [dimm_row(d) for d in dimms],
            "nics": [nic_row(n) for n in nics],
            "power": {
                "consumed_watts": first_control.get("PowerConsumedWatts"),
                "capacity_watts": first_control.get("PowerCapacityWatts"),
                "average_watts": _nav(first_control, "PowerMetrics", "AverageConsumedWatts"),
                "max_watts": _nav(first_control, "PowerMetrics", "MaxConsumedWatts"),
            },
            "power_supplies": [psu_row(p) for p in power.get("PowerSupplies") or []],
            "fans": [fan_row(f) for f in thermal.get("Fans") or []],
            "temperatures": [temperature_row(t) for t in thermal.get("Temperatures") or []],
            "health": health_rollup(system),
            "firmware": self.collect_firmware(client, errors),
            "storage": self.collect_storage(client, system, errors),
            "iml": iml["entries"],
            "iml_summary": {key: value for key, value in iml.items() if key != "entries"},
            "errors": errors,
        }

    @staticmethod
    def system_row(system: dict[str, Any], chassis: dict[str, Any]) -> dict[str, Any]:
        block = oem(system)
        bios = system.get("BiosVersion") or _nav(block, "Bios", "Current", "VersionString")
        return {
            "manufacturer": system.get("Manufacturer") or chassis.get("Manufacturer"),
            "model": system.get("Model"),
            "sku": system.get("SKU"),
            "serial": system.get("SerialNumber"),
            "uuid": system.get("UUID"),
            "asset_tag": system.get("AssetTag") or chassis.get("AssetTag"),
            "hostname": system.get("HostName"),
            "bios_version": bios,
            "power_state": system.get("PowerState"),
            "indicator_led": system.get("IndicatorLED"),
            "post_state": block.get("PostState"),
            # iLO4 puts these summaries under Processors/Memory, iLO5+ under
            # ProcessorSummary/MemorySummary (where the same keys are links).
            "cpu_count": _nav(system, "ProcessorSummary", "Count")
            or _nav(system, "Processors", "Count"),
            "cpu_model": (
                _nav(system, "ProcessorSummary", "Model")
                or _nav(system, "Processors", "ProcessorFamily")
                or ""
            ).strip()
            or None,
            "memory_gib": _nav(system, "MemorySummary", "TotalSystemMemoryGiB")
            or _nav(system, "Memory", "TotalSystemMemoryGB"),
            "status": status_row(system.get("Status")),
        }

    def collect_firmware(
        self, client: RedfishClient, errors: dict[str, str]
    ) -> list[dict[str, Any]]:
        """iLO5+ publishes a collection, iLO4 a single `Current` document."""
        attempts: dict[str, str] = {}
        for path in FIRMWARE_PATHS:
            document = self._fetch(client, attempts, f"firmware:{path}", path)
            if document is None:
                continue
            members = self._expand(client, document, "firmware", errors)
            return firmware_rows(document, members)
        errors.update(attempts)
        return []

    @staticmethod
    def _has_drives(controllers: list[dict[str, Any]]) -> bool:
        return any(controller["physical_drives"] for controller in controllers)

    def collect_storage(
        self, client: RedfishClient, system: dict[str, Any], errors: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Smart Array first (both generations), the standard Storage tree as fallback.

        The fallback is decided on *drives*, not on controllers: the physical
        disks are the leaf of the VM -> VMDK -> datastore -> logical drive ->
        physical disk chain the correlator walks, and a controller row without
        them is not worth keeping if the other tree has the full picture. Each
        path keeps its own errors so that a host which simply does not publish
        SmartStorage is not reported as broken when Storage answered.
        """
        smart_errors: dict[str, str] = {}
        smart = self.collect_smart_storage(client, system, smart_errors)
        if self._has_drives(smart):
            errors.update(smart_errors)
            return smart
        standard_errors: dict[str, str] = {}
        standard = self.collect_standard_storage(client, system, standard_errors)
        if self._has_drives(standard) or (standard and not smart):
            errors.update(standard_errors)
            return standard
        if smart:
            errors.update(smart_errors)
            return smart
        errors.update(smart_errors)
        errors.update(standard_errors)
        return []

    def collect_smart_storage(
        self, client: RedfishClient, system: dict[str, Any], errors: dict[str, str]
    ) -> list[dict[str, Any]]:
        base = (
            linked(system, "SmartStorage")
            or linked(oem(system), "SmartStorage")
            or SMART_STORAGE_PATH
        )
        document = self._fetch(client, errors, "smart_storage", base)
        if document is None:
            return []
        controllers_path = (
            linked(document, "ArrayControllers")
            or linked(oem(document), "ArrayControllers")
            or f"{base.rstrip('/')}/ArrayControllers/"
        )
        rows = []
        for controller in self._fetch_collection(
            client, errors, "array_controllers", controllers_path
        ):
            rows.append(self.smart_controller_row(client, controller, errors))
        return rows

    def smart_controller_row(
        self, client: RedfishClient, controller: dict[str, Any], errors: dict[str, str]
    ) -> dict[str, Any]:
        identifier = str(controller.get("Id") or controller.get("Location") or "controller")
        logical: list[dict[str, Any]] = []
        physical: list[dict[str, Any]] = []
        # HPE names the drive collection `PhysicalDrives` on both generations
        # even though its URL segment is `DiskDrives`; iLO4 repeats it in the
        # lowercase `links` block. `DiskDrives` is accepted as a link name too,
        # and the conventional path is the last resort.
        base = reference_key(_ref(controller)) or ""
        logical_path = linked(controller, "LogicalDrives") or (
            f"{base}/LogicalDrives/" if base else None
        )
        physical_path = linked(controller, "PhysicalDrives", "DiskDrives") or (
            f"{base}/DiskDrives/" if base else None
        )
        if logical_path:
            key = f"logical_drives:{identifier}"
            for document in self._fetch_collection(client, errors, key, logical_path):
                row = logical_drive_row(document)
                row["data_drives"] = self.data_drive_ids(client, document, errors, key)
                logical.append(row)
        if physical_path:
            key = f"disk_drives:{identifier}"
            physical = [
                physical_drive_row(d)
                for d in self._fetch_collection(client, errors, key, physical_path)
            ]
        return {
            "id": identifier,
            "source": "smartstorage",
            "model": (controller.get("Model") or "").strip() or None,
            "serial": (controller.get("SerialNumber") or "").strip() or None,
            "location": controller.get("Location"),
            "firmware": version_string(controller.get("FirmwareVersion")),
            "cache_mb": controller.get("CacheMemorySizeMiB"),
            "encryption_enabled": controller.get("EncryptionEnabled"),
            "status": status_row(controller.get("Status")),
            "logical_drives": logical,
            "physical_drives": physical,
        }

    def data_drive_ids(
        self,
        client: RedfishClient,
        logical_drive: dict[str, Any],
        errors: dict[str, str],
        key: str,
    ) -> list[str]:
        """Physical drives backing one logical drive: the storage half of the graph.

        Both halves of the join use the drive `Id`, whatever the link spelling
        was: a linked member contributes the last segment of its path, an
        expanded one its `Id`, and `physical_drives[*].id` is the same value.
        """
        node = (
            _nav(logical_drive, "Links", "DataDrives")
            or _nav(logical_drive, "links", "DataDrives")
            or logical_drive.get("DataDrives")
        )
        if isinstance(node, list):
            entries = [(entry, None) for entry in node if isinstance(entry, dict)]
            return self._drive_ids(entries)
        reference = redfish_path(_ref(node))
        if not reference:
            return []
        collection = self._fetch(client, errors, f"{key}:data_drives", reference)
        if collection is None:
            return []
        return self._drive_ids(collection_members(collection))

    @staticmethod
    def _drive_ids(members: Sequence[Member]) -> list[str]:
        ids: list[str] = []
        for entry, reference in members:
            identifier = None
            if entry is not None:
                identifier = entry.get("Id") or path_id(_ref(entry))
            else:
                identifier = path_id(reference)
            if identifier:
                ids.append(str(identifier))
        return ids

    def collect_standard_storage(
        self, client: RedfishClient, system: dict[str, Any], errors: dict[str, str]
    ) -> list[dict[str, Any]]:
        path = linked(system, "Storage")
        if not path:
            return []
        rows = []
        for storage in self._fetch_collection(client, errors, "storage", path):
            identifier = str(storage.get("Id") or "storage")
            controllers = storage.get("StorageControllers") or []
            primary = controllers[0] if controllers else {}
            drives = []
            for reference in (redfish_path(_ref(d)) for d in storage.get("Drives") or []):
                if not reference:
                    continue
                document = self._fetch(client, errors, f"drives:{identifier}", reference)
                if document is not None:
                    row = physical_drive_row(document)
                    row["id"] = row["id"] or path_id(reference)
                    drives.append(row)
            volumes: list[dict[str, Any]] = []
            volumes_path = linked(storage, "Volumes")
            if volumes_path:
                for document in self._fetch_collection(
                    client, errors, f"volumes:{identifier}", volumes_path
                ):
                    volume = logical_drive_row(document)
                    # Same join key as SmartStorage: the drive Id on both sides.
                    volume["data_drives"] = self._drive_ids(
                        [
                            (entry, None)
                            for entry in _nav(document, "Links", "Drives") or []
                            if isinstance(entry, dict)
                        ]
                    )
                    volumes.append(volume)
            rows.append(
                {
                    "id": identifier,
                    "source": "storage",
                    "model": (primary.get("Model") or "").strip() or None,
                    "serial": (primary.get("SerialNumber") or "").strip() or None,
                    "location": primary.get("Name"),
                    "firmware": version_string(primary.get("FirmwareVersion")),
                    "cache_mb": None,
                    "encryption_enabled": None,
                    "status": status_row(primary.get("Status") or storage.get("Status")),
                    "logical_drives": volumes,
                    "physical_drives": drives,
                }
            )
        return rows

    def collect_iml(
        self, client: RedfishClient, system: dict[str, Any], errors: dict[str, str]
    ) -> dict[str, Any]:
        """The tail of the Integrated Management Log, plus what was left out.

        A Gen9 that has been running for years holds hundreds of IML entries,
        and iLO4 hands them over inline: the cap applies to the whole ordered
        list so neither the snapshot nor the structured diff grows without
        bound. Entries that were already in hand still count towards the active
        fault total, so the metric reflects the log rather than the tail.
        """
        base = linked(system, "LogServices") or LOG_SERVICES_PATH
        services = self._fetch(client, errors, "log_services", base)
        iml_path = None
        if services is not None:
            for entry, reference in collection_members(services):
                if entry is not None and str(entry.get("Id") or "").upper() == "IML":
                    iml_path = redfish_path(_ref(entry)) or iml_path
                elif reference and path_id(reference) == "IML":
                    iml_path = reference
                if iml_path:
                    break
        if iml_path is None:
            iml_path = f"{base.rstrip('/')}/IML/"
        service = self._fetch(client, errors, "iml", iml_path)
        entries_path = linked(service or {}, "Entries") or f"{iml_path.rstrip('/')}/Entries/"
        collection = self._fetch(client, errors, "iml_entries", entries_path)
        members = collection_members(collection or {})
        kept = members[-IML_MAX_ENTRIES:] if len(members) > IML_MAX_ENTRIES else members
        rows = [iml_row(d) for d in self._materialise(client, kept, "iml_entries", errors)]
        dropped = [
            iml_row(entry) for entry, _ in members[: len(members) - len(kept)] if entry is not None
        ]
        return {
            "entries": rows,
            "total": len(members),
            "returned": len(rows),
            "truncated": len(members) > len(kept),
            "active": sum(1 for row in rows + dropped if row["active"]),
        }

    # -- metrics -----------------------------------------------------------
    @staticmethod
    def spared_gauges(errors: dict[str, str]) -> list[Any]:
        """Gauges whose section failed this run: absent rows mean "not collected"."""
        spared: list[Any] = []
        for prefixes, gauges in SECTION_GAUGES:
            if any(key.startswith(prefixes) for key in errors):
                spared.extend(gauges)
        return spared

    def publish_metrics(self, device_name: str, data: dict[str, Any]) -> None:
        """Set this run's gauges and drop the series of objects that are gone.

        A drive pulled for RMA, a supply removed from its bay or a sensor that
        stops being reported would otherwise keep its last value forever and
        its alert could never resolve.
        """
        run = _SERIES.run(device_name)

        for subsystem, health in (data.get("health") or {}).items():
            value = health_value(health)
            if value is not None:
                run.set(metrics.ILO_HEALTH_ROLLUP, value, device=device_name, subsystem=subsystem)

        for sensor in data.get("temperatures") or []:
            name = sensor.get("name")
            reading = sensor.get("celsius")
            if not name or not isinstance(reading, (int, float)) or reading <= 0:
                continue  # absent sensors report 0
            run.set(metrics.ILO_TEMPERATURE_CELSIUS, reading, device=device_name, sensor=name)
            critical = sensor.get("upper_critical")
            if isinstance(critical, (int, float)):
                run.set(
                    metrics.ILO_TEMPERATURE_CRITICAL_CELSIUS,
                    critical,
                    device=device_name,
                    sensor=name,
                )

        for fan in data.get("fans") or []:
            name = fan.get("name")
            if not name:
                continue
            reading = fan.get("reading")
            if isinstance(reading, (int, float)):
                run.set(metrics.ILO_FAN_PERCENT, reading, device=device_name, fan=name)
            value = health_value((fan.get("status") or {}).get("health"))
            if value is not None:
                run.set(metrics.ILO_FAN_HEALTH, value, device=device_name, fan=name)

        for psu in data.get("power_supplies") or []:
            name = psu.get("label") or psu.get("id") or psu.get("name")
            if not name:
                continue
            value = health_value((psu.get("status") or {}).get("health"))
            if value is not None:
                run.set(metrics.ILO_PSU_HEALTH, value, device=device_name, psu=name)
            output = psu.get("output_watts")
            if isinstance(output, (int, float)):
                run.set(metrics.ILO_PSU_OUTPUT_WATTS, output, device=device_name, psu=name)

        consumed = (data.get("power") or {}).get("consumed_watts")
        if isinstance(consumed, (int, float)):
            run.set(metrics.ILO_POWER_CONSUMED_WATTS, consumed, device=device_name)

        for controller in data.get("storage") or []:
            controller_id = str(controller.get("id") or "controller")
            value = health_value((controller.get("status") or {}).get("health"))
            if value is not None:
                run.set(
                    metrics.ILO_CONTROLLER_HEALTH,
                    value,
                    device=device_name,
                    controller=controller_id,
                )
            for drive in controller.get("physical_drives") or []:
                name = drive.get("location") or drive.get("id")
                value = health_value((drive.get("status") or {}).get("health"))
                if name and value is not None:
                    run.set(
                        metrics.ILO_DRIVE_HEALTH,
                        value,
                        device=device_name,
                        controller=controller_id,
                        drive=str(name),
                    )
            for drive in controller.get("logical_drives") or []:
                name = drive.get("name") or drive.get("id")
                value = health_value((drive.get("status") or {}).get("health"))
                if name and value is not None:
                    run.set(
                        metrics.ILO_LOGICAL_DRIVE_HEALTH,
                        value,
                        device=device_name,
                        controller=controller_id,
                        drive=str(name),
                    )

        summary = data.get("iml_summary") or {}
        active = summary.get("active")
        if not isinstance(active, int):
            active = sum(1 for entry in data.get("iml") or [] if entry.get("active"))
        run.set(metrics.ILO_ACTIVE_FAULTS, active, device=device_name)
        run.sweep(skip=self.spared_gauges(data.get("errors") or {}))
