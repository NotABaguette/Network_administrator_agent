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
* Smart Array lives under `Systems/1/SmartStorage/...` on both, but iLO5/6 also
  publish the standard `Systems/1/Storage` collection, which is used when
  SmartStorage is absent.
* iLO4 firmware is a single `Current` document, iLO5+ a proper
  `UpdateService/FirmwareInventory` collection.
* iLO4 spells fan readings `FanName`/`CurrentReading`/`Units`, iLO5+
  `Name`/`Reading`/`ReadingUnits`.

Every endpoint is fetched independently: a device that does not publish one
records the reason in `data["errors"]` and the rest of the run still lands.
"""

from __future__ import annotations

import logging
import re
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


class RedfishError(RuntimeError):
    """One Redfish GET failed. Callers degrade instead of losing the run."""


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


def collection_entries(doc: Any) -> tuple[list[dict[str, Any]], list[str]]:
    """Split a Redfish collection into already-expanded members and links to fetch.

    iLO uses `Members`, older firmware `Items` or `links.Member`, and sometimes
    inlines the whole member instead of linking to it.
    """
    inline: list[dict[str, Any]] = []
    links: list[str] = []
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
            if payload:
                inline.append(entry)
            elif reference:
                links.append(reference)
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

    def _expand(
        self,
        client: RedfishClient,
        collection: dict[str, Any] | None,
        key: str,
        errors: dict[str, str],
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Members of a collection, fetching the ones that are only linked."""
        inline, links = collection_entries(collection or {})
        if limit is not None and len(links) > limit:
            links = links[-limit:]  # the tail is the recent end of a log
        rows = list(inline)
        for reference in links:
            document = self._fetch(client, errors, f"{key}[{reference}]", reference)
            if document is not None:
                rows.append(document)
        return rows

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
            "iml": self.collect_iml(client, system, errors),
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

    def collect_storage(
        self, client: RedfishClient, system: dict[str, Any], errors: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Smart Array first (both generations), the standard Storage tree as fallback.

        Each path keeps its own errors so that a host which simply does not
        publish SmartStorage is not reported as broken when Storage answered.
        """
        smart_errors: dict[str, str] = {}
        controllers = self.collect_smart_storage(client, system, smart_errors)
        if controllers:
            errors.update(smart_errors)
            return controllers
        standard_errors: dict[str, str] = {}
        controllers = self.collect_standard_storage(client, system, standard_errors)
        if controllers:
            errors.update(standard_errors)
            return controllers
        errors.update(smart_errors)
        errors.update(standard_errors)
        return []

    def collect_smart_storage(
        self, client: RedfishClient, system: dict[str, Any], errors: dict[str, str]
    ) -> list[dict[str, Any]]:
        base = (
            _ref(system.get("SmartStorage"))
            or _ref(_nav(oem(system), "Links", "SmartStorage"))
            or SMART_STORAGE_PATH
        )
        document = self._fetch(client, errors, "smart_storage", base)
        if document is None:
            return []
        controllers_path = (
            _ref(document.get("ArrayControllers"))
            or _ref(_nav(document, "Links", "ArrayControllers"))
            or _ref(_nav(oem(document), "Links", "ArrayControllers"))
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
        logical_path = _ref(controller.get("LogicalDrives")) or _ref(
            _nav(controller, "Links", "LogicalDrives")
        )
        physical_path = _ref(controller.get("DiskDrives")) or _ref(
            _nav(controller, "Links", "DiskDrives")
        )
        if logical_path:
            key = f"logical_drives:{identifier}"
            for document in self._fetch_collection(client, errors, key, logical_path):
                row = logical_drive_row(document)
                row["data_drives"] = self.data_drive_refs(client, document, errors, key)
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

    def data_drive_refs(
        self,
        client: RedfishClient,
        logical_drive: dict[str, Any],
        errors: dict[str, str],
        key: str,
    ) -> list[str]:
        """Physical drives backing one logical drive: the storage half of the graph."""
        node = _nav(logical_drive, "Links", "DataDrives") or logical_drive.get("DataDrives")
        if isinstance(node, list):
            return [ref for ref in (_ref(entry) for entry in node) if ref]
        reference = _ref(node)
        if not reference:
            return []
        collection = self._fetch(client, errors, f"{key}:data_drives", reference)
        if collection is None:
            return []
        inline, links = collection_entries(collection)
        return links + [str(entry.get("Id")) for entry in inline if entry.get("Id")]

    def collect_standard_storage(
        self, client: RedfishClient, system: dict[str, Any], errors: dict[str, str]
    ) -> list[dict[str, Any]]:
        path = _ref(system.get("Storage"))
        if not path:
            return []
        rows = []
        for storage in self._fetch_collection(client, errors, "storage", path):
            identifier = str(storage.get("Id") or "storage")
            controllers = storage.get("StorageControllers") or []
            primary = controllers[0] if controllers else {}
            drives = []
            for reference in (_ref(d) for d in storage.get("Drives") or []):
                if not reference:
                    continue
                document = self._fetch(client, errors, f"drives:{identifier}", reference)
                if document is not None:
                    drives.append(physical_drive_row(document))
            volumes = []
            volumes_path = _ref(storage.get("Volumes"))
            if volumes_path:
                volumes = [
                    logical_drive_row(v)
                    for v in self._fetch_collection(
                        client, errors, f"volumes:{identifier}", volumes_path
                    )
                ]
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
    ) -> list[dict[str, Any]]:
        base = _ref(system.get("LogServices")) or LOG_SERVICES_PATH
        services = self._fetch(client, errors, "log_services", base)
        iml_path = None
        if services is not None:
            inline, links = collection_entries(services)
            for reference in links:
                if reference.rstrip("/").rsplit("/", 1)[-1].upper() == "IML":
                    iml_path = reference
                    break
            for entry in inline:
                if str(entry.get("Id") or "").upper() == "IML":
                    iml_path = _ref(entry) or iml_path
        if iml_path is None:
            iml_path = f"{base.rstrip('/')}/IML/"
        service = self._fetch(client, errors, "iml", iml_path)
        entries_path = _ref((service or {}).get("Entries")) or f"{iml_path.rstrip('/')}/Entries/"
        documents = self._fetch_collection(
            client, errors, "iml_entries", entries_path, limit=IML_MAX_ENTRIES
        )
        return [iml_row(d) for d in documents]

    # -- metrics -----------------------------------------------------------
    def publish_metrics(self, device_name: str, data: dict[str, Any]) -> None:
        for subsystem, health in (data.get("health") or {}).items():
            value = health_value(health)
            if value is not None:
                metrics.ILO_HEALTH_ROLLUP.labels(device=device_name, subsystem=subsystem).set(value)

        for sensor in data.get("temperatures") or []:
            name = sensor.get("name")
            reading = sensor.get("celsius")
            if not name or not isinstance(reading, (int, float)) or reading <= 0:
                continue  # absent sensors report 0
            metrics.ILO_TEMPERATURE_CELSIUS.labels(device=device_name, sensor=name).set(reading)
            critical = sensor.get("upper_critical")
            if isinstance(critical, (int, float)):
                metrics.ILO_TEMPERATURE_CRITICAL_CELSIUS.labels(
                    device=device_name, sensor=name
                ).set(critical)

        for fan in data.get("fans") or []:
            name = fan.get("name")
            if not name:
                continue
            reading = fan.get("reading")
            if isinstance(reading, (int, float)):
                metrics.ILO_FAN_PERCENT.labels(device=device_name, fan=name).set(reading)
            value = health_value((fan.get("status") or {}).get("health"))
            if value is not None:
                metrics.ILO_FAN_HEALTH.labels(device=device_name, fan=name).set(value)

        for psu in data.get("power_supplies") or []:
            name = psu.get("label") or psu.get("id") or psu.get("name")
            if not name:
                continue
            value = health_value((psu.get("status") or {}).get("health"))
            if value is not None:
                metrics.ILO_PSU_HEALTH.labels(device=device_name, psu=name).set(value)
            output = psu.get("output_watts")
            if isinstance(output, (int, float)):
                metrics.ILO_PSU_OUTPUT_WATTS.labels(device=device_name, psu=name).set(output)

        consumed = (data.get("power") or {}).get("consumed_watts")
        if isinstance(consumed, (int, float)):
            metrics.ILO_POWER_CONSUMED_WATTS.labels(device=device_name).set(consumed)

        for controller in data.get("storage") or []:
            controller_id = str(controller.get("id") or "controller")
            value = health_value((controller.get("status") or {}).get("health"))
            if value is not None:
                metrics.ILO_CONTROLLER_HEALTH.labels(
                    device=device_name, controller=controller_id
                ).set(value)
            for drive in controller.get("physical_drives") or []:
                name = drive.get("location") or drive.get("id")
                value = health_value((drive.get("status") or {}).get("health"))
                if name and value is not None:
                    metrics.ILO_DRIVE_HEALTH.labels(
                        device=device_name, controller=controller_id, drive=str(name)
                    ).set(value)
            for drive in controller.get("logical_drives") or []:
                name = drive.get("name") or drive.get("id")
                value = health_value((drive.get("status") or {}).get("health"))
                if name and value is not None:
                    metrics.ILO_LOGICAL_DRIVE_HEALTH.labels(
                        device=device_name, controller=controller_id, drive=str(name)
                    ).set(value)

        active = sum(1 for entry in data.get("iml") or [] if entry.get("active"))
        metrics.ILO_ACTIVE_FAULTS.labels(device=device_name).set(active)
