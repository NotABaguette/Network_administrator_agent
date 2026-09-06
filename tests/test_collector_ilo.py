"""iLO collector tests.

Driven by recorded Redfish documents for both generations:
`tests/fixtures/ilo4_redfish.json` (DL380 Gen9 / iLO 4, Redfish 1.0.0) and
`tests/fixtures/ilo5_redfish.json` (DL360 Gen10 / iLO 5, Redfish 1.6.0). The
fake transport 404s anything that was not recorded, exactly like a box that
does not publish an endpoint, so the graceful-degradation paths are exercised
rather than assumed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import requests
import yaml
from prometheus_client import REGISTRY
from pydantic import SecretStr

from infra_agent.collectors.base import COLLECTORS, Collector
from infra_agent.collectors.ilo import (
    IML_MAX_ENTRIES,
    IloCollector,
    RedfishError,
    RedfishSession,
    collection_entries,
    collection_members,
    firmware_rows,
    health_rollup,
    health_value,
    ilo_generation,
    linked,
    oem,
    oem_vendor,
    path_id,
    redfish_path,
    version_string,
)
from infra_agent.models.common import Credential, DeviceKind, SeedDevice

FIXTURES = Path(__file__).parent / "fixtures"
RULES = Path(__file__).resolve().parents[1] / "infra_agent" / "monitoring" / "rules"


def load(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text())


class FakeRedfish:
    """Serves recorded documents; an unrecorded path fails the way a real GET would.

    iLO answers a resource with or without its trailing slash, so the fake does
    too; anything that was not recorded 404s, exactly like a box that does not
    publish that endpoint.
    """

    def __init__(self, documents: dict[str, Any]):
        self.documents = documents
        self.requested: list[str] = []
        self.closed = False

    def get(self, path: str) -> dict[str, Any]:
        self.requested.append(path)
        for candidate in (path, path.rstrip("/") + "/", path.rstrip("/")):
            if candidate in self.documents:
                return self.documents[candidate]
        raise RedfishError(f"GET {path}: 404 Not Found")

    def count(self, path: str) -> int:
        """How many GETs landed on one resource, whatever the spelling."""
        wanted = path.rstrip("/")
        return sum(1 for seen in self.requested if seen.rstrip("/") == wanted)

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def ilo4() -> FakeRedfish:
    return FakeRedfish(load("ilo4_redfish.json"))


@pytest.fixture
def ilo5() -> FakeRedfish:
    return FakeRedfish(load("ilo5_redfish.json"))


@pytest.fixture
def collector() -> IloCollector:
    return IloCollector()


@pytest.fixture
def data4(collector, ilo4):
    return collector.collect_from(ilo4)


@pytest.fixture
def data5(collector, ilo5):
    return collector.collect_from(ilo5)


# --------------------------------------------------------------------------
# shape helpers
# --------------------------------------------------------------------------
def test_oem_block_resolves_both_spellings():
    assert oem({"Oem": {"Hp": {"PostState": "FinishedPost"}}}) == {"PostState": "FinishedPost"}
    assert oem({"Oem": {"Hpe": {"PostState": "InPost"}}}) == {"PostState": "InPost"}
    assert oem({}) == {}
    assert oem_vendor({"Oem": {"Hp": {}}}) == "Hp"
    assert oem_vendor({"Oem": {"Hpe": {}}}) == "Hpe"
    assert oem_vendor({"Oem": {"Dell": {}}}) is None


def test_generation_from_the_manager_then_from_the_oem_spelling():
    assert ilo_generation({"Model": "iLO 5"}, {}) == "iLO5"
    assert ilo_generation({"FirmwareVersion": "iLO 4 v2.82"}, {}) == "iLO4"
    assert ilo_generation({}, {"Oem": {"Hpe": {}}}) == "iLO5"
    assert ilo_generation({}, {"Oem": {"Hp": {}}}) == "iLO4"


def test_health_value_scale():
    assert health_value("OK") == 1.0
    assert health_value("Redundant") == 1.0
    assert health_value("Warning") == 0.5
    assert health_value("Degraded") == 0.5
    assert health_value("Critical") == 0.0
    assert health_value("Failed") == 0.0
    assert health_value("Unavailable") is None
    assert health_value(None) is None


def test_collection_entries_handles_every_shape_ilo_uses():
    assert collection_entries({"Members": [{"@odata.id": "/a"}]}) == ([], ["/a"])
    assert collection_entries({"Items": [{"Id": "1", "Name": "x"}]}) == (
        [{"Id": "1", "Name": "x"}],
        [],
    )
    assert collection_entries({"links": {"Member": [{"href": "/b"}]}}) == ([], ["/b"])
    assert collection_entries({}) == ([], [])


def test_redfish_path_rewrites_the_legacy_rest_prefix():
    assert (
        redfish_path("/rest/v1/Systems/1/Memory/proc1dimm1")
        == "/redfish/v1/Systems/1/Memory/proc1dimm1"
    )
    assert redfish_path("/redfish/v1/Systems/1/") == "/redfish/v1/Systems/1/"
    assert redfish_path(None) is None
    assert path_id("/redfish/v1/Systems/1/SmartStorage/ArrayControllers/0/DiskDrives/1/") == "1"
    assert path_id(None) is None


def test_collection_members_fetches_each_member_once_on_ilo4():
    """A real iLO4 collection lists the same members twice, Redfish and RIS."""
    collection = {
        "@odata.id": "/redfish/v1/Systems/1/Memory/",
        "Members@odata.count": 2,
        "Members": [
            {"@odata.id": "/redfish/v1/Systems/1/Memory/proc1dimm1/"},
            {"@odata.id": "/redfish/v1/Systems/1/Memory/proc1dimm2/"},
        ],
        "links": {
            "Member": [
                {"href": "/rest/v1/Systems/1/Memory/proc1dimm1"},
                {"href": "/rest/v1/Systems/1/Memory/proc1dimm2"},
            ],
            "self": {"href": "/rest/v1/Systems/1/Memory"},
        },
    }
    assert collection_members(collection) == [
        (None, "/redfish/v1/Systems/1/Memory/proc1dimm1/"),
        (None, "/redfish/v1/Systems/1/Memory/proc1dimm2/"),
    ]


def test_collection_members_prefers_an_expanded_member_over_a_link_to_it():
    entry = {"@odata.id": "/redfish/v1/Systems/1/LogServices/IML/Entries/7/", "Id": "7"}
    collection = {
        "Items": [entry],
        "links": {"Member": [{"href": "/rest/v1/Systems/1/LogServices/IML/Entries/7"}]},
    }
    assert collection_members(collection) == [(entry, None)]

    # ...whichever order the two spellings appear in
    collection = {
        "Members": [{"@odata.id": entry["@odata.id"]}],
        "Items": [entry],
    }
    assert collection_members(collection) == [(entry, None)]


def test_linked_resolves_a_name_wherever_the_generation_keeps_it():
    modern = {"Links": {"PhysicalDrives": {"@odata.id": "/redfish/v1/a/DiskDrives/"}}}
    legacy = {"links": {"PhysicalDrives": {"href": "/rest/v1/a/DiskDrives"}}}
    direct = {"PhysicalDrives": {"@odata.id": "/redfish/v1/a/DiskDrives/"}}
    assert linked(modern, "PhysicalDrives") == "/redfish/v1/a/DiskDrives/"
    assert linked(legacy, "PhysicalDrives") == "/redfish/v1/a/DiskDrives"
    assert linked(direct, "PhysicalDrives") == "/redfish/v1/a/DiskDrives/"
    assert linked(modern, "DiskDrives", "PhysicalDrives") == "/redfish/v1/a/DiskDrives/"
    assert linked({}, "PhysicalDrives") is None


def test_version_string_accepts_both_encodings():
    assert version_string("3.53") == "3.53"
    assert version_string({"Current": {"VersionString": "6.30"}}) == "6.30"
    assert version_string(None) is None


def test_health_rollup_keeps_string_and_nested_subsystems():
    rollup = health_rollup(
        {
            "Status": {"HealthRollup": "Warning"},
            "Oem": {
                "Hp": {
                    "AggregateHealthStatus": {
                        "Fans": {"Status": {"Health": "OK"}},
                        "PowerSupplyRedundancy": "Failed",
                        "AgentlessManagementService": "Unavailable",
                    }
                }
            },
        }
    )
    assert rollup == {"Fans": "OK", "PowerSupplyRedundancy": "Failed", "System": "Warning"}


def test_firmware_rows_normalises_the_ilo4_current_map():
    rows = firmware_rows(
        {
            "Current": {
                "SystemBMC": [{"Name": "iLO", "VersionString": "2.82", "Location": "System Board"}]
            }
        },
        [{"Id": "1", "Name": "System ROM", "Version": "U32 v2.68", "Updateable": True}],
    )
    assert rows[0] == {
        "component": "SystemBMC",
        "name": "iLO",
        "version": "2.82",
        "location": "System Board",
        "updateable": None,
    }
    assert rows[1]["name"] == "System ROM" and rows[1]["version"] == "U32 v2.68"


# --------------------------------------------------------------------------
# registration and contract
# --------------------------------------------------------------------------
def test_collector_is_registered_for_the_ilo_kind():
    assert COLLECTORS[DeviceKind.ilo] is IloCollector
    assert issubclass(IloCollector, Collector)
    assert IloCollector.name == "ilo"
    assert IloCollector.interval_seconds == 300  # iLO4 is session-limited (ADR 0004)


def test_scheduler_imports_the_ilo_collector():
    from infra_agent import scheduler

    scheduler._load_collectors()
    assert DeviceKind.ilo in COLLECTORS


# --------------------------------------------------------------------------
# iLO4
# --------------------------------------------------------------------------
def test_ilo4_identity(data4):
    assert data4["generation"] == "iLO4"
    assert data4["redfish_version"] == "1.0.0"
    assert data4["ilo"] == {
        "model": "iLO 4",
        "firmware": "iLO 4 v2.82",
        "uuid": "c5d5a4b0-1111-5cbb-9d6a-1c98ec1b0000",
        "license": "Perpetual",
        "status": {"health": "OK", "rollup": None, "state": "Enabled"},
    }
    system = data4["system"]
    assert system["model"] == "ProLiant DL380 Gen9"
    assert system["serial"] == "CZ3421AB01"
    assert system["bios_version"] == "P89 v2.76 (10/21/2019)"
    assert system["hostname"] == "esx-01"
    assert system["post_state"] == "FinishedPost"
    # iLO4 keeps the summaries under Processors/Memory rather than *Summary
    assert system["cpu_count"] == 2
    assert system["cpu_model"] == "Intel(R) Xeon(R) CPU E5-2650 v4 @ 2.20GHz"
    assert system["memory_gib"] == 128


def test_ilo4_collects_everything_it_publishes(data4):
    assert data4["errors"] == {}


def test_ilo4_processors_and_dimms(data4):
    assert [p["socket"] for p in data4["processors"]] == ["Proc 1", "Proc 2"]
    assert data4["processors"][0]["cores"] == 12
    assert data4["processors"][0]["threads"] == 24

    dimms = {d["locator"]: d for d in data4["memory"]}
    assert dimms["PROC 1 DIMM 1"]["size_mb"] == 16384
    assert dimms["PROC 1 DIMM 1"]["type"] == "DDR4"
    assert dimms["PROC 1 DIMM 1"]["speed_mhz"] == 2400
    assert dimms["PROC 1 DIMM 1"]["part_number"] == "809208-091"  # trimmed
    assert dimms["PROC 1 DIMM 1"]["present"] is True
    # this one has no Status block at all, only DIMMStatus
    assert dimms["PROC 1 DIMM 4"]["status"]["health"] == "GoodInUse"
    assert dimms["PROC 1 DIMM 2"]["present"] is False


def test_ilo4_nics_use_the_lowercase_mac_key(data4):
    nics = {n["id"]: n for n in data4["nics"]}
    assert nics["1"]["mac"] == "38:63:bb:3f:5a:10"
    assert nics["1"]["speed_mbps"] == 1000
    assert nics["2"]["link_status"] == "Disabled"


def test_ilo4_power_and_thermal(data4):
    assert data4["power"] == {
        "consumed_watts": 182,
        "capacity_watts": 1600,
        "average_watts": 178,
        "max_watts": 240,
    }
    psus = {p["label"]: p for p in data4["power_supplies"]}
    assert set(psus) == {"PSU 1", "PSU 2"}
    assert psus["PSU 1"]["status"]["health"] == "OK"
    assert psus["PSU 1"]["output_watts"] == 92
    assert psus["PSU 2"]["status"]["health"] == "Warning"

    fans = {f["name"]: f for f in data4["fans"]}
    assert fans["Fan 1"]["reading"] == 22  # CurrentReading / Units on iLO4
    assert fans["Fan 1"]["units"] == "Percent"
    assert fans["Fan 3"]["status"]["state"] == "Absent"

    temps = {t["name"]: t for t in data4["temperatures"]}
    assert temps["01-Inlet Ambient"]["celsius"] == 21  # CurrentReading, no ReadingCelsius
    assert temps["01-Inlet Ambient"]["upper_critical"] == 42


def test_ilo4_health_rollup(data4):
    health = data4["health"]
    assert health["Fans"] == "OK"
    assert health["PowerSupplies"] == "Warning"
    assert health["PowerSupplyRedundancy"] == "Failed"
    assert health["System"] == "OK"
    assert "AgentlessManagementService" not in health  # "Unavailable" is not a health value


def test_ilo4_firmware_comes_from_the_current_map(data4):
    versions = {row["name"]: row["version"] for row in data4["firmware"]}
    assert versions["iLO"] == "2.82 Dec 07 2023"
    assert versions["System ROM"] == "P89 v2.76 (10/21/2019)"
    assert versions["Smart Array P440ar Controller"] == "6.30"


def test_ilo4_smart_storage_via_the_oem_hp_paths(data4):
    (controller,) = data4["storage"]
    assert controller["source"] == "smartstorage"
    assert controller["model"] == "Smart Array P440ar"
    assert controller["firmware"] == "6.30"
    assert controller["cache_mb"] == 2048
    assert controller["status"]["health"] == "Warning"

    (logical,) = controller["logical_drives"]
    assert logical["raid"] == "1"
    assert logical["name"] == "01"
    assert logical["capacity_bytes"] == 1_144_609 * 1024 * 1024
    # The storage graph joins on the drive Id, the same value on both sides.
    assert logical["data_drives"] == ["0", "1"]
    assert [d["id"] for d in controller["physical_drives"]] == ["0", "1"]

    drives = {d["location"]: d for d in controller["physical_drives"]}
    assert drives["1I:1:1"]["model"] == "EG1200JEHMC"  # trimmed
    assert drives["1I:1:1"]["serial"] == "KZG8AB0001"
    assert drives["1I:1:1"]["speed_rpm"] == 10000
    assert drives["1I:1:1"]["firmware"] == "HPD4"
    assert drives["1I:1:1"]["status"]["health"] == "OK"
    assert drives["1I:1:2"]["status"]["health"] == "Warning"


def test_ilo4_iml_marks_unrepaired_faults_active(data4):
    entries = {e["id"]: e for e in data4["iml"]}
    assert entries["1"]["severity"] == "OK" and entries["1"]["active"] is False
    assert entries["7"]["severity"] == "Warning" and entries["7"]["active"] is True
    assert entries["9"]["severity"] == "Critical" and entries["9"]["active"] is True
    assert entries["9"]["categories"] == ["Storage"]
    assert entries["9"]["recommended_action"].startswith("Replace the drive")


def test_ilo4_never_asks_for_the_ilo5_firmware_collection_twice(ilo4, collector):
    collector.collect_from(ilo4)
    # It is tried once (and 404s), then the iLO4 path answers.
    assert ilo4.requested.count("/redfish/v1/UpdateService/FirmwareInventory/") == 1
    assert "/redfish/v1/Systems/1/FirmwareInventory/" in ilo4.requested


# --------------------------------------------------------------------------
# iLO5
# --------------------------------------------------------------------------
def test_ilo5_identity(data5):
    assert data5["generation"] == "iLO5"
    assert data5["redfish_version"] == "1.6.0"
    assert data5["ilo"]["firmware"] == "iLO 5 v2.78"
    system = data5["system"]
    assert system["model"] == "ProLiant DL360 Gen10"
    assert system["bios_version"] == "U32 v2.68 (07/14/2024)"
    assert system["asset_tag"] == "rack12-u14"
    assert system["cpu_count"] == 2
    assert system["cpu_model"] == "Intel(R) Xeon(R) Gold 5218 CPU @ 2.30GHz"
    assert system["memory_gib"] == 192
    assert data5["errors"] == {}


def test_ilo5_dimms_use_the_modern_keys(data5):
    dimms = {d["locator"]: d for d in data5["memory"]}
    assert dimms["PROC 1 DIMM 1"]["size_mb"] == 32768
    assert dimms["PROC 1 DIMM 1"]["speed_mhz"] == 2933
    assert dimms["PROC 1 DIMM 1"]["technology"] == "RDIMM"
    assert dimms["PROC 1 DIMM 3"]["present"] is False


def test_ilo5_nics_and_thermal(data5):
    nics = {n["id"]: n for n in data5["nics"]}
    assert nics["1"]["mac"] == "48:df:37:1a:2b:01"
    assert nics["1"]["link_status"] == "LinkUp"
    assert nics["2"]["link_status"] == "LinkDown"

    fans = {f["name"]: f for f in data5["fans"]}
    assert fans["Fan 1"]["reading"] == 18  # Reading / ReadingUnits on iLO5
    assert fans["Fan 3"]["reading"] == 96

    temps = {t["name"]: t for t in data5["temperatures"]}
    assert temps["06-P1 DIMM 7-12"]["celsius"] == 82
    assert temps["06-P1 DIMM 7-12"]["upper_critical"] == 89


def test_ilo5_firmware_comes_from_the_update_service(data5):
    versions = {row["name"]: row["version"] for row in data5["firmware"]}
    assert versions["System ROM"] == "U32 v2.68 (07/14/2024)"
    assert versions["iLO 5"] == "2.78 Jan 30 2024"
    assert all(row["updateable"] is True for row in data5["firmware"])


def test_ilo5_smart_storage_via_the_oem_hpe_paths(data5):
    (controller,) = data5["storage"]
    assert controller["source"] == "smartstorage"
    assert controller["model"] == "HPE Smart Array P408i-a SR Gen10"
    assert controller["firmware"] == "3.53"
    (logical,) = controller["logical_drives"]
    assert logical["raid"] == "1"
    assert logical["data_drives"] == [d["id"] for d in controller["physical_drives"]] == ["0", "1"]
    drives = {d["location"]: d for d in controller["physical_drives"]}
    assert drives["1I:1:1"]["media_type"] == "SSD"
    assert drives["1I:1:1"]["ssd_endurance_percent"] == 2


def test_ilo5_falls_back_to_the_standard_storage_tree(collector, ilo5):
    """A Gen10 with SmartStorage disabled still resolves drives through Systems/1/Storage."""
    without_smart_storage = {
        path: document for path, document in ilo5.documents.items() if "/SmartStorage/" not in path
    }
    client = FakeRedfish(without_smart_storage)
    data = collector.collect_from(client)

    (controller,) = data["storage"]
    assert controller["source"] == "storage"
    assert controller["model"] == "HPE Smart Array P408i-a SR Gen10"
    assert controller["firmware"] == "3.53"

    (volume,) = controller["logical_drives"]
    assert volume["raid"] == "RAID1"
    assert volume["capacity_bytes"] == 800_166_076_416

    drives = {d["location"]: d for d in controller["physical_drives"]}
    assert set(drives) == {"Port:1I Box:1 Bay:1", "Port:1I Box:1 Bay:2"}
    assert drives["Port:1I Box:1 Bay:1"]["capacity_bytes"] == 800_166_076_416
    assert drives["Port:1I Box:1 Bay:1"]["life_left_percent"] == 98
    assert drives["Port:1I Box:1 Bay:1"]["failure_predicted"] is False
    # the volume joins to those drives by Id here too
    assert volume["data_drives"] == sorted(d["id"] for d in controller["physical_drives"])
    # The SmartStorage attempt is not reported as a failure once Storage answered.
    assert data["errors"] == {}


def test_ilo5_iml_entries_are_fetched_individually(data5, ilo5):
    assert [e["id"] for e in data5["iml"]] == ["1", "2"]
    repaired = data5["iml"][1]
    assert repaired["severity"] == "Critical"
    assert repaired["repaired"] is True
    assert repaired["active"] is False  # repaired faults are not active
    assert "/redfish/v1/Systems/1/LogServices/IML/Entries/2/" in ilo5.requested


# --------------------------------------------------------------------------
# degradation
# --------------------------------------------------------------------------
def test_a_missing_endpoint_is_recorded_and_the_rest_still_lands(collector, ilo5):
    del ilo5.documents["/redfish/v1/Chassis/1/Thermal"]
    data = collector.collect_from(ilo5)

    assert data["fans"] == [] and data["temperatures"] == []
    assert "thermal" in data["errors"]
    assert "404" in data["errors"]["thermal"]
    assert data["system"]["model"] == "ProLiant DL360 Gen10"
    assert data["storage"] and data["processors"]


def test_a_host_with_no_storage_at_all_reports_both_attempts(collector, ilo5):
    stripped = {
        path: document
        for path, document in ilo5.documents.items()
        if "/SmartStorage/" not in path and "/Storage/" not in path
    }
    data = collector.collect_from(FakeRedfish(stripped))
    assert data["storage"] == []
    assert "smart_storage" in data["errors"]
    assert "storage" in data["errors"]


def _iml_documents(collection: dict[str, Any], entries: dict[str, Any] | None = None):
    return {
        "/redfish/v1/Systems/1": {
            "LogServices": {"@odata.id": "/redfish/v1/Systems/1/LogServices/"}
        },
        "/redfish/v1/Systems/1/LogServices/": {
            "Members": [{"@odata.id": "/redfish/v1/Systems/1/LogServices/IML/"}]
        },
        "/redfish/v1/Systems/1/LogServices/IML/": {
            "Entries": {"@odata.id": "/redfish/v1/Systems/1/LogServices/IML/Entries/"}
        },
        "/redfish/v1/Systems/1/LogServices/IML/Entries/": collection,
        **(entries or {}),
    }


def test_linked_iml_entries_are_capped_and_only_the_tail_is_fetched(collector):
    entries = {
        f"/redfish/v1/Systems/1/LogServices/IML/Entries/{i}/": {"Id": str(i), "Severity": "OK"}
        for i in range(100)
    }
    documents = _iml_documents({"Members": [{"@odata.id": path} for path in entries]}, entries)
    client = FakeRedfish(documents)

    result = collector.collect_iml(client, documents["/redfish/v1/Systems/1"], {})

    assert result["returned"] == IML_MAX_ENTRIES
    assert result["total"] == 100 and result["truncated"] is True
    assert result["entries"][-1]["id"] == "99"  # the recent end of the log
    # nothing beyond the cap is fetched: that is the point on a slow iLO4
    assert client.count("/redfish/v1/Systems/1/LogServices/IML/Entries/0/") == 0
    assert client.count("/redfish/v1/Systems/1/LogServices/IML/Entries/99/") == 1


@pytest.mark.parametrize("key", ["Items", "Members"])
def test_inline_iml_entries_are_capped_too(collector, key):
    """iLO4 hands the whole log over inline under Items; iLO5 expands Members.

    Without a cap on the combined list a Gen9 with years of history writes
    hundreds of rows into every snapshot and every structured diff.
    """
    inline = [
        {
            "@odata.id": f"/redfish/v1/Systems/1/LogServices/IML/Entries/{i}/",
            "Id": str(i),
            "Severity": "Critical" if i % 50 == 0 else "OK",
            "Oem": {"Hp": {"Repaired": False}},
        }
        for i in range(100)
    ]
    client = FakeRedfish(_iml_documents({key: inline}))

    result = collector.collect_iml(client, {}, {})

    assert result["returned"] == IML_MAX_ENTRIES
    assert result["total"] == 100 and result["truncated"] is True
    assert [row["id"] for row in result["entries"]][0] == "75"
    # entries 0 and 50 are outside the cap but were already in hand, so the
    # fault count still describes the log rather than only its tail
    assert result["active"] == 2
    assert client.count("/redfish/v1/Systems/1/LogServices/IML/Entries/0/") == 0


# --------------------------------------------------------------------------
# Smart Array drive links: the shapes real controllers publish
# --------------------------------------------------------------------------
CONTROLLER = "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/0/"
DISK_DRIVES = f"{CONTROLLER}DiskDrives/"


def _smart_storage(controller_links: dict[str, Any]) -> dict[str, Any]:
    """A minimal SmartStorage tree whose controller links its drives as given."""
    return {
        "/redfish/v1/Systems/1": {
            "SmartStorage": {"@odata.id": "/redfish/v1/Systems/1/SmartStorage/"}
        },
        "/redfish/v1/Systems/1/SmartStorage/": {
            "Links": {
                "ArrayControllers": {
                    "@odata.id": "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/"
                }
            }
        },
        "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/": {
            "Members": [{"@odata.id": CONTROLLER}]
        },
        CONTROLLER: {
            "@odata.id": CONTROLLER,
            "Id": "0",
            "Model": "Smart Array P440ar",
            "Status": {"Health": "OK"},
            **controller_links,
        },
        f"{CONTROLLER}LogicalDrives/": {"Members": []},
        DISK_DRIVES: {"Members": [{"@odata.id": f"{DISK_DRIVES}0/"}]},
        f"{DISK_DRIVES}0/": {
            "Id": "0",
            "Location": "1I:1:1",
            "CapacityMiB": 1_144_609,
            "Status": {"Health": "OK", "State": "Enabled"},
        },
    }


@pytest.mark.parametrize(
    ("links", "shape"),
    [
        (
            {"Links": {"PhysicalDrives": {"@odata.id": DISK_DRIVES}}},
            "Links/PhysicalDrives: what iLO4 and iLO5 both publish",
        ),
        (
            {
                "links": {
                    "PhysicalDrives": {
                        "href": "/rest/v1/Systems/1/SmartStorage/ArrayControllers/0/DiskDrives"
                    }
                }
            },
            "the legacy lowercase links block iLO4 carries alongside it",
        ),
        (
            {"Links": {"DiskDrives": {"@odata.id": DISK_DRIVES}}},
            "a controller that names the link after the URL segment",
        ),
        ({}, "no drive link at all: the conventional path under the controller"),
    ],
)
def test_physical_drives_are_found_however_the_controller_links_them(collector, links, shape):
    client = FakeRedfish(_smart_storage(links))
    errors: dict[str, str] = {}

    (controller,) = collector.collect_smart_storage(
        client, client.documents["/redfish/v1/Systems/1"], errors
    )

    assert [d["location"] for d in controller["physical_drives"]] == ["1I:1:1"], shape
    assert errors == {}, shape


def test_smart_storage_without_drives_falls_back_to_the_storage_tree(collector, ilo5):
    """The drives are the leaf of the storage chain: a controller row alone is not enough."""
    documents = dict(ilo5.documents)
    documents[DISK_DRIVES] = {"Members": []}
    data = collector.collect_from(FakeRedfish(documents))

    (controller,) = data["storage"]
    assert controller["source"] == "storage"
    assert len(controller["physical_drives"]) == 2


# --------------------------------------------------------------------------
# iLO4 publishes every collection twice; nothing may be fetched or kept twice
# --------------------------------------------------------------------------
def test_ilo4_fetches_each_member_once_despite_the_duplicated_collections(collector, ilo4):
    data = collector.collect_from(ilo4)

    assert [d["locator"] for d in data["memory"]] == [
        "PROC 1 DIMM 1",
        "PROC 1 DIMM 4",
        "PROC 1 DIMM 2",
    ]
    assert [p["socket"] for p in data["processors"]] == ["Proc 1", "Proc 2"]
    assert [n["id"] for n in data["nics"]] == ["1", "2"]
    assert [d["id"] for d in data["storage"][0]["physical_drives"]] == ["0", "1"]

    for path in (
        "/redfish/v1/Systems/1/Memory/proc1dimm1/",
        "/redfish/v1/Systems/1/Processors/1/",
        "/redfish/v1/Systems/1/EthernetInterfaces/1/",
        f"{DISK_DRIVES}0/",
    ):
        assert ilo4.count(path) == 1, path
    # the RIS root is never asked for: legacy hrefs are rewritten, not fetched
    assert [path for path in ilo4.requested if path.startswith("/rest/")] == []


def test_ilo4_iml_entries_come_from_the_inline_items(collector, ilo4):
    data = collector.collect_from(ilo4)

    assert [entry["id"] for entry in data["iml"]] == ["1", "7", "9"]
    assert data["iml_summary"] == {"total": 3, "returned": 3, "truncated": False, "active": 2}
    # they were already in hand, so they are not fetched again through the links
    assert ilo4.count("/redfish/v1/Systems/1/LogServices/IML/Entries/7/") == 0


# --------------------------------------------------------------------------
# metrics
# --------------------------------------------------------------------------
def test_metrics_from_an_ilo4_run(collector, data4):
    collector.publish_metrics("esx-01-ilo", data4)
    sample = REGISTRY.get_sample_value
    labels = {"device": "esx-01-ilo"}

    assert sample("infra_ilo_health_rollup", labels | {"subsystem": "PowerSupplies"}) == 0.5
    assert sample("infra_ilo_health_rollup", labels | {"subsystem": "PowerSupplyRedundancy"}) == 0.0
    assert sample("infra_ilo_health_rollup", labels | {"subsystem": "Fans"}) == 1.0

    assert sample("infra_ilo_temperature_celsius", labels | {"sensor": "01-Inlet Ambient"}) == 21
    assert (
        sample("infra_ilo_temperature_critical_celsius", labels | {"sensor": "01-Inlet Ambient"})
        == 42
    )
    # an absent sensor reads 0 and must not become a series
    assert sample("infra_ilo_temperature_celsius", labels | {"sensor": "14-Chipset"}) is None

    assert sample("infra_ilo_fan_percent", labels | {"fan": "Fan 1"}) == 22
    assert sample("infra_ilo_fan_health", labels | {"fan": "Fan 1"}) == 1.0

    assert sample("infra_ilo_psu_health", labels | {"psu": "PSU 1"}) == 1.0
    assert sample("infra_ilo_psu_health", labels | {"psu": "PSU 2"}) == 0.5
    assert sample("infra_ilo_psu_output_watts", labels | {"psu": "PSU 1"}) == 92
    assert sample("infra_ilo_power_consumed_watts", labels) == 182

    drive = labels | {"controller": "0", "drive": "1I:1:2"}
    assert sample("infra_ilo_drive_health", drive) == 0.5
    assert sample("infra_ilo_drive_health", labels | {"controller": "0", "drive": "1I:1:1"}) == 1.0
    assert (
        sample("infra_ilo_logical_drive_health", labels | {"controller": "0", "drive": "01"}) == 0.5
    )
    assert sample("infra_ilo_controller_health", labels | {"controller": "0"}) == 0.5
    assert sample("infra_ilo_active_faults", labels) == 2


def test_metrics_from_an_ilo5_run(collector, data5):
    collector.publish_metrics("esx-02-ilo", data5)
    sample = REGISTRY.get_sample_value
    labels = {"device": "esx-02-ilo"}

    assert sample("infra_ilo_fan_percent", labels | {"fan": "Fan 3"}) == 96
    assert sample("infra_ilo_temperature_celsius", labels | {"sensor": "06-P1 DIMM 7-12"}) == 82
    assert sample("infra_ilo_psu_health", labels | {"psu": "PSU 2"}) == 1.0
    assert sample("infra_ilo_power_consumed_watts", labels) == 214
    assert sample("infra_ilo_active_faults", labels) == 0


def test_a_drive_pulled_for_rma_loses_its_series(collector, ilo5):
    """Otherwise the failed drive keeps health 0 until another disk lands in the bay."""
    device = "esx-05-ilo"
    sample = REGISTRY.get_sample_value
    collector.publish_metrics(device, collector.collect_from(ilo5))
    gone = {"device": device, "controller": "0", "drive": "1I:1:2"}
    stays = {"device": device, "controller": "0", "drive": "1I:1:1"}
    assert sample("infra_ilo_drive_health", gone) == 1.0

    ilo5.documents[DISK_DRIVES] = {"Members": [{"@odata.id": f"{DISK_DRIVES}0/"}]}
    del ilo5.documents[f"{DISK_DRIVES}1/"]
    data = collector.collect_from(ilo5)
    assert data["errors"] == {}  # the drive is gone, not unreadable
    collector.publish_metrics(device, data)

    assert sample("infra_ilo_drive_health", gone) is None
    assert sample("infra_ilo_drive_health", stays) == 1.0


def test_a_failed_thermal_read_keeps_the_sensor_series(collector, ilo5):
    """An endpoint that errored means "not collected", not "the sensor is gone"."""
    device = "esx-06-ilo"
    sample = REGISTRY.get_sample_value
    sensor = {"device": device, "sensor": "06-P1 DIMM 7-12"}
    collector.publish_metrics(device, collector.collect_from(ilo5))
    assert sample("infra_ilo_temperature_celsius", sensor) == 82

    del ilo5.documents["/redfish/v1/Chassis/1/Thermal"]
    data = collector.collect_from(ilo5)
    assert "thermal" in data["errors"]
    collector.publish_metrics(device, data)

    assert sample("infra_ilo_temperature_celsius", sensor) == 82
    assert sample("infra_ilo_power_consumed_watts", {"device": device}) == 214


def test_collect_opens_and_closes_one_session(monkeypatch, collector, ilo5):
    monkeypatch.setattr(IloCollector, "_client", lambda self, device, cred: ilo5)
    device = SeedDevice(
        name="esx-02-ilo", kind=DeviceKind.ilo, mgmt_ip="10.0.0.122", credential_ref="ilo-ro"
    )
    data = collector.collect(device, Credential(username="infra-ro", password="hunter2"))

    assert ilo5.closed is True
    assert data["system"]["model"] == "ProLiant DL360 Gen10"
    assert "hunter2" not in json.dumps(data)
    assert (
        REGISTRY.get_sample_value("infra_ilo_power_consumed_watts", {"device": "esx-02-ilo"}) == 214
    )


# --------------------------------------------------------------------------
# the Redfish transport itself
# --------------------------------------------------------------------------
class FakeResponse:
    def __init__(self, status: int, headers: dict[str, str], payload: Any):
        self.status_code = status
        self.headers = headers
        self._payload = payload

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error")


class FakeHttp:
    login_status = 201

    def __init__(self) -> None:
        self.headers: dict[str, str] = {}
        self.auth: tuple[str, str] | None = None
        self.verify = True
        self.calls: list[tuple[str, str, dict[str, str]]] = []
        self.bodies: list[Any] = []
        self.closed = False

    def post(self, url, json=None, timeout=None):
        self.calls.append(("POST", url, dict(self.headers)))
        self.bodies.append(json)
        if self.login_status >= 400:
            return FakeResponse(self.login_status, {}, {})
        return FakeResponse(
            self.login_status,
            {"X-Auth-Token": "tok-abc", "Location": "/redfish/v1/SessionService/Sessions/1a2b"},
            {"Id": "1a2b"},
        )

    def get(self, url, timeout=None):
        self.calls.append(("GET", url, dict(self.headers)))
        if url.endswith("/missing"):
            return FakeResponse(404, {}, {})
        return FakeResponse(200, {}, {"Id": "1"})

    def delete(self, url, timeout=None):
        self.calls.append(("DELETE", url, dict(self.headers)))
        return FakeResponse(200, {}, {})

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def http(monkeypatch) -> FakeHttp:
    fake = FakeHttp()
    monkeypatch.setattr("infra_agent.collectors.ilo.requests.Session", lambda: fake)
    return fake


def test_session_logs_in_once_and_reuses_the_token(http):
    session = RedfishSession("https://10.0.0.121", "infra-ro", SecretStr("hunter2")).open()
    session.get("/redfish/v1/Systems/1")
    session.get("/redfish/v1/Chassis/1")
    session.close()

    methods = [call[0] for call in http.calls]
    assert methods == ["POST", "GET", "GET", "DELETE"]
    assert http.auth is None  # never falls back to per-request basic auth
    assert all(call[2].get("X-Auth-Token") == "tok-abc" for call in http.calls[1:])
    assert http.calls[-1][1] == "https://10.0.0.121/redfish/v1/SessionService/Sessions/1a2b"
    assert http.closed is True


def test_session_falls_back_to_basic_auth(http):
    FakeHttp.login_status = 401
    try:
        session = RedfishSession("https://10.0.0.121", "infra-ro", SecretStr("hunter2")).open()
        session.get("/redfish/v1/Systems/1")
        session.close()
    finally:
        FakeHttp.login_status = 201

    assert http.auth == ("infra-ro", "hunter2")
    assert [call[0] for call in http.calls] == ["POST", "GET"]  # no session to delete


def test_session_never_carries_the_password_in_its_repr(http):
    session = RedfishSession("https://10.0.0.121", "infra-ro", SecretStr("hunter2")).open()
    assert "hunter2" not in repr(session)
    assert "hunter2" not in str(vars(session))
    assert http.bodies[0]["Password"] == "hunter2"  # it did reach the wire, just not a log


def test_session_turns_http_errors_into_redfish_errors(http):
    session = RedfishSession("https://10.0.0.121", "infra-ro", SecretStr("x")).open()
    with pytest.raises(RedfishError, match="HTTPError"):
        session.get("/redfish/v1/missing")


def test_client_builds_the_url_from_the_device(monkeypatch, http, collector):
    device = SeedDevice(
        name="esx-01-ilo", kind=DeviceKind.ilo, mgmt_ip="10.0.0.121", credential_ref="ilo-ro"
    )
    client = collector._client(device, Credential(username="infra-ro", password="hunter2"))
    assert client.base_url == "https://10.0.0.121:443"
    assert client.url("/redfish/v1/") == "https://10.0.0.121:443/redfish/v1/"
    assert client.url("https://elsewhere/x") == "https://elsewhere/x"


# --------------------------------------------------------------------------
# alert rules
# --------------------------------------------------------------------------
def _metric_names_defined_in_code() -> set[str]:
    """Metric names as PromQL sees them: a Counter's series carries `_total`."""
    from prometheus_client import Counter

    from infra_agent.monitoring import metrics

    names = set()
    for value in vars(metrics).values():
        name = getattr(value, "_name", None)
        if isinstance(name, str) and name.startswith("infra_"):
            names.add(name)
            if isinstance(value, Counter):
                names.add(f"{name}_total")
    return names


def test_hardware_rules_are_valid_and_reference_real_metrics():
    document = yaml.safe_load((RULES / "hardware.yaml").read_text())
    (group,) = document["groups"]
    assert group["name"] == "infra-hardware"

    defined = _metric_names_defined_in_code()
    alerts = {rule["alert"] for rule in group["rules"]}
    assert {
        "PhysicalDriveDegraded",
        "PowerSupplyFailed",
        "FanFailed",
        "TemperatureCritical",
    } <= alerts

    for rule in group["rules"]:
        assert rule["labels"]["severity"] in {"info", "warning", "critical"}
        assert rule["annotations"]["summary"]
        referenced = set(re.findall(r"\binfra_[a-z0-9_]+", rule["expr"]))
        assert referenced, rule["alert"]
        assert referenced <= defined, (rule["alert"], referenced - defined)


def test_every_rule_file_is_loadable():
    for path in sorted(RULES.glob("*.yaml")):
        document = yaml.safe_load(path.read_text())
        assert document["groups"], path


# --------------------------------------------------------------------------
# the base collector contract, end to end
# --------------------------------------------------------------------------
def test_a_failing_drive_between_runs_becomes_one_structured_change(
    monkeypatch, collector, ilo5, tmp_path
):
    from infra_agent.collectors.base import run_collector
    from infra_agent.store.snapshots import FileSnapshotStore

    monkeypatch.setattr(IloCollector, "_client", lambda self, device, cred: ilo5)
    store = FileSnapshotStore(tmp_path / "snapshots")
    device = SeedDevice(
        name="esx-02-ilo", kind=DeviceKind.ilo, mgmt_ip="10.0.0.122", credential_ref="ilo-ro"
    )
    cred = Credential(username="infra-ro", password=SecretStr("hunter2"))

    first = run_collector(collector, device, cred, store, None)
    assert first.changes == []
    assert first.snapshot.data["system"]["serial"] == "CZ2951CD02"

    drive = "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/0/DiskDrives/1/"
    ilo5.documents[drive] = {
        **ilo5.documents[drive],
        "Status": {"Health": "Critical", "State": "Enabled"},
    }
    second = run_collector(collector, device, cred, store, None)

    changed = [c for c in second.changes if c.path.endswith("status.health")]
    assert [(c.op, c.old, c.new) for c in changed] == [("change", "OK", "Critical")]
    assert "physical_drives.1" in changed[0].path
