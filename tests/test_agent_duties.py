"""Scheduled duty tests: the facts each duty computes, and that it computes them
from the platform's own records rather than asking the model to remember.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from infra_agent.agent.duties import (
    COLLECTOR_QUERIES,
    Duties,
    extract_version,
    load_known_good,
    version_key,
)
from infra_agent.agent.runner import AgentRunner
from infra_agent.change.plan import ApprovalRecord, ChangePlan, ChangeState, Tier
from infra_agent.change.store import PlanStore
from infra_agent.config import Settings
from infra_agent.models.common import DeviceKind, SeedDevice, SeedInventory, Snapshot
from infra_agent.redaction.gateway import RedactionGateway
from infra_agent.store.snapshots import FileSnapshotStore
from tests.test_agent_runner import FakeClient, say
from tests.test_triage import RecordingNotifier

NOW = datetime(2026, 2, 1, 12, 0, tzinfo=UTC)


@dataclass
class FakePromql:
    """Stands in for `metrics.promql`.

    Collector health has to come from Prometheus: `run_collector` sets those
    gauges in the `infra-collectors` container, so the agent's own registry
    never has a sample and a registry scan would report an empty, healthy-
    looking estate every single day.
    """

    series: dict[str, list[tuple[dict[str, str], float]]] = field(default_factory=dict)
    error: Exception | None = None
    queries: list[str] = field(default_factory=list)

    def __call__(self, query: str) -> dict[str, Any]:
        self.queries.append(query)
        if self.error is not None:
            return {"query": query, "error": f"{type(self.error).__name__}: {self.error}"}
        rows = [
            {"labels": labels, "at": 1770000000, "value": str(value)}
            for labels, value in self.series.get(query, [])
        ]
        return {"query": query, "result_type": "vector", "row_count": len(rows), "rows": rows}


@dataclass
class FakeConfigStore:
    entries: dict[str, list[dict[str, str]]] = field(default_factory=dict)

    def history(self, device: str, limit: int = 20) -> list[dict[str, str]]:
        return self.entries.get(device, [])[:limit]


@dataclass
class FakeScheduler:
    jobs: list[tuple[Any, str, dict[str, Any]]] = field(default_factory=list)

    def add_job(self, func: Any, trigger: str, **kwargs: Any) -> None:
        self.jobs.append((func, trigger, kwargs))


INVENTORY = SeedInventory(
    devices=[
        SeedDevice(
            name="sw-core-01",
            kind=DeviceKind.cisco_ios,
            mgmt_ip="10.0.0.11",
            credential_ref="sw-core-01",
        ),
        SeedDevice(
            name="fw-01", kind=DeviceKind.fortigate, mgmt_ip="10.0.0.1", credential_ref="fw-01"
        ),
        SeedDevice(
            name="esx-01", kind=DeviceKind.esxi, mgmt_ip="10.0.0.21", credential_ref="esx-01"
        ),
    ]
)


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        secrets_dir=tmp_path / "secrets",
        seed_inventory=tmp_path / "seed.yaml",
    )


@pytest.fixture
def snapshots(tmp_path) -> FileSnapshotStore:
    return FileSnapshotStore(tmp_path / "snapshots")


def make_duties(settings, snapshots, *, turns=None, **kwargs) -> tuple[Duties, FakeClient]:
    client = FakeClient(turns or [say("The estate is fine.")])
    gateway = RedactionGateway(audit_log=settings.data_dir / "audit.jsonl")
    runner = AgentRunner(
        settings=settings,
        gateway=gateway,
        client=client,
        tools=[],
        summary_provider=lambda: {"device_count": 3},
    )
    kwargs.setdefault("notifier", RecordingNotifier())
    kwargs.setdefault("config_store", FakeConfigStore())
    kwargs.setdefault("metrics_query", FakePromql())
    duties = Duties(
        settings=settings,
        runner=runner,
        gateway=gateway,
        snapshots=snapshots,
        plan_store=PlanStore(settings.data_dir / "plans.db"),
        inventory=lambda: INVENTORY,
        now=lambda: NOW,
        **kwargs,
    )
    return duties, client


def save(store: FileSnapshotStore, device: str, collector: str, data: dict, at: datetime) -> None:
    store.save(Snapshot(device=device, collector=collector, taken_at=at, data=data))


# -- collector health ---------------------------------------------------------


def collector_series(**overrides: Any) -> dict[str, list[tuple[dict[str, str], float]]]:
    cisco = {"collector": "cisco", "device": "sw-core-01"}
    esxi = {"collector": "esxi", "device": "esx-01"}
    series = {
        COLLECTOR_QUERIES["last_success"]: [
            (cisco, NOW.timestamp() - 120),
            (esxi, NOW.timestamp() - 7200),
        ],
        COLLECTOR_QUERIES["errors_last_24h"]: [(esxi, 3.0)],
        COLLECTOR_QUERIES["changes_last_run"]: [(cisco, 2.0)],
    }
    series.update(overrides)
    return series


def test_collector_health_reads_the_collectors_own_metrics(settings, snapshots):
    promql = FakePromql(collector_series())
    duties, _ = make_duties(settings, snapshots, metrics_query=promql)

    health = duties.collector_health()
    rows = {row["device"]: row for row in health["collectors"]}

    assert health["available"] is True
    assert health["source"] == "prometheus"
    assert rows["sw-core-01"]["stale"] is False
    assert rows["sw-core-01"]["age_seconds"] == 120
    assert rows["sw-core-01"]["changes_last_run"] == 2
    assert rows["esx-01"]["stale"] is True, "an hour-old collector run is an alert in itself"
    assert rows["esx-01"]["errors_last_24h"] == 3
    assert set(promql.queries) == set(COLLECTOR_QUERIES.values())


def test_collector_health_goes_through_the_real_promql_tool(settings, snapshots, tmp_path):
    """The agent container has no collector samples of its own; Prometheus does."""
    from infra_agent.tools import observability_tools as obs
    from tests.test_observability_tools import FakeHttp

    http = FakeHttp(
        {
            "/api/v1/query": {
                "status": "success",
                "data": {
                    "resultType": "vector",
                    "result": [
                        {
                            "metric": {"collector": "cisco", "device": "sw-core-01"},
                            "value": [1770000000, str(NOW.timestamp() - 60)],
                        }
                    ],
                },
            }
        }
    )
    obs.reset()
    try:
        obs.configure(
            settings=settings,
            gateway=RedactionGateway(audit_log=tmp_path / "audit.jsonl"),
            http=http,
        )
        duties, _ = make_duties(settings, snapshots, metrics_query=None)

        health = duties.collector_health()
    finally:
        obs.reset()

    assert health["available"] is True
    assert [row["device"] for row in health["collectors"]] == ["sw-core-01"]
    assert health["collectors"][0]["stale"] is False
    assert [url for url, _ in http.calls] == ["http://prometheus:9090/api/v1/query"] * len(
        COLLECTOR_QUERIES
    )


def test_an_unreachable_prometheus_is_said_out_loud_not_reported_as_health(settings, snapshots):
    promql = FakePromql(error=ConnectionError("prometheus down"))
    duties, _ = make_duties(settings, snapshots, metrics_query=promql)

    health = duties.collector_health()

    assert health["available"] is False
    assert "ConnectionError" in health["reason"]
    assert health["collectors"] == []


def test_a_raising_metrics_query_does_not_break_the_digest(settings, snapshots):
    def boom(query: str) -> dict[str, Any]:
        raise RuntimeError("prometheus client exploded")

    duties, _ = make_duties(settings, snapshots, metrics_query=boom)

    health = duties.collector_health()

    assert health["available"] is False
    assert "RuntimeError" in health["reason"]


def test_no_collector_series_at_all_is_a_finding_not_silence(settings, snapshots):
    """An empty answer means the collectors are not reporting, not that they are fine."""
    duties, _ = make_duties(settings, snapshots, metrics_query=FakePromql({}))

    health = duties.collector_health()

    assert health["available"] is False
    assert "no infra_collector_" in health["reason"]
    assert health["collectors"] == []


# -- snapshot ages ------------------------------------------------------------


def test_snapshot_ages_flag_devices_with_no_recent_snapshot(settings, snapshots):
    save(snapshots, "sw-core-01", "cisco", {"version": "x"}, NOW - timedelta(minutes=5))
    save(snapshots, "fw-01", "fortigate", {"system": {}}, NOW - timedelta(hours=6))
    duties, _ = make_duties(settings, snapshots)

    rows = {row["device"]: row for row in duties.snapshot_ages()}

    assert rows["sw-core-01"]["stale"] is False
    assert rows["fw-01"]["stale"] is True
    assert rows["esx-01"]["age_seconds"] is None, "never collected"
    assert rows["esx-01"]["stale"] is True


# -- unapproved config changes ------------------------------------------------


def test_a_commit_without_an_approved_plan_is_flagged(settings, snapshots):
    configs = FakeConfigStore(
        {
            "sw-core-01": [
                {
                    "sha": "a" * 40,
                    "at": (NOW - timedelta(hours=2)).isoformat(),
                    "subject": "sw-core-01: running-config.txt changed",
                }
            ]
        }
    )
    duties, _ = make_duties(settings, snapshots, config_store=configs)

    (finding,) = duties.unapproved_config_changes()

    assert finding["device"] == "sw-core-01"
    assert finding["unapproved"] is True
    assert finding["approved_plan"] is None


def test_a_commit_that_matches_an_approved_plan_is_not_flagged(settings, snapshots):
    when = NOW - timedelta(hours=2)
    duties, _ = make_duties(
        settings,
        snapshots,
        config_store=FakeConfigStore(
            {"sw-core-01": [{"sha": "b" * 40, "at": when.isoformat(), "subject": "changed"}]}
        ),
    )
    plan = ChangePlan(
        title="Access port config",
        action="switch.access_port_config",
        targets=["sw-core-01"],
        state=ChangeState.done,
        approval=ApprovalRecord(
            approver="owner", channel="cli", at=when + timedelta(minutes=10), token_sha256="x"
        ),
    )
    duties.plans.save(plan)

    (finding,) = duties.unapproved_config_changes()

    assert finding["unapproved"] is False
    assert finding["approved_plan"] == plan.id


def test_old_commits_fall_out_of_the_window(settings, snapshots):
    configs = FakeConfigStore(
        {
            "sw-core-01": [
                {"sha": "c" * 40, "at": (NOW - timedelta(days=3)).isoformat(), "subject": "old"}
            ]
        }
    )
    duties, _ = make_duties(settings, snapshots, config_store=configs)

    assert duties.unapproved_config_changes() == []


def test_pending_approvals_are_listed_without_approval_material(settings, snapshots):
    duties, _ = make_duties(settings, snapshots)
    plan = ChangePlan(title="Add VLAN 40", action="vlan.add", targets=["sw-core-01"])
    plan.transition(ChangeState.dry_run)
    duties.plans.request_approval(plan)

    (row,) = duties.pending_approvals()

    assert row["id"] == plan.id
    assert row["tier"] == int(Tier.APPROVAL)
    assert "token" not in json.dumps(row)


# -- datastores ---------------------------------------------------------------


def test_the_datastore_forecast_projects_from_the_snapshot_series(settings, snapshots):
    tb = 1024**4
    save(
        snapshots,
        "esx-01",
        "esxi",
        {"datastores": [{"name": "ds1", "capacity_bytes": tb, "free_bytes": tb // 2}]},
        NOW - timedelta(days=10),
    )
    save(
        snapshots,
        "esx-01",
        "esxi",
        {"datastores": [{"name": "ds1", "capacity_bytes": tb, "free_bytes": tb // 4}]},
        NOW,
    )
    duties, _ = make_duties(settings, snapshots)

    (row,) = duties.datastore_forecast()

    assert row["host"] == "esx-01"
    assert row["datastore"] == "ds1"
    assert row["free_percent"] == 25.0
    assert row["observed_over_days"] == 10.0
    assert row["days_to_full"] == 10, "a quarter left, burning a quarter every ten days"
    assert row["concerning"] is True


def test_a_datastore_that_is_not_filling_is_not_concerning(settings, snapshots):
    tb = 1024**4
    for days_ago in (10, 0):
        save(
            snapshots,
            "esx-01",
            "esxi",
            {"datastores": [{"name": "ds1", "capacity_bytes": tb, "free_bytes": tb // 2}]},
            NOW - timedelta(days=days_ago),
        )
    duties, _ = make_duties(settings, snapshots)

    (row,) = duties.datastore_forecast()

    assert row["days_to_full"] is None
    assert row["concerning"] is False


def test_datastore_rows_survive_a_different_key_spelling(settings, snapshots):
    from infra_agent.agent.duties import datastores_of

    assert datastores_of({"datastores": [{"name": "a", "capacity": 100, "free": 10}]}) == [
        {"name": "a", "capacity": 100.0, "free": 10.0}
    ]
    assert datastores_of({"datastores": [{"name": "b"}]}) == []
    assert datastores_of({}) == []


# -- capacity and unused objects ---------------------------------------------


def test_unused_firewall_objects_and_free_ports_are_found(settings, snapshots):
    save(
        snapshots,
        "fw-01",
        "fortigate",
        {
            "policies": [{"id": 1, "srcaddr": ["lan"], "dstaddr": ["all"], "service": ["HTTPS"]}],
            "addrgrps": [{"name": "grp", "members": ["printers"]}],
            "addresses": [{"name": "lan"}, {"name": "printers"}, {"name": "old-branch-vpn"}],
            "services": [{"name": "HTTPS"}, {"name": "LEGACY-TCP-9000"}],
        },
        NOW,
    )
    save(
        snapshots,
        "sw-core-01",
        "cisco",
        {
            "interfaces_status": [
                {"port": "Gi1/0/1", "status": "connected", "vlan": "10"},
                {"port": "Gi1/0/2", "status": "notconnect", "vlan": "10", "name": "spare"},
            ]
        },
        NOW,
    )
    duties, _ = make_duties(settings, snapshots)

    findings = duties.unused_objects()
    names = {(f["device"], f["type"], f["name"]) for f in findings}

    assert ("fw-01", "address", "old-branch-vpn") in names
    assert ("fw-01", "service", "LEGACY-TCP-9000") in names
    assert ("fw-01", "address", "lan") not in names, "referenced by a policy"
    assert ("fw-01", "address", "printers") not in names, "referenced through a group"
    assert ("sw-core-01", "switchport", "Gi1/0/2") in names
    assert ("sw-core-01", "switchport", "Gi1/0/1") not in names


def test_capacity_summarises_what_the_snapshot_recorded(settings, snapshots):
    save(
        snapshots,
        "sw-core-01",
        "cisco",
        {
            "interfaces_status": [
                {"port": "Gi1/0/1", "status": "connected"},
                {"port": "Gi1/0/2", "status": "notconnect"},
            ]
        },
        NOW,
    )
    save(
        snapshots,
        "esx-01",
        "esxi",
        {
            "vms": [
                {"name": "vm1", "power_state": "poweredOn"},
                {"name": "vm2", "power_state": "poweredOff"},
            ],
            "datastores": [{"name": "ds1", "capacity_bytes": 100, "free_bytes": 20}],
        },
        NOW,
    )
    duties, _ = make_duties(settings, snapshots)

    rows = {row["device"]: row for row in duties.capacity()}

    assert rows["sw-core-01"]["ports_total"] == 2
    assert rows["sw-core-01"]["ports_free"] == 1
    assert rows["esx-01"]["vms_total"] == 2
    assert rows["esx-01"]["vms_powered_off"] == 1
    assert rows["esx-01"]["datastores"][0]["free_percent"] == 20.0


# -- firmware -----------------------------------------------------------------


def test_the_shipped_known_good_file_covers_every_device_kind():
    known = load_known_good()
    assert set(known) >= {kind.value for kind in DeviceKind}
    for kind, entry in known.items():
        assert entry["known_good"], kind
        assert entry["minimum"], kind


def test_firmware_is_compared_against_the_known_good_list(settings, snapshots):
    save(snapshots, "fw-01", "fortigate", {"system": {"version": "v7.4.5,build2702"}}, NOW)
    save(snapshots, "sw-core-01", "cisco", {"version": [{"version": "15.2(7)E4"}]}, NOW)
    duties, _ = make_duties(
        settings,
        snapshots,
        known_good={
            "fortigate": {"known_good": ["7.4.5"], "minimum": "7.4.5"},
            "cisco_ios": {"known_good": ["15.2(7)E10"], "minimum": "15.2(7)E9"},
        },
    )

    rows = {row["device"]: row for row in duties.firmware_versions()}

    assert rows["fw-01"] == {
        "device": "fw-01",
        "kind": "fortigate",
        "observed": "7.4.5",
        "known_good": ["7.4.5"],
        "minimum": "7.4.5",
        "status": "known_good",
        "notes": None,
    }
    assert rows["sw-core-01"]["observed"] == "15.2(7)E4"
    assert rows["sw-core-01"]["status"] == "below_minimum"
    assert rows["esx-01"]["status"] == "unknown", "no snapshot means no claim"


def test_a_version_that_is_new_rather_than_old_is_drift_not_below_minimum(settings, snapshots):
    save(snapshots, "fw-01", "fortigate", {"system": {"version": "v7.6.1,build0000"}}, NOW)
    duties, _ = make_duties(
        settings, snapshots, known_good={"fortigate": {"known_good": ["7.4.5"], "minimum": "7.4.5"}}
    )

    assert {r["device"]: r["status"] for r in duties.firmware_versions()}["fw-01"] == "drift"


def test_versions_are_pulled_out_of_whatever_shape_the_collector_used():
    assert extract_version({"system": {"version": "v7.4.5,build2702,240912 (GA.F)"}}) == "7.4.5"
    assert extract_version({"version": [{"version": "16.12.10"}]}) == "16.12.10"
    assert extract_version({"host": {"version": "8.0.3"}}) == "8.0.3"
    assert extract_version({"firmware": {"current": "2.82"}}) == "2.82"
    assert extract_version({"nothing": "here"}) is None
    assert version_key("15.2(7)E10") > version_key("15.2(7)E9")
    assert version_key("8.0.3") > version_key("7.0.3")


# -- the duties themselves ----------------------------------------------------


def test_the_daily_digest_hands_the_model_facts_and_reports_back(settings, snapshots):
    save(snapshots, "sw-core-01", "cisco", {"version": "x"}, NOW - timedelta(minutes=5))
    notifier = RecordingNotifier()
    duties, client = make_duties(
        settings,
        snapshots,
        notifier=notifier,
        turns=[say("Everything is quiet.")],
        drift_provider=lambda: {"objects_in_drift": 2},
    )

    result = duties.daily_digest()

    assert result.outcome == "completed"
    assert notifier.reports and notifier.reports[0][0] == "Daily digest"
    assert "Everything is quiet." in notifier.reports[0][1]
    content = client.calls[0]["messages"][0]["content"]
    for expected in (
        "collector_health",
        "snapshot_ages",
        "unapproved_config_changes",
        "datastore_forecast",
        "objects_in_drift",
    ):
        assert expected in content


def test_drift_says_so_when_reconciliation_is_not_wired(settings, snapshots):
    duties, _ = make_duties(settings, snapshots)

    assert duties.drift() == {
        "available": False,
        "reason": "NetBox reconciliation is not wired here yet",
    }


def test_a_failing_drift_provider_is_reported_not_raised(settings, snapshots):
    def boom() -> dict[str, Any]:
        raise RuntimeError("netbox down")

    duties, _ = make_duties(settings, snapshots, drift_provider=boom)

    assert duties.drift()["available"] is False
    assert "netbox down" in duties.drift()["reason"]


def test_the_weekly_report_covers_capacity_and_unused_objects(settings, snapshots):
    notifier = RecordingNotifier()
    duties, client = make_duties(settings, snapshots, notifier=notifier)

    duties.weekly_report()

    assert notifier.reports[0][0] == "Weekly capacity report"
    content = client.calls[0]["messages"][0]["content"]
    assert "capacity" in content and "unused_objects" in content


def test_the_firmware_duty_reports_against_the_baseline(settings, snapshots):
    save(snapshots, "fw-01", "fortigate", {"system": {"version": "v7.4.5"}}, NOW)
    notifier = RecordingNotifier()
    duties, client = make_duties(settings, snapshots, notifier=notifier)

    duties.firmware_inventory()

    assert notifier.reports[0][0] == "Firmware inventory"
    assert "known_good" in client.calls[0]["messages"][0]["content"]


def test_duty_context_is_redacted_on_the_way_to_the_model(settings, snapshots):
    configs = FakeConfigStore(
        {
            "sw-core-01": [
                {
                    "sha": "d" * 40,
                    "at": (NOW - timedelta(hours=1)).isoformat(),
                    "subject": "logged command: snmp-server community S3cret RO",
                }
            ]
        }
    )
    duties, client = make_duties(settings, snapshots, config_store=configs)

    duties.daily_digest()

    content = client.calls[0]["messages"][0]["content"]
    assert "S3cret" not in content
    assert "<REDACTED>" in content


def test_the_heartbeat_needs_no_model_at_all(settings, snapshots, monkeypatch):
    pinged: list[str | None] = []
    monkeypatch.setattr(
        "infra_agent.agent.heartbeat.ping", lambda url, timeout=5.0: pinged.append(url) or True
    )
    duties, client = make_duties(
        settings, snapshots, heartbeat_url_provider=lambda: "https://hc.example/ping"
    )

    assert duties.heartbeat() is True
    assert pinged == ["https://hc.example/ping"]
    assert client.calls == [], "the dead-man ping must work when the model does not"


def test_a_missing_heartbeat_url_is_not_an_error(settings, snapshots):
    duties, _ = make_duties(settings, snapshots, heartbeat_url_provider=lambda: None)
    assert duties.heartbeat() is False


def test_every_duty_is_scheduled(settings, snapshots):
    duties, _ = make_duties(settings, snapshots)
    scheduler = FakeScheduler()

    duties.register(scheduler)

    jobs = {kwargs["id"]: (func, trigger, kwargs) for func, trigger, kwargs in scheduler.jobs}
    assert set(jobs) == {
        "daily-digest",
        "weekly-report",
        "firmware-inventory",
        "heartbeat",
        "dr-export",
        "dr-verify",
    }
    assert jobs["heartbeat"][1] == "interval"
    assert jobs["heartbeat"][2]["minutes"] == 5
    assert jobs["daily-digest"][1] == "cron"
    assert jobs["weekly-report"][2]["day_of_week"] == "mon"
    assert jobs["dr-verify"][2]["day_of_week"] == "sat"


# -- the maintained baseline --------------------------------------------------


def test_the_known_good_list_is_re_read_on_every_run(settings, snapshots, tmp_path, monkeypatch):
    """ "Maintained" means the owner edits the file, not that they restart the agent."""
    baseline = tmp_path / "known_good_versions.yaml"
    baseline.write_text("fortigate:\n  known_good: ['7.4.5']\n  minimum: '7.4.5'\n")
    monkeypatch.setattr("infra_agent.agent.duties.KNOWN_GOOD_VERSIONS", baseline)
    save(snapshots, "fw-01", "fortigate", {"system": {"version": "v7.4.4"}}, NOW)
    duties, _ = make_duties(settings, snapshots)

    first = {row["device"]: row for row in duties.firmware_versions()}
    assert first["fw-01"]["status"] == "below_minimum"

    baseline.write_text("fortigate:\n  known_good: ['7.4.4', '7.4.5']\n  minimum: '7.4.4'\n")
    second = {row["device"]: row for row in duties.firmware_versions()}

    assert second["fw-01"]["status"] == "known_good", "no restart needed"


def test_an_unreadable_baseline_is_not_a_crash(settings, snapshots, tmp_path, monkeypatch):
    broken = tmp_path / "known_good_versions.yaml"
    broken.write_text("{{ this is not yaml")
    monkeypatch.setattr("infra_agent.agent.duties.KNOWN_GOOD_VERSIONS", broken)
    duties, _ = make_duties(settings, snapshots)

    rows = duties.firmware_versions()

    assert {row["status"] for row in rows} == {"unknown"}


def test_an_explicit_baseline_pins_it(settings, snapshots):
    duties, _ = make_duties(settings, snapshots, known_good={"fortigate": {"known_good": ["9.9"]}})

    assert duties.known_good() == {"fortigate": {"known_good": ["9.9"]}}


def test_the_digest_says_when_collector_health_is_unknown(settings, snapshots):
    duties, client = make_duties(
        settings, snapshots, metrics_query=FakePromql(error=ConnectionError("down"))
    )

    duties.daily_digest()

    content = client.calls[0]["messages"][0]["content"]
    assert "could not query Prometheus" in content
    assert '"available": false' in content.lower()
