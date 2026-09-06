"""The agent's own durable bookkeeping: triage dedup and Tier 0 history.

Both exist because the alternative is worse than forgetting: a repeat delivery
costing a full agent run, and a restart handing every object a fresh cooldown.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from infra_agent.agent.state import AgentStateStore, TriageGate, incident_signature
from infra_agent.agent.triage import AlertmanagerWebhook, group_incident
from tests.test_triage import PAYLOAD

NOW = datetime(2026, 2, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def store(tmp_path) -> AgentStateStore:
    return AgentStateStore(tmp_path / "agent-state.db")


def incident(payload: dict = PAYLOAD):
    return group_incident(AlertmanagerWebhook.model_validate(payload))


# -- the store ----------------------------------------------------------------


def test_a_triage_record_round_trips(store):
    assert store.last_triage("group-1") is None

    store.record_triage("group-1", "sig", NOW)
    when, signature = store.last_triage("group-1")

    assert when == NOW
    assert signature == "sig"


def test_forgetting_a_group_makes_the_next_delivery_new(store):
    store.record_triage("group-1", "sig", NOW)
    store.forget_triage("group-1")

    assert store.last_triage("group-1") is None


def test_tier0_history_is_kept_and_pruned(store):
    store.record_tier0("switch.clear_errdisable", "sw-core-01:Gi1/0/12", NOW)
    store.record_tier0("vm.power_on", "esx-01:web-01", NOW - timedelta(days=3))

    recent = store.tier0_history(since=NOW - timedelta(days=1))
    assert [(a, o) for a, o, _ in recent] == [("switch.clear_errdisable", "sw-core-01:Gi1/0/12")]

    store.prune_tier0(before=NOW - timedelta(days=1))
    assert len(store.tier0_history(since=NOW - timedelta(days=30))) == 1


def test_a_second_store_on_the_same_file_sees_the_history(tmp_path):
    """A restart is a new process against the same `infra-data` volume."""
    first = AgentStateStore(tmp_path / "agent-state.db")
    first.record_tier0("vm.snapshot", "web-01", NOW)

    second = AgentStateStore(tmp_path / "agent-state.db")

    assert [(a, o) for a, o, _ in second.tier0_history(since=NOW - timedelta(hours=1))] == [
        ("vm.snapshot", "web-01")
    ]


# -- the signature ------------------------------------------------------------


def test_the_signature_ignores_how_often_alertmanager_repeats_itself():
    assert incident_signature(incident()) == incident_signature(incident())


def test_the_signature_changes_when_the_alert_set_does():
    import copy

    grew = copy.deepcopy(PAYLOAD)
    grew["alerts"].append(
        {
            "status": "firing",
            "labels": {"alertname": "PortDown", "device": "sw-core-01"},
            "annotations": {},
            "fingerprint": "zzz",
        }
    )

    assert incident_signature(incident()) != incident_signature(incident(grew))


# -- the gate -----------------------------------------------------------------


def test_the_first_delivery_of_a_group_runs(store):
    gate = TriageGate(store, timedelta(hours=1))

    run, reason = gate.decide(incident(), now=NOW)

    assert run is True
    assert "new" in reason


def test_a_repeat_inside_the_window_does_not(store):
    gate = TriageGate(store, timedelta(hours=1))
    gate.decide(incident(), now=NOW)

    run, reason = gate.decide(incident(), now=NOW + timedelta(minutes=59))

    assert run is False
    assert "repeat" in reason


def test_a_repeat_after_the_window_does(store):
    gate = TriageGate(store, timedelta(hours=1))
    gate.decide(incident(), now=NOW)

    run, _ = gate.decide(incident(), now=NOW + timedelta(hours=1, minutes=1))

    assert run is True


def test_a_resolved_group_is_never_triaged(store):
    import copy

    body = copy.deepcopy(PAYLOAD)
    body["status"] = "resolved"
    for alert in body["alerts"]:
        alert["status"] = "resolved"
    gate = TriageGate(store, timedelta(hours=1))

    run, reason = gate.decide(incident(body), now=NOW)

    assert run is False
    assert reason == "resolved"


def test_an_unreadable_store_triages_rather_than_going_silent(store, monkeypatch):
    """Losing the dedup record costs a duplicate run; skipping costs the incident."""

    def boom(_key: str):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(store, "last_triage", boom)
    gate = TriageGate(store, timedelta(hours=1))

    run, _ = gate.decide(incident(), now=NOW)

    assert run is True
