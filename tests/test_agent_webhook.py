"""The agent's HTTP surface. FastAPI is an optional extra, so the tests skip
without it rather than making the core suite depend on it.
"""

from __future__ import annotations

from typing import Any

import pytest

from infra_agent.agent.triage import Incident, Triage, TriageService
from infra_agent.config import Settings
from tests.test_triage import PAYLOAD

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from infra_agent.agent import webhook  # noqa: E402
from infra_agent.agent.webhook import build_app  # noqa: E402


class FakeTriageService:
    """Only the two methods the webhook uses; the rest of TriageService is tested elsewhere."""

    def __init__(self, *, explode: bool = False) -> None:
        self.parsed: list[dict[str, Any]] = []
        self.triaged: list[Incident] = []
        self.explode = explode
        self.notifier = _Recorder()

    def parse(self, payload: dict[str, Any]) -> Incident:
        self.parsed.append(payload)
        return TriageService.parse(self, payload)  # type: ignore[arg-type]

    def triage(self, incident: Incident) -> Triage:
        self.triaged.append(incident)
        if self.explode:
            raise RuntimeError("the model is unreachable")
        return Triage(incident_id=incident.id)


class _Recorder:
    def __init__(self) -> None:
        self.messages: list[tuple[str, bool]] = []

    def send(self, text: str, *, critical: bool = False) -> None:
        self.messages.append((text, critical))


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(data_dir=tmp_path / "data", secrets_dir=tmp_path / "secrets")


def test_an_alertmanager_post_is_accepted_and_triaged(settings):
    service = FakeTriageService()
    with TestClient(build_app(service, settings=settings)) as client:
        response = client.post("/alerts", json=PAYLOAD)

    assert response.status_code == 202
    body = response.json()
    assert body["accepted"] is True
    assert body["severity"] == "critical"
    assert body["alerts"] == 2
    # Triage happens in the background, after the 202 Alertmanager needs.
    assert [incident.id for incident in service.triaged] == [body["incident"]]


def test_the_critical_receivers_query_string_is_accepted_and_ignored(settings):
    """`alertmanager.yml` posts critical groups to `/alerts?critical=1`; severity
    is still taken from the alert labels, which is the fact rather than the route."""
    service = FakeTriageService()
    with TestClient(build_app(service, settings=settings)) as client:
        response = client.post("/alerts?critical=1", json=PAYLOAD)

    assert response.status_code == 202
    assert response.json()["severity"] == "critical"
    assert [incident.severity for incident in service.triaged] == ["critical"]


def test_a_malformed_payload_is_reported_not_retried_forever(settings):
    service = FakeTriageService()
    with TestClient(build_app(service, settings=settings)) as client:
        response = client.post("/alerts", json={"alerts": "not a list"})

    assert response.status_code == 202
    assert response.json()["accepted"] is False
    assert service.triaged == []


def test_a_failing_triage_pages_the_owner_instead_of_disappearing(settings):
    service = FakeTriageService(explode=True)
    with TestClient(build_app(service, settings=settings)) as client:
        client.post("/alerts", json=PAYLOAD)

    assert service.notifier.messages
    text, critical = service.notifier.messages[0]
    assert "failed" in text and critical is True


def test_healthz_reports_the_safety_flags(settings):
    settings.frozen = True
    with TestClient(build_app(FakeTriageService(), settings=settings)) as client:
        body = client.get("/healthz").json()

    assert body["status"] == "ok"
    assert body["frozen"] is True
    assert body["model"] == settings.llm_model


def test_metrics_are_mounted_on_the_same_port(settings):
    with TestClient(build_app(FakeTriageService(), settings=settings)) as client:
        response = client.get("/metrics")

    assert response.status_code == 200
    assert "infra_agent_runs_total" in response.text or "python_info" in response.text


def test_there_is_no_approval_endpoint(settings):
    """Approvals are a human channel. Nothing here can be talked into granting one."""
    app = build_app(FakeTriageService(), settings=settings)
    paths = {getattr(route, "path", "") for route in app.routes}

    assert not any("approve" in path or "execute" in path for path in paths)
    with TestClient(app) as client:
        assert client.post("/approve", json={"plan_id": "x"}).status_code == 404


# -- not every delivery deserves a 64k-token run ------------------------------
#
# Alertmanager sends this endpoint the same group when it fires, every hour it
# keeps firing, and once more when it resolves. Each of those was a full agent
# run, and each could nominate a Tier 0 candidate of its own.


def resolved(payload: dict[str, Any]) -> dict[str, Any]:
    import copy

    body = copy.deepcopy(payload)
    body["status"] = "resolved"
    for alert in body["alerts"]:
        alert["status"] = "resolved"
        alert["endsAt"] = "2026-02-01T10:30:00Z"
    return body


def test_a_resolved_notification_is_reported_not_triaged(settings):
    service = FakeTriageService()
    with TestClient(build_app(service, settings=settings)) as client:
        response = client.post("/alerts", json=resolved(PAYLOAD))

    assert response.status_code == 202
    body = response.json()
    assert body["triaged"] is False
    assert body["reason"] == "resolved"
    assert service.triaged == [], "no model run for an alert that has gone away"
    assert service.notifier.messages and "Resolved" in service.notifier.messages[0][0]


def test_a_repeat_of_the_same_group_is_not_triaged_again(settings):
    service = FakeTriageService()
    app = build_app(service, settings=settings)
    with TestClient(app) as client:
        first = client.post("/alerts", json=PAYLOAD).json()
        second = client.post("/alerts", json=PAYLOAD).json()

    assert first["triaged"] is True
    assert second["triaged"] is False
    assert "repeat" in second["reason"]
    assert len(service.triaged) == 1


def test_a_group_that_gained_an_alert_is_triaged_again(settings):
    import copy

    changed = copy.deepcopy(PAYLOAD)
    changed["alerts"].append(
        {
            "status": "firing",
            "labels": {"alertname": "PortDown", "device": "sw-core-01", "severity": "warning"},
            "annotations": {},
            "startsAt": "2026-02-01T10:05:00Z",
            "fingerprint": "ghi789",
        }
    )
    service = FakeTriageService()
    app = build_app(service, settings=settings)
    with TestClient(app) as client:
        client.post("/alerts", json=PAYLOAD)
        second = client.post("/alerts", json=changed).json()

    assert second["triaged"] is True
    assert len(service.triaged) == 2


def test_a_resolved_group_starts_over_when_it_fires_again(settings):
    service = FakeTriageService()
    app = build_app(service, settings=settings)
    with TestClient(app) as client:
        client.post("/alerts", json=PAYLOAD)
        client.post("/alerts", json=resolved(PAYLOAD))
        again = client.post("/alerts", json=PAYLOAD).json()

    assert again["triaged"] is True
    assert len(service.triaged) == 2


def test_the_repeat_window_is_configurable(settings, monkeypatch):
    monkeypatch.setenv("INFRA_TRIAGE_REPEAT_MINUTES", "0")
    assert webhook.repeat_window().total_seconds() == 60 * webhook.DEFAULT_REPEAT_MINUTES

    monkeypatch.setenv("INFRA_TRIAGE_REPEAT_MINUTES", "5")
    assert webhook.repeat_window().total_seconds() == 300

    monkeypatch.setenv("INFRA_TRIAGE_REPEAT_MINUTES", "not a number")
    assert webhook.repeat_window().total_seconds() == 60 * webhook.DEFAULT_REPEAT_MINUTES


# -- who may make the agent think ---------------------------------------------


def test_without_a_configured_secret_the_endpoint_stays_open(settings, monkeypatch):
    monkeypatch.delenv("INFRA_ALERT_WEBHOOK_TOKEN", raising=False)
    service = FakeTriageService()
    with TestClient(build_app(service, settings=settings)) as client:
        assert client.post("/alerts", json=PAYLOAD).status_code == 202


def test_a_configured_secret_is_required(settings, monkeypatch):
    monkeypatch.setenv("INFRA_ALERT_WEBHOOK_TOKEN", "s3cret-webhook-token")
    service = FakeTriageService()
    app = build_app(service, settings=settings)
    with TestClient(app) as client:
        assert client.post("/alerts", json=PAYLOAD).status_code == 401
        assert (
            client.post(
                "/alerts", json=PAYLOAD, headers={"Authorization": "Bearer wrong"}
            ).status_code
            == 401
        )
        ok = client.post(
            "/alerts", json=PAYLOAD, headers={"Authorization": "Bearer s3cret-webhook-token"}
        )

    assert ok.status_code == 202
    assert len(service.triaged) == 1


def test_healthz_says_whether_the_endpoint_is_authenticated(settings, monkeypatch):
    monkeypatch.setenv("INFRA_ALERT_WEBHOOK_TOKEN", "x")
    with TestClient(build_app(FakeTriageService(), settings=settings)) as client:
        assert client.get("/healthz").json()["authenticated_alerts"] is True


def test_healthz_re_reads_the_freeze_marker(settings):
    from infra_agent.agent.freeze import FREEZE_MARKER

    app = build_app(FakeTriageService(), settings=settings)
    with TestClient(app) as client:
        assert client.get("/healthz").json()["frozen"] is False
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        (settings.data_dir / FREEZE_MARKER).touch()
        body = client.get("/healthz").json()

    assert body["frozen"] is True
    assert body["freeze_marker"] is True


# -- concurrency --------------------------------------------------------------


def test_a_triage_that_cannot_get_a_slot_is_dropped_loudly(settings, monkeypatch):
    import threading

    monkeypatch.setattr(webhook, "QUEUE_TIMEOUT_SECONDS", 0.05)
    service = FakeTriageService()
    incident = TriageService.parse(service, PAYLOAD)  # type: ignore[arg-type]
    full = threading.BoundedSemaphore(1)
    full.acquire()

    webhook._triage(service, incident, full)

    assert service.triaged == [], "the run never started"
    text, critical = service.notifier.messages[0]
    assert "dropped" in text and critical is True


def test_a_slot_is_returned_even_when_the_run_fails(settings):
    import threading

    service = FakeTriageService(explode=True)
    incident = TriageService.parse(service, PAYLOAD)  # type: ignore[arg-type]
    slots = threading.BoundedSemaphore(1)

    webhook._triage(service, incident, slots)
    webhook._triage(service, incident, slots)

    assert len(service.triaged) == 2
    assert slots.acquire(blocking=False) is True
