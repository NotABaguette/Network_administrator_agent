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


def test_the_critical_route_is_accepted_too(settings):
    service = FakeTriageService()
    with TestClient(build_app(service, settings=settings)) as client:
        response = client.post("/alerts?critical=1", json=PAYLOAD)

    assert response.status_code == 202
    assert service.triaged


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
