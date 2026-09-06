"""Service wiring: the freeze marker, the notifier choice, and the scheduler."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
from prometheus_client import REGISTRY

from infra_agent.agent import service
from infra_agent.agent.notify import LogNotifier
from infra_agent.config import Settings


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        secrets_dir=tmp_path / "secrets",
        seed_inventory=tmp_path / "seed.yaml",
    )


def frozen_gauge() -> float:
    return REGISTRY.get_sample_value("infra_frozen") or 0.0


def test_the_freeze_marker_freezes_the_service(settings):
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    (settings.data_dir / service.FREEZE_MARKER).touch()

    assert service.apply_freeze_marker(settings) is True
    assert settings.frozen is True
    assert frozen_gauge() == 1.0


def test_no_marker_leaves_the_service_running(settings):
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    assert service.apply_freeze_marker(settings) is False
    assert settings.frozen is False
    assert frozen_gauge() == 0.0


def test_an_environment_freeze_is_not_undone_by_a_missing_marker(settings):
    settings.frozen = True
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    assert service.apply_freeze_marker(settings) is True


def test_the_notifier_falls_back_to_the_log_without_telegram(settings):
    assert isinstance(service.build_notifier(settings), LogNotifier)


def test_a_telegram_notifier_is_used_when_the_module_offers_one(settings, monkeypatch):
    class TelegramNotifier:
        def send(self, text: str, *, critical: bool = False) -> None: ...

        def send_approval_request(self, plan: Any, token: str) -> None: ...

        def send_report(self, title: str, body_markdown: str) -> None: ...

    from infra_agent.agent import telegram_bot

    monkeypatch.setattr(telegram_bot, "build_notifier", lambda s: TelegramNotifier(), raising=False)

    assert isinstance(service.build_notifier(settings), TelegramNotifier)


def test_a_telegram_module_that_returns_nothing_is_ignored(settings, monkeypatch):
    from infra_agent.agent import telegram_bot

    monkeypatch.setattr(telegram_bot, "build_notifier", lambda s: None, raising=False)

    assert isinstance(service.build_notifier(settings), LogNotifier)


def test_a_telegram_module_that_raises_is_ignored(settings, monkeypatch):
    from infra_agent.agent import telegram_bot

    def boom(_: Settings) -> Any:
        raise RuntimeError("no bot token")

    monkeypatch.setattr(telegram_bot, "build_notifier", boom, raising=False)

    assert isinstance(service.build_notifier(settings), LogNotifier)


def test_build_service_wires_triage_and_duties_onto_one_runner(settings):
    triage, duties = service.build_service(settings)

    assert triage.runner is duties.runner
    assert triage.notifier is duties.notifier
    assert triage.settings is settings
    assert triage.guard.shadow_mode is settings.tier0_shadow_mode


def test_the_whole_service_shares_one_redaction_gateway(settings):
    """Public-IP pseudonyms are only reversible inside the gateway that made them."""
    from infra_agent.tools import observability_tools

    try:
        triage, duties = service.build_service(settings)

        assert triage.gateway is duties.gateway
        assert triage.runner.gateway is triage.gateway
        assert observability_tools.deps().gateway is triage.gateway
        assert observability_tools.deps().settings is settings
    finally:
        observability_tools.reset()


@dataclass
class FakeScheduler:
    jobs: list[str] = field(default_factory=list)
    started: bool = False

    def add_job(self, func: Any, trigger: str, **kwargs: Any) -> None:
        self.jobs.append(kwargs["id"])

    def start(self) -> None:
        self.started = True


def test_the_scheduler_gets_every_duty(settings, monkeypatch):
    scheduler = FakeScheduler()
    monkeypatch.setattr(
        "apscheduler.schedulers.background.BackgroundScheduler", lambda **_: scheduler
    )
    _, duties = service.build_service(settings)

    started = service.start_scheduler(duties)

    assert started is scheduler
    assert scheduler.started is True
    assert set(scheduler.jobs) == {
        "daily-digest",
        "weekly-report",
        "firmware-inventory",
        "heartbeat",
    }


# -- the owner's mornings, not UTC's ------------------------------------------


def test_the_scheduler_runs_in_the_owners_timezone(monkeypatch):
    monkeypatch.delenv("TZ", raising=False)
    monkeypatch.delenv("INFRA_AGENT_TIMEZONE", raising=False)
    assert service.scheduler_timezone() == "UTC"

    monkeypatch.setenv("TZ", "Europe/Amsterdam")
    assert service.scheduler_timezone() == "Europe/Amsterdam"

    monkeypatch.setenv("INFRA_AGENT_TIMEZONE", "Asia/Tehran")
    assert service.scheduler_timezone() == "Asia/Tehran", "the explicit setting wins"


def test_an_unknown_timezone_falls_back_to_utc(monkeypatch):
    monkeypatch.delenv("TZ", raising=False)
    monkeypatch.setenv("INFRA_AGENT_TIMEZONE", "Middle/Earth")

    assert service.scheduler_timezone() == "UTC"


def test_the_scheduler_is_built_with_that_timezone(settings, monkeypatch):
    monkeypatch.setenv("INFRA_AGENT_TIMEZONE", "Europe/Amsterdam")
    built: dict[str, Any] = {}

    def factory(**kwargs: Any) -> FakeScheduler:
        built.update(kwargs)
        return FakeScheduler()

    monkeypatch.setattr("apscheduler.schedulers.background.BackgroundScheduler", factory)
    _, duties = service.build_service(settings)

    service.start_scheduler(duties)

    assert built["timezone"] == "Europe/Amsterdam"


# -- the drift hook -----------------------------------------------------------


def test_no_drift_provider_is_wired_until_the_reconciler_offers_one(settings):
    assert service.build_drift_provider(settings) is None

    _, duties = service.build_service(settings)

    assert duties.drift()["available"] is False
    assert "not wired" in duties.drift()["reason"]


def test_the_reconciler_is_wired_into_the_digest_as_soon_as_it_exists(settings, monkeypatch):
    """Phase 2 only has to expose a factory; the digest picks it up from there."""
    from infra_agent import reconcile

    monkeypatch.setattr(
        reconcile,
        "build_drift_provider",
        lambda s: lambda: {"missing_in_netbox": ["sw-core-01"], "extra": []},
        raising=False,
    )

    _, duties = service.build_service(settings)

    assert duties.drift() == {
        "available": True,
        "missing_in_netbox": ["sw-core-01"],
        "extra": [],
    }


def test_a_reconciler_that_raises_does_not_break_the_service(settings, monkeypatch):
    from infra_agent import reconcile

    def boom(_settings: Settings) -> Any:
        raise RuntimeError("netbox unreachable")

    monkeypatch.setattr(reconcile, "build_drift_provider", boom, raising=False)

    assert service.build_drift_provider(settings) is None


def test_the_freeze_marker_helper_is_the_one_triage_uses(settings):
    """One implementation, so a freeze cannot be honoured in one path and not the other."""
    from infra_agent.agent import freeze

    assert service.FREEZE_MARKER == freeze.FREEZE_MARKER
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    (settings.data_dir / freeze.FREEZE_MARKER).touch()

    assert service.apply_freeze_marker(settings) is True
    assert freeze.refresh_frozen(settings) is True
