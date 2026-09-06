"""Unattended agent service: alert triage, scheduled duties, owner notifications.

`run()` is what `infra agent run` and the `infra-agent` container start. It:

1. reads the break-glass freeze marker (`data_dir/FROZEN`) into settings, so a
   `infra change freeze` takes effect on the next start without editing the
   environment;
2. picks the owner's notification channel (Telegram when it is configured, the
   log otherwise);
3. registers the scheduled duties on a background APScheduler;
4. serves the Alertmanager webhook, `/healthz` and `/metrics` on one port.

The Claude call shape lives in `infra_agent.agent.runner`; everything the model
sees goes through `RedactionGateway.egress` first, and `change.approve` /
`change.execute` are never in the tool list.
"""

from __future__ import annotations

import logging

from infra_agent.agent.duties import Duties
from infra_agent.agent.notify import LogNotifier, Notifier
from infra_agent.agent.runner import AgentRunner
from infra_agent.agent.triage import TriageService
from infra_agent.agent.webhook import AGENT_PORT, build_app, serve
from infra_agent.config import Settings, get_settings
from infra_agent.monitoring import metrics
from infra_agent.redaction.gateway import RedactionGateway
from infra_agent.tools import observability_tools

log = logging.getLogger(__name__)

FREEZE_MARKER = "FROZEN"


def apply_freeze_marker(settings: Settings) -> bool:
    """`infra change freeze` drops a marker file; honour it without a restart flag."""
    if (settings.data_dir / FREEZE_MARKER).exists():
        settings.frozen = True
    metrics.FROZEN.set(1 if settings.frozen else 0)
    return settings.frozen


#: Factory names `infra_agent.agent.telegram_bot` may expose. That module belongs
#: to the Telegram package; this service only asks it for a Notifier and falls
#: back to the log when it has none to give.
TELEGRAM_FACTORIES = ("build_notifier", "notifier", "build")


def build_notifier(settings: Settings) -> Notifier:
    """Telegram when the owner has configured it, the log otherwise."""
    try:
        from infra_agent.agent import telegram_bot

        for name in TELEGRAM_FACTORIES:
            factory = getattr(telegram_bot, name, None)
            if factory is None:
                continue
            notifier = factory(settings)
            if isinstance(notifier, Notifier):
                return notifier
    except Exception:
        log.info("no Telegram channel available; notifications go to the log", exc_info=True)
    return LogNotifier()


def build_service(settings: Settings | None = None) -> tuple[TriageService, Duties]:
    settings = settings or get_settings()
    gateway = RedactionGateway(audit_log=settings.audit_log)
    # One gateway for the whole service, tools included: the public-IP
    # pseudonyms only stay consistent (and reversible) inside one gateway, and
    # one audit log is what `docs/redaction-policy.md` asks us to review.
    observability_tools.configure(settings=settings, gateway=gateway)
    runner = AgentRunner(settings=settings, gateway=gateway)
    notifier = build_notifier(settings)
    triage = TriageService(settings=settings, runner=runner, notifier=notifier, gateway=gateway)
    duties = Duties(settings=settings, runner=runner, notifier=notifier, gateway=gateway)
    return triage, duties


def start_scheduler(duties: Duties):
    from apscheduler.schedulers.background import BackgroundScheduler

    scheduler = BackgroundScheduler(timezone="UTC")
    duties.register(scheduler)
    scheduler.start()
    return scheduler


def run(port: int = AGENT_PORT) -> None:
    settings = get_settings()
    frozen = apply_freeze_marker(settings)
    triage, duties = build_service(settings)
    log.info(
        "agent service starting (model=%s frozen=%s shadow=%s port=%s)",
        settings.llm_model,
        frozen,
        settings.tier0_shadow_mode,
        port,
    )
    scheduler = start_scheduler(duties)
    try:
        # /metrics is mounted on this app, so the agent needs one port only.
        serve(build_app(triage, settings=settings), port=port)
    finally:
        scheduler.shutdown(wait=False)
