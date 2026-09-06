"""Unattended agent service: alert triage, scheduled duties, Telegram bot.

Phase 0 ships the skeleton and the safety envelope; Phase 3 fills in the
duties and triage prompts. The Claude call shape is fixed here so later work
does not drift from it:

    from anthropic import Anthropic, beta_tool
    client = Anthropic()
    runner = client.beta.messages.tool_runner(
        model=settings.llm_model,                 # claude-opus-5
        max_tokens=settings.max_output_tokens_per_run,
        thinking={"type": "adaptive"},
        output_config={"effort": settings.llm_effort},
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        system=[{"type": "text", "text": SYSTEM_PREFIX, "cache_control": {"type": "ephemeral"}}],
        tools=[beta_tool(spec.fn) for spec in llm_tools()],   # llm_callable only
        messages=[{"role": "user", "content": redacted_task}],
    )
    for message in runner:                        # per-turn hook: caps, redaction, audit
        ...

Everything the model receives goes through RedactionGateway.egress first, and
the model never sees `change.approve` or `change.execute`.
"""

from __future__ import annotations

import logging
import time

from infra_agent.config import get_settings
from infra_agent.monitoring import metrics
from infra_agent.monitoring.metrics import start_metrics_server

log = logging.getLogger(__name__)


def run() -> None:
    settings = get_settings()
    start_metrics_server(9102)
    metrics.FROZEN.set(1 if settings.frozen else 0)
    log.info(
        "agent service starting (model=%s frozen=%s shadow=%s)",
        settings.llm_model,
        settings.frozen,
        settings.tier0_shadow_mode,
    )
    # Phase 3: APScheduler duties, Alertmanager webhook receiver on :9102/alerts,
    # Telegram long-polling bot, heartbeat every 5 minutes.
    while True:
        time.sleep(60)
