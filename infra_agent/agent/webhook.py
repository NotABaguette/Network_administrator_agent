"""The agent's inbound HTTP surface: Alertmanager alerts, health, metrics.

Bound to localhost in `deploy/docker-compose.yml` and reached only by
Alertmanager and Prometheus. There is no approval endpoint here and there never
will be one: approvals are a human channel (CLI, Telegram), never an HTTP call
this service could be talked into making.

Not every delivery deserves an agent run. `deploy/alertmanager/alertmanager.yml`
sets `send_resolved: true` and repeats a firing group every hour (critical) or
four hours, so one flapping alert would otherwise cost a 40-tool-call, 64k-token
run on every fire, every repeat and every resolve, each of which could
re-nominate a Tier 0 candidate. So:

* a `resolved` delivery is reported to the owner in one line and never triaged;
* a repeat of a group whose alert set has not changed is skipped inside
  `INFRA_TRIAGE_REPEAT_MINUTES` (default 60);
* at most `INFRA_TRIAGE_MAX_CONCURRENT` (default 2) triage runs are in flight;
* when `INFRA_ALERT_WEBHOOK_TOKEN` is set, `/alerts` requires it as a bearer
  token (Alertmanager sends it with `http_config.authorization`), so another
  container on the compose network cannot make the agent think.

Triage runs in a background task so Alertmanager gets its 202 immediately and
does not retry a webhook that is merely slow because the model is thinking.
"""


# No `from __future__ import annotations` here on purpose: FastAPI resolves an
# endpoint's annotations against the module globals when the route is
# registered, and the FastAPI names below are deliberately function-local
# (lazy) imports. Stringified annotations would not resolve and every endpoint
# would look like it took query parameters.

import hmac
import logging
import os
import threading
from datetime import timedelta
from typing import Any

from infra_agent.agent.freeze import marker_present, refresh_frozen
from infra_agent.agent.state import AgentStateStore, TriageGate
from infra_agent.agent.triage import TriageService
from infra_agent.config import Settings, get_settings

log = logging.getLogger(__name__)

#: The port `deploy/docker-compose.yml` publishes for the agent service.
AGENT_PORT = 9102

DEFAULT_REPEAT_MINUTES = 60
DEFAULT_MAX_CONCURRENT = 2
#: How long a queued triage waits for a slot before it is dropped with a note.
QUEUE_TIMEOUT_SECONDS = 600.0


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, "").strip() or default)
    except ValueError:
        log.warning("%s is not a number; using %s", name, default)
        return default
    return value if value > 0 else default


def webhook_token() -> str | None:
    """Shared secret Alertmanager must present, when the owner configured one."""
    return os.environ.get("INFRA_ALERT_WEBHOOK_TOKEN", "").strip() or None


def repeat_window() -> timedelta:
    return timedelta(minutes=_env_int("INFRA_TRIAGE_REPEAT_MINUTES", DEFAULT_REPEAT_MINUTES))


def build_app(
    service: TriageService | None = None,
    *,
    settings: Settings | None = None,
    gate: TriageGate | None = None,
) -> Any:
    """Build the FastAPI app. FastAPI is imported lazily: it is an optional extra."""
    from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
    from prometheus_client import make_asgi_app

    settings = settings or get_settings()
    triage_service = service or TriageService(settings=settings)
    if gate is None:
        state = getattr(triage_service, "state", None) or AgentStateStore(
            settings.data_dir / "agent-state.db"
        )
        gate = TriageGate(state, repeat_window())
    token = webhook_token()
    slots = threading.BoundedSemaphore(
        _env_int("INFRA_TRIAGE_MAX_CONCURRENT", DEFAULT_MAX_CONCURRENT)
    )
    app = FastAPI(title="infra-agent", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        """Liveness for Docker and the dead-man heartbeat."""
        return {
            "status": "ok",
            # Re-read so the break-glass state on show is the one that is in
            # force, not the one this process started with.
            "frozen": refresh_frozen(settings),
            "freeze_marker": marker_present(settings),
            "tier0_shadow_mode": settings.tier0_shadow_mode,
            "model": settings.llm_model,
            "authenticated_alerts": token is not None,
        }

    @app.post("/alerts", status_code=202)
    async def alerts(request: Request, background: BackgroundTasks) -> dict[str, Any]:
        """Alertmanager webhook: group the payload into one incident and triage it."""
        if token is not None and not _authorised(request, token):
            raise HTTPException(status_code=401, detail="unauthorised")
        payload = await request.json()
        try:
            incident = triage_service.parse(payload)
        except Exception as exc:
            log.exception("could not parse an Alertmanager payload")
            return {"accepted": False, "error": f"{type(exc).__name__}: {exc}"}
        body = {
            "accepted": True,
            "incident": incident.id,
            "status": incident.status,
            "severity": incident.severity,
            "alerts": len(incident.alerts),
        }
        run, reason = gate.decide(incident)
        if not run:
            log.info("not triaging %s: %s", incident.id, reason)
            if reason == "resolved":
                _notify(triage_service, f"Resolved: {incident.title}. No triage run.")
            return {**body, "triaged": False, "reason": reason}
        background.add_task(_triage, triage_service, incident, slots)
        return {**body, "triaged": True}

    app.mount("/metrics", make_asgi_app())
    return app


def _authorised(request: Any, token: str) -> bool:
    header = request.headers.get("authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer":
        return False
    return hmac.compare_digest(presented.strip(), token)


def _notify(service: Any, text: str, *, critical: bool = False) -> None:
    try:
        service.notifier.send(text, critical=critical)
    except Exception:
        log.exception("could not notify the owner")


def _triage(service: TriageService, incident: Any, slots: Any | None = None) -> None:
    if slots is not None and not slots.acquire(timeout=QUEUE_TIMEOUT_SECONDS):
        log.warning("dropped the triage of %s: too many runs in flight", incident.id)
        _notify(
            service,
            f"Triage of {incident.title} was dropped: too many agent runs in flight.",
            critical=True,
        )
        return
    try:
        service.triage(incident)
    except Exception:
        log.exception("triage of incident %s failed", getattr(incident, "id", "?"))
        _notify(
            service,
            f"Triage of incident {getattr(incident, 'id', '?')} failed; look at the agent log.",
            critical=True,
        )
    finally:
        if slots is not None:
            slots.release()


def serve(app: Any | None = None, host: str = "0.0.0.0", port: int = AGENT_PORT) -> None:
    """Run the app with uvicorn (lazy import: an optional extra)."""
    import uvicorn

    uvicorn.run(app or build_app(), host=host, port=port, log_level="info")
