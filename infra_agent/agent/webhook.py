"""The agent's inbound HTTP surface: Alertmanager alerts, health, metrics.

Bound to localhost in `deploy/docker-compose.yml` and reached only by
Alertmanager and Prometheus. There is no approval endpoint here and there never
will be one: approvals are a human channel (CLI, Telegram), never an HTTP call
this service could be talked into making.

Triage runs in a background task so Alertmanager gets its 202 immediately and
does not retry a webhook that is merely slow because the model is thinking.
"""


# No `from __future__ import annotations` here on purpose: FastAPI resolves an
# endpoint's annotations against the module globals when the route is
# registered, and the FastAPI names below are deliberately function-local
# (lazy) imports. Stringified annotations would not resolve and every endpoint
# would look like it took query parameters.

import logging
from typing import Any

from infra_agent.agent.triage import TriageService
from infra_agent.config import Settings, get_settings

log = logging.getLogger(__name__)

#: The port `deploy/docker-compose.yml` publishes for the agent service.
AGENT_PORT = 9102


def build_app(
    service: TriageService | None = None,
    *,
    settings: Settings | None = None,
) -> Any:
    """Build the FastAPI app. FastAPI is imported lazily: it is an optional extra."""
    from fastapi import BackgroundTasks, FastAPI, Request
    from prometheus_client import make_asgi_app

    settings = settings or get_settings()
    triage_service = service or TriageService(settings=settings)
    app = FastAPI(title="infra-agent", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        """Liveness for Docker and the dead-man heartbeat."""
        return {
            "status": "ok",
            "frozen": settings.frozen,
            "tier0_shadow_mode": settings.tier0_shadow_mode,
            "model": settings.llm_model,
        }

    @app.post("/alerts", status_code=202)
    async def alerts(request: Request, background: BackgroundTasks) -> dict[str, Any]:
        """Alertmanager webhook: group the payload into one incident and triage it."""
        payload = await request.json()
        try:
            incident = triage_service.parse(payload)
        except Exception as exc:
            log.exception("could not parse an Alertmanager payload")
            return {"accepted": False, "error": f"{type(exc).__name__}: {exc}"}
        background.add_task(_triage, triage_service, incident)
        return {
            "accepted": True,
            "incident": incident.id,
            "status": incident.status,
            "severity": incident.severity,
            "alerts": len(incident.alerts),
        }

    app.mount("/metrics", make_asgi_app())
    return app


def _triage(service: TriageService, incident: Any) -> None:
    try:
        service.triage(incident)
    except Exception:
        log.exception("triage of incident %s failed", getattr(incident, "id", "?"))
        try:
            service.notifier.send(
                f"Triage of incident {getattr(incident, 'id', '?')} failed; look at the agent log.",
                critical=True,
            )
        except Exception:
            log.exception("could not notify the owner about the triage failure")


def serve(app: Any | None = None, host: str = "0.0.0.0", port: int = AGENT_PORT) -> None:
    """Run the app with uvicorn (lazy import: an optional extra)."""
    import uvicorn

    uvicorn.run(app or build_app(), host=host, port=port, log_level="info")
