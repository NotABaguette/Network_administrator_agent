"""Dead-man heartbeat: ping an external service so the owner is paged when
mgmt-01 or the WAN disappears."""

from __future__ import annotations

import logging

import requests

from infra_agent.monitoring import metrics

log = logging.getLogger(__name__)


def ping(url: str | None, timeout: float = 5.0) -> bool:
    if not url:
        return False
    try:
        requests.get(url, timeout=timeout).raise_for_status()
    except requests.RequestException as exc:
        log.warning("heartbeat ping failed: %s", exc)
        return False
    metrics.HEARTBEAT_LAST_OK.set_to_current_time()
    return True
