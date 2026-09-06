"""The break-glass freeze marker, shared by the service and the triage path.

`infra change freeze` drops `data_dir/FROZEN` on the shared `infra-data`
volume. For an unattended agent that can run Tier 0 actions, "takes effect on
the next restart" is not good enough, so the marker is re-read on every path
that is about to act: a `stat` per triage run is all it costs.

Freezing is one-way here. Removing the marker does not thaw a running service
(`infra change unfreeze` plus a restart does), because `INFRA_FROZEN=1` in the
environment must keep the service frozen whether or not a marker file exists.
"""

from __future__ import annotations

from pathlib import Path

from infra_agent.config import Settings
from infra_agent.monitoring import metrics

#: File name of the break-glass marker inside `settings.data_dir`.
FREEZE_MARKER = "FROZEN"


def marker_path(settings: Settings) -> Path:
    return settings.data_dir / FREEZE_MARKER


def marker_present(settings: Settings) -> bool:
    try:
        return marker_path(settings).exists()
    except OSError:  # an unreadable data dir is not a reason to unfreeze
        return True


def refresh_frozen(settings: Settings) -> bool:
    """Fold the marker into `settings.frozen` and publish the gauge."""
    if marker_present(settings):
        settings.frozen = True
    metrics.FROZEN.set(1 if settings.frozen else 0)
    return settings.frozen
