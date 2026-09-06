"""Observed state to NetBox reconciliation (Phase 2).

    from infra_agent.reconcile import observed_estate, bootstrap, drift_report

`model.py` holds the canonical `Estate` that both observation and NetBox are
read into; `observed.py` builds it from collector snapshots; `netbox.py` wraps
pynetbox (lazily imported) and `fake.py` mirrors it in memory; `bootstrap.py`
writes the estate into NetBox idempotently; `baseline.py` records the accepted
baseline; `drift.py` compares the two sides. Nothing here handles raw device
configuration, so every artefact in this package is safe for the LLM path once
it has been through the redaction gateway.
"""

from infra_agent.reconcile.baseline import Baseline, BaselineStore
from infra_agent.reconcile.bootstrap import Reconciler, ReconcileReport, bootstrap, sync
from infra_agent.reconcile.drift import (
    DriftItem,
    DriftReport,
    Severity,
    compare,
    intended_from_netbox,
)
from infra_agent.reconcile.fake import FakeNetBox
from infra_agent.reconcile.model import Estate
from infra_agent.reconcile.netbox import NetBoxClient, NetBoxLike
from infra_agent.reconcile.observed import build_estate
from infra_agent.reconcile.service import (
    DEFAULT_SITE,
    accept_baseline,
    drift_report,
    intended_estate,
    netbox_client,
    observed_estate,
)

__all__ = [
    "DEFAULT_SITE",
    "Baseline",
    "BaselineStore",
    "DriftItem",
    "DriftReport",
    "Estate",
    "FakeNetBox",
    "NetBoxClient",
    "NetBoxLike",
    "ReconcileReport",
    "Reconciler",
    "Severity",
    "accept_baseline",
    "bootstrap",
    "build_estate",
    "compare",
    "drift_report",
    "intended_estate",
    "intended_from_netbox",
    "netbox_client",
    "observed_estate",
    "sync",
]
