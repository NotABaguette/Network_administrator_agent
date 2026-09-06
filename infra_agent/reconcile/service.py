"""Wiring: settings in, estates and reports out.

The CLI and the inventory tools both go through here so there is exactly one
definition of "the observed estate", "the intended estate" and "drift".
"""

from __future__ import annotations

from infra_agent.config import Settings, get_settings
from infra_agent.models.common import SeedInventory
from infra_agent.reconcile.baseline import Baseline, BaselineStore
from infra_agent.reconcile.drift import DriftReport, compare, intended_from_netbox
from infra_agent.reconcile.model import Estate
from infra_agent.reconcile.netbox import NetBoxClient, NetBoxLike
from infra_agent.reconcile.observed import build_estate
from infra_agent.store.snapshots import FileSnapshotStore

DEFAULT_SITE = "hq"
DEFAULT_SITE_NAME = "HQ"

NO_INTENT = (
    "no intended state to compare against: NetBox is not configured and no baseline "
    "has been accepted. Run `infra baseline accept` (or set INFRA_NETBOX_URL and "
    "INFRA_NETBOX_TOKEN and run `infra netbox bootstrap`) first."
)
NO_BASELINE = "no baseline accepted yet: run `infra baseline accept` to make drift meaningful"


def observed_estate(
    settings: Settings | None = None,
    site: str = DEFAULT_SITE,
    site_name: str = DEFAULT_SITE_NAME,
) -> Estate:
    """Parse the newest snapshot of every seed device into the canonical estate."""
    settings = settings or get_settings()
    return build_estate(
        FileSnapshotStore(settings.snapshot_dir),
        SeedInventory.load(settings.seed_inventory),
        site=site,
        site_name=site_name,
    )


def netbox_client(
    settings: Settings | None = None, *, dry_run: bool = False
) -> NetBoxClient | None:
    return NetBoxClient.from_settings(settings or get_settings(), dry_run=dry_run)


def baseline_store(settings: Settings | None = None) -> BaselineStore:
    return BaselineStore.from_settings(settings or get_settings())


def accept_baseline(
    accepted_by: str = "cli-user",
    note: str = "",
    settings: Settings | None = None,
    estate: Estate | None = None,
    client: NetBoxLike | None = None,
    site: str = DEFAULT_SITE,
) -> Baseline:
    """Record the current observed snapshot set as the accepted baseline."""
    settings = settings or get_settings()
    estate = estate if estate is not None else observed_estate(settings, site=site)
    client = client if client is not None else netbox_client(settings)
    return baseline_store(settings).accept(estate, accepted_by, note, client)


def intended_estate(
    settings: Settings | None = None,
    client: NetBoxLike | None = None,
    site: str = DEFAULT_SITE,
) -> tuple[Estate | None, str, list[str]]:
    """(estate, source, warnings). NetBox wins; the accepted baseline is the fallback."""
    settings = settings or get_settings()
    warnings: list[str] = []
    baseline = baseline_store(settings).current()
    if baseline is None:
        warnings.append(NO_BASELINE)
    client = client if client is not None else netbox_client(settings)
    if client is not None:
        return intended_from_netbox(client, site), "netbox", warnings
    if baseline is not None:
        return baseline.estate, "baseline", warnings
    return None, "none", [NO_INTENT]


def drift_report(
    device: str | None = None,
    settings: Settings | None = None,
    client: NetBoxLike | None = None,
    observed: Estate | None = None,
    site: str = DEFAULT_SITE,
) -> DriftReport:
    """Compare observed state against NetBox (or the accepted baseline)."""
    settings = settings or get_settings()
    observed = observed if observed is not None else observed_estate(settings, site=site)
    intended, source, warnings = intended_estate(settings, client, site=site)
    if intended is None:
        return DriftReport(
            site=observed.site,
            source="none",
            devices=[device] if device else sorted(d.name for d in observed.devices),
            warnings=[*observed.warnings, *warnings],
            observed_at=dict(observed.sources),
        )
    report = compare(observed, intended, source=source, devices=[device] if device else None)
    report.warnings = [*report.warnings, *warnings]
    return report
