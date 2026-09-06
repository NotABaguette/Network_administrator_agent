"""Risk tier computation and the Tier 0 guard. See docs/risk-tiers.md."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, Field

from infra_agent.change.plan import Tier


class ImpactSummary(BaseModel):
    """Output of impact_analyze() for the objects a plan touches."""

    touches_mgmt_path: bool = False
    touches_trunk_or_uplink: bool = False
    touches_wan_ha_vpn_stp: bool = False
    vlan_has_members_or_svi: bool = False
    feeds_ilo_or_mgmt_vlan: bool = False
    affected_objects: list[str] = Field(default_factory=list)


BASE_TIERS: dict[str, Tier] = {
    # tier 0 candidates (still gated by Tier0Guard)
    "vm.snapshot": Tier.AUTO,
    "vm.power_on": Tier.AUTO,
    "guest.service_restart": Tier.AUTO,
    "switch.clear_errdisable": Tier.AUTO,
    "discovery.rerun": Tier.AUTO,
    "esxi.log_bundle": Tier.AUTO,
    "alert.silence": Tier.AUTO,
    # tier 1
    "vlan.add": Tier.APPROVAL,
    "vlan.remove": Tier.APPROVAL,
    "switch.access_port_config": Tier.APPROVAL,
    "fortigate.address": Tier.APPROVAL,
    "fortigate.service": Tier.APPROVAL,
    "fortigate.policy": Tier.APPROVAL,
    "fortigate.static_route": Tier.APPROVAL,
    "vm.resize": Tier.APPROVAL,
    "vm.disk_extend": Tier.APPROVAL,
    "vm.create_from_template": Tier.APPROVAL,
    "esxi.host_setting": Tier.APPROVAL,
    "knowledge.doc_update": Tier.APPROVAL,
    # tier 2
    "fortigate.wan": Tier.WINDOW,
    "fortigate.sdwan": Tier.WINDOW,
    "fortigate.ha": Tier.WINDOW,
    "fortigate.vpn": Tier.WINDOW,
    "switch.trunk_port_config": Tier.WINDOW,
    "switch.stp": Tier.WINDOW,
    "firmware.update": Tier.WINDOW,
    "esxi.reboot": Tier.WINDOW,
    "storage.rebuild": Tier.WINDOW,
}


def compute_tier(action: str, impact: ImpactSummary) -> tuple[Tier, list[str]]:
    """Max of the action's base tier and every escalation that applies."""
    tier = BASE_TIERS.get(action, Tier.APPROVAL)
    reasons = [f"base tier for {action}: {tier.name}"]
    escalations = [
        (impact.touches_mgmt_path, "touches the platform's own management path"),
        (impact.touches_trunk_or_uplink, "touches a trunk, uplink or SVI"),
        (impact.touches_wan_ha_vpn_stp, "touches WAN, SD-WAN, HA, VPN or STP"),
        (
            impact.vlan_has_members_or_svi and action == "vlan.remove",
            "VLAN still has members or an SVI",
        ),
        (impact.feeds_ilo_or_mgmt_vlan, "target feeds an iLO or the management VLAN"),
    ]
    for applies, reason in escalations:
        if applies:
            tier = Tier.WINDOW
            reasons.append(f"escalated: {reason}")
    return tier, reasons


class Tier0Policy(BaseModel):
    action: str
    required_tag: str | None
    cause_allowlist: list[str] | None = None
    cause_denylist: list[str] = Field(default_factory=list)
    cooldown: timedelta = timedelta(minutes=30)
    max_per_day: int = 3


TIER0_POLICIES: dict[str, Tier0Policy] = {
    p.action: p
    for p in [
        Tier0Policy(
            action="vm.snapshot", required_tag=None, cooldown=timedelta(minutes=5), max_per_day=10
        ),
        Tier0Policy(
            action="vm.power_on",
            required_tag="auto:restart",
            cause_allowlist=["unexpected_off", "host_reboot"],
            cause_denylist=["human_power_off"],
        ),
        Tier0Policy(
            action="guest.service_restart",
            required_tag="auto:restart",
            cooldown=timedelta(minutes=15),
        ),
        Tier0Policy(
            action="switch.clear_errdisable",
            required_tag="auto:errdisable",
            cause_allowlist=["link-flap", "udld", "dtp-flap", "pagp-flap"],
            cause_denylist=["bpduguard", "loopback", "psecure-violation", "arp-inspection"],
            cooldown=timedelta(hours=1),
            max_per_day=2,
        ),
        Tier0Policy(
            action="discovery.rerun",
            required_tag=None,
            cooldown=timedelta(minutes=2),
            max_per_day=50,
        ),
        Tier0Policy(action="esxi.log_bundle", required_tag=None, max_per_day=5),
        Tier0Policy(action="alert.silence", required_tag=None, max_per_day=20),
    ]
}


class Tier0Guard:
    """Decides whether a Tier 0 action may run right now for a given object."""

    def __init__(self, frozen: bool = False, shadow_mode: bool = True):
        self.frozen = frozen
        self.shadow_mode = shadow_mode
        self._history: dict[tuple[str, str], list[datetime]] = defaultdict(list)

    def allow(
        self,
        action: str,
        object_id: str,
        object_tags: list[str],
        cause: str | None = None,
        now: datetime | None = None,
    ) -> tuple[bool, str]:
        now = now or datetime.now(UTC)
        if self.frozen:
            return False, "platform is frozen (break-glass)"
        policy = TIER0_POLICIES.get(action)
        if policy is None:
            return False, f"{action} is not a tier 0 action"
        if policy.required_tag and policy.required_tag not in object_tags:
            return False, f"{object_id} lacks opt-in tag {policy.required_tag}"
        if cause in policy.cause_denylist:
            return False, f"cause {cause!r} is denied for {action}"
        if policy.cause_allowlist is not None and cause not in policy.cause_allowlist:
            return False, f"cause {cause!r} is not in the allowlist for {action}"
        runs = [t for t in self._history[(action, object_id)] if now - t < timedelta(days=1)]
        if runs and now - max(runs) < policy.cooldown:
            return False, f"cooldown active for {action} on {object_id}"
        if len(runs) >= policy.max_per_day:
            return (
                False,
                f"retry cap ({policy.max_per_day}/day) reached for {action} on {object_id}",
            )
        return True, "shadow: would run" if self.shadow_mode else "allowed"

    def record(self, action: str, object_id: str, now: datetime | None = None) -> None:
        self._history[(action, object_id)].append(now or datetime.now(UTC))
