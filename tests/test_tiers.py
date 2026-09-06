from datetime import UTC, datetime, timedelta

from infra_agent.change.plan import Tier
from infra_agent.change.tiers import ImpactSummary, Tier0Guard, compute_tier


def test_base_tier_used_without_escalation():
    tier, reasons = compute_tier("vlan.add", ImpactSummary())
    assert tier is Tier.APPROVAL
    assert len(reasons) == 1


def test_mgmt_path_escalates_anything_to_tier2():
    tier, reasons = compute_tier("switch.access_port_config", ImpactSummary(touches_mgmt_path=True))
    assert tier is Tier.WINDOW
    assert any("management path" in r for r in reasons)


def test_vlan_remove_with_members_escalates():
    assert (
        compute_tier("vlan.remove", ImpactSummary(vlan_has_members_or_svi=True))[0] is Tier.WINDOW
    )
    assert compute_tier("vlan.add", ImpactSummary(vlan_has_members_or_svi=True))[0] is Tier.APPROVAL


def test_unknown_action_defaults_to_approval():
    assert compute_tier("something.new", ImpactSummary())[0] is Tier.APPROVAL


def test_tier0_requires_opt_in_tag_and_allowed_cause():
    guard = Tier0Guard(frozen=False, shadow_mode=False)
    ok, why = guard.allow("switch.clear_errdisable", "sw1:Gi1/0/5", [], cause="link-flap")
    assert not ok and "opt-in" in why
    ok, why = guard.allow(
        "switch.clear_errdisable", "sw1:Gi1/0/5", ["auto:errdisable"], cause="bpduguard"
    )
    assert not ok and "denied" in why
    ok, _ = guard.allow(
        "switch.clear_errdisable", "sw1:Gi1/0/5", ["auto:errdisable"], cause="link-flap"
    )
    assert ok


def test_tier0_cooldown_and_retry_cap():
    guard = Tier0Guard(frozen=False, shadow_mode=False)
    now = datetime.now(UTC)
    tags = ["auto:errdisable"]
    assert guard.allow("switch.clear_errdisable", "p", tags, "link-flap", now)[0]
    guard.record("switch.clear_errdisable", "p", now)
    ok, why = guard.allow(
        "switch.clear_errdisable", "p", tags, "link-flap", now + timedelta(minutes=5)
    )
    assert not ok and "cooldown" in why
    later = now + timedelta(hours=2)
    assert guard.allow("switch.clear_errdisable", "p", tags, "link-flap", later)[0]
    guard.record("switch.clear_errdisable", "p", later)
    ok, why = guard.allow(
        "switch.clear_errdisable", "p", tags, "link-flap", later + timedelta(hours=2)
    )
    assert not ok and "retry cap" in why


def test_human_power_off_is_never_undone():
    guard = Tier0Guard(frozen=False, shadow_mode=False)
    ok, why = guard.allow("vm.power_on", "vm-1", ["auto:restart"], cause="human_power_off")
    assert not ok and "denied" in why


def test_frozen_blocks_everything():
    guard = Tier0Guard(frozen=True)
    assert not guard.allow("discovery.rerun", "x", [])[0]


def test_shadow_mode_is_reported():
    guard = Tier0Guard(frozen=False, shadow_mode=True)
    ok, why = guard.allow("discovery.rerun", "x", [])
    assert ok and why.startswith("shadow")
