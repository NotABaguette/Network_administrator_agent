"""Onboarding status for the language model. Never returns secret values."""

from __future__ import annotations

from typing import Any

from infra_agent.config import get_settings
from infra_agent.models.common import DeviceKind, SeedInventory
from infra_agent.onboarding.secrets import SecretsStore
from infra_agent.tools.registry import tool


@tool("onboarding")
def status() -> dict[str, Any]:
    """Which devices are onboarded, whether each has a stored credential and a passing probe."""
    settings = get_settings()
    inv = SeedInventory.load(settings.seed_inventory)
    secrets = SecretsStore(settings.secrets_dir)
    platform_keys = secrets.keys("platform") if secrets.available() else []
    devices = []
    for d in inv.devices:
        devices.append(
            {
                "name": d.name,
                "kind": d.kind.value,
                "mgmt_ip": d.mgmt_ip,
                "tags": d.tags,
                "credential_stored": secrets.has("devices", d.credential_ref)
                if secrets.available()
                else None,
                "probe_ok": d.probe.ok if d.probe else None,
                "privilege": d.probe.privilege if d.probe else None,
                "read_only": d.probe.read_only if d.probe else None,
                "warnings": d.probe.warnings if d.probe else [],
            }
        )
    return {
        "sops_available": secrets.available(),
        "platform_secrets_present": sorted(platform_keys),
        "device_count": len(devices),
        "devices": devices,
        "kinds_missing": [k.value for k in DeviceKind if not inv.by_kind(k)],
    }


@tool("onboarding")
def next_step() -> dict[str, Any]:
    """The single most useful next onboarding action for the owner, with the exact command."""
    s = status()
    if not s["sops_available"]:
        return {"step": "install sops and age, then run `infra onboard init`"}
    required = {"anthropic_api_key", "telegram_bot_token", "telegram_owner_id", "heartbeat_url"}
    missing = sorted(required - set(s["platform_secrets_present"]))
    if missing:
        return {"step": "run `infra onboard init`", "missing_platform_secrets": missing}
    if s["device_count"] == 0:
        return {"step": "run `infra onboard add-device fortigate <mgmt-ip> --name fw-01`"}
    for d in s["devices"]:
        if d["credential_stored"] is False:
            cmd = f"infra onboard add-device {d['kind']} {d['mgmt_ip']} --name {d['name']}"
            return {"step": f"re-run `{cmd}`"}
        if d["probe_ok"] is False:
            return {"step": f"fix credential or reachability for {d['name']}, then re-add it"}
        if d["read_only"] is False:
            return {
                "step": f"{d['name']} collector credential is not read-only; run "
                f"`infra onboard accounts {d['name']}` and re-add with the new account"
            }
    if s["kinds_missing"]:
        return {"step": f"onboard the remaining device kinds: {', '.join(s['kinds_missing'])}"}
    return {"step": "run `infra onboard check` and fix anything red, then `infra collect`"}
