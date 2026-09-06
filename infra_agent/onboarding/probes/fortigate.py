from __future__ import annotations

from typing import Any

import requests

from infra_agent.models.common import Credential, ProbeResult, SeedDevice
from infra_agent.onboarding.probes.base import Probe

READ_SCOPES = {"read", "none", ""}


class FortiGateProbe(Probe):
    def probe(self, device: SeedDevice, cred: Credential) -> ProbeResult:
        if not cred.token:
            return ProbeResult(ok=False, error="FortiGate probe needs a REST API token")
        base = f"https://{device.mgmt_ip}:{device.port or 443}/api/v2"
        headers = {"Authorization": f"Bearer {cred.token.get_secret_value()}"}
        session = requests.Session()
        session.verify = False  # self-signed by default; pin the cert in Phase 1
        try:
            status = session.get(f"{base}/monitor/system/status", headers=headers, timeout=10)
            status.raise_for_status()
            results = status.json().get("results", {})
            identity = {
                "hostname": results.get("hostname"),
                "serial": status.json().get("serial"),
                "version": status.json().get("version"),
                "model": results.get("model_name"),
            }
            warnings: list[str] = []
            privilege, read_only = self._privilege(session, base, headers, warnings)
            return ProbeResult(
                ok=True,
                identity=identity,
                privilege=privilege,
                read_only=read_only,
                warnings=warnings,
            )
        except requests.RequestException as exc:
            return self.failure(exc)

    @staticmethod
    def _privilege(
        session: requests.Session, base: str, headers: dict[str, str], warnings: list[str]
    ) -> tuple[str, bool | None]:
        users = session.get(f"{base}/cmdb/system/api-user", headers=headers, timeout=10)
        if users.status_code != 200:
            warnings.append("cannot read api-user list; privilege unverified")
            return "unknown", None
        # The API cannot tell which api-user the token belongs to; when there is
        # exactly one api-user we know, otherwise report all profiles seen.
        profiles: list[dict[str, Any]] = []
        for user in users.json().get("results", []):
            prof_name = user.get("accprofile")
            prof = session.get(
                f"{base}/cmdb/system/accprofile/{prof_name}", headers=headers, timeout=10
            )
            if prof.status_code == 200:
                profiles.append({"user": user.get("name"), **prof.json()["results"][0]})
        if not profiles:
            return "unknown", None
        if len(profiles) > 1:
            warnings.append("several api-users exist; verify which one this token belongs to")
        prof = profiles[0]
        scope_keys = [
            k for k in prof if k.endswith("grp") or k in ("system", "admintimeout-override")
        ]
        writes = [k for k in scope_keys if str(prof.get(k, "")).lower() not in READ_SCOPES]
        read_only = not writes
        return (prof.get("name") or prof["user"]), read_only
