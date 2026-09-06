from __future__ import annotations

import requests

from infra_agent.models.common import Credential, ProbeResult, SeedDevice
from infra_agent.onboarding.probes.base import Probe


class IloProbe(Probe):
    def probe(self, device: SeedDevice, cred: Credential) -> ProbeResult:
        base = f"https://{device.mgmt_ip}:{device.port or 443}"
        auth = (cred.username or "", cred.password.get_secret_value() if cred.password else "")
        s = requests.Session()
        s.verify = False  # pin in Phase 1
        try:
            system = s.get(f"{base}/redfish/v1/Systems/1", auth=auth, timeout=15)
            system.raise_for_status()
            sysj = system.json()
            manager = s.get(f"{base}/redfish/v1/Managers/1", auth=auth, timeout=15).json()
            identity = {
                "model": sysj.get("Model"),
                "serial": sysj.get("SerialNumber"),
                "bios": (
                    sysj.get("BiosVersion")
                    or (sysj.get("Oem", {}).get("Hpe", {}) or sysj.get("Oem", {}).get("Hp", {}))
                    .get("Bios", {})
                    .get("Current", {})
                    .get("VersionString")
                ),
                "ilo_firmware": manager.get("FirmwareVersion"),
                "ilo_generation": "iLO5+" if "Hpe" in sysj.get("Oem", {}) else "iLO4",
            }
            warnings = []
            privilege, read_only = "unknown", None
            accounts = s.get(f"{base}/redfish/v1/AccountService/Accounts", auth=auth, timeout=15)
            if accounts.status_code == 200:
                for member in accounts.json().get("Members", []):
                    acc = s.get(base + member["@odata.id"], auth=auth, timeout=15).json()
                    if acc.get("UserName") == cred.username:
                        oem = acc.get("Oem", {}).get("Hpe") or acc.get("Oem", {}).get("Hp") or {}
                        privs = oem.get("Privileges", {})
                        writes = [k for k, v in privs.items() if v and k != "LoginPriv"]
                        privilege = acc.get("RoleId") or ("ReadOnly" if not writes else "Operator+")
                        read_only = not writes
            else:
                warnings.append("cannot list accounts; privilege unverified")
            if identity["ilo_generation"] == "iLO4":
                warnings.append("iLO4: poll no more than every 5 minutes and reuse sessions")
            return ProbeResult(
                ok=True,
                identity=identity,
                privilege=privilege,
                read_only=read_only,
                warnings=warnings,
            )
        except requests.RequestException as exc:
            return self.failure(exc)
