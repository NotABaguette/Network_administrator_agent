from __future__ import annotations

import ssl

from infra_agent.models.common import Credential, ProbeResult, SeedDevice
from infra_agent.onboarding.probes.base import Probe


class EsxiProbe(Probe):
    def probe(self, device: SeedDevice, cred: Credential) -> ProbeResult:
        try:
            from pyVim.connect import Disconnect, SmartConnect
        except ImportError as exc:  # pragma: no cover
            return ProbeResult(ok=False, error=f"pyvmomi not installed: {exc}")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # pin the thumbprint in Phase 1
        try:
            si = SmartConnect(
                host=device.mgmt_ip,
                port=device.port or 443,
                user=cred.username,
                pwd=cred.password.get_secret_value() if cred.password else "",
                sslContext=ctx,
            )
        except Exception as exc:
            return self.failure(exc)
        try:
            content = si.RetrieveContent()
            about = content.about
            host = content.rootFolder.childEntity[0].hostFolder.childEntity[0].host[0]
            session_id = content.sessionManager.currentSession.key
            can_write = content.authorizationManager.HasPrivilegeOnEntity(
                host, session_id, ["Host.Config.Settings", "VirtualMachine.Interact.PowerOn"]
            )
            license_name = None
            try:
                lic = content.licenseManager.licenses
                license_name = lic[0].name if lic else None
            except Exception:
                pass
            identity = {
                "hostname": host.name,
                "build": about.build,
                "version": about.version,
                "product": about.fullName,
                "license": license_name,
            }
            warnings = []
            if license_name and "Hypervisor" in license_name:
                warnings.append("free license: API writes are blocked; executor will use SSH")
            return ProbeResult(
                ok=True,
                identity=identity,
                privilege="admin" if any(can_write) else "read-only",
                read_only=not any(can_write),
                warnings=warnings,
            )
        except Exception as exc:
            return self.failure(exc)
        finally:
            Disconnect(si)
