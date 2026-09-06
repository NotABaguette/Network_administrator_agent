from __future__ import annotations

from abc import ABC, abstractmethod

from infra_agent.models.common import Credential, ProbeResult, SeedDevice


class Probe(ABC):
    """Connects with the supplied credential, records identity and privilege level.

    A probe never changes anything on the device and never returns the credential.
    """

    @abstractmethod
    def probe(self, device: SeedDevice, cred: Credential) -> ProbeResult: ...

    @staticmethod
    def failure(exc: Exception) -> ProbeResult:
        return ProbeResult(ok=False, error=f"{type(exc).__name__}: {exc}")
