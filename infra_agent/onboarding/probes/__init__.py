from infra_agent.models.common import DeviceKind
from infra_agent.onboarding.probes.base import Probe


def get_probe(kind: DeviceKind) -> Probe:
    if kind is DeviceKind.fortigate:
        from infra_agent.onboarding.probes.fortigate import FortiGateProbe

        return FortiGateProbe()
    if kind in (DeviceKind.cisco_ios, DeviceKind.cisco_iosxe):
        from infra_agent.onboarding.probes.cisco import CiscoProbe

        return CiscoProbe()
    if kind is DeviceKind.esxi:
        from infra_agent.onboarding.probes.esxi import EsxiProbe

        return EsxiProbe()
    if kind is DeviceKind.ilo:
        from infra_agent.onboarding.probes.ilo import IloProbe

        return IloProbe()
    raise LookupError(kind)


__all__ = ["Probe", "get_probe"]
