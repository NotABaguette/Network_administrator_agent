from infra_agent.change.executors.base import EXECUTORS, get_executor, load_all
from infra_agent.models.common import DeviceKind


def test_executor_registry_loads_without_error():
    load_all()
    assert isinstance(EXECUTORS, dict)


def test_unknown_platform_is_a_lookup_error():
    import pytest

    with pytest.raises(LookupError):
        get_executor("no-such-platform")


def test_guest_kinds_share_the_guest_platform():
    assert DeviceKind.guest_linux.platform == "guest"
    assert DeviceKind.guest_windows.platform == "guest"
    assert DeviceKind.cisco_iosxe.platform == "cisco"
