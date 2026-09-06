from infra_agent.collectors.fortigate import policy_row
from infra_agent.models.common import DeviceKind
from infra_agent.onboarding.accounts import account_commands
from infra_agent.onboarding.probes.cisco import parse_show_version

SHOW_VERSION_IOS = """Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.2(2)E8, RELEASE SOFTWARE (fc1)
sw-access-01 uptime is 3 weeks, 2 days
cisco WS-C2960-24TT-L (PowerPC405) processor (revision B0) with 65536K bytes of memory.
Model number                    : WS-C2960-24TT-L
System serial number            : FOC1234X5YZ
"""

SHOW_VERSION_XE = """Cisco IOS XE Software, Version 16.12.04
Cisco IOS Software [Gibraltar], Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.12.4, RELEASE SOFTWARE (fc5)
sw-core-01 uptime is 1 year, 4 weeks
Model Number                       : WS-C3850-24T
System Serial Number               : FCW5678A9BC
"""


def test_parse_show_version_classic_ios():
    ident = parse_show_version(SHOW_VERSION_IOS)
    assert ident == {
        "hostname": "sw-access-01",
        "version": "15.2(2)E8",
        "model": "WS-C2960-24TT-L",
        "serial": "FOC1234X5YZ",
        "os": "IOS",
    }


def test_parse_show_version_iosxe():
    ident = parse_show_version(SHOW_VERSION_XE)
    assert ident["os"] == "IOS-XE"
    assert ident["model"] == "WS-C3850-24T"
    assert ident["hostname"] == "sw-core-01"


def test_account_templates_are_least_privilege():
    fg = "\n".join(account_commands(DeviceKind.fortigate, "infra-ro", "pw", "10.0.0.50"))
    assert "set fwgrp read" in fg and "set ipv4-trusthost 10.0.0.50" in fg
    assert "read-write" not in fg
    esx = "\n".join(account_commands(DeviceKind.esxi, "infra-ro", "pw", "10.0.0.50"))
    assert "-r ReadOnly" in esx and "-c both" in esx
    ios = "\n".join(account_commands(DeviceKind.cisco_ios, "infra-ro", "pw", "10.0.0.50"))
    assert "privilege 15" in ios and "archive" in ios and "permit host 10.0.0.50" in ios
    ilo = "\n".join(account_commands(DeviceKind.ilo, "infra-ro", "pw", "10.0.0.50"))
    assert "\"LoginPriv\": true" in ilo and "\"iLOConfigPriv\": false" in ilo


def test_policy_row_flattens_names():
    row = policy_row(
        {
            "policyid": 7,
            "name": "lan-to-wan",
            "status": "enable",
            "action": "accept",
            "srcintf": [{"name": "lan"}],
            "dstintf": [{"name": "wan1"}, {"name": "wan2"}],
            "srcaddr": [{"name": "LAN_NET"}],
            "dstaddr": [{"name": "all"}],
            "service": [{"name": "HTTPS"}],
            "nat": "enable",
            "ips-sensor": "default",
        }
    )
    assert row["dstintf"] == ["wan1", "wan2"]
    assert row["utm"] == ["ips-sensor"]
    assert row["id"] == 7
