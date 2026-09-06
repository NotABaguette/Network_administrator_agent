"""The corpus: every secret pattern seen in the wild goes here first. The
gateway must strip 100% of it."""

import json

import pytest

from infra_agent.redaction.gateway import RawConfigError, RedactionGateway

SECRET = "SuP3rS3cretValue"
HASH = "$9$abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"

CORPUS = [
    # cisco
    f"username infra-ro privilege 15 secret 9 {HASH}",
    f"username admin password 7 {SECRET}",
    "enable secret 5 $1$abcd$efghijklmnopqrstuvw",
    f"snmp-server community {SECRET} RO",
    f"snmp-server user infra INFRA-GRP v3 auth sha {SECRET} priv aes 128 {SECRET}",
    f"tacacs-server key 7 {SECRET}",
    f" key 7 {SECRET}",
    f"ntp authentication-key 1 md5 {SECRET} 7",
    f"crypto isakmp key {SECRET} address 203.0.113.9",
    f"%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:username test secret {SECRET}",
    # fortios
    f"set password ENC {'A' * 40}",
    f"set psksecret ENC {'B' * 64}",
    f"    set api-key {SECRET}",
    f'    set private-key "{SECRET}"',
    f'cfgattr="password[{SECRET}]"',
    # linux / esxi
    "root:$6$saltsalt$hashhashhashhashhashhash:19000:0:99999:7:::",
    f"esxcli system account set -i root --password={SECRET}",
    # keys and tokens
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nABC\n-----END RSA PRIVATE KEY-----",
    "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789",
    "123456789:ABCdefGHIjklMNOpqrsTUVwxyz0123456789abc",
    f"Authorization: Bearer {SECRET}{SECRET}",
    "token 0123456789abcdef0123456789abcdef01234567",
    f"AGE-SECRET-KEY-1{'Q' * 58}",
    # generic
    f"password: {SECRET}",
    f'"api_key": "{SECRET}"',
    f"community={SECRET}",
    f"https://admin:{SECRET}@10.0.0.1/api",
]


@pytest.mark.parametrize("sample", CORPUS)
def test_corpus_is_stripped(gateway: RedactionGateway, sample: str):
    out = gateway.redact_text(sample)
    assert SECRET not in out
    assert HASH not in out
    assert "MIIEow" not in out
    assert "sk-ant-api03" not in out
    assert "ABCdefGHIjklMNOpqrsTUVwxyz" not in out
    assert "0123456789abcdef0123456789abcdef01234567" not in out
    assert "QQQQQQQQ" not in out
    assert "$6$saltsalt$hash" not in out


def test_structure_is_preserved(gateway: RedactionGateway):
    payload = {"device": "sw-01", "lines": [f"snmp-server community {SECRET} RO", "hostname sw-01"]}
    out = gateway.redact(payload)
    assert out["device"] == "sw-01"
    assert out["lines"][1] == "hostname sw-01"
    assert SECRET not in json.dumps(out)


def test_public_ips_are_pseudonymised_and_reversible(gateway: RedactionGateway):
    text = "wan1 8.8.8.8 lan 10.0.0.1 wan2 1.1.1.1 again 8.8.8.8"
    masked = gateway.redact_text(text)
    assert "8.8.8.8" not in masked and "1.1.1.1" not in masked
    assert "10.0.0.1" in masked
    assert masked.count("PUBIP_1") == 2
    assert gateway.unmask(masked) == text


def test_raw_config_is_refused(gateway: RedactionGateway):
    raw = "Building configuration...\n" + "\n".join(f"interface Gi1/0/{i}" for i in range(30))
    with pytest.raises(RawConfigError):
        gateway.egress({"config": raw}, tool="device.show")


def test_egress_writes_audit(gateway: RedactionGateway):
    gateway.egress({"a": f"password={SECRET}"}, tool="inventory.get_device")
    entry = json.loads(gateway.audit_log.read_text().splitlines()[0])
    assert entry["tool"] == "inventory.get_device"
    assert SECRET not in json.dumps(entry)


@pytest.mark.parametrize(
    "platform,command,allowed",
    [
        ("cisco", "show version", True),
        ("cisco", "show interfaces status", True),
        ("cisco", "show cdp neighbors detail", True),
        ("cisco", "show mac address-table dynamic", True),
        ("cisco", "show running-config", False),
        ("cisco", "show run", False),
        ("cisco", "show tech-support", False),
        ("cisco", "show archive log config all", False),
        ("cisco", "show version | include uptime", False),
        ("cisco", "configure terminal", False),
        ("fortigate", "get system status", True),
        ("fortigate", "get router info routing-table all", True),
        ("fortigate", "show full-configuration", False),
        ("fortigate", "show", False),
        ("fortigate", "execute backup config tftp x 10.0.0.5", False),
        ("fortigate", "diagnose debug enable", False),
        ("esxi", "esxcli network vswitch standard list", True),
        ("esxi", "esxcli system account list", False),
        ("esxi", "cat /etc/shadow", False),
        ("ilo", "GET /redfish/v1/Systems/1", True),
        ("ilo", "PATCH /redfish/v1/Systems/1", False),
        ("ilo", "GET /redfish/v1/AccountService", False),
        ("unknown", "show version", False),
    ],
)
def test_command_allowlist(gateway: RedactionGateway, platform, command, allowed):
    assert gateway.is_command_allowed(platform, command) is allowed
