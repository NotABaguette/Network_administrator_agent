"""Observability tool tests. The allowlist is the interesting one: `device.show`
must refuse anything that could return a raw config or a secret, and must refuse
it *before* it opens a session to the device.
"""

from __future__ import annotations

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
    assert "allowlist" in result["error"]
    assert wired.devices.calls == [], "a refused command never opens a session"


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


def test_the_fortios_monitor_map_only_covers_read_only_endpoints():
    for command, endpoint in obs.FORTIOS_MONITOR_MAP.items():
        assert endpoint.startswith("monitor/"), command
        assert "backup" not in endpoint and "cmdb" not in endpoint, command


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
