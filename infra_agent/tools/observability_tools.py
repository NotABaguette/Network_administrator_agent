"""Observability tools: Prometheus, Alertmanager, Loki and read-only `device.show`.

Everything here is read-only by construction:

* `device.show` turns a model-supplied string into a command that runs on a
  switch, a firewall or an ESXi shell, so it does not rely on the allowlist
  regexes alone. A command must survive three checks, in this order: a
  character allowlist (which rejects the embedded newline that would otherwise
  smuggle `configure terminal` past a `show ip route.*` pattern, and every
  shell metacharacter), the platform allowlist in
  `infra_agent/redaction/redaction.yaml`, and a per-platform structural check
  (`cisco` must be a `show`, `esxcli` must use a `get`/`list` verb). Only the
  normalised string is ever sent to the device.
* Every result leaves through `RedactionGateway.egress`, which also refuses
  anything that still looks like a raw device configuration.

Transports are injected (`configure`) so the tests drive fakes and never touch
a device or an HTTP endpoint.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any, Protocol

from infra_agent.config import Settings, get_settings
from infra_agent.models.common import Credential, SeedDevice, SeedInventory
from infra_agent.redaction.gateway import RedactionGateway
from infra_agent.tools.registry import tool

log = logging.getLogger(__name__)

MAX_LOG_LINES = 1000
MAX_LOG_MINUTES = 24 * 60

#: Everything an allowlisted read-only command needs, and nothing else. A
#: denylist of shell metacharacters is one forgotten character away from a
#: bypass; this is checked against the RAW command, before whitespace is
#: collapsed, because collapsing is what hides an embedded newline.
COMMAND_CHARSET = re.compile(r"^[A-Za-z0-9 _.:/@=,+-]+$")

#: The only `esxcli` verbs that read. The allow pattern in `redaction.yaml` is
#: a prefix match (`^esxcli (network|storage|...)\b`), so without this check
#: `esxcli network firewall set --enabled false` is "allowed".
ESXCLI_READ_VERBS = frozenset({"get", "list"})

#: FortiOS is queried through the read-only REST API rather than a CLI. Live
#: state comes from `monitor/...`; *configured* objects come from the read half
#: of the config API, `cmdb/...` (a plain GET). The distinction matters: asking
#: `monitor/firewall/policy` for the policies returns hit and byte counters
#: rather than the rules, and `monitor/firewall/address-dynamic` lists only
#: SDN-resolved addresses, not the address objects the owner configured.
FORTIOS_ENDPOINT_MAP: dict[str, str] = {
    "get system status": "monitor/system/status",
    "get system performance status": "monitor/system/resource/usage",
    "get system interface": "monitor/system/interface",
    "get system interface physical": "monitor/system/interface",
    "get system ha status": "monitor/system/ha-peer",
    "get system arp": "monitor/network/arp",
    "get system session status": "monitor/system/resource/usage",
    "get router info routing-table all": "monitor/router/ipv4",
    "get vpn ipsec tunnel summary": "monitor/vpn/ipsec",
    "get firewall policy": "cmdb/firewall/policy",
    "get firewall address": "cmdb/firewall/address",
    "get firewall service custom": "cmdb/firewall.service/custom",
    "get firewall vip": "cmdb/firewall/vip",
    "diagnose sys top": "monitor/system/resource/usage",
    "diagnose hardware sysinfo memory": "monitor/system/resource/usage",
    "diagnose hardware sysinfo cpu": "monitor/system/resource/usage",
    "diagnose ip arp list": "monitor/network/arp",
    "diagnose netlink interface list": "monitor/system/interface",
}

#: What the model would otherwise have to infer from an empty result.
FORTIOS_ENDPOINT_NOTES: dict[str, str] = {
    "get system ha status": (
        "this FortiGate 60F is standalone: an empty ha-peer list means there is no "
        "HA cluster, not that the query failed"
    ),
}

#: One poller at >=60s is what `docs/architecture.md` allows the 60F; a tool the
#: model can call in a loop gets its own floor.
FORTIGATE_MIN_INTERVAL_SECONDS = 2.0


def ssh_known_hosts() -> str | None:
    """Path to the operator's recorded host keys, when there is one.

    Until onboarding records a host key per device (a Phase 4 prerequisite:
    the ESXi SSH path is the one that will carry writes, and the Catalyst read
    account is priv-15), `INFRA_SSH_KNOWN_HOSTS` is the way to pin them. With
    it set, an unknown host key is a refusal rather than a warning.
    """
    value = os.environ.get("INFRA_SSH_KNOWN_HOSTS", "").strip()
    return value or None


def normalise_command(command: str) -> str:
    """The single spelling of a command that is checked *and* sent."""
    return " ".join(command.split())


def command_refusal(platform: str, command: str, gateway: RedactionGateway) -> str | None:
    """Why this command must not run, or None when it may. Never raises."""
    if not command.strip():
        return "no command was given"
    if not COMMAND_CHARSET.match(command):
        return (
            "the command contains characters that a read-only command never needs "
            "(control characters, newlines and shell metacharacters are refused)"
        )
    normalised = normalise_command(command)
    if not gateway.is_command_allowed(platform, normalised):
        return (
            "command is not on the read-only allowlist for platform "
            f"{platform}; see docs/redaction-policy.md"
        )
    if platform == "cisco" and not normalised.startswith("show "):
        return "only `show ...` commands are read-only on cisco"
    if platform == "esxi":
        return _esxi_refusal(normalised)
    return None


def _esxi_refusal(command: str) -> str | None:
    """ESXi runs this through a shell as the SSH user, so parse it as argv."""
    try:
        argv = shlex.split(command)
    except ValueError:
        return "the command could not be parsed into arguments"
    if not argv:
        return "empty command"
    if argv[0] == "vim-cmd":
        # The vim-cmd allow patterns are anchored and name read-only verbs.
        return None
    if argv[0] != "esxcli":
        return "only `esxcli` and `vim-cmd` are read-only on esxi"
    path = []
    for token in argv[1:]:
        if token.startswith("-"):
            break
        path.append(token)
    verb = path[-1] if path else ""
    if verb not in ESXCLI_READ_VERBS:
        return (
            f"esxcli verb {verb or '(none)'!r} is not read-only; "
            f"only {sorted(ESXCLI_READ_VERBS)} are allowed"
        )
    return None


class HttpTransport(Protocol):
    """Minimal JSON GET used for Prometheus, Alertmanager and Loki."""

    def get_json(self, url: str, params: dict[str, Any] | None = None) -> Any: ...


class DeviceTransport(Protocol):
    """Runs one already-allowlisted read-only command against one device."""

    def run(self, device: SeedDevice, cred: Credential | None, command: str) -> Any: ...


class RequestsHttpTransport:
    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout

    def get_json(self, url: str, params: dict[str, Any] | None = None) -> Any:
        import requests

        response = requests.get(url, params=params, timeout=self.timeout)
        response.raise_for_status()
        return response.json()


class CiscoShowTransport:
    """scrapli over SSH with the collector's read-only, priv-15 account."""

    def run(self, device: SeedDevice, cred: Credential | None, command: str) -> Any:
        from scrapli.driver.core import IOSXEDriver  # lazy: optional dependency

        if cred is None:
            raise LookupError(f"no stored credential for {device.name}")
        known_hosts = ssh_known_hosts()
        strict: dict[str, Any] = {"auth_strict_key": False}
        if known_hosts:
            strict = {"auth_strict_key": True, "ssh_known_hosts_file": known_hosts}
        driver = IOSXEDriver(
            host=device.mgmt_ip,
            port=device.port or 22,
            auth_username=cred.username or "",
            auth_password=cred.password.get_secret_value() if cred.password else "",
            transport="paramiko",
            timeout_socket=20,
            timeout_transport=30,
            timeout_ops=60,
            **strict,
        )
        with driver as conn:
            response = conn.send_command(command)
        if response.failed:
            raise RuntimeError(f"{command!r} failed on {device.name}")
        from infra_agent.collectors.cisco import parse

        platform = "cisco_ios"  # IOS-XE parses under the cisco_ios templates too
        return parse(platform, command, response.result)


class FortiGateShowTransport:
    """FortiOS REST API, GET only; the CLI is never used and never writes.

    One `requests.Session` per device is kept and reused: the 60F is a small box
    that `docs/architecture.md` gives one poller at >=60s, and a tool the model
    can call repeatedly should not open a new TLS session each time. Calls to the
    same device are also spaced by `FORTIGATE_MIN_INTERVAL_SECONDS`.
    """

    def __init__(self, timeout: float = 20.0) -> None:
        self.timeout = timeout
        self._sessions: dict[str, Any] = {}
        self._last_call: dict[str, float] = {}
        self._lock = threading.Lock()

    def session(self, device: SeedDevice, cred: Credential) -> Any:
        import requests

        with self._lock:
            session = self._sessions.get(device.name)
            if session is None:
                session = requests.Session()
                # TLS pinning is a Phase 1 decision; until it lands this mirrors
                # the collector rather than inventing a second policy.
                session.verify = False
                self._sessions[device.name] = session
            token = cred.token.get_secret_value() if cred.token else ""
            session.headers["Authorization"] = f"Bearer {token}"
            return session

    def _throttle(self, device: SeedDevice) -> None:
        with self._lock:
            last = self._last_call.get(device.name)
            now = time.monotonic()
            wait = 0.0 if last is None else FORTIGATE_MIN_INTERVAL_SECONDS - (now - last)
            self._last_call[device.name] = now + max(wait, 0.0)
        if wait > 0:
            time.sleep(wait)

    def run(self, device: SeedDevice, cred: Credential | None, command: str) -> Any:
        if cred is None or not cred.token:
            raise LookupError(f"no API token credential for {device.name}")
        normalised = normalise_command(command)
        endpoint = FORTIOS_ENDPOINT_MAP.get(normalised)
        if endpoint is None:
            raise LookupError(f"no read-only REST mapping for {command!r}")
        self._throttle(device)
        session = self.session(device, cred)
        base = f"https://{device.mgmt_ip}:{device.port or 443}/api/v2/"
        response = session.get(base + endpoint, timeout=self.timeout)
        response.raise_for_status()
        body = response.json()
        results = body.get("results", body) if isinstance(body, dict) else body
        # The endpoint is part of the answer: `cmdb/firewall/policy` is the rules,
        # `monitor/firewall/policy` would have been the counters.
        payload: dict[str, Any] = {"endpoint": f"api/v2/{endpoint}", "results": results}
        note = FORTIOS_ENDPOINT_NOTES.get(normalised)
        if note:
            payload["note"] = note
        return payload


class EsxiShowTransport:
    """SSH (`esxcli` / `vim-cmd`); hostd's API is read-only for us and often licensed off."""

    def __init__(self, timeout: float = 30.0) -> None:
        self.timeout = timeout

    def run(self, device: SeedDevice, cred: Credential | None, command: str) -> Any:
        import paramiko  # lazy: optional dependency

        if cred is None:
            raise LookupError(f"no stored credential for {device.name}")
        # `exec_command` still reaches a shell, which is why `command_refusal`
        # rejects every metacharacter before anything gets here.
        command = " ".join(shlex.split(normalise_command(command)))
        client = paramiko.SSHClient()
        known_hosts = ssh_known_hosts()
        if known_hosts:
            client.load_host_keys(known_hosts)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=device.mgmt_ip,
                port=device.port or 22,
                username=cred.username,
                password=cred.password.get_secret_value() if cred.password else None,
                key_filename=cred.ssh_key_path,
                timeout=self.timeout,
            )
            _, stdout, stderr = client.exec_command(command, timeout=self.timeout)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
        finally:
            client.close()
        if err.strip() and not out.strip():
            raise RuntimeError(err.strip()[:200])
        return out


class PlatformDeviceTransport:
    """Dispatches to the right read-only transport for the device's platform."""

    def __init__(self, **overrides: DeviceTransport) -> None:
        self.by_platform: dict[str, DeviceTransport] = {
            "cisco": CiscoShowTransport(),
            "fortigate": FortiGateShowTransport(),
            "esxi": EsxiShowTransport(),
        }
        self.by_platform.update(overrides)

    def run(self, device: SeedDevice, cred: Credential | None, command: str) -> Any:
        transport = self.by_platform.get(device.platform)
        if transport is None:
            raise LookupError(f"no read-only transport for platform {device.platform}")
        return transport.run(device, cred, command)


def _load_inventory() -> SeedInventory:
    return SeedInventory.load(get_settings().seed_inventory)


def _load_credential(device: SeedDevice) -> Credential | None:
    from infra_agent.onboarding.secrets import SecretsStore

    store = SecretsStore(get_settings().secrets_dir)
    if not store.available():
        return None
    raw = store.read("devices").get(device.credential_ref)
    return Credential.model_validate(raw) if raw else None


@dataclass
class Deps:
    """Everything the tools in this module talk to. Replaced wholesale in tests."""

    settings: Settings
    gateway: RedactionGateway
    http: HttpTransport
    devices: DeviceTransport
    inventory: Callable[[], SeedInventory]
    credentials: Callable[[SeedDevice], Credential | None]


_deps: Deps | None = None


def deps() -> Deps:
    global _deps
    if _deps is None:
        settings = get_settings()
        _deps = Deps(
            settings=settings,
            gateway=RedactionGateway(audit_log=settings.audit_log),
            http=RequestsHttpTransport(),
            devices=PlatformDeviceTransport(),
            inventory=_load_inventory,
            credentials=_load_credential,
        )
    return _deps


def configure(**overrides: Any) -> Deps:
    """Replace some of the tool dependencies (tests, and service wiring)."""
    global _deps
    _deps = replace(deps(), **overrides)
    return _deps


def reset() -> None:
    global _deps
    _deps = None


# -- metrics ----------------------------------------------------------------
@tool("metrics")
def promql(query: str) -> dict[str, Any]:
    """Run an instant PromQL query against Prometheus and return the samples as rows.

    Args:
        query: PromQL expression, for example `up{job="cisco"}`.
    """
    d = deps()
    url = d.settings.prometheus_url.rstrip("/") + "/api/v1/query"
    try:
        body = d.http.get_json(url, {"query": query})
    except Exception as exc:
        return dict(d.gateway.egress(_error("metrics.promql", exc, query=query), "metrics.promql"))
    data = body.get("data", {}) if isinstance(body, dict) else {}
    rows = []
    for item in data.get("result", []) or []:
        value = item.get("value") or (item.get("values") or [[None, None]])[-1]
        rows.append(
            {
                "labels": item.get("metric", {}),
                "at": value[0] if value else None,
                "value": value[1] if value and len(value) > 1 else None,
            }
        )
    payload = {
        "query": query,
        "result_type": data.get("result_type") or data.get("resultType"),
        "row_count": len(rows),
        "rows": rows,
    }
    return dict(d.gateway.egress(payload, tool="metrics.promql"))


@tool("metrics")
def alerts_active() -> dict[str, Any]:
    """List the alerts Alertmanager currently considers active, grouped and deduplicated."""
    d = deps()
    url = d.settings.alertmanager_url.rstrip("/") + "/api/v2/alerts"
    try:
        body = d.http.get_json(url, {"active": "true", "silenced": "false", "inhibited": "false"})
    except Exception as exc:
        return dict(d.gateway.egress(_error("metrics.alerts_active", exc), "metrics.alerts_active"))
    rows = []
    for alert in body or []:
        status = alert.get("status") or {}
        rows.append(
            {
                "fingerprint": alert.get("fingerprint"),
                "state": status.get("state"),
                "labels": alert.get("labels", {}),
                "annotations": alert.get("annotations", {}),
                "starts_at": alert.get("startsAt"),
                "ends_at": alert.get("endsAt"),
            }
        )
    payload = {"alert_count": len(rows), "alerts": rows}
    return dict(d.gateway.egress(payload, tool="metrics.alerts_active"))


# -- logs -------------------------------------------------------------------
@tool("logs")
def logql(query: str, minutes: int = 60, limit: int = 200) -> dict[str, Any]:
    """Query Loki over a recent time window and return the matching log lines.

    Args:
        query: LogQL selector, for example `{job="syslog", host="sw-core-01"}`.
        minutes: How far back to look, capped at 24 hours.
        limit: Maximum lines to return, capped at 1000.
    """
    d = deps()
    minutes = max(1, min(int(minutes), MAX_LOG_MINUTES))
    limit = max(1, min(int(limit), MAX_LOG_LINES))
    end = time.time()
    start = end - minutes * 60
    url = d.settings.loki_url.rstrip("/") + "/loki/api/v1/query_range"
    params = {
        "query": query,
        "start": int(start * 1e9),
        "end": int(end * 1e9),
        "limit": limit,
        "direction": "backward",
    }
    try:
        body = d.http.get_json(url, params)
    except Exception as exc:
        return dict(d.gateway.egress(_error("logs.logql", exc, query=query), "logs.logql"))
    data = body.get("data", {}) if isinstance(body, dict) else {}
    rows: list[dict[str, Any]] = []
    for stream in data.get("result", []) or []:
        labels = stream.get("stream", {})
        for entry in stream.get("values", []) or []:
            if len(entry) < 2:
                continue
            rows.append({"at_ns": entry[0], "labels": labels, "line": entry[1]})
    rows.sort(key=lambda row: str(row["at_ns"]), reverse=True)
    payload = {
        "query": query,
        "minutes": minutes,
        "limit": limit,
        "line_count": len(rows[:limit]),
        "lines": rows[:limit],
    }
    return dict(d.gateway.egress(payload, tool="logs.logql"))


# -- device -----------------------------------------------------------------
@tool("device", parallel_safe=False)
def show(device: str, command: str) -> dict[str, Any]:
    """Run one read-only show command on a device and return the parsed result.

    The command must be on the read-only allowlist for that device's platform;
    anything that could reveal a raw configuration or a secret is refused.

    Args:
        device: Device name as it appears in the inventory, for example `sw-core-01`.
        command: The read-only command, for example `show interfaces status`.
    """
    d = deps()
    target = d.inventory().get(device)
    if target is None:
        return dict(
            d.gateway.egress(
                {
                    "device": device,
                    "command": normalise_command(command),
                    "error": f"unknown device {device!r}",
                },
                tool="device.show",
            )
        )
    refusal = command_refusal(target.platform, command, d.gateway)
    if refusal is not None:
        # `command` is logged as the model wrote it, so a bypass attempt is
        # visible in the log; only the normalised form is ever reported or run.
        log.warning("refused %r on %s (%s): %s", command, device, target.platform, refusal)
        return dict(
            d.gateway.egress(
                {
                    "device": device,
                    "platform": target.platform,
                    "command": normalise_command(command),
                    "allowed": False,
                    "error": refusal,
                },
                tool="device.show",
            )
        )
    # From here on only the normalised command exists: the transport never sees
    # the string the model actually sent.
    normalised = normalise_command(command)
    try:
        cred = d.credentials(target)
        output = d.devices.run(target, cred, normalised)
    except Exception as exc:
        return dict(
            d.gateway.egress(
                _error("device.show", exc, device=device, command=normalised, allowed=True),
                tool="device.show",
            )
        )
    payload = {
        "device": device,
        "platform": target.platform,
        "command": normalised,
        "allowed": True,
        "output": output,
    }
    return dict(d.gateway.egress(payload, tool="device.show"))


def _error(tool_name: str, exc: Exception, **extra: Any) -> dict[str, Any]:
    log.warning("%s failed: %s", tool_name, exc)
    return {**extra, "error": f"{type(exc).__name__}: {exc}"}
