"""Catalyst executor: IOS and IOS-XE, over scrapli, with a timed rollback.

The rollback strategy is fixed by `docs/architecture.md` and by
`infra_agent/change/executors/base.py`:

    configure terminal revert timer <N>     # arms an automatic rollback
    ... the action's configuration ...
    end
    <post-checks run here>
    configure confirm                       # keeps the change
    configure revert now                    # or throws it away

Never `reload in`: a reload takes the whole switch down, and the point of the
revert timer is that a change that cuts the session off undoes itself while
everything else keeps running. `configure revert now` restores the archived
configuration taken when the timer was armed, so it also undoes the later steps
of a multi-step plan.

Three properties this module enforces rather than assumes:

* **The revert timer needs the archive feature.** Without `archive` + `path`,
  `configure terminal revert timer` has nothing to roll back to and the safety
  net is imaginary. `dry_run` runs `show archive` and blocks with the exact
  remediation when it is not configured; `apply` re-checks, because a plan may
  sit approved for hours.
* **Only the action's own commands are ever sent.** Every line is rendered from
  a template in `_config_lines`, every parameter is validated (VLAN ids, an
  interface-name charset, a description charset), and `_assert_safe` refuses
  anything matching `reload`, `write erase`, a bare `configure replace`, `erase`,
  `format`, `delete` or `boot` even if a template were ever changed to emit one.
* **Raw configuration stays on this side of the process.** `show
  running-config interface X` and `show vlan brief` are parsed here into a
  structured before/after; only that structure goes into the plan, and so only
  that structure can reach the model.

`show` output differs between classic IOS (2960 / 3560 / 3750) and IOS-XE
(3650 / 3850): the CDP `Device ID:` separator, the interface names
(`GigabitEthernet1/0/5` versus `Gi1/0/5`), the extra err-disabled VLAN column
and the multicast sections of the MAC table. The parsers here are written
against both, and `tests/test_executor_cisco.py` feeds them both.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any, Protocol

from infra_agent.change.executors.base import (
    CheckResult,
    DryRunResult,
    ExecutionContext,
    Executor,
    StepResult,
    register,
)
from infra_agent.change.plan import ChangeStep
from infra_agent.correlate.parsing import expand_vlan_list
from infra_agent.models.common import Credential, SeedDevice

log = logging.getLogger(__name__)

#: How long the switch waits for `configure confirm` before undoing the change.
#: Long enough for the post-checks (a few `show` commands), short enough that a
#: change which cut our own session off is gone before anyone is paged.
DEFAULT_REVERT_TIMER_MINUTES = 5

#: Exactly what to paste into the switch when `show archive` says the feature is
#: off. Without it `configure terminal revert timer` cannot roll anything back.
ARCHIVE_REMEDIATION = (
    "the archive feature is not configured, so `configure terminal revert timer` "
    "has no checkpoint to roll back to. Configure it first:\n"
    "  archive\n"
    "   path flash:archive\n"
    "   maximum 10\n"
    "   write-memory\n"
    "(use `path bootflash:archive` on IOS-XE), then dry-run this plan again."
)

#: A line the executor must never send, whatever a template says. `configure
#: replace` is here because it is the un-timed cousin of the revert vocabulary:
#: the allowed forms are matched first in `_assert_safe`.
FORBIDDEN_COMMAND = re.compile(
    r"^\s*(?:reload\b|write\s+erase\b|erase\b|format\b|delete\b|boot\b|"
    r"configure\s+replace\b|archive\s+tar\b|copy\b|no\s+archive\b|"
    r"crypto\b|username\b|enable\s+secret\b|enable\s+password\b|snmp-server\b)",
    re.IGNORECASE,
)

#: The revert vocabulary, allowed verbatim and nothing like it.
_REVERT_COMMANDS = re.compile(
    r"^configure (?:confirm|revert now|terminal(?: revert timer \d+)?)$", re.IGNORECASE
)

#: An interface name as a human writes it. No spaces, no punctuation a name
#: never needs, so nothing can smuggle a second command onto the line.
INTERFACE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]*[0-9](?:[/.:][0-9]+)*$")

#: A port description. Free text, but not free enough to contain a newline.
DESCRIPTION_CHARSET = re.compile(r"^[A-Za-z0-9 _.:/@=,+()\[\]#'-]{0,200}$")

#: A VLAN name as IOS accepts it.
VLAN_NAME_CHARSET = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")

#: Every status `show interfaces status` prints, lowercased. The name column is
#: free text and may be empty, so the status column is found by its vocabulary
#: rather than by counting fields.
INTERFACE_STATUSES = frozenset(
    {
        "connected",
        "notconnect",
        "disabled",
        "err-disabled",
        "errdisable",
        "monitoring",
        "inactive",
        "suspended",
        "sfpabsent",
        "noopermem",
    }
)

SUPPORTED_ACTIONS = frozenset(
    {
        "vlan.add",
        "vlan.remove",
        "switch.access_port_config",
        "switch.clear_errdisable",
        "switch.trunk_port_config",
    }
)

#: Long name -> the abbreviation `show` output uses, longest first so
#: `TenGigabitEthernet` never matches as `Ethernet`.
_INTERFACE_ABBREVIATIONS: tuple[tuple[str, str], ...] = (
    ("twentyfivegige", "twe"),
    ("tengigabitethernet", "te"),
    ("fortygigabitethernet", "fo"),
    ("hundredgige", "hu"),
    ("appgigabitethernet", "ap"),
    ("gigabitethernet", "gi"),
    ("fastethernet", "fa"),
    ("port-channel", "po"),
    ("portchannel", "po"),
    ("loopback", "lo"),
    ("vlan", "vl"),
    ("ethernet", "et"),
)


class CiscoError(RuntimeError):
    """A command failed on the switch, or was refused before it was sent."""


class UnsupportedStep(CiscoError):
    """The step is not something this executor knows how to render."""


def normalise_interface(name: str) -> str:
    """`GigabitEthernet1/0/5`, `Gi1/0/5` and `gi1/0/5` become one comparable key."""
    token = str(name).strip().lower().replace(" ", "")
    for long, short in _INTERFACE_ABBREVIATIONS:
        if token.startswith(long):
            return short + token[len(long) :]
    match = re.match(r"^([a-z-]+)(.*)$", token)
    if not match:
        return token
    head, tail = match.groups()
    for long, short in _INTERFACE_ABBREVIATIONS:
        if long.startswith(head) and len(head) >= 2:
            return short + tail
    return token


def _assert_safe(command: str) -> str:
    """The last gate before a line reaches the switch."""
    line = " ".join(str(command).split())
    if not line:
        raise CiscoError("refusing to send an empty command")
    if "\n" in command or "\r" in command:
        raise CiscoError("refusing to send a command containing a newline")
    if _REVERT_COMMANDS.match(line):
        return line
    if FORBIDDEN_COMMAND.match(line):
        raise CiscoError(f"refusing to send {line!r}: it is outside the action's command template")
    return line


def _vlan_id(value: Any, field: str = "vlan") -> int:
    try:
        vlan = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise UnsupportedStep(f"{field} {value!r} is not a VLAN id") from exc
    if not 1 <= vlan <= 4094:
        raise UnsupportedStep(f"{field} {vlan} is outside 1-4094")
    return vlan


def _interface(value: Any) -> str:
    name = str(value or "").strip()
    if not INTERFACE_NAME.match(name):
        raise UnsupportedStep(f"{name!r} is not an interface name")
    return name


def _vlan_list(value: Any, field: str) -> list[int]:
    vlans = sorted(expand_vlan_list(value))
    if not vlans:
        raise UnsupportedStep(f"{field} does not name any VLAN")
    for vlan in vlans:
        _vlan_id(vlan, field)
    return vlans


def _vlan_range(vlans: Sequence[int]) -> str:
    return ",".join(str(v) for v in vlans)


# -- the session ------------------------------------------------------------
class CiscoSession(Protocol):
    """One line in, its output back. The whole surface the executor needs.

    Keeping it this small is what lets `tests/test_executor_cisco.py` assert the
    exact command sequence, revert timer and all, without a device.
    """

    def send(self, command: str) -> str: ...


ConnectFactory = Callable[[SeedDevice, Credential], Any]


class ScrapliSession:
    """A `CiscoSession` over an open scrapli driver.

    `channel.send_input` is used rather than `send_command` because the config
    mode is entered with `configure terminal revert timer N`, which is not a
    command scrapli's privilege handling knows how to enter on its own. The
    IOS-XE prompt pattern matches `sw(config)#` and `sw(config-if)#`, so reading
    to the prompt works in every mode this executor uses.
    """

    #: How IOS reports a rejected command.
    _ERROR = re.compile(r"^%\s*\S", re.MULTILINE)

    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def send(self, command: str) -> str:
        line = _assert_safe(command)
        raw = self.connection.channel.send_input(line)
        output = _as_text(raw)
        if self._ERROR.search(output):
            raise CiscoError(f"{line!r} was rejected: {output.strip().splitlines()[0][:160]}")
        return output


def _as_text(value: Any) -> str:
    """scrapli returns bytes, a (raw, processed) pair, or a Response."""
    if isinstance(value, tuple):
        value = value[-1]
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    if isinstance(value, str):
        return value
    if getattr(value, "failed", False):
        raise CiscoError("the switch reported the command as failed")
    result = getattr(value, "result", None)
    return result if isinstance(result, str) else str(value)


@contextmanager
def scrapli_session(device: SeedDevice, credential: Credential) -> Iterator[CiscoSession]:
    """Open a read-write session to a Catalyst. The credential is never logged."""
    from scrapli.driver.core import IOSXEDriver  # lazy: optional dependency

    from infra_agent.tools.observability_tools import ssh_known_hosts

    known_hosts = ssh_known_hosts()
    strict: dict[str, Any] = {"auth_strict_key": False}
    if known_hosts:
        strict = {"auth_strict_key": True, "ssh_known_hosts_file": known_hosts}
    kwargs: dict[str, Any] = {
        "host": device.mgmt_ip,
        "port": device.port or 22,
        "auth_username": credential.username or "",
        "auth_password": credential.password.get_secret_value() if credential.password else "",
        "transport": "paramiko",
        "timeout_socket": 20,
        "timeout_transport": 30,
        "timeout_ops": 60,
        **strict,
    }
    if device.legacy_ssh:
        # The old 2960s only offer legacy key exchange and ciphers. Paramiko
        # takes that from the operator's ssh config rather than from scrapli, so
        # this is recorded on the connection and configured there (the same way
        # the collector reaches those switches).
        kwargs["ssh_config_file"] = True
    driver = IOSXEDriver(**kwargs)
    with driver as connection:
        yield ScrapliSession(connection)


# -- parsers (classic IOS and IOS-XE) ---------------------------------------
def parse_archive(output: str) -> bool:
    """True when the archive feature has a path, on either platform.

    Both print `The next archive file will be named ...` once `archive path` is
    set; without it IOS says `%Archive feature not enabled` and IOS-XE prints
    the header alone.
    """
    if re.search(r"^%", output or "", re.MULTILINE):
        return False
    return "the next archive file will be named" in (output or "").lower()


def parse_vlan_brief(output: str) -> dict[int, dict[str, Any]]:
    """`show vlan brief` -> {vlan: {name, status, ports}} on IOS and IOS-XE.

    The port column wraps onto continuation lines on both platforms; a line that
    does not start with a VLAN id extends the previous VLAN's port list.
    """
    vlans: dict[int, dict[str, Any]] = {}
    current: dict[str, Any] | None = None
    for raw in (output or "").splitlines():
        line = raw.rstrip()
        if not line.strip() or set(line.strip()) <= {"-", " "}:
            continue
        if line.lstrip().lower().startswith("vlan "):
            continue  # header
        head = re.match(r"^(\d{1,4})\s+(\S+)\s+(\S+)\s*(.*)$", line)
        if head:
            vlan_id, name, status, ports = head.groups()
            current = {
                "name": name,
                "status": status,
                "ports": [p.strip() for p in ports.split(",") if p.strip()],
            }
            vlans[int(vlan_id)] = current
            continue
        if current is not None and line.startswith((" ", "\t")):
            current["ports"].extend(p.strip() for p in line.split(",") if p.strip())
    return vlans


def parse_interface_status(output: str) -> dict[str, dict[str, str]]:
    """`show interfaces status` -> {normalised interface: {status, vlan, name}}.

    The columns are fixed-width on both platforms but the name column may be
    empty, so the status is found by its known vocabulary rather than by index.
    """
    rows: dict[str, dict[str, str]] = {}
    for raw in (output or "").splitlines():
        line = raw.rstrip()
        tokens = line.split()
        if len(tokens) < 2 or line.lower().startswith("port "):
            continue
        status_index = next(
            (i for i, t in enumerate(tokens[1:], start=1) if t.lower() in INTERFACE_STATUSES),
            None,
        )
        if status_index is None:
            continue
        rows[normalise_interface(tokens[0])] = {
            "interface": tokens[0],
            "name": " ".join(tokens[1:status_index]),
            "status": tokens[status_index],
            "vlan": tokens[status_index + 1] if len(tokens) > status_index + 1 else "",
        }
    return rows


def parse_errdisabled(output: str) -> dict[str, str]:
    """`show interfaces status err-disabled` -> {normalised interface: reason}.

    IOS-XE adds an `Err-disabled Vlans` column after the reason; the reason is
    the token that follows the `err-disabled` status either way.
    """
    rows: dict[str, str] = {}
    for raw in (output or "").splitlines():
        tokens = raw.split()
        if len(tokens) < 2 or raw.lower().startswith("port "):
            continue
        lowered = [t.lower() for t in tokens]
        if "err-disabled" not in lowered and "errdisable" not in lowered:
            continue
        index = lowered.index("err-disabled" if "err-disabled" in lowered else "errdisable")
        rows[normalise_interface(tokens[0])] = tokens[index + 1] if len(tokens) > index + 1 else ""
    return rows


def parse_cdp_detail(output: str) -> list[dict[str, str]]:
    """`show cdp neighbors detail` -> [{device_id, local_interface, platform}].

    Classic IOS prints `Device ID:sw-02`, IOS-XE prints `Device ID: sw-02`.
    """
    entries: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for raw in (output or "").splitlines():
        line = raw.strip()
        device = re.match(r"^Device ID\s*:\s*(\S+)", line, re.IGNORECASE)
        if device:
            if current:
                entries.append(current)
            current = {"device_id": device.group(1), "local_interface": "", "platform": ""}
            continue
        local = re.match(r"^Interface\s*:\s*([^,]+)", line, re.IGNORECASE)
        if local and current:
            current["local_interface"] = local.group(1).strip()
            continue
        platform = re.match(r"^Platform\s*:\s*([^,]+)", line, re.IGNORECASE)
        if platform and current:
            current["platform"] = platform.group(1).strip()
    if current:
        entries.append(current)
    return entries


def parse_mac_table(output: str) -> list[dict[str, str]]:
    """`show mac address-table` -> [{vlan, mac, type, port}], dynamic and static.

    Skips the CPU and multicast rows IOS-XE prints (`All 0100.0ccc.cccc STATIC
    CPU`) and the `Total Mac Addresses` footer both platforms print.
    """
    rows: list[dict[str, str]] = []
    for raw in (output or "").splitlines():
        tokens = raw.split()
        if len(tokens) < 4 or not tokens[0].isdigit():
            continue
        vlan, mac, kind, port = tokens[0], tokens[1], tokens[2], tokens[3]
        if not re.match(r"^[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}$", mac):
            continue
        if port.upper() == "CPU":
            continue
        rows.append({"vlan": vlan, "mac": mac.lower(), "type": kind.upper(), "port": port})
    return rows


def parse_running_interface(output: str) -> dict[str, Any]:
    """`show running-config interface X` -> the settings this executor changes.

    The raw text never leaves this process: only this structure reaches the
    plan, and therefore the model.
    """
    state: dict[str, Any] = {
        "interface": None,
        "description": None,
        "mode": None,
        "access_vlan": None,
        "voice_vlan": None,
        "native_vlan": None,
        "trunk_allowed_vlans": None,
        "portfast": False,
        "shutdown": False,
    }
    allowed: set[int] = set()
    saw_allowed = False
    for raw in (output or "").splitlines():
        line = raw.strip()
        if line.lower().startswith("interface "):
            state["interface"] = line.split(" ", 1)[1].strip()
            continue
        if line.lower().startswith("description "):
            state["description"] = line[len("description ") :].strip()
            continue
        match = re.match(r"^switchport mode (\S+)$", line, re.IGNORECASE)
        if match:
            state["mode"] = match.group(1).lower()
            continue
        match = re.match(r"^switchport access vlan (\d+)$", line, re.IGNORECASE)
        if match:
            state["access_vlan"] = int(match.group(1))
            continue
        match = re.match(r"^switchport voice vlan (\d+)$", line, re.IGNORECASE)
        if match:
            state["voice_vlan"] = int(match.group(1))
            continue
        match = re.match(r"^switchport trunk native vlan (\d+)$", line, re.IGNORECASE)
        if match:
            state["native_vlan"] = int(match.group(1))
            continue
        match = re.match(
            r"^switchport trunk allowed vlan (?:(add|remove|none)\s+)?(\S+)$", line, re.IGNORECASE
        )
        if match:
            verb, value = match.group(1), match.group(2)
            saw_allowed = True
            if (verb or "").lower() == "remove":
                allowed -= expand_vlan_list(value)
            elif (verb or "").lower() == "none":
                allowed = set()
            elif (verb or "").lower() == "add":
                allowed |= expand_vlan_list(value)
            else:
                allowed = expand_vlan_list(value)
            continue
        if re.match(r"^spanning-tree portfast", line, re.IGNORECASE):
            state["portfast"] = not line.lower().startswith("no ")
            continue
        if line.lower() == "shutdown":
            state["shutdown"] = True
            continue
        if line.lower() == "no shutdown":
            state["shutdown"] = False
    if saw_allowed:
        state["trunk_allowed_vlans"] = sorted(allowed)
    return state


# -- rendering the change ----------------------------------------------------
def _config_lines(step: ChangeStep) -> list[str]:
    """The exact configuration this step sends, and nothing else."""
    params = step.params
    if step.action == "vlan.add":
        vlan = _vlan_id(params.get("vlan"))
        lines = [f"vlan {vlan}"]
        name = params.get("name")
        if name is not None:
            name = str(name).strip()
            if not VLAN_NAME_CHARSET.match(name):
                raise UnsupportedStep(f"{name!r} is not a VLAN name")
            lines.append(f"name {name}")
        lines.append("exit")
        return lines
    if step.action == "vlan.remove":
        return [f"no vlan {_vlan_id(params.get('vlan'))}"]
    if step.action == "switch.access_port_config":
        return _access_port_lines(params)
    if step.action == "switch.clear_errdisable":
        # The supported way to bring an err-disabled port back without waiting
        # for errdisable recovery. It leaves the configuration as it was, so
        # `configure revert now` has nothing to undo and cannot make it worse.
        interface = _interface(params.get("interface"))
        return [f"interface {interface}", "shutdown", "no shutdown", "exit"]
    if step.action == "switch.trunk_port_config":
        return _trunk_port_lines(params)
    raise UnsupportedStep(f"{step.action!r} is not a cisco action")


def _access_port_lines(params: dict[str, Any]) -> list[str]:
    interface = _interface(params.get("interface"))
    lines = [f"interface {interface}"]
    if params.get("description") is not None:
        description = str(params["description"]).strip()
        if not DESCRIPTION_CHARSET.match(description):
            raise UnsupportedStep("the description contains characters a description never needs")
        lines.append(f"description {description}" if description else "no description")
    if params.get("access_vlan") is not None:
        vlan = _vlan_id(params["access_vlan"], "access_vlan")
        lines.append("switchport mode access")
        lines.append(f"switchport access vlan {vlan}")
    if params.get("portfast") is not None:
        lines.append(
            "spanning-tree portfast" if params["portfast"] else "no spanning-tree portfast"
        )
    if params.get("shutdown") is not None:
        lines.append("shutdown" if params["shutdown"] else "no shutdown")
    if len(lines) == 1:
        raise UnsupportedStep("switch.access_port_config was given nothing to change")
    lines.append("exit")
    return lines


def _trunk_port_lines(params: dict[str, Any]) -> list[str]:
    """Only `add` and `remove`: a bare `switchport trunk allowed vlan <list>`
    replaces the whole list, which on an uplink is how a trunk loses every VLAN
    that was not in the plan."""
    interface = _interface(params.get("interface"))
    lines = [f"interface {interface}"]
    if params.get("add_vlans"):
        lines.append(
            "switchport trunk allowed vlan add "
            + _vlan_range(_vlan_list(params["add_vlans"], "add_vlans"))
        )
    if params.get("remove_vlans"):
        lines.append(
            "switchport trunk allowed vlan remove "
            + _vlan_range(_vlan_list(params["remove_vlans"], "remove_vlans"))
        )
    if params.get("native_vlan") is not None:
        lines.append(
            f"switchport trunk native vlan {_vlan_id(params['native_vlan'], 'native_vlan')}"
        )
    if len(lines) == 1:
        raise UnsupportedStep(
            "switch.trunk_port_config needs add_vlans, remove_vlans or native_vlan; a bare "
            "allowed-VLAN list would replace the trunk's whole membership"
        )
    lines.append("exit")
    return lines


def _predict(step: ChangeStep, before: dict[str, Any]) -> dict[str, Any]:
    """What the switch would look like afterwards, from the parsed before-state."""
    after = dict(before)
    params = step.params
    if step.action == "switch.access_port_config":
        if params.get("access_vlan") is not None:
            after["mode"] = "access"
            after["access_vlan"] = _vlan_id(params["access_vlan"], "access_vlan")
        if params.get("description") is not None:
            after["description"] = str(params["description"]).strip() or None
        if params.get("portfast") is not None:
            after["portfast"] = bool(params["portfast"])
        if params.get("shutdown") is not None:
            after["shutdown"] = bool(params["shutdown"])
    elif step.action == "switch.trunk_port_config":
        allowed = set(before.get("trunk_allowed_vlans") or [])
        allowed |= (
            set(_vlan_list(params["add_vlans"], "add_vlans")) if params.get("add_vlans") else set()
        )
        if params.get("remove_vlans"):
            allowed -= set(_vlan_list(params["remove_vlans"], "remove_vlans"))
        after["trunk_allowed_vlans"] = sorted(allowed)
        if params.get("native_vlan") is not None:
            after["native_vlan"] = _vlan_id(params["native_vlan"], "native_vlan")
    elif step.action == "switch.clear_errdisable":
        after["shutdown"] = False
    return after


def _changed_keys(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    return sorted(k for k in after if before.get(k) != after.get(k))


# -- the executor ------------------------------------------------------------
@register
class CiscoExecutor(Executor):
    """Applies ChangePlan steps to a Catalyst with an armed revert timer."""

    platform = "cisco"

    def __init__(self, connect: ConnectFactory | None = None) -> None:
        self.connect = connect or scrapli_session
        #: (plan id, device) pairs whose revert timer this executor already armed.
        self._armed: set[tuple[str, str]] = set()

    # -- plumbing --------------------------------------------------------
    def supported_actions(self) -> set[str]:
        return set(SUPPORTED_ACTIONS)

    def _session(self, ctx: ExecutionContext) -> Any:
        factory = ctx.extra.get("connect") or self.connect
        return factory(ctx.device, ctx.credential)

    @staticmethod
    def _archive_ready(session: CiscoSession) -> bool:
        """Is there a checkpoint for `configure revert now` to go back to?

        A switch without the feature answers `%Archive feature not enabled`,
        which the session raises on, so the refusal is caught here and read as
        the answer it is rather than escaping as a transport error.
        """
        try:
            return parse_archive(session.send("show archive"))
        except CiscoError:
            return False

    @staticmethod
    def _revert_timer(steps: Sequence[ChangeStep]) -> int:
        for step in steps:
            value = step.params.get("revert_timer_minutes")
            if value is not None:
                try:
                    minutes = int(value)
                except (TypeError, ValueError):
                    continue
                if 1 <= minutes <= 120:
                    return minutes
        return DEFAULT_REVERT_TIMER_MINUTES

    # -- dry run ---------------------------------------------------------
    def dry_run(self, ctx: ExecutionContext, steps: list[ChangeStep]) -> DryRunResult:
        """Render the exact commands and a structured before/after diff."""
        blockers: list[str] = []
        warnings: list[str] = []
        changes: list[dict[str, Any]] = []
        commands: list[str] = []
        timer = self._revert_timer(steps)
        try:
            with self._session(ctx) as session:
                if not self._archive_ready(session):
                    blockers.append(ARCHIVE_REMEDIATION)
                vlans = parse_vlan_brief(session.send("show vlan brief"))
                for step in steps:
                    try:
                        lines = _config_lines(step)
                    except UnsupportedStep as exc:
                        blockers.append(str(exc))
                        continue
                    commands.extend([f"configure terminal revert timer {timer}", *lines, "end"])
                    change, step_warnings = self._preview(session, step, vlans)
                    changes.append(change)
                    warnings.extend(step_warnings)
        except CiscoError as exc:
            blockers.append(str(exc))
        except Exception as exc:  # a transport failure is a blocker, not a crash
            blockers.append(f"could not reach {ctx.device.name}: {type(exc).__name__}: {exc}")
        if commands:
            commands.append("configure confirm")
            if ctx.extra.get("persist", True):
                commands.append("write memory")
        diff: dict[str, Any] = {
            "device": ctx.device.name,
            "platform": "cisco",
            "revert_timer_minutes": timer,
            "persist": bool(ctx.extra.get("persist", True)),
            "commands": commands,
            "changes": changes,
        }
        return DryRunResult(ok=not blockers, diff=diff, warnings=warnings, blockers=blockers)

    def _preview(
        self, session: CiscoSession, step: ChangeStep, vlans: dict[int, dict[str, Any]]
    ) -> tuple[dict[str, Any], list[str]]:
        """One step's structured before/after, plus anything worth saying about it."""
        warnings: list[str] = []
        params = step.params
        if step.action in ("vlan.add", "vlan.remove"):
            vlan = _vlan_id(params.get("vlan"))
            exists = vlan in vlans
            before = {"exists": exists, "name": vlans.get(vlan, {}).get("name")}
            if step.action == "vlan.add":
                after = {"exists": True, "name": params.get("name") or before["name"]}
                if exists:
                    warnings.append(f"vlan {vlan} already exists, so adding it is a no-op")
            else:
                after = {"exists": False, "name": None}
                members = vlans.get(vlan, {}).get("ports") or []
                if members:
                    warnings.append(
                        f"vlan {vlan} still has {len(members)} member port(s): "
                        + ", ".join(members[:8])
                    )
                if not exists:
                    warnings.append(f"vlan {vlan} does not exist, so removing it is a no-op")
            return (
                {
                    "object": f"vlan {vlan}",
                    "before": before,
                    "after": after,
                    "changed": _changed_keys(before, after),
                },
                warnings,
            )
        interface = _interface(params.get("interface"))
        before = parse_running_interface(session.send(f"show running-config interface {interface}"))
        after = _predict(step, before)
        if step.action == "switch.access_port_config" and params.get("access_vlan") is not None:
            vlan = _vlan_id(params["access_vlan"], "access_vlan")
            if vlan not in vlans:
                warnings.append(
                    f"vlan {vlan} is not configured on this switch, so {interface} would sit in "
                    "a VLAN that does not exist"
                )
            if before.get("mode") == "trunk":
                warnings.append(
                    f"{interface} is currently a trunk; this plan turns it into an access port"
                )
        if step.action == "switch.trunk_port_config" and before.get("mode") not in (None, "trunk"):
            warnings.append(f"{interface} is not a trunk ({before.get('mode')})")
        return (
            {
                "object": f"interface {interface}",
                "before": before,
                "after": after,
                "changed": _changed_keys(before, after),
            },
            warnings,
        )

    # -- apply -----------------------------------------------------------
    def apply(self, ctx: ExecutionContext, step: ChangeStep) -> StepResult:
        """Arm the revert timer, send the step's configuration, capture before/after."""
        started = datetime.now(UTC)
        sent: list[str] = []
        key = (ctx.plan_id, ctx.device.name)
        try:
            lines = _config_lines(step)
            timer = self._revert_timer([step])
            with self._session(ctx) as session:
                if not self._archive_ready(session):
                    raise CiscoError(ARCHIVE_REMEDIATION)
                before = self._capture(session, step)
                sent.append(self._enter_config(session, timer, armed=key in self._armed))
                self._armed.add(key)
                for line in lines:
                    session.send(line)
                    sent.append(line)
                session.send("end")
                sent.append("end")
                after = self._capture(session, step)
        except Exception as exc:
            return StepResult(
                step=step,
                ok=False,
                output={"commands": sent, "revert_armed": key in self._armed},
                error=f"{type(exc).__name__}: {exc}",
                started_at=started,
                finished_at=datetime.now(UTC),
            )
        return StepResult(
            step=step,
            ok=True,
            output={
                "commands": sent,
                "revert_timer_minutes": timer,
                "revert_armed": True,
                "before": before,
                "after": after,
                "changed": _changed_keys(before, after),
            },
            started_at=started,
            finished_at=datetime.now(UTC),
        )

    @staticmethod
    def _enter_config(session: CiscoSession, timer: int, *, armed: bool) -> str:
        """`configure terminal revert timer N`, or plain config mode on a re-entry.

        A second step of the same plan re-arms the timer; some IOS releases
        refuse that while a rollback is already pending, and a plain `configure
        terminal` is then correct: `configure revert now` still restores the
        checkpoint taken when the timer was first armed, so the later steps are
        undone too.
        """
        line = f"configure terminal revert timer {timer}"
        try:
            session.send(line)
            return line
        except CiscoError:
            if not armed:
                raise
            session.send("configure terminal")
            return "configure terminal"

    @staticmethod
    def _capture(session: CiscoSession, step: ChangeStep) -> dict[str, Any]:
        """The structured state this step changes. Raw output stays local."""
        if step.action in ("vlan.add", "vlan.remove"):
            vlan = _vlan_id(step.params.get("vlan"))
            vlans = parse_vlan_brief(session.send("show vlan brief"))
            return {"exists": vlan in vlans, "name": vlans.get(vlan, {}).get("name")}
        interface = _interface(step.params.get("interface"))
        return parse_running_interface(session.send(f"show running-config interface {interface}"))

    # -- checks ----------------------------------------------------------
    def pre_check(self, ctx: ExecutionContext, checks: list[str]) -> list[CheckResult]:
        if not checks:
            return []
        with self._session(ctx) as session:
            return [self._evaluate(session, check) for check in checks]

    def post_check(self, ctx: ExecutionContext, checks: list[str]) -> list[CheckResult]:
        """Evaluate the post-checks and then commit - or leave the timer to run out.

        The engine calls this even when the plan declares no post-checks,
        because `configure confirm` lives here: without the call the armed
        revert timer would undo a change that worked.
        """
        results: list[CheckResult] = []
        with self._session(ctx) as session:
            results = [self._evaluate(session, check) for check in checks]
            if not all(r.ok for r in results):
                return results  # the engine rolls back, which issues `configure revert now`
            try:
                session.send("configure confirm")
            except Exception as exc:
                return [
                    *results,
                    CheckResult(
                        check="configure confirm",
                        ok=False,
                        detail=f"the change could not be committed: {type(exc).__name__}: {exc}",
                    ),
                ]
            self._armed.discard((ctx.plan_id, ctx.device.name))
            results.append(
                CheckResult(
                    check="configure confirm",
                    ok=True,
                    detail="the revert timer is cancelled and the change is committed",
                )
            )
            if ctx.extra.get("persist", True):
                results.append(self._persist(session))
        return results

    @staticmethod
    def _persist(session: CiscoSession) -> CheckResult:
        """`write memory`, reported as advisory: the change is already committed,
        and reverting a good change because it is not saved yet is worse than
        paging the owner about it."""
        try:
            session.send("write memory")
        except Exception as exc:
            return CheckResult(
                check="advisory: write memory",
                ok=False,
                detail=(
                    f"the change is live but was not saved to startup-config "
                    f"({type(exc).__name__}: {exc}); save it before the next reload"
                ),
            )
        return CheckResult(check="advisory: write memory", ok=True, detail="running-config saved")

    # -- rollback --------------------------------------------------------
    def rollback(self, ctx: ExecutionContext, applied: list[StepResult]) -> list[StepResult]:
        """`configure revert now`: back to the checkpoint the revert timer took.

        `applied` arrives in the order the steps were applied; the results come
        back in reverse, which is the order they were undone in. One revert
        undoes all of them, because they share the plan's checkpoint.
        """
        detail: dict[str, Any] = {"commands": ["configure revert now"]}
        error: str | None = None
        try:
            with self._session(ctx) as session:
                session.send("configure revert now")
            ok = True
        except Exception as exc:
            ok = False
            error = f"{type(exc).__name__}: {exc}"
        self._armed.discard((ctx.plan_id, ctx.device.name))
        return [
            StepResult(
                step=result.step,
                ok=ok,
                output={**detail, "reverted": ok},
                error=error,
                finished_at=datetime.now(UTC),
            )
            for result in reversed(applied)
        ]

    # -- the check language ----------------------------------------------
    def _evaluate(self, session: CiscoSession, check: str) -> CheckResult:
        text = " ".join(str(check).split())
        for pattern, handler in _CHECKS:
            match = pattern.match(text)
            if match:
                try:
                    ok, detail = handler(session, match)
                except Exception as exc:
                    return CheckResult(check=text, ok=False, detail=f"{type(exc).__name__}: {exc}")
                return CheckResult(check=text, ok=ok, detail=detail)
        # Fail closed: an unreadable post-check must never confirm a change.
        return CheckResult(
            check=text,
            ok=False,
            detail="this executor does not understand that check; see the cisco check language",
        )


def _check_interface_state(session: CiscoSession, match: re.Match[str]) -> tuple[bool, str]:
    interface = _interface(match.group("iface"))
    rows = parse_interface_status(session.send(f"show interfaces {interface} status"))
    row = rows.get(normalise_interface(interface))
    if row is None:
        return False, f"{interface} is not in `show interfaces status`"
    up = row["status"].lower() == "connected"
    want_up = match.group("state").lower() == "up"
    return up == want_up, f"{interface} is {row['status']}"


def _check_vlan_exists(session: CiscoSession, match: re.Match[str]) -> tuple[bool, str]:
    vlan = _vlan_id(match.group("vlan"))
    vlans = parse_vlan_brief(session.send("show vlan brief"))
    exists = vlan in vlans
    want = "not" not in match.group("exists").lower()
    detail = f"vlan {vlan} " + ("exists" if exists else "does not exist")
    if exists:
        detail += f" ({vlans[vlan]['name']}, {vlans[vlan]['status']})"
    return exists == want, detail


def _check_no_errdisable(session: CiscoSession, match: re.Match[str]) -> tuple[bool, str]:
    interface = _interface(match.group("iface"))
    rows = parse_errdisabled(session.send("show interfaces status err-disabled"))
    reason = rows.get(normalise_interface(interface))
    if reason is None:
        return True, f"{interface} is not err-disabled"
    return False, f"{interface} is err-disabled ({reason})"


def _check_cdp_neighbor(session: CiscoSession, match: re.Match[str]) -> tuple[bool, str]:
    interface = _interface(match.group("iface"))
    expected = match.group("peer").strip().lower()
    key = normalise_interface(interface)
    neighbours = [
        entry
        for entry in parse_cdp_detail(session.send(f"show cdp neighbors {interface} detail"))
        if not entry["local_interface"] or normalise_interface(entry["local_interface"]) == key
    ]
    if not neighbours:
        return False, f"no CDP neighbour on {interface}"
    seen = [entry["device_id"] for entry in neighbours]
    # `esx-01` matches `esx-01.lan` and `esx-01(FCH123)`: CDP device ids carry
    # the domain or the serial depending on the platform.
    ok = any(name.lower().split(".")[0].split("(")[0] == expected for name in seen)
    return ok, f"CDP on {interface} sees {', '.join(seen)}"


_MAC_OPERATORS: dict[str, Callable[[int, int], bool]] = {
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
    ">": lambda a, b: a > b,
    "<": lambda a, b: a < b,
    "==": lambda a, b: a == b,
    "=": lambda a, b: a == b,
}


def _check_mac_count(session: CiscoSession, match: re.Match[str]) -> tuple[bool, str]:
    vlan = _vlan_id(match.group("vlan"))
    rows = parse_mac_table(session.send(f"show mac address-table vlan {vlan}"))
    count = sum(1 for row in rows if row["vlan"] == str(vlan))
    wanted = int(match.group("count"))
    operator = _MAC_OPERATORS[match.group("op")]
    return operator(count, wanted), f"{count} MAC address(es) on vlan {vlan}"


#: The check language a plan writes its pre- and post-checks in. Anything else
#: fails closed.
_CHECKS: tuple[
    tuple[re.Pattern[str], Callable[[CiscoSession, re.Match[str]], tuple[bool, str]]], ...
] = (
    (
        re.compile(r"^interface (?P<iface>\S+) is (?P<state>up|down)$", re.IGNORECASE),
        _check_interface_state,
    ),
    (
        re.compile(r"^vlan (?P<vlan>\d+) (?P<exists>exists|does not exist)$", re.IGNORECASE),
        _check_vlan_exists,
    ),
    (
        re.compile(r"^no errdisable on (?P<iface>\S+)$", re.IGNORECASE),
        _check_no_errdisable,
    ),
    (
        re.compile(
            r"^cdp neighbou?r on (?P<iface>\S+) is (?P<peer>\S+)$",
            re.IGNORECASE,
        ),
        _check_cdp_neighbor,
    ),
    (
        re.compile(
            r"^mac count on vlan (?P<vlan>\d+) (?P<op>>=|<=|==|>|<|=) (?P<count>\d+)$",
            re.IGNORECASE,
        ),
        _check_mac_count,
    ),
)

CHECK_LANGUAGE = (
    "interface Gi1/0/5 is up|down",
    "vlan 20 exists | vlan 20 does not exist",
    "no errdisable on Gi1/0/5",
    "cdp neighbor on Gi1/0/48 is esx-01",
    "mac count on vlan 20 >= 1",
)
