"""Catalyst executor: IOS and IOS-XE, over scrapli, with a timed rollback.

The rollback strategy is fixed by `docs/architecture.md` and by
`infra_agent/change/executors/base.py`:

    configure terminal revert timer <N>     # arms an automatic rollback
    ... the action's configuration ...
    end
    <post-checks run here, on every device of the plan>
    configure confirm                       # keeps the change (commit phase)
    configure revert now                    # or throws it away

Never `reload in`: a reload takes the whole switch down, and the point of the
revert timer is that a change that cuts the session off undoes itself while
everything else keeps running. `configure revert now` restores the archived
configuration taken when the timer was armed, so it also undoes the later steps
of a multi-step plan - which is why the timer is armed once, by the first step,
and never re-armed.

Six properties this module enforces rather than assumes:

* **The revert timer needs the archive feature.** Without `archive` + `path`,
  `configure terminal revert timer` has nothing to roll back to and the safety
  net is imaginary. `dry_run` runs `show archive` and blocks with the exact
  remediation when it is not configured; `apply` re-checks, because a plan may
  sit approved for hours.
* **A VLAN needs somewhere to roll back to.** On a VTP server or client a
  normal-range VLAN lives in vlan.dat, not in the running-config, so the
  archive cannot restore it - and `no vlan 20` on a server deletes it across the
  whole domain. `dry_run` reads `show vtp status` and refuses VLAN work unless
  the switch is transparent or off; `apply` re-checks.
* **Confirming is a phase, not a side effect of checking.** `post_check` only
  verifies. The engine calls `commit` once *every* device of the plan has
  passed, so a two-switch plan cannot end with switch A confirmed and switch B
  reverted.
* **A rollback is verified, never assumed.** After `configure revert now` (or,
  for a change already confirmed, the inverse configuration built from the
  state each step captured) the object is read back and compared. Silence from
  the switch is not evidence, and a plan whose timer was never armed is told
  there was nothing to undo instead of being sent a revert.
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
from collections.abc import Callable, Iterable, Iterator, Sequence
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

#: Why a VLAN change is refused on a switch that is not VTP transparent (or
#: off), and what to do about it. Two separate reasons, both fatal:
#:
#: * in server or client mode a normal-range VLAN lives in `vlan.dat`, not in
#:   the running-config, so `configure revert now` cannot bring a deleted VLAN
#:   back - the rollback would report success while every access port in that
#:   VLAN stayed inactive;
#: * on a VTP server `no vlan 20` is not a local change at all: it propagates to
#:   every switch in the domain.
VTP_REMEDIATION = (
    "VLAN changes are refused on this switch: VTP is in {mode} mode (domain {domain}). "
    "Normal-range VLANs then live in vlan.dat rather than in the running-config, so the "
    "`configure terminal revert timer` rollback cannot restore a deleted VLAN, and on a "
    "server `no vlan N` deletes it across the whole VTP domain. Either set `vtp mode "
    "transparent` (or `vtp mode off`) on this switch, or make the VLAN change deliberately "
    "on the VTP server, then dry-run this plan again."
)

#: `show vtp status` did not say. VLAN changes stop here too: the rollback story
#: for a VLAN depends entirely on the answer.
VTP_UNKNOWN = (
    "VLAN changes are refused: this switch did not answer `show vtp status`, so whether a "
    "VLAN lives in the running-config (VTP transparent/off, where the revert timer can roll "
    "it back) or in vlan.dat (VTP server/client, where it cannot) is unknown."
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


#: What a rollback says when the switch did not come back to where it was.
_NOT_BACK = "the switch did not return to the state this step captured ({keys})"

#: IOS answering `configure revert now` with "there is nothing pending".
#: `ScrapliSession` already raises on a `%` line; this catches the wordings that
#: come back as ordinary output so silence is never read as success.
_REVERT_REFUSED = re.compile(
    r"(no rollback|not running|rollback.*not (?:configured|in progress)"
    r"|nothing to (?:revert|roll))",
    re.IGNORECASE,
)


def _revert_refusal(output: str) -> str | None:
    """The line where IOS said it had nothing to revert, if it said so."""
    for raw in (output or "").splitlines():
        line = raw.strip()
        if _REVERT_REFUSED.search(line) or (line.startswith("%") and not SYSLOG_LINE.match(line)):
            return line[:160]
    return None


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


#: Every VLAN a trunk can carry. `switchport trunk allowed vlan` missing from an
#: interface means all of them, which is not the same thing as none of them.
ALL_VLANS = frozenset(range(1, 4095))

#: How a trunk that allows everything is written in a diff, rather than as 4094
#: numbers.
ALL = "all"


def _vlan_range(vlans: Iterable[int]) -> str:
    """`[10, 20, 30, 31, 32]` -> `10,20,30-32`, the way IOS reads and prints it.

    One id per VLAN is not merely verbose: `switchport trunk allowed vlan add
    100,101,...,200` is a 700-character line, and the `all` case would be 20 kB
    that IOS rejects outright.
    """
    ordered = sorted(set(int(v) for v in vlans))
    if not ordered:
        return ""
    parts: list[str] = []
    start = previous = ordered[0]
    for vlan in ordered[1:]:
        if vlan == previous + 1:
            previous = vlan
            continue
        parts.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = vlan
    parts.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(parts)


def _allowed_display(vlans: Sequence[int] | None) -> str:
    """What the approver is shown for a trunk's allowed list: `all`, or a range."""
    return ALL if vlans is None else _vlan_range(vlans)


# -- the session ------------------------------------------------------------
class CiscoSession(Protocol):
    """One line in, its output back. The whole surface the executor needs.

    Keeping it this small is what lets `tests/test_executor_cisco.py` assert the
    exact command sequence, revert timer and all, without a device.
    """

    def send(self, command: str) -> str: ...


ConnectFactory = Callable[[SeedDevice, Credential], Any]


#: A syslog message, which is not a rejected command. A vty with `terminal
#: monitor` (or `logging monitor` left on) prints `%LINK-3-UPDOWN: ...` and
#: `%SYS-5-CONFIG_I: ...` straight into the middle of a `show`, and reading one
#: of those as a rejection would fail a post-check and roll a good change back.
#: `terminal no monitor` is sent when the session opens; this is the second line
#: of defence, and it is why not every `%` line is an error.
SYSLOG_LINE = re.compile(r"^%[A-Za-z][\w-]*-\d-[A-Za-z0-9_]+\s*:")


def error_line(output: str) -> str | None:
    """The first line of `output` that is IOS refusing the command, if any.

    IOS answers a bad command with `% Invalid input detected at '^' marker`,
    `% Incomplete command`, `%Archive feature not enabled` and friends: a `%` at
    the start of a line, followed by prose rather than by a syslog facility.
    """
    for raw in (output or "").splitlines():
        line = raw.strip()
        if line.startswith("%") and not SYSLOG_LINE.match(line):
            return line
    return None


class ScrapliSession:
    """A `CiscoSession` over an open scrapli driver.

    `channel.send_input` is used rather than `send_command` because the config
    mode is entered with `configure terminal revert timer N`, which is not a
    command scrapli's privilege handling knows how to enter on its own. The
    IOS-XE prompt pattern matches `sw(config)#` and `sw(config-if)#`, so reading
    to the prompt works in every mode this executor uses.
    """

    def __init__(self, connection: Any) -> None:
        self.connection = connection

    def send(self, command: str) -> str:
        line = _assert_safe(command)
        raw = self.connection.channel.send_input(line)
        output = _as_text(raw)
        rejected = error_line(output)
        if rejected:
            raise CiscoError(f"{line!r} was rejected: {rejected[:160]}")
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
        session = ScrapliSession(connection)
        # Log messages on the vty would land in the middle of a `show` and be
        # read as command rejections. Best effort: a switch that refuses the
        # command still works, `error_line` just has more to do.
        for line in ("terminal length 0", "terminal no monitor"):
            try:
                session.send(line)
            except Exception:
                log.debug("%s: `%s` was not accepted", device.name, line)
        yield session


# -- parsers (classic IOS and IOS-XE) ---------------------------------------
def parse_archive(output: str) -> bool:
    """True when the archive feature has a path, on either platform.

    Both print `The next archive file will be named flash:/archive/config-3`
    once `archive path` is set; without it IOS says `%Archive feature not
    enabled` and IOS-XE prints the header alone. The name has to be a real
    filesystem path (`flash:`, `bootflash:`, `disk0:`, a URL): a switch with
    `archive` but no `path` answers with the sentence and nothing usable after
    it, and a checkpoint that does not exist is exactly the safety net this
    check is here to refuse to imagine.
    """
    if error_line(output or ""):
        return False
    match = re.search(r"the next archive file will be named\s+(\S+)", output or "", re.IGNORECASE)
    if not match:
        return False
    name = match.group(1)
    return bool(re.match(r"^[A-Za-z][\w.-]*:", name))


def parse_vtp_status(output: str) -> dict[str, str]:
    """`show vtp status` -> {mode, domain}, on classic IOS and on VTPv3.

    VTPv3 prints a mode per feature under `Feature VLAN:`, and calls the server
    role `Primary Server` / `Secondary Server`; classic IOS prints one
    `VTP Operating Mode`. The VLAN feature's mode is the one that decides
    whether `vlan 20` is a line of running-config or a row in vlan.dat.
    """
    text = output or ""
    modes = [
        m.group(1).strip().lower() for m in re.finditer(r"VTP Operating Mode\s*:\s*(.+)", text)
    ]
    feature = re.split(r"Feature VLAN\s*:", text, maxsplit=1)
    if len(feature) > 1:
        after = [
            m.group(1).strip().lower()
            for m in re.finditer(r"VTP Operating Mode\s*:\s*(.+)", feature[1])
        ]
        modes = after or modes
    mode = ""
    for candidate in modes:
        if "server" in candidate:
            mode = "server"
        elif "client" in candidate:
            mode = "client"
        elif "transparent" in candidate:
            mode = "transparent"
        elif candidate.startswith("off"):
            mode = "off"
        if mode:
            break
    domain = re.search(r"VTP Domain Name\s*:\s*(.*)", text)
    return {"mode": mode, "domain": (domain.group(1).strip() if domain else "")}


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


def _inverse_lines(step: ChangeStep, before: dict[str, Any]) -> list[str]:
    """The configuration that puts `before` back, for a change already committed.

    `configure revert now` is the rollback while the revert timer is armed. Once
    `configure confirm` has run there is no checkpoint left, and for a VLAN
    there may never have been one: on a VTP server or client the VLAN lives in
    vlan.dat, which the archive does not carry (which is why `dry_run` refuses
    VLAN work on those switches in the first place). So the undo is written out
    of the state the step captured before it ran, and verified afterwards.

    An empty list means there is nothing to undo, not that the undo is unknown:
    `switch.clear_errdisable` shuts and unshuts a port without changing a line
    of configuration.
    """
    params = step.params
    if step.action in ("vlan.add", "vlan.remove"):
        vlan = _vlan_id(params.get("vlan"))
        if not before.get("exists"):
            return [f"no vlan {vlan}"]
        lines = [f"vlan {vlan}"]
        name = str(before.get("name") or "").strip()
        if name and VLAN_NAME_CHARSET.match(name):
            lines.append(f"name {name}")
        lines.append("exit")
        return lines
    if step.action == "switch.clear_errdisable":
        return []
    interface = _interface(params.get("interface"))
    lines = [f"interface {interface}"]
    if step.action == "switch.access_port_config":
        if params.get("description") is not None:
            description = str(before.get("description") or "").strip()
            lines.append(f"description {description}" if description else "no description")
        if params.get("access_vlan") is not None:
            previous = before.get("access_vlan")
            lines.append(
                f"switchport access vlan {int(previous)}"
                if previous
                else "no switchport access vlan"
            )
            mode = before.get("mode")
            lines.append(f"switchport mode {mode}" if mode else "no switchport mode")
        if params.get("portfast") is not None:
            lines.append(
                "spanning-tree portfast" if before.get("portfast") else "no spanning-tree portfast"
            )
        if params.get("shutdown") is not None:
            lines.append("shutdown" if before.get("shutdown") else "no shutdown")
    elif step.action == "switch.trunk_port_config":
        added, removed = _trunk_deltas(params)
        allowed = before.get("trunk_allowed_vlans")
        if allowed is None:
            # The trunk allowed everything before, so only a removal changed it.
            if removed:
                lines.append("switchport trunk allowed vlan add " + _vlan_range(removed))
        else:
            back = sorted(removed & set(allowed))
            undo = sorted(added - set(allowed))
            if back:
                lines.append("switchport trunk allowed vlan add " + _vlan_range(back))
            if undo:
                lines.append("switchport trunk allowed vlan remove " + _vlan_range(undo))
        if params.get("native_vlan") is not None:
            native = before.get("native_vlan")
            lines.append(
                f"switchport trunk native vlan {int(native)}"
                if native
                else "no switchport trunk native vlan"
            )
    if len(lines) == 1:
        return []
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
        added, removed = _trunk_deltas(params)
        before_allowed = before.get("trunk_allowed_vlans")
        if before_allowed is None:
            # No `switchport trunk allowed vlan` line at all: the trunk carries
            # every VLAN. Adding to that changes nothing; removing narrows it
            # for the first time, which is the whole trunk being rewritten.
            after["trunk_allowed_vlans"] = None if not removed else sorted(ALL_VLANS - removed)
        else:
            after["trunk_allowed_vlans"] = sorted((set(before_allowed) | added) - removed)
        if params.get("native_vlan") is not None:
            after["native_vlan"] = _vlan_id(params["native_vlan"], "native_vlan")
    elif step.action == "switch.clear_errdisable":
        after["shutdown"] = False
    return after


def _trunk_deltas(params: dict[str, Any]) -> tuple[set[int], set[int]]:
    """The VLANs a trunk step adds and the ones it removes."""
    added = set(_vlan_list(params["add_vlans"], "add_vlans")) if params.get("add_vlans") else set()
    removed = (
        set(_vlan_list(params["remove_vlans"], "remove_vlans"))
        if params.get("remove_vlans")
        else set()
    )
    return added, removed


def _changed_keys(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    return sorted(k for k in after if before.get(k) != after.get(k))


def _display(state: dict[str, Any]) -> dict[str, Any]:
    """One parsed state, as the approver should read it.

    The only translation is the trunk's allowed list: internally `None` means
    "every VLAN" and a list means exactly those, which reads as `[]` versus
    `[20]` in a diff and says the opposite of the truth. In the diff it is
    `all`, or an IOS range.
    """
    if "trunk_allowed_vlans" not in state:
        return dict(state)
    shown = dict(state)
    shown["trunk_allowed_vlans"] = _allowed_display(state.get("trunk_allowed_vlans"))
    return shown


def _state_differences(before: Any, after: Any) -> list[str]:
    """Which keys of a captured state did not come back to where they were."""
    if not isinstance(before, dict) or not isinstance(after, dict):
        return ["state"]
    return sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key))


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
    def _vtp_blocker(session: CiscoSession, steps: Sequence[ChangeStep]) -> str | None:
        """Refuse VLAN work on a switch where the rollback would be imaginary.

        Only asked when the plan actually touches a VLAN: an access-port move is
        a running-config change on any VTP mode, and does not care.
        """
        if not any(step.action.startswith("vlan.") for step in steps):
            return None
        try:
            status = parse_vtp_status(session.send("show vtp status"))
        except CiscoError:
            return VTP_UNKNOWN
        mode = status.get("mode") or ""
        if mode in ("server", "client"):
            return VTP_REMEDIATION.format(mode=mode, domain=status.get("domain") or "(unset)")
        if not mode:
            return VTP_UNKNOWN
        return None

    @staticmethod
    def _timer_minutes(steps: Sequence[ChangeStep], ctx: ExecutionContext | None = None) -> int:
        """How long the switch waits for `configure confirm`.

        A plan's steps are applied device by device and the change is confirmed
        only once *every* device has passed its post-checks, so the timer armed
        on the first switch has to outlive the whole plan - each extra device is
        another SSH session for its steps and another for its checks, and the
        2960s in this estate are not quick to log into. A step may still name
        its own `revert_timer_minutes`.
        """
        for step in steps:
            value = step.params.get("revert_timer_minutes")
            if value is not None:
                try:
                    minutes = int(value)
                except (TypeError, ValueError):
                    continue
                if 1 <= minutes <= 120:
                    return minutes
        extra = ctx.extra if ctx is not None else {}
        devices = max(1, int(extra.get("plan_devices") or 1))
        total_steps = max(1, int(extra.get("plan_steps") or len(steps) or 1))
        return min(120, DEFAULT_REVERT_TIMER_MINUTES + 2 * (devices - 1) + (total_steps - 1))

    # -- dry run ---------------------------------------------------------
    def dry_run(self, ctx: ExecutionContext, steps: list[ChangeStep]) -> DryRunResult:
        """Render the exact commands and a structured before/after diff."""
        blockers: list[str] = []
        warnings: list[str] = []
        changes: list[dict[str, Any]] = []
        commands: list[str] = []
        timer = self._timer_minutes(steps, ctx)
        try:
            with self._session(ctx) as session:
                if not self._archive_ready(session):
                    blockers.append(ARCHIVE_REMEDIATION)
                vtp = self._vtp_blocker(session, steps)
                if vtp:
                    blockers.append(vtp)
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
                    "before": _display(before),
                    "after": _display(after),
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
                "before": _display(before),
                "after": _display(after),
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
        before: dict[str, Any] | None = None
        try:
            lines = _config_lines(step)
            timer = self._timer_minutes([step], ctx)
            with self._session(ctx) as session:
                if not self._archive_ready(session):
                    raise CiscoError(ARCHIVE_REMEDIATION)
                # Re-checked here and not only in the dry run: a plan can sit
                # approved for hours, and a switch that changed VTP mode in
                # between is a switch whose VLAN rollback no longer exists.
                vtp = self._vtp_blocker(session, [step])
                if vtp:
                    raise CiscoError(vtp)
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
            output: dict[str, Any] = {"commands": sent, "revert_armed": key in self._armed}
            if before is not None:
                # What the port or VLAN looked like before this step: the only
                # thing a rollback can verify itself against.
                output["before"] = before
            return StepResult(
                step=step,
                ok=False,
                output=output,
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
        """Enter configuration mode, arming the revert timer exactly once.

        The timer is armed by the first step of a plan on a device and never
        again: `configure terminal revert timer N` takes a fresh checkpoint of
        the running-config, and a second one - taken when step 1 is already in
        place - would leave `configure revert now` undoing only the later steps.
        Whether a release resets or refuses a pending timer differs across the
        2960/3560/3750/3650 mix, so the executor does not find out. Later steps
        enter plain configuration mode and are covered by the first checkpoint.
        """
        if armed:
            session.send("configure terminal")
            return "configure terminal"
        line = f"configure terminal revert timer {timer}"
        session.send(line)
        return line

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
        """Verify, and only verify. Committing is a separate phase.

        Nothing here cancels the revert timer: the engine confirms every device
        of a plan only once all of them have passed their post-checks (see
        `commit`). Verifying and committing device A before device B is even
        looked at is what leaves A changed and confirmed when B fails - and on
        IOS a `configure confirm` cannot be taken back.
        """
        if not checks:
            return []
        with self._session(ctx) as session:
            return [self._evaluate(session, check) for check in checks]

    def commit(self, ctx: ExecutionContext) -> list[CheckResult]:
        """`configure confirm`, and `write memory` when the plan persists.

        Called by the change engine after every device's post-checks passed. Up
        to here the change is still holding its own undo: if this is never
        reached, the revert timer expires and the switch puts itself back.
        """
        results: list[CheckResult] = []
        with self._session(ctx) as session:
            try:
                session.send("configure confirm")
            except Exception as exc:
                return [
                    CheckResult(
                        check="configure confirm",
                        ok=False,
                        detail=f"the change could not be committed: {type(exc).__name__}: {exc}",
                    )
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
        """Put the switch back, and prove it - or say that it is not back.

        `applied` arrives in the order the steps were applied; the results come
        back in reverse, the order they were undone in. Which undo is used
        depends on what state the change is actually in:

        * **nothing was armed** - the first step never got its revert timer, so
          no configuration was sent. Nothing is sent now either: a
          `configure revert now` here either errors or silently reverts someone
          else's pending change.
        * **armed, not committed** - `configure revert now` restores the
          checkpoint the timer took, undoing every step of the plan at once.
        * **committed** - `configure confirm` has already thrown the checkpoint
          away, so each step is undone by the inverse configuration built from
          the state it captured, inside a revert timer of its own.

        In both undo paths the state is captured again afterwards and compared
        with what the step recorded before it ran. Silence from the switch is
        not evidence: `ok` means the port or the VLAN is measurably back.
        """
        key = (ctx.plan_id, ctx.device.name)
        if not any(r.output.get("revert_armed") for r in applied):
            self._armed.discard(key)
            return [
                StepResult(
                    step=result.step,
                    ok=True,
                    output={
                        "commands": [],
                        "reverted": False,
                        "reason": "no revert timer was armed, so no configuration was sent "
                        "and there is nothing to undo",
                    },
                    finished_at=datetime.now(UTC),
                )
                for result in reversed(applied)
            ]
        try:
            with self._session(ctx) as session:
                if ctx.extra.get("committed"):
                    results = self._rollback_inverse(session, ctx, applied)
                else:
                    results = self._rollback_timer(session, applied)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            results = [
                StepResult(
                    step=result.step,
                    ok=False,
                    output={"reverted": False},
                    error=error,
                    finished_at=datetime.now(UTC),
                )
                for result in reversed(applied)
            ]
        self._armed.discard(key)
        return results

    def _rollback_timer(self, session: CiscoSession, applied: list[StepResult]) -> list[StepResult]:
        """One `configure revert now` for the whole plan, then verify each step."""
        commands = ["configure revert now"]
        try:
            output = session.send("configure revert now")
        except Exception as exc:
            return [
                StepResult(
                    step=result.step,
                    ok=False,
                    output={"commands": commands, "reverted": False},
                    error=f"the rollback was refused: {type(exc).__name__}: {exc}",
                    finished_at=datetime.now(UTC),
                )
                for result in reversed(applied)
            ]
        refusal = _revert_refusal(output)
        return [
            self._verify_undo(session, result, commands, refusal) for result in reversed(applied)
        ]

    def _rollback_inverse(
        self, session: CiscoSession, ctx: ExecutionContext, applied: list[StepResult]
    ) -> list[StepResult]:
        """Undo a committed change step by step, from the state each step captured."""
        results: list[StepResult] = []
        for result in reversed(applied):
            before = result.output.get("before")
            if not isinstance(before, dict):
                results.append(
                    StepResult(
                        step=result.step,
                        ok=False,
                        output={"commands": [], "reverted": False},
                        error="this step captured no state, so a committed change cannot be "
                        "undone from it; check the device by hand",
                        finished_at=datetime.now(UTC),
                    )
                )
                continue
            results.append(self._undo_step(session, ctx, result.step, before))
        restored = [r for r in results if r.output.get("reverted")]
        if restored and all(r.ok for r in results) and ctx.extra.get("persist", True):
            # Advisory, as it is after a change: the restored configuration is
            # live either way, this is so it survives the next reload.
            self._persist(session)
        return results

    def _undo_step(
        self,
        session: CiscoSession,
        ctx: ExecutionContext,
        step: ChangeStep,
        before: dict[str, Any],
    ) -> StepResult:
        commands: list[str] = []
        try:
            lines = _inverse_lines(step, before)
            if not lines:
                return StepResult(
                    step=step,
                    ok=True,
                    output={
                        "commands": [],
                        "reverted": False,
                        "reason": f"{step.action} changes no configuration, so a committed "
                        "change has nothing to undo",
                    },
                    finished_at=datetime.now(UTC),
                )
            timer = self._timer_minutes([step], ctx)
            commands.append(self._enter_config(session, timer, armed=False))
            for line in lines:
                session.send(line)
                commands.append(line)
            session.send("end")
            commands.append("end")
            after = self._capture(session, step)
            differs = _state_differences(before, after)
            commands.append("configure revert now" if differs else "configure confirm")
            session.send(commands[-1])
        except Exception as exc:
            return StepResult(
                step=step,
                ok=False,
                output={"commands": commands, "reverted": False, "before": before},
                error=f"{type(exc).__name__}: {exc}",
                finished_at=datetime.now(UTC),
            )
        return StepResult(
            step=step,
            ok=not differs,
            output={
                "commands": commands,
                "reverted": not differs,
                "before": before,
                "after": after,
                "differs": differs,
            },
            error=None if not differs else _NOT_BACK.format(keys=", ".join(differs)),
            finished_at=datetime.now(UTC),
        )

    def _verify_undo(
        self,
        session: CiscoSession,
        result: StepResult,
        commands: list[str],
        refusal: str | None,
    ) -> StepResult:
        """Is this step's object back to the state the step captured before it ran?"""
        before = result.output.get("before")
        if refusal:
            return StepResult(
                step=result.step,
                ok=False,
                output={"commands": commands, "reverted": False},
                error=f"the rollback was refused: {refusal}",
                finished_at=datetime.now(UTC),
            )
        if not isinstance(before, dict):
            # The step failed before it captured anything, which means it also
            # configured nothing: there is no claim to make about it.
            return StepResult(
                step=result.step,
                ok=True,
                output={
                    "commands": commands,
                    "reverted": False,
                    "reason": "this step captured no state and changed nothing",
                },
                finished_at=datetime.now(UTC),
            )
        try:
            after = self._capture(session, result.step)
        except Exception as exc:
            return StepResult(
                step=result.step,
                ok=False,
                output={"commands": commands, "reverted": False, "before": before},
                error=f"the rollback could not be verified: {type(exc).__name__}: {exc}",
                finished_at=datetime.now(UTC),
            )
        differs = _state_differences(before, after)
        return StepResult(
            step=result.step,
            ok=not differs,
            output={
                "commands": commands,
                "reverted": not differs,
                "before": before,
                "after": after,
                "differs": differs,
            },
            error=None if not differs else _NOT_BACK.format(keys=", ".join(differs)),
            finished_at=datetime.now(UTC),
        )

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
