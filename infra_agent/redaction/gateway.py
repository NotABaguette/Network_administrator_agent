"""The single choke point for everything that leaves for the Claude API.

    gateway = RedactionGateway()
    safe = gateway.egress(payload, tool="inventory.get_device")

`egress` strips secrets from every string in the payload (recursively),
optionally pseudonymises public IPs, and appends a line to the egress audit
log. `is_command_allowed` enforces the read-only `device.show` allowlists.
Raw configs must never reach `egress`: callers pass parsed structures, and
`refuse_raw_config` is the assertion helper collectors use in tests.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

DEFAULT_RULES = Path(__file__).with_name("redaction.yaml")

_RAW_CONFIG_MARKERS = (
    re.compile(r"^!\s*Last configuration change", re.M),
    re.compile(r"^Building configuration\.\.\.", re.M),
    re.compile(r"^version \d+\.\d+\s*$", re.M),
    re.compile(r"^#config-version=", re.M),
    re.compile(r"^config system global\s*$", re.M),
)


class Rule(BaseModel):
    name: str
    pattern: str
    replacement: str

    _compiled: re.Pattern[str] | None = None

    def compiled(self) -> re.Pattern[str]:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern)
        return self._compiled


class CommandPolicy(BaseModel):
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)


class RedactionRules(BaseModel):
    mask_public_ips: bool = True
    rules: list[Rule]
    commands: dict[str, CommandPolicy] = Field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None = None) -> RedactionRules:
        raw = yaml.safe_load((path or DEFAULT_RULES).read_text())
        return cls.model_validate(raw)


class IpPseudonymizer:
    """Replaces public IPv4 addresses with stable tokens like PUBIP_3 and reverses them."""

    _ipv4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def __init__(self) -> None:
        self.forward: dict[str, str] = {}
        self.reverse: dict[str, str] = {}

    @staticmethod
    def is_public(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return addr.is_global

    def mask(self, text: str) -> str:
        def sub(match: re.Match[str]) -> str:
            ip = match.group(0)
            if not self.is_public(ip):
                return ip
            if ip not in self.forward:
                token = f"PUBIP_{len(self.forward) + 1}"
                self.forward[ip] = token
                self.reverse[token] = ip
            return self.forward[ip]

        return self._ipv4.sub(sub, text)

    _token = re.compile(r"PUBIP_\d+")

    def unmask(self, text: str) -> str:
        # Whole-token replacement so PUBIP_1 never corrupts PUBIP_10.
        return self._token.sub(lambda m: self.reverse.get(m.group(0), m.group(0)), text)


class RawConfigError(ValueError):
    """Raised when something that looks like a raw device config reaches egress."""


class RedactionGateway:
    def __init__(
        self,
        rules: RedactionRules | None = None,
        audit_log: Path | None = None,
        pseudonymizer: IpPseudonymizer | None = None,
    ):
        self.rules = rules or RedactionRules.load()
        self.audit_log = audit_log
        self.ips = pseudonymizer or IpPseudonymizer()
        self._command_policies = {
            platform: (
                [re.compile(p) for p in policy.allow],
                [re.compile(p) for p in policy.deny],
            )
            for platform, policy in self.rules.commands.items()
        }

    # -- text ---------------------------------------------------------------
    def redact_text(self, text: str) -> str:
        for rule in self.rules.rules:
            text = rule.compiled().sub(rule.replacement, text)
        if self.rules.mask_public_ips:
            text = self.ips.mask(text)
        return text

    def redact(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.redact_text(obj)
        if isinstance(obj, dict):
            return {self.redact_text(str(k)): self.redact(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.redact(v) for v in obj]
        return obj

    def unmask(self, text: str) -> str:
        """Reverse public-IP pseudonyms for the owner's channel only, never for the model."""
        return self.ips.unmask(text)

    # -- raw config guard ---------------------------------------------------
    @staticmethod
    def looks_like_raw_config(text: str) -> bool:
        hits = sum(1 for marker in _RAW_CONFIG_MARKERS if marker.search(text))
        return hits >= 1 and text.count("\n") > 20

    def refuse_raw_config(self, obj: Any) -> None:
        for s in _strings(obj):
            if self.looks_like_raw_config(s):
                raise RawConfigError("raw device configuration must not leave the network")

    # -- commands -----------------------------------------------------------
    _shell_meta = re.compile(r"[;&|`$<>(){}\\\n\r\x00-\x1f]")

    def is_command_allowed(self, platform: str, command: str) -> bool:
        # Newlines, pipes and shell metacharacters never belong in a read-only show
        # command on any platform; refuse before the allowlist gets a chance to match.
        if self._shell_meta.search(command):
            return False
        cmd = " ".join(command.strip().split())
        policy = self._command_policies.get(platform)
        if policy is None:
            return False
        allow, deny = policy
        if any(p.search(cmd) for p in deny):
            return False
        return any(p.match(cmd) for p in allow)

    # -- egress -------------------------------------------------------------
    def egress(self, payload: Any, tool: str) -> Any:
        self.refuse_raw_config(payload)
        redacted = self.redact(payload)
        self._audit(redacted, tool)
        return redacted

    def _audit(self, payload: Any, tool: str) -> None:
        if self.audit_log is None:
            return
        serialized = json.dumps(payload, default=str, sort_keys=True)
        entry = {
            "at": datetime.now(UTC).isoformat(),
            "tool": tool,
            "bytes": len(serialized.encode()),
            "sha256": hashlib.sha256(serialized.encode()).hexdigest(),
            "public_ips_masked": len(self.ips.forward),
        }
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_log.open("a") as fh:
            fh.write(json.dumps(entry) + "\n")


def _strings(obj: Any):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v)
