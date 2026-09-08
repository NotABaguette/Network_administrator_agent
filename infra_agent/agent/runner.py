"""The unattended agent loop around the Anthropic SDK beta Tool Runner.

Three rules shape this module and are enforced here rather than trusted to the
prompt:

1. Every tool result passes through :meth:`RedactionGateway.egress` before it is
   handed back to the model. The registry function is wrapped, so a tool that
   forgets to redact cannot leak.
2. Only ``llm_callable`` tools are wrapped, and ``change.approve`` /
   ``change.execute`` are additionally denied by name. Approval material never
   reaches this module.
3. A run is bounded: ``settings.max_tool_calls_per_run`` tool calls and
   ``settings.max_output_tokens_per_run`` output tokens. Hitting the cap ends the
   run with a report instead of letting the loop spin.

The Claude call shape is fixed by ``docs/architecture.md``::

    client.beta.messages.tool_runner(
        model=settings.llm_model,
        max_tokens=settings.max_output_tokens_per_run,
        thinking={"type": "adaptive"},
        output_config={"effort": settings.llm_effort},
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        system=[{"type": "text", "text": SYSTEM_PREFIX,
                 "cache_control": {"type": "ephemeral"}}],
        tools=[...],
        messages=[{"role": "user", "content": task}],
    )

The redacted estate summary is appended as a *second* system block so the first
one stays byte-stable and the ephemeral cache actually hits.

Two SDK contracts are load-bearing here and are covered by tests that use the
real classes rather than a fake:

* ``client.beta.messages.tool_runner`` partitions its ``tools`` argument with
  ``isinstance(tool, (BetaFunctionTool, BetaBuiltinFunctionTool))``. Anything
  else is passed through as a raw tool definition and is never dispatched, so
  the redacting wrapper has to be a real subclass or none of this module's
  guarantees hold at runtime.
* ``messages.parse`` refuses a non-streaming request whose ``max_tokens`` could
  take longer than ten minutes *unless* the client carries an explicit timeout.
  With the platform's 64k budget that is every single run, so the client is
  built with one.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from infra_agent.config import Settings, get_settings
from infra_agent.monitoring import metrics
from infra_agent.redaction.gateway import RawConfigError, RedactionGateway
from infra_agent.tools.registry import ToolSpec, llm_tools, load_all

log = logging.getLogger(__name__)

PROMPTS_DIR = Path(__file__).parent / "prompts"
SYSTEM_PROMPT_PATH = PROMPTS_DIR / "system.md"

#: Never handed to the model, whatever the registry happens to contain.
FORBIDDEN_TOOLS = frozenset({"change.approve", "change.execute", "change.rollback"})

#: Server-side refusal fallbacks: a declined turn is retried on a fallback model
#: inside the same call instead of ending the duty with nothing.
BETAS = ["server-side-fallback-2026-07-01"]
FALLBACKS = "default"

#: The SDK raises before any request when a non-streaming call could run longer
#: than ten minutes *and* the client still carries the default timeout
#: (``_calculate_nonstreaming_timeout``: ``3600 * max_tokens / 128_000 > 600``).
#: 64k output tokens trip that on every run, so the client declares its own
#: timeout: 1800s is the SDK's own worst-case estimate for that budget.
CLIENT_TIMEOUT_SECONDS = 1800.0
CLIENT_CONNECT_TIMEOUT_SECONDS = 10.0


def load_system_prefix(path: Path | None = None) -> str:
    return (path or SYSTEM_PROMPT_PATH).read_text(encoding="utf-8").strip()


SYSTEM_PREFIX = load_system_prefix()


class AgentRunResult(BaseModel):
    """What one agent run produced. Safe to log and to show the owner."""

    kind: str
    outcome: str  # completed | tool_call_cap | refusal | error
    report: str
    text: str = ""
    tool_calls: int = 0
    turns: int = 0
    stop_reason: str | None = None
    refusal_category: str | None = None
    payload: dict[str, Any] | None = Field(
        default=None, description="Structured object parsed out of the final message, if any"
    )

    @property
    def ok(self) -> bool:
        return self.outcome == "completed"


@dataclass
class ToolBudget:
    """Per-run tool call budget, shared by every wrapped tool in one run."""

    limit: int
    used: int = 0
    exhausted: bool = False
    per_tool: dict[str, int] = field(default_factory=dict)

    def remaining(self) -> int:
        return max(self.limit - self.used, 0)

    def take(self, tool: str) -> bool:
        if self.remaining() <= 0:
            self.exhausted = True
            return False
        self.used += 1
        self.per_tool[tool] = self.per_tool.get(tool, 0) + 1
        return True


class RedactedTool:
    """A registry tool as the model sees it: result redacted, call counted, capped.

    Implements the SDK's runnable-tool shape (``name`` / ``to_dict`` / ``call``)
    by delegating the schema to a ``beta_tool``-wrapped function and taking over
    the result path.

    This class is only the implementation: what is handed to the SDK is the
    subclass built by :func:`redacted_tool_class`, which also inherits the SDK's
    ``BetaBuiltinFunctionTool`` so that ``tool_runner`` recognises it as
    runnable. A plain class is silently treated as a raw tool definition -
    serialised into the request as-is and never dispatched - which would leave
    every tool result unredacted, uncounted and uncapped.
    """

    def __init__(
        self,
        spec: ToolSpec,
        inner: Any,
        gateway: RedactionGateway,
        budget: ToolBudget,
    ) -> None:
        self.spec = spec
        self._inner = inner
        self._gateway = gateway
        self._budget = budget

    @property
    def name(self) -> str:
        return str(self._inner.name)

    # `Any`, not `dict[str, Any]`: the SDK types this as a `BetaToolUnionParam`
    # TypedDict union, which a plain dict is not assignable to.
    def to_dict(self) -> Any:
        return dict(self._inner.to_dict())

    def call(self, input: Any) -> str:
        if not self._budget.take(self.spec.name):
            log.warning("tool call budget exhausted, refusing %s", self.spec.name)
            return json.dumps(
                {"error": "tool call budget for this run is exhausted", "tool": self.spec.name}
            )
        metrics.AGENT_TOOL_CALLS.labels(tool=self.spec.name).inc()
        try:
            result = self._inner.call(input)
        except Exception as exc:  # a tool failure is data for the model, not a crash
            log.exception("tool %s failed", self.spec.name)
            result = {"error": f"{type(exc).__name__}: {exc}"}
        try:
            safe = self._gateway.egress(result, tool=self.spec.name)
        except RawConfigError:
            # A tool that hands back a raw config is a bug in that tool. Drop the
            # result loudly rather than ending the run, and tell the model why.
            log.error("%s returned a raw device configuration; result dropped", self.spec.name)
            return json.dumps(
                {
                    "error": "refused: that result looked like a raw device configuration, "
                    "which never leaves the network. Ask for parsed rows instead.",
                    "tool": self.spec.name,
                }
            )
        return safe if isinstance(safe, str) else json.dumps(safe, default=str)


@lru_cache(maxsize=1)
def redacted_tool_class() -> type[RedactedTool]:
    """The SDK-recognised :class:`RedactedTool` subclass, built on first use.

    ``anthropic`` is an optional extra, so the base class cannot be imported at
    module import time; the subclass is built lazily and cached. Subclassing is
    what puts the wrapper on the runner's ``runnable_tools`` side of
    ``isinstance(tool, (BetaFunctionTool, BetaBuiltinFunctionTool))``.
    """
    from anthropic.lib.tools import BetaBuiltinFunctionTool

    class SdkRedactedTool(RedactedTool, BetaBuiltinFunctionTool):
        """`RedactedTool` the SDK's tool runner will actually dispatch to."""

    return SdkRedactedTool


def api_tool_name(name: str) -> str:
    """Registry names are dotted; the API only accepts ``[a-zA-Z0-9_-]``."""
    return name.replace(".", "_")


def unmask_for_owner(gateway: RedactionGateway, text: str) -> str:
    """Turn ``PUBIP_n`` pseudonyms back into the real addresses for the owner.

    ``docs/redaction-policy.md`` requires the reversal so the model's output
    stays usable; only text on its way *to a human* is unmasked, never anything
    that goes back to the model.

    The replacement runs longest-token-first: a plain pass in insertion order
    (what ``RedactionGateway.unmask`` does today) rewrites the ``PUBIP_1`` inside
    ``PUBIP_10``. Once the redaction package folds that ordering into ``unmask``
    this helper becomes a straight delegation.
    """
    reverse = getattr(getattr(gateway, "ips", None), "reverse", None)
    if not reverse:
        return text
    for token in sorted(reverse, key=len, reverse=True):
        text = text.replace(token, reverse[token])
    return text


def estate_summary(
    settings: Settings | None = None,
    gateway: RedactionGateway | None = None,
) -> dict[str, Any]:
    """A small, redacted picture of the estate for the system prompt."""
    from infra_agent.models.common import SeedInventory
    from infra_agent.store.snapshots import FileSnapshotStore

    settings = settings or get_settings()
    gateway = gateway or RedactionGateway(audit_log=settings.audit_log)
    inventory = SeedInventory.load(settings.seed_inventory)
    store = FileSnapshotStore(settings.snapshot_dir)
    now = datetime.now(UTC)
    devices: list[dict[str, Any]] = []
    for device in inventory.devices:
        snapshot = None
        for collector in (device.platform, device.kind.value):
            snapshot = store.latest(device.name, collector)
            if snapshot is not None:
                break
        devices.append(
            {
                "name": device.name,
                "kind": device.kind.value,
                "platform": device.platform,
                "tags": device.tags,
                "license": device.license,
                "snapshot_age_seconds": (
                    int((now - snapshot.taken_at).total_seconds()) if snapshot else None
                ),
            }
        )
    summary = {
        "frozen": settings.frozen,
        "tier0_shadow_mode": settings.tier0_shadow_mode,
        "device_count": len(devices),
        "devices": devices,
    }
    return dict(gateway.egress(summary, tool="agent.estate_summary"))


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Return the last balanced top-level JSON object in `text`, or None.

    The model is asked for JSON but may wrap it in prose or a fence, so parse
    what is actually there instead of trusting the formatting.
    """
    candidates: list[dict[str, Any]] = []
    depth = 0
    start = -1
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}" and depth:
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    parsed = json.loads(text[start : index + 1])
                except ValueError:
                    parsed = None
                if isinstance(parsed, dict):
                    candidates.append(parsed)
    return candidates[-1] if candidates else None


class AgentRunner:
    """One bounded, redacted Claude run with the platform's read tools attached."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        gateway: RedactionGateway | None = None,
        client: Any | None = None,
        tools: Sequence[ToolSpec] | None = None,
        summary_provider: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.gateway = gateway or RedactionGateway(audit_log=self.settings.audit_log)
        self._client = client
        self._tool_specs = list(tools) if tools is not None else None
        self._summary_provider = summary_provider

    # -- wiring -------------------------------------------------------------
    def client(self) -> Any:
        if self._client is None:
            import anthropic  # lazy: optional dependency

            # The explicit timeout is not a tuning knob: without it the SDK
            # refuses every non-streaming call this module makes (see the module
            # docstring), so each run would end as outcome="error".
            self._client = anthropic.Anthropic(timeout=self.request_timeout())
        return self._client

    def request_timeout(self) -> Any:
        """The per-request timeout every call in this module carries."""
        try:
            import anthropic  # lazy: optional dependency

            return anthropic.Timeout(CLIENT_TIMEOUT_SECONDS, connect=CLIENT_CONNECT_TIMEOUT_SECONDS)
        except Exception:  # pragma: no cover - only without the optional extra
            return CLIENT_TIMEOUT_SECONDS

    def tool_specs(self) -> list[ToolSpec]:
        if self._tool_specs is not None:
            specs = list(self._tool_specs)
        else:
            load_all()
            specs = llm_tools()
        allowed: list[ToolSpec] = []
        for spec in specs:
            if not spec.llm_callable or spec.name in FORBIDDEN_TOOLS:
                log.error("refusing to expose human-only tool %s to the model", spec.name)
                continue
            allowed.append(spec)
        return allowed

    def build_tools(self, budget: ToolBudget) -> list[RedactedTool]:
        from anthropic import beta_tool  # lazy: optional dependency

        wrapper = redacted_tool_class()
        wrapped: list[RedactedTool] = []
        for spec in self.tool_specs():
            try:
                inner = beta_tool(
                    spec.fn, name=api_tool_name(spec.name), description=spec.description
                )
            except Exception:  # a tool the SDK cannot describe is dropped, never guessed at
                log.exception("cannot build a tool schema for %s; skipping it", spec.name)
                continue
            wrapped.append(wrapper(spec, inner, self.gateway, budget))
        return wrapped

    def system_blocks(self, tools: Sequence[RedactedTool] = ()) -> list[dict[str, Any]]:
        summary = (self._summary_provider or self._default_summary)()
        # The API name is the dotted registry name with underscores, so tell the
        # model what the tools are actually called rather than leaving it to
        # guess from prose.
        summary = {**summary, "tools": sorted(tool.name for tool in tools)}
        return [
            {"type": "text", "text": SYSTEM_PREFIX, "cache_control": {"type": "ephemeral"}},
            {
                "type": "text",
                "text": "Estate summary (redacted):\n"
                + json.dumps(summary, indent=1, sort_keys=True, default=str),
            },
        ]

    def _default_summary(self) -> dict[str, Any]:
        try:
            return estate_summary(self.settings, self.gateway)
        except Exception:
            log.exception("estate summary failed; running without one")
            return {"error": "estate summary unavailable"}

    # -- the run ------------------------------------------------------------
    def run(self, task: str, *, kind: str = "ad_hoc", context: Any = None) -> AgentRunResult:
        """Run one bounded conversation and return a report on it."""
        budget = ToolBudget(limit=max(int(self.settings.max_tool_calls_per_run), 0))
        try:
            tools = self.build_tools(budget)
            content = self.user_content(task, context, kind=kind)
            runner = self.client().beta.messages.tool_runner(
                model=self.settings.llm_model,
                max_tokens=self.settings.max_output_tokens_per_run,
                thinking={"type": "adaptive"},
                output_config={"effort": self.settings.llm_effort},
                betas=BETAS,
                fallbacks=FALLBACKS,
                system=self.system_blocks(tools),
                tools=tools,
                messages=[{"role": "user", "content": content}],
                # Not a tuning knob: an explicit request timeout is what makes a
                # non-streaming call with this max_tokens legal at all, and
                # stating it here covers an injected client too.
                timeout=self.request_timeout(),
            )
            result = self._consume(runner, budget, kind)
        except Exception as exc:
            log.exception("agent run %s failed", kind)
            result = AgentRunResult(
                kind=kind,
                outcome="error",
                report=f"The run failed before it finished: {type(exc).__name__}: {exc}",
                tool_calls=budget.used,
            )
        metrics.AGENT_RUNS.labels(kind=kind, outcome=result.outcome).inc()
        return result

    def run_json(self, task: str, *, kind: str = "ad_hoc", context: Any = None) -> AgentRunResult:
        """`run` plus a best-effort parse of a JSON object out of the final message."""
        result = self.run(task, kind=kind, context=context)
        result.payload = extract_json_object(result.text)
        return result

    def user_content(self, task: str, context: Any = None, *, kind: str = "ad_hoc") -> str:
        """Everything the model reads about this task, redacted on the way out."""
        if context is None:
            return str(self.gateway.egress(task, tool=f"agent.{kind}.task"))
        safe = self.gateway.egress({"task": task, "context": context}, tool=f"agent.{kind}.task")
        return (
            f"{safe['task']}\n\nContext (redacted):\n"
            f"{json.dumps(safe['context'], indent=1, sort_keys=True, default=str)}"
        )

    def _consume(self, runner: Iterable[Any], budget: ToolBudget, kind: str) -> AgentRunResult:
        outcome = "completed"
        turns = 0
        texts: list[str] = []
        stop_reason: str | None = None
        refusal_category: str | None = None
        for message in runner:
            turns += 1
            stop_reason = getattr(message, "stop_reason", None)
            texts = _message_text(message) or texts
            if stop_reason == "refusal":
                outcome = "refusal"
                refusal_category = _refusal_category(message)
                break
            pending = _pending_tool_calls(message)
            # The SDK runs this turn's tools once the loop body returns, so the
            # cap is checked before they run and never overshoots.
            if budget.exhausted or (pending and budget.remaining() < pending):
                outcome = "tool_call_cap"
                break
        # From here on the text is owner-facing, so the public-IP pseudonyms go
        # back to being addresses. The conversation the SDK keeps for the model
        # is untouched and stays masked.
        text = unmask_for_owner(self.gateway, "\n".join(texts).strip())
        return AgentRunResult(
            kind=kind,
            outcome=outcome,
            report=_build_report(kind, outcome, text, budget, turns, refusal_category),
            text=text,
            tool_calls=budget.used,
            turns=turns,
            stop_reason=stop_reason,
            refusal_category=refusal_category,
        )


def _message_text(message: Any) -> list[str]:
    texts: list[str] = []
    for block in getattr(message, "content", None) or []:
        if getattr(block, "type", None) == "text" and getattr(block, "text", None):
            texts.append(str(block.text))
    return texts


def _pending_tool_calls(message: Any) -> int:
    return sum(
        1
        for block in getattr(message, "content", None) or []
        if getattr(block, "type", None) == "tool_use"
    )


def _refusal_category(message: Any) -> str | None:
    details = getattr(message, "stop_details", None)
    return getattr(details, "category", None) if details is not None else None


def _build_report(
    kind: str,
    outcome: str,
    text: str,
    budget: ToolBudget,
    turns: int,
    refusal_category: str | None,
) -> str:
    header = (
        f"Agent run `{kind}` finished as **{outcome}** after {turns} turn(s) "
        f"and {budget.used}/{budget.limit} tool call(s)."
    )
    if outcome == "tool_call_cap":
        return (
            f"{header}\n\nThe run was stopped because it reached the per-run tool call cap, "
            "so its conclusions are incomplete. Partial output:\n\n"
            f"{text or '(no text produced)'}"
        )
    if outcome == "refusal":
        reason = f" (category: {refusal_category})" if refusal_category else ""
        return (
            f"{header}\n\nThe model declined to answer{reason}; nothing was decided and no "
            "action was taken. Partial output:\n\n" + (text or "(no text produced)")
        )
    return f"{header}\n\n{text or '(no text produced)'}"
