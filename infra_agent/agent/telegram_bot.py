"""Telegram bot: the owner's primary channel.

Design constraints (ADR 0005 and docs/risk-tiers.md):

- long polling only: no inbound port on the firewall;
- only OWNER_ID is accepted, everything else is ignored and logged without
  its content;
- Tier 1 approvals are inline buttons whose ``callback_data`` carries only the
  plan id and an action. The approval token is *never* in the callback data,
  the message text or a log line: it lives in the in-process
  :class:`PendingApprovals` map, keyed by plan id and bound to the owner id;
- Tier 2 additionally requires the owner to type the confirmation phrase as a
  reply within ``PHRASE_TIMEOUT``. The phrase is never echoed by the bot: the
  owner types what they already know, which is what makes it a confirmation.

Redaction. Two different jobs, so two different objects:

- ``llm_gateway`` is a full :class:`RedactionGateway`. It is used for the only
  payload here that leaves for the Claude API: the ``/ask`` question, which is
  passed through ``egress()`` (audit line included) before the callback sees it.
- ``channel_redactor`` is a gateway configured with ``mask_public_ips=False``
  and is applied to every string this bot sends to Telegram. Telegram is a
  third party, so secrets are stripped there too, but the owner is a human on
  a human channel and wants to read real public IPs, and nothing here is an
  API egress so no audit line is written.

`python-telegram-bot` is an optional dependency and is imported lazily inside
functions, so importing this module (and the test suite) never requires it.
Never log or repr the Application or the Bot: their repr contains the token.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from infra_agent.change.plan import ChangePlan, Tier
from infra_agent.change.store import ApprovalError, PlanStore
from infra_agent.config import Settings, get_settings
from infra_agent.monitoring import metrics
from infra_agent.redaction.gateway import RawConfigError, RedactionGateway, RedactionRules

log = logging.getLogger(__name__)

#: Telegram's hard limit is 4096 characters; we split well below it.
MAX_MESSAGE_CHARS = 4000
#: Telegram's hard limit for callback_data is 64 bytes.
MAX_CALLBACK_BYTES = 64
#: How long the owner has to type a Tier 2 confirmation phrase.
PHRASE_TIMEOUT = timedelta(minutes=10)
#: How long a minted approval token stays usable from a button in this process.
APPROVAL_TTL = timedelta(hours=24)
#: Prefix of every callback_data this bot emits.
CALLBACK_PREFIX = "cp"
#: How often the quiet-hours queue is checked while the bot is polling.
QUIET_FLUSH_INTERVAL_SECONDS = 60.0
#: Longest structured diff rendered into an approval message.
MAX_DIFF_CHARS = 1500

AskCallback = Callable[[str], "str | Awaitable[str]"]
DigestCallback = Callable[[], "str | Awaitable[str]"]

COMMANDS: dict[str, str] = {
    "/status": "platform and estate summary",
    "/ask <question>": "route a question to the agent",
    "/pending": "list changes awaiting approval",
    "/freeze": "break-glass: stop all automation, agent read-only",
    "/unfreeze": "lift the freeze",
    "/digest": "send today's digest now",
    "/help": "this list",
}

TIER_LABELS = {
    Tier.AUTO: "automatic",
    Tier.APPROVAL: "one approval",
    Tier.WINDOW: "approval + window + confirmation phrase",
}

#: Read tools tried in order for the estate half of ``/status``. Other packages
#: register their own; whichever exists first and takes no arguments is used.
ESTATE_TOOLS = (
    "inventory.summary",
    "estate.summary",
    "topology.summary",
    "inventory.status",
    "onboarding.status",
)


class TelegramConfigError(RuntimeError):
    """The bot token or the owner id is missing from the secrets store."""


# --------------------------------------------------------------------------- #
# owner gate
# --------------------------------------------------------------------------- #
@dataclass
class OwnerGate:
    owner_id: int

    def allows(self, sender_id: int | None) -> bool:
        return sender_id is not None and int(sender_id) == self.owner_id


# --------------------------------------------------------------------------- #
# credentials
# --------------------------------------------------------------------------- #
def load_owner_credentials(
    secrets: Any | None = None, settings: Settings | None = None
) -> tuple[SecretStr, int]:
    """Read ``telegram_bot_token`` / ``telegram_owner_id`` from the platform secrets.

    The token is returned as a :class:`SecretStr` and is only unwrapped where
    it is handed to the Telegram client. It is never logged.
    """
    if secrets is None:
        from infra_agent.onboarding.secrets import SecretsStore

        secrets = SecretsStore((settings or get_settings()).secrets_dir)
    token = secrets.get("platform", "telegram_bot_token")
    owner = secrets.get("platform", "telegram_owner_id")
    if not token or owner in (None, ""):
        raise TelegramConfigError(
            "telegram_bot_token / telegram_owner_id are missing from "
            "secrets/platform.enc.yaml; run `infra onboard init`"
        )
    try:
        owner_id = int(str(owner).strip())
    except ValueError as exc:  # pragma: no cover - defensive
        raise TelegramConfigError("telegram_owner_id must be a numeric user id") from exc
    return SecretStr(str(token)), owner_id


# --------------------------------------------------------------------------- #
# message helpers
# --------------------------------------------------------------------------- #
def split_message(text: str, limit: int = MAX_MESSAGE_CHARS) -> list[str]:
    """Split `text` into chunks of at most `limit` characters, on line breaks."""
    if limit <= 0:
        raise ValueError("limit must be positive")
    if not text:
        return [""]
    chunks: list[str] = []
    current = ""
    for line in text.split("\n"):
        while len(line) > limit:
            if current:
                chunks.append(current)
                current = ""
            chunks.append(line[:limit])
            line = line[limit:]
        candidate = line if not current else f"{current}\n{line}"
        if len(candidate) > limit:
            chunks.append(current)
            current = line
        else:
            current = candidate
    if current or not chunks:
        chunks.append(current)
    return chunks


def channel_redactor() -> RedactionGateway:
    """Secret-stripping for the owner channel: no IP pseudonyms, no audit line."""
    rules = RedactionRules.load().model_copy(update={"mask_public_ips": False})
    return RedactionGateway(rules=rules)


def _callback_data(action: str, plan_id: str) -> str:
    return f"{CALLBACK_PREFIX}:{action}:{plan_id}"


def parse_callback(data: str | None) -> tuple[str, str] | None:
    """``cp:approve:<plan id>`` -> ``("approve", "<plan id>")``; None if not ours."""
    parts = (data or "").split(":", 2)
    if len(parts) != 3 or parts[0] != CALLBACK_PREFIX:
        return None
    action, plan_id = parts[1], parts[2]
    if action not in ("approve", "reject") or not plan_id:
        return None
    return action, plan_id


def approval_keyboard(plan_id: str) -> Any | None:
    """Approve / Reject buttons. None when the plan id will not fit callback_data."""
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup  # lazy: optional dep

    buttons = []
    for label, action in (("Approve", "approve"), ("Reject", "reject")):
        data = _callback_data(action, plan_id)
        if len(data.encode()) > MAX_CALLBACK_BYTES:
            return None
        buttons.append(InlineKeyboardButton(label, callback_data=data))
    return InlineKeyboardMarkup([buttons])


def _render_diff(diff: Any) -> str:
    if isinstance(diff, str):
        if RedactionGateway.looks_like_raw_config(diff):
            return "  <raw configuration withheld: a plan must carry a structured diff>"
        body = diff
    else:
        body = json.dumps(diff, indent=2, sort_keys=True, default=str)
    if len(body) > MAX_DIFF_CHARS:
        body = body[:MAX_DIFF_CHARS] + "\n... truncated"
    return "\n".join(f"  {line}" for line in body.split("\n"))


def render_plan(plan: ChangePlan) -> str:
    """Owner-facing summary of a plan, derived from ``llm_view()``.

    ``llm_view()`` excludes the approval record and the confirmation phrase, so
    neither can leak into the message by construction.
    """
    view = plan.llm_view()
    tier = Tier(view["tier"])
    lines = [
        f"Change {view['id']}: {view['title']}",
        f"tier {int(tier)} ({TIER_LABELS[tier]}) - action {view['action']} - state {view['state']}",
        f"targets: {', '.join(view['targets']) or '-'}",
    ]
    if view.get("summary"):
        lines += ["", str(view["summary"])]
    if view.get("tier_reasons"):
        lines += ["", "why this tier:"] + [f"  - {r}" for r in view["tier_reasons"]]
    lines += ["", "structured diff:", _render_diff(view.get("diff"))]
    if view.get("pre_checks"):
        lines += ["", "pre-checks:"] + [f"  - {c}" for c in view["pre_checks"]]
    if view.get("steps"):
        lines += ["", "steps:"] + [
            f"  {i}. [{s.get('platform', '?')}] {s.get('description', '')}"
            for i, s in enumerate(view["steps"], start=1)
        ]
    if view.get("post_checks"):
        lines += ["", "post-checks:"] + [f"  - {c}" for c in view["post_checks"]]
    if view.get("rollback"):
        lines += ["", "rollback:"] + [
            f"  {i}. [{s.get('platform', '?')}] {s.get('description', '')}"
            for i, s in enumerate(view["rollback"], start=1)
        ]
    window = view.get("window")
    if window:
        lines += ["", f"maintenance window: {window['start']} -> {window['end']}"]
    if tier is Tier.WINDOW:
        lines += [
            "",
            "Tier 2: press Approve, then reply with the exact confirmation phrase "
            f"within {int(PHRASE_TIMEOUT.total_seconds() // 60)} minutes. "
            "The phrase is not shown here.",
        ]
    return "\n".join(lines)


def _render_payload(value: Any, indent: int = 0, max_items: int = 8) -> list[str]:
    pad = "  " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}{key}:")
                lines += _render_payload(item, indent + 1, max_items)
            else:
                lines.append(f"{pad}{key}: {item}")
        return lines or [f"{pad}(empty)"]
    if isinstance(value, list):
        lines = []
        for item in value[:max_items]:
            if isinstance(item, dict):
                head = item.get("name") or item.get("id") or item.get("title")
                if head is not None:
                    rest = ", ".join(
                        f"{k}={v}"
                        for k, v in item.items()
                        if k not in ("name", "id", "title") and not isinstance(v, (dict, list))
                    )
                    lines.append(f"{pad}- {head}" + (f" ({rest})" if rest else ""))
                else:
                    lines.append(f"{pad}-")
                    lines += _render_payload(item, indent + 1, max_items)
            else:
                lines.append(f"{pad}- {item}")
        if len(value) > max_items:
            lines.append(f"{pad}- ... and {len(value) - max_items} more")
        return lines or [f"{pad}(none)"]
    return [f"{pad}{value}"]


# --------------------------------------------------------------------------- #
# quiet hours
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class QuietHours:
    """Hours (local time, 0-23) during which non-critical messages are queued.

    ``start == end`` or either being None means "never quiet"; a queue that can
    never be flushed would silently swallow the owner's notifications.
    """

    start: int | None = None
    end: int | None = None

    @classmethod
    def from_settings(cls, settings: Settings) -> QuietHours:
        return cls(settings.telegram_quiet_start, settings.telegram_quiet_end)

    @property
    def configured(self) -> bool:
        return self.start is not None and self.end is not None and self.start != self.end

    def is_quiet(self, when: datetime) -> bool:
        if not self.configured:
            return False
        assert self.start is not None and self.end is not None
        hour = when.hour
        if self.start < self.end:
            return self.start <= hour < self.end
        return hour >= self.start or hour < self.end

    def describe(self) -> str:
        if not self.configured:
            return "not configured"
        return f"{self.start:02d}:00-{self.end:02d}:00 local"


# --------------------------------------------------------------------------- #
# pending approvals (tokens live here and nowhere else)
# --------------------------------------------------------------------------- #
@dataclass
class PendingApproval:
    plan_id: str
    owner_id: int
    tier: Tier
    requested_at: datetime
    # repr=False so no accidental log line, traceback or f-string prints it.
    token: str = field(repr=False, default="")


@dataclass
class PhrasePrompt:
    plan_id: str
    owner_id: int
    expires_at: datetime


class PendingApprovals:
    """In-process map of plan id -> approval token, bound to the owner id.

    Deliberately not persisted: a token that survives a restart in a file is a
    token that can be stolen from a file. After a restart the owner approves
    from the CLI, or the change engine re-requests approval.
    """

    def __init__(self, ttl: timedelta = APPROVAL_TTL):
        self.ttl = ttl
        self._pending: dict[str, PendingApproval] = {}
        self._phrases: dict[int, PhrasePrompt] = {}

    def remember(
        self,
        plan_id: str,
        token: str,
        owner_id: int,
        tier: Tier,
        now: datetime | None = None,
    ) -> None:
        now = now or datetime.now(UTC)
        self._expire(now)
        self._pending[plan_id] = PendingApproval(
            plan_id=plan_id, owner_id=int(owner_id), tier=tier, requested_at=now, token=token
        )

    def token_for(self, plan_id: str, owner_id: int, now: datetime | None = None) -> str | None:
        now = now or datetime.now(UTC)
        self._expire(now)
        entry = self._pending.get(plan_id)
        if entry is None or entry.owner_id != int(owner_id):
            return None
        return entry.token

    def holds(self, plan_id: str) -> bool:
        return plan_id in self._pending

    def forget(self, plan_id: str) -> None:
        self._pending.pop(plan_id, None)
        for owner_id, prompt in list(self._phrases.items()):
            if prompt.plan_id == plan_id:
                del self._phrases[owner_id]

    def ids(self) -> list[str]:
        return list(self._pending)

    # -- tier 2 confirmation phrase ----------------------------------------
    def expect_phrase(self, plan_id: str, owner_id: int, now: datetime | None = None) -> None:
        now = now or datetime.now(UTC)
        self._phrases[int(owner_id)] = PhrasePrompt(
            plan_id=plan_id, owner_id=int(owner_id), expires_at=now + PHRASE_TIMEOUT
        )

    def pop_phrase_prompt(self, owner_id: int) -> PhrasePrompt | None:
        """Return and clear the pending phrase prompt (expired or not)."""
        return self._phrases.pop(int(owner_id), None)

    def awaiting_phrase(self, owner_id: int) -> bool:
        return int(owner_id) in self._phrases

    def _expire(self, now: datetime) -> None:
        for plan_id, entry in list(self._pending.items()):
            if now - entry.requested_at > self.ttl:
                log.info("approval token for %s expired in this bot session", plan_id)
                self.forget(plan_id)


# --------------------------------------------------------------------------- #
# notifier
# --------------------------------------------------------------------------- #
def _local_now() -> datetime:
    return datetime.now().astimezone()


class TelegramNotifier:
    """`infra_agent.agent.notify.Notifier` over a Telegram bot.

    The methods are synchronous because the protocol is: coroutines produced by
    the Telegram client are dispatched onto whatever loop is available (the
    polling loop when the bot is running, a throwaway loop otherwise).
    """

    def __init__(
        self,
        bot: Any,
        owner_id: int,
        *,
        pending: PendingApprovals | None = None,
        quiet_hours: QuietHours | None = None,
        redactor: RedactionGateway | None = None,
        clock: Callable[[], datetime] | None = None,
        loop: asyncio.AbstractEventLoop | None = None,
    ):
        self.bot = bot
        self.owner_id = int(owner_id)
        self.pending = pending if pending is not None else PendingApprovals()
        self.quiet_hours = quiet_hours or QuietHours()
        self.redactor = redactor or channel_redactor()
        self._clock = clock or _local_now
        self._loop = loop
        self._queue: list[str] = []
        self._tasks: set[asyncio.Task[Any]] = set()

    # -- Notifier protocol --------------------------------------------------
    def send(self, text: str, *, critical: bool = False) -> None:
        safe = self.redactor.redact_text(text)
        if not critical and self.quiet_hours.is_quiet(self._clock()):
            self._queue.append(safe)
            log.info(
                "quiet hours (%s): queued a non-critical message, %d waiting",
                self.quiet_hours.describe(),
                len(self._queue),
            )
            return
        self._deliver(safe)

    def send_approval_request(self, plan: ChangePlan, token: str) -> None:
        """Render the plan and offer Approve / Reject buttons.

        The token goes into :class:`PendingApprovals` only. It is not in the
        message, not in the callback data, and not in any log line. Approval
        requests are actionable, so they bypass quiet hours.
        """
        self.pending.remember(
            plan.id, token, owner_id=self.owner_id, tier=plan.tier, now=datetime.now(UTC)
        )
        text = self.redactor.redact_text(render_plan(plan))
        markup = approval_keyboard(plan.id)
        if markup is None:
            text += "\n\nApprove from the CLI: `infra change approve " + plan.id + "`"
        chunks = split_message(text)
        for chunk in chunks[:-1]:
            self._dispatch(self.bot.send_message(chat_id=self.owner_id, text=chunk))
        self._dispatch(
            self.bot.send_message(chat_id=self.owner_id, text=chunks[-1], reply_markup=markup)
        )
        log.info("approval request sent for %s (tier %s)", plan.id, int(plan.tier))

    def send_report(self, title: str, body_markdown: str) -> None:
        self.send(f"{title}\n\n{body_markdown}")

    # -- quiet hours --------------------------------------------------------
    def queued(self) -> int:
        return len(self._queue)

    def flush_quiet_queue(self, *, force: bool = False) -> int:
        """Deliver everything queued during quiet hours. Returns the count."""
        if not self._queue:
            return 0
        if not force and self.quiet_hours.is_quiet(self._clock()):
            return 0
        queued, self._queue = self._queue, []
        for text in queued:
            self._deliver(text)
        log.info("quiet hours ended: flushed %d queued message(s)", len(queued))
        return len(queued)

    # -- plumbing -----------------------------------------------------------
    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def _deliver(self, text: str) -> None:
        for chunk in split_message(text):
            self._dispatch(self.bot.send_message(chat_id=self.owner_id, text=chunk))

    def _dispatch(self, coro: Any) -> None:
        """Run `coro` on whatever loop is available; a failed send never propagates.

        Only the exception type is logged: a Telegram error can carry parts of
        the request back with it, and message bodies do not belong in the log.
        """
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is not None:
            task = running.create_task(coro)
            self._tasks.add(task)
            task.add_done_callback(self._finish_task)
            return
        if self._loop is not None and self._loop.is_running():
            future = asyncio.run_coroutine_threadsafe(coro, self._loop)
            future.add_done_callback(self._finish_task)
            return
        try:
            asyncio.run(coro)
        except Exception as exc:
            log.error("sending a telegram message failed (%s)", type(exc).__name__)

    def _finish_task(self, task: Any) -> None:
        self._tasks.discard(task)
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            log.error("sending a telegram message failed (%s)", type(exc).__name__)


# --------------------------------------------------------------------------- #
# handlers
# --------------------------------------------------------------------------- #
async def _maybe_await(value: Any) -> Any:
    if asyncio.iscoroutine(value) or isinstance(value, asyncio.Future):
        return await value
    return value


class TelegramBotApp:
    """Command, callback and message handlers. Every one of them is owner-gated."""

    def __init__(
        self,
        store: PlanStore,
        owner_id: int,
        *,
        ask: AskCallback | None = None,
        digest: DigestCallback | None = None,
        notifier: TelegramNotifier | None = None,
        pending: PendingApprovals | None = None,
        settings: Settings | None = None,
        llm_gateway: RedactionGateway | None = None,
        redactor: RedactionGateway | None = None,
        clock: Callable[[], datetime] | None = None,
    ):
        self.store = store
        self.gate = OwnerGate(int(owner_id))
        self.ask = ask
        self.digest = digest
        self.settings = settings or get_settings()
        self.pending = (
            pending
            if pending is not None
            else (notifier.pending if notifier is not None else PendingApprovals())
        )
        self.notifier = notifier
        self.channel_redactor = redactor or channel_redactor()
        self.llm_gateway = llm_gateway or RedactionGateway(audit_log=self.settings.audit_log)
        self._clock = clock or (lambda: datetime.now(UTC))

    # -- gate ---------------------------------------------------------------
    @property
    def owner_id(self) -> int:
        return self.gate.owner_id

    def _approver(self) -> str:
        return f"telegram:{self.gate.owner_id}"

    def _allowed(self, update: Any, kind: str) -> bool:
        sender = getattr(getattr(update, "effective_user", None), "id", None)
        if self.gate.allows(sender):
            return True
        # Content is deliberately not logged: it is not ours and may be anything.
        log.warning("ignored telegram %s from non-owner id=%r (content not logged)", kind, sender)
        return False

    # -- outbound -----------------------------------------------------------
    async def _reply(self, update: Any, text: str) -> None:
        message = getattr(update, "effective_message", None)
        if message is None:
            return
        for chunk in split_message(self.channel_redactor.redact_text(text)):
            await message.reply_text(chunk)

    async def _edit(self, query: Any, text: str) -> None:
        edit = getattr(query, "edit_message_text", None)
        if edit is None:
            return
        await edit(split_message(self.channel_redactor.redact_text(text))[0])

    # -- commands -----------------------------------------------------------
    async def cmd_help(self, update: Any, context: Any = None) -> None:
        if not self._allowed(update, "command"):
            return
        lines = ["Infrastructure agent - owner channel", ""]
        lines += [f"{cmd}  -  {desc}" for cmd, desc in COMMANDS.items()]
        lines += [
            "",
            "Approvals arrive as Approve / Reject buttons. Tier 2 changes also "
            "need the confirmation phrase typed as a reply.",
        ]
        await self._reply(update, "\n".join(lines))

    async def cmd_status(self, update: Any, context: Any = None) -> None:
        if not self._allowed(update, "command"):
            return
        payload = {
            "platform": self._platform_status(),
            "estate": self._estate_payload(),
        }
        try:
            self.channel_redactor.refuse_raw_config(payload)
            safe = self.channel_redactor.redact(payload)
        except RawConfigError:
            safe = {
                "platform": self.channel_redactor.redact(payload["platform"]),
                "estate": "withheld: a read tool returned raw configuration",
            }
        await self._reply(update, "\n".join(_render_payload(safe)))

    def _platform_status(self) -> dict[str, Any]:
        frozen = self.settings.frozen or (self.settings.data_dir / "FROZEN").exists()
        try:
            pending_count = len(self.store.pending())
        except Exception:  # pragma: no cover - defensive, store is local sqlite
            pending_count = -1
        quiet = (
            self.notifier.quiet_hours
            if self.notifier is not None
            else QuietHours.from_settings(self.settings)
        )
        return {
            "frozen": "yes" if frozen else "no",
            "tier0_shadow_mode": "on" if self.settings.tier0_shadow_mode else "off",
            "model": self.settings.llm_model,
            "awaiting_approval": pending_count,
            "quiet_hours": quiet.describe(),
            "queued_messages": self.notifier.queued() if self.notifier is not None else 0,
        }

    def _estate_payload(self) -> Any:
        """First registered, argument-free read tool from ESTATE_TOOLS."""
        import inspect

        try:
            from infra_agent.tools.registry import REGISTRY, load_all

            load_all()
        except Exception as exc:  # pragma: no cover - defensive
            return f"tool registry unavailable ({type(exc).__name__})"
        for name in ESTATE_TOOLS:
            spec = REGISTRY.get(name)
            if spec is None or not spec.llm_callable:
                continue
            required = [
                p
                for p in inspect.signature(spec.fn).parameters.values()
                if p.default is inspect.Parameter.empty
                and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)
            ]
            if required:
                continue
            try:
                return {name: spec.fn()}
            except Exception as exc:
                # Only the exception type: the message may carry anything.
                return f"{name} unavailable ({type(exc).__name__})"
        return "no read tool registered yet"

    async def cmd_pending(self, update: Any, context: Any = None) -> None:
        if not self._allowed(update, "command"):
            return
        plans = self.store.pending()
        if not plans:
            await self._reply(update, "Nothing is awaiting approval.")
            return
        lines = [f"{len(plans)} change(s) awaiting approval:", ""]
        for plan in plans:
            lines.append(
                f"{plan.id}  tier {int(plan.tier)}  {plan.title}"
                f"  -> {', '.join(plan.targets) or '-'}"
            )
            if not self.pending.holds(plan.id):
                lines.append("    no live button in this bot session; approve from the CLI")
        await self._reply(update, "\n".join(lines))

    async def cmd_ask(self, update: Any, context: Any = None) -> None:
        if not self._allowed(update, "command"):
            return
        question = self._command_argument(update, context)
        if not question:
            await self._reply(update, "Usage: /ask <question>")
            return
        if self.ask is None:
            await self._reply(update, "No agent is attached to this bot; /ask is unavailable.")
            return
        # The question is on its way to the model: full gateway, audit line included.
        try:
            safe_question = self.llm_gateway.egress(question, tool="telegram.ask")
        except RawConfigError:
            await self._reply(
                update,
                "That looks like a raw device configuration. The model never sees "
                "raw configs; ask about the parsed inventory instead.",
            )
            return
        try:
            answer = await _maybe_await(self.ask(safe_question))
        except Exception as exc:
            # Only the type: an agent error can quote the prompt or a key back.
            log.error("/ask failed (%s)", type(exc).__name__)
            await self._reply(update, f"The agent failed to answer ({type(exc).__name__}).")
            return
        await self._reply(update, str(answer) or "(no answer)")

    async def cmd_digest(self, update: Any, context: Any = None) -> None:
        if not self._allowed(update, "command"):
            return
        if self.digest is None:
            await self._reply(update, "No digest source is attached to this bot.")
            return
        try:
            body = await _maybe_await(self.digest())
        except Exception as exc:
            log.error("/digest failed (%s)", type(exc).__name__)
            await self._reply(update, f"The digest failed ({type(exc).__name__}).")
            return
        await self._reply(update, str(body) or "(empty digest)")

    async def cmd_freeze(self, update: Any, context: Any = None) -> None:
        if not self._allowed(update, "command"):
            return
        marker = self._freeze_marker()
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
        metrics.FROZEN.set(1)
        log.warning("break-glass freeze set from telegram by the owner")
        await self._reply(
            update,
            "FROZEN. All automation is stopped and the agent is read-only.\n"
            "Restart the services with INFRA_FROZEN=1 to enforce it across processes.",
        )

    async def cmd_unfreeze(self, update: Any, context: Any = None) -> None:
        if not self._allowed(update, "command"):
            return
        self._freeze_marker().unlink(missing_ok=True)
        metrics.FROZEN.set(0)
        log.warning("freeze lifted from telegram by the owner")
        await self._reply(update, "Unfrozen. Automation resumes on the next cycle.")

    def _freeze_marker(self) -> Path:
        return self.settings.data_dir / "FROZEN"

    @staticmethod
    def _command_argument(update: Any, context: Any) -> str:
        args = getattr(context, "args", None)
        if args:
            return " ".join(args).strip()
        text = getattr(getattr(update, "effective_message", None), "text", "") or ""
        parts = text.split(maxsplit=1)
        return parts[1].strip() if len(parts) > 1 else ""

    # -- inline buttons -----------------------------------------------------
    async def on_callback(self, update: Any, context: Any = None) -> None:
        query = getattr(update, "callback_query", None)
        if query is None:
            return
        if not self._allowed(update, "callback"):
            return  # not even answered: an unknown sender gets nothing back
        parsed = parse_callback(getattr(query, "data", None))
        if parsed is None:
            await query.answer("unknown action")
            return
        action, plan_id = parsed
        token = self.pending.token_for(plan_id, self.gate.owner_id, now=self._clock())
        if token is None:
            await query.answer("no live approval for this change")
            await self._edit(
                query,
                f"Change {plan_id}: this button is no longer live "
                "(the bot restarted). Approve from the CLI.",
            )
            return
        try:
            plan = self.store.get(plan_id)
        except KeyError:
            self.pending.forget(plan_id)
            await query.answer("unknown change")
            return

        if action == "reject":
            self.store.reject(
                plan_id, approver=self._approver(), channel="telegram", reason="rejected by owner"
            )
            self.pending.forget(plan_id)
            await query.answer("rejected")
            await self._edit(query, f"Change {plan_id} rejected. Nothing was executed.")
            return

        if plan.tier is Tier.WINDOW:
            self.pending.expect_phrase(plan_id, self.gate.owner_id, now=self._clock())
            await query.answer("confirmation phrase required")
            minutes = int(PHRASE_TIMEOUT.total_seconds() // 60)
            await self._edit(
                query,
                f"Change {plan_id} is Tier 2. Reply with the exact confirmation "
                f"phrase within {minutes} minutes to approve it.",
            )
            return

        try:
            self.store.approve(plan_id, token, approver=self._approver(), channel="telegram")
        except ApprovalError as exc:
            await query.answer("approval failed")
            await self._edit(query, f"Change {plan_id} was not approved: {exc}")
            return
        self.pending.forget(plan_id)
        await query.answer("approved")
        await self._edit(query, f"Change {plan_id} approved by the owner via Telegram.")

    # -- confirmation phrase replies ---------------------------------------
    async def on_message(self, update: Any, context: Any = None) -> None:
        if not self._allowed(update, "message"):
            return
        prompt = self.pending.pop_phrase_prompt(self.gate.owner_id)
        if prompt is None:
            return  # nothing is awaiting a phrase: stay quiet, this is a chat app
        text = (getattr(getattr(update, "effective_message", None), "text", "") or "").strip()
        if prompt.expires_at <= self._clock():
            await self._reply(
                update,
                f"The confirmation window for {prompt.plan_id} expired. "
                "Press Approve again to restart it.",
            )
            return
        token = self.pending.token_for(prompt.plan_id, self.gate.owner_id, now=self._clock())
        if token is None:
            await self._reply(update, f"Change {prompt.plan_id} is no longer awaiting approval.")
            return
        try:
            self.store.approve(
                prompt.plan_id,
                token,
                approver=self._approver(),
                channel="telegram",
                confirmation_phrase=text,
            )
        except ApprovalError:
            # The phrase itself is never echoed back and never logged.
            log.warning("tier 2 confirmation phrase rejected for %s", prompt.plan_id)
            await self._reply(
                update,
                f"That is not the confirmation phrase for {prompt.plan_id}. "
                "Nothing was approved; press Approve again to retry.",
            )
            return
        self.pending.forget(prompt.plan_id)
        await self._reply(
            update, f"Change {prompt.plan_id} approved by the owner via Telegram (Tier 2)."
        )

    async def on_ignored(self, update: Any, context: Any = None) -> None:
        """Catch-all in a lower group so non-owner traffic is logged, never answered."""
        sender = getattr(getattr(update, "effective_user", None), "id", None)
        log.warning("ignored telegram update from non-owner id=%r (content not logged)", sender)


# --------------------------------------------------------------------------- #
# application
# --------------------------------------------------------------------------- #
def build_application(
    store: PlanStore,
    *,
    ask: AskCallback | None = None,
    digest: DigestCallback | None = None,
    token: SecretStr | str | None = None,
    owner_id: int | None = None,
    bot: Any | None = None,
    settings: Settings | None = None,
    pending: PendingApprovals | None = None,
    quiet_hours: QuietHours | None = None,
    clock: Callable[[], datetime] | None = None,
) -> Any:
    """Build the polling Application. Tests pass `bot=` with a fake Bot.

    Returns the Application; ``application.bot_data`` carries ``"infra_bot"``
    (the :class:`TelegramBotApp`) and ``"notifier"`` (the
    :class:`TelegramNotifier`) so the agent service can reach both.
    """
    from telegram.ext import (  # lazy: optional dependency
        ApplicationBuilder,
        CallbackQueryHandler,
        CommandHandler,
        MessageHandler,
        filters,
    )

    settings = settings or get_settings()
    if owner_id is None or (token is None and bot is None):
        secret_token, secret_owner = load_owner_credentials(settings=settings)
        token = token if token is not None else secret_token
        owner_id = owner_id if owner_id is not None else secret_owner

    builder = ApplicationBuilder()
    if bot is not None:
        builder = builder.bot(bot)
    else:
        raw = token.get_secret_value() if isinstance(token, SecretStr) else str(token)
        builder = builder.token(raw)

    pending = pending if pending is not None else PendingApprovals()
    notifier_holder: dict[str, TelegramNotifier] = {}

    async def _post_init(application: Any) -> None:
        notifier = notifier_holder["notifier"]
        notifier.bind_loop(asyncio.get_running_loop())
        application.bot_data["quiet_flush_task"] = asyncio.get_running_loop().create_task(
            _quiet_hours_flusher(notifier)
        )

    async def _post_shutdown(application: Any) -> None:
        task = application.bot_data.pop("quiet_flush_task", None)
        if task is not None:
            task.cancel()

    application = builder.post_init(_post_init).post_shutdown(_post_shutdown).build()

    notifier = TelegramNotifier(
        application.bot,
        int(owner_id),
        pending=pending,
        quiet_hours=quiet_hours or QuietHours.from_settings(settings),
        clock=clock,
    )
    notifier_holder["notifier"] = notifier

    bot_app = TelegramBotApp(
        store,
        int(owner_id),
        ask=ask,
        digest=digest,
        notifier=notifier,
        pending=pending,
        settings=settings,
    )

    owner_filter = filters.User(user_id=int(owner_id))
    commands = {
        "help": bot_app.cmd_help,
        "start": bot_app.cmd_help,
        "status": bot_app.cmd_status,
        "pending": bot_app.cmd_pending,
        "ask": bot_app.cmd_ask,
        "digest": bot_app.cmd_digest,
        "freeze": bot_app.cmd_freeze,
        "unfreeze": bot_app.cmd_unfreeze,
    }
    for name, handler in commands.items():
        application.add_handler(CommandHandler(name, handler, filters=owner_filter))
    application.add_handler(CallbackQueryHandler(bot_app.on_callback))
    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND & owner_filter, bot_app.on_message)
    )
    # Lower group: anything from anyone else is logged and dropped.
    application.add_handler(MessageHandler(~owner_filter, bot_app.on_ignored), group=1)

    application.bot_data["infra_bot"] = bot_app
    application.bot_data["notifier"] = notifier
    return application


async def _quiet_hours_flusher(
    notifier: TelegramNotifier, interval: float = QUIET_FLUSH_INTERVAL_SECONDS
) -> None:
    while True:
        await asyncio.sleep(interval)
        try:
            notifier.flush_quiet_queue()
        except Exception as exc:  # pragma: no cover - a failed send must not kill the bot
            log.error("flushing the quiet-hours queue failed (%s)", type(exc).__name__)


def run_bot(
    store: PlanStore,
    ask: AskCallback | None = None,
    digest: DigestCallback | None = None,
) -> None:
    """Start the owner channel with long polling (no inbound port, ADR 0005)."""
    settings = get_settings()
    token, owner_id = load_owner_credentials(settings=settings)
    application = build_application(
        store, ask=ask, digest=digest, token=token, owner_id=owner_id, settings=settings
    )
    log.info("telegram bot starting: long polling, owner id %s", owner_id)
    application.run_polling(
        allowed_updates=["message", "callback_query"], drop_pending_updates=True
    )
