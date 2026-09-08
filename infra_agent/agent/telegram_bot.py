"""Telegram bot: the owner's primary channel.

Design constraints (ADR 0005 and docs/risk-tiers.md):

- long polling only: no inbound port on the firewall;
- only the owner's user id, in a private chat, is accepted. Everything else is
  ignored and logged without its content;
- Tier 1 approvals are inline buttons whose ``callback_data`` carries only the
  plan id and an action. The approval token is *never* in the callback data,
  the message text or a log line: it lives in the in-process
  :class:`PendingApprovals` map, keyed by plan id and bound to the owner id;
- Tier 2 additionally requires the owner to type the confirmation phrase as a
  reply within ``PHRASE_TIMEOUT``. The phrase is never echoed by the bot: the
  owner types what they already know, which is what makes it a confirmation.
  The Approve/Reject keyboard survives the prompt, a wrong phrase and an
  expiry, so a Tier 2 change can always be retried from the phone.

Redaction. Two different jobs, so two different objects:

- ``channel_redactor`` is a gateway configured with ``mask_public_ips=False``
  and is applied to every string this bot sends to Telegram. Telegram is a
  third party, so secrets are stripped there too, but the owner is a human on
  a human channel and wants to read real public IPs, and nothing here is an
  API egress so no audit line is written.
- ``llm_gateway`` guards the only payload that heads for the model: the
  ``/ask`` question. By default it is a *pre-filter* (see :func:`ask_gateway`):
  it refuses raw configs and strips secrets, writes the ``telegram.ask`` audit
  line for the bot -> agent hop, and deliberately mints no IP pseudonyms,
  because the agent package owns the gateway at the real Claude API boundary
  and holds the only reverse map. Pass ``llm_gateway=<the agent's gateway>`` to
  share one instance; the answer is then unmasked with it before the owner
  sees it, as docs/redaction-policy.md requires.

Never parse ``context.args``: python-telegram-bot builds it with
``message.text.split()``, which collapses newlines, and both the raw-config
guard and the line-anchored secret rules depend on the line structure.

`python-telegram-bot` is an optional dependency and is imported lazily inside
functions, so importing this module (and the test suite) never requires it.
Never log or repr the Application or the Bot: their repr contains the token,
and see :func:`install_log_guards` for the transport loggers that would
otherwise print it on every long-poll.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import logging
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from infra_agent.change.plan import ChangePlan, ChangeState, InvalidTransition, Tier
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
#: Port the bot exposes `infra_frozen` and the client metrics on.
BOT_METRICS_PORT = 9103
#: File under data_dir that survives a restart with the quiet-hours backlog.
QUIET_QUEUE_FILE = "telegram-quiet-queue.json"
#: Approver label written into plan history. The owner's numeric Telegram id is
#: a secret (it comes out of the SOPS store) and plan history is LLM-visible
#: through `llm_view()`, so the id never goes in; the channel says "telegram".
OWNER_APPROVER = "telegram-owner"

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

#: States from which a plan can no longer be approved or rejected.
TERMINAL_STATES = frozenset(
    {
        ChangeState.approved,
        ChangeState.executing,
        ChangeState.verifying,
        ChangeState.done,
        ChangeState.rolled_back,
        ChangeState.cancelled,
        ChangeState.failed,
    }
)

#: Read tools tried in order for the estate half of ``/status``. Other packages
#: register their own; whichever exists first and takes no arguments is used.
ESTATE_TOOLS = (
    "inventory.summary",
    "estate.summary",
    "topology.summary",
    "inventory.status",
    "onboarding.status",
)

#: Commands that reach the agent or shell out and must not block the loop.
NON_BLOCKING_COMMANDS = frozenset({"ask", "digest", "status"})


class TelegramConfigError(RuntimeError):
    """The bot token or the owner id is missing from the secrets store."""


# --------------------------------------------------------------------------- #
# logging guards (invariant 5: secrets never touch logs)
# --------------------------------------------------------------------------- #
#: The `telegram-bot-token` shape, compiled here so the log guard needs no file
#: I/O and works before any config is loaded. Deliberately *without* the leading
#: word boundary the redaction.yaml rule uses: the token appears in the log as
#: part of a URL path, `.../bot123456789:AAE...`, where `\b` never matches
#: between "bot" and the first digit.
_TOKEN_RE = re.compile(r"\d{5,16}:[A-Za-z0-9_-]{20,}")

#: Loggers that would otherwise print `https://api.telegram.org/bot<TOKEN>/...`.
TRANSPORT_LOGGERS = (
    "httpx",
    "httpcore",
    "httpcore.connection",
    "httpcore.http11",
    "telegram.request",
)


class TokenRedactingFilter(logging.Filter):
    """Rewrites anything shaped like a bot token out of a record."""

    def filter(self, record: logging.LogRecord) -> bool:
        _redact_record(record)
        return True


def _add_filter_once(target: Any, log_filter: logging.Filter) -> None:
    if not any(isinstance(f, TokenRedactingFilter) for f in getattr(target, "filters", [])):
        target.addFilter(log_filter)


def _redact_record(record: logging.LogRecord) -> logging.LogRecord:
    try:
        message = record.getMessage()
    except Exception:  # pragma: no cover - a broken record is not ours to fix
        return record
    if _TOKEN_RE.search(message):
        record.msg = _TOKEN_RE.sub("<REDACTED-TOKEN>", message)
        record.args = ()
    return record


def install_log_guards(level: int = logging.WARNING) -> None:
    """Keep the bot token out of the logs.

    Two known leaks, both reachable from ``infra bot run``:

    - httpx logs one request line per call at INFO, and python-telegram-bot
      builds its URLs as ``https://api.telegram.org/bot<TOKEN>/<method>``, so
      the CLI's ``logging.basicConfig(level=INFO)`` would print the token once
      per long-poll (every ~10 s) and once per outbound message;
    - ``telegram.ext.ExtBot`` logs "Set Bot API URL: ..." at DEBUG, which
      ``infra -v bot run`` turns on.

    Both go to the container log, which Alloy ships to Loki, so anyone with
    Grafana read access would own the owner channel. Defences: the transport
    loggers are raised to `level`, a filter is attached to them and to the root
    logger, and - because a filter on a logger does not see records that
    propagate up from its children - the record factory rewrites the token
    pattern out of *every* record at creation, whichever logger made it.
    """
    log_filter = TokenRedactingFilter()
    for name in TRANSPORT_LOGGERS:
        logger = logging.getLogger(name)
        logger.setLevel(level)
        _add_filter_once(logger, log_filter)
    root = logging.getLogger()
    _add_filter_once(root, log_filter)
    for handler in root.handlers:
        _add_filter_once(handler, log_filter)

    previous = logging.getLogRecordFactory()
    if getattr(previous, "_infra_token_guard", False):
        return

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        return _redact_record(previous(*args, **kwargs))

    factory._infra_token_guard = True  # type: ignore[attr-defined]
    logging.setLogRecordFactory(factory)


# --------------------------------------------------------------------------- #
# owner gate
# --------------------------------------------------------------------------- #
@dataclass
class OwnerGate:
    """Owner user id *and* private chat (ADR 0005: this is a 1:1 channel).

    Checking the chat as well is cheap defence in depth: without it the owner's
    ``/status`` typed in a group would answer into that group, and a Tier 2
    confirmation phrase typed there would be read by everyone in it.
    """

    owner_id: int

    def allows(
        self, sender_id: int | None, chat_id: int | None = None, chat_type: str | None = None
    ) -> bool:
        if sender_id is None or int(sender_id) != self.owner_id:
            return False
        if chat_type is not None:
            return str(chat_type) == "private"
        if chat_id is not None:
            return int(chat_id) == self.owner_id
        return True  # no chat information at all: user id is all we can check


# --------------------------------------------------------------------------- #
# credentials
# --------------------------------------------------------------------------- #
def load_owner_credentials(
    secrets: Any | None = None, settings: Settings | None = None
) -> tuple[SecretStr, int]:
    """Read ``telegram_bot_token`` / ``telegram_owner_id`` from the platform secrets.

    The token is returned as a :class:`SecretStr` and is only unwrapped where
    it is handed to the Telegram client. Neither value is ever logged.
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


def ask_gateway(settings: Settings) -> RedactionGateway:
    """Pre-filter for ``/ask``: refuse raw configs, strip secrets, no pseudonyms.

    Pseudonymising here would be wrong. The agent package owns the gateway at
    the Claude API boundary and holds the only reverse map, so a ``PUBIP_n``
    minted by a bot-private :class:`IpPseudonymizer` would mean nothing to it,
    could collide with a token it assigns to a different WAN address in the
    same run, and would come back to the owner unreversed. This gateway still
    writes the ``telegram.ask`` audit line, which records the bot -> agent hop;
    the API-boundary line is the agent's to write.
    """
    rules = RedactionRules.load().model_copy(update={"mask_public_ips": False})
    return RedactionGateway(rules=rules, audit_log=settings.audit_log)


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
            "The phrase follows in a separate message, or read it with "
            "`infra change show`.",
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

    Every outbound message is chained behind the previous one on that loop, so
    the chunks of one long report - and the Approve/Reject keyboard relative to
    the plan body it belongs to - can never arrive out of order because one
    HTTP round-trip was slower than the next.
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
        queue_path: Path | None = None,
    ):
        self.bot = bot
        self.owner_id = int(owner_id)
        self.pending = pending if pending is not None else PendingApprovals()
        self.quiet_hours = quiet_hours or QuietHours()
        self.redactor = redactor or channel_redactor()
        self._clock = clock or _local_now
        self._loop = loop
        self._queue_path = queue_path
        self._queue: list[str] = self._load_queue()
        self._tasks: set[asyncio.Task[Any]] = set()
        self._chain: asyncio.Task[Any] | None = None
        self._chain_loop: asyncio.AbstractEventLoop | None = None

    # -- Notifier protocol --------------------------------------------------
    def send(self, text: str, *, critical: bool = False) -> None:
        safe = self.redactor.redact_text(text)
        if not critical and self.quiet_hours.is_quiet(self._clock()):
            self._queue.append(safe)
            self._persist_queue()
            log.info(
                "quiet hours (%s): queued a non-critical message, %d waiting",
                self.quiet_hours.describe(),
                len(self._queue),
            )
            return
        self._deliver(safe)

    def send_approval_request(
        self, plan: ChangePlan, token: str, phrase: str | None = None
    ) -> None:
        """Render the plan and offer Approve / Reject buttons.

        The token goes into :class:`PendingApprovals` only. It is not in the
        message, not in the callback data, and not in any log line. Approval
        requests are actionable, so they bypass quiet hours. A Tier 2
        confirmation `phrase` is delivered to the owner in its own message,
        after the plan, so it can be typed back once Approve is pressed; it is
        never logged and never rendered inside the plan text.
        """
        self.pending.remember(
            plan.id, token, owner_id=self.owner_id, tier=plan.tier, now=datetime.now(UTC)
        )
        text = self.redactor.redact_text(render_plan(plan))
        markup = approval_keyboard(plan.id)
        if markup is None:
            text += "\n\nApprove from the CLI: `infra change approve " + plan.id + "`"
        self._deliver(text, reply_markup=markup)
        if phrase and plan.tier is Tier.WINDOW:
            self._deliver(
                f"Confirmation phrase for {plan.id} (press Approve, then reply with exactly "
                f"this):\n{phrase}"
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
        self._persist_queue()
        for text in queued:
            self._deliver(text)
        log.info("quiet hours ended: flushed %d queued message(s)", len(queued))
        return len(queued)

    def _load_queue(self) -> list[str]:
        """Recover the backlog a restart would otherwise drop, silently."""
        if self._queue_path is None or not self._queue_path.exists():
            return []
        try:
            data = json.loads(self._queue_path.read_text())
        except (OSError, ValueError) as exc:
            log.error(
                "the quiet-hours queue file is unreadable (%s); starting empty", type(exc).__name__
            )
            return []
        if not isinstance(data, list):
            return []
        recovered = [str(item) for item in data]
        if recovered:
            log.info("recovered %d queued quiet-hours message(s) from disk", len(recovered))
        return recovered

    def _persist_queue(self) -> None:
        if self._queue_path is None:
            return
        try:
            self._queue_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._queue_path.with_name(self._queue_path.name + ".tmp")
            tmp.write_text(json.dumps(self._queue))
            tmp.replace(self._queue_path)
        except OSError as exc:  # pragma: no cover - defensive, data_dir is local
            log.error("persisting the quiet-hours queue failed (%s)", type(exc).__name__)

    # -- plumbing -----------------------------------------------------------
    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def _deliver(self, text: str, reply_markup: Any = None) -> None:
        self._dispatch(self._send_chunks(split_message(text), reply_markup))

    async def _send_chunks(self, chunks: Sequence[str], reply_markup: Any = None) -> None:
        """One logical message, sent strictly in order; the keyboard rides the last chunk."""
        last = len(chunks) - 1
        for index, chunk in enumerate(chunks):
            await self.bot.send_message(
                chat_id=self.owner_id,
                text=chunk,
                reply_markup=reply_markup if index == last else None,
            )

    def _dispatch(self, coro: Any) -> None:
        """Run `coro` on whatever loop is available; a failed send never propagates.

        Only the exception type is logged: a Telegram error can carry parts of
        the request back with it, and message bodies do not belong in the log.
        """
        try:
            running: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is not None:
            self._schedule(coro, running)
            return
        if self._loop is not None and self._loop.is_running():
            try:
                self._loop.call_soon_threadsafe(self._schedule, coro, self._loop)
                return
            except RuntimeError as exc:  # pragma: no cover - loop closed under us
                log.error("sending a telegram message failed (%s)", type(exc).__name__)
                coro.close()
                return
        try:
            asyncio.run(coro)
        except Exception as exc:
            log.error("sending a telegram message failed (%s)", type(exc).__name__)

    def _schedule(self, coro: Any, loop: asyncio.AbstractEventLoop) -> None:
        previous = self._chain if self._chain_loop is loop else None
        self._chain_loop = loop
        task = loop.create_task(self._sequenced(previous, coro))
        self._chain = task
        self._tasks.add(task)
        task.add_done_callback(self._finish_task)

    @staticmethod
    async def _sequenced(previous: asyncio.Task[Any] | None, coro: Any) -> None:
        if previous is not None and not previous.done():
            try:
                await asyncio.wait({previous})
            except BaseException:
                coro.close()  # we were cancelled: do not leave an un-awaited coroutine
                raise
        await coro

    def _finish_task(self, task: Any) -> None:
        self._tasks.discard(task)
        if task is self._chain:
            self._chain = None
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            log.error("sending a telegram message failed (%s)", type(exc).__name__)


# --------------------------------------------------------------------------- #
# handlers
# --------------------------------------------------------------------------- #
async def _call(fn: Callable[..., Any], *args: Any) -> Any:
    """Await a coroutine function, run a blocking one in a worker thread.

    ``ask`` reaches the agent, whose runs take minutes (up to
    ``max_tool_calls_per_run`` tool calls), and ``/status`` shells out to sops.
    Running either on the polling loop would park the owner's break-glass
    ``/freeze`` and every pending approval behind it.
    """
    if inspect.iscoroutinefunction(fn):
        return await fn(*args)
    result = await asyncio.to_thread(fn, *args)
    if inspect.isawaitable(result):
        return await result
    return result


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
        # Shared gateway (the agent's) when given, otherwise the /ask pre-filter.
        self.llm_gateway = llm_gateway or ask_gateway(self.settings)
        self._clock = clock or (lambda: datetime.now(UTC))

    # -- gate ---------------------------------------------------------------
    @property
    def owner_id(self) -> int:
        return self.gate.owner_id

    def _allowed(self, update: Any, kind: str) -> bool:
        sender = getattr(getattr(update, "effective_user", None), "id", None)
        chat = getattr(update, "effective_chat", None)
        chat_id = getattr(chat, "id", None)
        chat_type = getattr(chat, "type", None)
        if self.gate.allows(sender, chat_id=chat_id, chat_type=chat_type):
            return True
        # Content is deliberately not logged: it is not ours and may be anything.
        if self.gate.allows(sender):
            # The owner, but not in the private channel. Their id is a secret
            # from the SOPS store, so it is described, never printed.
            log.warning("ignored telegram %s from the owner outside the private chat", kind)
        else:
            log.warning(
                "ignored telegram %s from non-owner id=%r (content not logged)", kind, sender
            )
        return False

    # -- outbound -----------------------------------------------------------
    async def _reply(self, update: Any, text: str) -> None:
        message = getattr(update, "effective_message", None)
        if message is None:
            return
        for chunk in split_message(self.channel_redactor.redact_text(text)):
            await message.reply_text(chunk)

    async def _edit(self, query: Any, text: str, *, reply_markup: Any = None) -> None:
        """Edit the message a button lives on.

        Telegram drops the inline keyboard whenever ``reply_markup`` is omitted
        from ``editMessageText``. That is what we want for a final outcome, and
        exactly what we must not do for the Tier 2 phrase prompt: without the
        keyboard the owner has nothing left to press after a mistyped phrase.
        """
        edit = getattr(query, "edit_message_text", None)
        if edit is None:
            return
        body = split_message(self.channel_redactor.redact_text(text))[0]
        if reply_markup is None:
            await edit(body)
        else:
            await edit(body, reply_markup=reply_markup)

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
        # sqlite plus a read tool that may shell out to sops: off the loop.
        payload = await asyncio.to_thread(self._status_payload)
        try:
            self.channel_redactor.refuse_raw_config(payload)
            safe = self.channel_redactor.redact(payload)
        except RawConfigError:
            safe = {
                "platform": self.channel_redactor.redact(payload["platform"]),
                "estate": "withheld: a read tool returned raw configuration",
            }
        await self._reply(update, "\n".join(_render_payload(safe)))

    def _status_payload(self) -> dict[str, Any]:
        return {"platform": self._platform_status(), "estate": self._estate_payload()}

    def _platform_status(self) -> dict[str, Any]:
        frozen = self.settings.frozen or self._freeze_marker().exists()
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
        question = self._command_argument(update)
        if not question:
            await self._reply(update, "Usage: /ask <question>")
            return
        if self.ask is None:
            await self._reply(update, "No agent is attached to this bot; /ask is unavailable.")
            return
        # On its way to the model: raw configs refused, secrets stripped, audited.
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
            answer = await _call(self.ask, safe_question)
        except Exception as exc:
            # Only the type: an agent error can quote the prompt or a key back.
            log.error("/ask failed (%s)", type(exc).__name__)
            await self._reply(update, f"The agent failed to answer ({type(exc).__name__}).")
            return
        # Reverse any pseudonyms the shared gateway minted (no-op for the pre-filter).
        await self._reply(update, self.llm_gateway.unmask(str(answer)) or "(no answer)")

    async def cmd_digest(self, update: Any, context: Any = None) -> None:
        if not self._allowed(update, "command"):
            return
        if self.digest is None:
            await self._reply(update, "No digest source is attached to this bot.")
            return
        try:
            body = await _call(self.digest)
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
            f"FROZEN. The marker {marker} is set and this process is read-only.\n"
            "Tier 0 automation stops as soon as the agent consults the marker; "
            "restart the services with INFRA_FROZEN=1 to enforce it everywhere.",
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
    def _command_argument(update: Any, context: Any = None) -> str:
        """Everything after the command, verbatim - newlines and all.

        ``context.args`` is never used. python-telegram-bot builds it as
        ``message.text.split()[1:]``, which folds a pasted `show running-config`
        into a single line: the raw-config guard (which needs >20 newlines) then
        never fires and every line-anchored secret rule ('(?im)^...') stops
        matching after the first line, so the plaintext passwords, SNMP
        communities and FortiOS PSKs in it would go straight to the model.
        """
        message = getattr(update, "effective_message", None)
        text = getattr(message, "text", None) or getattr(message, "caption", None) or ""
        if not text:
            return ""
        entities = getattr(message, "entities", None) or getattr(message, "caption_entities", None)
        end = 0
        for entity in entities or ():
            if getattr(entity, "type", None) == "bot_command" and getattr(entity, "offset", 1) == 0:
                end = int(getattr(entity, "length", 0))
                break
        if end == 0:
            head = text.split(maxsplit=1)
            if not head or not head[0].startswith("/"):
                return text.strip()
            end = text.index(head[0]) + len(head[0])
        return text[end:].strip()

    # -- inline buttons -----------------------------------------------------
    def _explain(self, plan: ChangePlan, exc: Exception) -> str:
        """Turn a refusal into something actionable. No token, no phrase.

        Neither :class:`ApprovalError` nor :class:`InvalidTransition` carries
        approval material in its message ("invalid approval token", "tier 2
        changes execute only inside their window", "<state> -> <state> is not
        allowed"), so they are safe to show the owner verbatim.
        """
        message = str(exc).rstrip(".")
        window = plan.window
        if window is not None and "window" in message:
            now = datetime.now(UTC)
            if now < window.start:
                return f"{message}. The window opens at {window.start.isoformat()}."
            if now > window.end:
                return f"{message}. The window closed at {window.end.isoformat()}."
        return f"{message}."

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
            try:
                self.store.reject(
                    plan_id,
                    approver=OWNER_APPROVER,
                    channel="telegram",
                    reason="rejected by owner",
                )
            except (ApprovalError, InvalidTransition) as exc:
                await self._refusal(query, plan, exc, verb="rejected")
                return
            self.pending.forget(plan_id)
            await query.answer("rejected")
            await self._edit(query, f"Change {plan_id} rejected. Nothing was executed.")
            return

        if plan.tier is Tier.WINDOW:
            self.pending.expect_phrase(plan_id, self.gate.owner_id, now=self._clock())
            await query.answer("confirmation phrase required")
            minutes = int(PHRASE_TIMEOUT.total_seconds() // 60)
            # Keep the keyboard: a mistyped phrase must not strand the owner.
            await self._edit(
                query,
                f"Change {plan_id} is Tier 2. Reply with the exact confirmation "
                f"phrase within {minutes} minutes to approve it.",
                reply_markup=approval_keyboard(plan_id),
            )
            return

        try:
            self.store.approve(plan_id, token, approver=OWNER_APPROVER, channel="telegram")
        except (ApprovalError, InvalidTransition) as exc:
            await self._refusal(query, plan, exc, verb="approved")
            return
        self.pending.forget(plan_id)
        await query.answer("approved")
        await self._edit(query, f"Change {plan_id} approved by the owner via Telegram.")

    async def _refusal(self, query: Any, plan: ChangePlan, exc: Exception, *, verb: str) -> None:
        """Tell the owner why, and keep the keyboard unless retrying is pointless.

        A refused approve or reject leaves the store untouched, so the plan we
        already read still holds the current state: terminal means the change
        moved on elsewhere and the buttons are dead, anything else (a Tier 2
        window that has not opened yet) means the owner should press again.
        """
        log.warning("telegram button on %s refused (%s)", plan.id, type(exc).__name__)
        await query.answer(f"not {verb}")
        settled = plan.state in TERMINAL_STATES
        if settled:
            self.pending.forget(plan.id)
        await self._edit(
            query,
            f"Change {plan.id} was not {verb}: {self._explain(plan, exc)}",
            reply_markup=None if settled else approval_keyboard(plan.id),
        )

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
            plan = self.store.get(prompt.plan_id)
        except KeyError:
            self.pending.forget(prompt.plan_id)
            await self._reply(update, f"Change {prompt.plan_id} no longer exists.")
            return
        try:
            self.store.approve(
                prompt.plan_id,
                token,
                approver=OWNER_APPROVER,
                channel="telegram",
                confirmation_phrase=text,
            )
        except (ApprovalError, InvalidTransition) as exc:
            # The phrase itself is never echoed back and never logged.
            log.warning(
                "tier 2 approval from telegram refused for %s (%s)",
                prompt.plan_id,
                type(exc).__name__,
            )
            if "confirmation phrase" in str(exc):
                await self._reply(
                    update,
                    f"That is not the confirmation phrase for {prompt.plan_id}. "
                    "Nothing was approved; press Approve again to retry.",
                )
            else:
                await self._reply(
                    update,
                    f"Change {prompt.plan_id} was not approved: {self._explain(plan, exc)} "
                    "Press Approve again when it can go ahead.",
                )
            return
        self.pending.forget(prompt.plan_id)
        await self._reply(
            update, f"Change {prompt.plan_id} approved by the owner via Telegram (Tier 2)."
        )

    async def on_ignored(self, update: Any, context: Any = None) -> None:
        """Catch-all in a lower group so foreign traffic is logged, never answered."""
        sender = getattr(getattr(update, "effective_user", None), "id", None)
        if self.gate.allows(sender):
            log.warning("ignored telegram update from the owner outside the private chat")
            return
        log.warning("ignored telegram update from non-owner id=%r (content not logged)", sender)


async def _log_handler_error(update: object, context: Any) -> None:
    """Application-wide error handler.

    Only the exception type is logged. python-telegram-bot's default path
    prints a full traceback, and a traceback from the request layer can carry
    the message body, the URL (token included) and the request payload with it.
    """
    exc = getattr(context, "error", None)
    log.error("a telegram handler failed (%s)", type(exc).__name__)


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
    llm_gateway: RedactionGateway | None = None,
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
        install_log_guards()  # before a single request line can be emitted
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
            with contextlib.suppress(asyncio.CancelledError):
                await task

    application = builder.post_init(_post_init).post_shutdown(_post_shutdown).build()

    notifier = TelegramNotifier(
        application.bot,
        int(owner_id),
        pending=pending,
        quiet_hours=quiet_hours or QuietHours.from_settings(settings),
        clock=clock,
        queue_path=settings.data_dir / QUIET_QUEUE_FILE,
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
        llm_gateway=llm_gateway,
    )

    # Private chat only: ADR 0005 describes a 1:1 owner channel, and a Tier 2
    # phrase typed in a group would be read by everyone in it.
    owner_filter = filters.User(user_id=int(owner_id)) & filters.ChatType.PRIVATE
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
        # /ask, /digest and /status may take minutes; they must not hold up
        # /freeze or a Reject. Approvals stay blocking so they stay serialised.
        application.add_handler(
            CommandHandler(
                name, handler, filters=owner_filter, block=name not in NON_BLOCKING_COMMANDS
            )
        )
    application.add_handler(CallbackQueryHandler(bot_app.on_callback))
    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND & owner_filter, bot_app.on_message)
    )
    # Lower group: anything from anyone else is logged and dropped.
    application.add_handler(MessageHandler(~owner_filter, bot_app.on_ignored), group=1)
    application.add_error_handler(_log_handler_error)

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


#: Updates we ask Telegram for. Nothing else can reach a handler.
ALLOWED_UPDATES = ["message", "callback_query"]


async def start_polling(application: Any, *, drop_pending_updates: bool = False) -> None:
    """Start the bot on the caller's event loop (for embedding in the agent service).

    ``run_bot`` owns the process and its signal handlers; this pair does not,
    so a service that already runs a loop can host the owner channel next to
    its scheduler - which is the only way an Approve button can reach the
    process that holds the minted token.
    """
    await application.initialize()
    if application.post_init is not None:
        await application.post_init(application)
    await application.start()
    await application.updater.start_polling(
        allowed_updates=ALLOWED_UPDATES, drop_pending_updates=drop_pending_updates
    )


async def stop_polling(application: Any) -> None:
    """Counterpart of :func:`start_polling`; safe to call on a stopped Application."""
    updater = getattr(application, "updater", None)
    if updater is not None and updater.running:
        await updater.stop()
    if application.running:
        await application.stop()
    if application.post_shutdown is not None:
        await application.post_shutdown(application)
    await application.shutdown()


_UNSET = object()


def run_bot(
    store: PlanStore,
    ask: AskCallback | None = None,
    digest: DigestCallback | None = None,
    *,
    settings: Settings | None = None,
    metrics_port: int | None = BOT_METRICS_PORT,
    stop_signals: Any = _UNSET,
    close_loop: bool = True,
) -> None:
    """Start the owner channel with long polling (no inbound port, ADR 0005).

    ``stop_signals`` is passed through to python-telegram-bot: pass ``None``
    when the bot is not on the main thread. Nothing here logs the token or the
    owner id; both come out of the SOPS store.
    """
    settings = settings or get_settings()
    install_log_guards()
    token, owner_id = load_owner_credentials(settings=settings)
    application = build_application(
        store, ask=ask, digest=digest, token=token, owner_id=owner_id, settings=settings
    )
    metrics.FROZEN.set(1 if settings.frozen or (settings.data_dir / "FROZEN").exists() else 0)
    if metrics_port is not None:
        try:
            # Without a server in this process, /freeze's gauge is scraped by
            # nobody and no alert ever fires on it.
            metrics.start_metrics_server(metrics_port)
        except OSError as exc:
            # A busy port must not stop the owner channel from coming up.
            log.warning("bot metrics server not started (%s)", type(exc).__name__)
    log.info("telegram bot starting: long polling, metrics on %s", metrics_port)
    kwargs: dict[str, Any] = {
        "allowed_updates": ALLOWED_UPDATES,
        # False on purpose: a /freeze typed while the bot was down is the one
        # message that must not be dropped. Stale button presses are harmless,
        # the token map is empty after a restart.
        "drop_pending_updates": False,
        "close_loop": close_loop,
    }
    if stop_signals is not _UNSET:
        kwargs["stop_signals"] = stop_signals
    application.run_polling(**kwargs)
