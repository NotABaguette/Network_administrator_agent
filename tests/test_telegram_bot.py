"""Offline tests for the Telegram owner channel.

Everything runs against fake Bot / Update objects; no network, no real token,
no python-telegram-bot Application unless the test builds one explicitly (and
even then nothing is initialised, so no HTTP happens).
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from prometheus_client import REGISTRY

from infra_agent.agent.notify import Notifier
from infra_agent.agent.telegram_bot import (
    MAX_MESSAGE_CHARS,
    PHRASE_TIMEOUT,
    OwnerGate,
    PendingApprovals,
    QuietHours,
    TelegramBotApp,
    TelegramConfigError,
    TelegramNotifier,
    _quiet_hours_flusher,
    build_application,
    load_owner_credentials,
    parse_callback,
    render_plan,
    split_message,
)
from infra_agent.change.plan import ChangePlan, ChangeState, MaintenanceWindow, Tier
from infra_agent.change.store import PlanStore
from infra_agent.config import Settings

OWNER = 4242
STRANGER = 9999
PHRASE = "MAINTAIN esx-01 2026-09-06"


# --------------------------------------------------------------------------- #
# fakes
# --------------------------------------------------------------------------- #
class FakeMessage:
    def __init__(self, text: str = ""):
        self.text = text
        self.replies: list[str] = []

    async def reply_text(self, text, **kwargs):
        self.replies.append(text)
        return text


class FakeQuery:
    def __init__(self, data: str, user_id: int):
        self.data = data
        self.from_user = SimpleNamespace(id=user_id)
        self.answers: list[str | None] = []
        self.edits: list[str] = []

    async def answer(self, text=None, **kwargs):
        self.answers.append(text)

    async def edit_message_text(self, text, **kwargs):
        self.edits.append(text)


class FakeUpdate:
    def __init__(self, user_id: int, text: str = "", callback_data: str | None = None):
        self.effective_user = SimpleNamespace(id=user_id)
        self.effective_message = FakeMessage(text)
        self.callback_query = FakeQuery(callback_data, user_id) if callback_data else None


class FakeBot:
    """Records outbound messages instead of talking to Telegram."""

    def __init__(self):
        self.sent: list[SimpleNamespace] = []

    async def send_message(self, chat_id, text, reply_markup=None, **kwargs):
        self.sent.append(SimpleNamespace(chat_id=chat_id, text=text, reply_markup=reply_markup))
        return self.sent[-1]

    @property
    def texts(self) -> list[str]:
        return [m.text for m in self.sent]


class FakeSecrets:
    def __init__(self, data: dict[str, dict[str, object]]):
        self.data = data

    def get(self, name, key):
        return self.data.get(name, {}).get(key)


def run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        secrets_dir=tmp_path / "secrets",
        seed_inventory=tmp_path / "seed.yaml",
    )


@pytest.fixture
def store(tmp_path) -> PlanStore:
    return PlanStore(tmp_path / "plans.db")


@pytest.fixture
def bot() -> FakeBot:
    return FakeBot()


@pytest.fixture
def notifier(bot) -> TelegramNotifier:
    return TelegramNotifier(bot, OWNER)


@pytest.fixture
def bot_app(store, settings, notifier) -> TelegramBotApp:
    return TelegramBotApp(
        store,
        OWNER,
        notifier=notifier,
        pending=notifier.pending,
        settings=settings,
        ask=None,
        digest=None,
    )


def make_plan(store: PlanStore, tier: Tier = Tier.APPROVAL, **kwargs) -> tuple[ChangePlan, str]:
    """A plan parked in awaiting_approval, plus the freshly minted token."""
    now = datetime.now(UTC)
    fields: dict = {
        "title": "add vlan 42 on sw-core-01",
        "action": "vlan.add",
        "targets": ["sw-core-01"],
        "summary": "vlan 42 for the lab",
        "diff": {"vlan": {"add": [{"id": 42, "name": "lab"}]}},
        "tier": tier,
    }
    if tier is Tier.WINDOW:
        fields |= {
            "action": "esxi.reboot",
            "confirmation_phrase": PHRASE,
            "window": MaintenanceWindow(
                start=now - timedelta(hours=1), end=now + timedelta(hours=1)
            ),
        }
    fields |= kwargs
    plan = ChangePlan(**fields)
    plan.transition(ChangeState.dry_run)
    token = store.request_approval(plan)
    return store.get(plan.id), token


# --------------------------------------------------------------------------- #
# owner gate
# --------------------------------------------------------------------------- #
def test_owner_gate_only_accepts_the_owner():
    gate = OwnerGate(OWNER)
    assert gate.allows(OWNER)
    assert not gate.allows(STRANGER)
    assert not gate.allows(None)


def test_non_owner_commands_are_ignored_and_logged_without_content(bot_app, caplog):
    secret_text = "/status please-do-not-log-this-text"
    update = FakeUpdate(STRANGER, text=secret_text)
    with caplog.at_level(logging.WARNING):
        run(bot_app.cmd_status(update))
        run(bot_app.cmd_freeze(update))
        run(bot_app.cmd_pending(update))
        run(bot_app.cmd_ask(update))
    assert update.effective_message.replies == []
    assert not (bot_app.settings.data_dir / "FROZEN").exists()
    text = caplog.text
    assert "non-owner" in text and str(STRANGER) in text
    assert "please-do-not-log-this-text" not in text


def test_non_owner_callback_cannot_approve(bot_app, store, caplog):
    plan, token = make_plan(store)
    bot_app.pending.remember(plan.id, token, owner_id=OWNER, tier=plan.tier)
    update = FakeUpdate(STRANGER, callback_data=f"cp:approve:{plan.id}")
    with caplog.at_level(logging.WARNING):
        run(bot_app.on_callback(update))
    assert update.callback_query.answers == []  # not even acknowledged
    assert store.get(plan.id).state is ChangeState.awaiting_approval
    assert "non-owner" in caplog.text


def test_non_owner_message_never_confirms_a_tier2_phrase(bot_app, store):
    plan, token = make_plan(store, Tier.WINDOW)
    bot_app.pending.remember(plan.id, token, owner_id=OWNER, tier=plan.tier)
    bot_app.pending.expect_phrase(plan.id, OWNER)
    run(bot_app.on_message(FakeUpdate(STRANGER, text=PHRASE)))
    assert store.get(plan.id).state is ChangeState.awaiting_approval
    assert bot_app.pending.awaiting_phrase(OWNER)  # prompt untouched


# --------------------------------------------------------------------------- #
# approval flow, tier 1
# --------------------------------------------------------------------------- #
def test_approval_request_keeps_the_token_out_of_every_payload(notifier, bot, store):
    plan, token = make_plan(store)
    notifier.send_approval_request(plan, token)

    assert bot.sent, "the owner got no approval request"
    for message in bot.sent:
        assert token not in message.text
        assert plan.id in "".join(bot.texts)
    markup = bot.sent[-1].reply_markup
    datas = [button.callback_data for row in markup.inline_keyboard for button in row]
    assert datas == [f"cp:approve:{plan.id}", f"cp:reject:{plan.id}"]
    assert all(token not in data for data in datas)
    # the token lives only in the in-process map, bound to the owner
    assert notifier.pending.token_for(plan.id, OWNER) == token
    assert notifier.pending.token_for(plan.id, STRANGER) is None
    assert token not in repr(notifier.pending._pending[plan.id])


def test_approve_button_approves_through_the_plan_store(bot_app, notifier, store):
    plan, token = make_plan(store)
    notifier.send_approval_request(plan, token)
    update = FakeUpdate(OWNER, callback_data=f"cp:approve:{plan.id}")

    run(bot_app.on_callback(update))

    approved = store.get(plan.id)
    assert approved.state is ChangeState.approved
    assert approved.approval is not None
    assert approved.approval.channel == "telegram"
    assert approved.approval.approver == f"telegram:{OWNER}"
    assert token not in json.dumps(approved.llm_view())
    assert token not in "".join(update.callback_query.edits)
    assert not bot_app.pending.holds(plan.id)  # single use


def test_reject_button_cancels_the_plan(bot_app, notifier, store):
    plan, token = make_plan(store)
    notifier.send_approval_request(plan, token)
    run(bot_app.on_callback(FakeUpdate(OWNER, callback_data=f"cp:reject:{plan.id}")))
    assert store.get(plan.id).state is ChangeState.cancelled
    assert not bot_app.pending.holds(plan.id)


def test_button_is_dead_after_a_bot_restart(bot_app, store):
    """A token is never persisted, so a restarted bot cannot approve anything."""
    plan, _token = make_plan(store)
    update = FakeUpdate(OWNER, callback_data=f"cp:approve:{plan.id}")
    run(bot_app.on_callback(update))
    assert store.get(plan.id).state is ChangeState.awaiting_approval
    assert "no live approval" in " ".join(a or "" for a in update.callback_query.answers)


def test_unknown_callback_data_is_rejected(bot_app):
    assert parse_callback("cp:approve:abc") == ("approve", "abc")
    assert parse_callback("cp:execute:abc") is None
    assert parse_callback("nope:approve:abc") is None
    assert parse_callback(None) is None
    update = FakeUpdate(OWNER, callback_data="garbage")
    run(bot_app.on_callback(update))
    assert update.callback_query.answers == ["unknown action"]


# --------------------------------------------------------------------------- #
# approval flow, tier 2
# --------------------------------------------------------------------------- #
def test_tier2_button_alone_does_not_approve(bot_app, notifier, bot, store):
    plan, token = make_plan(store, Tier.WINDOW)
    notifier.send_approval_request(plan, token)
    update = FakeUpdate(OWNER, callback_data=f"cp:approve:{plan.id}")

    run(bot_app.on_callback(update))

    assert store.get(plan.id).state is ChangeState.awaiting_approval
    assert bot_app.pending.awaiting_phrase(OWNER)
    prompt_text = " ".join(update.callback_query.edits)
    assert "confirmation phrase" in prompt_text
    # neither the phrase nor the token is ever shown by the bot
    everything = "".join(bot.texts) + prompt_text
    assert PHRASE not in everything
    assert token not in everything


def test_tier2_wrong_phrase_does_not_approve(bot_app, notifier, store, caplog):
    plan, token = make_plan(store, Tier.WINDOW)
    notifier.send_approval_request(plan, token)
    run(bot_app.on_callback(FakeUpdate(OWNER, callback_data=f"cp:approve:{plan.id}")))

    wrong = FakeUpdate(OWNER, text="maintain esx-01")
    with caplog.at_level(logging.WARNING):
        run(bot_app.on_message(wrong))

    assert store.get(plan.id).state is ChangeState.awaiting_approval
    assert "not the confirmation phrase" in " ".join(wrong.effective_message.replies)
    assert "Nothing was approved" in " ".join(wrong.effective_message.replies)
    assert "maintain esx-01" not in caplog.text  # the attempt is not logged either


def test_tier2_correct_phrase_approves(bot_app, notifier, store):
    plan, token = make_plan(store, Tier.WINDOW)
    notifier.send_approval_request(plan, token)
    run(bot_app.on_callback(FakeUpdate(OWNER, callback_data=f"cp:approve:{plan.id}")))

    reply = FakeUpdate(OWNER, text=PHRASE)
    run(bot_app.on_message(reply))

    approved = store.get(plan.id)
    assert approved.state is ChangeState.approved
    assert approved.approval is not None
    assert approved.approval.channel == "telegram"
    assert PHRASE not in " ".join(reply.effective_message.replies)
    assert not bot_app.pending.holds(plan.id)


def test_tier2_phrase_prompt_expires_after_ten_minutes(store, settings, notifier):
    """The phrase must arrive within PHRASE_TIMEOUT of pressing Approve."""
    clock = SimpleNamespace(now=datetime(2026, 9, 6, 12, 0, tzinfo=UTC))
    app = TelegramBotApp(
        store,
        OWNER,
        notifier=notifier,
        pending=notifier.pending,
        settings=settings,
        clock=lambda: clock.now,
    )
    plan, token = make_plan(store, Tier.WINDOW)
    notifier.send_approval_request(plan, token)
    run(app.on_callback(FakeUpdate(OWNER, callback_data=f"cp:approve:{plan.id}")))
    assert app.pending._phrases[OWNER].expires_at == clock.now + PHRASE_TIMEOUT

    clock.now += PHRASE_TIMEOUT + timedelta(seconds=1)
    late = FakeUpdate(OWNER, text=PHRASE)
    run(app.on_message(late))

    assert store.get(plan.id).state is ChangeState.awaiting_approval
    assert "expired" in " ".join(late.effective_message.replies)
    assert not app.pending.awaiting_phrase(OWNER)

    # pressing Approve again restarts the window, and the phrase then works
    run(app.on_callback(FakeUpdate(OWNER, callback_data=f"cp:approve:{plan.id}")))
    clock.now += timedelta(minutes=1)
    run(app.on_message(FakeUpdate(OWNER, text=PHRASE)))
    assert store.get(plan.id).state is ChangeState.approved


def test_plain_message_without_a_prompt_is_ignored(bot_app):
    update = FakeUpdate(OWNER, text="hello")
    run(bot_app.on_message(update))
    assert update.effective_message.replies == []


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #
def test_render_plan_uses_llm_view_and_shows_the_structured_diff(store):
    plan, _ = make_plan(store, Tier.WINDOW)
    text = render_plan(plan)
    assert plan.id in text and plan.title in text
    assert "structured diff" in text
    assert PHRASE not in text
    assert "tier 2" in text


def test_render_plan_withholds_a_raw_config_diff(store):
    raw = "Building configuration...\n" + "\n".join(f"interface Gi1/0/{i}" for i in range(40))
    plan, _ = make_plan(store, diff=raw)
    text = render_plan(plan)
    assert "raw configuration withheld" in text
    assert "interface Gi1/0/3" not in text


def test_split_message_respects_the_limit_and_keeps_the_content():
    body = "\n".join(f"line {i} " + "x" * 60 for i in range(400))
    chunks = split_message(body)
    assert len(chunks) > 1
    assert all(len(c) <= MAX_MESSAGE_CHARS for c in chunks)
    assert "\n".join(chunks) == body


def test_split_message_hard_splits_a_single_long_line():
    chunks = split_message("y" * 9500)
    assert [len(c) for c in chunks] == [4000, 4000, 1500]
    assert "".join(chunks) == "y" * 9500


def test_send_report_splits_long_messages(notifier, bot):
    body = "\n".join(f"* item {i} " + "z" * 50 for i in range(300))
    notifier.send_report("Daily digest", body)
    assert len(bot.sent) > 1
    assert all(len(m.text) <= MAX_MESSAGE_CHARS for m in bot.sent)
    assert "Daily digest" in bot.texts[0]
    assert "item 299" in bot.texts[-1]


# --------------------------------------------------------------------------- #
# quiet hours
# --------------------------------------------------------------------------- #
def test_quiet_hours_window_maths():
    night = QuietHours(22, 7)
    assert night.configured
    assert night.is_quiet(datetime(2026, 9, 6, 23, 30))
    assert night.is_quiet(datetime(2026, 9, 6, 3, 0))
    assert not night.is_quiet(datetime(2026, 9, 6, 12, 0))
    day = QuietHours(9, 17)
    assert day.is_quiet(datetime(2026, 9, 6, 10, 0))
    assert not day.is_quiet(datetime(2026, 9, 6, 18, 0))
    assert not QuietHours().configured
    assert not QuietHours(7, 7).is_quiet(datetime(2026, 9, 6, 7, 30))


def test_quiet_hours_from_settings(tmp_path):
    s = Settings(data_dir=tmp_path, telegram_quiet_start=22, telegram_quiet_end=7)
    assert QuietHours.from_settings(s) == QuietHours(22, 7)
    assert QuietHours.from_settings(Settings(data_dir=tmp_path)) == QuietHours(None, None)


def test_quiet_hours_queue_then_flush(bot):
    clock = SimpleNamespace(now=datetime(2026, 9, 6, 23, 0, tzinfo=UTC))
    notifier = TelegramNotifier(bot, OWNER, quiet_hours=QuietHours(22, 7), clock=lambda: clock.now)

    notifier.send("disk 80% on datastore1")
    assert bot.sent == []
    assert notifier.queued() == 1

    notifier.send("uplink down on sw-core-01", critical=True)
    assert bot.texts == ["uplink down on sw-core-01"]  # critical bypasses quiet hours

    assert notifier.flush_quiet_queue() == 0  # still quiet
    clock.now = datetime(2026, 9, 7, 8, 0, tzinfo=UTC)
    assert notifier.flush_quiet_queue() == 1
    assert bot.texts[-1] == "disk 80% on datastore1"
    assert notifier.queued() == 0
    assert notifier.flush_quiet_queue() == 0


def test_quiet_hours_do_not_delay_approval_requests(bot, store):
    notifier = TelegramNotifier(
        bot,
        OWNER,
        quiet_hours=QuietHours(0, 24 - 1),
        clock=lambda: datetime(2026, 9, 6, 3, 0, tzinfo=UTC),
    )
    plan, token = make_plan(store)
    notifier.send_approval_request(plan, token)
    assert bot.sent and notifier.queued() == 0


def test_queued_message_content_is_not_logged(bot, caplog):
    notifier = TelegramNotifier(
        bot,
        OWNER,
        quiet_hours=QuietHours(22, 7),
        clock=lambda: datetime(2026, 9, 6, 23, 0, tzinfo=UTC),
    )
    with caplog.at_level(logging.INFO):
        notifier.send("mgmt-01 root password rotation reminder")
    assert "rotation reminder" not in caplog.text
    assert "queued" in caplog.text


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def test_freeze_creates_the_marker_and_sets_the_metric(bot_app):
    marker = bot_app.settings.data_dir / "FROZEN"
    update = FakeUpdate(OWNER, text="/freeze")
    run(bot_app.cmd_freeze(update))
    assert marker.exists()
    assert REGISTRY.get_sample_value("infra_frozen") == 1
    assert "FROZEN" in " ".join(update.effective_message.replies)

    run(bot_app.cmd_unfreeze(FakeUpdate(OWNER, text="/unfreeze")))
    assert not marker.exists()
    assert REGISTRY.get_sample_value("infra_frozen") == 0


def test_status_reports_the_platform_and_never_leaks_a_token(bot_app, notifier, store):
    plan, token = make_plan(store)
    notifier.send_approval_request(plan, token)
    update = FakeUpdate(OWNER, text="/status")
    run(bot_app.cmd_status(update))
    text = " ".join(update.effective_message.replies)
    assert "frozen: no" in text
    assert "awaiting_approval: 1" in text
    assert "model: claude-opus-5" in text
    assert token not in text


def test_status_strips_secrets_from_read_tool_output(bot_app, monkeypatch):
    payload = {"devices": [{"name": "fw-01", "note": "api-key: 0123456789abcdef"}]}
    monkeypatch.setattr(bot_app, "_estate_payload", lambda: payload)
    update = FakeUpdate(OWNER, text="/status")
    run(bot_app.cmd_status(update))
    text = " ".join(update.effective_message.replies)
    assert "0123456789abcdef" not in text
    assert "<REDACTED>" in text


def test_status_withholds_a_read_tool_that_returns_a_raw_config(bot_app, monkeypatch):
    raw = "!\n! Last configuration change at 10:00\n" + "\n".join(f"line {i}" for i in range(30))
    monkeypatch.setattr(bot_app, "_estate_payload", lambda: {"cisco": raw})
    update = FakeUpdate(OWNER, text="/status")
    run(bot_app.cmd_status(update))
    text = " ".join(update.effective_message.replies)
    assert "withheld" in text
    assert "Last configuration change" not in text


def test_pending_lists_plans_without_any_token(bot_app, notifier, store):
    plan_a, token_a = make_plan(store)
    plan_b, _token_b = make_plan(store, title="resize vm-db-01", action="vm.resize")
    notifier.send_approval_request(plan_a, token_a)  # only A has a live button

    update = FakeUpdate(OWNER, text="/pending")
    run(bot_app.cmd_pending(update))
    text = " ".join(update.effective_message.replies)

    assert plan_a.id in text and plan_b.id in text
    assert token_a not in text
    assert "no live button" in text


def test_pending_when_nothing_is_waiting(bot_app):
    update = FakeUpdate(OWNER, text="/pending")
    run(bot_app.cmd_pending(update))
    assert "Nothing is awaiting approval." in update.effective_message.replies


def test_ask_routes_to_the_callback_through_the_redaction_gateway(store, settings, notifier):
    asked: list[str] = []

    def ask(question: str) -> str:
        asked.append(question)
        return "sw-core-01 port Gi1/0/7"

    app = TelegramBotApp(store, OWNER, ask=ask, notifier=notifier, settings=settings)
    update = FakeUpdate(OWNER, text="/ask where is vm-db-01, password=Hunter2secret")
    run(app.cmd_ask(update))

    assert asked and "Hunter2secret" not in asked[0]
    assert "<REDACTED>" in asked[0]
    assert "where is vm-db-01" in asked[0]
    assert update.effective_message.replies == ["sw-core-01 port Gi1/0/7"]
    # egress() wrote exactly one audit line, so what left is provable
    entries = [json.loads(line) for line in settings.audit_log.read_text().splitlines()]
    assert [e["tool"] for e in entries] == ["telegram.ask"]


def test_ask_supports_an_async_callback(store, settings, notifier):
    async def ask(question: str) -> str:
        await asyncio.sleep(0)
        return f"answer to {question}"

    app = TelegramBotApp(store, OWNER, ask=ask, notifier=notifier, settings=settings)
    update = FakeUpdate(OWNER, text="/ask what broke")
    run(app.cmd_ask(update))
    assert update.effective_message.replies == ["answer to what broke"]


def test_ask_without_an_agent_or_a_question(bot_app):
    empty = FakeUpdate(OWNER, text="/ask")
    run(bot_app.cmd_ask(empty))
    assert "Usage: /ask" in empty.effective_message.replies[0]

    unwired = FakeUpdate(OWNER, text="/ask anything")
    run(bot_app.cmd_ask(unwired))
    assert "No agent is attached" in unwired.effective_message.replies[0]


def test_ask_reports_a_failing_agent_without_leaking_the_error(store, settings, notifier, caplog):
    def ask(question: str) -> str:
        raise RuntimeError("anthropic api key sk-ant-0123456789abcdefghij rejected")

    app = TelegramBotApp(store, OWNER, ask=ask, notifier=notifier, settings=settings)
    update = FakeUpdate(OWNER, text="/ask why")
    with caplog.at_level(logging.DEBUG):
        run(app.cmd_ask(update))
    reply = update.effective_message.replies[0]
    assert "RuntimeError" in reply
    assert "sk-ant-" not in reply
    assert "sk-ant-" not in caplog.text  # no traceback with the key in it either


def test_digest_uses_the_supplied_callback(store, settings, notifier):
    app = TelegramBotApp(
        store, OWNER, digest=lambda: "3 alerts, 1 change", notifier=notifier, settings=settings
    )
    update = FakeUpdate(OWNER, text="/digest")
    run(app.cmd_digest(update))
    assert update.effective_message.replies == ["3 alerts, 1 change"]

    unwired = FakeUpdate(OWNER, text="/digest")
    run(TelegramBotApp(store, OWNER, settings=settings).cmd_digest(unwired))
    assert "No digest source" in unwired.effective_message.replies[0]


def test_help_lists_the_commands(bot_app):
    update = FakeUpdate(OWNER, text="/help")
    run(bot_app.cmd_help(update))
    text = " ".join(update.effective_message.replies)
    for command in ("/status", "/pending", "/ask", "/freeze", "/unfreeze", "/digest"):
        assert command in text


# --------------------------------------------------------------------------- #
# secrets and wiring
# --------------------------------------------------------------------------- #
def test_load_owner_credentials_wraps_the_token(settings):
    secrets = FakeSecrets(
        {"platform": {"telegram_bot_token": "123456789:AAE-token", "telegram_owner_id": "4242"}}
    )
    token, owner_id = load_owner_credentials(secrets, settings)
    assert owner_id == OWNER
    assert token.get_secret_value() == "123456789:AAE-token"
    assert "AAE-token" not in repr(token) and "AAE-token" not in str(token)


def test_load_owner_credentials_requires_both_values(settings):
    with pytest.raises(TelegramConfigError):
        load_owner_credentials(FakeSecrets({"platform": {}}), settings)
    with pytest.raises(TelegramConfigError):
        load_owner_credentials(FakeSecrets({"platform": {"telegram_bot_token": "t"}}), settings)


def test_notifier_satisfies_the_notifier_protocol(notifier):
    assert isinstance(notifier, Notifier)


def test_build_application_wires_owner_only_handlers(store, settings, bot):
    from telegram.ext import CallbackQueryHandler, CommandHandler, MessageHandler

    application = build_application(store, bot=bot, owner_id=OWNER, settings=settings)

    inner = application.bot_data["infra_bot"]
    assert isinstance(inner, TelegramBotApp)
    assert inner.owner_id == OWNER
    assert isinstance(application.bot_data["notifier"], TelegramNotifier)
    assert application.bot_data["notifier"].pending is inner.pending

    commands: set[str] = set()
    for handler in application.handlers[0]:
        if isinstance(handler, CommandHandler):
            commands |= set(handler.commands)
            assert handler.filters is not None  # owner filter
    assert commands == {
        "help",
        "start",
        "status",
        "pending",
        "ask",
        "digest",
        "freeze",
        "unfreeze",
    }
    assert any(isinstance(h, CallbackQueryHandler) for h in application.handlers[0])
    assert any(isinstance(h, MessageHandler) for h in application.handlers[0])
    # group 1 exists only to log what is dropped
    assert [type(h) for h in application.handlers[1]] == [MessageHandler]


def test_pending_approvals_expire(store):
    pending = PendingApprovals(ttl=timedelta(minutes=5))
    now = datetime(2026, 9, 6, 12, 0, tzinfo=UTC)
    pending.remember("plan1", "tok", owner_id=OWNER, tier=Tier.APPROVAL, now=now)
    assert pending.token_for("plan1", OWNER, now=now + timedelta(minutes=4)) == "tok"
    assert pending.token_for("plan1", OWNER, now=now + timedelta(minutes=6)) is None
    assert pending.ids() == []


def test_ask_refuses_a_pasted_raw_config(store, settings, notifier):
    asked: list[str] = []
    app = TelegramBotApp(
        store, OWNER, ask=lambda q: asked.append(q) or "ok", notifier=notifier, settings=settings
    )
    raw = "!\n! Last configuration change at 10:00\n" + "\n".join(
        f"interface Gi1/0/{i}" for i in range(30)
    )
    update = FakeUpdate(OWNER, text=f"/ask {raw}")
    run(app.cmd_ask(update))
    assert asked == []
    assert "raw device configuration" in update.effective_message.replies[0]
    assert not settings.audit_log.exists()


def test_a_failing_send_does_not_propagate(caplog):
    class BrokenBot:
        async def send_message(self, **kwargs):
            raise RuntimeError("telegram is unreachable")

    notifier = TelegramNotifier(BrokenBot(), OWNER)
    with caplog.at_level(logging.ERROR):
        notifier.send("host down")
    assert "RuntimeError" in caplog.text
    assert "host down" not in caplog.text


def test_quiet_hours_flusher_task_drains_the_queue_on_the_polling_loop(bot):
    """The background task the Application starts, and the in-loop dispatch path."""
    clock = SimpleNamespace(now=datetime(2026, 9, 6, 23, 0, tzinfo=UTC))
    notifier = TelegramNotifier(bot, OWNER, quiet_hours=QuietHours(22, 7), clock=lambda: clock.now)
    notifier.send("queued while quiet")

    async def drive():
        task = asyncio.get_running_loop().create_task(_quiet_hours_flusher(notifier, interval=0.01))
        await asyncio.sleep(0.05)
        assert bot.sent == []
        clock.now = datetime(2026, 9, 7, 8, 0, tzinfo=UTC)
        await asyncio.sleep(0.05)
        task.cancel()

    run(drive())
    assert bot.texts == ["queued while quiet"]
