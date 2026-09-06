"""AgentRunner unit tests. Everything runs against FakeClient: no network, no devices.

FakeClient mimics the one part of the SDK the runner depends on -
`client.beta.messages.tool_runner(...)` returning an iterable that yields one
message per turn and executes that turn's tool calls *after* the consumer's loop
body returns. That ordering is what makes the per-run tool call cap enforceable,
so the fake reproduces it exactly (including not running the tools of a turn the
consumer broke out of).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest
from prometheus_client import REGISTRY

from infra_agent.agent.runner import (
    FORBIDDEN_TOOLS,
    SYSTEM_PREFIX,
    AgentRunner,
    ToolBudget,
    extract_json_object,
)
from infra_agent.config import Settings
from infra_agent.redaction.gateway import RedactionGateway
from infra_agent.tools.registry import ToolSpec

# -- the fake -----------------------------------------------------------------


@dataclass
class FakeBlock:
    type: str
    text: str | None = None
    name: str | None = None
    input: dict[str, Any] | None = None
    id: str = "toolu_fake"


@dataclass
class FakeStopDetails:
    category: str | None = None
    type: str = "refusal"
    explanation: str = ""


@dataclass
class FakeMessage:
    content: list[FakeBlock]
    stop_reason: str = "end_turn"
    stop_details: FakeStopDetails | None = None


def say(text: str, *, stop_reason: str = "end_turn") -> FakeMessage:
    return FakeMessage([FakeBlock("text", text=text)], stop_reason=stop_reason)


def call(tool: str, **kwargs: Any) -> FakeMessage:
    return FakeMessage([FakeBlock("tool_use", name=tool, input=kwargs)], stop_reason="tool_use")


class FakeToolRunner:
    """Yields the scripted turns and runs each turn's tools the way the SDK does."""

    def __init__(self, turns: list[FakeMessage], tools: list[Any]) -> None:
        self.turns = turns
        self.tools = {tool.name: tool for tool in tools}
        self.results: list[tuple[str, str]] = []
        self.unknown: list[str] = []

    def __iter__(self):
        for message in self.turns:
            yield message
            calls = [b for b in message.content if b.type == "tool_use"]
            if not calls:
                return
            for block in calls:
                tool = self.tools.get(block.name or "")
                if tool is None:
                    self.unknown.append(block.name or "")
                    continue
                self.results.append((block.name or "", tool.call(block.input or {})))


@dataclass
class FakeClient:
    """Stands in for `anthropic.Anthropic` in tests."""

    turns: list[FakeMessage] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)
    runners: list[FakeToolRunner] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.beta = SimpleNamespace(messages=SimpleNamespace(tool_runner=self._tool_runner))

    def _tool_runner(self, **kwargs: Any) -> FakeToolRunner:
        self.calls.append(kwargs)
        runner = FakeToolRunner(list(self.turns), list(kwargs["tools"]))
        self.runners.append(runner)
        return runner


# -- fixtures -----------------------------------------------------------------


def echo(value: str) -> dict[str, Any]:
    """Echo a value back.

    Args:
        value: anything at all.
    """
    return {"echoed": value}


def leaky() -> dict[str, Any]:
    """Return something that contains material the gateway must strip."""
    return {
        "line": "snmp-server community S3cretC0mmunity RO",
        "key": "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "public_peer": "8.8.4.4",
    }


def spec(name: str, fn: Any, *, llm_callable: bool = True) -> ToolSpec:
    return ToolSpec(
        name=name,
        group=name.split(".")[0],
        fn=fn,
        description=fn.__doc__ or "",
        tier=None,
        llm_callable=llm_callable,
        parallel_safe=True,
    )


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        secrets_dir=tmp_path / "secrets",
        seed_inventory=tmp_path / "seed.yaml",
        max_tool_calls_per_run=10,
    )


@pytest.fixture
def gateway(tmp_path) -> RedactionGateway:
    return RedactionGateway(audit_log=tmp_path / "audit.jsonl")


def make_runner(settings, gateway, client, tools=None) -> AgentRunner:
    return AgentRunner(
        settings=settings,
        gateway=gateway,
        client=client,
        tools=tools if tools is not None else [spec("test.echo", echo)],
        summary_provider=lambda: {"device_count": 0},
    )


def counter(tool: str) -> float:
    return REGISTRY.get_sample_value("infra_agent_tool_calls_total", {"tool": tool}) or 0.0


# -- the loop -----------------------------------------------------------------


def test_tool_call_round_trip(settings, gateway):
    client = FakeClient([call("test_echo", value="hello"), say("The switch is fine.")])
    before = counter("test.echo")

    result = make_runner(settings, gateway, client).run("check the switch", kind="triage")

    assert result.outcome == "completed"
    assert result.text == "The switch is fine."
    assert result.tool_calls == 1
    assert result.turns == 2
    assert client.runners[0].results == [("test_echo", json.dumps({"echoed": "hello"}))]
    assert client.runners[0].unknown == []
    assert counter("test.echo") == before + 1


def test_tool_results_are_redacted_before_the_model_sees_them(settings, gateway):
    client = FakeClient([call("test_leaky"), say("done")])
    runner = make_runner(settings, gateway, client, tools=[spec("test.leaky", leaky)])

    runner.run("look at the switch")

    (_, payload) = client.runners[0].results[0]
    assert "S3cretC0mmunity" not in payload
    assert "sk-ant-api03" not in payload
    assert "<REDACTED>" in payload
    # Public addresses are pseudonymised and reversible on the way back.
    assert "8.8.4.4" not in payload
    assert gateway.unmask("PUBIP_1") == "8.8.4.4"


def test_every_tool_result_is_audited(settings, gateway, tmp_path):
    client = FakeClient([call("test_echo", value="x"), say("done")])
    make_runner(settings, gateway, client).run("go")

    audited = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert "test.echo" in {entry["tool"] for entry in audited}
    assert all(entry["sha256"] and entry["bytes"] for entry in audited)


def test_tool_call_cap_stops_the_run_with_a_report(settings, gateway):
    settings.max_tool_calls_per_run = 2
    client = FakeClient(
        [
            call("test_echo", value="1"),
            call("test_echo", value="2"),
            call("test_echo", value="3"),
            say("never reached"),
        ]
    )

    result = make_runner(settings, gateway, client).run("loop forever", kind="triage")

    assert result.outcome == "tool_call_cap"
    assert result.tool_calls == 2, "the cap must not be overshot"
    assert len(client.runners[0].results) == 2
    assert "tool call cap" in result.report
    assert "incomplete" in result.report


def test_budget_refuses_extra_calls_inside_one_turn(settings, gateway):
    """Defence in depth: several tool_use blocks in one turn cannot exceed the cap."""
    settings.max_tool_calls_per_run = 1
    budget = ToolBudget(limit=1)
    runner = make_runner(settings, gateway, FakeClient())
    tool = runner.build_tools(budget)[0]

    assert json.loads(tool.call({"value": "a"})) == {"echoed": "a"}
    refused = json.loads(tool.call({"value": "b"}))
    assert "budget" in refused["error"]
    assert budget.used == 1
    assert budget.exhausted


def test_refusal_ends_the_run_with_a_report(settings, gateway):
    refusal = FakeMessage(
        [FakeBlock("text", text="I cannot help with that.")],
        stop_reason="refusal",
        stop_details=FakeStopDetails(category="cyber"),
    )
    client = FakeClient([call("test_echo", value="1"), refusal])

    result = make_runner(settings, gateway, client).run("something", kind="daily_digest")

    assert result.outcome == "refusal"
    assert result.stop_reason == "refusal"
    assert result.refusal_category == "cyber"
    assert "declined" in result.report
    assert "nothing was decided" in result.report


def test_a_refused_turn_never_runs_its_tools(settings, gateway):
    refusal = FakeMessage(
        [FakeBlock("tool_use", name="test_echo", input={"value": "x"})],
        stop_reason="refusal",
    )
    client = FakeClient([refusal])

    result = make_runner(settings, gateway, client).run("something")

    assert result.outcome == "refusal"
    assert client.runners[0].results == []
    assert result.tool_calls == 0


def test_a_failing_tool_becomes_data_not_a_crash(settings, gateway):
    def broken() -> dict[str, Any]:
        """Always fails."""
        raise RuntimeError("device unreachable")

    client = FakeClient([call("test_broken"), say("noted")])
    result = make_runner(settings, gateway, client, tools=[spec("test.broken", broken)]).run("go")

    assert result.outcome == "completed"
    assert "device unreachable" in client.runners[0].results[0][1]


def test_sdk_failure_is_reported_not_raised(settings, gateway):
    class Exploding:
        def __init__(self) -> None:
            self.beta = SimpleNamespace(messages=SimpleNamespace(tool_runner=self._boom))

        def _boom(self, **_: Any):
            raise ConnectionError("api unreachable")

    result = make_runner(settings, gateway, Exploding()).run("go", kind="weekly_report")

    assert result.outcome == "error"
    assert "ConnectionError" in result.report


# -- what the model is allowed to see -----------------------------------------


def test_approve_and_execute_are_absent_from_the_tool_list(settings, gateway):
    runner = AgentRunner(settings=settings, gateway=gateway, client=FakeClient())
    names = {tool.spec.name for tool in runner.build_tools(ToolBudget(limit=5))}

    assert FORBIDDEN_TOOLS.isdisjoint(names)
    assert "change.propose" in names, "the read/propose path must still be there"
    assert all("." not in tool.name for tool in runner.build_tools(ToolBudget(limit=5)))


def test_a_forbidden_tool_is_dropped_even_if_the_registry_marks_it_callable(settings, gateway):
    sneaky = spec("change.approve", echo, llm_callable=True)
    runner = make_runner(settings, gateway, FakeClient(), tools=[sneaky, spec("test.echo", echo)])

    assert [s.name for s in runner.tool_specs()] == ["test.echo"]


def test_human_only_specs_are_dropped(settings, gateway):
    human = spec("change.something_human", echo, llm_callable=False)
    runner = make_runner(settings, gateway, FakeClient(), tools=[human])

    assert runner.tool_specs() == []


def test_the_call_shape_is_the_one_the_architecture_fixes(settings, gateway):
    client = FakeClient([say("hi")])
    make_runner(settings, gateway, client).run("a task", kind="triage")

    kwargs = client.calls[0]
    assert kwargs["model"] == settings.llm_model
    assert kwargs["max_tokens"] == settings.max_output_tokens_per_run
    assert kwargs["thinking"] == {"type": "adaptive"}
    assert kwargs["output_config"] == {"effort": settings.llm_effort}
    assert kwargs["betas"] == ["server-side-fallback-2026-07-01"]
    assert kwargs["fallbacks"] == "default"
    assert kwargs["messages"][0]["role"] == "user"
    assert "a task" in kwargs["messages"][0]["content"]


def test_the_system_prompt_is_the_cached_prefix_plus_a_redacted_summary(settings, gateway):
    client = FakeClient([say("hi")])
    AgentRunner(
        settings=settings,
        gateway=gateway,
        client=client,
        tools=[],
        summary_provider=lambda: {"device_count": 2, "frozen": False},
    ).run("a task")

    system = client.calls[0]["system"]
    assert system[0] == {
        "type": "text",
        "text": SYSTEM_PREFIX,
        "cache_control": {"type": "ephemeral"},
    }
    assert "cannot approve or execute changes" in system[0]["text"]
    assert "cache_control" not in system[1], "the volatile block must not poison the cache"
    assert '"device_count": 2' in system[1]["text"]


def test_the_estate_summary_is_redacted(settings, gateway, tmp_path):
    from infra_agent.agent.runner import estate_summary
    from infra_agent.models.common import DeviceKind, SeedDevice, SeedInventory

    inventory = SeedInventory(
        devices=[
            SeedDevice(
                name="fw-01",
                kind=DeviceKind.fortigate,
                mgmt_ip="10.0.0.1",
                credential_ref="fw-01",
                tags=["edge"],
            )
        ]
    )
    inventory.save(settings.seed_inventory)

    summary = estate_summary(settings, gateway)

    assert summary["device_count"] == 1
    assert summary["devices"][0]["name"] == "fw-01"
    assert summary["devices"][0]["snapshot_age_seconds"] is None
    assert summary["frozen"] is False


def test_the_task_and_context_are_redacted_on_the_way_out(settings, gateway):
    client = FakeClient([say("hi")])
    runner = make_runner(settings, gateway, client)

    runner.run(
        "explain this",
        context={"log": "enable secret 5 $1$abcd$efghijklmnopqrstuv", "device": "sw-core-01"},
    )

    content = client.calls[0]["messages"][0]["content"]
    assert "$1$abcd$" not in content
    assert "<REDACTED" in content
    assert "sw-core-01" in content


def test_a_raw_config_never_reaches_the_model(settings, gateway, caplog):
    running_config = "Building configuration...\n" + "\n".join(
        f"interface GigabitEthernet1/0/{n}\n description uplink" for n in range(1, 40)
    )

    def dump() -> str:
        """Hand back a raw running-config, which must be refused."""
        return running_config

    client = FakeClient([call("test_dump"), say("done")])
    with caplog.at_level("ERROR"):
        result = make_runner(settings, gateway, client, tools=[spec("test.dump", dump)]).run(
            "dump it"
        )

    (_, payload) = client.runners[0].results[0]
    assert "GigabitEthernet1/0/1" not in payload
    assert "raw device configuration" in payload
    assert "raw device configuration" in caplog.text
    # The run itself carries on: one broken tool does not kill the duty.
    assert result.outcome == "completed"


# -- helpers ------------------------------------------------------------------


def test_a_raw_config_in_the_context_never_reaches_the_model(settings, gateway):
    client = FakeClient([say("hi")])
    running_config = "Building configuration...\n" + "\n".join(
        f"interface GigabitEthernet1/0/{n}\n description uplink" for n in range(1, 40)
    )

    result = make_runner(settings, gateway, client).run("explain", context={"cfg": running_config})

    assert result.outcome == "error"
    assert "RawConfigError" in result.report
    assert client.calls == [], "the request is never made"


def test_run_json_parses_the_last_json_object_out_of_the_answer(settings, gateway):
    client = FakeClient([say('Here is my answer.\n```json\n{"probable_cause": "flapping"}\n```')])

    result = make_runner(settings, gateway, client).run_json("triage", kind="triage")

    assert result.payload == {"probable_cause": "flapping"}


def test_extract_json_object_handles_prose_braces_and_strings():
    assert extract_json_object("no json here") is None
    assert extract_json_object('prose { not json } {"a": 1}') == {"a": 1}
    assert extract_json_object('{"a": "}"} tail') == {"a": "}"}
    assert extract_json_object('{"a": 1}\n{"b": 2}') == {"b": 2}
    assert extract_json_object('{"a": {"b": "\\""}}') == {"a": {"b": '"'}}


def test_run_records_the_outcome_metric(settings, gateway):
    def value() -> float:
        return (
            REGISTRY.get_sample_value(
                "infra_agent_runs_total", {"kind": "unit_test", "outcome": "completed"}
            )
            or 0.0
        )

    before = value()
    make_runner(settings, gateway, FakeClient([say("hi")])).run("go", kind="unit_test")
    assert value() == before + 1
