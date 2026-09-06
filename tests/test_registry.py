from infra_agent.tools.registry import REGISTRY, human_only_tools, llm_tools, load_all


def test_approve_and_execute_are_never_llm_callable():
    load_all()
    names = {t.name for t in llm_tools()}
    assert "change.approve" not in names
    assert "change.execute" not in names
    assert {t.name for t in human_only_tools()} >= {"change.approve", "change.execute"}
    assert "change.propose" in names
    assert "onboarding.status" in names


def test_every_tool_has_a_description():
    load_all()
    for spec in REGISTRY.values():
        assert spec.description, spec.name
