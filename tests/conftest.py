import pytest

from infra_agent.redaction.gateway import RedactionGateway


@pytest.fixture
def gateway(tmp_path):
    return RedactionGateway(audit_log=tmp_path / "audit.jsonl")
