"""FastMCP front-end over the tool registry for Claude Code / Claude Desktop.

Only tools with llm_callable=True are registered, and every result passes
through the redaction gateway before it leaves the process.
"""

from __future__ import annotations

import functools
from typing import Any

from infra_agent.config import get_settings
from infra_agent.redaction.gateway import RedactionGateway
from infra_agent.tools.registry import llm_tools, load_all


def build_server() -> Any:
    from fastmcp import FastMCP  # lazy: optional dependency

    settings = get_settings()
    gateway = RedactionGateway(audit_log=settings.audit_log)
    mcp = FastMCP("infra-agent")
    load_all()
    for spec in llm_tools():

        def make(spec_: Any) -> Any:
            @functools.wraps(spec_.fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                result = spec_.fn(*args, **kwargs)
                return gateway.egress(result, tool=spec_.name)

            return wrapper

        mcp.tool(name=spec.name.replace(".", "_"), description=spec.description)(make(spec))
    return mcp


def serve(host: str = "127.0.0.1", port: int = 8765, transport: str = "streamable-http") -> None:
    build_server().run(transport=transport, host=host, port=port)
