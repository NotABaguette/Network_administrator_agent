"""Typed tool registry shared by the MCP server and the agent service.

Tools declare a group, an optional tier and whether the language model may
call them at all. `change.approve` and `change.execute` are registered with
llm_callable=False so no front-end can ever expose them to the model.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from infra_agent.change.plan import Tier


@dataclass(frozen=True)
class ToolSpec:
    name: str
    group: str
    fn: Callable[..., Any]
    description: str
    tier: Tier | None
    llm_callable: bool
    parallel_safe: bool

    @property
    def signature(self) -> inspect.Signature:
        return inspect.signature(self.fn)


REGISTRY: dict[str, ToolSpec] = {}


def tool(
    group: str,
    *,
    name: str | None = None,
    tier: Tier | None = None,
    llm_callable: bool = True,
    parallel_safe: bool = True,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        tool_name = f"{group}.{name or fn.__name__}"
        if tool_name in REGISTRY:
            raise ValueError(f"tool {tool_name} already registered")
        REGISTRY[tool_name] = ToolSpec(
            name=tool_name,
            group=group,
            fn=fn,
            description=inspect.getdoc(fn) or "",
            tier=tier,
            llm_callable=llm_callable,
            parallel_safe=parallel_safe,
        )
        return fn

    return decorator


def llm_tools() -> list[ToolSpec]:
    return [spec for spec in REGISTRY.values() if spec.llm_callable]


def human_only_tools() -> list[ToolSpec]:
    return [spec for spec in REGISTRY.values() if not spec.llm_callable]


def load_all() -> None:
    """Import every `infra_agent.tools.*_tools` module so the registry is populated."""
    import importlib
    import pkgutil

    import infra_agent.tools as pkg

    for mod in pkgutil.iter_modules(pkg.__path__):
        if mod.name.endswith("_tools"):
            importlib.import_module(f"{pkg.__name__}.{mod.name}")
