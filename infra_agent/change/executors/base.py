"""Executor contract: how an approved ChangePlan touches a device.

An executor is per platform ("cisco", "fortigate", "esxi", "guest"). The
change engine drives it: dry_run -> pre-checks -> apply each step -> verify
post-checks -> on failure, rollback in reverse. Executors receive the READ-WRITE
credential (SeedDevice.rw_credential_ref) only through ExecutionContext and
never log it. Rollback strategy is fixed by design (docs/architecture.md):

- cisco:     `configure terminal revert timer N` + `configure confirm` from the
             post-check. Never `reload in`.
- fortigate: inverse REST object operations using the captured previous object
             body. Never revision restore (it reboots the 60F).
- esxi:      host-config backup before host changes; VM snapshot before VM
             changes except disk extends; SSH (esxcli / vim-cmd) when the free
             license blocks API writes.
- guest:     service restart / package ops over SSH or WinRM with a captured
             previous state.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, ClassVar, Protocol

from pydantic import BaseModel, Field

from infra_agent.change.plan import ChangeStep
from infra_agent.models.common import Credential, SeedDevice


class DryRunResult(BaseModel):
    ok: bool
    diff: dict[str, Any] | str = Field(default_factory=dict, description="structured diff only")
    warnings: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list, description="reasons the plan must not run")


class StepResult(BaseModel):
    step: ChangeStep
    ok: bool
    output: dict[str, Any] = Field(default_factory=dict, description="structured, secret-free")
    error: str | None = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None


class CheckResult(BaseModel):
    check: str
    ok: bool
    detail: str = ""


@dataclass
class ExecutionContext:
    plan_id: str
    device: SeedDevice
    credential: Credential  # read-write; never logged, never in any LLM-visible payload
    dry_run: bool = False
    frozen: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


class Executor(ABC):
    platform: ClassVar[str]

    @abstractmethod
    def supported_actions(self) -> set[str]:
        """ChangeStep.action values this executor implements."""

    @abstractmethod
    def dry_run(self, ctx: ExecutionContext, steps: list[ChangeStep]) -> DryRunResult:
        """Validate the steps against live state and return the structured diff."""

    @abstractmethod
    def pre_check(self, ctx: ExecutionContext, checks: list[str]) -> list[CheckResult]:
        """Evaluate the plan's pre_checks; any failure aborts before apply."""

    @abstractmethod
    def apply(self, ctx: ExecutionContext, step: ChangeStep) -> StepResult:
        """Apply one step. Must capture what rollback needs into step_result.output."""

    @abstractmethod
    def post_check(self, ctx: ExecutionContext, checks: list[str]) -> list[CheckResult]:
        """Evaluate the plan's post_checks; any failure triggers rollback."""

    @abstractmethod
    def rollback(self, ctx: ExecutionContext, applied: list[StepResult]) -> list[StepResult]:
        """Undo the applied steps in reverse order using their captured output."""


class SupportsCommit(Protocol):
    """Optional second phase for platforms whose change holds its own undo.

    The change engine calls `commit(ctx)` only after EVERY device's post-checks
    passed. The Cisco executor implements it: `apply` leaves a `configure
    terminal revert timer` armed and `commit` issues `configure confirm` (and
    `write memory` when the plan persists). Platforms whose change is permanent
    the moment it is applied (FortiOS inverse operations, ESXi, guests) must NOT
    define `commit`: the engine treats its absence as "already committed" and
    then chooses the inverse-operation rollback path for that device.
    """

    def commit(self, ctx: ExecutionContext) -> list[CheckResult]: ...


EXECUTORS: dict[str, type[Executor]] = {}


def register(cls: type[Executor]) -> type[Executor]:
    EXECUTORS[cls.platform] = cls
    return cls


def get_executor(platform: str) -> Executor:
    try:
        return EXECUTORS[platform]()
    except KeyError as exc:
        raise LookupError(f"no executor registered for platform {platform!r}") from exc


def load_all() -> None:
    """Import every executor module so the registry is populated."""
    import importlib
    import pkgutil

    import infra_agent.change.executors as pkg

    for mod in pkgutil.iter_modules(pkg.__path__):
        if mod.name != "base":
            importlib.import_module(f"{pkg.__name__}.{mod.name}")
