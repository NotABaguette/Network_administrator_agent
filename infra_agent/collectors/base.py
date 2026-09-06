"""Collector contract.

A collector talks to one kind of device with a READ-ONLY credential, returns a
structured dict (never raw text), optionally returns raw config files for the
config git store, and is wrapped by `run_collector` which persists the
snapshot, computes the structured diff, commits configs and updates metrics.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from infra_agent.configstore.git_store import ConfigGitStore
from infra_agent.models.common import Credential, DeviceKind, SeedDevice, Snapshot
from infra_agent.monitoring import metrics
from infra_agent.store.snapshots import Change, FileSnapshotStore, diff_structures


class Collector(ABC):
    kind: ClassVar[DeviceKind]
    name: ClassVar[str]
    interval_seconds: ClassVar[int] = 300

    @abstractmethod
    def collect(self, device: SeedDevice, cred: Credential) -> dict[str, Any]:
        """Return structured observed state. Must not include secrets or raw configs."""

    def configs(self, device: SeedDevice, cred: Credential) -> dict[str, str]:
        """Return {filename: raw_config_text} for the config git store. Default: none."""
        return {}


COLLECTORS: dict[DeviceKind, type[Collector]] = {}


def register(cls: type[Collector]) -> type[Collector]:
    COLLECTORS[cls.kind] = cls
    return cls


def get_collector(kind: DeviceKind) -> Collector:
    try:
        return COLLECTORS[kind]()
    except KeyError as exc:
        raise LookupError(f"no collector registered for {kind.value}") from exc


class RunResult(BaseModel):
    snapshot: Snapshot
    changes: list[Change] = Field(default_factory=list)
    config_commits: dict[str, str] = Field(default_factory=dict)
    duration_seconds: float


def run_collector(
    collector: Collector,
    device: SeedDevice,
    cred: Credential,
    store: FileSnapshotStore,
    config_store: ConfigGitStore | None = None,
) -> RunResult:
    labels = {"collector": collector.name, "device": device.name}
    start = time.monotonic()
    try:
        data = collector.collect(device, cred)
        previous = store.latest(device.name, collector.name)
        snapshot = Snapshot(device=device.name, collector=collector.name, data=data)
        store.save(snapshot)
        changes = diff_structures(previous.data, data) if previous else []
        commits: dict[str, str] = {}
        if config_store is not None:
            for filename, content in collector.configs(device, cred).items():
                sha = config_store.write(device.name, filename, content)
                if sha:
                    commits[filename] = sha
                    metrics.CONFIG_COMMITS.labels(**labels).inc()
        metrics.COLLECTOR_LAST_SUCCESS.labels(**labels).set_to_current_time()
        metrics.SNAPSHOT_CHANGES.labels(**labels).set(len(changes))
        return RunResult(
            snapshot=snapshot,
            changes=changes,
            config_commits=commits,
            duration_seconds=time.monotonic() - start,
        )
    except Exception:
        metrics.COLLECTOR_ERRORS.labels(**labels).inc()
        raise
    finally:
        metrics.COLLECTOR_DURATION.labels(**labels).observe(time.monotonic() - start)
