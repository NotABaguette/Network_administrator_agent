"""Shared data models: device kinds, the pre-NetBox seed inventory, snapshots."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, SecretStr


class DeviceKind(StrEnum):
    fortigate = "fortigate"
    cisco_ios = "cisco_ios"
    cisco_iosxe = "cisco_iosxe"
    esxi = "esxi"
    ilo = "ilo"
    guest_linux = "guest_linux"
    guest_windows = "guest_windows"

    @property
    def platform(self) -> str:
        """Platform family used by redaction allowlists and executors."""
        if self in (DeviceKind.cisco_ios, DeviceKind.cisco_iosxe):
            return "cisco"
        if self in (DeviceKind.guest_linux, DeviceKind.guest_windows):
            return "guest"
        return self.value


class Credential(BaseModel):
    """A device credential as stored in secrets/devices.enc.yaml (never logged)."""

    username: str | None = None
    password: SecretStr | None = None
    token: SecretStr | None = None
    ssh_key_path: str | None = None

    def redacted(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "password": "***" if self.password else None,
            "token": "***" if self.token else None,
            "ssh_key_path": self.ssh_key_path,
        }


class ProbeResult(BaseModel):
    """What the onboarding credential probe learned. Safe to show to the LLM."""

    ok: bool
    identity: dict[str, Any] = Field(default_factory=dict)
    privilege: str = "unknown"
    read_only: bool | None = None
    warnings: list[str] = Field(default_factory=list)
    error: str | None = None
    probed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SeedDevice(BaseModel):
    name: str
    kind: DeviceKind
    mgmt_ip: str
    credential_ref: str
    rw_credential_ref: str | None = Field(
        default=None, description="read-write credential for the change engine; None = no writes"
    )
    port: int | None = None
    tags: list[str] = Field(default_factory=list)
    notes: str | None = None
    legacy_ssh: bool = Field(default=False, description="Old 2960s need legacy KEX/ciphers")
    license: str | None = Field(default=None, description="ESXi: free|licensed; decides API vs SSH")
    probe: ProbeResult | None = None

    @property
    def platform(self) -> str:
        return self.kind.platform


class SeedInventory(BaseModel):
    """Devices onboarded before NetBox exists. Written by `infra onboard add-device`."""

    devices: list[SeedDevice] = Field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> SeedInventory:
        if not path.exists():
            return cls()
        raw = yaml.safe_load(path.read_text()) or {}
        return cls.model_validate(raw)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.model_dump(mode="json", exclude_none=True)
        path.write_text(yaml.safe_dump(data, sort_keys=False))

    def get(self, name: str) -> SeedDevice | None:
        return next((d for d in self.devices if d.name == name), None)

    def upsert(self, device: SeedDevice) -> None:
        for i, existing in enumerate(self.devices):
            if existing.name == device.name:
                self.devices[i] = device
                return
        self.devices.append(device)

    def by_kind(self, kind: DeviceKind) -> list[SeedDevice]:
        return [d for d in self.devices if d.kind == kind]


class Snapshot(BaseModel):
    """One collector run against one device."""

    device: str
    collector: str
    taken_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    data: dict[str, Any] = Field(default_factory=dict)
