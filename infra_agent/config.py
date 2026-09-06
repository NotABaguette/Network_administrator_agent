"""Runtime settings. Everything is overridable with INFRA_* environment variables.

Secrets (device credentials, API keys) are NOT settings: they live in
SOPS-encrypted files read by `infra_agent.onboarding.secrets`.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="INFRA_", env_file=".env", extra="ignore")

    # Paths
    data_dir: Path = Path("data")
    secrets_dir: Path = Path("secrets")
    seed_inventory: Path = Path("inventory/seed.yaml")
    config_repo_dir: Path | None = None
    redaction_rules: Path | None = None
    egress_audit_log: Path | None = None

    # Platform services
    postgres_dsn: str | None = None
    netbox_url: str | None = None
    netbox_token: str | None = None
    prometheus_url: str = "http://prometheus:9090"
    loki_url: str = "http://loki:3100"
    alertmanager_url: str = "http://alertmanager:9093"

    # Safety
    frozen: bool = Field(default=False, description="Break-glass: no automation, agent read-only")
    tier0_shadow_mode: bool = Field(
        default=True, description="Tier 0 actions are logged as 'would have done' instead of run"
    )

    # Agent
    llm_model: str = "claude-opus-5"
    llm_effort: str = "high"
    max_tool_calls_per_run: int = 40
    max_output_tokens_per_run: int = 64000

    # Telegram owner channel (token and owner id live in secrets, not here)
    telegram_quiet_start: int | None = Field(
        default=None, ge=0, le=23, description="Local hour at which quiet hours begin"
    )
    telegram_quiet_end: int | None = Field(
        default=None, ge=0, le=23, description="Local hour at which quiet hours end"
    )

    # Metrics
    metrics_port: int = 9101

    @property
    def config_repo(self) -> Path:
        return self.config_repo_dir or (self.data_dir / "configs")

    @property
    def snapshot_dir(self) -> Path:
        return self.data_dir / "snapshots"

    @property
    def audit_log(self) -> Path:
        return self.egress_audit_log or (self.data_dir / "egress-audit.jsonl")


@lru_cache
def get_settings() -> Settings:
    return Settings()
