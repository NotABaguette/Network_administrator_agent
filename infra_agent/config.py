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

    # Correlation
    mgmt_vm_name: str = Field(
        default="mgmt-01",
        description="Name or tag of the VM running this platform; everything on its path "
        "through host, uplinks, switch ports and the firewall escalates to Tier 2",
    )
    topology_docs_dir: Path = Path("docs/topology")

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

    # Disaster recovery (infra_agent/dr/, docs/runbooks/dr-mgmt-01.md)
    dr_target: str | None = Field(
        default=None,
        description="Where `infra dr export` ships bundles: a local directory, "
        "ssh://user@host/path or user@host:/path. SSH targets must use key auth "
        "(BatchMode); a password in this string would be a secret in a setting",
    )
    dr_retention_days: int = Field(
        default=14, ge=1, description="Bundles older than this are pruned, except the newest one"
    )
    dr_grafana_url: str | None = Field(
        default=None,
        description="Grafana base URL for the dashboard export; the API token lives in "
        "secrets/platform.enc.yaml under grafana_api_token",
    )
    dr_postgres_databases: list[str] = Field(
        default_factory=lambda: ["infra", "netbox"],
        description="Databases pg_dump'ed into the bundle",
    )
    dr_backup_root: str = Field(
        default="/vmfs/volumes/backup",
        description="Default path on an ESXi host holding ghettoVCB output; a device tag "
        "`backup-root:<path>` overrides it per host",
    )
    dr_backup_status_dir: Path | None = Field(
        default=None,
        description="Local directory where agent-based guest backups publish "
        "status.json (see docs/runbooks/dr-mgmt-01.md)",
    )

    @property
    def config_repo(self) -> Path:
        return self.config_repo_dir or (self.data_dir / "configs")

    @property
    def snapshot_dir(self) -> Path:
        return self.data_dir / "snapshots"

    @property
    def graph_dir(self) -> Path:
        return self.data_dir / "graph"

    @property
    def audit_log(self) -> Path:
        return self.egress_audit_log or (self.data_dir / "egress-audit.jsonl")

    @property
    def dr_dir(self) -> Path:
        """Where DR bundles are built and kept locally before they are pushed."""
        return self.data_dir / "dr"

    @property
    def dr_state_file(self) -> Path:
        return self.data_dir / "dr-state.json"


@lru_cache
def get_settings() -> Settings:
    return Settings()
