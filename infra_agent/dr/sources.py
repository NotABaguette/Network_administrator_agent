"""The two parts of the bundle that come from a live service: Postgres and Grafana.

Both are injectable. The default Postgres dumper shells out to `pg_dump`; the
default Grafana exporter talks to the HTTP API. Neither is required for an
export to succeed: a DR export that refuses to produce a bundle because
Grafana is restarting is worse than a bundle with a missing dashboard, so a
failure here is recorded as a component that is not ok and the export
continues. Postgres is the same, and the runbook says so: without a Postgres
dump you still get the snapshots, the plans, the configs and the secrets, and
NetBox can be re-bootstrapped from them.

Credentials never reach an argument vector. `pg_dump` is told where to connect
through libpq environment variables (PGHOST, PGUSER, PGPASSWORD, ...), because
argv is visible to every user on the box through `ps`, and because a DSN in
argv ends up in exception text the moment something fails.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import unquote, urlsplit

from infra_agent.dr.errors import DRError

log = logging.getLogger(__name__)

PG_DUMP_TIMEOUT = 1800.0
GRAFANA_TIMEOUT = 15.0


class PgDumper(Protocol):
    def __call__(self, dsn: str, database: str, dest: Path) -> None:
        """Write a restorable dump of `database` to `dest`, or raise DRError."""


class GrafanaExporter(Protocol):
    def __call__(self) -> dict[str, Any]:
        """Return {uid: dashboard json}, or raise DRError."""


def pg_env(dsn: str, database: str) -> dict[str, str]:
    """libpq environment for one database of a `postgresql://...` DSN.

    The database in the DSN is replaced by `database`: the platform keeps
    `infra` and `netbox` on the same server with the same credentials, and one
    DSN in the settings should not mean one dumpable database.
    """
    parts = urlsplit(dsn)
    if parts.scheme not in ("postgres", "postgresql"):
        raise DRError(f"postgres_dsn is not a postgresql:// URL (scheme {parts.scheme!r})")
    if not parts.hostname:
        raise DRError("postgres_dsn has no host")
    env = {"PGHOST": parts.hostname, "PGDATABASE": database}
    if parts.port:
        env["PGPORT"] = str(parts.port)
    if parts.username:
        env["PGUSER"] = unquote(parts.username)
    if parts.password:
        env["PGPASSWORD"] = unquote(parts.password)
    return env


def scrub(text: str, *secrets: str | None) -> str:
    """Remove anything we know to be secret from a message before it is logged."""
    cleaned = " ".join(text.split())
    for secret in secrets:
        if secret:
            cleaned = cleaned.replace(secret, "***")
    return cleaned[-400:]


def pg_dump_to_file(dsn: str, database: str, dest: Path) -> None:
    """Default dumper: `pg_dump --format=custom` into `dest`."""
    import os

    env = dict(os.environ)
    connection = pg_env(dsn, database)
    env.update(connection)
    dest.parent.mkdir(parents=True, exist_ok=True)
    argv = [
        "pg_dump",
        "--format=custom",
        "--no-owner",
        "--no-privileges",
        "--file",
        str(dest),
    ]
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, env=env, timeout=PG_DUMP_TIMEOUT
        )
    except FileNotFoundError as exc:
        raise DRError("pg_dump is not installed on this host") from exc
    except subprocess.TimeoutExpired as exc:
        raise DRError(f"pg_dump of {database} timed out") from exc
    if proc.returncode != 0:
        detail = scrub(proc.stderr or "", connection.get("PGPASSWORD"))
        raise DRError(f"pg_dump of {database} failed: {detail}")


#: Custom-format dumps start with this magic; a plain-SQL dump starts with "--".
PGDMP_MAGIC = b"PGDMP"


def looks_like_pg_dump(path: Path) -> bool:
    try:
        head = path.open("rb").read(16)
    except OSError:
        return False
    return head.startswith(PGDMP_MAGIC) or head.lstrip().startswith(b"--")


class HttpGrafanaExporter:
    """Dashboards out of the Grafana HTTP API.

    Provisioned dashboards (`deploy/grafana/provisioning`) are already in git;
    this catches the ones somebody built in the browser, which is where the
    interesting ones usually are.
    """

    def __init__(self, url: str, token: str | None, timeout: float = GRAFANA_TIMEOUT) -> None:
        self.url = url.rstrip("/")
        self._token = token
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    def __call__(self) -> dict[str, Any]:
        import requests  # lazy: keeps the core import light

        try:
            search = requests.get(
                f"{self.url}/api/search",
                params={"type": "dash-db", "limit": 500},
                headers=self._headers(),
                timeout=self.timeout,
            )
            search.raise_for_status()
            found = search.json()
            dashboards: dict[str, Any] = {}
            for row in found if isinstance(found, list) else []:
                uid = str(row.get("uid") or "").strip()
                if not uid:
                    continue
                one = requests.get(
                    f"{self.url}/api/dashboards/uid/{uid}",
                    headers=self._headers(),
                    timeout=self.timeout,
                )
                one.raise_for_status()
                dashboards[uid] = one.json()
        except Exception as exc:  # noqa: BLE001 - any transport failure is the same answer
            raise DRError(f"Grafana export failed ({type(exc).__name__}: {exc})") from exc
        return dashboards


def grafana_exporter(url: str | None, token: str | None) -> GrafanaExporter | None:
    if not url:
        return None
    return HttpGrafanaExporter(url, token)


def grafana_token(secrets_dir: Path) -> str | None:
    """The API token from secrets/platform.enc.yaml, if the store is usable."""
    try:
        from infra_agent.onboarding.secrets import SecretsStore

        store = SecretsStore(secrets_dir)
        if not store.available():
            return None
        value = store.get("platform", "grafana_api_token")
        return str(value) if value else None
    except Exception:
        log.info("no Grafana API token available; exporting dashboards anonymously")
        return None


def git_bundle(repo: Path, dest: Path, runner: Any = None) -> None:
    """`git bundle create <dest> --all` for the config repo.

    A bundle is one file, verifiable on its own (`git bundle verify`) and
    clonable without a server, which is exactly what a restore needs.
    """
    run = runner or _git_runner
    if not (repo / ".git").exists():
        raise DRError(f"{repo} is not a git repository")
    dest.parent.mkdir(parents=True, exist_ok=True)
    code, out = run(["git", "-C", str(repo), "bundle", "create", str(dest), "--all"])
    if code != 0:
        raise DRError(f"git bundle failed: {scrub(out)}")


def _git_runner(argv: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=600)
    except FileNotFoundError:
        return 127, "git is not installed on this host"
    except subprocess.TimeoutExpired:
        return 124, "git timed out"
    return proc.returncode, (proc.stderr or "") + (proc.stdout or "")
