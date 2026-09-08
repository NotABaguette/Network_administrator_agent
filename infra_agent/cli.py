"""`infra` command line."""

from __future__ import annotations

import logging

import typer
from rich.console import Console

from infra_agent import __version__
from infra_agent.onboarding.cli import app as onboard_app

app = typer.Typer(help="AI infrastructure administrator", no_args_is_help=True)
console = Console()
app.add_typer(onboard_app, name="onboard")

change_app = typer.Typer(help="ChangePlans (human-only approval lives here)")
agent_app = typer.Typer(help="Unattended agent service")
mcp_app = typer.Typer(help="MCP server for Claude Code / Desktop")
netbox_app = typer.Typer(help="NetBox source of truth: bootstrap and sync")
baseline_app = typer.Typer(help="The accepted baseline that drift is measured against")
graph_app = typer.Typer(help="Topology graph: build, render, impact analysis")
bot_app = typer.Typer(help="Telegram bot: owner channel and approvals")
dr_app = typer.Typer(help="Disaster recovery: export, verify, import, platform health")
app.add_typer(change_app, name="change")
app.add_typer(agent_app, name="agent")
app.add_typer(mcp_app, name="mcp")
app.add_typer(netbox_app, name="netbox")
app.add_typer(baseline_app, name="baseline")
app.add_typer(graph_app, name="graph")
app.add_typer(bot_app, name="bot")
app.add_typer(dr_app, name="dr")


@app.callback()
def _root(verbose: bool = typer.Option(False, "-v")) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO)


@app.command()
def version() -> None:
    console.print(__version__)


@app.command()
def collect(
    loop: bool = typer.Option(False, help="run forever on each collector's interval"),
) -> None:
    """Run every collector once (or forever) against the seed inventory."""
    from infra_agent.scheduler import run_forever, run_once

    run_forever() if loop else run_once()


@change_app.command("approve")
def change_approve(
    plan_id: str,
    token: str = typer.Option(..., prompt=True, hide_input=True),
    phrase: str | None = typer.Option(None, help="tier 2 confirmation phrase"),
) -> None:
    """Approve a pending ChangePlan with the token shown to you (never to the model)."""
    from infra_agent.tools import change_tools

    change_tools.approve(plan_id, token, approver="cli-user", channel="cli", phrase=phrase)
    console.print(f"[green]approved[/] {plan_id}")


@change_app.command("list")
def change_list(state: str | None = None) -> None:
    from infra_agent.tools import change_tools

    console.print_json(data=change_tools.list_plans(state))


@change_app.command("freeze")
def change_freeze() -> None:
    """Break-glass. Sets the freeze marker; restart services with INFRA_FROZEN=1 to enforce."""
    from infra_agent.config import get_settings

    marker = get_settings().data_dir / "FROZEN"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    console.print("[red]frozen[/]: all automation stopped, agent read-only")


@change_app.command("unfreeze")
def change_unfreeze() -> None:
    from infra_agent.config import get_settings

    marker = get_settings().data_dir / "FROZEN"
    marker.unlink(missing_ok=True)
    console.print("[green]unfrozen[/]")


def _refuse_when_frozen(dry_run: bool) -> None:
    """INFRA_FROZEN stops all automation, and sync is a scheduled duty in waiting."""
    from infra_agent.config import get_settings

    if dry_run or not get_settings().frozen:
        return
    console.print(
        "[red]frozen[/]: INFRA_FROZEN is set, so nothing writes. "
        "Re-run with --dry-run to preview, or unfreeze first."
    )
    raise typer.Exit(code=3)


def _reconcile_client(dry_run: bool):
    """The configured NetBox, or an in-memory preview when only dry-running."""
    from infra_agent.reconcile import FakeNetBox, netbox_client

    client = netbox_client(dry_run=dry_run)
    if client is not None:
        return client
    if dry_run:
        console.print("[yellow]NetBox not configured[/]: previewing against an empty instance")
        return FakeNetBox(dry_run=True)
    console.print(
        "[red]NetBox not configured[/]: set INFRA_NETBOX_URL and INFRA_NETBOX_TOKEN, "
        "or re-run with --dry-run to preview"
    )
    raise typer.Exit(code=2)


def _print_reconcile(report) -> None:
    from rich.table import Table

    table = Table("endpoint", "created", "updated", "unchanged")
    for endpoint, counts in report.by_endpoint().items():
        table.add_row(
            endpoint,
            str(counts.get("created", 0) + counts.get("would-create", 0)),
            str(counts.get("updated", 0) + counts.get("would-update", 0)),
            str(counts.get("unchanged", 0)),
        )
    console.print(table)
    for warning in report.warnings:
        console.print(f"[yellow]warning[/]: {warning}")
    console.print(report.summary_line())


@netbox_app.command("bootstrap")
def netbox_bootstrap(
    site: str = typer.Option("hq", help="NetBox site slug"),
    dry_run: bool = typer.Option(False, "--dry-run", help="show what would change, write nothing"),
) -> None:
    """Create site, roles, device types, devices, interfaces, VLANs, prefixes, clusters and VMs."""
    from infra_agent.reconcile import bootstrap, observed_estate

    _refuse_when_frozen(dry_run)
    estate = observed_estate(site=site)
    _print_reconcile(bootstrap(estate, _reconcile_client(dry_run)))


@netbox_app.command("sync")
def netbox_sync(
    device: list[str] = typer.Option(None, "--device", "-d", help="limit to these devices"),
    site: str = typer.Option("hq", help="NetBox site slug"),
    dry_run: bool = typer.Option(False, "--dry-run", help="show what would change, write nothing"),
) -> None:
    """Refresh NetBox from the newest snapshots (idempotent: unchanged objects are not written)."""
    from infra_agent.reconcile import observed_estate, sync

    _refuse_when_frozen(dry_run)
    estate = observed_estate(site=site)
    _print_reconcile(sync(estate, _reconcile_client(dry_run), devices=list(device) or None))


@baseline_app.command("accept")
def baseline_accept(
    note: str = typer.Option("", help="why this state is correct"),
    by: str = typer.Option("cli-user", help="who accepted it"),
    site: str = typer.Option("hq", help="NetBox site slug"),
) -> None:
    """Record the current observed snapshot set as the accepted baseline."""
    from infra_agent.reconcile import accept_baseline

    baseline = accept_baseline(accepted_by=by, note=note, site=site)
    console.print_json(data=baseline.llm_view())


@baseline_app.command("show")
def baseline_show() -> None:
    """Show the accepted baseline, if there is one."""
    from infra_agent.reconcile import BaselineStore

    baseline = BaselineStore.from_settings().current()
    if baseline is None:
        console.print("[yellow]no baseline accepted[/]: run `infra baseline accept`")
        raise typer.Exit(code=1)
    console.print_json(data=baseline.llm_view())


@app.command()
def drift(
    device: str | None = typer.Option(None, "--device", "-d", help="limit to one device"),
    site: str = typer.Option("hq", help="NetBox site slug"),
    as_json: bool = typer.Option(False, "--json", help="print the full structured report"),
) -> None:
    """Compare observed state with NetBox (or the accepted baseline).

    Exits 1 when there is drift, like `diff`, so a scheduled run can alert on it.
    """
    from rich.table import Table

    from infra_agent.reconcile import drift_report

    report = drift_report(device=device, site=site)
    if as_json:
        console.print_json(data=report.llm_view())
        raise typer.Exit(code=1 if report.items else 0)
    for warning in report.warnings:
        console.print(f"[yellow]warning[/]: {warning}")
    if report.clean:
        console.print(f"[green]{report.headline()}[/]")
        return
    table = Table("severity", "device", "type", "object", "change", "summary")
    colors = {"high": "red", "medium": "yellow", "low": "cyan", "info": "white"}
    for item in report.items:
        colour = colors.get(item.severity.value, "white")
        table.add_row(
            f"[{colour}]{item.severity.value}[/]",
            item.device,
            item.object_type,
            item.object,
            item.change,
            item.summary,
        )
    console.print(table)
    console.print(report.headline())
    raise typer.Exit(code=1)


@graph_app.command("build")
def graph_build() -> None:
    """Correlate the latest snapshots into the topology graph and persist it."""
    from infra_agent.correlate import service

    graph, findings, path = service.build_and_persist()
    console.print_json(data=graph.summary())
    console.print(f"graph written to [bold]{path}[/]")
    for finding in findings:
        colour = {"critical": "red", "warning": "yellow"}.get(finding.severity, "cyan")
        console.print(f"[{colour}]{finding.severity}[/]: {finding.title}")
    if not findings:
        console.print("[green]no consistency findings[/]")


@graph_app.command("render")
def graph_render(
    diagram: str | None = typer.Option(None, help="print one view instead of writing files"),
    vlan: int | None = typer.Option(None, help="vlan id for --diagram vlan"),
) -> None:
    """Write docs/topology/*.md, or print a single Mermaid diagram."""
    from infra_agent.correlate import service
    from infra_agent.correlate.mermaid import render as render_diagram

    if diagram:
        console.print(render_diagram(service.load_graph(), diagram=diagram, vlan=vlan))
        return
    for path in service.render_docs():
        console.print(f"wrote {path}")


@graph_app.command("impact")
def graph_impact(
    object_id: str,
    action: str | None = typer.Option(
        None, help="change action to compute the tier for (default: per object kind)"
    ),
) -> None:
    """What breaks if this object dies, and which tier escalations it triggers."""
    from infra_agent.change.tiers import compute_tier
    from infra_agent.correlate import service
    from infra_agent.correlate.impact import default_action, impact_analyze

    graph = service.load_graph()
    report = impact_analyze(object_id, graph)
    if not report.found:
        console.print(f"[red]unknown object[/]: {object_id}")
        raise typer.Exit(code=1)
    age = service.freshness(graph)
    if age["stale"]:
        console.print(
            f"[yellow]the graph was built at {age['built_at']}[/]; run `infra graph build`"
        )
    console.print(f"[bold]{report.label}[/] ({report.kind})")
    console.print_json(data=report.summary.model_dump(mode="json"))
    for line in report.describe():
        console.print(f"  - {line}")
    if not report.affected:
        console.print("  - nothing else depends on it")
    action = action or default_action(graph, report.object_id)
    tier, reasons = compute_tier(action, report.summary)
    console.print(f"a [bold]{action}[/] change here would compute as tier [bold]{tier.name}[/]")
    for reason in reasons:
        console.print(f"  · {reason}")


@graph_app.command("findings")
def graph_findings() -> None:
    """Consistency findings from the last graph build."""
    from infra_agent.correlate import service

    console.print_json(data=[f.model_dump(mode="json") for f in service.load_findings()])


@agent_app.command("run")
def agent_run() -> None:
    from infra_agent.agent.service import run

    run()


def _agent_callbacks() -> tuple[object | None, object | None]:
    """`/ask` and `/digest` entry points, when the agent package exposes them.

    The bot's approval tokens live in memory, so an Approve button only works
    in the process that minted it: the full deployment hosts the bot inside the
    agent service (`telegram_bot.start_polling`). This standalone runner is for
    a bot-only box; it picks up the agent callbacks if they happen to be
    importable and otherwise says so instead of silently answering
    "not attached".
    """
    try:
        from infra_agent.agent import service
    except Exception:  # pragma: no cover - the agent package is optional here
        return None, None
    return getattr(service, "ask", None), getattr(service, "digest", None)


@bot_app.command("run")
def bot_run(
    metrics_port: int = typer.Option(9103, help="port for infra_frozen and client metrics"),
) -> None:
    """Start the Telegram owner channel (long polling; approvals are human-only)."""
    from infra_agent.agent.telegram_bot import run_bot
    from infra_agent.tools.change_tools import store

    ask, digest = _agent_callbacks()
    console.print("starting the telegram bot (long polling); Ctrl-C to stop")
    if ask is None or digest is None:
        console.print(
            "[yellow]note[/]: no agent callbacks found, so /ask and /digest are inert, and "
            "Approve buttons only appear for plans this process itself proposed. "
            "Run the bot inside the agent service for the full owner channel."
        )
    run_bot(store(), ask=ask, digest=digest, metrics_port=metrics_port)


# --------------------------------------------------------------------------
# Disaster recovery (infra_agent/dr/, docs/runbooks/dr-mgmt-01.md)
# --------------------------------------------------------------------------
def _dr_settings():
    from infra_agent.config import get_settings

    return get_settings()


@dr_app.command("export")
def dr_export(
    to: str | None = typer.Option(
        None,
        "--to",
        help="destination directory or ssh://user@host/path (default: INFRA_DR_TARGET)",
    ),
    host: str | None = typer.Option(None, help="override the hostname recorded in the manifest"),
    prune: bool = typer.Option(True, help="apply INFRA_DR_RETENTION_DAYS after the export"),
) -> None:
    """Export data_dir, the config repo, secrets, inventory and the databases.

    Produces a dated, checksummed tarball with a manifest. `deploy/.env` and the
    age private key are deliberately not in it; the manifest says why.
    """
    from infra_agent.dr.export import export_bundle

    settings = _dr_settings()
    result = export_bundle(settings, to=to, host=host, prune=prune)
    console.print_json(data=result.summary())
    for warning in result.warnings:
        console.print(f"[yellow]incomplete[/]: {warning}")
    console.print(f"[green]wrote[/] {result.bundle}")
    if result.pushed_to:
        console.print(f"[green]pushed to[/] {result.pushed_to}")
    if not result.ok:
        raise typer.Exit(code=1)


@dr_app.command("verify")
def dr_verify(
    bundle: str | None = typer.Argument(
        None, help="bundle to verify (default: the newest local one)"
    ),
    as_json: bool = typer.Option(False, "--json", help="print the structured report"),
    record: bool = typer.Option(
        True, help="remember the outcome in dr-state.json and the DR gauges"
    ),
) -> None:
    """Restore a bundle into a temp dir and prove every part of it loads.

    Exits 1 when anything fails, so a scheduled run can alert on it.
    """
    from pathlib import Path as _Path

    from infra_agent.dr.transfer import newest_bundle
    from infra_agent.dr.verify import verify, verify_and_record

    settings = _dr_settings()
    target = _Path(bundle) if bundle else newest_bundle(settings.dr_dir)
    if target is None:
        console.print(f"[red]no bundle[/] in {settings.dr_dir}; run `infra dr export` first")
        raise typer.Exit(code=2)
    report = verify_and_record(target, settings) if record else verify(target)
    if as_json:
        console.print_json(data=report.llm_view())
    else:
        for check in report.checks:
            colour = "green" if check.ok else "red"
            console.print(f"[{colour}]{check.line()}[/]")
        console.print(report.headline())
    if not report.ok:
        raise typer.Exit(code=1)


@dr_app.command("import")
def dr_import(
    bundle: str,
    force: bool = typer.Option(
        False, "--force", help="overwrite a non-empty data_dir (never a bad checksum)"
    ),
) -> None:
    """Restore a bundle in place. Refuses a non-empty data_dir unless --force.

    The platform is left FROZEN: nothing automates against restored state until
    a human has checked it and run `infra change unfreeze`.
    """
    from pathlib import Path as _Path

    from infra_agent.dr.errors import DRError
    from infra_agent.dr.restore import import_bundle

    try:
        report = import_bundle(_Path(bundle), _dr_settings(), force=force)
    except DRError as exc:
        console.print(f"[red]refused[/]: {exc}")
        raise typer.Exit(code=2) from exc
    console.print_json(data=report.summary())
    for warning in report.warnings:
        console.print(f"[yellow]note[/]: {warning}")
    console.print(f"[green]{report.headline()}[/]")


@dr_app.command("health")
def dr_health(
    as_json: bool = typer.Option(False, "--json", help="print the structured report"),
) -> None:
    """Could this platform recover right now? Local state only, no Prometheus.

    Exits 1 when a check fails, so it works as a container healthcheck.
    """
    from infra_agent.dr.health import health_report

    report = health_report(_dr_settings())
    if as_json:
        console.print_json(data=report.llm_view())
    else:
        for check in report.checks:
            colour = "green" if check.ok else "red"
            console.print(f"[{colour}]{check.line()}[/]")
        if report.frozen:
            console.print("[yellow]the platform is frozen[/] (break-glass marker or INFRA_FROZEN)")
        console.print(report.headline())
    if not report.ok:
        raise typer.Exit(code=1)


@dr_app.command("list")
def dr_list() -> None:
    """Local bundles, newest first."""
    from infra_agent.dr.transfer import local_bundles

    settings = _dr_settings()
    found = local_bundles(settings.dr_dir)
    if not found:
        console.print(f"[yellow]no bundles[/] in {settings.dr_dir}")
        return
    from rich.table import Table

    table = Table("bundle", "bytes", "checksum")
    for path in found:
        sidecar = path.with_name(path.name + ".sha256")
        table.add_row(path.name, str(path.stat().st_size), "yes" if sidecar.exists() else "missing")
    console.print(table)


@mcp_app.command("serve")
def mcp_serve(
    host: str = "127.0.0.1", port: int = 8765, transport: str = "streamable-http"
) -> None:
    from infra_agent.mcp_server.server import serve

    serve(host=host, port=port, transport=transport)


if __name__ == "__main__":
    app()
