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
app.add_typer(change_app, name="change")
app.add_typer(agent_app, name="agent")
app.add_typer(mcp_app, name="mcp")
app.add_typer(netbox_app, name="netbox")
app.add_typer(baseline_app, name="baseline")


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


@agent_app.command("run")
def agent_run() -> None:
    from infra_agent.agent.service import run

    run()


@mcp_app.command("serve")
def mcp_serve(
    host: str = "127.0.0.1", port: int = 8765, transport: str = "streamable-http"
) -> None:
    from infra_agent.mcp_server.server import serve

    serve(host=host, port=port, transport=transport)


if __name__ == "__main__":
    app()
