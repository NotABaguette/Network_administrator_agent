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
graph_app = typer.Typer(help="Topology graph: build, render, impact analysis")
app.add_typer(change_app, name="change")
app.add_typer(agent_app, name="agent")
app.add_typer(mcp_app, name="mcp")
app.add_typer(graph_app, name="graph")


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


@mcp_app.command("serve")
def mcp_serve(
    host: str = "127.0.0.1", port: int = 8765, transport: str = "streamable-http"
) -> None:
    from infra_agent.mcp_server.server import serve

    serve(host=host, port=port, transport=transport)


if __name__ == "__main__":
    app()
