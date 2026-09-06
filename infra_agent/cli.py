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
app.add_typer(change_app, name="change")
app.add_typer(agent_app, name="agent")
app.add_typer(mcp_app, name="mcp")


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
