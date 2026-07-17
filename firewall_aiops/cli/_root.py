"""Top-level Typer app: assembles sub-apps and top-level commands."""

from __future__ import annotations

import typer

from firewall_aiops.cli._common import cli_errors
from firewall_aiops.cli.doctor import doctor_cmd
from firewall_aiops.cli.init import init_cmd
from firewall_aiops.cli.log import log_cmd
from firewall_aiops.cli.overview import overview_cmd
from firewall_aiops.cli.rules import rules_app
from firewall_aiops.cli.secret import secret_app
from firewall_aiops.cli.undo import undo_app

app = typer.Typer(
    name="firewall-aiops",
    help="Governed AI-ops for OPNsense + pfSense: rules, NAT, aliases, VPN, "
    "DHCP, diagnostics, and governed writes (toggle/apply/reboot).",
    no_args_is_help=True,
)

app.add_typer(rules_app, name="rules")
app.add_typer(secret_app, name="secret")
app.add_typer(undo_app, name="undo")
app.command("init")(init_cmd)
app.command("overview")(overview_cmd)
app.command("log")(log_cmd)
app.command("doctor")(doctor_cmd)


@app.command("mcp")
@cli_errors
def mcp_cmd() -> None:
    """Start the MCP server (stdio transport).

    Single-command entry point for MCP clients (does not go through uvx/PyPI
    resolution at launch):
        firewall-aiops mcp
    """
    import sys

    if sys.version_info < (3, 11):
        typer.echo(
            f"ERROR: firewall-aiops requires Python >= 3.11 "
            f"(got {sys.version_info.major}.{sys.version_info.minor}).\n"
            f"Fix: uv python install 3.12 && "
            f"uv tool install --python 3.12 --force firewall-aiops",
            err=True,
        )
        raise typer.Exit(2)

    from mcp_server.server import main as _mcp_main

    _mcp_main()


if __name__ == "__main__":
    app()
