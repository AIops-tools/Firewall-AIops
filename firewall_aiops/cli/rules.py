"""``firewall-aiops rules`` — list / show / toggle filter rules."""

from __future__ import annotations

import json
from typing import Annotated

import typer

from firewall_aiops.cli._common import (
    DryRunOption,
    TargetOption,
    cli_errors,
    console,
    double_confirm,
    dry_run_print,
    get_connection,
)

rules_app = typer.Typer(
    name="rules",
    help="Firewall filter rules: list, show detail, and toggle enable/disable.",
    no_args_is_help=True,
)


@rules_app.command("list")
@cli_errors
def rules_list(
    interface: Annotated[
        str | None, typer.Option("--interface", "-i", help="Filter by interface")
    ] = None,
    target: TargetOption = None,
) -> None:
    """List filter rules (optionally on one interface)."""
    from firewall_aiops.ops import rules as ops

    conn, _ = get_connection(target)
    console.print_json(json.dumps(ops.list_rules(conn, interface)))


@rules_app.command("show")
@cli_errors
def rules_show(
    uuid: Annotated[str, typer.Argument(help="Rule uuid/id (from 'rules list')")],
    target: TargetOption = None,
) -> None:
    """Show one rule's full detail."""
    from firewall_aiops.ops import rules as ops

    conn, _ = get_connection(target)
    console.print_json(json.dumps(ops.rule_detail(conn, uuid)))


@rules_app.command("toggle")
@cli_errors
def rules_toggle(
    uuid: Annotated[str, typer.Argument(help="Rule uuid/id to toggle")],
    enable: Annotated[bool, typer.Option("--enable/--disable", help="Target state")] = True,
    target: TargetOption = None,
    dry_run: DryRunOption = False,
) -> None:
    """Enable/disable a filter rule (staged — run apply to make it live)."""
    from mcp_server.tools import writes as gov

    verb = "enable" if enable else "disable"
    if dry_run:
        dry_run_print(operation="toggle_rule", api_call=f"{verb} rule",
                      parameters={"uuid": uuid, "enable": enable})
        return
    double_confirm(f"{verb} rule", uuid)
    console.print_json(json.dumps(gov.toggle_rule(uuid=uuid, enable=enable, target=target)))
