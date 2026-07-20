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


def _require_ok(result: dict) -> dict:
    """Surface a governed tool's sanitised ``{"error": ...}`` as a CLI failure.

    The governed twins are wrapped in ``@tool_errors``, which turns a refusal
    into an error dict rather than an exception — without this the CLI would
    print a DRY-RUN banner over a refusal.
    """
    if isinstance(result, dict) and result.get("error"):
        console.print(f"[red]Error: {result['error']}[/]")
        raise typer.Exit(1)
    return result


def _print_management_impact(impact: dict | None) -> None:
    """Render the lockout warning in the human-readable banner, not as raw JSON."""
    if not impact:
        return
    colour = "bold red" if impact.get("certain") else "yellow"
    console.print(f"[{colour}]  Management impact: {impact.get('finding', '')}[/]")
    warnings = impact.get("warnings") or []
    if warnings:
        console.print(f"[{colour}]  Uncertain because: {', '.join(warnings)}[/]")
    console.print(f"[{colour}]  {impact.get('action_hint', '')}[/]")


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
        # Through the GOVERNED twin: the preview then reports the same
        # management-plane impact AND lands the same audit row as the real call.
        preview = gov.toggle_rule(uuid=uuid, enable=enable, target=target, dry_run=True)
        _require_ok(preview)
        dry_run_print(operation="toggle_rule", api_call=f"{verb} rule",
                      parameters={"uuid": uuid, "enable": enable})
        _print_management_impact(preview.get("managementImpact"))
        return
    double_confirm(f"{verb} rule", uuid)
    result = gov.toggle_rule(uuid=uuid, enable=enable, target=target)
    _require_ok(result)
    console.print_json(json.dumps(result))
