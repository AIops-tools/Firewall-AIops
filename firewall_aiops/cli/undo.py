"""``firewall-aiops undo`` — list recorded undo tokens and apply them.

Real execution is delegated to the ``@governed_tool``-wrapped functions in
``mcp_server.tools.undo`` so an applied undo is audited on the SAME governance
path as any other write (the inverse tool it dispatches is itself re-gated).
"""

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
)

undo_app = typer.Typer(
    name="undo",
    help="List recorded undo tokens and apply their inverse operations.",
    no_args_is_help=True,
)

UndoIdArg = Annotated[str, typer.Argument(help="Undo id from 'undo list'")]


@undo_app.command("list")
@cli_errors
def undo_list_cmd(
    limit: Annotated[int, typer.Option("--limit", help="Max tokens to show")] = 50,
    target: TargetOption = None,
) -> None:
    """List recorded, not-yet-applied undo tokens."""
    from mcp_server.tools import undo as gov

    console.print_json(json.dumps(gov.undo_list(limit=limit, target=target)))


@undo_app.command("apply")
@cli_errors
def undo_apply_cmd(
    undo_id: UndoIdArg, target: TargetOption = None, dry_run: DryRunOption = False
) -> None:
    """Apply a recorded undo (dispatches its inverse tool; dry-run + confirm)."""
    from mcp_server.tools import undo as gov

    if dry_run:
        preview = gov.undo_apply(undo_id=undo_id, dry_run=True, target=target)
        dry_run_print(
            operation="undo_apply",
            api_call=f"inverse: {preview.get('wouldApply', {}).get('tool', '?')}",
            parameters=preview.get("wouldApply", {}).get("params", {}),
        )
        return
    double_confirm("apply undo", undo_id)
    console.print_json(json.dumps(gov.undo_apply(undo_id=undo_id, target=target)))
