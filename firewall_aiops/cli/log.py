"""``firewall-aiops log`` — recent firewall-log entries."""

from __future__ import annotations

import json
from typing import Annotated

import typer

from firewall_aiops.cli._common import TargetOption, cli_errors, console, get_connection


@cli_errors
def log_cmd(
    action: Annotated[
        str | None, typer.Option("--action", "-a", help="Filter: pass/block/reject")
    ] = None,
    limit: Annotated[int, typer.Option("--limit", "-n", help="Max entries")] = 100,
    target: TargetOption = None,
) -> None:
    """Show recent firewall-log entries (optionally filtered to pass/block)."""
    from firewall_aiops.ops import diag as ops

    conn, _ = get_connection(target)
    console.print_json(json.dumps(ops.firewall_log(conn, action, limit)))
