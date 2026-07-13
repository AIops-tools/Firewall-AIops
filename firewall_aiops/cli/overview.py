"""``firewall-aiops overview`` — one-shot firewall health."""

from __future__ import annotations

import json

from firewall_aiops.cli._common import TargetOption, cli_errors, console, get_connection


@cli_errors
def overview_cmd(target: TargetOption = None) -> None:
    """One-shot summary: platform/version + gateway/interface health + rule count."""
    from firewall_aiops.ops import overview as ops

    conn, _ = get_connection(target)
    console.print_json(json.dumps(ops.firewall_overview(conn)))
