"""Diagnostics / traffic MCP tools — firewall log, states, top talkers (read-only)."""

from typing import Optional

from firewall_aiops.governance import governed_tool
from firewall_aiops.ops import diag as ops
from mcp_server._shared import _get_connection, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def firewall_log(action: Optional[str] = None, limit: int = 200,
                 target: Optional[str] = None) -> dict:
    """[READ] Recent firewall-log entries, optionally filtered to pass/block.

    Args:
        action: Optional filter — one of pass, block, reject, rdr, nat.
        limit: Max entries to return (default 200).
        target: Firewall target name from config; omit for the default.

    Returns an envelope: {"entries": [...], "returned": N, "limit": L,
    "truncated": bool}. When "truncated" is true there are more entries than
    were returned — re-run with a higher limit rather than treating the
    result as the complete log.
    """
    return ops.firewall_log(_get_connection(target), action, limit)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def states_table(top: int = 100, target: Optional[str] = None) -> dict:
    """[READ] Active pf state-table entries (connections currently tracked).

    Args:
        top: How many state entries to return (default 100).
        target: Firewall target name from config; omit for the default.

    Returns an envelope: {"states": [...], "returned": N, "limit": L,
    "truncated": bool, "total": T}. "truncated" is true when the state table
    holds more entries than were returned.
    """
    return ops.states_table(_get_connection(target), top)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def top_talkers(top: int = 20, target: Optional[str] = None) -> dict:
    """[READ] Busiest source hosts, aggregated from the state table by bytes.

    Args:
        top: How many talkers to return (default 20).
        target: Firewall target name from config; omit for the default.

    Returns an envelope: {"topTalkers": [...], "returned": N, "limit": L,
    "truncated": bool, "total": T}. "truncated" is true when more distinct
    sources were seen than were returned.
    """
    return ops.top_talkers(_get_connection(target), top)
