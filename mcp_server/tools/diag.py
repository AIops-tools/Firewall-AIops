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
    """
    return ops.top_talkers(_get_connection(target), top)
