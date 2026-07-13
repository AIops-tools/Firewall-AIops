"""Alias MCP tools — list aliases and expand an alias' entries (read-only)."""

from typing import Optional

from firewall_aiops.governance import governed_tool
from firewall_aiops.ops import aliases as ops
from mcp_server._shared import _get_connection, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def list_aliases(target: Optional[str] = None) -> dict:
    """[READ] All firewall aliases (name, type, description, member count).

    Args:
        target: Firewall target name from config; omit for the default.
    """
    return ops.list_aliases(_get_connection(target))


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def alias_entries(name: str, target: Optional[str] = None) -> dict:
    """[READ] The member entries (hosts/networks/ports) of one alias.

    Args:
        name: Alias name (from list_aliases).
        target: Firewall target name from config; omit for the default.
    """
    return ops.alias_entries(_get_connection(target), name)
