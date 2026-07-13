"""DHCP MCP tools — active leases and static mappings (read-only)."""

from typing import Optional

from firewall_aiops.governance import governed_tool
from firewall_aiops.ops import dhcp as ops
from mcp_server._shared import _get_connection, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def dhcp_leases(online_only: bool = False, target: Optional[str] = None) -> dict:
    """[READ] Active DHCP leases (IP, MAC, hostname, state).

    Args:
        online_only: If True, return only leases marked online.
        target: Firewall target name from config; omit for the default.
    """
    return ops.leases(_get_connection(target), online_only)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def dhcp_static_mappings(target: Optional[str] = None) -> dict:
    """[READ] DHCP static (reserved) mappings (MAC ↔ IP).

    Args:
        target: Firewall target name from config; omit for the default.
    """
    return ops.static_mappings(_get_connection(target))
