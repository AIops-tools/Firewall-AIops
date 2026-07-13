"""NAT MCP tools — port forwards, outbound NAT, 1:1 NAT (read-only)."""

from typing import Optional

from firewall_aiops.governance import governed_tool
from firewall_aiops.ops import nat as ops
from mcp_server._shared import _get_connection, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def nat_port_forwards(target: Optional[str] = None) -> dict:
    """[READ] Inbound port-forward (DNAT) rules, normalized.

    Args:
        target: Firewall target name from config; omit for the default.
    """
    return ops.port_forwards(_get_connection(target))


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def nat_outbound(target: Optional[str] = None) -> dict:
    """[READ] Outbound (source) NAT mappings, normalized.

    Args:
        target: Firewall target name from config; omit for the default.
    """
    return ops.outbound_nat(_get_connection(target))


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def nat_one_to_one(target: Optional[str] = None) -> dict:
    """[READ] 1:1 NAT mappings (external ↔ internal), normalized.

    Args:
        target: Firewall target name from config; omit for the default.
    """
    return ops.one_to_one_nat(_get_connection(target))
