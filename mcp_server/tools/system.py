"""System MCP tools — firmware/version, health, interfaces, gateways (read-only)."""

from typing import Optional

from firewall_aiops.governance import governed_tool
from firewall_aiops.ops import system as ops
from mcp_server._shared import _get_connection, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def firmware_status(target: Optional[str] = None) -> dict:
    """[READ] Firmware / OS version and whether updates are available.

    Args:
        target: Firewall target name from config; omit for the default.
    """
    return ops.firmware_status(_get_connection(target))


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def health_status(target: Optional[str] = None) -> dict:
    """[READ] System health snapshot: hostname, uptime, CPU, memory, load.

    Args:
        target: Firewall target name from config; omit for the default.
    """
    return ops.health_status(_get_connection(target))


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def interface_status(target: Optional[str] = None) -> dict:
    """[READ] Interfaces with link status + address, down interfaces first.

    Args:
        target: Firewall target name from config; omit for the default.
    """
    return ops.interface_status(_get_connection(target))


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def gateway_status(target: Optional[str] = None) -> dict:
    """[READ] WAN/LAN gateways with status, loss %, and RTT latency.

    Args:
        target: Firewall target name from config; omit for the default.
    """
    return ops.gateway_status(_get_connection(target))
