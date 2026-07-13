"""VPN MCP tools — WireGuard, OpenVPN, IPsec (read-only)."""

from typing import Optional

from firewall_aiops.governance import governed_tool
from firewall_aiops.ops import vpn as ops
from mcp_server._shared import _get_connection, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def wireguard_status(target: Optional[str] = None) -> dict:
    """[READ] WireGuard peers with connected state, last handshake, transfer.

    Args:
        target: Firewall target name from config; omit for the default.
    """
    return ops.wireguard_status(_get_connection(target))


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def openvpn_sessions(target: Optional[str] = None) -> dict:
    """[READ] OpenVPN sessions / connected clients (name, address, bytes).

    Args:
        target: Firewall target name from config; omit for the default.
    """
    return ops.openvpn_sessions(_get_connection(target))


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def ipsec_sas(target: Optional[str] = None) -> dict:
    """[READ] IPsec security associations (phase-1/phase-2) with state.

    Args:
        target: Firewall target name from config; omit for the default.
    """
    return ops.ipsec_sas(_get_connection(target))
