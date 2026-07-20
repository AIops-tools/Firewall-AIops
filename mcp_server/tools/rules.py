"""Firewall rule MCP tools — list, detail, hit stats, states (read-only)."""

from typing import Optional

from firewall_aiops.governance import governed_tool
from firewall_aiops.ops import rules as ops
from mcp_server._shared import _get_connection, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def list_rules(interface: Optional[str] = None, target: Optional[str] = None) -> dict:
    """[READ] List filter rules (optionally on one interface), normalized.

    Args:
        interface: Optional interface name to filter by (e.g. wan, lan).
        target: Firewall target name from config; omit for the default.
    """
    return ops.list_rules(_get_connection(target), interface)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def rule_detail(uuid: str, target: Optional[str] = None) -> dict:
    """[READ] One rule's full detail by uuid/id.

    Args:
        uuid: Rule uuid (OPNsense) or id (pfSense), from list_rules.
        target: Firewall target name from config; omit for the default.
    """
    return ops.rule_detail(_get_connection(target), uuid)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def rule_stats(top: int = 20, target: Optional[str] = None) -> dict:
    """[READ] Per-rule hit counts / evaluations, busiest first (top-N).

    Args:
        top: How many rules to return, busiest first (default 20).
        target: Firewall target name from config; omit for the default.
    """
    return ops.rule_stats(_get_connection(target), top)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def rule_states(top: int = 50, target: Optional[str] = None) -> dict:
    """[READ] Active pf state-table entries associated with rules (top-N).

    Args:
        top: How many state entries to return (default 50).
        target: Firewall target name from config; omit for the default.
    """
    return ops.rule_states(_get_connection(target), top)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def pending_changes(target: Optional[str] = None) -> dict:
    """[READ] The staged rule set apply_changes would commit, with lockout risk.

    Run this BEFORE apply_changes. It reports whether committing the staged rules
    would cut the endpoint this tool manages the firewall through — a disabled
    'pass' rule that permits management access, or an enabled 'block' rule that
    covers it. Findings are ranked worst-first and carry a `certain` flag:
    certain ones make apply_changes refuse, uncertain ones (alias destinations,
    'any', interface groups) are warnings only and never block.

    `basis` states what this is: the staged rule STATE, not a diff against the
    running config — neither platform exposes a per-rule dirty flag over REST.

    Args:
        target: Firewall target name from config; omit for the default.
    """
    from firewall_aiops.ops import pending as pending_ops

    return pending_ops.pending_changes(_get_connection(target))
