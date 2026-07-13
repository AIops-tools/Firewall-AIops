"""Flagship firewall-analysis MCP tools (read-only)."""

from typing import Any, Optional

from firewall_aiops.governance import governed_tool
from firewall_aiops.ops import analysis as ops
from mcp_server._shared import _get_connection, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def gateway_health_rca(
    loss_pct: float = 5.0,
    latency_ms: float = 150.0,
    gateways: Optional[list[dict[str, Any]]] = None,
    target: Optional[str] = None,
) -> dict:
    """[READ] Rank gateways by loss + latency, map each down/degraded one to cause + action.

    The flagship WAN RCA: pulls gateway status, flags each gateway that is down
    (status down/offline or 100% loss) or degraded (loss/latency over threshold),
    ranks worst-first, and attaches a likely cause and a recommended action.
    Every ranking carries its numbers, not a black-box verdict. Pass 'gateways'
    for pure analysis, or a target to pull live.

    Args:
        loss_pct: Loss %% at/above which a gateway is degraded (default 5.0).
        latency_ms: RTT ms at/above which a gateway is degraded (default 150).
        gateways: Injected rows {name, address, status, lossPercent, rttMs};
            skips the live pull.
        target: Firewall target name from config; omit for the default.

    Returns dict: {gatewaysEvaluated, downCount, degradedCount, thresholds,
        worst:[{name, address, status, lossPercent, rttMs, down, degraded, cause,
        action}], note}.
    """
    if gateways is None:
        gateways = ops.pull_gateways(_get_connection(target))
    return ops.gateway_health_rca(gateways, loss_pct=loss_pct, latency_ms=latency_ms)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def rule_hit_and_shadow_analysis(
    rules: Optional[list[dict[str, Any]]] = None,
    interface: Optional[str] = None,
    target: Optional[str] = None,
) -> dict:
    """[READ] Flag never-hit enabled rules and shadowed/redundant rules.

    Finds enabled rules with zero evaluations (dead or misordered), rules fully
    covered by an earlier terminating rule (shadowed), and rules identical to an
    earlier one (redundant). Rules are compared in list order, top-down, exactly
    as pf evaluates them; every finding names the offending/covering rule uuid.
    Pass 'rules' for pure analysis, or a target to pull live.

    Args:
        rules: Injected rows {uuid, sequence, enabled, action, interface,
            protocol, source, destination, destinationPort, evaluations}.
        interface: Optional interface filter when pulling live.
        target: Firewall target name from config; omit for the default.

    Returns dict: {rulesEvaluated, unusedCount, shadowedCount, redundantCount,
        unusedRules, shadowedRules, redundantRules, note}.
    """
    if rules is None:
        from firewall_aiops.ops import rules as rule_ops

        pulled = rule_ops.list_rules(_get_connection(target), interface)
        rules = pulled.get("rules", []) if isinstance(pulled, dict) else []
    return ops.rule_hit_and_shadow_analysis(rules)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def blocked_traffic_rca(
    top: int = 20,
    limit: int = 500,
    log_entries: Optional[list[dict[str, Any]]] = None,
    target: Optional[str] = None,
) -> dict:
    """[READ] Rank the noisiest blocked sources and classify cause + action.

    Keeps only blocked firewall-log entries, aggregates by source (hit count,
    distinct destination ports, busiest port), ranks the noisiest sources, and
    classifies each as a port scan, a service probe/brute-force on a sensitive
    port, or generic — with a recommended action. Every entry carries its
    numbers. Pass 'log_entries' for pure analysis, or a target to pull live.

    Args:
        top: How many source rows to return, noisiest first (default 20).
        limit: How many recent log rows to pull when live (default 500).
        log_entries: Injected rows {action, source, destination, destinationPort,
            protocol}; skips the live pull.
        target: Firewall target name from config; omit for the default.

    Returns dict: {blocksEvaluated, distinctSources, topSources:[{source, hits,
        distinctPorts, topPort, topPortHits, cause, action}], note}.
    """
    if log_entries is None:
        log_entries = ops.pull_blocked_log(_get_connection(target), limit=limit)
    return ops.blocked_traffic_rca(log_entries, top=top)
