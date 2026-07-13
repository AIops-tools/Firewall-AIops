"""One-shot firewall overview (read-only).

A single call an operator can lead with: platform + version, gateway health,
interface up/down counts, and rule count. Resilient — a failing sub-call
degrades to a partial summary with an ``errors`` list.
"""

from __future__ import annotations

from typing import Any

from firewall_aiops.ops import rules as rule_ops
from firewall_aiops.ops import system


def firewall_overview(conn: Any) -> dict:
    """[READ] Summary: platform/version + gateway/interface health + rule count."""
    errors: list[str] = []

    fw = system.firmware_status(conn)
    if isinstance(fw, dict) and "error" in fw:
        errors.append(f"firmware: {fw['error']}")
        fw = {}

    gws = system.gateway_status(conn)
    gw_list = gws.get("gateways", []) if isinstance(gws, dict) and "error" not in gws else []
    if isinstance(gws, dict) and "error" in gws:
        errors.append(f"gateways: {gws['error']}")

    ifaces = system.interface_status(conn)
    if_ok = isinstance(ifaces, dict) and "error" not in ifaces
    if_list = ifaces.get("interfaces", []) if if_ok else []
    if isinstance(ifaces, dict) and "error" in ifaces:
        errors.append(f"interfaces: {ifaces['error']}")

    rl = rule_ops.list_rules(conn)
    rule_total = rl.get("total") if isinstance(rl, dict) and "error" not in rl else None
    if isinstance(rl, dict) and "error" in rl:
        errors.append(f"rules: {rl['error']}")

    return {
        "platform": conn.target.platform,
        "target": conn.target.name,
        "version": fw.get("version"),
        "updatesAvailable": fw.get("updatesAvailable"),
        "gatewaysTotal": len(gw_list),
        "gatewaysHealthy": sum(1 for g in gw_list if "up" in str(g.get("status", "")).lower()
                               or str(g.get("status", "")).lower() == "none"),
        "interfacesTotal": len(if_list),
        "interfacesUp": sum(1 for i in if_list if i.get("up")),
        "ruleCount": rule_total,
        "errors": errors,
    }
