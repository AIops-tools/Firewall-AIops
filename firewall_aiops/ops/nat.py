"""NAT reads — port forwards, outbound NAT, 1:1 NAT (read-only).

Platform-neutral: OPNsense and pfSense both model port-forward, outbound
(source) NAT, and 1:1 NAT, under different paths/fields reconciled here. All
reads; nothing mutates NAT config.
"""

from __future__ import annotations

from typing import Any

from firewall_aiops.ops._util import pick, rule_enabled, s


def _norm_pf(r: dict) -> dict:
    return {
        "uuid": s(pick(r, "uuid", "id", "tracker")),
        "enabled": rule_enabled(r),
        "interface": s(pick(r, "interface", "if")),
        "protocol": s(pick(r, "protocol", "proto")),
        "sourcePort": s(pick(r, "source_port", "srcport")),
        "destination": s(pick(r, "destination_net", "destination", "dst")),
        "destinationPort": s(pick(r, "destination_port", "dstport")),
        "target": s(pick(r, "target", "redirect_target_ip", "natip")),
        "targetPort": s(pick(r, "target_port", "redirect_target_port", "natport")),
        "description": s(pick(r, "description", "descr")),
    }


def port_forwards(conn: Any) -> dict:
    """[READ] Inbound port-forward (DNAT) rules, normalized."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("nat_port_forward")))
        return {"total": len(rows), "portForwards": [_norm_pf(r) for r in rows]}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def outbound_nat(conn: Any) -> dict:
    """[READ] Outbound (source) NAT mappings, normalized."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("nat_outbound")))
        maps = [
            {
                "uuid": s(pick(r, "uuid", "id", "tracker")),
                "enabled": rule_enabled(r),
                "interface": s(pick(r, "interface", "if")),
                "source": s(pick(r, "source_net", "source", "src")),
                "translation": s(pick(r, "target", "translation", "natip", "target_ip")),
                "description": s(pick(r, "description", "descr")),
            }
            for r in rows
        ]
        return {"total": len(maps), "outboundNat": maps}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def one_to_one_nat(conn: Any) -> dict:
    """[READ] 1:1 NAT mappings (external ↔ internal), normalized."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("nat_one_to_one")))
        maps = [
            {
                "uuid": s(pick(r, "uuid", "id", "tracker")),
                "enabled": rule_enabled(r),
                "interface": s(pick(r, "interface", "if")),
                "external": s(pick(r, "external", "external_net", "destination")),
                "internal": s(pick(r, "internal", "source_net", "source")),
                "description": s(pick(r, "description", "descr")),
            }
            for r in rows
        ]
        return {"total": len(maps), "oneToOneNat": maps}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}
