"""Firewall rule reads — list, detail, hit-count stats, states (read-only).

Platform-neutral rule surface: OPNsense ``/api/firewall/filter/searchRule`` and
pfSense ``/api/v2/firewall/rules`` return the same concepts under different
field names, reconciled through the shared field pickers. Nothing here mutates a
rule — toggling lives in :mod:`firewall_aiops.ops.writes`.
"""

from __future__ import annotations

from typing import Any

from firewall_aiops.ops._util import as_obj, num, pick, rule_enabled, s


def _norm_rule(r: dict) -> dict:
    """Normalise one rule row across OPNsense / pfSense field names."""
    return {
        "uuid": s(pick(r, "uuid", "id", "tracker", "@attributes")),
        "sequence": s(pick(r, "sequence", "seq", "order")),
        "enabled": rule_enabled(r),
        "action": s(pick(r, "action", "type")),
        "interface": s(pick(r, "interface", "if", "descr")),
        "protocol": s(pick(r, "protocol", "proto", "ipprotocol")),
        "source": s(pick(r, "source_net", "source", "src")),
        "destination": s(pick(r, "destination_net", "destination", "dst")),
        "destinationPort": s(pick(r, "destination_port", "dstport", "dport")),
        "description": s(pick(r, "description", "descr", "label")),
        "evaluations": num(pick(r, "evaluations", "evals", default=0)),
    }


def list_rules(conn: Any, interface: str | None = None) -> dict:
    """[READ] All filter rules (optionally on one interface), normalized."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("rules_search")))
        rules = [_norm_rule(r) for r in rows]
        if interface:
            want = interface.strip().lower()
            rules = [r for r in rules if r["interface"].lower() == want]
        return {"total": len(rules), "rules": rules}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def rule_detail(conn: Any, uuid: str) -> dict:
    """[READ] One rule's full detail by uuid/id."""
    try:
        raw = conn.get(conn.platform.path("rule_get", uuid=s(uuid, 64)))
        obj = as_obj(raw)
        # OPNsense wraps under {"rule": {...}}; pfSense under {"data": {...}}.
        inner = as_obj(pick(obj, "rule", "data")) or obj
        detail = _norm_rule(inner)
        detail["uuid"] = detail["uuid"] or s(uuid)
        return detail
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200), "uuid": s(uuid)}


def rule_stats(conn: Any, top: int = 20) -> dict:
    """[READ] Per-rule hit counts / evaluations, busiest first (top-N)."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("rule_stats")))
        stats = [
            {
                "uuid": s(pick(r, "uuid", "id", "tracker", "rule")),
                "description": s(pick(r, "description", "descr", "label")),
                "evaluations": num(pick(r, "evaluations", "evals", "pcnt", default=0)),
                "packets": num(pick(r, "packets", "pkts", default=0)),
                "bytes": num(pick(r, "bytes", "bytes_total", default=0)),
            }
            for r in rows
        ]
        stats.sort(key=lambda x: x["evaluations"], reverse=True)
        return {"total": len(stats), "rules": stats[: max(1, int(top))]}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def rule_states(conn: Any, top: int = 50) -> dict:
    """[READ] Active pf state-table entries associated with rules (top-N)."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("rule_states")))
        states = [
            {
                "interface": s(pick(r, "interface", "if", "ifname")),
                "protocol": s(pick(r, "proto", "protocol")),
                "source": s(pick(r, "src", "source", "src_addr")),
                "destination": s(pick(r, "dst", "destination", "dst_addr")),
                "state": s(pick(r, "state", "status")),
                "age": s(pick(r, "age", "creation")),
            }
            for r in rows
        ]
        return {"total": len(states), "states": states[: max(1, int(top))]}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}
