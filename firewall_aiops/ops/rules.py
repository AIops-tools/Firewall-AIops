"""Firewall rule reads — list, detail, hit-count stats, states (read-only).

Platform-neutral rule surface: OPNsense ``/api/firewall/filter/searchRule`` and
pfSense ``/api/v2/firewall/rules`` return the same concepts under different
field names, reconciled through the shared field pickers. Nothing here mutates a
rule — toggling lives in :mod:`firewall_aiops.ops.writes`.
"""

from __future__ import annotations

from typing import Any

from firewall_aiops.ops._util import as_int, as_obj, opt, pick, rule_enabled, s


def _iface(value: Any) -> str | None:
    """Normalise a rule's interface, which is a LIST on pfSense.

    OPNsense reports a string. pfSense reports ``["lan"]``, and stringifying it
    produced the literal ``"['lan']"`` — user-visible garbage, and it also made
    ``list_rules(interface="lan")`` match nothing at all, so filtering by
    interface returned an empty list that read as "no rules on that interface".

    A rule can also sit on several interfaces at once (pfSense floating rules),
    which is why the filter below matches *membership* rather than the whole
    joined string — otherwise "wan,lan" would fail to match a request for "wan"
    and the filter would keep silently dropping exactly those rules.
    """
    if isinstance(value, list):
        return opt(",".join(str(v) for v in value if v)) or None
    return opt(value)


def _evaluations(r: dict) -> int | None:
    """Per-rule hit counter, or ``None`` when the platform reports none.

    pfSense's REST API exposes no per-rule evaluation counter anywhere (checked
    against the appliance's own OpenAPI schema — 212 paths, none of them rule
    statistics). Defaulting the absent counter to ``0`` made every enabled rule
    look never-hit, and ``rule_hit_and_shadow_analysis`` then recommended
    deleting every working rule on the firewall. Absent is not zero.
    """
    value = pick(r, "evaluations", "evals")
    return None if value is None else as_int(value)


def _counter(r: dict, *keys: str) -> int | None:
    """A numeric counter, or ``None`` when the platform reported none of ``keys``."""
    value = pick(r, *keys)
    return None if value is None else as_int(value)


def _norm_rule(r: dict) -> dict:
    """Normalise one rule row across OPNsense / pfSense field names."""
    return {
        "uuid": opt(pick(r, "uuid", "id", "tracker", "@attributes")),
        # pfSense has no "sequence" field: a rule's ``id`` IS its position in the
        # evaluation order, so the order is stated in the payload rather than
        # left for the consumer to infer from list position.
        "sequence": opt(pick(r, "sequence", "seq", "order", "id")),
        "enabled": rule_enabled(r),
        "action": opt(pick(r, "action", "type")),
        "interface": _iface(pick(r, "interface", "if", "descr")),
        "protocol": opt(pick(r, "protocol", "proto", "ipprotocol")),
        "source": opt(pick(r, "source_net", "source", "src")),
        "destination": opt(pick(r, "destination_net", "destination", "dst")),
        "destinationPort": opt(pick(r, "destination_port", "dstport", "dport")),
        "description": opt(pick(r, "description", "descr", "label")),
        "evaluations": _evaluations(r),
    }


def list_rules(conn: Any, interface: str | None = None) -> dict:
    """[READ] All filter rules (optionally on one interface), normalized."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("rules_search")))
        rules = [_norm_rule(r) for r in rows]
        if interface:
            want = interface.strip().lower()
            # A rule whose interface the API did not report is null, not "" —
            # it cannot match a requested interface, so skip it rather than
            # crashing on .lower().
            rules = [
                r for r in rules
                if r["interface"] is not None
                and want in [i.strip().lower() for i in r["interface"].split(",")]
            ]
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
                "uuid": opt(pick(r, "uuid", "id", "tracker", "rule")),
                "description": opt(pick(r, "description", "descr", "label")),
                "evaluations": _counter(r, "evaluations", "evals", "pcnt"),
                "packets": _counter(r, "packets", "pkts"),
                "bytes": _counter(r, "bytes", "bytes_total"),
            }
            for r in rows
        ]
        # "Busiest first" is only meaningful if the platform reported counters.
        # Sorting an all-null column and calling the result a ranking presents
        # an arbitrary order as data — say the counters are missing instead.
        counted = [x for x in stats if x["evaluations"] is not None]
        if counted:
            stats.sort(key=lambda x: (x["evaluations"] is not None, x["evaluations"]), reverse=True)
        return {
            "total": len(stats),
            "rules": stats[: max(1, int(top))],
            "hitCountersAvailable": bool(counted),
            "note": None if counted else (
                "This firewall reports no per-rule hit counters, so the rows are "
                "in API order, not busiest-first, and every counter is null."
            ),
        }
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def rule_states(conn: Any, top: int = 50) -> dict:
    """[READ] Active pf state-table entries associated with rules (top-N)."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("rule_states")))
        states = [
            {
                "interface": opt(pick(r, "interface", "if", "ifname")),
                "protocol": opt(pick(r, "proto", "protocol")),
                "source": opt(pick(r, "src", "source", "src_addr")),
                "destination": opt(pick(r, "dst", "destination", "dst_addr")),
                "state": opt(pick(r, "state", "status")),
                "age": opt(pick(r, "age", "creation")),
            }
            for r in rows
        ]
        return {"total": len(states), "states": states[: max(1, int(top))]}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}
