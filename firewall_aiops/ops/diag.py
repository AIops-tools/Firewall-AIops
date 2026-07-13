"""Diagnostics / traffic reads — firewall log, states table, top talkers.

Platform-neutral log + state-table surface. ``firewall_log`` pulls recent pass /
block entries; ``states_table`` lists active connections; ``top_talkers``
aggregates the state table by source to surface the busiest hosts. All reads.
"""

from __future__ import annotations

from typing import Any

from firewall_aiops.ops._util import num, pick, s

_ACTIONS = {"pass", "block", "rdr", "nat", "reject"}


def normalize_log(rows: list[dict]) -> list[dict]:
    """Normalise raw firewall-log rows across OPNsense / pfSense field names."""
    out = []
    for r in rows:
        out.append(
            {
                "time": s(pick(r, "__timestamp__", "time", "timestamp", "date")),
                "action": s(pick(r, "action", "act", "reason"), 32).lower(),
                "interface": s(pick(r, "interface", "if", "realint")),
                "protocol": s(pick(r, "protoname", "protocol", "proto")),
                "source": s(pick(r, "src", "source", "srcip", "src_addr")),
                "sourcePort": s(pick(r, "srcport", "source_port", "src_port")),
                "destination": s(pick(r, "dst", "destination", "dstip", "dst_addr")),
                "destinationPort": s(pick(r, "dstport", "destination_port", "dst_port")),
                "label": s(pick(r, "label", "rulenr", "rid", "description")),
            }
        )
    return out


def pull_log(conn: Any, limit: int = 500) -> list[dict]:
    """[READ] Raw, normalised recent firewall-log rows (shared by the RCA)."""
    rows = conn.platform.rows(conn.get(conn.platform.path("firewall_log")))
    return normalize_log(rows)[: max(1, int(limit))]


def firewall_log(conn: Any, action: str | None = None, limit: int = 200) -> dict:
    """[READ] Recent firewall-log entries, optionally filtered to pass/block."""
    try:
        entries = pull_log(conn, limit=max(limit, 200) if action else limit)
        if action:
            want = action.strip().lower()
            if want not in _ACTIONS:
                raise ValueError(
                    f"Unknown action '{action}'. Choose one of: {', '.join(sorted(_ACTIONS))}."
                )
            entries = [e for e in entries if e["action"] == want]
        entries = entries[: max(1, int(limit))]
        return {"total": len(entries), "action": s(action) if action else "all", "entries": entries}
    except ValueError:
        raise
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def states_table(conn: Any, top: int = 100) -> dict:
    """[READ] Active pf state-table entries (connections currently tracked)."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("states")))
        states = [
            {
                "interface": s(pick(r, "interface", "if", "ifname")),
                "protocol": s(pick(r, "proto", "protocol")),
                "source": s(pick(r, "src", "source", "src_addr")),
                "destination": s(pick(r, "dst", "destination", "dst_addr")),
                "state": s(pick(r, "state", "status")),
                "bytes": num(pick(r, "bytes", "bytes_total", default=0)),
                "packets": num(pick(r, "packets", "pkts", default=0)),
            }
            for r in rows
        ]
        return {"total": len(states), "states": states[: max(1, int(top))]}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def top_talkers(conn: Any, top: int = 20) -> dict:
    """[READ] Busiest source hosts, aggregated from the state table by bytes."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("top_talkers")))
        agg: dict[str, dict] = {}
        for r in rows:
            src = s(pick(r, "src", "source", "src_addr")) or "(unknown)"
            bucket = agg.setdefault(src, {"source": src, "connections": 0, "bytes": 0.0})
            bucket["connections"] += 1
            bucket["bytes"] += num(pick(r, "bytes", "bytes_total", default=0))
        talkers = sorted(agg.values(), key=lambda t: (t["bytes"], t["connections"]), reverse=True)
        return {"total": len(talkers), "topTalkers": talkers[: max(1, int(top))]}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}
