"""Diagnostics / traffic reads — firewall log, states table, top talkers.

Platform-neutral log + state-table surface. ``firewall_log`` pulls recent pass /
block entries; ``states_table`` lists active connections; ``top_talkers``
aggregates the state table by source to surface the busiest hosts. All reads.
"""

from __future__ import annotations

from typing import Any

from firewall_aiops.ops._util import num, opt, pick, s

_ACTIONS = {"pass", "block", "rdr", "nat", "reject"}


def _lower(value: str | None) -> str | None:
    """Lowercase a value that may be absent, keeping absence as absence."""
    return value.lower() if value is not None else None


def normalize_log(rows: list[dict]) -> list[dict]:
    """Normalise raw firewall-log rows across OPNsense / pfSense field names."""
    out = []
    for r in rows:
        out.append(
            {
                "time": opt(pick(r, "__timestamp__", "time", "timestamp", "date")),
                # Lowercased for comparison, but only when the log row actually
                # carried an action — an absent action stays null rather than
                # becoming the string "none".
                "action": _lower(opt(pick(r, "action", "act", "reason"), 32)),
                "interface": opt(pick(r, "interface", "if", "realint")),
                "protocol": opt(pick(r, "protoname", "protocol", "proto")),
                "source": opt(pick(r, "src", "source", "srcip", "src_addr")),
                "sourcePort": opt(pick(r, "srcport", "source_port", "src_port")),
                "destination": opt(pick(r, "dst", "destination", "dstip", "dst_addr")),
                "destinationPort": opt(pick(r, "dstport", "destination_port", "dst_port")),
                "label": opt(pick(r, "label", "rulenr", "rid", "description")),
            }
        )
    return out


def pull_log(conn: Any, limit: int = 500) -> list[dict]:
    """[READ] Raw, normalised recent firewall-log rows (shared by the RCA)."""
    rows = conn.platform.rows(conn.get(conn.platform.path("firewall_log")))
    return normalize_log(rows)[: max(1, int(limit))]


def firewall_log(conn: Any, action: str | None = None, limit: int = 200) -> dict:
    """[READ] Recent firewall-log entries, optionally filtered to pass/block.

    Returns a truncation envelope::

        {"entries": [...], "returned": 200, "limit": 200, "truncated": true, ...}

    so a cut-off read announces itself. ``truncated`` is measured against the
    full matched set, not inferred from the returned length happening to equal
    the limit — a consumer (and a smaller local model especially) faced with a
    long result otherwise tends to report that nothing came back at all.
    """
    try:
        want_limit = max(1, int(limit))
        # One more than asked for, so truncation is measured rather than guessed.
        entries = pull_log(conn, limit=max(want_limit, 200) + 1 if action else want_limit + 1)
        if action:
            want = action.strip().lower()
            if want not in _ACTIONS:
                raise ValueError(
                    f"Unknown action '{action}'. Choose one of: {', '.join(sorted(_ACTIONS))}."
                )
            entries = [e for e in entries if e["action"] == want]
        truncated = len(entries) > want_limit
        entries = entries[:want_limit]
        return {
            "action": s(action) if action else "all",
            "entries": entries,
            "returned": len(entries),
            "limit": want_limit,
            "truncated": truncated,
        }
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
                "interface": opt(pick(r, "interface", "if", "ifname")),
                "protocol": opt(pick(r, "proto", "protocol")),
                "source": opt(pick(r, "src", "source", "src_addr")),
                "destination": opt(pick(r, "dst", "destination", "dst_addr")),
                "state": opt(pick(r, "state", "status")),
                "bytes": num(pick(r, "bytes", "bytes_total", default=0)),
                "packets": num(pick(r, "packets", "pkts", default=0)),
            }
            for r in rows
        ]
        want = max(1, int(top))
        return {
            "states": states[:want],
            "returned": min(len(states), want),
            "limit": want,
            "truncated": len(states) > want,
            "total": len(states),
        }
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def top_talkers(conn: Any, top: int = 20) -> dict:
    """[READ] Busiest source hosts, aggregated from the state table by bytes."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("top_talkers")))
        agg: dict[str, dict] = {}
        for r in rows:
            src = opt(pick(r, "src", "source", "src_addr")) or "(unknown)"
            bucket = agg.setdefault(src, {"source": src, "connections": 0, "bytes": 0.0})
            bucket["connections"] += 1
            bucket["bytes"] += num(pick(r, "bytes", "bytes_total", default=0))
        talkers = sorted(agg.values(), key=lambda t: (t["bytes"], t["connections"]), reverse=True)
        want = max(1, int(top))
        return {
            "topTalkers": talkers[:want],
            "returned": min(len(talkers), want),
            "limit": want,
            "truncated": len(talkers) > want,
            "total": len(talkers),
        }
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}
