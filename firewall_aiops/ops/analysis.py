"""Flagship signature analyses over firewall telemetry (pure analysis).

These are the differentiators — transparent heuristics, every flag reported with
its numbers so an operator can see *why* something was ranked, never a black-box
verdict:

  1. ``gateway_health_rca`` — rank WAN/LAN gateways by loss + latency, flag each
     down/degraded gateway and map it to a likely cause + recommended action.
  2. ``rule_hit_and_shadow_analysis`` — find never-hit (evaluations=0) enabled
     rules and rules shadowed/duplicated by an earlier terminating rule.
  3. ``blocked_traffic_rca`` — aggregate blocked log entries by source + port,
     rank the noisiest sources, and classify each (scan / brute-force / probe)
     with a recommended action.

All three are pure functions (no I/O): pass them the telemetry (from the reads
in the other ops modules, or injected) and they return the analysis. The live
pulls that feed them live in the ``pull_*`` helpers.
"""

from __future__ import annotations

from typing import Any

from firewall_aiops.ops import diag, system
from firewall_aiops.ops._util import num, s

MAX_ROWS = 100

# ── 1. gateway health RCA ────────────────────────────────────────────────────
DEFAULT_LOSS_PCT = 5.0
DEFAULT_LATENCY_MS = 150.0
_DOWN_WORDS = {"down", "offline", "loss", "force_down", "unknown"}


def pull_gateways(conn: Any) -> list[dict]:
    """[READ] Live gateway status rows for the RCA."""
    out = system.gateway_status(conn)
    return out.get("gateways", []) if isinstance(out, dict) else []


def _classify_gateway(is_down: bool, loss: float, rtt: float, loss_pct: float,
                      latency_ms: float) -> dict:
    if is_down:
        return {
            "cause": "Gateway is down (no monitoring reply / 100% loss)",
            "action": "Check the WAN link/modem and ISP; fail over to a secondary "
            "gateway if this is the default route.",
        }
    hi_loss = loss >= loss_pct
    hi_lat = rtt >= latency_ms
    if hi_loss and hi_lat:
        return {
            "cause": "Upstream congestion or ISP degradation (loss and latency both high)",
            "action": "Open an ISP ticket; shift traffic to the healthier gateway.",
        }
    if hi_loss:
        return {
            "cause": "Packet loss on the last mile (loss high, latency normal)",
            "action": "Check WAN cabling/SFP and the modem; escalate line quality to the ISP.",
        }
    if hi_lat:
        return {
            "cause": "High latency on a distant/bufferbloated path (latency high, loss normal)",
            "action": "Enable per-gateway traffic shaping/QoS; verify the path/peering.",
        }
    return {"cause": "Healthy — within thresholds", "action": "No action needed."}


def gateway_health_rca(
    gateways: list[dict],
    loss_pct: float = DEFAULT_LOSS_PCT,
    latency_ms: float = DEFAULT_LATENCY_MS,
) -> dict:
    """[READ] Rank gateways by loss + latency and map each to a cause + action.

    Pure analysis over ``gateways`` rows (from ``pull_gateways`` or injected):
    {name, address, status, lossPercent, rttMs}. A gateway is *down* when its
    status reads down/offline or loss is 100%, *degraded* when loss >= loss_pct
    or latency >= latency_ms. Ranks worst-first by a composite of loss (x10) +
    latency and attaches a likely cause + action; every ranking carries its
    numbers.
    """
    ranked = []
    for g in gateways or []:
        status = str(g.get("status") or "").lower()
        loss = num(g.get("lossPercent"))
        rtt = num(g.get("rttMs"))
        is_down = loss >= 100 or any(w in status for w in _DOWN_WORDS)
        degraded = is_down or loss >= loss_pct or rtt >= latency_ms
        entry = {
            "name": s(g.get("name")),
            "address": s(g.get("address")),
            "status": s(g.get("status")),
            "lossPercent": loss,
            "rttMs": rtt,
            "down": is_down,
            "degraded": degraded,
            "_score": (1000 if is_down else 0) + loss * 10 + rtt,
        }
        entry.update(_classify_gateway(is_down, loss, rtt, loss_pct, latency_ms))
        ranked.append(entry)

    ranked.sort(key=lambda e: e["_score"], reverse=True)
    for e in ranked:
        e.pop("_score", None)
    return {
        "gatewaysEvaluated": len(ranked),
        "downCount": sum(1 for e in ranked if e["down"]),
        "degradedCount": sum(1 for e in ranked if e["degraded"]),
        "thresholds": {"lossPct": loss_pct, "latencyMs": latency_ms},
        "worst": ranked[:MAX_ROWS],
        "note": (
            "Advisory read-only heuristic: gateways ranked by loss (x10) + latency; "
            "'down' = status down/offline or 100% loss; 'degraded' = loss >= lossPct "
            "or latency >= latencyMs."
        ),
    }


# ── 2. rule hit + shadow analysis ────────────────────────────────────────────
_TERMINATING = {"pass", "block", "reject", "drop"}
_ANY = {"", "any", "*", "0.0.0.0/0", "::/0"}


def _match_field(a: str, b: str) -> bool:
    """An earlier rule's field covers a later one's if equal or 'any'/broader."""
    an, bn = str(a or "").lower(), str(b or "").lower()
    return an in _ANY or an == bn


def _covers(earlier: dict, later: dict) -> bool:
    """True when ``earlier`` (terminating) would match everything ``later`` does."""
    if str(earlier.get("action") or "").lower() not in _TERMINATING:
        return False
    return (
        _match_field(earlier.get("interface", ""), later.get("interface", ""))
        and _match_field(earlier.get("protocol", ""), later.get("protocol", ""))
        and _match_field(earlier.get("source", ""), later.get("source", ""))
        and _match_field(earlier.get("destination", ""), later.get("destination", ""))
        and _match_field(earlier.get("destinationPort", ""), later.get("destinationPort", ""))
    )


def _sig(rule: dict) -> tuple:
    return (
        str(rule.get("action", "")).lower(),
        str(rule.get("interface", "")).lower(),
        str(rule.get("protocol", "")).lower(),
        str(rule.get("source", "")).lower(),
        str(rule.get("destination", "")).lower(),
        str(rule.get("destinationPort", "")).lower(),
    )


def rule_hit_and_shadow_analysis(rules: list[dict]) -> dict:
    """[READ] Flag never-hit enabled rules and shadowed/redundant rules.

    Pure analysis over ``rules`` rows (from ``list_rules`` or injected): {uuid,
    sequence, enabled, action, interface, protocol, source, destination,
    destinationPort, evaluations}. Rules are compared *in list order* (top-down,
    as pf evaluates them). Reported findings:

      * **unusedRules** — enabled rules with evaluations == 0 (candidates to
        remove or fix; a rule that never matches is either dead or misordered).
      * **shadowedRules** — a rule fully covered by an earlier enabled
        terminating rule (pass/block/reject/drop) that would always match first.
      * **redundantRules** — a rule with the exact same match+action as an
        earlier enabled rule.

    Every finding names the offending/covering rule uuid so the operator can act.
    """
    ordered = list(rules or [])
    unused, shadowed, redundant = [], [], []
    seen_sig: dict[tuple, str] = {}

    for idx, rule in enumerate(ordered):
        if not rule.get("enabled", True):
            continue
        uuid = rule.get("uuid")
        if num(rule.get("evaluations")) == 0:
            unused.append({
                "uuid": s(uuid),
                "description": s(rule.get("description")),
                "interface": s(rule.get("interface")),
                "action": s(rule.get("action")),
            })
        sig = _sig(rule)
        if sig in seen_sig:
            redundant.append({
                "uuid": s(uuid),
                "duplicateOf": s(seen_sig[sig]),
                "description": s(rule.get("description")),
            })
        else:
            seen_sig[sig] = str(uuid)
        for earlier in ordered[:idx]:
            if earlier.get("enabled", True) and _sig(earlier) != sig and _covers(earlier, rule):
                shadowed.append({
                    "uuid": s(uuid),
                    "shadowedBy": s(earlier.get("uuid")),
                    "description": s(rule.get("description")),
                })
                break

    return {
        "rulesEvaluated": len(ordered),
        "unusedCount": len(unused),
        "shadowedCount": len(shadowed),
        "redundantCount": len(redundant),
        "unusedRules": unused[:MAX_ROWS],
        "shadowedRules": shadowed[:MAX_ROWS],
        "redundantRules": redundant[:MAX_ROWS],
        "note": (
            "Advisory read-only heuristic: 'unused' = enabled rule with 0 "
            "evaluations; 'shadowed' = covered by an earlier terminating rule; "
            "'redundant' = identical match+action to an earlier rule. Review before "
            "removing — evaluation counters reset on reboot/reload."
        ),
    }


# ── 3. blocked-traffic RCA ───────────────────────────────────────────────────
_SENSITIVE_PORTS = {
    "22": "SSH", "23": "Telnet", "3389": "RDP", "445": "SMB", "3306": "MySQL",
    "5432": "PostgreSQL", "1433": "MSSQL", "6379": "Redis", "21": "FTP",
}
_SCAN_PORT_THRESHOLD = 10


def pull_blocked_log(conn: Any, limit: int = 500) -> list[dict]:
    """[READ] Live recent firewall-log rows for the blocked-traffic RCA."""
    return diag.pull_log(conn, limit=limit)


def _classify_source(distinct_ports: int, top_port: str, hits: int) -> dict:
    if distinct_ports >= _SCAN_PORT_THRESHOLD:
        return {
            "cause": f"Port scan — {distinct_ports} distinct destination ports blocked",
            "action": "Confirm the source is untrusted, then add a drop/blocklist "
            "alias entry for it; alert if it is an internal host (possible compromise).",
        }
    service = _SENSITIVE_PORTS.get(top_port)
    if service:
        return {
            "cause": f"Repeated probes to {service} (port {top_port}) — {hits} blocks",
            "action": f"Verify {service} is not meant to be exposed; block the source "
            "and ensure the service is firewalled to trusted networks only.",
        }
    return {
        "cause": "Blocked traffic from a single source (no scan/service pattern)",
        "action": "Review whether the block is expected; add to a blocklist alias if hostile.",
    }


def blocked_traffic_rca(log_entries: list[dict], top: int = 20) -> dict:
    """[READ] Rank the noisiest blocked sources and classify cause + action.

    Pure analysis over firewall-log rows (from ``pull_blocked_log`` or injected):
    {action, source, destination, destinationPort, protocol}. Keeps only
    ``action == 'block'``, aggregates by source (hit count, distinct destination
    ports, busiest port), ranks the noisiest sources, and classifies each as a
    port scan, a service probe/brute-force, or generic — with a recommended
    action. Every entry carries its numbers.
    """
    blocked = [e for e in (log_entries or []) if str(e.get("action", "")).lower() == "block"]
    by_source: dict[str, dict] = {}
    for e in blocked:
        src = s(e.get("source")) or "(unknown)"
        bucket = by_source.setdefault(src, {"source": src, "hits": 0, "ports": {}})
        bucket["hits"] += 1
        port = s(e.get("destinationPort")) or "?"
        bucket["ports"][port] = bucket["ports"].get(port, 0) + 1

    ranked = []
    for bucket in by_source.values():
        ports = bucket["ports"]
        top_port = max(ports, key=lambda p: ports[p]) if ports else "?"
        entry = {
            "source": bucket["source"],
            "hits": bucket["hits"],
            "distinctPorts": len(ports),
            "topPort": top_port,
            "topPortHits": ports.get(top_port, 0),
        }
        entry.update(_classify_source(len(ports), top_port, ports.get(top_port, 0)))
        ranked.append(entry)

    ranked.sort(key=lambda e: e["hits"], reverse=True)
    return {
        "blocksEvaluated": len(blocked),
        "distinctSources": len(by_source),
        "topSources": ranked[: max(1, int(top))],
        "note": (
            "Advisory read-only heuristic: sources ranked by block count; "
            f">= {_SCAN_PORT_THRESHOLD} distinct ports reads as a scan, a busy "
            "sensitive port as a service probe. Correlate before blocking."
        ),
    }
