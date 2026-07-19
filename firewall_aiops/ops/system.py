"""System reads — firmware/version, health, interfaces, gateways (read-only).

The day-to-day "is this firewall healthy?" surface, platform-neutral: each op
asks the platform for the right path and unwraps the payload through the shared
helpers, so the same function serves OPNsense and pfSense. Every call is
resilient — a transport/parse failure surfaces as ``{"error": ...}`` instead of
raising, and all firewall text is sanitised via ``s``.
"""

from __future__ import annotations

from typing import Any

from firewall_aiops.ops._util import as_obj, num, opt, pick, s, to_bool


def firmware_status(conn: Any) -> dict:
    """[READ] Firmware / OS version and update availability."""
    try:
        obj = as_obj(conn.get(conn.platform.path("firmware")))
        obj = as_obj(pick(obj, "data")) or obj
        return {
            "platform": conn.target.platform,
            "version": opt(pick(obj, "product_version", "version", "installed_version")),
            "product": opt(pick(obj, "product_name", "product", "base", "config_version")),
            "updatesAvailable": to_bool(
                pick(obj, "status", "updates", "needs_update", default=False)
            ),
            "lastCheck": opt(pick(obj, "last_check", "updated", "download_size")),
        }
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def health_status(conn: Any) -> dict:
    """[READ] System health snapshot: uptime, CPU, memory, load."""
    try:
        obj = as_obj(conn.get(conn.platform.path("system_info")))
        obj = as_obj(pick(obj, "data")) or obj
        return {
            "platform": conn.target.platform,
            "hostname": opt(pick(obj, "hostname", "name")),
            "uptime": opt(pick(obj, "uptime", "uptime_seconds")),
            "cpuPercent": num(pick(obj, "cpu", "cpu_usage", "cpu_load", default=0)),
            "memPercent": num(pick(obj, "memory", "mem_usage", "memory_used_percent", default=0)),
            "loadAverage": opt(pick(obj, "loadavg", "load_average", "load")),
            "versions": opt(pick(obj, "versions", "kernel", "biosdate")),
        }
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def interface_status(conn: Any) -> dict:
    """[READ] Interfaces with link/status and address, worst (down) first."""
    try:
        raw = conn.get(conn.platform.path("interfaces"))
        rows = _interface_rows(conn, raw)
        ifaces = [
            {
                "name": opt(pick(r, "name", "device", "descr", "if")),
                "description": opt(pick(r, "description", "descr", "friendlyname")),
                "status": opt(pick(r, "status", "linkstate", "state")),
                "up": to_bool(pick(r, "status", "enabled", "linkstate", default=False)),
                "address": opt(pick(r, "ipaddr", "address", "ip", "ipv4")),
            }
            for r in rows
        ]
        ifaces.sort(key=lambda i: i["up"])
        return {"total": len(ifaces), "interfaces": ifaces}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def _interface_rows(conn: Any, raw: Any) -> list[dict]:
    """OPNsense returns a name→record map; pfSense a list under ``data``."""
    if isinstance(raw, dict) and not any(
        isinstance(v, list) for v in raw.values()
    ) and "data" not in raw:
        rows = []
        for name, rec in raw.items():
            rec = dict(rec) if isinstance(rec, dict) else {"status": rec}
            rec.setdefault("name", name)
            rows.append(rec)
        return [conn.platform.normalise(r) for r in rows]
    return conn.platform.rows(raw)


def gateway_status(conn: Any) -> dict:
    """[READ] WAN/LAN gateways with status, loss %, and RTT (latency)."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("gateways")))
        gws = [
            {
                "name": opt(pick(r, "name", "gateway", "gwname")),
                "address": opt(pick(r, "address", "monitorip", "gateway_ip")),
                "status": opt(pick(r, "status", "status_translated", "state")),
                "lossPercent": num(_strip_pct(pick(r, "loss", "loss_percent", default=0))),
                "rttMs": num(_strip_unit(pick(r, "delay", "rtt", "latency", default=0))),
                "stddevMs": num(_strip_unit(pick(r, "stddev", "rttsd", default=0))),
            }
            for r in rows
        ]
        return {"total": len(gws), "gateways": gws}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def _strip_pct(value: Any) -> Any:
    """Strip a trailing ``%`` so ``"3.0 %"`` parses as 3.0."""
    return str(value).replace("%", "").strip() if value is not None else 0


def _strip_unit(value: Any) -> Any:
    """Strip a trailing unit (``ms``) so ``"12.4 ms"`` parses as 12.4."""
    return str(value).replace("ms", "").strip() if value is not None else 0
