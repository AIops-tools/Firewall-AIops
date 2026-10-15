"""DHCP reads — active leases and static mappings (read-only).

Platform-neutral: OPNsense ``/api/dhcpv4/...`` and pfSense
``/api/v2/status/dhcp_server/leases`` reconciled through the shared pickers.
"""

from __future__ import annotations

from typing import Any

from firewall_aiops.ops._util import opt, pick, s, to_bool


def _lease_online(value: Any) -> bool | None:
    """Lease online state; ``None`` when unreported or an unrecognised word.

    Platforms report status *words* ("online" / "offline", "active/online",
    "idle/offline"), and ``to_bool`` reads any non-empty word as true — so an
    offline lease came back online. Words are mapped; flags go through to_bool.
    """
    if value is None:
        return None
    text = str(value).strip().lower()
    if "offline" in text:
        return False
    if "online" in text:
        return True
    if text in {"1", "0", "true", "false", "yes", "no"} or isinstance(value, (bool, int)):
        return to_bool(value)
    return None


def leases(conn: Any, online_only: bool = False) -> dict:
    """[READ] Active DHCP leases (IP, MAC, hostname, state)."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("dhcp_leases")))
        entries = [
            {
                "ip": opt(pick(r, "address", "ip", "ipaddr")),
                "mac": opt(pick(r, "mac", "hwaddr", "mac_address")),
                "hostname": opt(pick(r, "hostname", "client-hostname", "descr")),
                "state": opt(pick(r, "state", "status", "act")),
                "online": _lease_online(pick(r, "online", "online_status", "status")),
                "starts": opt(pick(r, "starts", "start")),
                "ends": opt(pick(r, "ends", "end", "expires")),
            }
            for r in rows
        ]
        if online_only:
            # Leases whose state the platform did not report are counted, not
            # silently dropped: an empty result must not read as "no clients".
            unknown = sum(1 for e in entries if e["online"] is None)
            entries = [e for e in entries if e["online"] is True]
            return {"total": len(entries), "leases": entries, "onlineUnknown": unknown}
        return {"total": len(entries), "leases": entries}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def static_mappings(conn: Any) -> dict:
    """[READ] DHCP static (reserved) mappings (MAC ↔ IP)."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("dhcp_static")))
        maps = [
            {
                "mac": opt(pick(r, "mac", "hwaddr", "mac_address")),
                "ip": opt(pick(r, "ipaddr", "ip", "address")),
                "hostname": opt(pick(r, "hostname", "host")),
                "description": opt(pick(r, "descr", "description")),
            }
            for r in rows
        ]
        return {"total": len(maps), "staticMappings": maps}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}
