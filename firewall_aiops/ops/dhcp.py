"""DHCP reads — active leases and static mappings (read-only).

Platform-neutral: OPNsense ``/api/dhcpv4/...`` and pfSense
``/api/v2/status/dhcp_server/leases`` reconciled through the shared pickers.
"""

from __future__ import annotations

from typing import Any

from firewall_aiops.ops._util import pick, s, to_bool


def leases(conn: Any, online_only: bool = False) -> dict:
    """[READ] Active DHCP leases (IP, MAC, hostname, state)."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("dhcp_leases")))
        entries = [
            {
                "ip": s(pick(r, "address", "ip", "ipaddr")),
                "mac": s(pick(r, "mac", "hwaddr", "mac_address")),
                "hostname": s(pick(r, "hostname", "client-hostname", "descr")),
                "state": s(pick(r, "state", "status", "act")),
                "online": to_bool(pick(r, "online", "status", default=False)),
                "starts": s(pick(r, "starts", "start")),
                "ends": s(pick(r, "ends", "end", "expires")),
            }
            for r in rows
        ]
        if online_only:
            entries = [e for e in entries if e["online"]]
        return {"total": len(entries), "leases": entries}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def static_mappings(conn: Any) -> dict:
    """[READ] DHCP static (reserved) mappings (MAC ↔ IP)."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("dhcp_static")))
        maps = [
            {
                "mac": s(pick(r, "mac", "hwaddr", "mac_address")),
                "ip": s(pick(r, "ipaddr", "ip", "address")),
                "hostname": s(pick(r, "hostname", "host")),
                "description": s(pick(r, "descr", "description")),
            }
            for r in rows
        ]
        return {"total": len(maps), "staticMappings": maps}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}
