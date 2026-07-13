"""VPN reads — WireGuard, OpenVPN, IPsec (read-only).

Platform-neutral tunnel status: WireGuard peers + handshake, OpenVPN sessions,
and IPsec security associations (phase-1/phase-2). Each op is resilient — a VPN
subsystem that is not installed/enabled reports ``{"error": ...}`` rather than
raising.
"""

from __future__ import annotations

from typing import Any

from firewall_aiops.ops._util import num, pick, s, to_bool


def wireguard_status(conn: Any) -> dict:
    """[READ] WireGuard peers with connected state + last handshake + transfer."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("wireguard")))
        peers = [
            {
                "name": s(pick(r, "name", "peer", "public-key", "publicKey")),
                "endpoint": s(pick(r, "endpoint", "latest-endpoint")),
                "allowedIps": s(pick(r, "allowed-ips", "allowedIps", "tunneladdress")),
                "connected": to_bool(pick(r, "connected", "status", default=False)),
                "lastHandshake": s(pick(r, "latest-handshake", "lastHandshake", "handshake")),
                "transferRx": num(pick(r, "transfer-rx", "bytesReceived", default=0)),
                "transferTx": num(pick(r, "transfer-tx", "bytesSent", default=0)),
            }
            for r in rows
        ]
        return {"total": len(peers), "peers": peers}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def openvpn_sessions(conn: Any) -> dict:
    """[READ] OpenVPN sessions/connected clients (name, address, bytes)."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("openvpn")))
        sessions = [
            {
                "commonName": s(pick(r, "common_name", "commonName", "name", "description")),
                "realAddress": s(pick(r, "real_address", "realAddress", "remote_host")),
                "virtualAddress": s(pick(r, "virtual_address", "virtualAddress", "tunnel_addr")),
                "bytesReceived": num(pick(r, "bytes_received", "bytesReceived", default=0)),
                "bytesSent": num(pick(r, "bytes_sent", "bytesSent", default=0)),
                "connectedSince": s(pick(r, "connected_since", "connectedSince", "connect_time")),
            }
            for r in rows
        ]
        return {"total": len(sessions), "sessions": sessions}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def ipsec_sas(conn: Any) -> dict:
    """[READ] IPsec security associations (phase-1/phase-2) with state."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("ipsec")))
        sas = [
            {
                "name": s(pick(r, "name", "con-id", "description", "ikeid")),
                "localAddress": s(pick(r, "local-host", "local_address", "local-addrs")),
                "remoteAddress": s(pick(r, "remote-host", "remote_address", "remote-addrs")),
                "state": s(pick(r, "state", "status", "phase")),
                "installed": to_bool(pick(r, "installed", "established", default=False)),
                "bytesIn": num(pick(r, "bytes-in", "bytesIn", default=0)),
                "bytesOut": num(pick(r, "bytes-out", "bytesOut", default=0)),
            }
            for r in rows
        ]
        return {"total": len(sas), "securityAssociations": sas}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}
