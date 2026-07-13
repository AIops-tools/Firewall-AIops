"""Alias reads — list aliases and resolve an alias' entries (read-only).

Aliases (named groups of hosts/networks/ports) are the reusable building blocks
of firewall/NAT rules. This module lists them and expands one alias to its
member entries. Mutating an alias' entries lives in
:mod:`firewall_aiops.ops.writes`.
"""

from __future__ import annotations

from typing import Any

from firewall_aiops.ops._util import as_obj, pick, s


def list_aliases(conn: Any) -> dict:
    """[READ] All firewall aliases (name, type, description, member count)."""
    try:
        rows = conn.platform.rows(conn.get(conn.platform.path("aliases_search")))
        aliases = [
            {
                "uuid": s(pick(r, "uuid", "id")),
                "name": s(pick(r, "name", "aliasname")),
                "type": s(pick(r, "type", "aliastype")),
                "description": s(pick(r, "description", "descr")),
                "entries": _entry_count(pick(r, "content", "address", "entries", default="")),
            }
            for r in rows
        ]
        return {"total": len(aliases), "aliases": aliases}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def _entry_count(content: Any) -> int:
    """Count members in an alias' content (list, or newline/space-delimited str)."""
    if isinstance(content, list):
        return len([c for c in content if c])
    text = str(content or "").replace(",", "\n").replace(" ", "\n")
    return len([line for line in text.splitlines() if line.strip()])


def alias_entries(conn: Any, name: str) -> dict:
    """[READ] The member entries (hosts/networks/ports) of one alias."""
    try:
        raw = conn.get(conn.platform.path("alias_entries", name=s(name, 64)))
        entries = _extract_entries(conn, raw)
        return {"alias": s(name), "total": len(entries), "entries": entries}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200), "alias": s(name)}


def _extract_entries(conn: Any, raw: Any) -> list[str]:
    """Pull an alias' entries out of either platform's response shape.

    OPNsense ``alias_util/list`` returns ``{"rows": [{"ip": "1.2.3.4"}, ...]}``;
    pfSense returns the alias record with an ``address`` list under ``data``.
    """
    obj = as_obj(raw)
    inner = as_obj(pick(obj, "data")) or obj
    address = pick(inner, "address", "content", "entries")
    if isinstance(address, list):
        return [s(a, 128) for a in address if a]
    if isinstance(address, str) and address:
        parts = address.replace(",", "\n").replace(" ", "\n").splitlines()
        return [s(p, 128) for p in parts if p.strip()]
    rows = conn.platform.rows(raw)
    out = [s(pick(r, "ip", "address", "entry", "host"), 128) for r in rows]
    return [e for e in out if e]
