"""Governed firewall writes — the only state-changing operations in the tool.

Every reversible write reads the firewall's current state **before** it changes
anything, so the harness records a faithful undo / audit trail (the before-state
is fetched via a real GET, never guessed):

  * ``toggle_rule`` — reads the rule's current ``enabled`` flag, then flips it;
    undo toggles it back.
  * ``add_alias_entry`` / ``remove_alias_entry`` — read the alias' current member
    entries, then add/remove one; undo restores.

The "make it live" writes commit staged config and are the graduated-autonomy
high-risk tier: ``apply_changes`` and ``reconfigure``. ``kill_states`` and
``restart_service`` are medium; ``reboot`` is high and irreversible (audit only).

Each function returns a plain descriptor; the MCP layer adds dry-run + the
governance harness (risk tier + audit + undo).
"""

from __future__ import annotations

from typing import Any

from firewall_aiops.ops import aliases as alias_ops
from firewall_aiops.ops import rules as rule_ops
from firewall_aiops.ops._util import s
from firewall_aiops.platform import OPNSENSE


def _is_opnsense(conn: Any) -> bool:
    return conn.target.platform == OPNSENSE


# ── rule enable/disable (reversible) ─────────────────────────────────────────


def toggle_rule(conn: Any, uuid: str, enable: bool) -> dict:
    """[WRITE][med] Enable/disable a filter rule, capturing its prior state.

    Reads the rule first so ``priorState.enabled`` reflects what it *was* before
    the flip (drives a faithful undo). Does not apply — a separate
    ``apply_changes`` commits staged rule config on both platforms.
    """
    prior = rule_ops.rule_detail(conn, uuid)
    was_enabled = bool(prior.get("enabled", True)) if "error" not in prior else None
    if _is_opnsense(conn):
        flag = "1" if enable else "0"
        conn.post(conn.platform.path("rule_toggle", uuid=s(uuid, 64), enabled=flag))
    else:
        conn.patch(conn.platform.path("rule_toggle"), json={"id": uuid, "disabled": not enable})
    return {
        "action": "toggle_rule",
        "uuid": s(uuid),
        "enabled": bool(enable),
        "priorState": {"enabled": was_enabled},
        "note": "Staged — run apply_changes to make it live.",
    }


# ── alias entry add/remove (reversible) ──────────────────────────────────────


def _capture_alias(conn: Any, name: str) -> list[str]:
    """Best-effort snapshot of an alias' current entries (for undo/audit)."""
    out = alias_ops.alias_entries(conn, name)
    return out.get("entries", []) if isinstance(out, dict) else []


def add_alias_entry(conn: Any, name: str, entry: str) -> dict:
    """[WRITE][med] Add one entry to an alias, capturing prior entries. Undo: remove."""
    prior = _capture_alias(conn, name)
    if _is_opnsense(conn):
        conn.post(conn.platform.path("alias_add", name=s(name, 64)), json={"address": entry})
    else:
        conn.post(conn.platform.path("alias_add"), json={"name": name, "address": [entry]})
    return {
        "action": "add_alias_entry",
        "alias": s(name),
        "entry": s(entry, 128),
        "priorState": {"entries": prior},
    }


def remove_alias_entry(conn: Any, name: str, entry: str) -> dict:
    """[WRITE][med] Remove one entry from an alias, capturing prior entries. Undo: add."""
    prior = _capture_alias(conn, name)
    if _is_opnsense(conn):
        conn.post(conn.platform.path("alias_delete", name=s(name, 64)), json={"address": entry})
    else:
        conn.delete(conn.platform.path("alias_delete"), json={"name": name, "address": [entry]})
    return {
        "action": "remove_alias_entry",
        "alias": s(name),
        "entry": s(entry, 128),
        "priorState": {"entries": prior},
    }


# ── apply / reconfigure (high — commits staged config) ───────────────────────


def apply_changes(conn: Any) -> dict:
    """[WRITE][high] Commit staged firewall (filter) config — makes edits live."""
    conn.post(conn.platform.path("apply"))
    return {"action": "apply_changes", "platform": conn.target.platform, "applied": True}


def reconfigure(conn: Any, subsystem: str = "filter") -> dict:
    """[WRITE][high] Reload/commit a subsystem's config (filter/nat/aliases)."""
    conn.post(conn.platform.path("reconfigure"), json={"subsystem": s(subsystem, 32)})
    return {
        "action": "reconfigure",
        "platform": conn.target.platform,
        "subsystem": s(subsystem, 32),
    }


# ── operational writes ───────────────────────────────────────────────────────


def kill_states(conn: Any, filter_ip: str = "") -> dict:
    """[WRITE][med] Flush pf state-table entries (optionally for one source IP)."""
    payload = {"filter": s(filter_ip, 64)} if filter_ip else {}
    path = conn.platform.path("kill_states")
    if _is_opnsense(conn):
        conn.post(path, json=payload)
    else:
        conn.delete(path, json=payload or None)
    return {"action": "kill_states", "filter": s(filter_ip, 64) or "all"}


def restart_service(conn: Any, service: str) -> dict:
    """[WRITE][med] Restart a firewall service (e.g. unbound, dhcpd, openvpn)."""
    conn.post(conn.platform.path("service_restart", service=s(service, 32)))
    return {"action": "restart_service", "service": s(service, 32)}


def reboot(conn: Any) -> dict:
    """[WRITE][high] Reboot the firewall. IRREVERSIBLE — audit only, no undo."""
    conn.post(conn.platform.path("reboot"))
    return {"action": "reboot", "platform": conn.target.platform, "rebooting": True}
