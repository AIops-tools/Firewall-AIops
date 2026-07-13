"""Governed firewall-write MCP tools (the only state-changing tools).

Every tool is wrapped with the governance harness (audit + graduated approval
tier) and takes a ``dry_run`` preview. Reversible writes pass an ``undo=``
callback that turns the fetched before-state into an inverse descriptor the
harness records; irreversible ones (apply/reconfigure/reboot) record none.

Risk tiers: apply_changes / reconfigure / reboot = high (commit staged config or
irreversible); toggle_rule / add_alias_entry / remove_alias_entry / kill_states /
restart_service = medium.
"""

from typing import Any, Optional

from firewall_aiops.governance import governed_tool
from firewall_aiops.ops import writes as ops
from mcp_server._shared import _get_connection, mcp, tool_errors

# ── undo descriptors (built from the fetched before-state) ──────────────────


def _toggle_undo(params: dict[str, Any], result: Any) -> Optional[dict]:
    """Inverse of toggle_rule: restore the rule's prior enabled state."""
    if not isinstance(result, dict):
        return None
    prior = (result.get("priorState") or {}).get("enabled")
    if prior is None:
        return None
    return {
        "tool": "toggle_rule",
        "params": {"uuid": params.get("uuid"), "enable": bool(prior)},
        "skill": "firewall-aiops",
        "note": "Inverse of toggle_rule: restore the rule's prior enabled state.",
    }


def _add_alias_undo(params: dict[str, Any], result: Any) -> Optional[dict]:
    """Inverse of add_alias_entry: remove the entry that was just added."""
    if not isinstance(result, dict):
        return None
    return {
        "tool": "remove_alias_entry",
        "params": {"name": params.get("name"), "entry": params.get("entry")},
        "skill": "firewall-aiops",
        "note": "Inverse of add_alias_entry: remove the entry that was added.",
    }


def _remove_alias_undo(params: dict[str, Any], result: Any) -> Optional[dict]:
    """Inverse of remove_alias_entry: add the entry back."""
    if not isinstance(result, dict):
        return None
    return {
        "tool": "add_alias_entry",
        "params": {"name": params.get("name"), "entry": params.get("entry")},
        "skill": "firewall-aiops",
        "note": "Inverse of remove_alias_entry: add the entry back.",
    }


# ── rule enable/disable ──────────────────────────────────────────────────────


@mcp.tool()
@governed_tool(risk_level="medium", undo=_toggle_undo)
@tool_errors("dict")
def toggle_rule(
    uuid: str,
    enable: bool,
    dry_run: bool = False,
    target: Optional[str] = None,
) -> dict:
    """[WRITE][risk=medium] Enable/disable a filter rule; reversible.

    Reads the rule first so the harness records an undo that restores its prior
    enabled state. Staged only — run apply_changes to make it live. Pass
    dry_run=True to preview.

    Args:
        uuid: Rule uuid (OPNsense) or id (pfSense), from list_rules.
        enable: True to enable the rule, False to disable.
        dry_run: If True, preview without changing.
        target: Firewall target name from config; omit for the default.
    """
    conn = _get_connection(target)
    if dry_run:
        return {"dryRun": True, "wouldToggle": {"uuid": uuid, "enable": enable}}
    return ops.toggle_rule(conn, uuid, enable)


# ── alias entry add/remove ───────────────────────────────────────────────────


@mcp.tool()
@governed_tool(risk_level="medium", undo=_add_alias_undo)
@tool_errors("dict")
def add_alias_entry(
    name: str,
    entry: str,
    dry_run: bool = False,
    target: Optional[str] = None,
) -> dict:
    """[WRITE][risk=medium] Add one entry to an alias; reversible (undo removes it).

    Captures the alias' prior entries before the change. Pass dry_run=True to
    preview.

    Args:
        name: Alias name (from list_aliases).
        entry: The host/network/port to add.
        dry_run: If True, preview without changing.
        target: Firewall target name from config; omit for the default.
    """
    conn = _get_connection(target)
    if dry_run:
        return {"dryRun": True, "wouldAdd": {"alias": name, "entry": entry}}
    return ops.add_alias_entry(conn, name, entry)


@mcp.tool()
@governed_tool(risk_level="medium", undo=_remove_alias_undo)
@tool_errors("dict")
def remove_alias_entry(
    name: str,
    entry: str,
    dry_run: bool = False,
    target: Optional[str] = None,
) -> dict:
    """[WRITE][risk=medium] Remove one entry from an alias; reversible (undo adds it back).

    Captures the alias' prior entries before the change. Pass dry_run=True to
    preview.

    Args:
        name: Alias name (from list_aliases).
        entry: The host/network/port to remove.
        dry_run: If True, preview without changing.
        target: Firewall target name from config; omit for the default.
    """
    conn = _get_connection(target)
    if dry_run:
        return {"dryRun": True, "wouldRemove": {"alias": name, "entry": entry}}
    return ops.remove_alias_entry(conn, name, entry)


# ── apply / reconfigure (high) ───────────────────────────────────────────────


@mcp.tool()
@governed_tool(risk_level="high")
@tool_errors("dict")
def apply_changes(dry_run: bool = False, target: Optional[str] = None) -> dict:
    """[WRITE][risk=high] Commit staged firewall config — makes edits live.

    This is the "make it live" step after staged edits (e.g. toggle_rule).
    Requires an approver (FIREWALL_AUDIT_APPROVED_BY) under the graduated-autonomy
    policy. Pass dry_run=True to preview.

    Args:
        dry_run: If True, preview without applying.
        target: Firewall target name from config; omit for the default.
    """
    conn = _get_connection(target)
    if dry_run:
        return {"dryRun": True, "wouldApply": {"platform": conn.target.platform}}
    return ops.apply_changes(conn)


@mcp.tool()
@governed_tool(risk_level="high")
@tool_errors("dict")
def reconfigure(subsystem: str = "filter", dry_run: bool = False,
                target: Optional[str] = None) -> dict:
    """[WRITE][risk=high] Reload/commit a subsystem's config (filter/nat/aliases).

    Requires an approver (FIREWALL_AUDIT_APPROVED_BY). Pass dry_run=True to preview.

    Args:
        subsystem: Config subsystem to reload (filter, nat, aliases).
        dry_run: If True, preview without reconfiguring.
        target: Firewall target name from config; omit for the default.
    """
    conn = _get_connection(target)
    if dry_run:
        return {"dryRun": True, "wouldReconfigure": {"subsystem": subsystem}}
    return ops.reconfigure(conn, subsystem)


# ── operational writes ───────────────────────────────────────────────────────


@mcp.tool()
@governed_tool(risk_level="medium")
@tool_errors("dict")
def kill_states(filter_ip: str = "", dry_run: bool = False,
                target: Optional[str] = None) -> dict:
    """[WRITE][risk=medium] Flush pf state-table entries (optionally one source IP).

    Drops tracked connections; they re-establish on the next packet. Pass
    dry_run=True to preview.

    Args:
        filter_ip: Optional source IP to scope the flush to (blank = all states).
        dry_run: If True, preview without flushing.
        target: Firewall target name from config; omit for the default.
    """
    conn = _get_connection(target)
    if dry_run:
        return {"dryRun": True, "wouldKillStates": {"filter": filter_ip or "all"}}
    return ops.kill_states(conn, filter_ip)


@mcp.tool()
@governed_tool(risk_level="medium")
@tool_errors("dict")
def restart_service(service: str, dry_run: bool = False,
                    target: Optional[str] = None) -> dict:
    """[WRITE][risk=medium] Restart a firewall service (unbound, dhcpd, openvpn, ...).

    Pass dry_run=True to preview.

    Args:
        service: Service name to restart.
        dry_run: If True, preview without restarting.
        target: Firewall target name from config; omit for the default.
    """
    conn = _get_connection(target)
    if dry_run:
        return {"dryRun": True, "wouldRestart": {"service": service}}
    return ops.restart_service(conn, service)


@mcp.tool()
@governed_tool(risk_level="high")
@tool_errors("dict")
def reboot(dry_run: bool = False, target: Optional[str] = None) -> dict:
    """[WRITE][risk=high] Reboot the firewall. IRREVERSIBLE — audit only, no undo.

    Requires an approver (FIREWALL_AUDIT_APPROVED_BY) under the graduated-autonomy
    policy. Pass dry_run=True to preview.

    Args:
        dry_run: If True, preview without rebooting.
        target: Firewall target name from config; omit for the default.
    """
    conn = _get_connection(target)
    if dry_run:
        return {"dryRun": True, "wouldReboot": {"platform": conn.target.platform}}
    return ops.reboot(conn)
