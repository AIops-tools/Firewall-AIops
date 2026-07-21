"""Governed firewall-write MCP tools (the only state-changing tools).

Every tool is wrapped with the governance harness (audit + a descriptive
risk-tier label, not a gate) and takes a ``dry_run`` preview. Reversible writes
pass an ``undo=`` callback that turns the fetched before-state into an inverse
descriptor the harness records; irreversible ones (apply/reconfigure/reboot)
record none.

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
        # The preview reads the rule and reports the SAME managementImpact the
        # real call would, so a preview can never look safer than the write.
        return {
            "dryRun": True,
            "wouldToggle": {"uuid": uuid, "enable": enable},
            "managementImpact": ops.assess_toggle(conn, uuid, enable),
        }
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
def apply_changes(
    dry_run: bool = False, override: bool = False, target: Optional[str] = None
) -> dict:
    """[WRITE][risk=high] Commit staged firewall config — makes edits live.

    This is the "make it live" step after staged edits (e.g. toggle_rule).

    Reads the staged rule set first and REFUSES when committing it would provably
    cut the endpoint this tool manages the firewall through — disabling the
    'pass' rule that permits management access, or enabling a 'block' rule that
    covers it, locks out this tool and the undo that would reverse it. Uncertain
    cases (alias destinations, 'any', interface groups) warn and proceed.

    dry_run=True returns the full staged change set and its assessment, not just
    an acknowledgement — use it before every apply.

    Args:
        dry_run: If True, return the staged change set + lockout assessment
            without applying.
        override: Proceed despite a certain lockout finding. Only for operators
            with console / out-of-band access who mean it.
        target: Firewall target name from config; omit for the default.
    """
    conn = _get_connection(target)
    if dry_run:
        # The guard runs BEFORE the preview returns: a dry-run whose answer is
        # "this would be refused" has to say so, or the caller gets a green
        # preview followed by a refusal it will read as transient and retry.
        assessment = ops.guard_apply(conn, "apply staged firewall config", override)
        return {
            "dryRun": True,
            "wouldApply": {"platform": conn.target.platform},
            "pendingChanges": assessment,
        }
    return ops.apply_changes(conn, override=override)


@mcp.tool()
@governed_tool(risk_level="high")
@tool_errors("dict")
def reconfigure(subsystem: str = "filter", dry_run: bool = False,
                override: bool = False, target: Optional[str] = None) -> dict:
    """[WRITE][risk=high] Reload/commit a subsystem's config (filter/nat/aliases).

    Reloading the 'filter' subsystem commits the staged rule set just as
    apply_changes does, so it carries the same lockout guard and the same
    override.

    Args:
        subsystem: Config subsystem to reload (filter, nat, aliases).
        dry_run: If True, preview without reconfiguring.
        override: Proceed despite a certain lockout finding (filter subsystem).
        target: Firewall target name from config; omit for the default.
    """
    conn = _get_connection(target)
    if dry_run:
        preview: dict = {"dryRun": True, "wouldReconfigure": {"subsystem": subsystem}}
        if str(subsystem).strip().lower() == "filter":
            # Same guard, same fail-open semantics, before the preview returns.
            preview["pendingChanges"] = ops.guard_apply(
                conn, f"reconfigure the {subsystem} subsystem", override
            )
        return preview
    return ops.reconfigure(conn, subsystem, override=override)


# ── operational writes ───────────────────────────────────────────────────────


@mcp.tool()
@governed_tool(risk_level="medium")
@tool_errors("dict")
def kill_states(filter_ip: str = "", dry_run: bool = False,
                target: Optional[str] = None) -> dict:
    """[WRITE][risk=medium] Flush pf state-table entries (optionally one source IP).

    Drops tracked connections; they re-establish on the next packet. This
    includes THIS tool's own connection state, so the call may appear to fail
    even though the flush ran — that is a lost response, not a lockout, and a
    blind retry is the wrong reaction. Access is not lost: the permitting rule
    is untouched. Pass dry_run=True to preview.

    Args:
        filter_ip: Optional source IP to scope the flush to (blank = all states).
        dry_run: If True, preview without flushing.
        target: Firewall target name from config; omit for the default.
    """
    conn = _get_connection(target)
    if dry_run:
        return {
            "dryRun": True,
            "wouldKillStates": {"filter": filter_ip or "all"},
            "sessionImpact": ops.KILL_STATES_SESSION_NOTE,
        }
    return ops.kill_states(conn, filter_ip)


@mcp.tool()
@governed_tool(risk_level="medium")
@tool_errors("dict")
def restart_service(service: str, dry_run: bool = False,
                    target: Optional[str] = None) -> dict:
    """[WRITE][risk=medium] Restart a firewall service (unbound, dhcpd, openvpn, ...).

    REFUSES the service that answers this appliance's own management API
    (nginx / lighttpd / configd / webgui and friends): restarting it kills the
    connection this tool is using, so the restart cannot be observed and the undo
    cannot run. Restart those from the console instead. Pass dry_run=True to
    preview.

    Args:
        service: Service name to restart.
        dry_run: If True, preview without restarting.
        target: Firewall target name from config; omit for the default.
    """
    conn = _get_connection(target)
    if dry_run:
        # Refuse on the preview too: reporting "this would be refused" and then
        # returning success is the preview being wrong.
        ops.guard_restart_service(conn, service)
        return {"dryRun": True, "wouldRestart": {"service": service}}
    return ops.restart_service(conn, service)


@mcp.tool()
@governed_tool(risk_level="high")
@tool_errors("dict")
def reboot(dry_run: bool = False, target: Optional[str] = None) -> dict:
    """[WRITE][risk=high] Reboot the firewall. IRREVERSIBLE — audit only, no undo.

    Pass dry_run=True to preview.

    Args:
        dry_run: If True, preview without rebooting.
        target: Firewall target name from config; omit for the default.
    """
    conn = _get_connection(target)
    if dry_run:
        return {"dryRun": True, "wouldReboot": {"platform": conn.target.platform}}
    return ops.reboot(conn)
