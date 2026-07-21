"""Governed firewall writes — the only state-changing operations in the tool.

Every reversible write reads the firewall's current state **before** it changes
anything, so the harness records a faithful undo / audit trail (the before-state
is fetched via a real GET, never guessed):

  * ``toggle_rule`` — reads the rule's current ``enabled`` flag, then flips it;
    undo toggles it back.
  * ``add_alias_entry`` / ``remove_alias_entry`` — read the alias' current member
    entries, then add/remove one; undo restores.

The "make it live" writes commit staged config and are the high-risk tier:
``apply_changes`` and ``reconfigure``. ``kill_states`` and ``restart_service``
are medium; ``reboot`` is high and irreversible (audit only). The risk tier is a
descriptive label carried into the audit row, not a gate.

Three writes additionally refuse to destroy the tool's own management path
(:class:`SelfLockout`), because a firewall is the one device where a routine
edit can sever the connection carrying it — and the recorded undo needs that
same connection to run:

  * ``restart_service`` — restarting the service that answers this platform's
    own API (``nginx`` / ``lighttpd`` / ``configd``, and the aliases an agent
    told "restart the web service" would actually pass) kills the request
    in-flight and every request after it.
  * ``apply_changes`` / ``reconfigure`` — committing a staged rule set that
    disables the ``pass`` rule permitting management access, or enables a
    ``block`` rule covering it, locks the tool out the instant it lands.

The rule guards are **exact and fail open**: only a literal match on both the
management host and port refuses; aliases, ``any`` and interface groups produce
a named warning and proceed (see :mod:`firewall_aiops.ops.lockout`).
``toggle_rule`` runs the same assessment at staging time, where warning is
cheapest, and reports it without blocking.

Each function returns a plain descriptor; the MCP layer adds dry-run + the
governance harness (risk tier + audit + undo).
"""

from __future__ import annotations

from typing import Any

from firewall_aiops.governance import capture_prior_state
from firewall_aiops.ops import aliases as alias_ops
from firewall_aiops.ops import lockout
from firewall_aiops.ops import pending as pending_ops
from firewall_aiops.ops import rules as rule_ops
from firewall_aiops.ops._util import s
from firewall_aiops.platform import OPNSENSE

# kill_states flushes the pf state table, which includes the state entry for the
# connection this tool is issuing the flush over. That is NOT a lockout — the
# permitting rule survives, states re-establish on the next packet, and the next
# call reconnects — but the POST response can be lost in the flush, so the call
# may look like it failed when it actually ran.
KILL_STATES_SESSION_NOTE = (
    "This flushes the pf state table, including the state entry for THIS tool's own "
    "connection. The call may appear to fail (lost response) even though the flush "
    "ran — do not retry blindly. Access is not lost: the permitting rule is "
    "untouched and the next call re-establishes state."
)


class SelfLockout(ValueError):  # noqa: N818 — teaching error, reads as a statement
    """Refused: the operation would cut the path this tool manages the firewall over."""


def _is_opnsense(conn: Any) -> bool:
    return conn.target.platform == OPNSENSE


# ── rule enable/disable (reversible) ─────────────────────────────────────────


def assess_toggle(conn: Any, uuid: str, enable: bool) -> dict | None:
    """Management-plane impact of the state a toggle WOULD stage. Read-only.

    Shared by ``toggle_rule`` and its dry-run so the preview reports exactly what
    the real call would report. Reading is what makes the preview able to answer
    at all — a dry_run may read; it must never write.
    """
    return _staging_warning(conn, rule_ops.rule_detail(conn, uuid), enable)


def _staging_warning(conn: Any, rule: dict, enable: bool) -> dict | None:
    """Assess the state a toggle would STAGE for management-plane impact.

    Warning here is the cheapest point in the workflow: the rule row is already
    in hand, and the operator learns about the risk while the change is still
    only staged. Never blocks — ``apply_changes`` is where the refusal lives.
    """
    if not isinstance(rule, dict) or "error" in rule:
        return None
    target = conn.target
    staged = {**rule, "enabled": bool(enable)}
    finding = lockout.assess_rule(staged, str(target.host), int(target.port))
    if finding is None:
        return None
    return {
        **finding,
        "note": (
            "Staged only — nothing is live yet. Re-check with pending_changes "
            "before apply_changes, and make sure you have console access."
        ),
    }


def toggle_rule(conn: Any, uuid: str, enable: bool) -> dict:
    """[WRITE][med] Enable/disable a filter rule, capturing its prior state.

    Reads the rule first so ``priorState.enabled`` reflects what it *was* before
    the flip (drives a faithful undo). Does not apply — a separate
    ``apply_changes`` commits staged rule config on both platforms.

    Reports ``managementImpact`` when the state being staged would affect the
    endpoint this tool reaches the firewall through — in BOTH directions:
    disabling a ``pass`` rule that permits management access, or enabling a
    ``block`` rule that covers it. Advisory only at this stage.
    """
    prior = rule_ops.rule_detail(conn, uuid)
    was_enabled = bool(prior.get("enabled", True)) if "error" not in prior else None
    warning = _staging_warning(conn, prior, enable)
    # Stash the before-state BEFORE the mutating request: if the response is
    # lost the toggle may still have landed, and this is the only thing that
    # lets the harness record the inverse anyway (flagged effect_verified=False).
    capture_prior_state({"enabled": was_enabled})
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
        "managementImpact": warning,
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
    capture_prior_state({"entries": prior})
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
    capture_prior_state({"entries": prior})
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


def guard_apply(conn: Any, action: str, override: bool) -> dict:
    """Refuse a commit that would provably cut this tool's own management path.

    Fails OPEN everywhere it is not certain: a staged rule whose destination is
    an alias, ``any`` or an interface group produces a warning and proceeds, and
    a rule set that cannot be read at all does NOT block (the assessment says so
    explicitly rather than reporting a clean bill of health).
    """
    assessment = pending_ops.pending_changes(conn)
    if assessment.get("error"):
        return assessment
    if assessment.get("blocking") and not override:
        target = conn.target
        worst = next(f for f in assessment["findings"] if f["certain"])
        raise SelfLockout(
            f"Refusing to {action}: a staged rule would cut this tool's own management "
            f"path. Rule '{worst.get('uuid')}' is {worst.get('action')} / "
            f"enabled={worst.get('enabled')} for {worst.get('destination')}:"
            f"{worst.get('destinationPort')}, which matches the endpoint this tool "
            f"reaches the firewall through ({target.host}:{target.port}). Applying it "
            f"would make every later call — including the undo that reverses it — fail "
            f"to connect. Fix the rule with toggle_rule, or, if you have console / "
            f"out-of-band access and mean to do this, re-run with override=True. Use "
            f"pending_changes to see the full staged set first."
        )
    return assessment


def apply_changes(conn: Any, override: bool = False) -> dict:
    """[WRITE][high] Commit staged firewall (filter) config — makes edits live.

    Reads the staged rule set first and refuses when committing it would
    provably sever this tool's own management path (see
    :mod:`firewall_aiops.ops.lockout`). ``override=True`` proceeds anyway — for
    operators who have console access and mean it.
    """
    assessment = guard_apply(conn, "apply staged firewall config", override)
    conn.post(conn.platform.path("apply"))
    return {
        "action": "apply_changes",
        "platform": conn.target.platform,
        "applied": True,
        "override": bool(override),
        "managementImpact": _impact_summary(assessment),
    }


def reconfigure(conn: Any, subsystem: str = "filter", override: bool = False) -> dict:
    """[WRITE][high] Reload/commit a subsystem's config (filter/nat/aliases).

    Carries the same lockout guard as ``apply_changes`` for the ``filter``
    subsystem — reloading the filter commits the staged rule set just as surely.
    """
    assessment = (
        guard_apply(conn, f"reconfigure the {s(subsystem, 32)} subsystem", override)
        if s(subsystem, 32).lower() == "filter"
        else {}
    )
    conn.post(conn.platform.path("reconfigure"), json={"subsystem": s(subsystem, 32)})
    return {
        "action": "reconfigure",
        "platform": conn.target.platform,
        "subsystem": s(subsystem, 32),
        "override": bool(override),
        "managementImpact": _impact_summary(assessment),
    }


def _impact_summary(assessment: dict) -> dict | None:
    """Condense a lockout assessment for a write result (None when clean)."""
    if not assessment:
        return None
    if assessment.get("error"):
        return {"assessed": False, "error": assessment["error"]}
    findings = assessment.get("findings") or []
    if not findings:
        return None
    return {
        "assessed": True,
        "certainCount": assessment.get("certainCount", 0),
        "uncertainCount": assessment.get("uncertainCount", 0),
        "findings": findings,
    }


# ── operational writes ───────────────────────────────────────────────────────


def kill_states(conn: Any, filter_ip: str = "") -> dict:
    """[WRITE][med] Flush pf state-table entries (optionally for one source IP).

    Drops this tool's own connection state along with everything else, so the
    response to this very call can be lost. That is a lost response, not a
    lockout — see :data:`KILL_STATES_SESSION_NOTE`.
    """
    payload = {"filter": s(filter_ip, 64)} if filter_ip else {}
    path = conn.platform.path("kill_states")
    if _is_opnsense(conn):
        conn.post(path, json=payload)
    else:
        conn.delete(path, json=payload or None)
    return {
        "action": "kill_states",
        "filter": s(filter_ip, 64) or "all",
        "note": KILL_STATES_SESSION_NOTE,
    }


def restart_service(conn: Any, service: str) -> dict:
    """[WRITE][med] Restart a firewall service (e.g. unbound, dhcpd, openvpn).

    Refuses the service that answers this platform's own management API. An
    agent told "restart the web service" will happily pass ``nginx``,
    ``lighttpd`` or ``webgui`` — all legal arguments that kill the request
    in-flight and every call after it, undo included. The platform descriptor
    owns that list (:attr:`~firewall_aiops.platform.Platform.api_services`)
    because it already knows which daemon serves its own URLs. Matching is
    exact: an unrecognised service name is never blocked on a guess.
    """
    guard_restart_service(conn, service)
    conn.post(conn.platform.path("service_restart", service=s(service, 32)))
    return {"action": "restart_service", "service": s(service, 32)}


def guard_restart_service(conn: Any, service: str) -> None:
    """Refuse a restart of the daemon serving this appliance's own API.

    Shared by the real call and its dry-run so a preview can never report
    success for something the write would refuse.
    """
    platform = conn.platform
    if platform.serves_own_api(service):
        raise SelfLockout(
            f"Refusing to restart '{service}': that service answers this "
            f"{platform.label} appliance's own management API, which is how this tool "
            f"is talking to it right now. Restarting it drops the request in flight and "
            f"every call after it — including the undo — until the daemon comes back, "
            f"and it may not come back cleanly. Restart it from the console or the web "
            f"GUI instead. Services that are safe here are the ones the firewall "
            f"*serves* rather than the one it answers on: unbound, dhcpd, openvpn, "
            f"ipsec, and so on."
        )


def reboot(conn: Any) -> dict:
    """[WRITE][high] Reboot the firewall. IRREVERSIBLE — audit only, no undo."""
    conn.post(conn.platform.path("reboot"))
    return {"action": "reboot", "platform": conn.target.platform, "rebooting": True}
