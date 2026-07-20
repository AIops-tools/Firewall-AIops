"""Does this staged rule change cut the path this tool manages the firewall over?

``apply_changes`` is the moment a staged edit becomes real, and a firewall is
the one device where a rule change can sever the connection carrying it. The
tool knows its own endpoint — ``TargetConfig.host`` / ``.port`` build the
``base_url`` every request goes to — which is this repo's analogue of
identity-aiops' ``self_user_id()``: the identity an operation must refuse to
destroy.

Two staged states are dangerous, and they are mirror images:

  * a **disabled** ``pass`` rule that permits management access — the permit
    disappears on apply;
  * an **enabled** ``block`` rule that covers management access — the block
    starts matching on apply.

Everything here is a pure function over already-normalised rule rows
(:func:`firewall_aiops.ops.rules._norm_rule`), so it is cheap enough to run at
staging time (``toggle_rule``) as well as at commit time (``apply_changes``).

**Certainty is tracked explicitly and uncertainty FAILS OPEN.** A rule whose
destination is an alias, ``any``, or an interface group *might* cover the
management endpoint, but "might" must never block a legitimate change — those
surface as a named warning (``ALIAS_DESTINATION``, ``ANY_DESTINATION``,
``ANY_PORT``, ...) and the operation proceeds. Only a literal match on both host
and port is treated as certain enough to refuse. Guessing in the other direction
would make the firewall's own rule engine unmanageable through this tool.
"""

from __future__ import annotations

from typing import Any

# Rule actions, normalised across OPNsense / pfSense vocabularies.
_PASS_ACTIONS = {"pass", "allow", "accept", "permit"}
_BLOCK_ACTIONS = {"block", "reject", "deny", "drop"}

# Destination/port tokens that mean "everything" — a match we cannot rule out,
# but also cannot confirm.
_WILDCARDS = {"", "any", "*", "all", "0.0.0.0/0", "::/0"}

# Named reasons a verdict is uncertain. Stable strings: they travel in results
# and an operator (or a playbook) keys off them.
ALIAS_DESTINATION = "ALIAS_DESTINATION"
ANY_DESTINATION = "ANY_DESTINATION"
ANY_PORT = "ANY_PORT"
PORT_RANGE = "PORT_RANGE"
INTERFACE_GROUP = "INTERFACE_GROUP"

_MATCH_YES = "yes"
_MATCH_MAYBE = "maybe"
_MATCH_NO = "no"


def _norm(value: Any) -> str:
    return str(value).strip().lower() if value is not None else ""


def _looks_like_address(token: str) -> bool:
    """Whether ``token`` is a literal address/CIDR rather than an alias name."""
    if not token:
        return False
    head = token.split("/", 1)[0]
    if ":" in head:  # IPv6 literal
        return all(c in "0123456789abcdef:" for c in head)
    parts = head.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _match_host(destination: Any, host: str) -> tuple[str, str]:
    """Compare a rule destination against the management host.

    Returns ``(verdict, reason)`` where verdict is yes/maybe/no.
    """
    dest = _norm(destination)
    if dest in _WILDCARDS:
        return _MATCH_MAYBE, ANY_DESTINATION
    if not _looks_like_address(dest):
        # An alias (or an interface-group keyword like "lan net"): it may well
        # resolve to the management address, but we cannot see through it here.
        return _MATCH_MAYBE, ALIAS_DESTINATION
    if dest == _norm(host):
        return _MATCH_YES, ""
    if "/" in dest:
        # A literal CIDR that is not an exact match still might contain the
        # host; subnet math is not worth guessing wrong in either direction.
        return _MATCH_MAYBE, ANY_DESTINATION
    return _MATCH_NO, ""


def _match_port(destination_port: Any, port: int) -> tuple[str, str]:
    """Compare a rule destination port against the management port."""
    raw = _norm(destination_port)
    if raw in _WILDCARDS:
        return _MATCH_MAYBE, ANY_PORT
    if raw.isdigit():
        return (_MATCH_YES, "") if int(raw) == int(port) else (_MATCH_NO, "")
    if "-" in raw or ":" in raw:
        lo, _, hi = raw.replace(":", "-").partition("-")
        if lo.isdigit() and hi.isdigit() and int(lo) <= int(port) <= int(hi):
            return _MATCH_YES, ""
        if lo.isdigit() and hi.isdigit():
            return _MATCH_NO, ""
        return _MATCH_MAYBE, PORT_RANGE
    return _MATCH_MAYBE, PORT_RANGE


def _covers_management(rule: dict, host: str, port: int) -> tuple[str, list[str]]:
    """Whether ``rule`` covers the management endpoint. Uncertainty fails open."""
    host_verdict, host_reason = _match_host(rule.get("destination"), host)
    port_verdict, port_reason = _match_port(rule.get("destinationPort"), port)
    reasons = [r for r in (host_reason, port_reason) if r]
    if _norm(rule.get("interface")) in {"", "any"}:
        reasons.append(INTERFACE_GROUP)
    if _MATCH_NO in (host_verdict, port_verdict):
        return _MATCH_NO, []
    if host_verdict == _MATCH_YES and port_verdict == _MATCH_YES:
        return _MATCH_YES, reasons
    return _MATCH_MAYBE, reasons


def assess_rule(rule: dict, host: str, port: int) -> dict | None:
    """Assess ONE staged rule for management-plane impact.

    Returns ``None`` when the rule is harmless. Otherwise a finding with an
    explicit ``certain`` flag — callers refuse on ``certain`` and warn on the
    rest.
    """
    action = _norm(rule.get("action"))
    enabled = bool(rule.get("enabled"))
    if action in _PASS_ACTIONS and not enabled:
        direction = "a disabled 'pass' rule — applying removes this permit"
    elif action in _BLOCK_ACTIONS and enabled:
        direction = "an enabled 'block' rule — applying starts blocking this traffic"
    else:
        return None

    verdict, reasons = _covers_management(rule, host, port)
    if verdict == _MATCH_NO:
        return None
    return {
        "uuid": rule.get("uuid"),
        "action": rule.get("action"),
        "enabled": enabled,
        "interface": rule.get("interface"),
        "destination": rule.get("destination"),
        "destinationPort": rule.get("destinationPort"),
        "description": rule.get("description"),
        "certain": verdict == _MATCH_YES,
        "severity": "high" if verdict == _MATCH_YES else "medium",
        "finding": (
            f"This is {direction}, and its destination "
            f"{'matches' if verdict == _MATCH_YES else 'may match'} the endpoint "
            f"this tool manages the firewall through ({host}:{port})."
        ),
        "warnings": reasons,
        "cause": (
            "The staged rule set changes whether the management address/port is "
            "reachable. Committing it can cut this tool's own connection — and the "
            "recorded undo needs that same connection to run."
        ),
        "action_hint": (
            "Confirm you have console or out-of-band access before applying, or "
            "narrow the rule so it does not cover the management endpoint."
        ),
    }


def assess_rules(rules: list[dict], host: str, port: int) -> dict:
    """Assess a staged rule set. Findings are ranked worst-first.

    ``blocking`` is true only when at least one finding is *certain* — that is
    the fail-open line: 'might match' produces warnings, never a refusal.
    """
    findings = [
        f for f in (assess_rule(r, host, port) for r in rules if isinstance(r, dict))
        if f is not None
    ]
    findings.sort(key=lambda f: (not f["certain"], str(f.get("uuid") or "")))
    for index, finding in enumerate(findings, start=1):
        finding["rank"] = index
    certain = [f for f in findings if f["certain"]]
    return {
        "managementEndpoint": {"host": host, "port": port},
        "findings": findings,
        "certainCount": len(certain),
        "uncertainCount": len(findings) - len(certain),
        "blocking": bool(certain),
    }
