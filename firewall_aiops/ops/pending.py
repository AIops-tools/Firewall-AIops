"""What would ``apply_changes`` actually commit?

``apply_changes`` used to be a blind commit: its dry-run said only
``{"wouldApply": {"platform": ...}}`` and nothing in the package could read the
staged change set at all. That is the worst possible shape for the one call that
turns edits into live firewall behaviour — it commits whatever is staged,
including edits staged outside this tool by someone in the web GUI.

Both platforms serve the *staged* rule set from their rules API (that is exactly
why ``toggle_rule`` reports "Staged — run apply_changes to make it live"), so
the change set is readable: it is the rule set as it will behave after the
commit. This module surfaces it and, more importantly, runs it through
:mod:`firewall_aiops.ops.lockout` so both the dry-run and the commit guard see
the same assessment.

What this does NOT claim: neither platform exposes a per-rule "dirty" flag over
its REST API, so this is the staged *state*, not a diff against the running
config. ``basis`` says so in the payload rather than letting a caller assume a
diff. Anything uncertain is reported as a named warning and never blocks.
"""

from __future__ import annotations

from typing import Any

from firewall_aiops.ops import lockout
from firewall_aiops.ops import rules as rule_ops
from firewall_aiops.ops._util import s

_BASIS = (
    "Staged rule state as the platform reports it, not a diff against the "
    "running config — neither OPNsense nor pfSense exposes a per-rule dirty "
    "flag over REST. Rules already live appear here too."
)


def pending_changes(conn: Any) -> dict:
    """[READ] The staged rule set apply_changes would commit, with lockout risk.

    Returns the management-plane assessment alongside the counts, so an operator
    (or ``apply_changes``' own guard) can see whether committing would cut the
    path this tool reaches the firewall over.
    """
    target = conn.target
    listing = rule_ops.list_rules(conn)
    if isinstance(listing, dict) and listing.get("error"):
        # A probe failure is NOT "nothing pending" — saying so would let the
        # guard wave through exactly the commit it exists to catch.
        return {
            "platform": s(target.platform, 32),
            "basis": _BASIS,
            "error": listing["error"],
            "note": (
                "Could not read the staged rule set, so the lockout assessment is "
                "UNKNOWN — not clean. Check connectivity ('firewall-aiops doctor') "
                "before applying."
            ),
        }
    staged = listing.get("rules", []) if isinstance(listing, dict) else []
    assessment = lockout.assess_rules(staged, str(target.host), int(target.port))
    return {
        "platform": s(target.platform, 32),
        "basis": _BASIS,
        "stagedRuleCount": len(staged),
        **assessment,
    }
