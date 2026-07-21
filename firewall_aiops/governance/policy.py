"""Risk-tier tagging for the audit trail — NOT authorization.

Whether a read or a write is permitted is deliberately not the skill's decision.
That belongs to the agent's judgement, or to the permissions of the account the
tool connects with — give it a read-only role and writes fail at the server, the
place that actually owns the permission. The skill's job is to run the operation
accurately and record it, both over MCP and over the CLI; it does not police.

An earlier design put a whole authorization layer here — read-only mode, YAML
deny rules, a secure-by-default approver gate. All of that is gone: it duplicated
a decision the agent and the account already own, and every gate was one more way
for a correct operation to be refused.

What remains is a stateless classifier that maps a tool's declared ``risk_level``
to a tier name carried into the audit log, so a reviewer can see at a glance that
a row was, say, a high-risk delete. It gates nothing.
"""

from __future__ import annotations

import threading

RISK_LEVELS = ("low", "medium", "high", "critical")

# risk_level → audit tier. Purely descriptive: no tier blocks anything, it only
# labels the audit row. 'confirm' echoes that the CLI double-confirms a medium
# write; 'review' marks the destructive operations a human is most likely to
# want to see in the trail.
_TIER_BY_RISK = {
    "low": "none",
    "medium": "confirm",
    "high": "review",
    "critical": "review",
}


class PolicyEngine:
    """Stateless risk-tier classifier.

    Kept as a lock-guarded singleton so the ``reset_policy_engine()`` hook the
    test fixtures call stays valid, but it holds no rules and denies nothing.
    """

    def tier_for(self, risk_level: str) -> str:
        """Return the audit tier name for a declared risk level."""
        return _TIER_BY_RISK.get(risk_level, "none")


_engine: PolicyEngine | None = None
_engine_lock = threading.Lock()


def get_policy_engine() -> PolicyEngine:
    """Return the global PolicyEngine singleton (lazy, lock-guarded)."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = PolicyEngine()
    return _engine


def reset_policy_engine() -> None:
    """Reset the singleton. Tests use this between cases."""
    global _engine
    with _engine_lock:
        _engine = None
