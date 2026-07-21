"""Governance harness for firewall-aiops — audit, policy, budget, undo, sanitize.

A self-contained, vendored governance layer. firewall-aiops has NO dependency on
any external skill family — this package is its own copy of the harness:

  - ``@governed_tool`` — mandatory decorator on every MCP tool: policy pre-check,
    token/runaway budget guard, graduated-autonomy risk-tier gate, audit logging,
    and undo-token recording.
  - unified SQLite audit log under ``~/.firewall-aiops/`` (override with
    ``FIREWALL_AIOPS_HOME``).
  - ``sanitize`` — output hygiene (encoding-level defense) for API-returned text.

State lives under ``ops_home()`` (default ``~/.firewall-aiops``).
"""

from firewall_aiops.governance.audit import AuditEngine, get_engine
from firewall_aiops.governance.budget import BudgetExceeded, BudgetTracker, get_budget
from firewall_aiops.governance.decorators import PolicyDenied, governed_tool
from firewall_aiops.governance.outcome import (
    UNKNOWN_FIELD,
    capture_prior_state,
    is_unknown,
    mark_unknown,
)
from firewall_aiops.governance.patterns import Pattern, PatternMatch, get_pattern_engine
from firewall_aiops.governance.policy import get_policy_engine
from firewall_aiops.governance.sanitize import opt_str, sanitize
from firewall_aiops.governance.undo import UndoStore, get_undo_store

__all__ = [
    "governed_tool",
    "sanitize",
    "opt_str",
    "capture_prior_state",
    "mark_unknown",
    "is_unknown",
    "UNKNOWN_FIELD",
    "PolicyDenied",
    "get_engine",
    "AuditEngine",
    "get_policy_engine",
    "get_budget",
    "BudgetTracker",
    "BudgetExceeded",
    "get_undo_store",
    "UndoStore",
    "Pattern",
    "PatternMatch",
    "get_pattern_engine",
]
