"""Test isolation: redirect the governance harness state at a tmp dir.

Governed-tool calls write an audit row (and, for reversible writes, an undo
token). This autouse fixture points ``FIREWALL_AIOPS_HOME`` at a throwaway
directory and resets the harness singletons so nothing touches the real
``~/.firewall-aiops`` during tests.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolate_harness_home(tmp_path_factory, monkeypatch):
    home = tmp_path_factory.mktemp("fw-home")
    monkeypatch.setenv("FIREWALL_AIOPS_HOME", str(home))

    import firewall_aiops.governance.audit as audit
    import firewall_aiops.governance.undo as undo

    monkeypatch.setattr(audit, "_engine", None, raising=False)
    monkeypatch.setattr(audit, "_DEFAULT_DB", None, raising=False)
    monkeypatch.setattr(undo, "_store", None, raising=False)
    yield


@pytest.fixture(autouse=True)
def _default_approver(monkeypatch):
    """FIREWALL_AUDIT_APPROVED_BY is an optional audit annotation now, not a
    gate — nothing requires it and it blocks nothing. Setting it globally just
    means the audit rows tests inspect carry a stable approved_by value; the
    governance-persistence tests clear it where they check the unset case."""
    monkeypatch.setenv("FIREWALL_AUDIT_APPROVED_BY", "pytest")
