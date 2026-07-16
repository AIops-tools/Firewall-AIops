"""Governance persistence — REAL audit.db / undo.db rows, not mocked stores.

The other governance tests monkeypatch the stores and only verify that undo
descriptors are *constructed*. These tests bind the whole harness to a
throwaway home (``FIREWALL_AIOPS_HOME``) and assert that the rows compliance
evidence is built from actually land on disk, and that the secure-by-default
approver gate (no rules.yaml → high/critical needs an approver) enforces.
"""

from __future__ import annotations

import json
import sqlite3
from unittest.mock import MagicMock

import pytest

import firewall_aiops.governance.audit as audit_mod
import firewall_aiops.governance.policy as policy_mod
import firewall_aiops.governance.undo as undo_mod
from firewall_aiops.governance import PolicyDenied, governed_tool


def _reset_singletons() -> None:
    audit_mod.reset_engine()
    policy_mod.reset_policy_engine()
    undo_mod.reset_undo_store()


@pytest.fixture
def gov_home(tmp_path, monkeypatch):
    """Bind the harness to a temp home with NO approver and NO rules file."""
    monkeypatch.setenv("FIREWALL_AIOPS_HOME", str(tmp_path))
    monkeypatch.delenv("FIREWALL_AUDIT_APPROVED_BY", raising=False)
    monkeypatch.delenv("FIREWALL_POLICY_DISABLED", raising=False)
    _reset_singletons()
    yield tmp_path
    _reset_singletons()


def _rows(db_path, table: str) -> list[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(f"SELECT * FROM {table}")]  # noqa: S608
    finally:
        conn.close()


# Synthetic governed tools — they exercise the harness itself, so the tests
# stay valid even as the product tool surface evolves.
@governed_tool(
    risk_level="medium",
    undo=lambda p, r: {
        "tool": "restore_widget",
        "params": {"name": p["name"], "prior": r["priorState"]},
    },
)
def _rename_widget(name: str, target: str = "") -> dict:
    return {"status": "renamed", "priorState": f"old-{name}"}


@governed_tool(risk_level="high")
def _drop_widget(name: str, target: str = "") -> dict:
    return {"status": "dropped"}


@pytest.mark.unit
def test_medium_write_persists_audit_and_undo_rows(gov_home):
    result = _rename_widget(name="w1", target="fw1")
    assert result["status"] == "renamed"
    assert result.get("_undo_id"), "successful write must carry an _undo_id"

    audit = _rows(gov_home / "audit.db", "audit_log")
    assert len(audit) == 1
    row = audit[0]
    assert row["tool"] == "_rename_widget"
    assert row["status"] == "ok"
    assert row["risk_level"] == "medium"
    assert json.loads(row["params"])["name"] == "w1"

    undo = _rows(gov_home / "undo.db", "undo_log")
    assert len(undo) == 1
    assert undo[0]["undo_id"] == result["_undo_id"]
    assert undo[0]["undo_tool"] == "restore_widget"
    assert json.loads(undo[0]["undo_params"]) == {"name": "w1", "prior": "old-w1"}
    assert undo[0]["status"] == "recorded"


@pytest.mark.unit
def test_high_risk_denied_without_approver_and_denial_is_audited(gov_home):
    """Secure by default: no rules.yaml + no approver → high risk is denied,
    and the denial itself must land in the audit log."""
    with pytest.raises(PolicyDenied, match="requires 'dual' approval"):
        _drop_widget(name="w2", target="fw1")

    audit = _rows(gov_home / "audit.db", "audit_log")
    assert len(audit) == 1
    assert audit[0]["tool"] == "_drop_widget"
    assert audit[0]["status"] == "denied"
    assert audit[0]["risk_tier"] == "dual"

    assert not (gov_home / "undo.db").exists() or not _rows(gov_home / "undo.db", "undo_log")


@pytest.mark.unit
def test_high_risk_allowed_with_named_approver(gov_home, monkeypatch):
    monkeypatch.setenv("FIREWALL_AUDIT_APPROVED_BY", "netops-alice")
    result = _drop_widget(name="w3", target="fw1")
    assert result["status"] == "dropped"

    audit = _rows(gov_home / "audit.db", "audit_log")
    assert len(audit) == 1
    assert audit[0]["status"] == "ok"
    assert audit[0]["approved_by"] == "netops-alice"


@pytest.mark.unit
def test_operator_rules_file_restores_tier_none_for_high_risk(gov_home):
    """An operator-authored rules.yaml (without risk_tiers) is an explicit
    choice: the default dual gate must stand down."""
    (gov_home / "rules.yaml").write_text("deny: []\n", "utf-8")
    _reset_singletons()
    result = _drop_widget(name="w4", target="fw1")
    assert result["status"] == "dropped"


@pytest.mark.unit
def test_real_write_tool_persists_priorstate_undo(gov_home, monkeypatch):
    """End-to-end through a REAL product write tool: toggle_rule must capture
    the rule's prior enabled state before flipping and persist the
    restore-undo on disk."""
    from firewall_aiops.ops import rules as rule_ops
    from firewall_aiops.platform import OPNSENSE, get_platform
    from mcp_server.tools import writes as gov

    conn = MagicMock(name="conn")
    conn.target.platform = OPNSENSE
    conn.platform = get_platform(OPNSENSE)
    monkeypatch.setattr(rule_ops, "rule_detail", lambda c, u: {"uuid": u, "enabled": True})
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)

    result = gov.toggle_rule(uuid="r1", enable=False)
    assert result["priorState"] == {"enabled": True}
    assert result.get("_undo_id")

    undo = _rows(gov_home / "undo.db", "undo_log")
    assert len(undo) == 1
    assert undo[0]["undo_tool"] == "toggle_rule"
    assert json.loads(undo[0]["undo_params"]) == {"uuid": "r1", "enable": True}

    audit = _rows(gov_home / "audit.db", "audit_log")
    assert [r["tool"] for r in audit] == ["toggle_rule"]
    assert audit[0]["risk_level"] == "medium"

@pytest.mark.unit
def test_sanitized_error_result_is_audited_as_error_and_records_no_undo(gov_home):
    """@tool_errors converts exceptions to {"error": ...} dicts before the harness
    sees them — those must land in the audit log as status=error (not ok), and no
    undo may be recorded for a call that changed nothing."""

    @governed_tool(
        risk_level="low",
        undo=lambda p, r: {"tool": "never_recorded", "params": {}},
    )
    def _broken_widget(target: str = "") -> dict:
        return {"error": "boom (sanitized upstream)"}

    result = _broken_widget(target="t1")
    assert result["error"]
    assert "_undo_id" not in result

    audit = _rows(gov_home / "audit.db", "audit_log")
    assert audit[-1]["tool"] == "_broken_widget"
    assert audit[-1]["status"] == "error"
    assert not (gov_home / "undo.db").exists() or not _rows(gov_home / "undo.db", "undo_log")
