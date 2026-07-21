"""Governance persistence — REAL audit.db / undo.db rows, not mocked stores.

The other governance tests monkeypatch the stores and only verify that undo
descriptors are *constructed*. These tests bind the whole harness to a
throwaway home (``FIREWALL_AIOPS_HOME``) and assert that the rows compliance
evidence is built from actually land on disk — every governed call lands an
audit row, and a reversible write also lands an undo token.
"""

from __future__ import annotations

import json
import sqlite3
from unittest.mock import MagicMock

import pytest

import firewall_aiops.governance.audit as audit_mod
import firewall_aiops.governance.policy as policy_mod
import firewall_aiops.governance.undo as undo_mod
from firewall_aiops.governance import (
    capture_prior_state,
    governed_tool,
    mark_unknown,
)


def _reset_singletons() -> None:
    audit_mod.reset_engine()
    policy_mod.reset_policy_engine()
    undo_mod.reset_undo_store()


@pytest.fixture
def gov_home(tmp_path, monkeypatch):
    """Bind the harness to a throwaway home with no approver annotation set."""
    monkeypatch.setenv("FIREWALL_AIOPS_HOME", str(tmp_path))
    monkeypatch.delenv("FIREWALL_AUDIT_APPROVED_BY", raising=False)
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
def test_high_risk_runs_without_an_approver_and_is_audited(gov_home):
    """The skill no longer authorizes. A high-risk write with no approver
    recorded runs to completion — whether it *should* is the agent's decision
    or the account's permissions — and it is audited either way."""
    result = _drop_widget(name="w2", target="fw1")
    assert result["status"] == "dropped"

    audit = _rows(gov_home / "audit.db", "audit_log")
    assert len(audit) == 1
    assert audit[0]["tool"] == "_drop_widget"
    assert audit[0]["status"] == "ok"
    # risk_tier is still recorded as a descriptive label — it just gates nothing.
    assert audit[0]["risk_tier"] == "review"


@pytest.mark.unit
def test_an_approver_is_still_recorded_when_supplied(gov_home, monkeypatch):
    """approved_by is optional audit context now, not a gate: supplying it does
    nothing but annotate the trail."""
    monkeypatch.setenv("FIREWALL_AUDIT_APPROVED_BY", "netops-alice")
    result = _drop_widget(name="w3", target="fw1")
    assert result["status"] == "dropped"

    audit = _rows(gov_home / "audit.db", "audit_log")
    assert audit[0]["status"] == "ok"
    assert audit[0]["approved_by"] == "netops-alice"


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

# ── Previews ───────────────────────────────────────────────────────────────
#
# A preview is governed like any other call, but it changes nothing. Two things
# must therefore not apply to it, and both were live defects.


@pytest.mark.unit
def test_dry_run_records_no_undo_token(gov_home):
    """A preview's undo callable has no before-state to read, so permissive
    defaults invent one. That produced a real, APPLICABLE inverse for an
    operation that never happened — undo_apply would then perform it."""

    @governed_tool(
        risk_level="medium",
        undo=lambda p, r: {
            "tool": "start_widget",
            # The permissive default that caused the bug, kept deliberately.
            "params": {"running": (r.get("priorState") or {}).get("running", True)},
        },
    )
    def _stop_widget(name: str, dry_run: bool = False, target: str = "") -> dict:
        if dry_run:
            return {"dryRun": True, "wouldStop": name}
        return {"status": "stopped", "priorState": {"running": True}}

    preview = _stop_widget(name="w1", dry_run=True, target="t1")
    assert preview["wouldStop"] == "w1"
    assert "_undo_id" not in preview
    assert not (gov_home / "undo.db").exists() or not _rows(gov_home / "undo.db", "undo_log")

    # The real call still records one — the guard must be scoped to previews.
    _stop_widget(name="w1", dry_run=False, target="t1")
    assert len(_rows(gov_home / "undo.db", "undo_log")) == 1


@pytest.mark.unit
def test_a_high_risk_preview_and_its_write_both_run_and_audit(gov_home):
    """No gate stands between a caller and either the preview or the write. Both
    are audited; the preview records no undo (nothing changed)."""

    @governed_tool(risk_level="high")
    def _drop_thing(name: str, dry_run: bool = False, target: str = "") -> dict:
        if dry_run:
            return {"dryRun": True, "wouldDrop": name}
        return {"status": "dropped"}

    preview = _drop_thing(name="w5", dry_run=True, target="prod-host")
    assert preview["wouldDrop"] == "w5"
    audit = _rows(gov_home / "audit.db", "audit_log")
    assert audit[-1]["status"] == "ok"
    assert audit[-1]["risk_tier"] == "review", "the tier is still recorded, as a label"

    result = _drop_thing(name="w5", dry_run=False, target="prod-host")
    assert result["status"] == "dropped"
    assert _rows(gov_home / "audit.db", "audit_log")[-1]["status"] == "ok"


# ── Undetermined outcomes ──────────────────────────────────────────────────
#
# A write that loses its response is NOT a failed write: the request may have
# landed. Auditing it as 'error' asserts a failure the tool cannot vouch for,
# and it did so precisely for the writes that can sever their own connection
# (stop the container proxying the API, disable the rule permitting access).


@pytest.mark.unit
def test_undetermined_outcome_is_audited_unknown_not_error(gov_home):
    @governed_tool(risk_level="medium")
    def _lost_response(target: str = "") -> dict:
        return mark_unknown({"error": "ReadTimeout: operation failed."})

    result = _lost_response(target="t1")
    assert result["outcomeUnknown"] is True

    audit = _rows(gov_home / "audit.db", "audit_log")
    assert audit[-1]["status"] == "unknown", (
        "a lost response must not be recorded as a definite failure"
    )


@pytest.mark.unit
def test_undetermined_outcome_records_unverified_undo_from_captured_prior_state(gov_home):
    """The change is probably live, so the inverse must still be recorded —
    flagged, because nobody may be told the effect was confirmed."""

    @governed_tool(
        risk_level="medium",
        undo=lambda p, r: {
            "tool": "start_widget",
            "params": {"name": p["name"], "prior": r["priorState"]["running"]},
        },
    )
    def _stop_widget(name: str, target: str = "") -> dict:
        capture_prior_state({"running": True})  # before issuing the mutation
        return mark_unknown({"error": "ReadTimeout: operation failed."})

    result = _stop_widget(name="w9", target="t1")

    undo = _rows(gov_home / "undo.db", "undo_log")
    assert len(undo) == 1, "an unconfirmed change is exactly when a rollback is wanted"
    assert undo[0]["undo_tool"] == "start_widget"
    assert json.loads(undo[0]["undo_params"]) == {"name": "w9", "prior": True}
    assert undo[0]["effect_verified"] == 0
    assert undo[0]["status"] == "recorded", "must stay listable and appliable"
    assert result["_undo_id"] == undo[0]["undo_id"]


@pytest.mark.unit
def test_undetermined_outcome_without_captured_prior_state_records_nothing(gov_home):
    """Fabricating a descriptor from an empty error payload would produce a
    WRONG inverse — worse than none. Opt-in capture is the whole point."""

    @governed_tool(
        risk_level="medium",
        undo=lambda p, r: {"tool": "start_widget", "params": {"name": p["name"]}},
    )
    def _stop_widget_uncaptured(name: str, target: str = "") -> dict:
        return mark_unknown({"error": "ReadTimeout: operation failed."})

    _stop_widget_uncaptured(name="w9", target="t1")

    assert not (gov_home / "undo.db").exists() or not _rows(gov_home / "undo.db", "undo_log")
    assert _rows(gov_home / "audit.db", "audit_log")[-1]["status"] == "unknown"


@pytest.mark.unit
def test_confirmed_write_records_verified_undo(gov_home):
    """The ordinary path keeps effect_verified=1 — the flag must distinguish,
    not merely exist."""
    _rename_widget(name="w1", target="prod-host")
    assert _rows(gov_home / "undo.db", "undo_log")[0]["effect_verified"] == 1


@pytest.mark.unit
def test_captured_prior_state_does_not_leak_into_the_next_call(gov_home):
    """One call's before-state recorded as another's would be a fabricated
    rollback target — the failure mode this whole mechanism exists to prevent."""

    @governed_tool(risk_level="medium")
    def _captures_then_succeeds(target: str = "") -> dict:
        capture_prior_state({"running": True})
        return {"status": "ok"}

    @governed_tool(
        risk_level="medium",
        undo=lambda p, r: {"tool": "start_widget", "params": {"prior": r["priorState"]}},
    )
    def _later_lost_response(target: str = "") -> dict:
        return mark_unknown({"error": "ReadTimeout: operation failed."})

    _captures_then_succeeds(target="t1")
    _later_lost_response(target="t1")

    assert not (gov_home / "undo.db").exists() or not _rows(gov_home / "undo.db", "undo_log")


@pytest.mark.unit
def test_undo_db_predating_effect_verified_is_migrated_in_place(gov_home, monkeypatch):
    """Existing installs have an undo.db without the column. It must gain one,
    and its existing rows must read as verified — which is accurate, since the
    old code only ever recorded on the confirmed path."""
    db = gov_home / "undo.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE undo_log (undo_id TEXT PRIMARY KEY, ts TEXT NOT NULL, "
        "skill TEXT NOT NULL DEFAULT '', tool TEXT NOT NULL DEFAULT '', "
        "undo_skill TEXT NOT NULL DEFAULT '', undo_tool TEXT NOT NULL DEFAULT '', "
        "undo_params TEXT NOT NULL DEFAULT '{}', orig_params TEXT NOT NULL DEFAULT '{}', "
        "status TEXT NOT NULL DEFAULT 'recorded', workflow_id TEXT NOT NULL DEFAULT '', "
        "note TEXT NOT NULL DEFAULT '')"
    )
    conn.execute(
        "INSERT INTO undo_log (undo_id, ts, tool, undo_tool) VALUES ('old1', 'x', 't', 'u')"
    )
    conn.commit()
    conn.close()

    undo_mod.reset_undo_store()
    store = undo_mod.get_undo_store(db)
    assert store.get("old1")["effect_verified"] == 1

    store.record(skill="s", tool="t", undo_descriptor={"tool": "u"}, effect_verified=False)
    fresh = [r for r in store.list() if r["undo_id"] != "old1"]
    assert fresh[0]["effect_verified"] == 0
