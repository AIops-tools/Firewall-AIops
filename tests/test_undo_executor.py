"""Undo EXECUTOR — undo_apply dispatches a recorded inverse through its governed
tool, on a real undo.db in an isolated home. Closes the loop from "undo recorded"
to "undo actually executed".

Portable across the line: the dispatched inverse is a synthetic governed tool
registered on the real MCP instance, so this file is identical everywhere except
the package import path.
"""

from __future__ import annotations

import sqlite3

import pytest

import firewall_aiops.governance.audit as audit_mod
import firewall_aiops.governance.policy as policy_mod
import firewall_aiops.governance.undo as undo_mod
from firewall_aiops.governance import governed_tool
from mcp_server._shared import mcp
from mcp_server.tools import undo as gov

_CALLS: list[dict] = []


@governed_tool(risk_level="low")
def _undo_probe(value: str = "", target=None) -> dict:
    """Synthetic inverse target used only by the undo-executor tests."""
    _CALLS.append({"value": value})
    return {"ok": True, "value": value}


@pytest.fixture
def gov_home(tmp_path, monkeypatch):
    _CALLS.clear()
    # Register the probe only for the duration of these tests so it never
    # pollutes the real tool registry (which exact-count smoke tests assert on).
    mcp.add_tool(_undo_probe, name="_undo_probe")
    monkeypatch.setenv("FIREWALL_AIOPS_HOME", str(tmp_path))
    monkeypatch.setenv("FIREWALL_AUDIT_APPROVED_BY", "pytest")
    audit_mod.reset_engine()
    policy_mod.reset_policy_engine()
    undo_mod.reset_undo_store()
    yield tmp_path
    mcp._tool_manager._tools.pop("_undo_probe", None)
    audit_mod.reset_engine()
    policy_mod.reset_policy_engine()
    undo_mod.reset_undo_store()


def _record(undo_tool="_undo_probe", params=None):
    descriptor = {"tool": undo_tool, "params": params if params is not None else {"value": "v1"}}
    return undo_mod.get_undo_store().record(
        skill="probe", tool="orig_op", undo_descriptor=descriptor,
    )


@pytest.mark.unit
def test_undo_list_returns_recorded_tokens(gov_home):
    uid = _record()
    out = gov.undo_list()
    assert out["count"] == 1
    assert out["undos"][0]["undoId"] == uid
    assert out["undos"][0]["inverseTool"] == "_undo_probe"


@pytest.mark.unit
def test_undo_apply_dispatches_inverse_and_marks_applied(gov_home):
    uid = _record(params={"value": "restore-me"})
    result = gov.undo_apply(undo_id=uid)
    assert result["applied"] is True
    assert result["inverseTool"] == "_undo_probe"
    # the inverse governed tool actually ran with the recorded params
    assert _CALLS == [{"value": "restore-me"}]
    # the token is consumed (single-use)
    assert undo_mod.get_undo_store().get(uid)["status"] == "applied"
    assert uid not in {u["undoId"] for u in gov.undo_list()["undos"]}


@pytest.mark.unit
def test_undo_apply_dry_run_previews_without_running(gov_home):
    uid = _record()
    out = gov.undo_apply(undo_id=uid, dry_run=True)
    assert out["dryRun"] is True
    assert out["wouldApply"]["tool"] == "_undo_probe"
    assert _CALLS == []
    assert undo_mod.get_undo_store().get(uid)["status"] == "recorded"


@pytest.mark.unit
def test_undo_apply_is_single_use(gov_home):
    uid = _record()
    gov.undo_apply(undo_id=uid)
    second = gov.undo_apply(undo_id=uid)
    assert "already 'applied'" in second["error"]


@pytest.mark.unit
def test_undo_apply_unknown_id_errors(gov_home):
    out = gov.undo_apply(undo_id="deadbeef")
    assert "Unknown undo id" in out["error"]


@pytest.mark.unit
def test_undo_apply_unregistered_inverse_errors(gov_home):
    uid = _record(undo_tool="no_such_tool_xyz")
    out = gov.undo_apply(undo_id=uid)
    assert "not registered" in out["error"]
    assert undo_mod.get_undo_store().get(uid)["status"] == "recorded"


@pytest.mark.unit
def test_cli_undo_apply_dry_run_renders(gov_home):
    """The `undo apply --dry-run` CLI path must render without error — guards
    against dry_run_print signature drift across tools (api_call vs detail)."""
    from typer.testing import CliRunner

    from firewall_aiops.cli import app

    uid = _record()
    result = CliRunner().invoke(app, ["undo", "apply", uid, "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "DRY-RUN" in result.output
    assert _CALLS == []
    assert undo_mod.get_undo_store().get(uid)["status"] == "recorded"


@pytest.mark.unit
def test_undo_apply_audits_both_wrapper_and_inverse(gov_home):
    uid = _record()
    gov.undo_apply(undo_id=uid)
    conn = sqlite3.connect(gov_home / "audit.db")
    try:
        tools = [r[0] for r in conn.execute("SELECT tool FROM audit_log ORDER BY id")]
    finally:
        conn.close()
    assert "undo_apply" in tools
    assert "_undo_probe" in tools
